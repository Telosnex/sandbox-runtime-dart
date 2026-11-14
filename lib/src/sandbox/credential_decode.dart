// Ported from sandbox-runtime src/sandbox/credential-decode.ts @ 0bbebed.
// ignore_for_file: constant_identifier_names, dangling_library_doc_comments, slash_for_doc_comments

import 'dart:convert';

import '../node/buffer.dart' show Buffer;
import 'credential_sentinel.dart' show SENTINEL_PREFIX;

/**
 * Decoding support for encoded credential formats (`decode` on a
 * `credentials.files` entry). Currently JWT only.
 *
 * Pure helpers: the default extraction pattern for finding JWT candidates
 * in a file, the verification predicate that confirms a candidate actually
 * is a JWT before it gets masked, and the minting of a JWT-shaped fake to
 * stand in for the real token inside the sandbox.
 */

/**
 * Default `extract` pattern for `decode: "jwt"` entries.
 *
 * A JWT's first segment is the base64url encoding of a JSON header that
 * starts `{"` (it always declares `alg`/`typ`), and base64url of `{"` is
 * `eyJ` — so every JWT starts with `eyJ`. Capture group 1 is the whole
 * three-segment token. The pattern over-matches (any eyJ-prefixed
 * base64url triple); {@link verifyJwt} filters the false positives.
 */
const String JWT_DEFAULT_EXTRACT_PATTERN =
    '(eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+)';

/** Parse a base64url segment as JSON, or undefined if either step fails. */
// Dart has no undefined: `_undefined` stands for it (JSON `null` is a value).
Object? _decodeSegment(String segment) {
  try {
    return jsonDecode(Buffer.from(segment, 'base64url').toString('utf8'));
  } catch (_) {
    return _undefined;
  }
}

const Object _undefined = Object();

/**
 * True when `candidate` is structurally a JWT: three dot-separated
 * segments, the first two base64url-decoding to JSON, and the header
 * (segment 1) declaring an `alg` property.
 *
 * Used to filter extraction candidates before masking — a regex match
 * that fails this check (e.g. a random base64 blob the default pattern
 * over-matched) is left untouched rather than masked.
 */
bool verifyJwt(String candidate) {
  final parts = candidate.split('.');
  if (parts.length != 3) return false;
  final header = _decodeSegment(parts[0]);
  if (header is! Map || !header.containsKey('alg')) {
    return false;
  }
  return !identical(_decodeSegment(parts[1]), _undefined);
}

/**
 * Fixed far-future `exp` claim for fake JWTs (2286-11-20). A constant, not
 * an offset from now, so the fake is fully deterministic given the uuid.
 */
const int _FAKE_JWT_EXP = 9999999999;

/** Fixed signature filler: base64url("srt-fake"). Never a valid signature. */
const String _FAKE_JWT_SIGNATURE = 'c3J0LWZha2U';

String _base64url(String s) {
  return Buffer.from(s, 'utf8').toString('base64url');
}

/**
 * Mint a structurally valid fake JWT carrying the sentinel identity
 * `fake_value_<uuid>` in its `sub` claim. Deterministic given `uuid`.
 *
 * The fake is parseable by client-side JWT handling (three segments, JSON
 * header/payload, far-future `exp`), so a tool inside the sandbox that
 * inspects the token before sending it doesn't break. The header says
 * `alg: HS256` — NOT `alg: none` — deliberately: misconfigured validators
 * accept `alg: none` tokens as valid, whereas an HS256 header forces every
 * validator to attempt signature verification and reject the garbage
 * signature. So if the fake ever reaches a verifier unswapped (e.g. sent
 * to a non-injectHosts destination, the designed fail-closed pass-through),
 * it is cryptographically rejected.
 */
String mintFakeJwt(String uuid) {
  final header = _base64url(jsonEncode({'alg': 'HS256', 'typ': 'JWT'}));
  final payload = _base64url(
    jsonEncode({'sub': SENTINEL_PREFIX + uuid, 'exp': _FAKE_JWT_EXP}),
  );
  return '$header.$payload.$_FAKE_JWT_SIGNATURE';
}

/** Result of {@link maskJwtClaims}. */
class MaskedClaimsResult {
  const MaskedClaimsResult({
    required this.fakeToken,
    required this.claimSentinels,
  });

  /**
   * The rebuilt token: the original header segment verbatim, the modified
   * payload re-encoded, and the fixed filler signature.
   */
  final String fakeToken;

  /** Claim name → the sentinel now carried in the fake payload. */
  final Map<String, String> claimSentinels;
}

/**
 * Claim-level masking for a verified JWT: replace each named top-level
 * payload claim that is present with a string value by a caller-provided
 * sentinel, and rebuild the token around the modified payload.
 *
 * The rebuilt token is `header.payload'.signature-filler`:
 *
 * - **Header**: the original base64url segment is reused verbatim, so the
 *   token still advertises the real `alg`/`typ`/`kid` and client-side
 *   header inspection sees exactly what it would outside the sandbox.
 * - **Payload**: the decoded object with the named claims swapped for
 *   sentinels, re-encoded with `JSON.stringify`. Key order and whitespace
 *   inside the payload segment may differ from the original encoding —
 *   irrelevant to any JSON consumer, and the segment bytes change anyway
 *   because a claim value changed.
 * - **Signature**: the fixed filler from {@link mintFakeJwt}, NOT the real
 *   signature. For RS/ES algorithms signature verification needs only the
 *   public key, so shipping the real signature over a modified payload
 *   would hand the sandbox an offline brute-force oracle for a low-entropy
 *   masked claim (guess the claim, re-encode, verify). The filler also
 *   keeps the fake a non-credential end to end, consistent with the
 *   garbage-signature rationale in {@link mintFakeJwt}.
 *
 * Claims that are absent from the payload, or present with a non-string
 * value, are skipped (the caller logs them). Returns `null` — without
 * invoking `sentinelFor` — when no named claim matched, or when the
 * payload does not decode to a JSON object; the caller routes that
 * through its no-match policy.
 *
 * Pure on `token`/`claims`; the callback may close over a registry.
 */
MaskedClaimsResult? maskJwtClaims(
  String token,
  List<String> claims,
  String Function(String claim, String realValue) sentinelFor,
) {
  final parts = token.split('.');
  final headerSeg = parts[0];
  final payloadSeg = parts.length > 1 ? parts[1] : null;
  final payload = _decodeSegment(payloadSeg ?? '');
  // verifyJwt only guarantees the payload is JSON — it could still be a
  // scalar or array, which has no claims to mask.
  if (payload is! Map<String, dynamic>) {
    return null;
  }
  final record = payload;

  // Collect matches before minting any sentinel, so a null return never
  // leaves an orphaned registration behind in the caller's registry.
  final matched = <(String claim, String value)>[];
  for (final claim in claims) {
    final value = record[claim];
    if (value is String) matched.add((claim, value));
  }
  if (matched.isEmpty) return null;

  final claimSentinels = <String, String>{};
  for (final (claim, value) in matched) {
    final sentinel = sentinelFor(claim, value);
    record[claim] = sentinel;
    claimSentinels[claim] = sentinel;
  }
  return MaskedClaimsResult(
    fakeToken:
        '$headerSeg.${_base64url(jsonEncode(record))}.$_FAKE_JWT_SIGNATURE',
    claimSentinels: claimSentinels,
  );
}
