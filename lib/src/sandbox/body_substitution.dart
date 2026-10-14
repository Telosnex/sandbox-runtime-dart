// Ported from sandbox-runtime src/sandbox/body-substitution.ts @ 24eb39e.
// ignore_for_file: dangling_library_doc_comments, slash_for_doc_comments

/**
 * Streaming sentinel→real substitution for forwarded HTTP request bodies.
 *
 * The proxy substitutes masked-credential sentinels in request headers
 * (SentinelRegistry.substituteInHeaders); a credential a tool places in a
 * request body (JSON payload, form post) would otherwise reach the API as
 * the useless fake. Sentinels are exact-match strings over `[a-z0-9_-]`, so
 * they survive JSON, form-urlencoded, multipart, and XML verbatim — a raw
 * byte scan needs no format parsing. Bodies are never buffered whole:
 * memory is bounded by one chunk plus a hold-back of `maxSentinelLength - 1`
 * bytes carried across chunk boundaries.
 *
 * Fail-safe direction: substitution is fake→real, so a missed sentinel
 * (compressed body, base64-wrapped, split by an encoder) means the FAKE
 * value reaches the API and auth fails — never a leaked secret.
 */

import 'dart:math' as math;
import 'dart:typed_data';

import '../node/buffer.dart' show Buffer;
import '../node/http.dart' as http;
import '../node/stream.dart' as stream;
import '../utils/debug.dart' show logForDebugging;
import 'request_filter.dart' show BODYLESS_METHODS;

/** One sentinel→real replacement, as raw bytes. */
class SentinelBufferPair {
  const SentinelBufferPair({required this.sentinel, required this.realValue});

  final Uint8List sentinel;
  final Uint8List realValue;
}

/**
 * Per-destination substitution set for masked-credential body rewriting.
 * Consulted once per request with the canonical destination host (the
 * CONNECT target, never the spoofable Host header). Empty/undefined means
 * no credential is injectable at the host — the caller must keep the
 * existing bare pipe, byte-identical.
 */
typedef GetBodySubstitutions =
    List<SentinelBufferPair>? Function(String destHost);

/** True when substitution cannot change the body length. */
bool allLengthMatched(List<SentinelBufferPair> pairs) {
  return pairs.every((p) => p.sentinel.length == p.realValue.length);
}

/**
 * Build the substitution Transform for one forwarded request, or undefined
 * when the body must keep the existing bare pipe, byte-identical: bodyless
 * method, no credential injectable at `destHost`, or a Content-Encoding the
 * byte scan cannot see through.
 *
 * When substitution can change the body length (some injectable sentinel is
 * not length-matched with its real value — e.g. a caller-minted JWT-shaped
 * fake), Content-Length is deleted from `fwdHeaders` so the outbound
 * request re-frames as chunked; otherwise Content-Length stays verbatim.
 */
stream.Transform? prepareBodySubstitution(
  GetBodySubstitutions? getBodySubstitutions,
  http.IncomingMessage req,
  http.IncomingHttpHeaders fwdHeaders,
  String destHost,
) {
  if (getBodySubstitutions == null) return null;
  // A bodyless-method request can still carry a declared body (GET-with-body
  // APIs are legal HTTP and forwarded today) — skip only when there is
  // provably nothing to scan.
  final declaresBody =
      req.headers['content-length'] != null ||
      req.headers['transfer-encoding'] != null;
  if (BODYLESS_METHODS.contains(req.method ?? 'GET') && !declaresBody) {
    return null;
  }
  final pairs = getBodySubstitutions(destHost);
  if (pairs == null || pairs.isEmpty) return null;
  if (req.headers['content-encoding'] != null) {
    // Fail-safe direction: an encoded body cannot be scanned for sentinel
    // bytes, so it passes through unchanged — a sentinel in it reaches the
    // upstream as the useless fake and auth fails, but the real secret
    // cannot leak. Warn so the resulting 401 is diagnosable.
    logForDebugging(
      '[body-substitution] $destHost: request body has Content-Encoding '
      '"${req.headers['content-encoding']}"; masked-credential '
      'substitution skipped — a sentinel in this body reaches the '
      'upstream as the fake value',
      level: 'warn',
    );
    return null;
  }
  if (!allLengthMatched(pairs)) {
    fwdHeaders.remove('content-length');
  }
  return createBodySubstitutionTransform(pairs);
}

/**
 * Transform that replaces every occurrence of each pair's sentinel bytes
 * with its real-value bytes.
 *
 * Boundary-safe: the last `maxSentinelLength - 1` bytes of each chunk are
 * held back and prepended to the next chunk, so a sentinel split across any
 * chunk boundary is still seen whole; the hold-back is flushed on stream
 * end. Replacement is left-to-right, resuming after each replacement — the
 * substituted real value is never rescanned. Backpressure propagates
 * through normal Transform semantics.
 */
stream.Transform createBodySubstitutionTransform(
  List<SentinelBufferPair> pairs,
) {
  final maxLen = pairs
      .map((p) => p.sentinel.length)
      .fold<num>(double.negativeInfinity, math.max);
  Uint8List? carry;
  return stream.Transform(
    transform: (Object chunk, String? encoding, Function callback) {
      final buf = Buffer.isBuffer(chunk)
          ? chunk as Uint8List
          : Buffer.from(chunk, encoding ?? 'utf8').toUint8List();
      final work = (carry?.length ?? 0) > 0
          ? Buffer.concat([carry!, buf])
          : buf;
      final (:out, :tail) = _substitute(work, pairs, maxLen);
      carry = tail;
      callback(null, out);
    },
    flush: (Function callback) {
      // The hold-back cannot contain a complete sentinel — the scan loop
      // only stops when no full match remains — so it flushes verbatim.
      callback(null, (carry?.length ?? 0) > 0 ? carry : null);
    },
  );
}

({Uint8List out, Uint8List tail}) _substitute(
  Uint8List work,
  List<SentinelBufferPair> pairs,
  num maxLen,
) {
  final parts = <Uint8List>[];
  var pos = 0;
  for (;;) {
    // Earliest match across all pairs (typically 1–3 sentinels per host).
    // Matching is earliest-position-then-registration-order, not
    // longest-match — sound because no sentinel is a substring of another
    // (registerWithSentinel's caller contract).
    var matchIdx = -1;
    SentinelBufferPair? matchPair;
    for (final p in pairs) {
      final i = Buffer.indexOf(work, p.sentinel, pos);
      if (i != -1 && (matchIdx == -1 || i < matchIdx)) {
        matchIdx = i;
        matchPair = p;
      }
    }
    if (matchPair == null) break;
    parts.addAll([
      Uint8List.sublistView(work, pos, matchIdx),
      matchPair.realValue,
    ]);
    pos = matchIdx + matchPair.sentinel.length;
  }
  // Hold back the longest suffix that could still be a proper prefix of a
  // sentinel completed by the next chunk. A partial match of a sentinel of
  // length L occupies at most L-1 trailing bytes, so maxLen-1 always covers
  // it. Copied (not a subarray view) so the carry never aliases a buffer
  // the stream may reuse.
  // Dart: sublistView does not clamp an end past the length as subarray does.
  final tailStart = math
      .min(math.max(pos, work.length - (maxLen - 1)), work.length)
      .toInt();
  parts.add(Uint8List.sublistView(work, pos, tailStart));
  return (
    out: Buffer.concat(parts),
    tail: Buffer.from(Uint8List.sublistView(work, tailStart)).toUint8List(),
  );
}
