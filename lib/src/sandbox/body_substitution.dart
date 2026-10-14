// STUB: pending port of src/sandbox/body-substitution.ts @ 24eb39e.
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

import 'dart:typed_data';

import '../node/http.dart' as http;
import '../node/stream.dart' as stream;
import '../utils/debug.dart';
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
bool allLengthMatched(List<SentinelBufferPair> pairs) =>
    pairs.every((p) => p.sentinel.length == p.realValue.length);

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
  final declaresBody =
      req.headers['content-length'] != null ||
      req.headers['transfer-encoding'] != null;
  if (BODYLESS_METHODS.contains(req.method ?? 'GET') && !declaresBody) {
    return null;
  }
  final pairs = getBodySubstitutions(destHost);
  if (pairs == null || pairs.isEmpty) return null;
  if (req.headers['content-encoding'] != null) {
    logForDebugging(
      '[body-substitution] $destHost: request body has Content-Encoding "${req.headers['content-encoding']}"; masked-credential substitution skipped — a sentinel in this body reaches the upstream as the fake value',
      level: 'warn',
    );
    return null;
  }
  if (!allLengthMatched(pairs)) fwdHeaders.remove('content-length');
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
      .reduce((a, b) => a > b ? a : b);
  Uint8List carry = Uint8List(0);
  return stream.Transform(
    transform: (Object chunk, Object? encoding, Function callback) {
      final bytes = chunk is String
          ? Uint8List.fromList(chunk.codeUnits)
          : Uint8List.fromList(chunk as List<int>);
      final work = Uint8List(carry.length + bytes.length)
        ..setRange(0, carry.length, carry)
        ..setRange(carry.length, carry.length + bytes.length, bytes);
      final result = _substitute(work, pairs, maxLen);
      carry = result.$2;
      Function.apply(callback, [null, result.$1]);
    },
    flush: (Function callback) {
      Function.apply(callback, [null, carry.isEmpty ? null : carry]);
    },
  );
}

(Uint8List, Uint8List) _substitute(
  Uint8List work,
  List<SentinelBufferPair> pairs,
  int maxLen,
) {
  final out = BytesBuilder(copy: false);
  var pos = 0;
  while (true) {
    var matchIndex = -1;
    SentinelBufferPair? matchPair;
    for (final pair in pairs) {
      final index = _indexOf(work, pair.sentinel, pos);
      if (index >= 0 && (matchIndex < 0 || index < matchIndex)) {
        matchIndex = index;
        matchPair = pair;
      }
    }
    if (matchPair == null) break;
    out.add(work.sublist(pos, matchIndex));
    out.add(matchPair.realValue);
    pos = matchIndex + matchPair.sentinel.length;
  }
  final tailStart = (work.length - (maxLen - 1)).clamp(pos, work.length);
  out.add(work.sublist(pos, tailStart));
  return (out.takeBytes(), Uint8List.fromList(work.sublist(tailStart)));
}

int _indexOf(List<int> haystack, List<int> needle, int start) {
  for (var i = start; i + needle.length <= haystack.length; i++) {
    var found = true;
    for (var j = 0; j < needle.length; j++) {
      if (haystack[i + j] != needle[j]) {
        found = false;
        break;
      }
    }
    if (found) return i;
  }
  return -1;
}
