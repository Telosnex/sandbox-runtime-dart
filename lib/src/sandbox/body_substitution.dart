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
    throw UnimplementedError(
      'pending port of src/sandbox/body-substitution.ts',
    );

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
) => throw UnimplementedError(
  'pending port of src/sandbox/body-substitution.ts',
);

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
) => throw UnimplementedError(
  'pending port of src/sandbox/body-substitution.ts',
);
