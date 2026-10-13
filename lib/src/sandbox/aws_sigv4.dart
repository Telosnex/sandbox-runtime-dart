// Ported from sandbox-runtime src/sandbox/aws-sigv4.ts @ 24eb39e.
// ignore_for_file: constant_identifier_names, dangling_library_doc_comments, slash_for_doc_comments

import '../node/aws_crypto.dart' as node_crypto;
import '../node/incoming_http_headers.dart' show IncomingHttpHeaders;
import '../node/url_search_params.dart' as node_url;

/**
 * AWS Signature Version 4 protocol code for the TLS-terminating proxy.
 *
 * A masked AWS credential hands the sandboxed process a fake access key id
 * and secret, so any SigV4 signature the client computes is an HMAC over
 * the fake secret — header substitution can swap the access key id in the
 * credential scope, but it cannot fix the signature. The proxy therefore
 * re-signs: strip the client's Authorization, keep its credential scope /
 * signed-header set / x-amz-date, and recompute the signature with the
 * real secret over the request as it actually goes upstream. Prior art:
 * awslabs/aws-sigv4-proxy.
 *
 * This module is pure protocol code — request classification,
 * Authorization parsing, canonical-request construction, and signing —
 * validated against the official aws-sig-v4-test-suite vectors
 * (test/fixtures/aws-sigv4-suite). The credential-pair registry and the
 * proxy-side planner live in credential-aws-pairs.ts.
 */

const SIGV4_ALGORITHM = 'AWS4-HMAC-SHA256';
const SIGV4A_ALGORITHM = 'AWS4-ECDSA-P256-SHA256';
const UNSIGNED_PAYLOAD = 'UNSIGNED-PAYLOAD';

/**
 * How a request references AWS SigV4 authentication:
 *
 * - `header-sigv4`: Authorization is `AWS4-HMAC-SHA256 ...` — the case the
 *   proxy can re-sign.
 * - `streaming`: `x-amz-content-sha256` declares an aws-chunked payload
 *   (`STREAMING-*`) whose chunk signatures chain off the seed signature —
 *   re-signing would require rewriting the body's per-chunk signatures.
 * - `presigned`: the signature lives in the query (`X-Amz-Algorithm` /
 *   `X-Amz-Signature`) — re-signing would rewrite the URL itself. Applies
 *   whenever the Authorization header does not itself classify: a non-AWS
 *   Authorization value (e.g. `Basic ...`) must not exempt the query, or
 *   adding a junk header would bypass the presigned policy.
 * - `sigv4a`: Authorization is `AWS4-ECDSA-P256-SHA256 ...` — asymmetric
 *   signing keyed off the secret via ECDSA; there is no shared-key HMAC to
 *   recompute without the client's derived private key.
 */
typedef Sigv4Kind = String;

/**
 * Access key id the signature references — from the Authorization
 * `Credential=<akid>/...` scope, or `X-Amz-Credential` in the query for
 * presigned URLs. Callers exact-match this against registered masked
 * pairs to decide whether the request is theirs to handle.
 */
typedef Sigv4Detection = ({Sigv4Kind kind, String accessKeyId});

/**
 * Classify a request's SigV4 shape from headers and the request-target
 * only (no body inspection). Returns null when the request carries no
 * recognizable SigV4 signature.
 */
Sigv4Detection? detectSigv4(IncomingHttpHeaders headers, String requestTarget) {
  final auth = singleHeader(headers['authorization']);
  if (auth != null && auth.startsWith(SIGV4A_ALGORITHM)) {
    final akid = _credentialAccessKeyId(auth);
    if (akid != null) return (kind: 'sigv4a', accessKeyId: akid);
  } else if (auth != null && auth.startsWith(SIGV4_ALGORITHM)) {
    final akid = _credentialAccessKeyId(auth);
    if (akid != null) {
      final contentSha = singleHeader(headers['x-amz-content-sha256']);
      // Covers STREAMING-AWS4-HMAC-SHA256-PAYLOAD, its -TRAILER variant,
      // and STREAMING-UNSIGNED-PAYLOAD-TRAILER: all declare an aws-chunked
      // body the plain re-sign path cannot reproduce.
      final kind = contentSha != null && contentSha.startsWith('STREAMING-')
          ? 'streaming'
          : 'header-sigv4';
      return (kind: kind, accessKeyId: akid);
    }
  }

  // Presigned URL: the signature is in the query string. Checked whenever
  // the Authorization header did not classify above — an unrecognized or
  // malformed Authorization value alongside presigned sentinel params must
  // not turn the request invisible to the presigned policy.
  final q = requestTarget.indexOf('?');
  if (q == -1) return null;
  final params = node_url.URLSearchParams(requestTarget.substring(q + 1));
  if (params.get('X-Amz-Algorithm') != SIGV4_ALGORITHM) return null;
  if (!params.has('X-Amz-Signature')) return null;
  final credential = params.get('X-Amz-Credential');
  if (credential == null || credential.isEmpty) return null;
  final akid = credential.split('/').first;
  return akid.isNotEmpty ? (kind: 'presigned', accessKeyId: akid) : null;
}

/** `Credential=<akid>/...` access key id from an Authorization value. */
String? _credentialAccessKeyId(String auth) {
  final m = RegExp(r'Credential=([^/,\s]+)/').firstMatch(auth);
  return m?.group(1);
}

/**
 * Parse an `AWS4-HMAC-SHA256 Credential=..., SignedHeaders=...,
 * Signature=...` Authorization value. Returns null when any component is
 * missing or the credential scope is not the 5-part
 * `<akid>/<date>/<region>/<service>/aws4_request` form.
 */
typedef ParsedSigv4Authorization = ({
  String accessKeyId,
  String date,
  String region,
  String service,
  List<String> signedHeaders,
  String signature,
});

/**
 * Parse an `AWS4-HMAC-SHA256 Credential=..., SignedHeaders=...,
 * Signature=...` Authorization value. Returns null when any component is
 * missing or the credential scope is not the 5-part
 * `<akid>/<date>/<region>/<service>/aws4_request` form.
 */
ParsedSigv4Authorization? parseSigv4Authorization(String auth) {
  if (!auth.startsWith(SIGV4_ALGORITHM)) return null;
  final cred = RegExp(r'Credential=([^,\s]+)').firstMatch(auth)?.group(1);
  final signedHeaders = RegExp(
    r'SignedHeaders=([^,\s]+)',
  ).firstMatch(auth)?.group(1);
  final signature = RegExp(
    r'Signature=([0-9a-fA-F]+)',
  ).firstMatch(auth)?.group(1);
  if (cred == null ||
      cred.isEmpty ||
      signedHeaders == null ||
      signedHeaders.isEmpty ||
      signature == null ||
      signature.isEmpty) {
    return null;
  }
  final parts = cred.split('/');
  if (parts.length != 5 || parts[4] != 'aws4_request') return null;
  final accessKeyId = parts[0];
  final date = parts[1];
  final region = parts[2];
  final service = parts[3];
  if (accessKeyId.isEmpty ||
      date.isEmpty ||
      region.isEmpty ||
      service.isEmpty) {
    return null;
  }
  return (
    accessKeyId: accessKeyId,
    date: date,
    region: region,
    service: service,
    signedHeaders: signedHeaders
        .split(';')
        .map((h) => h.toLowerCase())
        .toList(),
    signature: signature,
  );
}

/**
 * Strict RFC 3986 percent-encoding: everything except unreserved
 * characters (A-Za-z0-9 - _ . ~) is encoded. encodeURIComponent leaves
 * `!'()*` raw; SigV4 requires them encoded.
 */
String uriEncode(String s) {
  return Uri.encodeComponent(s).replaceAllMapped(RegExp(r"[!'()*]"), (m) {
    final hex = m[0]!.codeUnitAt(0).toRadixString(16).toUpperCase();
    return '%$hex';
  });
}

/**
 * Canonical URI per SigV4: for S3 the raw request path is used verbatim
 * (no dot-segment normalization, no re-encoding — S3 object keys are
 * byte-significant and the service verifies against the wire path); for
 * every other service, dot segments are resolved and the path is
 * percent-encoded once more on top of its wire encoding ('/' preserved).
 * Matches the AWS SDK signer (smithy SignatureV4.getCanonicalPath) and
 * awslabs/aws-sigv4-proxy, which disables path escaping for s3 only.
 *
 * rawPath is the target the proxy forwards, so the signature covers the
 * path on the wire: the client's bytes unchanged when no filterRequest is
 * configured, the normalized target when one is.
 */
String canonicalUri(String rawPath, String service) {
  if (rawPath.isEmpty) return '/';
  if (service == 's3') return rawPath;
  final segments = <String>[];
  for (final seg in rawPath.split('/')) {
    if (seg.isEmpty || seg == '.') continue;
    if (seg == '..') {
      if (segments.isNotEmpty) segments.removeLast();
    } else {
      segments.add(seg);
    }
  }
  final trailing = segments.isNotEmpty && rawPath.endsWith('/') ? '/' : '';
  final normalized = '/${segments.join('/')}$trailing';
  return uriEncode(
    normalized,
  ).replaceAll(RegExp(r'%2F', caseSensitive: false), '/');
}

/**
 * Canonical query string per SigV4: each key and value is decoded then
 * strictly re-encoded, pairs are sorted by encoded key then encoded
 * value, and joined with '&'. A literal '+' is treated as a plus (RFC
 * 3986), not a space.
 */
String canonicalQueryString(String rawQuery) {
  if (rawQuery.isEmpty) return '';
  final pairs = <(String, String)>[];
  for (final part in rawQuery.split('&')) {
    if (part.isEmpty) continue;
    final eq = part.indexOf('=');
    final rawKey = eq == -1 ? part : part.substring(0, eq);
    final rawValue = eq == -1 ? '' : part.substring(eq + 1);
    pairs.add((
      uriEncode(_safeDecode(rawKey)),
      uriEncode(_safeDecode(rawValue)),
    ));
  }
  pairs.sort((a, b) {
    final keyComparison = a.$1.compareTo(b.$1);
    return keyComparison != 0 ? keyComparison : a.$2.compareTo(b.$2);
  });
  return pairs.map((pair) => '${pair.$1}=${pair.$2}').join('&');
}

String _safeDecode(String s) {
  try {
    return Uri.decodeComponent(s);
  } catch (_) {
    return s;
  }
}

/** SigV4 "trimall": strip leading/trailing whitespace, collapse runs. */
String _trimall(String value) =>
    value.trim().replaceAll(RegExp(r'[ \t]+'), ' ');

class Sigv4SignInput {
  Sigv4SignInput({
    required this.method,
    required this.requestTarget,
    required this.headers,
    required this.hostHeader,
    required this.signedHeaders,
    required this.payloadHash,
    required this.amzDate,
    required this.scope,
    this.accessKeyId,
    this.secretAccessKey,
  });

  String method;
  /**
   * Origin-form request-target exactly as forwarded upstream
   * (`/path?query`). The canonical URI/query are derived from it.
   */
  String requestTarget;
  /**
   * Headers as they will be sent upstream. `host` is not looked up here —
   * its value comes from `hostHeader`.
   */
  IncomingHttpHeaders headers;
  String hostHeader;
  /**
   * Lowercase header names to sign. Sorted internally; every name other
   * than `host` must be present in `headers`.
   */
  List<String> signedHeaders;
  /** Hex SHA-256 of the payload, or the UNSIGNED-PAYLOAD marker. */
  String payloadHash;
  /** ISO 8601 basic timestamp (e.g. 20150830T123600Z). */
  String amzDate;
  ({String date, String region, String service}) scope;
  String? accessKeyId;
  String? secretAccessKey;
}

/**
 * Build the SigV4 canonical request. Throws if a signed header (other
 * than `host`) is absent from `headers` — the caller must have validated
 * presence, since signing an empty value the upstream never sees would
 * produce a signature the service rejects confusingly.
 */
String buildCanonicalRequest(Sigv4SignInput input) {
  final q = input.requestTarget.indexOf('?');
  final rawPath = q == -1
      ? input.requestTarget
      : input.requestTarget.substring(0, q);
  final rawQuery = q == -1 ? '' : input.requestTarget.substring(q + 1);

  final names = input.signedHeaders.map((h) => h.toLowerCase()).toList()
    ..sort();
  final headerLines = <String>[];
  for (final name in names) {
    final value = name == 'host' ? input.hostHeader : input.headers[name];
    if (value == null) {
      throw Exception('signed header "$name" is missing from the request');
    }
    final String canonical;
    if (value is List) {
      canonical = value.map((value) => _trimall(value as String)).join(',');
    } else {
      canonical = _trimall(value.toString());
    }
    headerLines.add('$name:$canonical');
  }

  return [
    input.method.toUpperCase(),
    canonicalUri(rawPath, input.scope.service),
    canonicalQueryString(rawQuery),
    '${headerLines.join('\n')}\n',
    names.join(';'),
    input.payloadHash,
  ].join('\n');
}

/** String-to-sign over a canonical request. */
String buildStringToSign(
  String canonicalRequest,
  String amzDate,
  ({String date, String region, String service}) scope,
) {
  return [
    SIGV4_ALGORITHM,
    amzDate,
    '${scope.date}/${scope.region}/${scope.service}/aws4_request',
    sha256Hex(canonicalRequest),
  ].join('\n');
}

/** kSigning = HMAC-chain(AWS4+secret, date, region, service, terminator). */
node_crypto.Buffer deriveSigningKey(
  String secretAccessKey,
  ({String date, String region, String service}) scope,
) {
  final kDate = _hmac('AWS4$secretAccessKey', scope.date);
  final kRegion = _hmac(kDate, scope.region);
  final kService = _hmac(kRegion, scope.service);
  return _hmac(kService, 'aws4_request');
}

/** Full Authorization header value. */
typedef Sigv4SignResult = ({
  String authorization,
  String signature,
  String canonicalRequest,
  String stringToSign,
});

/**
 * Sign a request with SigV4. The caller supplies the credential scope and
 * timestamp taken from the client's (fake-signed) request so the re-signed
 * request stays byte-compatible with what the client believes it sent.
 */
Sigv4SignResult signSigv4(Sigv4SignInput input) {
  final accessKeyId = input.accessKeyId;
  final secretAccessKey = input.secretAccessKey;
  if (accessKeyId == null || secretAccessKey == null) {
    throw ArgumentError('accessKeyId and secretAccessKey are required to sign');
  }
  final canonicalRequest = buildCanonicalRequest(input);
  final stringToSign = buildStringToSign(
    canonicalRequest,
    input.amzDate,
    input.scope,
  );
  final signature =
      node_crypto
              .createHmac(
                'sha256',
                deriveSigningKey(secretAccessKey, input.scope),
              )
              .update(stringToSign, 'utf8')
              .digest('hex')
          as String;
  final names = input.signedHeaders.map((h) => h.toLowerCase()).toList()
    ..sort();
  final scopeStr =
      '${input.scope.date}/${input.scope.region}/${input.scope.service}/aws4_request';
  return (
    authorization:
        '$SIGV4_ALGORITHM Credential=$accessKeyId/$scopeStr, '
        'SignedHeaders=${names.join(';')}, Signature=$signature',
    signature: signature,
    canonicalRequest: canonicalRequest,
    stringToSign: stringToSign,
  );
}

String sha256Hex(Object data) {
  return node_crypto.createHash('sha256').update(data).digest('hex') as String;
}

node_crypto.Buffer _hmac(Object key, String data) {
  return node_crypto.createHmac('sha256', key).update(data, 'utf8').digest()
      as node_crypto.Buffer;
}

/** First value of a possibly-repeated header, or undefined. */
String? singleHeader(Object? v) {
  if (v is List) return v.isEmpty ? null : v.first as String;
  return v as String?;
}
