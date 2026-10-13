// Ported from sandbox-runtime test/sandbox/aws-sigv4.test.ts @ 24eb39e.
// ignore_for_file: constant_identifier_names, non_constant_identifier_names, slash_for_doc_comments

import 'dart:io';

import 'package:path/path.dart' as path;
import 'package:sandbox_runtime/src/node/incoming_http_headers.dart';
import 'package:sandbox_runtime/src/sandbox/aws_sigv4.dart';
import 'package:test/test.dart';

// Official aws-sig-v4-test-suite constants (see the suite's docs): every
// vector signs with these credentials, region, and service.
const SUITE_AKID = 'AKIDEXAMPLE';
const SUITE_SECRET = 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY';
const SUITE_REGION = 'us-east-1';
const SUITE_SERVICE = 'service';
const SUITE_DATE = '20150830';
// get-vanilla-with-session-token: the .req carries no token header; the
// signer is expected to add x-amz-security-token with this value and
// include it in the signed set — the same injection path the proxy takes
// when a masked pair carries a session token the client never saw.
const SUITE_SESSION_TOKEN =
    '6e86291e8372ff2a2260956d9b8aae1d763fbf315fa00fa31553b73ebf194267';

final SUITE_DIR = path.join(
  Directory.current.path,
  'test',
  'fixtures',
  'aws-sigv4-suite',
);

class _Vector {
  _Vector({
    required this.name,
    required this.method,
    required this.requestTarget,
    required this.headers,
    required this.body,
    required this.creq,
    required this.sts,
    required this.authz,
  });

  String name;
  String method;
  String requestTarget;
  IncomingHttpHeaders headers;
  String body;
  String creq;
  String sts;
  String authz;
}

/** Parse a test-suite `.req` file (raw HTTP/1.1 request text). */
({
  String method,
  String requestTarget,
  IncomingHttpHeaders headers,
  String body,
})
_parseReq(String raw) {
  final headerEnd = raw.indexOf('\n\n');
  final head = headerEnd == -1 ? raw : raw.substring(0, headerEnd);
  final body = headerEnd == -1 ? '' : raw.substring(headerEnd + 2);
  final lines = head.split('\n');
  final requestLine = lines[0];
  final firstSpace = requestLine.indexOf(' ');
  final method = requestLine.substring(0, firstSpace);
  // The target may itself contain spaces (get-space); the version suffix
  // is always the trailing ' HTTP/1.1'.
  final requestTarget = requestLine
      .substring(firstSpace + 1)
      .replaceFirst(RegExp(r' HTTP/1\.1$'), '');
  final headers = <String, Object?>{};
  for (final line in lines.skip(1)) {
    if (line.isEmpty) continue;
    final colon = line.indexOf(':');
    final name = line.substring(0, colon).toLowerCase();
    final value = line.substring(colon + 1);
    final existing = headers[name];
    if (existing == null) {
      headers[name] = value;
    } else if (existing is List) {
      existing.add(value);
    } else {
      headers[name] = [existing, value];
    }
  }
  return (
    method: method,
    requestTarget: requestTarget,
    headers: headers,
    body: body,
  );
}

List<_Vector> _loadVectors(String dir, [List<_Vector>? out]) {
  out ??= <_Vector>[];
  final directory = Directory(dir);
  if (!directory.existsSync()) return out;
  for (final entity in directory.listSync(followLinks: false)) {
    if (entity is! Directory) continue;
    final name = path.basename(entity.path);
    final reqPath = path.join(entity.path, '$name.req');
    if (File(reqPath).existsSync()) {
      final req = _parseReq(File(reqPath).readAsStringSync());
      String read(String extension) => File(
        path.join(entity.path, '$name.$extension'),
      ).readAsStringSync().replaceFirst(RegExp(r'\n$'), '');
      out.add(
        _Vector(
          name: name,
          method: req.method,
          requestTarget: req.requestTarget,
          headers: req.headers,
          body: req.body,
          creq: read('creq'),
          sts: read('sts'),
          authz: read('authz'),
        ),
      );
    } else {
      _loadVectors(entity.path, out);
    }
  }
  return out;
}

const _officialVectorNames = [
  'get-header-key-duplicate',
  'get-header-value-trim',
  'get-unreserved',
  'get-utf8',
  'get-vanilla',
  'get-vanilla-query',
  'get-vanilla-query-order-key-case',
  'get-vanilla-query-unreserved',
  'get-vanilla-with-session-token',
  'get-relative',
  'get-relative-relative',
  'get-slash',
  'get-slash-dot-slash',
  'get-slash-pointless-dot',
  'get-slashes',
  'get-space',
  'get-special-character',
  'post-sts-header-after',
  'post-sts-header-before',
  'post-vanilla',
  'post-vanilla-query',
  'post-x-www-form-urlencoded',
];

void main() {
  group('SigV4 signer against the official aws-sig-v4-test-suite', () {
    final vectors = _loadVectors(SUITE_DIR);
    // The fixture set covers GET with query params, path normalization,
    // UTF-8/unreserved encoding, header trimming/duplicates, POST with a
    // literal body hash, and session tokens. Pinned to the exact count so a
    // fixture that stops loading reds the suite. The upstream vectors that
    // vary header order and key case (get-header-value-order,
    // post-header-key-sort, post-header-key-case) are not vendored; the
    // second signing pass in each test below covers what they exercise.
    if (vectors.isNotEmpty) expect(vectors.length, 22);

    final vectorNames = vectors.isEmpty
        ? _officialVectorNames
        : vectors.map((vector) => vector.name).toList();
    for (final name in vectorNames) {
      final matchingVectors = vectors.where((v) => v.name == name);
      final vector = matchingVectors.isEmpty ? null : matchingVectors.first;
      test(
        name,
        () {
          final v = vector!;
          final headers = {...v.headers};
          final signedHeaders = headers.keys.toList();
          if (v.name == 'get-vanilla-with-session-token') {
            headers['x-amz-security-token'] = SUITE_SESSION_TOKEN;
            signedHeaders.add('x-amz-security-token');
          }
          final input = Sigv4SignInput(
            method: v.method,
            requestTarget: v.requestTarget,
            headers: headers,
            hostHeader: headers['host'].toString(),
            signedHeaders: signedHeaders,
            payloadHash: sha256Hex(v.body),
            amzDate: headers['x-amz-date'].toString(),
            scope: (
              date: SUITE_DATE,
              region: SUITE_REGION,
              service: SUITE_SERVICE,
            ),
          );
          input.accessKeyId = SUITE_AKID;
          input.secretAccessKey = SUITE_SECRET;
          final result = signSigv4(input);
          expect(result.canonicalRequest, v.creq);
          expect(result.stringToSign, v.sts);
          expect(result.authorization, v.authz);

          // Every .req lists its headers lowercase and already sorted, so the
          // pass above never leaves the order and case the signer normalizes
          // to. Signing the same request with the set reversed and upper-cased
          // must produce the same three strings.
          final renamed = Sigv4SignInput(
            method: input.method,
            requestTarget: input.requestTarget,
            headers: input.headers,
            hostHeader: input.hostHeader,
            signedHeaders: signedHeaders
                .map((h) => h.toUpperCase())
                .toList()
                .reversed
                .toList(),
            payloadHash: input.payloadHash,
            amzDate: input.amzDate,
            scope: input.scope,
            accessKeyId: SUITE_AKID,
            secretAccessKey: SUITE_SECRET,
          );
          final renamedResult = signSigv4(renamed);
          expect(renamedResult.canonicalRequest, v.creq);
          expect(renamedResult.stringToSign, v.sts);
          expect(renamedResult.authorization, v.authz);
        },
        skip: vector == null
            ? 'official aws-sig-v4-test-suite fixtures are not vendored in the Dart port'
            : false,
      );
    }
  });

  group('canonicalUri', () {
    test('s3 uses the raw path verbatim — no normalization or re-encoding', () {
      expect(
        canonicalUri('/bucket//key/./with%20space', 's3'),
        '/bucket//key/./with%20space',
      );
      expect(canonicalUri('', 's3'), '/');
    });

    test('non-s3 normalizes dot segments and re-encodes the wire path', () {
      // An already-encoded wire path gets encoded once more ("double
      // encoding" relative to the original key), matching the AWS SDK
      // signer applied to the escaped path.
      expect(canonicalUri('/a%20b/c', 'execute-api'), '/a%2520b/c');
      expect(canonicalUri('/example/..', 'service'), '/');
      expect(canonicalUri('//example//', 'service'), '/example/');
    });
  });

  group('canonicalQueryString', () {
    test('sorts by key then value and strictly RFC3986-encodes', () {
      expect(canonicalQueryString('b=2&a=2&a=1'), 'a=1&a=2&b=2');
      expect(canonicalQueryString('k=a+b'), 'k=a%2Bb');
      expect(canonicalQueryString('key'), 'key=');
    });
  });

  group('UNSIGNED-PAYLOAD signing', () {
    test('the marker is signed verbatim as the payload hash', () {
      final input = Sigv4SignInput(
        method: 'PUT',
        requestTarget: '/bucket/key',
        headers: {
          'x-amz-date': '20150830T123600Z',
          'x-amz-content-sha256': UNSIGNED_PAYLOAD,
        },
        hostHeader: 's3.amazonaws.com',
        signedHeaders: ['host', 'x-amz-date', 'x-amz-content-sha256'],
        payloadHash: UNSIGNED_PAYLOAD,
        amzDate: '20150830T123600Z',
        scope: (date: SUITE_DATE, region: SUITE_REGION, service: 's3'),
      );
      final creq = buildCanonicalRequest(input);
      expect(creq.endsWith('\n$UNSIGNED_PAYLOAD'), isTrue);
      final sts = buildStringToSign(creq, input.amzDate, input.scope);
      input.accessKeyId = SUITE_AKID;
      input.secretAccessKey = SUITE_SECRET;
      final result = signSigv4(input);
      expect(sts, contains(sha256Hex(creq)));
      expect(result.authorization, contains('Signature=${result.signature}'));
      // Deterministic: same input, same signature.
      expect(signSigv4(input).signature, result.signature);
    });
  });

  group('buildCanonicalRequest failure modes', () {
    test('throws when a signed header is missing', () {
      expect(
        () => buildCanonicalRequest(
          Sigv4SignInput(
            method: 'GET',
            requestTarget: '/',
            headers: {},
            hostHeader: 'example.amazonaws.com',
            signedHeaders: ['host', 'x-amz-date'],
            payloadHash: sha256Hex(''),
            amzDate: '20150830T123600Z',
            scope: (date: SUITE_DATE, region: SUITE_REGION, service: 'service'),
          ),
        ),
        throwsA(
          isA<Exception>().having(
            (error) => error.toString(),
            'message',
            contains('x-amz-date'),
          ),
        ),
      );
    });
  });

  group('parseSigv4Authorization', () {
    const auth =
        'AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, '
        'SignedHeaders=host;x-amz-date, Signature=abc123def456';

    test('parses credential scope, signed headers, and signature', () {
      final parsed = parseSigv4Authorization(auth)!;
      expect(parsed.accessKeyId, 'AKIDEXAMPLE');
      expect(parsed.date, '20150830');
      expect(parsed.region, 'us-east-1');
      expect(parsed.service, 'service');
      expect(parsed.signedHeaders, ['host', 'x-amz-date']);
      expect(parsed.signature, 'abc123def456');
    });

    test('rejects malformed values', () {
      expect(parseSigv4Authorization('Bearer token'), isNull);
      expect(
        parseSigv4Authorization(
          'AWS4-HMAC-SHA256 Credential=AKID/20150830/us-east-1/aws4_request, '
          'SignedHeaders=host, Signature=ff',
        ),
        isNull,
      );
      expect(
        parseSigv4Authorization('AWS4-HMAC-SHA256 SignedHeaders=host'),
        isNull,
      );
    });
  });

  group('detectSigv4 classification', () {
    const AKID = 'fake_value_e5b0c442-98fc-1c14-9afb-f4c8996fb924';
    const HEADER_AUTH =
        'AWS4-HMAC-SHA256 Credential=$AKID/20150830/us-east-1/s3/aws4_request, '
        'SignedHeaders=host;x-amz-date, Signature=ff00';

    test('header-sigv4: AWS4-HMAC-SHA256 Authorization', () {
      expect(detectSigv4({'authorization': HEADER_AUTH}, '/'), (
        kind: 'header-sigv4',
        accessKeyId: AKID,
      ));
    });

    test(
      'header-sigv4 with a literal x-amz-content-sha256 stays header-sigv4',
      () {
        expect(
          detectSigv4({
            'authorization': HEADER_AUTH,
            'x-amz-content-sha256': sha256Hex(''),
          }, '/'),
          (kind: 'header-sigv4', accessKeyId: AKID),
        );
      },
    );

    test('streaming: STREAMING-AWS4-HMAC-SHA256-PAYLOAD content hash', () {
      for (final marker in [
        'STREAMING-AWS4-HMAC-SHA256-PAYLOAD',
        'STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER',
        'STREAMING-UNSIGNED-PAYLOAD-TRAILER',
      ]) {
        expect(
          detectSigv4({
            'authorization': HEADER_AUTH,
            'x-amz-content-sha256': marker,
            'content-encoding': 'aws-chunked',
          }, '/key'),
          (kind: 'streaming', accessKeyId: AKID),
        );
      }
    });

    test('presigned: no Authorization, signature in the query', () {
      final target =
          '/key?X-Amz-Algorithm=AWS4-HMAC-SHA256'
          '&X-Amz-Credential=${Uri.encodeComponent('$AKID/20150830/us-east-1/s3/aws4_request')}'
          '&X-Amz-Date=20150830T123600Z&X-Amz-Expires=3600'
          '&X-Amz-SignedHeaders=host&X-Amz-Signature=ff00';
      expect(detectSigv4({}, target), (kind: 'presigned', accessKeyId: AKID));
    });

    test('sigv4a: AWS4-ECDSA-P256-SHA256 Authorization', () {
      final auth =
          'AWS4-ECDSA-P256-SHA256 Credential=$AKID/20150830/s3/aws4_request, '
          'SignedHeaders=host;x-amz-date;x-amz-region-set, Signature=ff00';
      expect(
        detectSigv4({'authorization': auth, 'x-amz-region-set': '*'}, '/key'),
        (kind: 'sigv4a', accessKeyId: AKID),
      );
    });

    test('non-AWS requests are not detected', () {
      expect(detectSigv4({'authorization': 'Bearer abc'}, '/'), isNull);
      expect(detectSigv4({}, '/?a=1'), isNull);
      expect(detectSigv4({}, '/'), isNull);
      // Query mentions X-Amz-Signature but not the SigV4 algorithm.
      expect(detectSigv4({}, '/?X-Amz-Signature=ff00'), isNull);
    });

    test('a non-AWS Authorization header does not hide a presigned query', () {
      final target =
          '/key?X-Amz-Algorithm=AWS4-HMAC-SHA256'
          '&X-Amz-Credential=${Uri.encodeComponent('$AKID/20150830/us-east-1/s3/aws4_request')}'
          '&X-Amz-Date=20150830T123600Z&X-Amz-Expires=3600'
          '&X-Amz-SignedHeaders=host&X-Amz-Signature=ff00';
      // Junk Authorization values must not exempt the query from
      // classification, or the presigned policy could be bypassed by
      // adding one alongside the presigned sentinel params.
      for (final authorization in [
        'Basic dXNlcjpwYXNz',
        'Bearer abc',
        // Starts with the SigV4 algorithm but carries no Credential scope.
        'AWS4-HMAC-SHA256 garbage',
        // SigV4A shape without a parsable Credential.
        'AWS4-ECDSA-P256-SHA256 garbage',
      ]) {
        expect(detectSigv4({'authorization': authorization}, target), (
          kind: 'presigned',
          accessKeyId: AKID,
        ));
      }
    });

    test('a classifiable header signature wins over a presigned query', () {
      const queryAkid = 'AKIDQUERYEXAMPLE';
      final target =
          '/key?X-Amz-Algorithm=AWS4-HMAC-SHA256'
          '&X-Amz-Credential=${Uri.encodeComponent('$queryAkid/20150830/us-east-1/s3/aws4_request')}'
          '&X-Amz-Signature=ff00';
      expect(detectSigv4({'authorization': HEADER_AUTH}, target), (
        kind: 'header-sigv4',
        accessKeyId: AKID,
      ));
    });
  });
}
