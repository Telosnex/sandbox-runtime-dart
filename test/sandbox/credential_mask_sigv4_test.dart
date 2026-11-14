// Ported from sandbox-runtime test/sandbox/credential-mask-sigv4.test.ts @ 0bbebed.
// ignore_for_file: constant_identifier_names, non_constant_identifier_names, slash_for_doc_comments, prefer_interpolation_to_compose_strings
/**
 * End-to-end SigV4 re-signing through the TLS-terminating proxy.
 *
 * The client (curl --aws-sigv4, a real independent SigV4 implementation)
 * holds only the FAKE credentials, exactly like a sandboxed AWS SDK. The
 * proxy terminates TLS, detects the fake access key id in the credential
 * scope, and re-signs with the real pair. The local TLS upstream plays
 * the AWS service: it recomputes the signature from the REAL secret over
 * the request it received and asserts an exact match.
 *
 * The signer itself is pinned by the official test vectors in
 * aws-sigv4.test.ts; these tests pin the proxy plumbing around it.
 */
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:path/path.dart' show join;
import 'package:sandbox_runtime/src/node/fs.dart'
    show mkdtempSync, readFileSync, rmSync, writeFileSync;
import 'package:sandbox_runtime/src/node/http.dart' as http;
import 'package:sandbox_runtime/src/node/https.dart' as https;
import 'package:sandbox_runtime/src/node/net.dart' as net;
import 'package:sandbox_runtime/src/node/os.dart' show tmpdir;
import 'package:sandbox_runtime/src/node/tls.dart' as tls;
import 'package:sandbox_runtime/src/sandbox/aws_sigv4.dart';
import 'package:sandbox_runtime/src/sandbox/body_substitution.dart';
import 'package:sandbox_runtime/src/sandbox/credential_aws_pairs.dart';
import 'package:sandbox_runtime/src/sandbox/credential_sentinel.dart';
import 'package:sandbox_runtime/src/sandbox/http_proxy.dart';
import 'package:sandbox_runtime/src/sandbox/mitm_ca.dart';
import 'package:sandbox_runtime/src/sandbox/mitm_leaf.dart';
import 'package:sandbox_runtime/src/sandbox/request_filter.dart';
import 'package:sandbox_runtime/src/sandbox/sandbox_config.dart';
import 'package:sandbox_runtime/src/sandbox/tls_terminate_proxy.dart'
    show MAX_SIGV4_RESIGN_BODY_BYTES;
import 'package:test/test.dart';

// Every case here runs a proxy configured to terminate TLS, so each is
// skipped where this runtime cannot terminate it in-process.
import '../helpers/emitted_connections.dart' show SERVES_EMITTED_CONNECTIONS;

// Dart: upstream's `describeWithTls as describe`, which `group` cannot alias.
final Object? _tlsSkip = SERVES_EMITTED_CONNECTIONS
    ? null
    : 'TLS termination unavailable';

// Dart: the object literal upstream hands createHttpProxyServer; every
// option not named here is absent (null).
class _HttpOptions implements HttpProxyServerOptions {
  _HttpOptions({
    this.mitmCA,
    this.tlsTerminateUpstreamCA,
    this.mutateHeaders,
    this.getBodySubstitutions,
    this.planSigv4,
    this.maxSigv4ResignBodyBytes,
  });
  @override
  final MitmCA? mitmCA;
  @override
  final dynamic tlsTerminateUpstreamCA;
  @override
  final MutateForwardedHeaders? mutateHeaders;
  @override
  final GetBodySubstitutions? getBodySubstitutions;
  @override
  final PlanSigv4? planSigv4;
  @override
  final int? maxSigv4ResignBodyBytes;
  @override
  FutureOr<bool> filter(
    int port,
    String host,
    dynamic socket, [
    String? encodedCommand,
    void Function(String reason)? explain,
  ]) => true;
  @override
  dynamic noSuchMethod(Invocation invocation) => null;
}

final FIXTURE_DIR = join(
  Directory.current.path, // import.meta.dir, '..'
  'test',
  'fixtures',
  'tls-terminate',
);
final CA_CERT = join(FIXTURE_DIR, 'ca.crt');
final CA_KEY = join(FIXTURE_DIR, 'ca.key');
final CA_PEM = readFileSync(CA_CERT, 'utf8') as String;

const REAL_AKID = 'AKIAIOSFODNN7EXAMPLE';
const REAL_SECRET = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
const REAL_TOKEN = 'FQoGZXIvYXdzEXAMPLEsessiontoken==';
const REGION = 'us-east-1';
const SERVICE = 's3';
const DEST = '127.0.0.1';

/** Host matcher for tests: exact equality. */
bool eq(String h, String p) => h == p;

typedef Captured = ({
  String method,
  String url,
  http.IncomingHttpHeaders headers,
  Uint8List body,
});

/**
 * "AWS-side" verification: recompute the signature from the REAL secret
 * over the request exactly as the upstream received it, and compare.
 */
void verifyUpstreamSignature(
  Captured captured, [
  ({String? secret, String? akid}) opts = (secret: null, akid: null),
]) {
  final auth = parseSigv4Authorization(
    singleHeader(captured.headers['authorization'])!,
  );
  expect(auth, isNotNull);
  expect(auth!.accessKeyId, opts.akid ?? REAL_AKID);
  final contentSha = singleHeader(captured.headers['x-amz-content-sha256']);
  final payloadHash = contentSha == UNSIGNED_PAYLOAD
      ? UNSIGNED_PAYLOAD
      : sha256Hex(captured.body);
  final expected = signSigv4(
    Sigv4SignInput(
      method: captured.method,
      requestTarget: captured.url,
      headers: captured.headers,
      hostHeader: singleHeader(captured.headers['host'])!,
      signedHeaders: auth.signedHeaders,
      payloadHash: payloadHash,
      amzDate: singleHeader(captured.headers['x-amz-date'])!,
      scope: (date: auth.date, region: auth.region, service: auth.service),
      accessKeyId: auth.accessKeyId,
      secretAccessKey: opts.secret ?? REAL_SECRET,
    ),
  );
  expect(auth.signature, expected.signature);
}

typedef CurlResult = ({int exit, int status, String body});

Future<CurlResult> curlViaProxy(
  int proxyPort,
  String url, {
  List<String>? headers,
  String? method,
  String? data,
  /** Path to a file sent as the request body (--data-binary @file). */
  String? dataFile,
  ({String akid, String secret})? awsSigv4,
}) async {
  final args = <String>[
    '-sS',
    '--proxy',
    'http://127.0.0.1:$proxyPort',
    // An empty list overrides NO_PROXY, which would send curl around
    // the proxy under test for 127.0.0.1.
    '--noproxy',
    '',
    '--max-time',
    '10',
    '-D',
    '-',
    '--cacert',
    CA_CERT,
  ];
  if (method != null && method.isNotEmpty) args.addAll(['-X', method]);
  if (data != null) args.addAll(['--data-binary', data]);
  if (dataFile != null) args.addAll(['--data-binary', '@$dataFile']);
  if (awsSigv4 != null) {
    args.addAll([
      '--aws-sigv4',
      'aws:amz:$REGION:$SERVICE',
      '--user',
      '${awsSigv4.akid}:${awsSigv4.secret}',
    ]);
  }
  for (final h in headers ?? <String>[]) {
    args.addAll(['-H', h]);
  }
  args.add(url);

  // Dart: dart:io's Process.start; its streams decode and end as Node's do.
  final child = await Process.start('curl', args);
  final outFuture = child.stdout.transform(utf8.decoder).join();
  final errFuture = child.stderr.transform(utf8.decoder).join();
  final out = await outFuture;
  final err = await errFuture;
  final exit = await child.exitCode;
  final sep = out.lastIndexOf('\r\n\r\n');
  final headerPart = sep >= 0 ? out.substring(0, sep) : out;
  final body = sep >= 0 ? out.substring(sep + 4) : '';
  final blocks = headerPart.split(RegExp(r'\r\n\r\n'));
  final m = RegExp(
    r'HTTP/[\d.]+ (\d+)',
  ).firstMatch(blocks.isNotEmpty ? blocks[blocks.length - 1] : '');
  return (
    exit: exit,
    status: m != null ? int.parse(m[1]!) : 0,
    body: body.isNotEmpty ? body : err,
  );
}

// Dart: upstream's `state` object literal, as a class.
class _State {
  _State({
    required this.ca,
    required this.sentinels,
    required this.fakeAkid,
    required this.fakeSecret,
    required this.fakeToken,
  });
  MitmCA ca;
  SentinelRegistry sentinels;
  String fakeAkid;
  String fakeSecret;
  String? fakeToken;
  net.NodeServer? upstream;
  int? upstreamPort;
  net.NodeServer? proxy;
  int? proxyPort;
  Captured? captured;
}

/** One TLS upstream + one terminating proxy with the given SigV4 config. */
({_State state, Future<void> Function() start, Future<void> Function() stop})
makeStack({
  Sigv4Config? sigv4,
  bool? sessionToken,
  int? maxSigv4ResignBodyBytes,
  /** Also wire request-BODY sentinel substitution (body-substitution.ts). */
  bool? bodySubstitution,
}) {
  final ca = createMitmCA(caCertPath: CA_CERT, caKeyPath: CA_KEY);
  final sentinels = SentinelRegistry();
  final pairs = AwsPairRegistry();
  final fakeAkid = sentinels.register('AWS_ACCESS_KEY_ID', REAL_AKID, [DEST]);
  final fakeSecret = sentinels.register('AWS_SECRET_ACCESS_KEY', REAL_SECRET, [
    DEST,
  ]);
  String? fakeToken;
  if (sessionToken == true) {
    fakeToken = sentinels.register('AWS_SESSION_TOKEN', REAL_TOKEN, [DEST]);
  }
  pairs.register(
    AwsCredentialPair(
      accessKeyIdSentinel: fakeAkid,
      realAccessKeyId: REAL_AKID,
      realSecretAccessKey: REAL_SECRET,
      realSessionToken: sessionToken == true ? REAL_TOKEN : null,
      injectHosts: [DEST],
    ),
  );

  final state = _State(
    ca: ca,
    sentinels: sentinels,
    fakeAkid: fakeAkid,
    fakeSecret: fakeSecret,
    fakeToken: fakeToken,
  );

  Future<void> start() async {
    final upCert = mintLeafCert(ca, DEST);
    final upLeafOnly = RegExp(
      r'-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----\r?\n?',
    ).firstMatch(upCert.certPem)![0]!;
    final upstream = https.createServer(
      {'cert': upLeafOnly, 'key': upCert.keyPem},
      (http.IncomingMessage req, http.ServerResponse res) {
        final chunks = <Uint8List>[];
        req.on('data', (Object? c) => chunks.add(c as Uint8List));
        req.on('end', () {
          state.captured = (
            method: req.method!,
            url: req.url!,
            headers: req.headers,
            body: Uint8List.fromList([for (final c in chunks) ...c]),
          );
          res.writeHead(200, {'content-type': 'text/plain'});
          res.end('ok');
        });
      },
    );
    final upstreamListening = Completer<void>();
    upstream.listen(0, DEST, () => upstreamListening.complete());
    await upstreamListening.future;
    state.upstream = upstream;
    state.upstreamPort = (upstream.address() as net.NodeAddress).port;

    final proxy = createHttpProxyServer(
      _HttpOptions(
        mitmCA: ca,
        tlsTerminateUpstreamCA: CA_PEM,
        mutateHeaders: (headers, destHost) =>
            sentinels.substituteInHeaders(headers, destHost, eq),
        getBodySubstitutions: bodySubstitution == true
            ? (String destHost) => sentinels.sentinelsForHost(destHost, eq)
            : null,
        planSigv4: createSigv4Planner(pairs, sigv4, eq),
        maxSigv4ResignBodyBytes: maxSigv4ResignBodyBytes,
      ),
    );
    final proxyListening = Completer<void>();
    proxy.listen(0, '127.0.0.1', () => proxyListening.complete());
    await proxyListening.future;
    state.proxy = proxy;
    state.proxyPort = (proxy.address() as net.NodeAddress).port;
  }

  Future<void> stop() async {
    if (state.proxy != null) {
      final closed = Completer<void>();
      state.proxy!.close(() => closed.complete());
      await closed.future;
    }
    if (state.upstream != null) {
      final closed = Completer<void>();
      state.upstream!.close(() => closed.complete());
      await closed.future;
    }
    await disposeMitmCA(ca);
  }

  return (state: state, start: start, stop: stop);
}

void main() {
  group('SigV4 re-signing through the TLS-terminating proxy', skip: _tlsSkip, () {
    final stack = makeStack(sessionToken: true);
    final state = stack.state;

    setUpAll(stack.start);
    tearDownAll(stack.stop);

    test(
      'curl --aws-sigv4 with fake creds: upstream sees a valid real-credential signature',
      timeout: const Timeout(Duration(milliseconds: 20000)),
      () async {
        state.captured = null;
        final r = await curlViaProxy(
          state.proxyPort!,
          'https://$DEST:${state.upstreamPort}/bucket/key?list-type=2&prefix=a%20b',
          awsSigv4: (akid: state.fakeAkid, secret: state.fakeSecret),
        );
        expect(r.exit, 0);
        expect(r.status, 200);
        final captured = state.captured!;
        expect(captured, isNotNull);

        // The scope carries the REAL access key id...
        final auth = singleHeader(captured.headers['authorization'])!;
        expect(auth, contains('Credential=$REAL_AKID/'));
        expect(auth, contains('/$REGION/$SERVICE/aws4_request'));
        // ...and the signature verifies against the REAL secret over the
        // request as received (the upstream's own recomputation).
        verifyUpstreamSignature(captured);
        // Nothing fake leaked upstream.
        expect(jsonEncode(captured.headers), isNot(contains(state.fakeAkid)));
        expect(jsonEncode(captured.headers), isNot(contains(state.fakeSecret)));
      },
    );

    test(
      'POST with a body: hash recomputed over the forwarded bytes, body intact',
      timeout: const Timeout(Duration(milliseconds: 20000)),
      () async {
        state.captured = null;
        const body = 'Param1=value1&Param2=value2';
        final r = await curlViaProxy(
          state.proxyPort!,
          'https://$DEST:${state.upstreamPort}/',
          awsSigv4: (akid: state.fakeAkid, secret: state.fakeSecret),
          data: body,
          headers: ['Content-Type: application/x-www-form-urlencoded'],
        );
        expect(r.exit, 0);
        expect(r.status, 200);
        final captured = state.captured!;
        expect(utf8.decode(captured.body), body);
        // curl signs the body hash without emitting x-amz-content-sha256, so
        // the proxy had to buffer the body and recompute the hash itself —
        // the recomputed signature only verifies if it covers sha256(body).
        verifyUpstreamSignature(captured);
      },
    );

    test(
      'DELETE with a chunked literal-hash body: proxy re-frames with content-length',
      timeout: const Timeout(Duration(milliseconds: 20000)),
      () async {
        // The unsound case needs a client that sends its body chunked WITHOUT
        // signing Transfer-Encoding (curl signs every header it sends, so this
        // is hand-rolled with the repo's own signing primitives). Without the
        // unconditional content-length restore, Node's end(Buffer) emits NO
        // framing for bodyless-default methods — the upstream parses an empty
        // DELETE and the raw-appended body poisons the connection (verified:
        // 400 + empty body on Node). Bun auto-computes a content-length, so
        // under bun this pins the e2e scenario rather than the regression.
        state.captured = null;
        const body = 'delete-with-chunked-body';
        final payloadHash = sha256Hex(Uint8List.fromList(utf8.encode(body)));
        final amzDate = DateTime.now()
            .toUtc()
            .toIso8601String()
            .replaceAll(RegExp(r'[-:]'), '')
            .replaceFirst(RegExp(r'\..*'), 'Z');
        final scope = (
          date: amzDate.substring(0, 8),
          region: REGION,
          service: SERVICE,
        );
        final hostHeader = '$DEST:${state.upstreamPort}';
        final signed = signSigv4(
          Sigv4SignInput(
            method: 'DELETE',
            requestTarget: '/bucket/key',
            headers: {
              'x-amz-content-sha256': payloadHash,
              'x-amz-date': amzDate,
            },
            hostHeader: hostHeader,
            signedHeaders: ['host', 'x-amz-content-sha256', 'x-amz-date'],
            payloadHash: payloadHash,
            amzDate: amzDate,
            scope: scope,
            accessKeyId: state.fakeAkid,
            secretAccessKey: state.fakeSecret,
          ),
        );
        final statusDone = Completer<String>();
        void resolve(String v) {
          if (!statusDone.isCompleted) statusDone.complete(v);
        }

        var resp = '';
        late final net.NodeSocket raw;
        raw = net.connect(state.proxyPort!, '127.0.0.1', () {
          raw.write(
            'CONNECT $DEST:${state.upstreamPort} HTTP/1.1\r\nHost: $DEST:${state.upstreamPort}\r\n\r\n',
          );
        });
        raw.on('error', (Object? _) {});
        raw.once('data', (Object? _) {
          late final tls.TLSSocket tlsSocket;
          tlsSocket = tls.connect(
            // SNI cannot carry an IP literal; the CA is pinned, so skip the
            // hostname identity check instead.
            {
              'socket': raw,
              'ca': CA_PEM,
              'checkServerIdentity': (Object? a, Object? b) => null,
            },
            () {
              tlsSocket.write(
                'DELETE /bucket/key HTTP/1.1\r\n'
                'Host: $hostHeader\r\n'
                'Authorization: ${signed.authorization}\r\n'
                'x-amz-date: $amzDate\r\n'
                'x-amz-content-sha256: $payloadHash\r\n'
                'Transfer-Encoding: chunked\r\n'
                '\r\n'
                '${body.length.toRadixString(16)}\r\n$body\r\n0\r\n\r\n',
              );
            },
          );
          tlsSocket.on('data', (Object? d) {
            resp += utf8.decode(d as List<int>);
            if (resp.contains('\r\n\r\n')) {
              tlsSocket.destroy();
              resolve(resp.split('\r\n')[0]);
            }
          });
          tlsSocket.on('error', (Object? _) => resolve(resp.split('\r\n')[0]));
        });
        Timer(
          const Duration(milliseconds: 8000),
          () => resolve(resp.split('\r\n')[0]),
        );
        final status = await statusDone.future;
        expect(status, contains('200'));
        final captured = state.captured!;
        expect(captured, isNotNull);
        expect(captured.method, 'DELETE');
        expect(utf8.decode(captured.body), body);
        expect(
          singleHeader(captured.headers['content-length']),
          '${body.length}',
        );
        verifyUpstreamSignature(captured);
      },
    );

    test(
      'the real session token is injected and covered by the signature',
      timeout: const Timeout(Duration(milliseconds: 20000)),
      () async {
        state.captured = null;
        final r = await curlViaProxy(
          state.proxyPort!,
          'https://$DEST:${state.upstreamPort}/',
          awsSigv4: (akid: state.fakeAkid, secret: state.fakeSecret),
        );
        expect(r.exit, 0);
        expect(r.status, 200);
        final captured = state.captured!;
        expect(
          singleHeader(captured.headers['x-amz-security-token']),
          REAL_TOKEN,
        );
        final auth = parseSigv4Authorization(
          singleHeader(captured.headers['authorization'])!,
        )!;
        expect(auth.signedHeaders, contains('x-amz-security-token'));
        verifyUpstreamSignature(captured);
      },
    );

    test(
      'UNSIGNED-PAYLOAD: re-signed without hashing the body',
      timeout: const Timeout(Duration(milliseconds: 20000)),
      () async {
        // Hand-signed client request (curl --aws-sigv4 always hashes), using
        // the vector-pinned signer with the FAKE credentials — the same
        // bytes a real SDK configured for UNSIGNED-PAYLOAD would produce.
        state.captured = null;
        const amzDate = '20260715T000000Z';
        final hostHeader = '$DEST:${state.upstreamPort}';
        final http.IncomingHttpHeaders headers = {
          'x-amz-date': amzDate,
          'x-amz-content-sha256': UNSIGNED_PAYLOAD,
        };
        final authorization = signSigv4(
          Sigv4SignInput(
            method: 'PUT',
            requestTarget: '/bucket/key',
            headers: headers,
            hostHeader: hostHeader,
            signedHeaders: ['host', 'x-amz-date', 'x-amz-content-sha256'],
            payloadHash: UNSIGNED_PAYLOAD,
            amzDate: amzDate,
            scope: (date: '20260715', region: REGION, service: SERVICE),
            accessKeyId: state.fakeAkid,
            secretAccessKey: state.fakeSecret,
          ),
        ).authorization;
        final r = await curlViaProxy(
          state.proxyPort!,
          'https://$DEST:${state.upstreamPort}/bucket/key',
          method: 'PUT',
          data: 'streamed-bytes',
          headers: [
            'Authorization: $authorization',
            'X-Amz-Date: $amzDate',
            'X-Amz-Content-Sha256: $UNSIGNED_PAYLOAD',
          ],
        );
        expect(r.exit, 0);
        expect(r.status, 200);
        final captured = state.captured!;
        expect(utf8.decode(captured.body), 'streamed-bytes');
        // Marker preserved; signature covers the marker, not a body hash.
        expect(
          singleHeader(captured.headers['x-amz-content-sha256']),
          UNSIGNED_PAYLOAD,
        );
        verifyUpstreamSignature(captured);
      },
    );

    test(
      'an AWS-shaped request with unmasked credentials is untouched',
      timeout: const Timeout(Duration(milliseconds: 20000)),
      () async {
        state.captured = null;
        const otherAkid = 'AKIDUNRELATEDEXAMPLE';
        const otherSecret = 'unrelated-real-secret-the-proxy-never-saw';
        const amzDate = '20260715T000000Z';
        final authorization = signSigv4(
          Sigv4SignInput(
            method: 'GET',
            requestTarget: '/',
            headers: {'x-amz-date': amzDate},
            hostHeader: '$DEST:${state.upstreamPort}',
            signedHeaders: ['host', 'x-amz-date'],
            payloadHash: sha256Hex(''),
            amzDate: amzDate,
            scope: (date: '20260715', region: REGION, service: SERVICE),
            accessKeyId: otherAkid,
            secretAccessKey: otherSecret,
          ),
        ).authorization;
        final r = await curlViaProxy(
          state.proxyPort!,
          'https://$DEST:${state.upstreamPort}/',
          headers: ['Authorization: $authorization', 'X-Amz-Date: $amzDate'],
        );
        expect(r.exit, 0);
        expect(r.status, 200);
        // Byte-identical Authorization upstream: never rewritten, never denied.
        expect(
          singleHeader(state.captured!.headers['authorization']),
          authorization,
        );
        verifyUpstreamSignature(state.captured!, (
          akid: otherAkid,
          secret: otherSecret,
        ));
      },
    );

    test(
      'a signed hop-by-hop header fails closed instead of crashing the proxy',
      timeout: const Timeout(Duration(milliseconds: 20000)),
      () async {
        // The client lists a header in SignedHeaders that it also declares
        // hop-by-hop via Connection, so the proxy strips it before signing.
        // The plan must see the post-strip header set and deny — not throw
        // inside the signer after claiming the request.
        state.captured = null;
        const amzDate = '20260715T000000Z';
        final r = await curlViaProxy(
          state.proxyPort!,
          'https://$DEST:${state.upstreamPort}/',
          headers: [
            'Authorization: AWS4-HMAC-SHA256 Credential=${state.fakeAkid}/20260715/$REGION/$SERVICE/aws4_request, '
                'SignedHeaders=host;x-amz-date;x-custom, Signature=ff00',
            'X-Amz-Date: $amzDate',
            'Connection: x-custom',
            'X-Custom: value',
          ],
        );
        expect(r.status, 403);
        expect(r.body, contains('x-custom'));
        expect(state.captured, isNull);
        // The proxy survived: a follow-up request still works.
        final r2 = await curlViaProxy(
          state.proxyPort!,
          'https://$DEST:${state.upstreamPort}/',
          awsSigv4: (akid: state.fakeAkid, secret: state.fakeSecret),
        );
        expect(r2.status, 200);
      },
    );

    test(
      'a non-AWS request with a masked sentinel still gets plain substitution',
      timeout: const Timeout(Duration(milliseconds: 20000)),
      () async {
        state.captured = null;
        final r = await curlViaProxy(
          state.proxyPort!,
          'https://$DEST:${state.upstreamPort}/',
          headers: ['X-Api-Key: ${state.fakeAkid}'],
        );
        expect(r.exit, 0);
        expect(r.status, 200);
        expect(singleHeader(state.captured!.headers['x-api-key']), REAL_AKID);
      },
    );
  });

  group('literal-hash body buffering cap', skip: _tlsSkip, () {
    // The production 64 MiB cap (MAX_SIGV4_RESIGN_BODY_BYTES) is injected
    // smaller here so the over-cap denial doesn't need a 64 MiB fixture
    // upload per test; the mechanism under test is identical.
    const CAP = 256 * 1024;
    final stack = makeStack(maxSigv4ResignBodyBytes: CAP);
    final state = stack.state;
    late String bodyDir;
    late String underCapFile;
    late String overCapFile;

    setUpAll(() async {
      await stack.start();
      bodyDir = mkdtempSync(join(tmpdir(), 'srt-sigv4-body-'));
      underCapFile = join(bodyDir, 'under');
      overCapFile = join(bodyDir, 'over');
      writeFileSync(underCapFile, Uint8List(CAP)..fillRange(0, CAP, 0x61));
      writeFileSync(
        overCapFile,
        Uint8List(CAP + 1)..fillRange(0, CAP + 1, 0x61),
      );
    });
    tearDownAll(() async {
      rmSync(bodyDir, {'recursive': true, 'force': true});
      await stack.stop();
    });

    test('the default cap is the exported 64 MiB constant', () {
      expect(MAX_SIGV4_RESIGN_BODY_BYTES, 64 * 1024 * 1024);
    });

    test(
      'a body at the cap is buffered and re-signed',
      timeout: const Timeout(Duration(milliseconds: 30000)),
      () async {
        state.captured = null;
        final r = await curlViaProxy(
          state.proxyPort!,
          'https://$DEST:${state.upstreamPort}/bucket/key',
          method: 'PUT',
          dataFile: underCapFile,
          awsSigv4: (akid: state.fakeAkid, secret: state.fakeSecret),
          // curl sends Expect: 100-continue for large bodies; disable so
          // the flow matches the small-body tests.
          headers: ['Expect:'],
        );
        expect(r.exit, 0);
        expect(r.status, 200);
        final captured = state.captured!;
        expect(captured.body.length, CAP);
        verifyUpstreamSignature(captured);
      },
    );

    test(
      'a body over the cap fails closed with a 403, nothing upstream',
      timeout: const Timeout(Duration(milliseconds: 30000)),
      () async {
        state.captured = null;
        final r = await curlViaProxy(
          state.proxyPort!,
          'https://$DEST:${state.upstreamPort}/bucket/key',
          method: 'PUT',
          dataFile: overCapFile,
          awsSigv4: (akid: state.fakeAkid, secret: state.fakeSecret),
          headers: ['Expect:'],
        );
        expect(r.status, 403);
        expect(r.body, contains('$CAP-byte'));
        expect(r.body, contains('UNSIGNED-PAYLOAD'));
        expect(state.captured, isNull);
        // The proxy survived: a follow-up request still works.
        final r2 = await curlViaProxy(
          state.proxyPort!,
          'https://$DEST:${state.upstreamPort}/',
          awsSigv4: (akid: state.fakeAkid, secret: state.fakeSecret),
        );
        expect(r2.status, 200);
      },
    );
  });

  group('multi-megabyte upload through the terminating relay', skip: _tlsSkip, () {
    // Regression test for the client→inner relay in terminateAndForward:
    // under Bun, pipe()'s pause/resume flow control corrupted the TLS byte
    // stream once a large upload queued writes (client saw bad_record_mac /
    // a mid-upload reset). 16 MiB trips the old code near-deterministically;
    // the relay must deliver every byte intact. See relayPullMode.
    const SIZE = 16 * 1024 * 1024;
    final stack = makeStack(maxSigv4ResignBodyBytes: SIZE);
    final state = stack.state;
    late String bodyDir;
    late String bigFile;

    setUpAll(() async {
      await stack.start();
      bodyDir = mkdtempSync(join(tmpdir(), 'srt-sigv4-big-'));
      bigFile = join(bodyDir, 'big');
      writeFileSync(bigFile, Uint8List(SIZE)..fillRange(0, SIZE, 0x61));
    });
    tearDownAll(() async {
      rmSync(bodyDir, {'recursive': true, 'force': true});
      await stack.stop();
    });

    test(
      'a 16 MiB literal-hash PUT uploads intact and re-signs',
      timeout: const Timeout(Duration(milliseconds: 30000)),
      () async {
        state.captured = null;
        final r = await curlViaProxy(
          state.proxyPort!,
          'https://$DEST:${state.upstreamPort}/bucket/big',
          method: 'PUT',
          dataFile: bigFile,
          awsSigv4: (akid: state.fakeAkid, secret: state.fakeSecret),
          headers: ['Expect:'],
        );
        expect(r.exit, 0);
        expect(r.status, 200);
        final captured = state.captured!;
        expect(captured.body.length, SIZE);
        // Byte-intact, not just length-intact: the historical failure mode was
        // corruption inside the stream, which TLS turns into a hard error, but
        // assert content anyway so a silent-corruption regression cannot pass.
        expect(captured.body.every((b) => b == 0x61), true);
        verifyUpstreamSignature(captured);
      },
    );
  });

  group('policies for non-re-signable SigV4 shapes', skip: _tlsSkip, () {
    List<String> streamingHeaders(String fakeAkid) {
      return [
        'Authorization: AWS4-HMAC-SHA256 Credential=$fakeAkid/20260715/$REGION/$SERVICE/aws4_request, '
            'SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=ff00',
        'X-Amz-Date: 20260715T000000Z',
        'X-Amz-Content-Sha256: STREAMING-AWS4-HMAC-SHA256-PAYLOAD',
        'Content-Encoding: aws-chunked',
      ];
    }

    List<String> sigv4aHeaders(String fakeAkid) {
      return [
        'Authorization: AWS4-ECDSA-P256-SHA256 Credential=$fakeAkid/20260715/$SERVICE/aws4_request, '
            'SignedHeaders=host;x-amz-date;x-amz-region-set, Signature=ff00',
        'X-Amz-Date: 20260715T000000Z',
        'X-Amz-Region-Set: *',
      ];
    }

    String presignedTarget(String fakeAkid) {
      return '/key?X-Amz-Algorithm=AWS4-HMAC-SHA256'
          '&X-Amz-Credential=${Uri.encodeComponent('$fakeAkid/20260715/$REGION/$SERVICE/aws4_request')}'
          '&X-Amz-Date=20260715T000000Z&X-Amz-Expires=3600'
          '&X-Amz-SignedHeaders=host&X-Amz-Signature=ff00';
    }

    group('default: deny with a clear error naming the case', skip: _tlsSkip, () {
      final stack = makeStack();
      final state = stack.state;
      setUpAll(stack.start);
      tearDownAll(stack.stop);

      test(
        'streaming',
        timeout: const Timeout(Duration(milliseconds: 20000)),
        () async {
          state.captured = null;
          final r = await curlViaProxy(
            state.proxyPort!,
            'https://$DEST:${state.upstreamPort}/bucket/key',
            method: 'PUT',
            data: 'chunked',
            headers: streamingHeaders(state.fakeAkid),
          );
          expect(r.status, 403);
          expect(r.body, contains('streaming'));
          expect(r.body, contains('credentials.sigv4.streaming'));
          expect(state.captured, isNull);
        },
      );

      test(
        'presigned',
        timeout: const Timeout(Duration(milliseconds: 20000)),
        () async {
          state.captured = null;
          final r = await curlViaProxy(
            state.proxyPort!,
            'https://$DEST:${state.upstreamPort}${presignedTarget(state.fakeAkid)}',
          );
          expect(r.status, 403);
          expect(r.body, contains('presigned'));
          expect(r.body, contains('credentials.sigv4.presigned'));
          expect(state.captured, isNull);
        },
      );

      test(
        'sigv4a',
        timeout: const Timeout(Duration(milliseconds: 20000)),
        () async {
          state.captured = null;
          final r = await curlViaProxy(
            state.proxyPort!,
            'https://$DEST:${state.upstreamPort}/',
            headers: sigv4aHeaders(state.fakeAkid),
          );
          expect(r.status, 403);
          expect(r.body, contains('sigv4a'));
          expect(r.body, contains('credentials.sigv4.sigv4a'));
          expect(state.captured, isNull);
        },
      );

      test(
        'a presigned URL with an unmasked key id is not denied',
        timeout: const Timeout(Duration(milliseconds: 20000)),
        () async {
          state.captured = null;
          final r = await curlViaProxy(
            state.proxyPort!,
            'https://$DEST:${state.upstreamPort}${presignedTarget('AKIDUNRELATEDEXAMPLE')}',
          );
          expect(r.status, 200);
          expect(state.captured, isNotNull);
        },
      );

      test(
        'a junk Authorization header does not bypass the presigned policy',
        timeout: const Timeout(Duration(milliseconds: 20000)),
        () async {
          state.captured = null;
          final r = await curlViaProxy(
            state.proxyPort!,
            'https://$DEST:${state.upstreamPort}${presignedTarget(state.fakeAkid)}',
            headers: ['Authorization: Basic dXNlcjpwYXNz'],
          );
          expect(r.status, 403);
          expect(r.body, contains('presigned'));
          expect(state.captured, isNull);
        },
      );

      test(
        'junk Authorization + unmasked presigned query stays untouched',
        timeout: const Timeout(Duration(milliseconds: 20000)),
        () async {
          state.captured = null;
          const junkAuth = 'Basic dXNlcjpwYXNz';
          final r = await curlViaProxy(
            state.proxyPort!,
            'https://$DEST:${state.upstreamPort}${presignedTarget('AKIDUNRELATEDEXAMPLE')}',
            headers: ['Authorization: $junkAuth'],
          );
          expect(r.status, 200);
          expect(
            singleHeader(state.captured!.headers['authorization']),
            junkAuth,
          );
          expect(state.captured!.url, contains('X-Amz-Signature=ff00'));
        },
      );
    });

    group('passthrough when configured', skip: _tlsSkip, () {
      final stack = makeStack(
        sigv4: const Sigv4Config(
          streaming: 'passthrough',
          presigned: 'passthrough',
          sigv4a: 'passthrough',
        ),
      );
      final state = stack.state;
      setUpAll(stack.start);
      tearDownAll(stack.stop);

      test(
        'each shape is forwarded un-resigned',
        timeout: const Timeout(Duration(milliseconds: 30000)),
        () async {
          // streaming
          state.captured = null;
          var r = await curlViaProxy(
            state.proxyPort!,
            'https://$DEST:${state.upstreamPort}/bucket/key',
            method: 'PUT',
            data: 'chunked',
            headers: streamingHeaders(state.fakeAkid),
          );
          expect(r.status, 200);
          var auth = singleHeader(state.captured!.headers['authorization'])!;
          // Not re-signed: the client's fake-secret signature survives (and
          // will fail at a real upstream). Ordinary sentinel substitution
          // still ran on the header text.
          expect(auth, contains('Signature=ff00'));
          expect(auth, contains('Credential=$REAL_AKID/'));

          // presigned
          state.captured = null;
          r = await curlViaProxy(
            state.proxyPort!,
            'https://$DEST:${state.upstreamPort}${presignedTarget(state.fakeAkid)}',
          );
          expect(r.status, 200);
          expect(state.captured!.url, contains('X-Amz-Signature=ff00'));

          // sigv4a
          state.captured = null;
          r = await curlViaProxy(
            state.proxyPort!,
            'https://$DEST:${state.upstreamPort}/',
            headers: sigv4aHeaders(state.fakeAkid),
          );
          expect(r.status, 200);
          auth = singleHeader(state.captured!.headers['authorization'])!;
          expect(auth, startsWith('AWS4-ECDSA-P256-SHA256'));
          expect(auth, contains('Signature=ff00'));
        },
      );
    });
  });

  group('body substitution composes with SigV4 re-signing', skip: _tlsSkip, () {
    // Ordering contract under test: when a literal-hash SigV4 request
    // carries body-injectable sentinels, the proxy buffers the SUBSTITUTED
    // stream (body → bodyTransform → collectBody), hashes that, and signs —
    // the signature must cover the bytes actually sent upstream, never the
    // sentinel-bearing bytes the client wrote.
    final stack = makeStack(bodySubstitution: true);
    final state = stack.state;
    setUpAll(stack.start);
    tearDownAll(stack.stop);

    test(
      'literal-hash POST: recomputed hash covers the substituted body (length-matched)',
      timeout: const Timeout(Duration(milliseconds: 20000)),
      () async {
        // Real value ≥ 47 bytes → the sentinel is padded to the same length,
        // so substitution cannot change the body length.
        final real = 'real-api-token-' + 'x' * 45;
        final fake = state.sentinels.register('API_TOKEN_LONG', real, [DEST]);
        expect(fake.length, real.length);

        state.captured = null;
        final body = jsonEncode({'token': fake, 'note': 'sentinel in body'});
        final r = await curlViaProxy(
          state.proxyPort!,
          'https://$DEST:${state.upstreamPort}/compose/long',
          awsSigv4: (akid: state.fakeAkid, secret: state.fakeSecret),
          data: body,
          headers: ['Content-Type: application/json'],
        );
        expect(r.exit, 0);
        expect(r.status, 200);
        final captured = state.captured!;
        // Body substitution ran: upstream got the REAL token, never the fake.
        expect(utf8.decode(captured.body), contains(real));
        expect(utf8.decode(captured.body), isNot(contains(fake)));
        // Length-matched → framing untouched.
        expect(
          singleHeader(captured.headers['content-length']),
          '${utf8.encode(body).length}',
        );
        // The crux: verifyUpstreamSignature recomputes the hash over the
        // body AS RECEIVED (post-substitution); the proxy's signature only
        // verifies if it hashed the substituted bytes too.
        verifyUpstreamSignature(captured);
      },
    );

    test(
      'literal-hash POST: short secret re-frames; signature and Content-Length track the substituted body',
      timeout: const Timeout(Duration(milliseconds: 20000)),
      () async {
        // Real value < 47 bytes → the sentinel is longer than the real value,
        // substitution shrinks the body, and the buffered length becomes the
        // outgoing Content-Length.
        const real = 'short-real-token';
        final fake = state.sentinels.register('API_TOKEN_SHORT', real, [DEST]);
        expect(fake.length, greaterThan(real.length));

        state.captured = null;
        final body = jsonEncode({'token': fake});
        final r = await curlViaProxy(
          state.proxyPort!,
          'https://$DEST:${state.upstreamPort}/compose/short',
          awsSigv4: (akid: state.fakeAkid, secret: state.fakeSecret),
          data: body,
          headers: ['Content-Type: application/json'],
        );
        expect(r.exit, 0);
        expect(r.status, 200);
        final captured = state.captured!;
        expect(utf8.decode(captured.body), contains(real));
        expect(utf8.decode(captured.body), isNot(contains(fake)));
        // Re-framed to the substituted (shorter) length, not the client's.
        expect(captured.body.length, lessThan(utf8.encode(body).length));
        expect(
          singleHeader(captured.headers['content-length']),
          '${captured.body.length}',
        );
        verifyUpstreamSignature(captured);
      },
    );
  });
}
