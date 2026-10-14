// Ported from sandbox-runtime test/sandbox/credential-mask-body.test.ts @ 24eb39e.
// ignore_for_file: constant_identifier_names, non_constant_identifier_names, slash_for_doc_comments
import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:path/path.dart' as path;
import 'package:sandbox_runtime/src/node/fs.dart'
    show mkdtempSync, readFileSync, rmSync, writeFileSync;
import 'package:sandbox_runtime/src/node/http.dart' as http;
import 'package:sandbox_runtime/src/node/https.dart' as https;
import 'package:sandbox_runtime/src/node/net.dart' as net;
import 'package:sandbox_runtime/src/node/os.dart' show tmpdir;
import 'package:sandbox_runtime/src/node/zlib.dart' show gzipSync;
import 'package:sandbox_runtime/src/sandbox/body_substitution.dart';
import 'package:sandbox_runtime/src/sandbox/credential_sentinel.dart';
import 'package:sandbox_runtime/src/sandbox/http_proxy.dart';
import 'package:sandbox_runtime/src/sandbox/mitm_ca.dart';
import 'package:sandbox_runtime/src/sandbox/mitm_leaf.dart';
import 'package:sandbox_runtime/src/sandbox/request_filter.dart';
import 'package:test/test.dart';

import '../helpers/emitted_connections.dart' show testWithTls;

/**
 * End-to-end tests for masked-credential substitution in request BODIES:
 * a sandboxed client sends the sentinel (fake) in a JSON / form / multipart
 * body, and the upstream must receive the real secret with valid framing.
 * Driven with curl like tls-terminate-proxy.test.ts, so a real
 * CONNECT-through-proxy client exercises the terminated path.
 */

// Committed test-only CA — see test/fixtures/tls-terminate/README.md.
final FIXTURE_DIR = path.join(
  Directory.current.path, // import.meta.dir, '..'
  'test',
  'fixtures',
  'tls-terminate',
);
final CA_CERT = path.join(FIXTURE_DIR, 'ca.crt');
final CA_KEY = path.join(FIXTURE_DIR, 'ca.key');
final CA_PEM = readFileSync(CA_CERT, 'utf8') as String;

// Longer than the 47-byte base sentinel, so register() length-matches it.
const REAL_LONG = 'ghp_realsecret_0123456789abcdef_0123456789abcdef_0123456789';
// Shorter than the base sentinel — register() keeps 47 bytes, NOT matched.
const REAL_SHORT = 'ghp_short';

/** Host matcher for tests: exact equality. */
bool eq(String h, String p) => h == p;

typedef SeenRequest = ({
  String method,
  String url,
  http.IncomingHttpHeaders headers,
  Uint8List body,
});

// Dart: the object literal upstream hands createHttpProxyServer; every
// option not named here is absent (null).
class _HttpOptions implements HttpProxyServerOptions {
  _HttpOptions({
    this.mitmCA,
    this.tlsTerminateUpstreamCA,
    this.mutateHeaders,
    this.mutateHeadersPlaintext,
    this.getBodySubstitutions,
    this.getBodySubstitutionsPlaintext,
  });
  @override
  final MitmCA? mitmCA;
  @override
  final dynamic tlsTerminateUpstreamCA;
  @override
  final MutateForwardedHeaders? mutateHeaders;
  @override
  final MutateForwardedHeaders? mutateHeadersPlaintext;
  @override
  final GetBodySubstitutions? getBodySubstitutions;
  @override
  final GetBodySubstitutions? getBodySubstitutionsPlaintext;
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

/**
 * On the chunked-fallback path the proxy deletes the client's (now stale)
 * Content-Length and lets the runtime re-frame the upstream leg. Node
 * streams it chunked; Bun sometimes buffers a small body and sends a fresh
 * correct Content-Length instead. Both are valid framing — what must never
 * appear is the stale length, `clientSentLength`.
 */
void expectReframed(SeenRequest got, int clientSentLength) {
  final cl = got.headers['content-length'];
  if (got.headers['transfer-encoding'] == 'chunked') {
    expect(cl, isNull);
  } else {
    expect(cl, '${got.body.length}');
  }
  expect(cl, isNot('$clientSentLength'));
}

void main() {
  group('credential-mask-body: end-to-end through the TLS-terminating proxy', () {
    // Every case runs a TLS-terminating proxy: skipped where none can run.
    final test = testWithTls;
    final ca = createMitmCA(caCertPath: CA_CERT, caKeyPath: CA_KEY);

    late net.NodeServer upstream;
    late int upstreamPort;
    final seen = <SeenRequest>[];
    SeenRequest lastSeen() => seen[seen.length - 1];

    /** Proxy wired to `reg` exactly as sandbox-manager wires the registry. */
    Future<({net.NodeServer server, int port})> startProxy(
      SentinelRegistry reg,
    ) async {
      final server = createHttpProxyServer(
        _HttpOptions(
          mitmCA: ca,
          tlsTerminateUpstreamCA: CA_PEM,
          mutateHeaders: (h, d) => reg.substituteInHeaders(h, d, eq),
          getBodySubstitutions: (d) => reg.sentinelsForHost(d, eq),
        ),
      );
      final listening = Completer<void>();
      server.listen(0, '127.0.0.1', () => listening.complete());
      await listening.future;
      return (server: server, port: (server.address() as net.NodeAddress).port);
    }

    Future<void> stop(net.NodeServer s) {
      final done = Completer<void>();
      s.close(() => done.complete());
      return done.future;
    }

    setUpAll(() async {
      final upCert = mintLeafCert(ca, '127.0.0.1');
      final upLeafOnly = RegExp(
        r'-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----\r?\n?',
      ).firstMatch(upCert.certPem)!.group(0)!;
      upstream = https.createServer(
        {'cert': upLeafOnly, 'key': upCert.keyPem},
        (http.IncomingMessage req, http.ServerResponse res) {
          final chunks = <Uint8List>[];
          req.on('data', (Object? c) => chunks.add(c as Uint8List));
          req.on('end', () {
            seen.add((
              method: req.method!,
              url: req.url!,
              headers: req.headers,
              body: Uint8List.fromList([for (final c in chunks) ...c]),
            ));
            res.writeHead(200, {'x-upstream': 'ok'});
            res.end('ok');
          });
        },
      );
      final listening = Completer<void>();
      upstream.listen(0, '127.0.0.1', () => listening.complete());
      await listening.future;
      upstreamPort = (upstream.address() as net.NodeAddress).port;
    });

    tearDownAll(() async {
      await stop(upstream);
    });

    String url(String path) => 'https://127.0.0.1:$upstreamPort$path';

    test(
      'JSON body, length-matched: real secret arrives, Content-Length verbatim',
      () async {
        final reg = SentinelRegistry();
        final sentinel = reg.register('GH_TOKEN', REAL_LONG, ['127.0.0.1']);
        expect(sentinel.length, REAL_LONG.length); // length-matched
        final (:server, :port) = await startProxy(reg);
        try {
          final payload = '{"token":"$sentinel","note":"hi"}';
          final r = await curlViaProxy(
            port,
            url('/json'),
            method: 'POST',
            body: payload,
            headers: ['Content-Type: application/json'],
          );
          expect(r.exit, 0);
          expect(r.status, 200);
          final got = lastSeen();
          expect(utf8.decode(got.body), '{"token":"$REAL_LONG","note":"hi"}');
          // Same byte length → the client's Content-Length was forwarded
          // verbatim and still frames the substituted body correctly.
          expect(got.headers['content-length'], '${payload.length}');
          expect(got.headers['transfer-encoding'], isNull);
        } finally {
          await stop(server);
        }
      },
    );

    test(
      'JSON body, non-length-matched sentinel: chunked fallback, real secret arrives',
      () async {
        final reg = SentinelRegistry();
        final sentinel = reg.register('GH_TOKEN', REAL_SHORT, ['127.0.0.1']);
        expect(sentinel.length, isNot(REAL_SHORT.length));
        final (:server, :port) = await startProxy(reg);
        try {
          final payload = '{"token":"$sentinel"}';
          final r = await curlViaProxy(
            port,
            url('/json-chunked'),
            method: 'POST',
            body: payload,
            headers: ['Content-Type: application/json'],
          );
          expect(r.exit, 0);
          expect(r.status, 200);
          final got = lastSeen();
          expect(utf8.decode(got.body), '{"token":"$REAL_SHORT"}');
          // Substitution changed the body length: the client's Content-Length
          // was dropped and the upstream leg re-framed.
          expectReframed(got, payload.length);
        } finally {
          await stop(server);
        }
      },
    );

    test(
      'caller-minted sentinel (registerWithSentinel) also takes the chunked fallback',
      () async {
        final reg = SentinelRegistry();
        // Shaped fake, e.g. a JWT-form sentinel — never padded by the registry.
        const fake =
            'eyJhbGciOiJub25lIn0.fake-a1b2c3d4-5678-4abc-8def-000011112222';
        reg.registerWithSentinel('JWT', fake, REAL_LONG, ['127.0.0.1']);
        final (:server, :port) = await startProxy(reg);
        try {
          const payload = 'token=$fake';
          final r = await curlViaProxy(
            port,
            url('/jwt'),
            method: 'POST',
            body: payload,
            headers: ['Content-Type: application/x-www-form-urlencoded'],
          );
          expect(r.exit, 0);
          expect(r.status, 200);
          final got = lastSeen();
          expect(utf8.decode(got.body), 'token=$REAL_LONG');
          expectReframed(got, payload.length);
        } finally {
          await stop(server);
        }
      },
    );

    test('form-urlencoded body, length-matched path', () async {
      final reg = SentinelRegistry();
      final sentinel = reg.register('GH_TOKEN', REAL_LONG, ['127.0.0.1']);
      final (:server, :port) = await startProxy(reg);
      try {
        final payload = 'a=1&token=$sentinel&b=2';
        final r = await curlViaProxy(
          port,
          url('/form'),
          method: 'POST',
          body: payload,
          headers: ['Content-Type: application/x-www-form-urlencoded'],
        );
        expect(r.exit, 0);
        expect(r.status, 200);
        final got = lastSeen();
        expect(utf8.decode(got.body), 'a=1&token=$REAL_LONG&b=2');
        expect(got.headers['content-length'], '${payload.length}');
      } finally {
        await stop(server);
      }
    });

    test(
      'multipart body: sentinel inside a part is substituted, framing intact',
      () async {
        final reg = SentinelRegistry();
        final sentinel = reg.register('GH_TOKEN', REAL_LONG, ['127.0.0.1']);
        final (:server, :port) = await startProxy(reg);
        try {
          final r = await curlViaProxy(
            port,
            url('/multipart'),
            formFields: [('token', sentinel), ('name', 'unrelated')],
          );
          expect(r.exit, 0);
          expect(r.status, 200);
          final got = lastSeen();
          final body = utf8.decode(got.body);
          expect(body, contains(REAL_LONG));
          expect(body, isNot(contains(sentinel)));
          expect(body, contains('name="name"'));
          // Length-matched substitution → curl's multipart Content-Length still
          // frames the body exactly.
          expect(got.headers['content-length'], '${got.body.length}');
          final boundary = RegExp(
            r'boundary=(\S+)',
          ).firstMatch('${got.headers['content-type']}')!.group(1)!;
          expect(body, contains('--$boundary--'));
        } finally {
          await stop(server);
        }
      },
    );

    test(
      'gzip request body passes through byte-identical (fail-safe skip)',
      () async {
        final reg = SentinelRegistry();
        final sentinel = reg.register('GH_TOKEN', REAL_LONG, ['127.0.0.1']);
        final (:server, :port) = await startProxy(reg);
        final tmp = mkdtempSync(path.join(tmpdir(), 'srt-body-gz-'));
        try {
          final gz = gzipSync(utf8.encode('{"token":"$sentinel"}'));
          final gzPath = path.join(tmp, 'body.gz');
          writeFileSync(gzPath, gz);
          final r = await curlViaProxy(
            port,
            url('/gz'),
            method: 'POST',
            dataFile: gzPath,
            headers: [
              'Content-Type: application/json',
              'Content-Encoding: gzip',
            ],
          );
          expect(r.exit, 0);
          expect(r.status, 200);
          final got = lastSeen();
          expect(got.body, gz);
          expect(got.headers['content-length'], '${gz.length}');
        } finally {
          await stop(server);
          rmSync(tmp, {'recursive': true, 'force': true});
        }
      },
    );

    test(
      'host without injectable credentials: byte-identical passthrough',
      () async {
        final reg = SentinelRegistry();
        // Injectable only at some OTHER host — not at the CONNECT target.
        final sentinel = reg.register('GH_TOKEN', REAL_LONG, [
          'other.example.com',
        ]);
        final (:server, :port) = await startProxy(reg);
        try {
          final payload = '{"token":"$sentinel"}';
          final r = await curlViaProxy(
            port,
            url('/other-host'),
            method: 'POST',
            body: payload,
            headers: ['Content-Type: application/json'],
          );
          expect(r.exit, 0);
          expect(r.status, 200);
          final got = lastSeen();
          // The fake stays a useless fake; nothing about the request changed.
          expect(utf8.decode(got.body), payload);
          expect(got.headers['content-length'], '${payload.length}');
          expect(got.headers['transfer-encoding'], isNull);
        } finally {
          await stop(server);
        }
      },
    );

    test(
      'regression: header substitution still works alongside body substitution',
      () async {
        final reg = SentinelRegistry();
        final sentinel = reg.register('GH_TOKEN', REAL_LONG, ['127.0.0.1']);
        final (:server, :port) = await startProxy(reg);
        try {
          final r = await curlViaProxy(
            port,
            url('/both'),
            method: 'POST',
            body: '{"token":"$sentinel"}',
            headers: [
              'Content-Type: application/json',
              'Authorization: Bearer $sentinel',
            ],
          );
          expect(r.exit, 0);
          expect(r.status, 200);
          final got = lastSeen();
          expect(got.headers['authorization'], 'Bearer $REAL_LONG');
          expect(utf8.decode(got.body), '{"token":"$REAL_LONG"}');
        } finally {
          await stop(server);
        }
      },
    );

    test('regression: bodyless GET is unaffected', () async {
      final reg = SentinelRegistry();
      reg.register('GH_TOKEN', REAL_LONG, ['127.0.0.1']);
      final (:server, :port) = await startProxy(reg);
      try {
        final r = await curlViaProxy(port, url('/plain-get'));
        expect(r.exit, 0);
        expect(r.status, 200);
        final got = lastSeen();
        expect(got.method, 'GET');
        expect(got.body.length, 0);
      } finally {
        await stop(server);
      }
    });
  });

  group('credential-mask-body: plaintext proxy path (opt-in)', () {
    test(
      'getBodySubstitutionsPlaintext substitutes in a plain-HTTP POST body',
      () async {
        final seen = <SeenRequest>[];
        final upstream = http.createServer((
          http.IncomingMessage req,
          http.ServerResponse res,
        ) {
          final chunks = <Uint8List>[];
          req.on('data', (Object? c) => chunks.add(c as Uint8List));
          req.on('end', () {
            seen.add((
              method: req.method!,
              url: req.url!,
              headers: req.headers,
              body: Uint8List.fromList([for (final c in chunks) ...c]),
            ));
            res.writeHead(200);
            res.end('ok');
          });
        });
        final upstreamListening = Completer<void>();
        upstream.listen(0, '127.0.0.1', () => upstreamListening.complete());
        await upstreamListening.future;
        final upstreamPort = (upstream.address() as net.NodeAddress).port;

        final reg = SentinelRegistry();
        final sentinel = reg.register('GH_TOKEN', REAL_LONG, ['127.0.0.1']);
        final proxy = createHttpProxyServer(
          _HttpOptions(
            mutateHeadersPlaintext: (h, d) => reg.substituteInHeaders(h, d, eq),
            getBodySubstitutionsPlaintext: (d) => reg.sentinelsForHost(d, eq),
          ),
        );
        final proxyListening = Completer<void>();
        proxy.listen(0, '127.0.0.1', () => proxyListening.complete());
        await proxyListening.future;
        final proxyPort = (proxy.address() as net.NodeAddress).port;

        try {
          final payload = '{"token":"$sentinel"}';
          final status = await () {
            final completer = Completer<int>();
            final req = http.request(
              {
                'host': '127.0.0.1',
                'port': proxyPort,
                'method': 'POST',
                // Absolute-form request-target: this is how proxy clients speak
                // plain HTTP to a forward proxy.
                'path': 'http://127.0.0.1:$upstreamPort/plain',
                'headers': {
                  'content-type': 'application/json',
                  'content-length': payload.length,
                },
              },
              (http.IncomingMessage res) {
                res.resume();
                res.on('end', () => completer.complete(res.statusCode ?? 0));
              },
            );
            req.on('error', (Object e) => completer.completeError(e));
            req.end(payload);
            return completer.future;
          }();
          expect(status, 200);
          final got = seen[seen.length - 1];
          expect(utf8.decode(got.body), '{"token":"$REAL_LONG"}');
          expect(got.headers['content-length'], '${payload.length}');
        } finally {
          final proxyClosed = Completer<void>();
          proxy.close(() => proxyClosed.complete());
          await proxyClosed.future;
          final upstreamClosed = Completer<void>();
          upstream.close(() => upstreamClosed.complete());
          await upstreamClosed.future;
        }
      },
    );
  });
}

typedef CurlResult = ({
  int exit,
  int status,
  Map<String, String> headers,
  String body,
  String stderr,
});

Future<CurlResult> curlViaProxy(
  int proxyPort,
  String url, {
  String? method,
  String? body,
  /** Raw request headers, `Name: value` form. */
  List<String>? headers,
  /** Multipart form fields (`curl -F name=value`). */
  List<(String, String)>? formFields,
  /** File whose bytes become the request body (`--data-binary @file`). */
  String? dataFile,
}) async {
  final args = [
    '-sS',
    '-v',
    '--proxy',
    'http://127.0.0.1:$proxyPort',
    // An empty list overrides NO_PROXY, which would send curl around
    // the proxy under test for 127.0.0.1.
    '--noproxy',
    '',
    '--cacert',
    CA_CERT,
    '--max-time',
    '10',
    '-D',
    '-',
  ];
  if (method != null && method.isNotEmpty) args.addAll(['-X', method]);
  for (final h in headers ?? <String>[]) {
    args.addAll(['-H', h]);
  }
  if (body != null) args.addAll(['--data-binary', body]);
  if (dataFile != null) args.addAll(['--data-binary', '@$dataFile']);
  for (final (name, value) in formFields ?? <(String, String)>[]) {
    args.addAll(['-F', '$name=$value']);
  }
  args.add(url);

  // Dart: dart:io's Process.start; its streams decode and end as Node's do.
  final child = await Process.start('curl', args);
  final outFuture = child.stdout.transform(utf8.decoder).join();
  final stderrFuture = child.stderr.transform(utf8.decoder).join();
  final out = await outFuture;
  final stderr = await stderrFuture;
  final exit = await child.exitCode;

  final sep = out.lastIndexOf('\r\n\r\n');
  final headerPart = sep >= 0 ? out.substring(0, sep) : '';
  final bodyOut = sep >= 0 ? out.substring(sep + 4) : out;
  final blocks = headerPart.split(RegExp(r'\r\n\r\n'));
  final lastHdr = blocks.isNotEmpty ? blocks[blocks.length - 1] : '';
  final lines = lastHdr.split('\r\n');
  final statusLine = lines.isNotEmpty ? lines.removeAt(0) : '';
  final m = RegExp(r'HTTP/[\d.]+ (\d+)').firstMatch(statusLine);
  final status = m != null ? int.parse(m.group(1)!) : 0;
  final responseHeaders = <String, String>{};
  for (final line in lines) {
    final i = line.indexOf(':');
    if (i > 0) {
      responseHeaders[line.substring(0, i).toLowerCase()] = line
          .substring(i + 1)
          .trim();
    }
  }
  return (
    exit: exit,
    status: status,
    headers: responseHeaders,
    body: bodyOut,
    stderr: stderr,
  );
}
