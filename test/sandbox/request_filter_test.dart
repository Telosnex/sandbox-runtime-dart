// Ported from sandbox-runtime test/sandbox/request-filter.test.ts @ 24eb39e.

// ignore_for_file: slash_for_doc_comments, constant_identifier_names, non_constant_identifier_names
import 'dart:async';
import 'dart:convert';
import 'dart:io' show Directory, File;

import 'package:path/path.dart' as path;
import 'package:test/test.dart';

// Every case here runs a proxy configured to terminate TLS, so each is
// skipped where this runtime cannot terminate it in-process.
import '../helpers/emitted_connections.dart' show SERVES_EMITTED_CONNECTIONS;
import 'package:sandbox_runtime/src/node/abort.dart' show AbortSignal;
import 'package:sandbox_runtime/src/node/child_process.dart' show spawn;
import 'package:sandbox_runtime/src/node/fetch.dart' as fetch;
import 'package:sandbox_runtime/src/node/http.dart' as http;
import 'package:sandbox_runtime/src/node/https.dart' as https;
import 'package:sandbox_runtime/src/node/net.dart' show NodeAddress, NodeServer;
import 'package:sandbox_runtime/src/node/url.dart' show URL;
import 'package:sandbox_runtime/src/sandbox/http_proxy.dart';
import 'package:sandbox_runtime/src/sandbox/mitm_ca.dart';
import 'package:sandbox_runtime/src/sandbox/mitm_leaf.dart';
import 'package:sandbox_runtime/src/sandbox/request_filter.dart';

final FIXTURE_DIR = path.join(
  Directory.current.path, // import.meta.dir, '..'
  'test',
  'fixtures',
  'tls-terminate',
);
final CA_CERT = path.join(FIXTURE_DIR, 'ca.crt');
final CA_KEY = path.join(FIXTURE_DIR, 'ca.key');
final CA_PEM = File(CA_CERT).readAsStringSync();

// Dart: the object literal upstream passes to createHttpProxyServer; every
// option not named here is absent (null).
class _HttpOptions implements HttpProxyServerOptions {
  _HttpOptions({this.mitmCA, this.filterRequest, this.tlsTerminateUpstreamCA});
  @override
  final MitmCA? mitmCA;
  @override
  final FilterRequestCallback? filterRequest;
  @override
  final dynamic tlsTerminateUpstreamCA;
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

void main() {
  // Dart: describeWithTls as a plain group with its skip, so the title audit sees it.
  group(
    'network.filterRequest',
    skip: SERVES_EMITTED_CONNECTIONS ? false : 'TLS termination unavailable',
    () {
      // Every test here drives real TLS (CA mint, MITM re-encrypt) through a
      // spawned curl whose functional watchdog is --max-time 10. The per-test
      // budget must exceed that watchdog: with bun's 5s default, a slow shard
      // gets an opaque 5001ms kill instead of a pass or a diagnosable curl
      // failure. 15s keeps curl as the real timeout.
      const TEST_TIMEOUT = Timeout(Duration(milliseconds: 15000));

      late NodeServer upstream;
      late int upstreamPort;

      setUpAll(() async {
        final ca0 = createMitmCA(caCertPath: CA_CERT, caKeyPath: CA_KEY);
        final upCert = mintLeafCert(ca0, '127.0.0.1');
        final upLeafOnly = RegExp(
          r'-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----\r?\n?',
        ).firstMatch(upCert.certPem)![0]!;
        upstream = https.createServer(
          {'cert': upLeafOnly, 'key': upCert.keyPem},
          (http.IncomingMessage req, http.ServerResponse res) {
            var body = '';
            req.on('data', (Object c) => body += utf8.decode(c as List<int>));
            req.on('end', () {
              res.writeHead(200, {'x-upstream': 'ok'});
              res.end(
                jsonEncode({
                  'path': req.url,
                  'method': req.method,
                  'echoed': body,
                }),
              );
            });
          },
        );
        final listening = Completer<void>();
        upstream.listen(0, '127.0.0.1', () => listening.complete());
        await listening.future;
        upstreamPort = (upstream.address() as NodeAddress).port;
      });

      tearDownAll(() async {
        final r = Completer<void>();
        upstream.close(() => r.complete());
        await r.future;
      });

      Future<void> withProxy(
        FilterRequestCallback filterRequest,
        Future<void> Function(int proxyPort) fn,
      ) async {
        final ca = createMitmCA(caCertPath: CA_CERT, caKeyPath: CA_KEY);
        final proxy = createHttpProxyServer(
          _HttpOptions(
            mitmCA: ca,
            filterRequest: filterRequest,
            tlsTerminateUpstreamCA: CA_PEM,
          ),
        );
        final listening = Completer<void>();
        proxy.listen(0, '127.0.0.1', () => listening.complete());
        await listening.future;
        try {
          await fn((proxy.address() as NodeAddress).port);
        } finally {
          final closed = Completer<void>();
          proxy.close(() => closed.complete());
          await closed.future;
        }
      }

      test(
        'callback receives method, URL, headers; allow forwards upstream',
        () async {
          fetch.Request? seen;
          await withProxy(
            (req, [info]) async {
              seen = req;
              return const RequestDecision(action: 'allow');
            },
            (port) async {
              final r = await curl(
                port,
                'https://127.0.0.1:$upstreamPort/hello?a=1',
                headers: ['X-Custom: yep'],
              );
              expect(r.status, 200);
              expect(r.headers['x-upstream'], 'ok');
            },
          );
          expect(seen, isNotNull);
          expect(seen!.method, 'GET');
          final u = URL(seen!.url);
          expect(u.hostname, '127.0.0.1');
          expect(u.port, '$upstreamPort');
          expect(u.pathname, '/hello');
          expect(u.search, '?a=1');
          expect(seen!.headers.get('x-custom'), 'yep');
          expect(seen!.body, isNull);
          expect(seen!.signal, isA<AbortSignal>());
        },
        timeout: TEST_TIMEOUT,
      );

      // Regression: previously, the URL passed to filterRequest was built
      // from `req.headers.host ?? target.hostname`. The Host header is
      // attacker-controlled (the sandboxed client picks any value once TLS
      // is terminated), so a sandboxed process could CONNECT to allowlisted
      // host A and send a decrypted request with `Host: B` (some other
      // allowlisted host). filterRequest would see "the request is going
      // to B" while the request is actually delivered to A. A consumer
      // using filterRequest for per-host method gating (e.g. "POST allowed
      // only to inference endpoints") was bypassable: spoof
      // `Host: api.inference.example` on a CONNECT to a non-inference
      // host, get the POST allowed, and have it delivered to the original
      // CONNECT target.
      //
      // Fix: derive the URL from the verified CONNECT target only.
      test(
        'URL passed to filterRequest is the CONNECT target, NOT a spoofed Host header',
        () async {
          fetch.Request? seen;
          var upstreamSawRequest = false;
          upstream.on('request', () {
            upstreamSawRequest = true;
          });
          await withProxy(
            (req, [info]) async {
              seen = req;
              // Deny anything that isn't 127.0.0.1 — i.e. emulate a per-host
              // policy. If the URL came from the spoofed Host header, this
              // would erroneously allow the request through.
              final host = URL(req.url).hostname;
              if (host != '127.0.0.1') {
                return RequestDecision(
                  action: 'deny',
                  reason: 'unexpected host $host',
                );
              }
              return const RequestDecision(
                action: 'deny',
                reason: 'denied for the test',
              );
            },
            (port) async {
              final r = await curl(
                port,
                'https://127.0.0.1:$upstreamPort/x',
                method: 'POST',
                body: 'exfil',
                headers: ['Host: spoofed.example.com'],
              );
              // We expect the deny to fire, but with the CORRECT host
              // (127.0.0.1), not 'spoofed.example.com'.
              expect(r.status, 403);
              expect(r.body, contains('denied for the test'));
            },
          );
          expect(seen, isNotNull);
          final u = URL(seen!.url);
          expect(u.hostname, '127.0.0.1');
          expect(u.port, '$upstreamPort');
          // Upstream must NOT have seen the request — even though the Host
          // header named an allowlisted-looking host.
          expect(upstreamSawRequest, false);
        },
        timeout: TEST_TIMEOUT,
      );

      test('deny returns 403 with reason; upstream not reached', () async {
        var upstreamHit = false;
        const decision = RequestDecision(
          action: 'deny',
          reason: 'nope: not on the list',
        );
        await withProxy((req, [info]) async => decision, (port) async {
          final r = await curl(port, 'https://127.0.0.1:$upstreamPort/denied');
          expect(r.status, 403);
          expect(r.body.trim(), 'nope: not on the list');
          expect(r.headers['x-proxy-error'], 'blocked-by-sandbox-runtime');
          upstreamHit = r.headers['x-upstream'] == 'ok';
        });
        expect(upstreamHit, false);
      }, timeout: TEST_TIMEOUT);

      test('throw → deny (fail closed)', () async {
        await withProxy(
          (req, [info]) {
            throw StateError('boom');
          },
          (port) async {
            final r = await curl(port, 'https://127.0.0.1:$upstreamPort/');
            expect(r.status, 403);
            expect(r.body, contains('sandbox policy check failed: boom'));
          },
        );
      }, timeout: TEST_TIMEOUT);

      test('decision can depend on request path (awaited)', () async {
        await withProxy(
          (req, [info]) async {
            await Future<void>.delayed(const Duration(milliseconds: 5));
            return URL(req.url).pathname == '/ok'
                ? const RequestDecision(action: 'allow')
                : const RequestDecision(
                    action: 'deny',
                    reason: 'path not allowed',
                  );
          },
          (port) async {
            final a = await curl(port, 'https://127.0.0.1:$upstreamPort/ok');
            expect(a.status, 200);
            final b = await curl(port, 'https://127.0.0.1:$upstreamPort/nope');
            expect(b.status, 403);
            expect(b.body, contains('path not allowed'));
          },
        );
      }, timeout: TEST_TIMEOUT);

      test('callback can read the body; upstream still receives it', () async {
        var seenBody = '';
        await withProxy(
          (req, [info]) async {
            seenBody = await req.text();
            return seenBody.contains('forbidden')
                ? const RequestDecision(
                    action: 'deny',
                    reason: 'body matched forbidden',
                  )
                : const RequestDecision(action: 'allow');
          },
          (port) async {
            final a = await curl(
              port,
              'https://127.0.0.1:$upstreamPort/up',
              method: 'POST',
              body: 'hello-from-client',
            );
            expect(a.status, 200);
            expect(seenBody, 'hello-from-client');
            // Upstream got the same bytes the callback read.
            expect(jsonDecode(a.body)['echoed'], 'hello-from-client');

            final b = await curl(
              port,
              'https://127.0.0.1:$upstreamPort/up',
              method: 'POST',
              body: 'this is forbidden content',
            );
            expect(b.status, 403);
            expect(b.body.trim(), 'body matched forbidden');
          },
        );
      }, timeout: TEST_TIMEOUT);

      test(
        'callback that ignores body does not buffer it (upstream still gets it)',
        () async {
          await withProxy(
            (req, [info]) async => const RequestDecision(action: 'allow'),
            (port) async {
              final r = await curl(
                port,
                'https://127.0.0.1:$upstreamPort/up',
                method: 'POST',
                body: 'passthrough',
              );
              expect(r.status, 200);
              expect(jsonDecode(r.body)['echoed'], 'passthrough');
            },
          );
        },
        timeout: TEST_TIMEOUT,
      );

      test('also gates plain HTTP through the proxy', () async {
        fetch.Request? seen;
        final httpUp = http.createServer((
          http.IncomingMessage req,
          http.ServerResponse res,
        ) {
          res.writeHead(200, {'x-upstream': 'ok'});
          res.end('plain');
        });
        final listening = Completer<void>();
        httpUp.listen(0, '127.0.0.1', () => listening.complete());
        await listening.future;
        final httpUpPort = (httpUp.address() as NodeAddress).port;
        try {
          await withProxy(
            (req, [info]) async {
              seen = req;
              return URL(req.url).pathname == '/ok'
                  ? const RequestDecision(action: 'allow')
                  : const RequestDecision(action: 'deny', reason: 'nope');
            },
            (port) async {
              final a = await curl(port, 'http://127.0.0.1:$httpUpPort/ok');
              expect(a.status, 200);
              expect(URL(seen!.url).protocol, 'http:');
              final b = await curl(port, 'http://127.0.0.1:$httpUpPort/bad');
              expect(b.status, 403);
              expect(b.body.trim(), 'nope');
            },
          );
        } finally {
          final closed = Completer<void>();
          httpUp.close(() => closed.complete());
          await closed.future;
        }
      }, timeout: TEST_TIMEOUT);

      test('no filterRequest → all requests forward (back-compat)', () async {
        final ca = createMitmCA(caCertPath: CA_CERT, caKeyPath: CA_KEY);
        final proxy = createHttpProxyServer(
          _HttpOptions(mitmCA: ca, tlsTerminateUpstreamCA: CA_PEM),
        );
        final listening = Completer<void>();
        proxy.listen(0, '127.0.0.1', () => listening.complete());
        await listening.future;
        try {
          final r = await curl(
            (proxy.address() as NodeAddress).port,
            'https://127.0.0.1:$upstreamPort/compat',
          );
          expect(r.status, 200);
        } finally {
          final closed = Completer<void>();
          proxy.close(() => closed.complete());
          await closed.future;
        }
      }, timeout: TEST_TIMEOUT);
    },
  );
}

typedef CurlResult = ({
  int exit,
  int status,
  Map<String, String> headers,
  String body,
});

Future<CurlResult> curl(
  int proxyPort,
  String url, {
  List<String>? headers,
  String? method,
  String? body,
}) async {
  final args = [
    '-sS',
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
  for (final h in headers ?? <String>[]) {
    args.addAll(['-H', h]);
  }
  if (method != null && method.isNotEmpty) args.addAll(['-X', method]);
  if (body != null) args.addAll(['--data-binary', body]);
  args.add(url);

  final child = spawn('curl', args);
  var out = '';
  final stdoutEnd = Completer<void>();
  final stderrEnd = Completer<void>();
  child.stdout!
      .transform(utf8.decoder)
      .listen((c) => out += c, onDone: () => stdoutEnd.complete());
  child.stderr!
      .transform(utf8.decoder)
      .listen((_) {}, onDone: () => stderrEnd.complete());
  await Future.wait([stdoutEnd.future, stderrEnd.future]);
  final exitCompleter = Completer<int>();
  child.on(
    'close',
    (int? code, [Object? _]) => exitCompleter.complete(code ?? 1),
  );
  final exit = await exitCompleter.future;

  final sep = out.lastIndexOf('\r\n\r\n');
  final headerPart = sep >= 0 ? out.substring(0, sep) : '';
  final bodyOut = sep >= 0 ? out.substring(sep + 4) : out;
  final blocks = headerPart.split(RegExp(r'\r\n\r\n'));
  final lastHdr = blocks.isEmpty ? '' : blocks[blocks.length - 1];
  final lines = lastHdr.split('\r\n');
  final m = RegExp(r'HTTP/[\d.]+ (\d+)').firstMatch(lines.removeAt(0));
  final status = m != null ? int.parse(m.group(1)!) : 0;
  final outHeaders = <String, String>{};
  for (final line in lines) {
    final i = line.indexOf(':');
    if (i > 0) {
      outHeaders[line.substring(0, i).toLowerCase()] = line
          .substring(i + 1)
          .trim();
    }
  }
  return (exit: exit, status: status, headers: outHeaders, body: bodyOut);
}
