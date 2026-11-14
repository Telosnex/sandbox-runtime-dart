// Ported from sandbox-runtime test/sandbox/trailers-then-request.test.ts @ 0bbebed.
// ignore_for_file: constant_identifier_names, non_constant_identifier_names, slash_for_doc_comments, prefer_interpolation_to_compose_strings
import 'dart:async';

import 'package:sandbox_runtime/src/node/http.dart' as http;
import 'package:sandbox_runtime/src/node/https.dart' as https;
import 'package:sandbox_runtime/src/node/net.dart' as net;
import 'package:sandbox_runtime/src/node/stream.dart' as stream;
import 'package:sandbox_runtime/src/node/tls.dart' as tls;
import 'package:sandbox_runtime/src/sandbox/http_proxy.dart';
import 'package:sandbox_runtime/src/sandbox/mitm_ca.dart';
import 'package:sandbox_runtime/src/sandbox/mitm_leaf.dart';
import 'package:sandbox_runtime/src/sandbox/proxy_only.dart';
import 'package:sandbox_runtime/src/sandbox/request_filter.dart'
    show FilterRequestCallback, RequestDecision;
import 'package:test/test.dart';

import '../helpers/emitted_connections.dart' show SERVES_EMITTED_CONNECTIONS;
import '../helpers/fake_decider.dart' show fakeDecider;

// Dart: the object literal upstream hands createHttpProxyServer; every
// option not named here is absent (null).
class _HttpOptions implements HttpProxyServerOptions {
  _HttpOptions({this.mitmCA, this.tlsTerminateUpstreamCA, this.filterRequest});
  @override
  final MitmCA? mitmCA;
  @override
  final dynamic tlsTerminateUpstreamCA;
  @override
  final FilterRequestCallback? filterRequest;
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

final cleanup = <FutureOr<void> Function()>[];

/**
 * Where the requests go through the proxy: srt-proxy on plain HTTP or in a
 * TLS-terminated tunnel, or the full sandbox mode's proxy in a
 * TLS-terminated tunnel. Each terminated tunnel's connection is handed to
 * an HTTP server, which is where a runtime's parser reports trailers.
 */
typedef Path =
    String; // 'srt-proxy, plain HTTP' | 'srt-proxy, TLS' | 'full mode, TLS'

/** The proxy under test, and what it asked about each request. */
Future<({int port, List<String> Function() asked})> startProxy(
  Path path,
  String target,
  GeneratedCa authority,
) async {
  if (path == 'full mode, TLS') {
    final asked = <String>[];
    final proxy = createHttpProxyServer(
      _HttpOptions(
        mitmCA: createMitmCA(
          caCertPem: authority.certPem,
          caKeyPem: authority.keyPem,
        ),
        tlsTerminateUpstreamCA: authority.certPem,
        filterRequest: (request, [info]) async {
          asked.add(
            '${request.method} ${Uri.parse(request.url).path} x-late=${request.headers.get('x-late') ?? 'undefined'}',
          );
          return const RequestDecision(action: 'allow');
        },
      ),
    );
    final listening = Completer<void>();
    proxy.listen(0, '127.0.0.1', () => listening.complete());
    await listening.future;
    cleanup.add(() {
      final r = Completer<void>();
      proxy.close(() => r.complete());
      proxy.closeAllConnections();
      return r.future;
    });
    return (
      port: (proxy.address() as net.NodeAddress).port,
      asked: () => asked,
    );
  }
  final d = fakeDecider([target], (f) => {'action': 'allow'});
  final streams = d['streams'] as Map;
  final proxy = startProxyOnly(
    ProxyOnlyOptions(
      listen: const ProxyListenHostPort(host: '127.0.0.1', port: 0),
      decider: (
        input: streams['input'] as stream.Readable,
        output: streams['output'] as stream.Writable,
      ),
      deciderTimeoutMs: 2000,
      caPem: SERVES_EMITTED_CONNECTIONS
          ? authority.keyPem + authority.certPem
          : null,
      upstreamCA: SERVES_EMITTED_CONNECTIONS ? authority.certPem : null,
    ),
  );
  cleanup.add(() => proxy.close());
  await proxy.ready;
  return (
    port: (proxy.listener.address() as net.NodeAddress).port,
    asked: () => (d['seen'] as List<Map<String, Object?>>)
        .map(
          (f) =>
              '${f['method']} ${f['path']} x-late=${(f['headers'] as Map<String, Object?>?)?['x-late'] ?? 'undefined'}',
        )
        .toList(),
  );
}

void main() {
  tearDown(() async {
    while (cleanup.isNotEmpty) {
      await cleanup.removeLast()();
    }
  });

  /**
   * A request's trailers are its own. A runtime's parser reports them the
   * way it reports a batch of header lines, with the request's target again;
   * held over, they would be read as the start of the next request's head on
   * the connection, whose target would then begin with the previous one and
   * whose headers would begin with the previous request's trailers.
   */
  for (final path in const [
    'srt-proxy, plain HTTP',
    'srt-proxy, TLS',
    'full mode, TLS',
  ]) {
    group('a request after a chunked request with trailers ($path)', () {
      final tlsPath = path != 'srt-proxy, plain HTTP';
      test(
        'has its own target and headers, for the request filter and for the upstream',
        skip: tlsPath && !SERVES_EMITTED_CONNECTIONS
            ? 'TLS termination unavailable'
            : null,
        () async {
          final authority = generateCa();
          final got = <String>[];
          void handler(http.IncomingMessage req, http.ServerResponse res) {
            req.resume();
            req.on('end', () {
              got.add(
                '${req.method} ${req.url} x-late=${req.headers['x-late'] ?? 'undefined'}',
              );
              res.end('upstream ok');
            });
          }

          late final net.NodeServer up;
          if (tlsPath) {
            final leaf = mintLeafCert(
              createMitmCA(
                caCertPem: authority.certPem,
                caKeyPem: authority.keyPem,
              ),
              '127.0.0.1',
            );
            final leafOnly = RegExp(
              r'-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----\r?\n?',
            ).firstMatch(leaf.certPem)![0]!;
            up = https.createServer({
              'cert': leafOnly,
              'key': leaf.keyPem,
            }, handler);
          } else {
            up = http.createServer(handler);
          }
          final listening = Completer<void>();
          up.listen(0, '127.0.0.1', () => listening.complete());
          await listening.future;
          cleanup.add(() {
            final r = Completer<void>();
            up.close(() => r.complete());
            (up as http.NodeHttpServer).closeAllConnections();
            return r.future;
          });
          final target = '127.0.0.1:${(up.address() as net.NodeAddress).port}';
          final proxy = await startProxy(path, target, authority);
          net.NodeSocket sock = await () {
            final completer = Completer<net.NodeSocket>();
            late final net.NodeSocket c;
            c = net.connect(
              proxy.port,
              '127.0.0.1',
              () => completer.complete(c),
            );
            c.on('error', (Object? e) {
              if (!completer.isCompleted) completer.completeError(e!);
            });
            return completer.future;
          }();
          sock.on('error', (Object? _) {});
          if (tlsPath) {
            final raw = sock;
            raw.write('CONNECT $target HTTP/1.1\r\nHost: $target\r\n\r\n');
            final first = Completer<void>();
            raw.once('data', (Object? _) => first.complete());
            await first.future;
            sock = await () {
              final completer = Completer<tls.TLSSocket>();
              final t = tls.connect({
                'socket': raw,
                'ca': authority.certPem,
                'checkServerIdentity': (Object? a, Object? b) => null,
                'ALPNProtocols': ['http/1.1'],
              });
              t.on('error', (Object? e) {
                if (!completer.isCompleted) completer.completeError(e!);
              });
              t.once('secureConnect', (Object? _) => completer.complete(t));
              return completer.future;
            }();
            sock.on('error', (Object? _) {});
          }
          String head(String method, String p, List<String> more) => [
            '$method ${tlsPath ? p : 'http://$target$p'} HTTP/1.1',
            'Host: $target',
            ...more,
            '',
            '',
          ].join('\r\n');
          final first =
              head('POST', '/first', [
                'Transfer-Encoding: chunked',
                'Trailer: X-Late',
              ]) +
              '3\r\nabc\r\n2\r\nde\r\n0\r\nX-Late: from-the-trailer\r\n\r\n';
          final second = head('GET', '/second', ['Connection: close']);
          final closed = Completer<void>();
          sock.once('close', (Object? _) => closed.complete());
          sock.resume();
          // The second request goes once the first has been read, not in the
          // same write: this is about what a finished request leaves behind on
          // its connection, not about pipelining.
          sock.write(first);
          await Future<void>.delayed(const Duration(milliseconds: 150));
          sock.write(second);
          await closed.future;
          final asked = proxy.asked();
          expect(asked, [
            'POST /first x-late=undefined',
            'GET /second x-late=undefined',
          ]);
          expect(got, asked);
        },
      );
    });
  }
}
