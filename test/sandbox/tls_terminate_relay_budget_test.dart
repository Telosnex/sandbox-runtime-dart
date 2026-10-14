// Ported from sandbox-runtime test/sandbox/tls-terminate-relay-budget.test.ts @ 24eb39e.
// ignore_for_file: constant_identifier_names, non_constant_identifier_names, slash_for_doc_comments
import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:sandbox_runtime/src/node/crypto.dart' show createHash;
import 'package:sandbox_runtime/src/node/http.dart' as http;
import 'package:sandbox_runtime/src/node/https.dart' as https;
import 'package:sandbox_runtime/src/node/net.dart' as net;
import 'package:sandbox_runtime/src/node/tls.dart' as tls;
import 'package:sandbox_runtime/src/sandbox/emitted_connection.dart'
    show ByteBudget, createByteBudget;
import 'package:sandbox_runtime/src/sandbox/http_proxy.dart';
import 'package:sandbox_runtime/src/sandbox/mitm_ca.dart';
import 'package:sandbox_runtime/src/sandbox/mitm_leaf.dart';
import 'package:test/test.dart';

// Every case here runs a proxy configured to terminate TLS, so each is
// skipped where this runtime cannot terminate it in-process.
import '../helpers/emitted_connections.dart' show SERVES_EMITTED_CONNECTIONS;

// Dart: upstream's `testWithTls as test`, which `test` cannot alias (and
// whose helper takes no timeout).
final Object? _tlsSkip = SERVES_EMITTED_CONNECTIONS
    ? null
    : 'TLS termination unavailable';

// Dart: the object literal upstream hands createHttpProxyServer; every
// option not named here is absent (null).
class _HttpOptions implements HttpProxyServerOptions {
  _HttpOptions({this.mitmCA, this.tlsTerminateUpstreamCA, this.byteBudget});
  @override
  final MitmCA? mitmCA;
  @override
  final dynamic tlsTerminateUpstreamCA;
  @override
  final ByteBudget? byteBudget;
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
  final cleanup = <FutureOr<void> Function()>[];
  tearDown(() async {
    for (final fn in cleanup.toList().reversed) {
      await fn();
    }
    cleanup.clear();
  });

  test(
    'two large responses to slow readers through terminated tunnels share a small budget, arrive whole, and leave it empty',
    () async {
      const SIZE = 48 << 20;
      final chunk = Uint8List(64 << 10);
      for (var i = 0; i < chunk.length; i++) {
        chunk[i] = (i * 31 + (i >> 8)) & 0xff;
      }
      final whole = createHash('sha256');
      for (var sent = 0; sent < SIZE; sent += chunk.length) {
        whole.update(chunk);
      }
      final wholeDigest = whole.digest('hex');

      final ca = generateCa();
      final leaf = mintLeafCert(
        createMitmCA(caCertPem: ca.certPem, caKeyPem: ca.keyPem),
        '127.0.0.1',
      );
      final leafOnly = RegExp(
        r'-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----\r?\n?',
      ).firstMatch(leaf.certPem)!.group(0)!;
      // Each large response reports the first time the path to its client is
      // full, so the clients start reading only once the proxy holds all it will.
      final backedUp = <void Function()>[];
      final up = https.createServer({'cert': leafOnly, 'key': leaf.keyPem}, (
        http.IncomingMessage req,
        http.ServerResponse res,
      ) {
        if (req.url != '/large') {
          res.end('small');
          return;
        }
        res.writeHead(200, {'Content-Length': SIZE});
        res.on('error', (_) {});
        var sent = 0;
        void pump() {
          while (sent < SIZE) {
            sent += chunk.length;
            if (!res.write(chunk)) {
              (backedUp.isEmpty ? null : backedUp.removeAt(0))?.call();
              res.once('drain', pump);
              return;
            }
          }
          res.end();
        }

        pump();
      });
      final upListening = Completer<void>();
      up.listen(0, '127.0.0.1', () => upListening.complete());
      await upListening.future;
      cleanup.add(() {
        final r = Completer<void>();
        up.close(() => r.complete());
        return r.future;
      });
      final target = '127.0.0.1:${(up.address() as net.NodeAddress).port}';

      final budget = createByteBudget(30000);
      final proxy = createHttpProxyServer(
        _HttpOptions(
          mitmCA: createMitmCA(caCertPem: ca.certPem, caKeyPem: ca.keyPem),
          tlsTerminateUpstreamCA: ca.certPem,
          byteBudget: budget,
        ),
      );
      final proxyListening = Completer<void>();
      proxy.listen(0, '127.0.0.1', () => proxyListening.complete());
      await proxyListening.future;
      cleanup.add(() {
        final r = Completer<void>();
        proxy.close(() => r.complete());
        return r.future;
      });
      final port = (proxy.address() as net.NodeAddress).port;

      Future<net.NodeSocket> tunnel() {
        final completer = Completer<net.NodeSocket>();
        late final net.NodeSocket c;
        c = net.connect({'port': port, 'host': '127.0.0.1'}, () {
          c.write('CONNECT $target HTTP/1.1\r\nHost: $target\r\n\r\n');
        });
        cleanup.add(() => c.destroy());
        c.on('error', (Object e) => completer.completeError(e));
        var head = '';
        void onData(Object? d) {
          head += latin1.decode(d as List<int>);
          if (!head.contains('\r\n\r\n')) return;
          c.off('data', onData);
          if (!head.startsWith('HTTP/1.1 200')) {
            return completer.completeError(Exception(head));
          }
          final t = tls.connect({
            'socket': c,
            'ca': ca.certPem,
            'checkServerIdentity': (Object? a, Object? b) => null,
            'ALPNProtocols': ['http/1.1'],
          });
          t.on('error', (Object e) => completer.completeError(e));
          t.on('secureConnect', () => completer.complete(t));
        }

        c.on('data', onData);
        return completer.future;
      }

      // `startReading` holds the body unread until it resolves; after that the
      // reader takes one chunk per turn of the event loop.
      Future<({int bytes, String digest})> get(
        String path,
        Future<Object?> startReading,
      ) async {
        final socket = await tunnel();
        final completer = Completer<({int bytes, String digest})>();
        final req = http.request(
          {
            'createConnection': () => socket,
            'path': path,
            'headers': {'Host': target, 'Connection': 'close'},
          },
          (http.IncomingMessage res) {
            final hash = createHash('sha256');
            var bytes = 0;
            res.on('error', (Object e) => completer.completeError(e));
            res.on(
              'end',
              () => completer.complete((
                bytes: bytes,
                digest: hash.digest('hex') as String,
              )),
            );
            startReading.then(
              (_) => res.on('data', (Object? d) {
                bytes += (d as Uint8List).length;
                hash.update(d);
                res.pause();
                // Dart: setImmediate is Timer.run.
                Timer.run(() => res.resume());
              }),
            );
          },
        );
        req.on('error', (Object e) => completer.completeError(e));
        req.end();
        return completer.future;
      }

      final bothBackedUp = Future.wait([
        () {
          final c = Completer<void>();
          backedUp.add(() => c.complete());
          return c.future;
        }(),
        () {
          final c = Completer<void>();
          backedUp.add(() => c.complete());
          return c.future;
        }(),
      ]);
      final [a, b] = await Future.wait([
        get('/large', bothBackedUp),
        get('/large', bothBackedUp),
      ]);
      expect(a, (bytes: SIZE, digest: wholeDigest));
      expect(b, (bytes: SIZE, digest: wholeDigest));
      expect(budget.waiters.length, 0);
      expect(budget.used, 0);

      final after = await get('/small', Future.value());
      expect(after.bytes, 5);
      expect(budget.used, 0);
    },
    // Dart: node/tls.dart connect() throws UnimplementedError for the `socket` option.
    tags: ['pending'],
    skip: _tlsSkip,
    timeout: const Timeout(Duration(milliseconds: 30000)),
  );
}
