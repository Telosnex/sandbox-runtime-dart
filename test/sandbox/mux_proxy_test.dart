// Ported from sandbox-runtime test/sandbox/mux-proxy.test.ts @ 24eb39e.
library;

// ignore_for_file: slash_for_doc_comments
import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:sandbox_runtime/src/node/fs.dart' show existsSync;
import 'package:sandbox_runtime/src/node/http.dart' as http;
import 'package:sandbox_runtime/src/node/net.dart';
import 'package:sandbox_runtime/src/sandbox/mux_proxy.dart';
import 'package:test/test.dart';

void main() {
  /**
   * Exercises the first-byte sniffer in isolation: a stub http.Server
   * stands in for the real HTTP proxy and a recording callback stands in
   * for the SOCKS handler. Runs on all platforms — on Windows the HTTP
   * backend listens on an ephemeral TCP port (range [0,0]); elsewhere it
   * listens on a unix socket.
   */
  group('mux-proxy first-byte dispatch', () {
    late MuxProxyServer mux;
    late http.NodeHttpServer httpStub;
    late int port;
    late List<Uint8List> socksHits;

    setUp(() async {
      socksHits = [];
      httpStub = http.createServer((
        http.IncomingMessage req,
        http.ServerResponse res,
      ) {
        res.writeHead(200, {'connection': 'close'});
        res.end('http-request:${req.method}:${req.url}\n');
      });
      httpStub.on('connect', (http.IncomingMessage req, NodeSocket sock) {
        sock.end(
          'HTTP/1.1 200 Connection Established\r\n\r\nhttp-connect:${req.url}\n',
        );
      });
      mux = createMuxProxyServer(
        MuxProxyOptions(
          httpServer: httpStub,
          handleSocksConnection: (sock) {
            // Drain everything the client sends so we can assert the unshifted
            // first byte is intact, then close.
            sock.on('data', (Uint8List chunk) => socksHits.add(chunk));
            sock.end(
              Uint8List.fromList([0x05, 0x00]),
            ); // SOCKS5 "no auth" reply
          },
          firstByteTimeoutMs: 500,
        ),
      );
      await mux.listenHttpBackend();
      final listening = Completer<void>();
      mux.server.once('error', listening.completeError);
      mux.server.listen(0, '127.0.0.1', () => listening.complete());
      await listening.future;
      port = mux.getPort()!;
    });

    tearDown(() async {
      await mux.close();
    });

    Future<Uint8List> send(Uint8List bytes) {
      final completer = Completer<Uint8List>();
      final chunks = BytesBuilder();
      late final NodeSocket c;
      c = connect(port, '127.0.0.1', () => c.write(bytes));
      c.on('data', (Uint8List d) => chunks.add(d));
      c.on('close', () {
        if (!completer.isCompleted) completer.complete(chunks.takeBytes());
      });
      c.on('error', (Object e) {
        if (!completer.isCompleted) completer.completeError(e);
      });
      return completer.future;
    }

    Uint8List concat(List<Uint8List> l) =>
        Uint8List.fromList([for (final b in l) ...b]);

    test(
      'routes 0x05 (SOCKS5 greeting) to the SOCKS handler with byte 0 intact',
      () async {
        final greeting = Uint8List.fromList([0x05, 0x01, 0x00]);
        final reply = await send(greeting);
        expect(reply, equals([0x05, 0x00]));
        // The handler must see the FULL greeting including the peeked 0x05.
        expect(concat(socksHits), equals(greeting));
      },
    );

    test('routes 0x04 (SOCKS4) to the SOCKS handler', () async {
      final req = Uint8List.fromList([
        0x04, 0x01, 0x00, 0x50, 0x7f, 0x00, 0x00, 0x01, 0x00, //
      ]);
      await send(req);
      expect(concat(socksHits)[0], 0x04);
    });

    test('routes an absolute-URI GET to the HTTP backend', () async {
      final reply = await send(
        Uint8List.fromList(
          utf8.encode(
            'GET http://x/ HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n',
          ),
        ),
      );
      final text = utf8.decode(reply);
      expect(text, contains('HTTP/1.1 200'));
      expect(text, contains('http-request:GET:http://x/'));
      expect(socksHits.length, 0);
    });

    test('routes CONNECT to the HTTP backend connect handler', () async {
      final reply = await send(
        Uint8List.fromList(
          utf8.encode('CONNECT x:443 HTTP/1.1\r\nHost: x:443\r\n\r\n'),
        ),
      );
      final text = utf8.decode(reply);
      expect(text, contains('200 Connection Established'));
      expect(text, contains('http-connect:x:443'));
    });

    test(
      'routes a TLS ClientHello first byte (0x16) to HTTP, not SOCKS',
      () async {
        // Not a valid HTTP request — the backend will 400 it — but the point
        // is it must NOT be treated as SOCKS.
        await send(
          Uint8List.fromList([0x16, 0x03, 0x01, 0x00, 0x05]),
        ).catchError((_) => Uint8List(0));
        expect(socksHits.length, 0);
      },
    );

    test(
      'destroys a connect-then-stall client after firstByteTimeoutMs',
      () async {
        final start = DateTime.now().millisecondsSinceEpoch;
        final closed = Completer<void>();
        final c = connect(port, '127.0.0.1');
        // Send nothing; wait for the server to drop us.
        c.on('close', () => closed.complete());
        c.on('error', (_) {}); // ECONNRESET is fine
        await closed.future;
        final elapsed = DateTime.now().millisecondsSinceEpoch - start;
        expect(elapsed, greaterThanOrEqualTo(450));
        expect(elapsed, lessThan(2000));
        expect(socksHits.length, 0);
      },
    );

    test('handles connect-then-immediate-close without dispatching', () async {
      final closed = Completer<void>();
      late final NodeSocket c;
      c = connect(port, '127.0.0.1', () => c.end());
      c.on('close', () => closed.complete());
      c.on('error', (_) {});
      await closed.future;
      expect(socksHits.length, 0);
    });

    test(
      'removeBackendSocketSync removes the backend socket file, and close() still works',
      () {
        final address = httpStub.address(); // a path, or on Windows a port
        if (address is String) expect(existsSync(address), isTrue);
        mux.removeBackendSocketSync();
        if (address is String) expect(existsSync(address), isFalse);
      },
    );
  });
}
