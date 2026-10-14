// Ported from sandbox-runtime test/sandbox/connect-non-tls.test.ts @ 24eb39e.
// ignore_for_file: slash_for_doc_comments, non_constant_identifier_names
import 'dart:async';
import 'dart:typed_data';

import 'package:sandbox_runtime/src/node/buffer.dart';
import 'package:sandbox_runtime/src/node/events.dart' show once;
import 'package:sandbox_runtime/src/node/globals.dart'
    show clearInterval, setInterval, setTimeout;
import 'package:sandbox_runtime/src/node/globals.dart' as globals show Timeout;
import 'package:sandbox_runtime/src/node/net.dart';
import 'package:sandbox_runtime/src/sandbox/http_proxy.dart';
import 'package:sandbox_runtime/src/sandbox/mitm_ca.dart';
import 'package:sandbox_runtime/src/sandbox/tls_terminate_proxy.dart';
import 'package:test/test.dart';

import '../helpers/emitted_connections.dart' show SERVES_EMITTED_CONNECTIONS;

// Dart: upstream's `it.skipIf(!SERVES_EMITTED_CONNECTIONS)`.
final Object _tlsSkip = SERVES_EMITTED_CONNECTIONS
    ? false
    : 'TLS termination unavailable';

// Dart: the object literal upstream hands createHttpProxyServer; every option
// not named here is absent (null).
class _HttpOptions implements HttpProxyServerOptions {
  _HttpOptions({required this.filterFn, this.mitmCA});
  final bool Function(int port, String host) filterFn;
  @override
  final MitmCA? mitmCA;
  @override
  FutureOr<bool> filter(
    int port,
    String host,
    dynamic socket, [
    String? encodedCommand,
    void Function(String reason)? explain,
  ]) => filterFn(port, host);
  @override
  dynamic noSuchMethod(Invocation invocation) => null;
}

// Dart: looksLikeClientHello takes a Uint8List; a Buffer is not one.
bool _looksLikeClientHello(Buffer b) => looksLikeClientHello(b.toUint8List());

/**
 * Regression: with tlsTerminate on, every CONNECT was handed to the
 * TLS terminator regardless of port/protocol. The Linux sandbox routes
 * `git push` over SSH through this proxy via
 *   GIT_SSH_COMMAND=ssh -o ProxyCommand='socat - PROXY:localhost:%h:%p,...'
 * which is `CONNECT github.com:22` — not TLS. The terminator replied with a
 * fatal protocol_version alert and closed, breaking SSH.
 *
 * Fix: sniff the client's first post-CONNECT bytes; only terminate when they
 * look like a TLS ClientHello, otherwise opaque-tunnel (base-sandbox
 * behaviour, hostname allowlist still enforced upstream of this branch).
 */

void main() {
  group('looksLikeClientHello', () {
    test('matches a TLS Handshake record header', () {
      // type=0x16, version=0x0301 (TLS1.0 record layer; ClientHello uses this
      // for all TLS versions), then arbitrary length/body bytes.
      expect(
        _looksLikeClientHello(Buffer.from([0x16, 0x03, 0x01, 0x00, 0x2a])),
        true,
      );
      expect(
        _looksLikeClientHello(Buffer.from([0x16, 0x03, 0x03, 0xff])),
        true,
      );
      expect(_looksLikeClientHello(Buffer.from([0x16, 0x03, 0x00])), true);
    });
    test('rejects an SSH banner', () {
      expect(
        _looksLikeClientHello(Buffer.from('SSH-2.0-OpenSSH_9.7\r\n')),
        false,
      );
    });
    test('rejects plain HTTP', () {
      expect(_looksLikeClientHello(Buffer.from('GET / HTTP/1.1\r\n')), false);
    });
    test('rejects a TLS Alert record (not Handshake)', () {
      expect(
        _looksLikeClientHello(Buffer.from([0x15, 0x03, 0x01, 0x00, 0x02])),
        false,
      );
    });
    test('rejects short buffers', () {
      expect(_looksLikeClientHello(Buffer.from([0x16, 0x03])), false);
      expect(_looksLikeClientHello(Buffer.alloc(0)), false);
    });
  });

  group('CONNECT carrying non-TLS bytes with mitmCA configured', () {
    late NodeServer upstream;
    late int upstreamPort;
    late List<Uint8List> received;

    setUp(() async {
      received = [];
      upstream = createServer((NodeSocket sock) {
        sock.on('data', (Uint8List d) => received.add(d));
        sock.write('SSH-2.0-FakeUpstream\r\n');
      });
      upstream.listen(0, '127.0.0.1');
      await once(upstream, 'listening');
      upstreamPort = (upstream.address() as NodeAddress).port;
    });

    tearDown(() => upstream.close());

    Future<({String buf, String upstreamSaw})> tunnel(Object? mitmCA) async {
      final proxy = createHttpProxyServer(
        _HttpOptions(filterFn: (_, _) => true, mitmCA: mitmCA as MitmCA?),
      );
      proxy.listen(0, '127.0.0.1');
      await once(proxy, 'listening');
      final proxyPort = (proxy.address() as NodeAddress).port;

      final NodeSocket sock = connect({'host': '127.0.0.1', 'port': proxyPort});
      await once(sock, 'connect');
      sock.write(
        'CONNECT localhost:$upstreamPort HTTP/1.1\r\nHost: localhost:$upstreamPort\r\n\r\n',
      );

      var buf = '';
      var sent = false;
      sock.on('data', (Uint8List d) {
        buf += Buffer.wrap(d).toString();
        if (!sent && buf.contains('Connection Established')) {
          sent = true;
          sock.write('SSH-2.0-OpenSSH_9.7\r\n');
        }
      });
      await Future.any<Object?>([
        () {
          final r = Completer<void>();
          late final globals.Timeout i;
          i = setInterval(() {
            if (buf.contains('FakeUpstream') && received.isNotEmpty) {
              clearInterval(i);
              r.complete();
            }
          }, 10);
          return r.future;
        }(),
        once(sock, 'close'),
        () {
          final r = Completer<void>();
          setTimeout(() => r.complete(), 2000);
          return r.future;
        }(),
      ]);
      sock.destroy();
      proxy.close();
      return (buf: buf, upstreamSaw: Buffer.concat(received).toString());
    }

    test('without mitmCA: opaque tunnel relays SSH bytes (baseline)', () async {
      final r = await tunnel(null);
      expect(r.buf, contains('SSH-2.0-FakeUpstream'));
      expect(r.upstreamSaw, contains('SSH-2.0-OpenSSH'));
    });

    test(
      'with mitmCA: non-TLS bytes are sniffed and opaque-tunnelled',
      () async {
        final ca = createMitmCA();
        try {
          final r = await tunnel(ca);
          // Before the fix: buf was "200...\r\n\r\n\x15\x03\x01\x00\x02\x02\x46"
          // (TLS protocol_version alert) and upstreamSaw was "".
          expect(r.buf, contains('SSH-2.0-FakeUpstream'));
          expect(r.upstreamSaw, contains('SSH-2.0-OpenSSH'));
        } finally {
          await disposeMitmCA(ca);
        }
      },
      skip: _tlsSkip,
    );

    test('with mitmCA: hostname filter still runs before the sniff', () async {
      var filterCalled = false;
      final ca = createMitmCA();
      try {
        final proxy = createHttpProxyServer(
          _HttpOptions(
            filterFn: (_, host) {
              filterCalled = host == 'localhost';
              return false;
            },
            mitmCA: ca,
          ),
        );
        proxy.listen(0, '127.0.0.1');
        await once(proxy, 'listening');
        final proxyPort = (proxy.address() as NodeAddress).port;
        final sock = connect({'host': '127.0.0.1', 'port': proxyPort});
        await once(sock, 'connect');
        sock.write(
          'CONNECT localhost:$upstreamPort HTTP/1.1\r\nHost: localhost:$upstreamPort\r\n\r\n',
        );
        var buf = '';
        sock.on('data', (Uint8List d) => buf += Buffer.wrap(d).toString());
        await once(sock, 'close');
        proxy.close();
        expect(filterCalled, true);
        expect(buf, contains('403 Forbidden'));
      } finally {
        await disposeMitmCA(ca);
      }
    }, skip: _tlsSkip);
  });
}
