// Ported from sandbox-runtime test/sandbox/mux-proxy-e2e.test.ts @ 0bbebed.
// ignore_for_file: slash_for_doc_comments
import 'dart:async';
import 'dart:typed_data';

import 'package:sandbox_runtime/src/node/buffer.dart';
import 'package:sandbox_runtime/src/node/net.dart' show NodeSocket, connect;
import 'package:sandbox_runtime/src/sandbox/sandbox_config.dart';
import 'package:sandbox_runtime/src/sandbox/sandbox_manager.dart';
import 'package:test/test.dart';

void main() {
  /**
   * End-to-end: SandboxManager.initialize() starts the mux, then we drive
   * both protocols against the SAME port and check the real HTTP/SOCKS
   * backends respond. Runs on all platforms; on Windows the HTTP backend
   * uses a localhost TCP port inside the WFP range, elsewhere a unix
   * socket. Uses a denied host so no real egress happens — the test only
   * needs to see the protocol-correct refusal.
   */
  group('mux-proxy end-to-end via SandboxManager', () {
    late int port;
    late String authToken;

    setUpAll(() async {
      final config = SandboxRuntimeConfig(
        network: NetworkConfig(
          // Nothing allowed — we only assert the protocol-level response,
          // never the upstream dial.
          allowedDomains: [],
          deniedDomains: [],
        ),
        filesystem: FilesystemConfig(
          denyRead: [],
          allowWrite: [],
          denyWrite: [],
        ),
      );
      await SandboxManager.initialize(config);
      port = SandboxManager.getProxyPort()!;
      // The proxy requires auth; SandboxManager exposes the token for the
      // env-var builder, so reuse that.
      authToken = SandboxManager.getProxyAuthToken()!;
      expect(SandboxManager.getSocksProxyPort(), port);
    });

    tearDownAll(() async {
      await SandboxManager.reset();
    });

    Future<Buffer> exchange(
      void Function(NodeSocket sock) write,
      bool Function(Buffer buf) doneWhen,
    ) {
      final completer = Completer<Buffer>();
      final chunks = <Uint8List>[];
      late final NodeSocket c;
      c = connect(port, '127.0.0.1', () => write(c));
      void finish() {
        c.destroy();
        if (!completer.isCompleted) completer.complete(Buffer.concat(chunks));
      }

      c.on('data', (Uint8List d) {
        chunks.add(d);
        if (doneWhen(Buffer.concat(chunks))) finish();
      });
      c.on('close', finish);
      c.on('error', (Object e) {
        if (!completer.isCompleted) completer.completeError(e);
      });
      Timer(const Duration(milliseconds: 4000), finish);
      return completer.future;
    }

    test(
      'HTTP CONNECT to a denied host returns 403 from the real http-proxy',
      () async {
        final basic = Buffer.from('srt:$authToken').toString('base64');
        final reply = await exchange(
          (c) => c.write(
            'CONNECT denied.example:443 HTTP/1.1\r\n'
            'Host: denied.example:443\r\n'
            'Proxy-Authorization: Basic $basic\r\n\r\n',
          ),
          (buf) => buf.toString().contains('\r\n\r\n'),
        );
        expect(reply.toString(), matches(RegExp(r'^HTTP/1\.1 403 ')));
      },
    );

    test(
      'HTTP CONNECT without auth returns 407 from the real http-proxy',
      () async {
        final reply = await exchange(
          (c) => c.write(
            'CONNECT denied.example:443 HTTP/1.1\r\nHost: denied.example:443\r\n\r\n',
          ),
          (buf) => buf.toString().contains('\r\n\r\n'),
        );
        expect(reply.toString(), matches(RegExp(r'^HTTP/1\.1 407 ')));
      },
    );

    test(
      'SOCKS5 greeting on the same port gets a SOCKS method-select reply',
      () async {
        // Offer user/pass (0x02); server should select it: [0x05, 0x02].
        final reply = await exchange(
          (c) => c.write(Buffer.from([0x05, 0x01, 0x02]).toUint8List()),
          (buf) => buf.length >= 2,
        );
        expect(reply.sublist(0, 2), equals(Buffer.from([0x05, 0x02])));
      },
    );

    test(
      'SOCKS5 full handshake to a denied host returns CONNECTION_NOT_ALLOWED',
      () async {
        final reply = await exchange(
          (c) {
            // Greeting: VER=5, NMETHODS=1, METHODS=[user/pass]
            c.write(Buffer.from([0x05, 0x01, 0x02]).toUint8List());
            // Auth: VER=1, ULEN=3, "srt", PLEN, token
            final tok = Buffer.from(authToken);
            c.write(
              Buffer.concat([
                Buffer.from([0x01, 3]),
                Buffer.from('srt'),
                Buffer.from([tok.length]),
                tok,
              ]).toUint8List(),
            );
            // CONNECT: VER=5, CMD=1, RSV=0, ATYP=3(domain), len, host, port
            final host = Buffer.from('denied.example');
            c.write(
              Buffer.concat([
                Buffer.from([0x05, 0x01, 0x00, 0x03, host.length]),
                host,
                Buffer.from([0x01, 0xbb]), // 443
              ]).toUint8List(),
            );
          },
          // method-select(2) + auth-status(2) + connect-reply(>=7)
          (buf) => buf.length >= 2 + 2 + 7,
        );
        // [0..1] method-select: 05 02
        expect(reply.sublist(0, 2), equals(Buffer.from([0x05, 0x02])));
        // [2..3] auth status: 01 00 (success)
        expect(reply.sublist(2, 4), equals(Buffer.from([0x01, 0x00])));
        // [4] VER=5, [5] REP — 0x02 = connection not allowed by ruleset
        expect(reply[4], 0x05);
        expect(reply[5], 0x02);
      },
    );
  });
}
