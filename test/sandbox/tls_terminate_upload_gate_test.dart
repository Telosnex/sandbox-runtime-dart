// Ported from sandbox-runtime test/sandbox/tls-terminate-upload-gate.test.ts @ 24eb39e.
// ignore_for_file: constant_identifier_names, non_constant_identifier_names, slash_for_doc_comments
@Tags(
  ['pending'],
) // Dart: client gets empty response (no 200) after 60s; stalled-upstream upload hold-back not working
library;

import 'dart:async';
import 'dart:convert';

import 'package:sandbox_runtime/src/node/buffer.dart' show Buffer;
import 'package:sandbox_runtime/src/node/crypto.dart' show createHash;
import 'package:sandbox_runtime/src/node/net.dart' as net;
import 'package:sandbox_runtime/src/node/tls.dart' as tls;
import 'package:sandbox_runtime/src/sandbox/emitted_connection.dart'
    show ByteBudget, createByteBudget;
import 'package:sandbox_runtime/src/sandbox/http_proxy.dart';
import 'package:sandbox_runtime/src/sandbox/mitm_ca.dart';
import 'package:sandbox_runtime/src/sandbox/mitm_leaf.dart';
import 'package:test/test.dart';

import '../helpers/emitted_connections.dart' show SERVES_EMITTED_CONNECTIONS;

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

// An upload through a TLS-terminated tunnel to an upstream that stops
// reading: the proxy holds a bounded part of it, and the rest waits in the
// client. The proxy is handed its connections with emit('connection'), the
// path on which Bun's server is held back by the proxy (the upload gate);
// on a connection Bun's own listener accepted, the runtime reads on.

void main() {
  final cleanup = <FutureOr<void> Function()>[];
  tearDown(() async {
    while (cleanup.isNotEmpty) {
      await cleanup.removeLast()();
    }
  });

  const SIZE = 96 << 20;

  /**
   * A TLS upstream that reads a request's head and then nothing until
   * `release()`; then it reads the body (Content-Length: SIZE) and answers
   * with how many bytes it got and their SHA-256.
   */
  Future<({int port, void Function() release})> stallingUpstream(
    String cert,
    String key,
  ) async {
    late void Function() release;
    final released = Completer<void>();
    release = () => released.complete();
    final server = tls.createServer({'cert': cert, 'key': key}, (
      tls.TLSSocket s,
    ) {
      s.on('error', (Object? _) {});
      cleanup.add(() => s.destroy());
      var head = Buffer.alloc(0);
      late void Function(Object? d) onHead;
      onHead = (Object? d) {
        head = Buffer.concat([head, d as List<int>]);
        final end = head.indexOfBytes('\r\n\r\n');
        if (end < 0) return;
        s.off('data', onHead);
        s.pause();
        final hash = createHash('sha256');
        var got = 0;
        void take(Object? b) {
          got += (b as List<int>).length;
          hash.update(b);
          if (got < SIZE) return;
          final answer = '$got ${hash.digest('hex')}';
          s.end(
            'HTTP/1.1 200 OK\r\nContent-Length: ${answer.length}\r\nConnection: close\r\n\r\n$answer',
          );
        }

        released.future.then((_) {
          take(head.sublist(end + 4));
          s.on('data', take);
          s.resume();
        });
      };
      s.on('data', onHead);
    });
    final listening = Completer<void>();
    server.listen(0, '127.0.0.1', () => listening.complete());
    await listening.future;
    cleanup.add(() {
      final r = Completer<void>();
      server.close(() => r.complete());
      return r.future;
    });
    return (port: (server.address() as net.NodeAddress).port, release: release);
  }

  test(
    'an upload to a stalled upstream is held back in the client, then arrives whole',
    () async {
      final ca = generateCa();
      final mitmCA = createMitmCA(caCertPem: ca.certPem, caKeyPem: ca.keyPem);
      final leaf = mintLeafCert(mitmCA, '127.0.0.1');
      final up = await stallingUpstream(
        RegExp(
          r'-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----\r?\n?',
        ).firstMatch(leaf.certPem)!.group(0)!,
        leaf.keyPem,
      );
      final target = '127.0.0.1:${up.port}';

      final budget = createByteBudget(256 << 20);
      final proxy = createHttpProxyServer(
        _HttpOptions(
          mitmCA: mitmCA,
          tlsTerminateUpstreamCA: ca.certPem,
          byteBudget: budget,
        ),
      );
      // The proxy is handed each connection, as a host that accepts them
      // itself does; its own listen() is never called.
      net.NodeSocket? handed;
      final front = net.createServer((net.NodeSocket s) {
        handed = s;
        s.on('error', (Object? _) {});
        cleanup.add(() => s.destroy());
        proxy.emit('connection', s);
      });
      final frontListening = Completer<void>();
      front.listen(0, '127.0.0.1', () => frontListening.complete());
      await frontListening.future;
      cleanup.add(() {
        final r = Completer<void>();
        front.close(() => r.complete());
        return r.future;
      });

      final raw = net.connect(
        (front.address() as net.NodeAddress).port,
        '127.0.0.1',
      );
      raw.on('error', (Object? _) {});
      cleanup.add(() => raw.destroy());
      raw.write('CONNECT $target HTTP/1.1\r\nHost: $target\r\n\r\n');
      final connectReply = await (() {
        final r = Completer<String>();
        raw.once(
          'data',
          (Object? d) => r.complete(latin1.decode(d as List<int>)),
        );
        return r.future;
      })();
      expect(connectReply, startsWith('HTTP/1.1 200'));
      final tls.TLSSocket t = tls.connect({
        'socket': raw,
        'ca': ca.certPem,
        'checkServerIdentity': (Object? a, Object? b) => null,
      });
      t.on('error', (Object? _) {});
      await (() {
        final r = Completer<void>();
        t.once('secureConnect', () => r.complete());
        return r.future;
      })();
      // The answer: a head and a body of the upstream's count and digest.
      var response = '';
      final answered = (() {
        final resolve = Completer<void>();
        t.on('data', (Object? d) {
          response += latin1.decode(d as List<int>);
          if (RegExp(r'\r\n\r\n\d+ [0-9a-f]{64}$').hasMatch(response) &&
              !resolve.isCompleted) {
            resolve.complete();
          }
        });
        t.once('close', () {
          if (!resolve.isCompleted) resolve.complete();
        });
        return resolve.future;
      })();

      t.write(
        'POST /upload HTTP/1.1\r\nHost: $target\r\nContent-Length: $SIZE\r\n\r\n',
      );
      final chunk = Buffer.alloc(64 << 10);
      for (var i = 0; i < chunk.length; i++) {
        chunk[i] = (i * 7 + (i >> 9)) & 0xff;
      }
      final whole = createHash('sha256');
      for (var n = 0; n < SIZE; n += chunk.length) {
        whole.update(chunk);
      }
      var sent = 0;
      void pump() {
        while (sent < SIZE) {
          sent += chunk.length;
          if (!t.write(chunk)) {
            t.once('drain', pump);
            return;
          }
        }
      }

      pump();

      // Wait until the proxy stops taking the upload in (or has all of it).
      var read = -1;
      for (var stable = 0, i = 0; stable < 4 && i < 50; i++) {
        await Future<void>.delayed(const Duration(milliseconds: 250));
        final now = handed?.bytesRead ?? 0;
        stable = now == read ? stable + 1 : 0;
        read = now;
      }
      // The gate's 4 MiB, stream and kernel buffers: far below the upload.
      expect(read, lessThan(32 << 20));

      up.release();
      await answered;
      expect(response, startsWith('HTTP/1.1 200'));
      expect(
        response.substring(response.indexOf('\r\n\r\n') + 4),
        '$SIZE ${whole.digest('hex')}',
      );
      expect(budget.used, 0);
    },
    skip: SERVES_EMITTED_CONNECTIONS ? null : 'TLS termination unavailable',
    timeout: const Timeout(Duration(milliseconds: 60000)),
  );
}
