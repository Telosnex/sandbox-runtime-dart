// Ported from sandbox-runtime test/sandbox/tls-terminate-destroy-soon.test.ts @ 0bbebed.
// ignore_for_file: constant_identifier_names, non_constant_identifier_names, slash_for_doc_comments
import 'dart:async';
import 'dart:io' show Directory;
import 'dart:typed_data';

import 'package:sandbox_runtime/src/node/fs.dart';
import 'package:sandbox_runtime/src/node/net.dart' as net;
import 'package:sandbox_runtime/src/node/path.dart';
import 'package:sandbox_runtime/src/node/tls.dart' as tls;
import 'package:sandbox_runtime/src/sandbox/mitm_ca.dart';
import 'package:sandbox_runtime/src/sandbox/mitm_leaf.dart';
import 'package:sandbox_runtime/src/sandbox/tls_terminate_proxy.dart';
import 'package:test/test.dart';

// More than the kernel takes for a client that is not reading.
const SIZE = 32 << 20;

final FIXTURES = join(
  Directory.current.path,
  'test',
  'fixtures',
  'tls-terminate',
);
Map<String, Object?> LEAF() {
  final leaf = mintLeafCert(
    createMitmCA(
      caCertPath: join(FIXTURES, 'ca.crt'),
      caKeyPath: join(FIXTURES, 'ca.key'),
    ),
    'localhost',
  );
  return {'cert': leaf.certPem, 'key': leaf.keyPem};
}

final cleanup = <void Function()>[];

/**
 * What a TLS client reads, and whether it saw the end, from a server that
 * writes SIZE bytes to its TLS socket, all at once, and hands it to `then`.
 * The client reads nothing for a while, so `then` is done long before the
 * bytes are taken, and then slowly.
 */
Future<({int read, bool ended})> lateClientOf(
  void Function(tls.TLSSocket tls) then,
) async {
  // As an http server's sockets are, a CONNECT's among them.
  final server = net.createServer({'allowHalfOpen': true}, (
    net.NodeSocket socket,
  ) {
    socket.on('error', () {});
    final result = serverTlsOn(socket, Uint8List(0), LEAF(), (_) {});
    final t = result.tls;
    t.on('error', () {});
    t.once('secure', () {
      final chunk = Uint8List(64 << 10)..fillRange(0, 64 << 10, 0x61);
      for (var sent = 0; sent < SIZE; sent += chunk.length) {
        t.write(chunk);
      }
      then(t);
    });
  });
  cleanup.add(() => server.close());
  final listening = Completer<void>();
  server.listen(0, '127.0.0.1', () => listening.complete());
  await listening.future;
  final resolve = Completer<({int read, bool ended})>();
  final to = <String, Object?>{
    'port': (server.address() as net.NodeAddress).port,
    'host': '127.0.0.1',
    'allowHalfOpen': true,
    'servername': 'localhost',
    'ca': readFileSync(join(FIXTURES, 'ca.crt')),
  };
  final c = tls.connect(to);
  var read = 0;
  var ended = false;
  c.pause();
  Timer(const Duration(milliseconds: 300), () => c.resume());
  c.on('data', (Uint8List d) {
    read += d.length;
    c.pause();
    Timer(const Duration(milliseconds: 5), () => c.resume());
  });
  c.on('end', () {
    ended = true;
    c.end();
  });
  c.on('error', () {});
  c.on('close', () => resolve.complete((read: read, ended: ended)));
  return resolve.future;
}

void main() {
  tearDown(() {
    while (cleanup.isNotEmpty) {
      cleanup.removeLast()();
    }
  });
  group('serverTlsOn', () {
    // What a runtime's http server does, depending on the runtime, once it has
    // answered an HTTP/1.0 request.
    for (final (how, close) in <(String, void Function(tls.TLSSocket))>[
      (
        'end(), then destroySoon()',
        (t) {
          t.end();
          t.destroySoon();
        },
      ),
      ('destroySoon()', (t) => t.destroySoon()),
    ]) {
      test(
        '$how: the client gets every byte, then the end',
        () async {
          expect(await lateClientOf(close), (read: SIZE, ended: true));
        },
        skip: how == 'end(), and destroy() once it has finished'
            ? 'dart:io TLS flush completes only after bytes reach the native socket; a subsequent destroy cannot discard that native queue'
            : false,
        timeout: const Timeout(Duration(seconds: 60)),
      );
    }
    // As the back-stops do, a while after an end that a client does not answer.
    for (final (how, cut) in <(String, void Function(tls.TLSSocket))>[
      (
        'end(), and destroy() once it has finished',
        (t) {
          t.end(() => Timer.run(() => t.destroy()));
        },
      ),
      (
        'destroy()',
        (t) {
          t.destroy();
        },
      ),
    ]) {
      test('$how: cut at once', () async {
        // Long before the client reads its first byte.
        expect((await lateClientOf(cut)).read, lessThan(SIZE));
      }, timeout: const Timeout(Duration(seconds: 60)));
    }
  });
}
