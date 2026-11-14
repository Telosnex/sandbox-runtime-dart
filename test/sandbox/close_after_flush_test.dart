// Ported from sandbox-runtime test/sandbox/close-after-flush.test.ts @ 0bbebed.
import 'dart:async';
import 'dart:typed_data';

import 'package:sandbox_runtime/src/node/buffer.dart';
import 'package:sandbox_runtime/src/node/globals.dart' show setTimeout;
import 'package:sandbox_runtime/src/node/net.dart';
import 'package:sandbox_runtime/src/sandbox/tls_terminate_proxy.dart';
import 'package:test/test.dart';

// Dart: Buffer.alloc takes no fill argument.
Buffer _alloc(int size, int fill) =>
    Buffer.wrap(Uint8List(size)..fillRange(0, size, fill));

void main() {
  final cleanup = <void Function()>[];
  tearDown(() {
    while (cleanup.isNotEmpty) {
      cleanup.removeLast()();
    }
  });

  group('closeAfterFlush', () {
    test(
      'a slow client that sends bytes nobody reads still gets every byte, then a FIN',
      () async {
        final size = 32 << 20;
        void Function(String how) closedBy = (_) {};
        final howC = Completer<String>();
        closedBy = (String v) => howC.complete(v);
        final how = howC.future;
        final server = createServer((NodeSocket s) {
          s.on('error', () {});
          // Nothing reads what the client sends, as a relay whose far end has
          // closed does not.
          s.pause();
          final chunk = _alloc(64 << 10, 0x61);
          var sent = 0;
          void pump() {
            while (sent < size) {
              sent += chunk.length;
              if (!s.write(chunk)) {
                s.once('drain', pump);
                return;
              }
            }
            closeAfterFlush(s, closedBy);
          }

          pump();
        });
        cleanup.add(() => server.close());
        final listening = Completer<void>();
        server.listen(0, '127.0.0.1', () => listening.complete());
        await listening.future;
        final readC = Completer<int>();
        final c = connect((server.address() as NodeAddress).port, '127.0.0.1');
        var n = 0;
        var poked = false;
        c.on('data', (Uint8List d) {
          n += d.length;
          // Once the server is done writing, bytes it will never read, more
          // than the runtime reads ahead into a paused socket.
          if (!poked && n > size / 2) {
            poked = true;
            c.write(_alloc(4 << 20, 0x62));
          }
          c.pause();
          setTimeout(() => c.resume(), 1);
        });
        c.on('error', () {});
        c.on('close', () => readC.complete(n));
        final read = await readC.future;
        expect(read, size);
        expect(await how, 'the client ending after the flush');
      },
      timeout: const Timeout(Duration(milliseconds: 60000)),
    );
    test(
      'a client that takes nothing is cut after the time allowed, not before',
      () async {
        final began = DateTime.now().millisecondsSinceEpoch;
        final closed = Completer<String>();
        final server = createServer((NodeSocket s) {
          s.on('error', () {});
          // More than the kernel takes for a client that reads nothing.
          s.write(_alloc(32 << 20, 0x61));
          closeAfterFlush(s, (how) => closed.complete(how), 400);
        });
        cleanup.add(() => server.close());
        server.listen(0, '127.0.0.1', () {
          final c = connect(
            (server.address() as NodeAddress).port,
            '127.0.0.1',
          );
          c.on('error', () {});
          c.pause();
          cleanup.add(() => c.destroy());
        });
        final how = await closed.future;
        expect(how, 'not flushed in 400 ms');
        expect(
          DateTime.now().millisecondsSinceEpoch - began,
          greaterThanOrEqualTo(400),
        );
      },
      timeout: const Timeout(Duration(seconds: 5)),
    );
  });
}
