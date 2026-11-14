// Tests for the Node stream/promises shim; no upstream counterpart.
import 'package:sandbox_runtime/src/node/errno.dart';
import 'package:sandbox_runtime/src/node/stream.dart' as stream;
import 'package:sandbox_runtime/src/node/stream_promises.dart' as promises;
import 'package:test/test.dart';

void main() {
  test('finished waits until a readable has been consumed', () async {
    final source = stream.Readable.from(['one', 'two'], objectMode: false);
    var complete = false;
    final done = promises.finished(source).then((_) => complete = true);
    await Future<void>.delayed(Duration.zero);
    expect(complete, isFalse);
    source.resume();
    await done;
    expect(source.readableEnded, isTrue);
  });

  test('finished rejects a stream error', () async {
    final source = stream.Readable(read: (int _) {});
    final error = NodeError('failed', code: 'EIO');
    final done = expectLater(promises.finished(source), throwsA(same(error)));
    source.destroy(error);
    await done;
  });

  test('finished rejects a premature close', () async {
    final source = stream.Readable(read: (int _) {});
    final done = expectLater(
      promises.finished(source),
      throwsA(
        isA<NodeError>().having(
          (e) => e.code,
          'code',
          'ERR_STREAM_PREMATURE_CLOSE',
        ),
      ),
    );
    source.destroy();
    await done;
  });

  test(
    'finished keeps listeners by default and removes them with cleanup',
    () async {
      for (final cleanup in [false, true]) {
        final source = stream.Readable.from(['x'], objectMode: false);
        final done = promises.finished(source, {'cleanup': cleanup});
        source.resume();
        await done;
        for (final event in ['end', 'finish', 'error', 'close']) {
          expect(source.listenerCount(event), cleanup ? 0 : 1);
        }
      }
    },
  );

  test('finished resolves for a readable that already ended', () async {
    final source = stream.Readable.from(['x'], objectMode: false);
    final done = promises.finished(source);
    source.resume();
    await done;
    await promises.finished(source, {'cleanup': true});
  });
}
