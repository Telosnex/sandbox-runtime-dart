import 'dart:async';
import 'dart:io' as io;

import 'package:sandbox_runtime/src/node/buffer.dart';
import 'package:sandbox_runtime/src/node/errno.dart';
import 'package:sandbox_runtime/src/node/os.dart' as os;
import 'package:sandbox_runtime/src/node/process.dart' as process;
import 'package:test/test.dart';

void main() {
  test('pid, uid, version(s), memoryUsage, argv', () {
    expect(process.pid, io.pid);
    expect(process.geteuid!(), isA<int>());
    expect(process.version, startsWith('v'));
    expect(process.versions['bun'], isNull);
    expect(process.memoryUsage().rss, greaterThan(0));
    expect(process.argv, hasLength(greaterThanOrEqualTo(2)));
    expect(os.EOL, '\n');
  }, testOn: '!windows');

  test('env is mutable', () {
    process.env['SRT_TEST_X'] = '1';
    expect(process.env['SRT_TEST_X'], '1');
    process.env.remove('SRT_TEST_X');
  });

  test('a SIGUSR1 listener receives the signal; once removes itself', () async {
    final got = <String>[];
    final done = Completer<void>();
    void onSig(String s) {
      got.add(s);
      done.complete();
    }

    process.once('SIGUSR1', onSig);
    expect(process.listenerCount('SIGUSR1'), 1);
    process.kill(process.pid, 'SIGUSR1');
    await done.future;
    expect(got, ['SIGUSR1']);
    expect(process.listenerCount('SIGUSR1'), 0);
  }, testOn: '!windows');

  test('off removes a listener', () {
    void f() {}
    process.on('SIGUSR2', f);
    process.off('SIGUSR2', f);
    expect(process.listenerCount('SIGUSR2'), 0);
  }, testOn: '!windows');

  test('kill of a missing pid throws ESRCH', () {
    expect(
      () => process.kill(0x7ffffff0),
      throwsA(isA<NodeError>().having((e) => e.code, 'c', 'ESRCH')),
    );
  }, testOn: '!windows');

  test('errorMessage reads JS err.message', () {
    expect(errorMessage(NodeError('boom', code: 'X')), 'boom');
    expect(errorMessage(StateError('s')), 's');
    expect(errorMessage(const FormatException('f')), 'f');
    expect(errorMessage('str'), 'str');
  });

  test('Buffer helpers', () {
    final b = Buffer.from([1, 2, 3, 4, 5]);
    expect(readUInt16BE(b, 1), 0x0203);
    expect(readUInt32BE(b), 0x01020304);
    expect(() => readUInt16BE(b, 4), throwsRangeError);
    writeUInt16BE(b, 0xabcd, 3);
    expect(b.toString('hex'), '010203abcd');
    expect(b.indexOfBytes([3, 0xab]), 2);
    expect(b.indexOfBytes([1], 1), -1);
    expect(Buffer.concat([b, Buffer.from('a')]).length, 6);
    expect(Buffer.isBuffer(b), isTrue);
    expect(b.readUIntBE(0, 3), 0x010203);
    expect(b.readUIntLE(0, 2), 0x0201);
    expect(() => b.readUIntBE(3, 3), throwsRangeError);
    expect(() => b.readUIntLE(0, 7), throwsRangeError);
    expect(os.endianness(), 'LE');
    expect(Buffer.byteLength('aa', 'hex'), 1);
  });
}
