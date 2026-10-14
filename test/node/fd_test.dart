@TestOn('mac-os || linux')
library;

import 'dart:ffi';
import 'dart:io';

import 'package:sandbox_runtime/src/node/errno.dart';
import 'package:sandbox_runtime/src/node/fd.dart';
import 'package:test/test.dart';

final int Function(int) _dup = DynamicLibrary.process()
    .lookupFunction<Int32 Function(Int32), int Function(int)>('dup');

void main() {
  test('rejects an invalid file descriptor with EBADF', () {
    expect(
      () => setCloseOnExec(-1),
      throwsA(isA<NodeError>().having((e) => e.code, 'code', 'EBADF')),
    );
  });

  test(
    'sets FD_CLOEXEC, and a spawned child does not inherit the fd',
    () async {
      // dup() returns a descriptor without FD_CLOEXEC.
      final fd = _dup(2);
      expect(fd, greaterThan(2));
      expect(getFdFlags(fd) & 1, 0);
      final before = await Process.run('/bin/sh', [
        '-c',
        'if (: <&$fd) 2>/dev/null; then echo open; else echo closed; fi',
      ]);
      setCloseOnExec(fd);
      expect(getFdFlags(fd) & 1, 1);
      final after = await Process.run('/bin/sh', [
        '-c',
        'if (: <&$fd) 2>/dev/null; then echo open; else echo closed; fi',
      ]);
      expect((after.stdout as String).trim(), 'closed');
      // Informative: dart:io may close extra fds itself when spawning.
      printOnFailure('before: ${before.stdout}');
    },
  );
}
