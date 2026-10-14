import 'dart:io';

import 'package:path/path.dart' as p;
import 'package:sandbox_runtime/src/node/buffer.dart';
import 'package:sandbox_runtime/src/node/errno.dart';
import 'package:sandbox_runtime/src/node/fs.dart' as fs;
import 'package:sandbox_runtime/src/node/process.dart' as process;
import 'package:test/test.dart';

void main() {
  late String dir;
  setUp(() => dir = fs.mkdtempSync(p.join(Directory.systemTemp.path, 'fs-')));
  tearDown(() => fs.rmSync(dir, {'recursive': true, 'force': true}));

  test('mkdtempSync takes a full-path prefix', () {
    expect(p.basename(dir), startsWith('fs-'));
    expect(Directory(dir).existsSync(), isTrue);
  }, testOn: '!windows');

  test('statSync reports uid, mode, size and type', () {
    final f = p.join(dir, 'f');
    fs.writeFileSync(f, 'abc', {'mode': 0x180});
    final st = fs.statSync(f);
    expect(st.isFile(), isTrue);
    expect(st.size, 3);
    expect(st.mode & 0x1ff, 0x180);
    expect(st.uid, process.getuid!());
    expect(st.ino, isNot(0));
    expect(st.mtimeMs, closeTo(DateTime.now().millisecondsSinceEpoch, 60000));
    Link(p.join(dir, 'l')).createSync(f);
    expect(fs.lstatSync(p.join(dir, 'l')).isSymbolicLink(), isTrue);
    expect(fs.statSync(p.join(dir, 'l')).isSymbolicLink(), isFalse);
  }, testOn: '!windows');

  test(
    'writeFileSync mode applies only on creation, honours umask-free open',
    () {
      final f = p.join(dir, 'k');
      fs.writeFileSync(f, 'x', {'mode': 0x180});
      expect(fs.statSync(f).mode & 0x1ff, 0x180);
      fs.chmodSync(f, 0x1a4);
      fs.writeFileSync(f, 'y', {'mode': 0x180});
      expect(fs.statSync(f).mode & 0x1ff, 0x1a4);
      expect(fs.readFileSync(f, 'utf8'), 'y');
    },
    testOn: '!windows',
  );

  test('errors carry code, syscall and path', () {
    final missing = p.join(dir, 'nope', 'x');
    for (final call in <void Function()>[
      () => fs.openSync(missing, 'r'),
      () => fs.statSync(missing),
      () => fs.writeFileSync(missing, 'x'),
    ]) {
      expect(
        call,
        throwsA(
          isA<NodeError>()
              .having((e) => e.code, 'code', 'ENOENT')
              .having((e) => e.path, 'path', missing),
        ),
      );
    }
    final e = (() {
      try {
        fs.openSync(missing, 'r');
      } on NodeError catch (e) {
        return e;
      }
    })()!;
    expect(e.syscall, 'open');
    expect(e.message, "ENOENT: no such file or directory, open '$missing'");
    expect(
      () => fs.closeSync(9999),
      throwsA(isA<NodeError>().having((e) => e.code, 'code', 'EBADF')),
    );
  }, testOn: '!windows');

  test('mkdirSync recursive returns the first created directory', () {
    final deep = p.join(dir, 'a', 'b', 'c');
    expect(fs.mkdirSync(deep, {'recursive': true}), p.join(dir, 'a'));
    expect(fs.mkdirSync(deep, {'recursive': true}), isNull);
    expect(
      () => fs.mkdirSync(deep),
      throwsA(isA<NodeError>().having((e) => e.code, 'code', 'EEXIST')),
    );
  }, testOn: '!windows');

  test('fd calls: openSync, writeFileSync(fd), fstatSync, readvSync', () {
    final f = p.join(dir, 'fd');
    final fd = fs.openSync(f, 'w+', 0x180);
    fs.writeFileSync(fd, 'hello');
    expect(fs.fstatSync(fd).size, 5);
    expect(fs.fstatSync(fd).isFile(), isTrue);
    final a = Buffer.alloc(2), b = Buffer.alloc(10);
    expect(fs.readvSync(fd, [a, b], 0), 5);
    expect(a.toString(), 'he');
    expect(b.toString().substring(0, 3), 'llo');
    expect(fs.readvSync(fd, [Buffer.alloc(0)]), 0);
    fs.closeSync(fd);
    expect(() => fs.fstatSync(fd), throwsA(isA<NodeError>()));
    final rfd = fs.openSync(f, 'r');
    expect(fs.readFileSync(rfd, 'utf8'), 'hello');
    fs.closeSync(rfd);
  }, testOn: '!windows');

  test('O_TMPFILE flag value composes like upstream', () {
    final flag = 0x400000 | fs.constants.O_DIRECTORY;
    if (Platform.isLinux) {
      final fd = fs.openSync(dir, flag | fs.constants.O_RDWR, 0x180);
      fs.writeFileSync(fd, 'x');
      expect(fs.fstatSync(fd).nlink, 0);
      fs.closeSync(fd);
    }
  }, testOn: 'linux');

  test('renameSync and unlinkSync', () {
    final a = p.join(dir, 'a'), b = p.join(dir, 'b');
    fs.writeFileSync(a, '1');
    fs.renameSync(a, b);
    expect(fs.existsSync(b), isTrue);
    fs.unlinkSync(b);
    expect(
      () => fs.unlinkSync(b),
      throwsA(isA<NodeError>().having((e) => e.syscall, 's', 'unlink')),
    );
  }, testOn: '!windows');
}
