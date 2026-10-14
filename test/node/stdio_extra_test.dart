import 'dart:convert';
import 'dart:io' as io;

import 'package:sandbox_runtime/src/node/child_process.dart';
import 'package:sandbox_runtime/src/node/events.dart' as events;
import 'package:sandbox_runtime/src/node/fs.dart' as fs;
import 'package:sandbox_runtime/src/node/net.dart' as net;
import 'package:test/test.dart';

void main() {
  late io.Directory tmp;
  setUp(() => tmp = io.Directory.systemTemp.createTempSync('stdio_extra'));
  tearDown(() => tmp.deleteSync(recursive: true));

  test('spawn extra pipe is a duplex socket', () async {
    final child = spawn(
      '/bin/sh',
      ['-c', 'cat <&5 >&5; echo done'],
      {
        'stdio': ['ignore', 'pipe', 'ignore', 'ignore', 'ignore', 'pipe'],
      },
    );
    expect(child.stdio.length, 6);
    final sock = child.stdio[5]! as net.NodeSocket;
    final got = <int>[];
    sock.on('data', (Object? d) => got.addAll(d as List<int>));
    sock.end('hello');
    final closed = Future<void>.delayed(const Duration(seconds: 10));
    await Future.any([closed, events.once(child, 'close')]);
    expect(utf8.decode(got), 'hello');
  });

  test('int fd is inherited at its slot; writeSync, copyFileSync', () {
    final f = '${tmp.path}/a';
    final fd = fs.openSync(f, 'w');
    expect(fs.writeSync(fd, 'xy'), 2);
    final r = spawnSync(
      '/bin/sh',
      ['-c', 'printf zz >&7'],
      {
        'stdio': [
          'ignore',
          'ignore',
          'ignore',
          'ignore',
          'ignore',
          'ignore',
          'ignore',
          fd,
        ],
      },
    );
    fs.closeSync(fd);
    expect(r.status, 0);
    fs.copyFileSync(f, '${tmp.path}/b');
    expect(io.File('${tmp.path}/b').readAsStringSync(), 'xyzz');
    expect(() => fs.copyFileSync(f, '${tmp.path}/b', 1), throwsA(anything));
  });

  test('spawnSync collects extra pipes', () {
    final r = spawnSync(
      '/bin/sh',
      ['-c', 'printf hi >&3'],
      {
        'stdio': ['ignore', 'ignore', 'ignore', 'pipe'],
      },
    );
    expect(
      utf8.decode((r.output[3]! as dynamic).toUint8List() as List<int>),
      'hi',
    );
  });
}
