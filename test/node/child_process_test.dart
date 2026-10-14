@TestOn("!windows")
library;

import 'dart:async';

import 'package:sandbox_runtime/src/node/buffer.dart';
import 'package:sandbox_runtime/src/node/child_process.dart';
import 'package:sandbox_runtime/src/node/errno.dart';
import 'package:test/test.dart';
import 'dart:io' show Platform;

void reaperTest(String name, dynamic Function() body) => test(name, body,
    skip: Platform.isLinux
        ? 'Linux: VM reaper steals child status; pending spawn helper (PORT_WORKLOG)'
        : null);

void main() {
  reaperTest('spawnSync pipes input and returns Buffers without encoding', () {
    final r = spawnSync('cat', [], {'input': 'hi'});
    expect(r.status, 0);
    expect(r.stdout, isA<Buffer>());
    expect((r.stdout as Buffer).toString(), 'hi');
    expect(r.pid, greaterThan(0));
  });

  reaperTest('spawnSync encoding, stderr, exit status and env', () {
    final r = spawnSync(
      'sh',
      ['-c', r'echo $FOO; echo e >&2; exit 4'],
      {
        'encoding': 'utf8',
        'env': {'FOO': 'bar', 'PATH': '/usr/bin:/bin'},
      },
    );
    expect(r.stdout, 'bar\n');
    expect(r.stderr, 'e\n');
    expect(r.status, 4);
    expect(r.signal, isNull);
    expect(r.error, isNull);
  });

  reaperTest('spawnSync stdio ignore yields null output', () {
    final r = spawnSync(
      'echo',
      ['x'],
      {
        'stdio': ['ignore', 'pipe', 'ignore'],
      },
    );
    expect((r.stdout as Buffer).toString(), 'x\n');
    expect(r.stderr, isNull);
  });

  reaperTest('spawnSync timeout kills with SIGTERM and reports ETIMEDOUT', () {
    final r = spawnSync('sleep', ['5'], {'timeout': 100});
    expect(r.status, isNull);
    expect(r.signal, 'SIGTERM');
    expect((r.error as NodeError).code, 'ETIMEDOUT');
    expect((r.error as NodeError).syscall, 'spawnSync sleep');
  });

  reaperTest('spawnSync launch failure is an ENOENT error, not a throw', () {
    final r = spawnSync('definitely-not-a-command-xyz', ['a']);
    expect(r.status, isNull);
    final e = r.error as NodeError;
    expect(e.code, 'ENOENT');
    expect(e.syscall, 'spawnSync definitely-not-a-command-xyz');
    expect(e.spawnargs, ['a']);
  });

  reaperTest('shell option runs the joined line through /bin/sh', () {
    final r = spawnSync(
      'echo',
      [r'$((1+2))'],
      {'shell': true, 'encoding': 'utf8'},
    );
    expect(r.stdout, '3\n');
  });

  reaperTest('spawnSync cwd', () {
    final r = spawnSync('pwd', [], {'cwd': '/', 'encoding': 'utf8'});
    expect(r.stdout, '/\n');
  });

  reaperTest('spawn: sync pid, stdin, exit and close events', () async {
    final child = spawn('sh', ['-c', r'read x; echo got $x; exit 3']);
    expect(child.pid, isNotNull);
    final out = <int>[];
    child.stdout!.listen(out.addAll);
    child.stdin!.end('a\n');
    final exit = Completer<(int?, String?)>();
    child.on('exit', (int? c, String? s) => exit.complete((c, s)));
    final closed = Completer<void>();
    child.on('close', (int? c, String? s) => closed.complete());
    expect(await exit.future, (3, null));
    await closed.future;
    expect(String.fromCharCodes(out), 'got a\n');
    expect(child.exitCode, 3);
  });

  reaperTest('spawn: kill reports the signal', () async {
    final child = spawn('sleep', ['5']);
    final exit = Completer<(int?, String?)>();
    child.on('exit', (int? c, String? s) => exit.complete((c, s)));
    expect(child.kill('SIGKILL'), isTrue);
    expect(await exit.future, (null, 'SIGKILL'));
    expect(child.signalCode, 'SIGKILL');
    expect(child.kill(), isFalse);
  });

  reaperTest('spawn: launch failure has null pid and an async error event', () async {
    final child = spawn('definitely-not-a-command-xyz');
    expect(child.pid, isNull);
    final err = Completer<Object>();
    child.on('error', (Object e) => err.complete(e));
    expect((await err.future as NodeError).code, 'ENOENT');
  });

  reaperTest('killPid with an unknown pid throws ESRCH', () {
    expect(
      () => killPid(0x7ffffff0, 'SIGTERM'),
      throwsA(isA<NodeError>().having((e) => e.code, 'code', 'ESRCH')),
    );
    expect(
      () => killPid(1, 'SIGBOGUS'),
      throwsA(
        isA<NodeError>().having((e) => e.code, 'code', 'ERR_UNKNOWN_SIGNAL'),
      ),
    );
  });

  reaperTest('execSync throws on failure, returns stdout', () {
    expect(execSync('echo', ['hi']), 'hi\n');
    expect(() => execSync('false', []), throwsA(isA<NodeError>()));
    expect(
      () => execSync('sleep', ['5'], timeout: const Duration(seconds: 1)),
      throwsA(isA<NodeError>().having((e) => e.code, 'code', 'ETIMEDOUT')),
    );
  });
}
