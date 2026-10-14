// Ported from sandbox-runtime test/utils/ripgrep.test.ts @ 24eb39e.

import 'dart:io';

import 'package:path/path.dart' as path;
import 'package:sandbox_runtime/src/node/abort.dart';
import 'package:sandbox_runtime/src/utils/ripgrep.dart';
import 'package:test/test.dart';

final _nodeExecutable = _findNode();

String? _findNode() {
  final pathEntries =
      Platform.environment['PATH']?.split(Platform.isWindows ? ';' : ':') ??
      const <String>[];
  final executableName = Platform.isWindows ? 'node.exe' : 'node';
  for (final entry in pathEntries) {
    final candidate = File(path.join(entry, executableName));
    if (candidate.existsSync()) return candidate.absolute.path;
  }
  return null;
}

void main() {
  group('ripGrep', () {
    test('finds matches with default config', () async {
      final directory = await Directory.systemTemp.createTemp('rg-test-');
      try {
        File(
          path.join(directory.path, 'a.txt'),
        ).writeAsStringSync('hello\nworld\nfoo');
        final results = await ripGrep(
          ['-l', 'world'],
          directory.path,
          AbortController().signal,
        );
        expect(results, hasLength(1));
        expect(results[0], contains('a.txt'));
      } finally {
        directory.deleteSync(recursive: true);
      }
    });

    test('returns empty array on no matches (exit code 1)', () async {
      final directory = await Directory.systemTemp.createTemp('rg-test-');
      try {
        File(path.join(directory.path, 'a.txt')).writeAsStringSync('hello');
        final results = await ripGrep(
          ['-l', 'nonexistent-pattern-xyz'],
          directory.path,
          AbortController().signal,
        );
        expect(results, isEmpty);
      } finally {
        directory.deleteSync(recursive: true);
      }
    });

    test(
      'passes argv0 to spawn (multicall binary dispatch)',
      () async {
        // Spawn node with a script that echoes process.argv0 — shell scripts can't
        // observe argv0 via $0 (shebang loader resets it), but native binaries can.
        final directory = await Directory.systemTemp.createTemp('rg-argv0-');
        try {
          final script = File(path.join(directory.path, 'echo-argv0.cjs'));
          // ripGrep appends target as the last arg; ignore it and print argv0.
          script.writeAsStringSync('process.stdout.write(process.argv0)');

          final results = await ripGrep(
            [],
            directory.path,
            AbortController().signal,
            RipgrepConfig(
              command: _nodeExecutable!,
              args: [script.path],
              argv0: 'rg',
            ),
          );
          expect(results, ['rg']);
        } finally {
          directory.deleteSync(recursive: true);
        }
      },
      skip: _nodeExecutable == null
          ? 'Node.js is unavailable'
          : Platform.isWindows
          ? 'Dart Process.start cannot override argv[0] on Windows'
          : false,
    );

    test('uses execFile path when argv0 is not set', () async {
      final directory = await Directory.systemTemp.createTemp('rg-noargv0-');
      try {
        final script = File(path.join(directory.path, 'echo-argv0.cjs'));
        script.writeAsStringSync('process.stdout.write(process.argv0)');

        final results = await ripGrep(
          [],
          directory.path,
          AbortController().signal,
          RipgrepConfig(command: _nodeExecutable!, args: [script.path]),
        );
        // Without argv0 override, process.argv0 defaults to the executable path.
        expect(results[0], isNot('rg'));
        expect(results[0], contains(path.basename(_nodeExecutable!)));
      } finally {
        directory.deleteSync(recursive: true);
      }
    }, skip: _nodeExecutable == null ? 'Node.js is unavailable' : false);

    test('says what had been listed when it rejects', () async {
      final directory = await Directory.systemTemp.createTemp('rg-listed-');
      try {
        final script = File(path.join(directory.path, 'lists-then-fails.cjs'));
        script.writeAsStringSync(
          "process.stdout.write('one\\ntwo\\nhalf a li'); "
          "process.stderr.write('went wrong'); process.exitCode = 2",
        );

        Object? error;
        try {
          await ripGrep(
            [],
            directory.path,
            AbortController().signal,
            RipgrepConfig(command: _nodeExecutable!, args: [script.path]),
          );
        } catch (caught) {
          error = caught;
        }

        expect(error, isA<RipgrepError>());
        expect((error! as RipgrepError).listed, ['one', 'two']);
        expect((error as RipgrepError).stderr, 'went wrong');
      } finally {
        directory.deleteSync(recursive: true);
      }
    }, skip: _nodeExecutable == null ? 'Node.js is unavailable' : false);

    test('rejects on exit code > 1', () async {
      await expectLater(
        ripGrep(['--invalid-flag-xyz'], '.', AbortController().signal),
        throwsA(
          predicate(
            (error) =>
                error is RipgrepError &&
                RegExp(r'ripgrep failed').hasMatch(error.message),
            'RipgrepError whose message matches /ripgrep failed/',
          ),
        ),
      );
    });
  });
}
