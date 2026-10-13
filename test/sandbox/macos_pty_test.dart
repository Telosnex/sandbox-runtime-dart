// Ported from sandbox-runtime test/sandbox/macos-pty.test.ts @ 24eb39e.
import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:path/path.dart' as path;
import 'package:test/test.dart';

import 'package:sandbox_runtime/src/sandbox/macos_sandbox_utils.dart';
import 'package:sandbox_runtime/src/sandbox/sandbox_schemas.dart';

Future<ProcessResult> _spawnSyncLike(String command, Duration timeout) async {
  final child = await Process.start('/bin/sh', ['-c', command]);
  final stdout = child.stdout.transform(utf8.decoder).join();
  final stderr = child.stderr.transform(utf8.decoder).join();
  try {
    final exitCode = await child.exitCode.timeout(timeout);
    return ProcessResult(child.pid, exitCode, await stdout, await stderr);
  } on TimeoutException {
    child.kill(ProcessSignal.sigkill);
    return ProcessResult(child.pid, -1, await stdout, await stderr);
  }
}

void main() {
  group(
    'macOS Seatbelt PTY Support',
    skip: Platform.isMacOS ? false : 'macOS only',
    () {
      final testBaseDir = path.join(
        Directory.systemTemp.path,
        'seatbelt-pty-test-${DateTime.now().millisecondsSinceEpoch}',
      );
      setUpAll(() {
        Directory(testBaseDir).createSync(recursive: true);
      });
      tearDownAll(() {
        final dir = Directory(testBaseDir);
        if (dir.existsSync()) dir.deleteSync(recursive: true);
      });

      test('should allow PTY operations when allowPty is true', () async {
        final outputFile = path.join(testBaseDir, 'pty-output.txt');
        final writeConfig = FsWriteRestrictionConfig(
          allowOnly: [testBaseDir],
          denyWithinAllow: [],
        );

        // Use 'script' command which requires PTY allocation
        final wrappedCommand = wrapCommandWithSandboxMacOS(
          MacOSSandboxParams(
            command: 'script -q $outputFile echo "pty works"',
            needsNetworkRestriction: false,
            readConfig: null,
            writeConfig: writeConfig,
            allowPty: true,
          ),
        );

        final result = await _spawnSyncLike(
          wrappedCommand,
          const Duration(seconds: 10),
        );

        expect(result.exitCode, 0);
        expect(
          FileSystemEntity.typeSync(outputFile),
          isNot(FileSystemEntityType.notFound),
        );
        final content = File(outputFile).readAsStringSync();
        expect(content, contains('pty works'));
      });

      test('should block PTY operations when allowPty is false', () async {
        final outputFile = path.join(testBaseDir, 'pty-blocked.txt');
        final writeConfig = FsWriteRestrictionConfig(
          allowOnly: [testBaseDir],
          denyWithinAllow: [],
        );

        final wrappedCommand = wrapCommandWithSandboxMacOS(
          MacOSSandboxParams(
            command: 'script -q $outputFile echo "should fail"',
            needsNetworkRestriction: false,
            readConfig: null,
            writeConfig: writeConfig,
            allowPty: false,
          ),
        );

        final result = await _spawnSyncLike(
          wrappedCommand,
          const Duration(seconds: 10),
        );

        expect(result.exitCode, isNot(0));
      });
    },
  );
}
