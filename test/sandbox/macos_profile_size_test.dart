// Ported from sandbox-runtime test/sandbox/macos-profile-size.test.ts @ 24eb39e.
// ignore_for_file: constant_identifier_names, slash_for_doc_comments
import 'dart:convert';
import 'dart:io';

import 'package:path/path.dart' as path;
import 'package:test/test.dart';

import 'package:sandbox_runtime/src/sandbox/macos_sandbox_utils.dart';
import 'package:sandbox_runtime/src/sandbox/sandbox_schemas.dart';

///
/// The Seatbelt profile is passed to sandbox-exec in argv, so its size counts
/// against ARG_MAX (1 MiB on macOS) for every sandboxed exec. These tests pin
/// that a configuration with several hundred denied paths stays under half of
/// that limit, and that the resulting profile still spawns and enforces each
/// kind of path filter it contains (subpath, literal ancestor, regex).
///
void main() {
  group(
    'macOS Seatbelt profile size',
    skip: Platform.isMacOS ? false : 'requires macOS Seatbelt',
    () {
      const MACOS_ARG_MAX = 1024 * 1024;
      const GROUPS = 200;

      final testBaseDir = path.join(
        Directory.systemTemp.resolveSymbolicLinksSync(),
        'seatbelt-size-test-${DateTime.now().millisecondsSinceEpoch}',
      );
      final allowedDir = path.join(testBaseDir, 'allowed');
      String groupDir(int i) => path.join(
        allowedDir,
        'nested',
        'groups',
        'g${i.toString().padLeft(4, '0')}',
      );
      // One group dir exists on disk so a denied write reaches the sandbox
      // check instead of failing with ENOENT on the parent.
      final probedGroup = groupDir(150);

      final denyWithinAllow = <String>[];
      for (var i = 0; i < GROUPS; i++) {
        denyWithinAllow.addAll([
          path.join(groupDir(i), 'a.conf'),
          path.join(groupDir(i), 'a.conf.lock'),
          path.join(groupDir(i), 'b'),
        ]);
      }
      denyWithinAllow.add(path.join(allowedDir, '**', '*.key'));
      final writeConfig = FsWriteRestrictionConfig(
        allowOnly: [allowedDir],
        denyWithinAllow: denyWithinAllow,
      );

      setUpAll(() {
        Directory(probedGroup).createSync(recursive: true);
      });

      tearDownAll(() {
        final base = Directory(testBaseDir);
        if (base.existsSync()) base.deleteSync(recursive: true);
      });

      test('fits ${GROUPS * 3} deny paths in under half of ARG_MAX', () {
        final wrappedCommand = wrapCommandWithSandboxMacOS(
          MacOSSandboxParams(
            command: 'true',
            needsNetworkRestriction: false,
            readConfig: null,
            writeConfig: writeConfig,
          ),
        );

        expect(utf8.encode(wrappedCommand).length, lessThan(MACOS_ARG_MAX / 2));

        // Same-shaped groups fold into regexes: far below one filter per path.

        expect(utf8.encode(wrappedCommand).length, lessThan(64 * 1024));
      });

      test(
        'spawns and enforces subpath, literal-ancestor and regex filters',
        () async {
          final allowedFile = path.join(probedGroup, 'other');
          final deniedFile = path.join(probedGroup, 'a.conf');
          final deniedByGlob = path.join(probedGroup, 'x.key');
          final wrappedCommand = wrapCommandWithSandboxMacOS(
            MacOSSandboxParams(
              command:
                  'touch $allowedFile; touch $deniedFile; touch $deniedByGlob; mv $probedGroup $probedGroup.moved',
              needsNetworkRestriction: false,
              readConfig: null,
              writeConfig: writeConfig,
            ),
          );

          final execution = await _spawnSync(wrappedCommand);

          expect(execution.error, isNull);
          expect(File(allowedFile).existsSync(), isTrue);
          expect(File(deniedFile).existsSync(), isFalse);
          expect(File(deniedByGlob).existsSync(), isFalse);
          expect(Directory('$probedGroup.moved').existsSync(), isFalse);
          expect(
            execution.result!.stderr,
            contains('$deniedFile: Operation not permitted'),
          );
          expect(
            execution.result!.stderr,
            contains('$deniedByGlob: Operation not permitted'),
          );
          expect(
            execution.result!.stderr,
            contains('$probedGroup.moved: Operation not permitted'),
          );
        },
      );

      // Glob denyRead entries are now rendered up to four times (base deny,
      // re-emit after allowRead, move-blocking, trailing unlink re-deny). Pin
      // the size at a few hundred of them, check the profile still compiles and
      // enforces, and log how long wrapping + sandbox-exec startup take so a
      // regression in either shows up in CI output.
      test(
        'fits ${GROUPS * 2 + 100} glob denyRead entries and still enforces them',
        () async {
          final denyOnly = <String>[];
          for (var i = 0; i < GROUPS; i++) {
            denyOnly.addAll([
              path.join(groupDir(i), '**', '*.secret'),
              path.join(groupDir(i), '**', '.env'),
            ]);
          }
          for (var i = 0; i < 100; i++) {
            denyOnly.add(path.join(allowedDir, 'area$i', '**', 'credentials'));
          }
          final secretFile = path.join(probedGroup, 'x.secret');
          final plainFile = path.join(probedGroup, 'x.plain');
          File(secretFile).writeAsStringSync('SIZE_TEST_SECRET');
          File(plainFile).writeAsStringSync('SIZE_TEST_PLAIN');

          final wrapStopwatch = Stopwatch()..start();
          final wrappedCommand = wrapCommandWithSandboxMacOS(
            MacOSSandboxParams(
              command:
                  'cat $plainFile; cat $secretFile; mv $secretFile $secretFile.moved; true',
              needsNetworkRestriction: false,
              readConfig: FsReadRestrictionConfig(
                denyOnly: denyOnly,
                allowWithinDeny: [allowedDir],
              ),
              writeConfig: FsWriteRestrictionConfig(
                allowOnly: [allowedDir],
                denyWithinAllow: [],
              ),
            ),
          );
          wrapStopwatch.stop();
          final wrapMs = wrapStopwatch.elapsedMicroseconds / 1000;
          expect(
            utf8.encode(wrappedCommand).length,
            lessThan(MACOS_ARG_MAX / 2),
          );

          final spawnStopwatch = Stopwatch()..start();
          final execution = await _spawnSync(wrappedCommand);
          spawnStopwatch.stop();
          final spawnMs = spawnStopwatch.elapsedMicroseconds / 1000;
          print(
            '[record] ${denyOnly.length} glob denies: profile ${utf8.encode(wrappedCommand).length} bytes, '
            'wrap ${wrapMs.toStringAsFixed(1)}ms, sandbox-exec+command ${spawnMs.toStringAsFixed(0)}ms',
          );

          expect(execution.error, isNull);
          final result = execution.result!;
          expect(result.exitCode, 0);
          expect(result.stdout, contains('SIZE_TEST_PLAIN'));
          expect(result.stdout, isNot(contains('SIZE_TEST_SECRET')));
          expect(File(secretFile).existsSync(), isTrue);
          expect(File('$secretFile.moved').existsSync(), isFalse);
        },
      );
    },
  );
}

Future<({ProcessResult? result, Object? error})> _spawnSync(
  String wrappedCommand,
) async {
  Process? child;
  try {
    child = await Process.start('/bin/bash', ['-c', wrappedCommand]);
    final stdout = child.stdout.transform(utf8.decoder).join();
    final stderr = child.stderr.transform(utf8.decoder).join();
    final exitCode = await child.exitCode.timeout(const Duration(seconds: 30));
    return (
      result: ProcessResult(child.pid, exitCode, await stdout, await stderr),
      error: null,
    );
  } catch (error) {
    child?.kill();
    return (result: null, error: error);
  }
}
