// Ported from sandbox-runtime test/sandbox/macos-seatbelt.test.ts @ 24eb39e.
// ignore_for_file: constant_identifier_names, non_constant_identifier_names
// ignore_for_file: slash_for_doc_comments

import 'dart:convert';
import 'dart:io';

import 'package:path/path.dart' as path;
import 'package:test/test.dart';

import 'package:sandbox_runtime/src/sandbox/macos_sandbox_utils.dart';
import 'package:sandbox_runtime/src/sandbox/sandbox_schemas.dart';

bool _exists(String pathName) =>
    FileSystemEntity.typeSync(pathName, followLinks: false) !=
    FileSystemEntityType.notFound;

void _mkdir(String pathName) => Directory(pathName).createSync(recursive: true);
void _write(String pathName, String contents) =>
    File(pathName).writeAsStringSync(contents);
String _read(String pathName) => File(pathName).readAsStringSync();
void _remove(String pathName) {
  final directory = Directory(pathName);
  if (directory.existsSync()) directory.deleteSync(recursive: true);
}

ProcessResult _spawnSync(String command) => Process.runSync(
  '/bin/sh',
  ['-c', command],
  stdoutEncoding: utf8,
  stderrEncoding: utf8,
);

/// Tests for macOS Seatbelt read bypass vulnerability
///
/// Issue: Files protected by read deny rules could be exfiltrated by moving them
/// to readable locations using the mv command. The rename() syscall was not blocked
/// by file-read* rules.
///
/// Fix: Added file-write-unlink deny rules to block rename/move operations on:
/// 1. The denied files/directories themselves
/// 2. All ancestor directories (to prevent moving parent directories)
///
/// These tests use the actual sandbox profile generation code to ensure real-world coverage.
void main() {
  group(
    'macOS Seatbelt Read Bypass Prevention',
    skip: Platform.isMacOS ? false : 'requires macOS Seatbelt',
    () {
      final TEST_BASE_DIR = path.join(
        Directory.systemTemp.path,
        'seatbelt-test-${DateTime.now().millisecondsSinceEpoch}',
      );
      final TEST_DENIED_DIR = path.join(TEST_BASE_DIR, 'denied-dir');
      final TEST_SECRET_FILE = path.join(TEST_DENIED_DIR, 'secret.txt');
      const TEST_SECRET_CONTENT = 'SECRET_CREDENTIAL_DATA';
      final TEST_MOVED_FILE = path.join(TEST_BASE_DIR, 'moved-secret.txt');
      final TEST_MOVED_DIR = path.join(TEST_BASE_DIR, 'moved-denied-dir');

      // Additional test files for glob pattern testing
      final TEST_GLOB_DIR = path.join(TEST_BASE_DIR, 'glob-test');
      final TEST_GLOB_FILE1 = path.join(TEST_GLOB_DIR, 'secret1.txt');
      final TEST_GLOB_FILE2 = path.join(TEST_GLOB_DIR, 'secret2.log');
      final TEST_GLOB_MOVED = path.join(TEST_BASE_DIR, 'moved-glob.txt');

      setUpAll(() {
        // Create test directory structure
        _mkdir(TEST_DENIED_DIR);
        _write(TEST_SECRET_FILE, TEST_SECRET_CONTENT);

        // Create glob test files
        _mkdir(TEST_GLOB_DIR);
        _write(TEST_GLOB_FILE1, 'GLOB_SECRET_1');
        _write(TEST_GLOB_FILE2, 'GLOB_SECRET_2');
      });

      tearDownAll(() {
        // Clean up test directory
        if (_exists(TEST_BASE_DIR)) _remove(TEST_BASE_DIR);
      });

      group('Literal Path - Direct File Move Prevention', () {
        test(
          'should block moving a read-denied file to a readable location',
          () {
            // Use actual read restriction config with literal path
            final readConfig = FsReadRestrictionConfig(
              denyOnly: [TEST_DENIED_DIR],
            );

            // Generate actual sandbox command using our production code
            final wrappedCommand = wrapCommandWithSandboxMacOS(
              MacOSSandboxParams(
                command: 'mv $TEST_SECRET_FILE $TEST_MOVED_FILE',
                needsNetworkRestriction: false,
                readConfig: readConfig,
                writeConfig: null,
              ),
            );

            // Verify the file exists before test
            expect(_exists(TEST_SECRET_FILE), isTrue);

            // Execute the wrapped command
            final result = _spawnSync(wrappedCommand);

            // The move should fail with operation not permitted
            expect(result.exitCode, isNot(0));
            final output = (result.stderr as String).toLowerCase();
            expect(output, contains('operation not permitted'));

            // Verify the file was NOT moved
            expect(_exists(TEST_SECRET_FILE), isTrue);
            expect(_exists(TEST_MOVED_FILE), isFalse);
          },
        );

        test('should still block reading the file (sanity check)', () {
          // Use actual read restriction config
          final readConfig = FsReadRestrictionConfig(
            denyOnly: [TEST_DENIED_DIR],
          );

          // Generate actual sandbox command
          final wrappedCommand = wrapCommandWithSandboxMacOS(
            MacOSSandboxParams(
              command: 'cat $TEST_SECRET_FILE',
              needsNetworkRestriction: false,
              readConfig: readConfig,
              writeConfig: null,
            ),
          );

          // Execute the wrapped command
          final result = _spawnSync(wrappedCommand);

          // The read should fail
          expect(result.exitCode, isNot(0));
          final output = (result.stderr as String).toLowerCase();
          expect(output, contains('operation not permitted'));

          // Should NOT see the secret content
          expect(result.stdout, isNot(contains(TEST_SECRET_CONTENT)));
        });
      });

      group('Literal Path - Ancestor Directory Move Prevention', () {
        test(
          'should block moving an ancestor directory of a read-denied file',
          () {
            // Use actual read restriction config
            final readConfig = FsReadRestrictionConfig(
              denyOnly: [TEST_DENIED_DIR],
            );

            // Generate actual sandbox command
            final wrappedCommand = wrapCommandWithSandboxMacOS(
              MacOSSandboxParams(
                command: 'mv $TEST_DENIED_DIR $TEST_MOVED_DIR',
                needsNetworkRestriction: false,
                readConfig: readConfig,
                writeConfig: null,
              ),
            );

            // Verify the directory exists before test
            expect(_exists(TEST_DENIED_DIR), isTrue);

            // Execute the wrapped command
            final result = _spawnSync(wrappedCommand);

            // The move should fail
            expect(result.exitCode, isNot(0));
            final output = (result.stderr as String).toLowerCase();
            expect(output, contains('operation not permitted'));

            // Verify the directory was NOT moved
            expect(_exists(TEST_DENIED_DIR), isTrue);
            expect(_exists(TEST_MOVED_DIR), isFalse);
          },
        );

        test('should block moving the grandparent directory', () {
          // Deny reading a specific file deep in the hierarchy
          final readConfig = FsReadRestrictionConfig(
            denyOnly: [TEST_SECRET_FILE],
          );
          final movedBaseDir = path.join(
            Directory.systemTemp.path,
            'moved-base-${DateTime.now().millisecondsSinceEpoch}',
          );

          // Try to move the grandparent directory (TEST_BASE_DIR)
          final wrappedCommand = wrapCommandWithSandboxMacOS(
            MacOSSandboxParams(
              command: 'mv $TEST_BASE_DIR $movedBaseDir',
              needsNetworkRestriction: false,
              readConfig: readConfig,
              writeConfig: null,
            ),
          );

          // Execute the wrapped command
          final result = _spawnSync(wrappedCommand);

          // The move should fail because TEST_BASE_DIR is an ancestor of TEST_SECRET_FILE
          expect(result.exitCode, isNot(0));
          final output = (result.stderr as String).toLowerCase();
          expect(output, contains('operation not permitted'));

          // Verify the directory was NOT moved
          expect(_exists(TEST_BASE_DIR), isTrue);
          expect(_exists(movedBaseDir), isFalse);
        });
      });

      group('Glob Pattern - File Move Prevention', () {
        test('should block moving files matching a glob pattern (*.txt)', () {
          // Use glob pattern that matches all .txt files in glob-test directory
          final globPattern = path.join(TEST_GLOB_DIR, '*.txt');
          final readConfig = FsReadRestrictionConfig(denyOnly: [globPattern]);

          // Try to move a .txt file that matches the pattern
          final wrappedCommand = wrapCommandWithSandboxMacOS(
            MacOSSandboxParams(
              command: 'mv $TEST_GLOB_FILE1 $TEST_GLOB_MOVED',
              needsNetworkRestriction: false,
              readConfig: readConfig,
              writeConfig: null,
            ),
          );

          // Verify file exists
          expect(_exists(TEST_GLOB_FILE1), isTrue);

          // Execute the wrapped command
          final result = _spawnSync(wrappedCommand);

          // The move should fail for .txt file
          expect(result.exitCode, isNot(0));
          final output = (result.stderr as String).toLowerCase();
          expect(output, contains('operation not permitted'));

          // Verify the file was NOT moved
          expect(_exists(TEST_GLOB_FILE1), isTrue);
          expect(_exists(TEST_GLOB_MOVED), isFalse);
        });

        test('should still block reading files matching the glob pattern', () {
          // Use glob pattern
          final globPattern = path.join(TEST_GLOB_DIR, '*.txt');
          final readConfig = FsReadRestrictionConfig(denyOnly: [globPattern]);

          // Try to read a file matching the glob
          final wrappedCommand = wrapCommandWithSandboxMacOS(
            MacOSSandboxParams(
              command: 'cat $TEST_GLOB_FILE1',
              needsNetworkRestriction: false,
              readConfig: readConfig,
              writeConfig: null,
            ),
          );

          // Execute the wrapped command
          final result = _spawnSync(wrappedCommand);

          // The read should fail
          expect(result.exitCode, isNot(0));
          final output = (result.stderr as String).toLowerCase();
          expect(output, contains('operation not permitted'));

          // Should NOT see the content
          expect(result.stdout, isNot(contains('GLOB_SECRET_1')));
        });

        test(
          'should block moving the parent directory containing glob-matched files',
          () {
            // Use glob pattern
            final globPattern = path.join(TEST_GLOB_DIR, '*.txt');
            final readConfig = FsReadRestrictionConfig(denyOnly: [globPattern]);
            final movedGlobDir = path.join(TEST_BASE_DIR, 'moved-glob-dir');

            // Try to move the parent directory
            final wrappedCommand = wrapCommandWithSandboxMacOS(
              MacOSSandboxParams(
                command: 'mv $TEST_GLOB_DIR $movedGlobDir',
                needsNetworkRestriction: false,
                readConfig: readConfig,
                writeConfig: null,
              ),
            );

            // Execute the wrapped command
            final result = _spawnSync(wrappedCommand);

            // The move should fail because TEST_GLOB_DIR is an ancestor of the glob pattern
            expect(result.exitCode, isNot(0));
            final output = (result.stderr as String).toLowerCase();
            expect(output, contains('operation not permitted'));

            // Verify the directory was NOT moved
            expect(_exists(TEST_GLOB_DIR), isTrue);
            expect(_exists(movedGlobDir), isFalse);
          },
        );
      });

      group('Glob Pattern - Recursive Patterns', () {
        test(
          'should block moving files matching a recursive glob pattern (**/*.txt)',
          () {
            // Create nested directory structure
            final nestedDir = path.join(TEST_GLOB_DIR, 'nested');
            final nestedFile = path.join(nestedDir, 'nested-secret.txt');
            _mkdir(nestedDir);
            _write(nestedFile, 'NESTED_SECRET');

            // Use recursive glob pattern
            final globPattern = path.join(TEST_GLOB_DIR, '**', '*.txt');
            final readConfig = FsReadRestrictionConfig(denyOnly: [globPattern]);
            final movedNested = path.join(TEST_BASE_DIR, 'moved-nested.txt');

            // Try to move the nested file
            final wrappedCommand = wrapCommandWithSandboxMacOS(
              MacOSSandboxParams(
                command: 'mv $nestedFile $movedNested',
                needsNetworkRestriction: false,
                readConfig: readConfig,
                writeConfig: null,
              ),
            );

            // Execute the wrapped command
            final result = _spawnSync(wrappedCommand);

            // The move should fail
            expect(result.exitCode, isNot(0));
            final output = (result.stderr as String).toLowerCase();
            expect(output, contains('operation not permitted'));

            // Verify the file was NOT moved
            expect(_exists(nestedFile), isTrue);
            expect(_exists(movedNested), isFalse);
          },
        );
      });
    },
  );

  group(
    'macOS Seatbelt Write Bypass Prevention',
    skip: Platform.isMacOS ? false : 'requires macOS Seatbelt',
    () {
      final TEST_BASE_DIR = path.join(
        Directory.systemTemp.path,
        'seatbelt-write-test-${DateTime.now().millisecondsSinceEpoch}',
      );
      final TEST_ALLOWED_DIR = path.join(TEST_BASE_DIR, 'allowed');
      final TEST_DENIED_DIR = path.join(TEST_ALLOWED_DIR, 'secrets');
      final TEST_DENIED_FILE = path.join(TEST_DENIED_DIR, 'secret.txt');
      const TEST_ORIGINAL_CONTENT = 'ORIGINAL_CONTENT';
      const TEST_MODIFIED_CONTENT = 'MODIFIED_CONTENT';

      // Additional test paths
      final TEST_RENAMED_DIR = path.join(TEST_BASE_DIR, 'renamed-secrets');

      // Glob pattern test paths
      final TEST_GLOB_DIR = path.join(TEST_ALLOWED_DIR, 'glob-test');
      final TEST_GLOB_SECRET1 = path.join(TEST_GLOB_DIR, 'secret1.txt');
      final TEST_GLOB_SECRET2 = path.join(TEST_GLOB_DIR, 'secret2.log');
      final TEST_GLOB_RENAMED = path.join(TEST_BASE_DIR, 'renamed-glob');

      setUpAll(() {
        // Create test directory structure
        _mkdir(TEST_DENIED_DIR);
        _mkdir(TEST_GLOB_DIR);

        // Create test files with original content
        _write(TEST_DENIED_FILE, TEST_ORIGINAL_CONTENT);
        _write(TEST_GLOB_SECRET1, TEST_ORIGINAL_CONTENT);
        _write(TEST_GLOB_SECRET2, TEST_ORIGINAL_CONTENT);
      });

      tearDownAll(() {
        if (_exists(TEST_BASE_DIR)) _remove(TEST_BASE_DIR);
      });

      group('Literal Path - Direct Directory Move Prevention', () {
        test(
          'should block write bypass via directory rename (mv a c, write c/b, mv c a)',
          () {
            // Allow writing to TEST_ALLOWED_DIR but deny TEST_DENIED_DIR
            final writeConfig = FsWriteRestrictionConfig(
              allowOnly: [TEST_ALLOWED_DIR],
              denyWithinAllow: [TEST_DENIED_DIR],
            );

            // Step 1: Try to rename the denied directory
            final mvCommand1 = wrapCommandWithSandboxMacOS(
              MacOSSandboxParams(
                command: 'mv $TEST_DENIED_DIR $TEST_RENAMED_DIR',
                needsNetworkRestriction: false,
                readConfig: null,
                writeConfig: writeConfig,
              ),
            );
            final result1 = _spawnSync(mvCommand1);

            // The move should fail
            expect(result1.exitCode, isNot(0));
            final output1 = (result1.stderr as String).toLowerCase();
            expect(output1, contains('operation not permitted'));

            // Verify the directory was NOT moved
            expect(_exists(TEST_DENIED_DIR), isTrue);
            expect(_exists(TEST_RENAMED_DIR), isFalse);
          },
        );

        test(
          'should still block direct writes to denied paths (sanity check)',
          () {
            final writeConfig = FsWriteRestrictionConfig(
              allowOnly: [TEST_ALLOWED_DIR],
              denyWithinAllow: [TEST_DENIED_DIR],
            );

            // Try to write directly to the denied file
            final wrappedCommand = wrapCommandWithSandboxMacOS(
              MacOSSandboxParams(
                command: 'echo "$TEST_MODIFIED_CONTENT" > $TEST_DENIED_FILE',
                needsNetworkRestriction: false,
                readConfig: null,
                writeConfig: writeConfig,
              ),
            );
            final result = _spawnSync(wrappedCommand);

            // The write should fail
            expect(result.exitCode, isNot(0));
            final output = (result.stderr as String).toLowerCase();
            expect(output, contains('operation not permitted'));

            // Verify the file was NOT modified
            expect(_read(TEST_DENIED_FILE), TEST_ORIGINAL_CONTENT);
          },
        );
      });

      group('Literal Path - Ancestor Directory Move Prevention', () {
        test(
          'should block moving an ancestor directory of a write-denied path',
          () {
            final writeConfig = FsWriteRestrictionConfig(
              allowOnly: [TEST_ALLOWED_DIR],
              denyWithinAllow: [TEST_DENIED_FILE],
            );
            final movedAllowedDir = path.join(TEST_BASE_DIR, 'moved-allowed');

            // Try to move the parent directory (TEST_ALLOWED_DIR)
            final wrappedCommand = wrapCommandWithSandboxMacOS(
              MacOSSandboxParams(
                command: 'mv $TEST_ALLOWED_DIR $movedAllowedDir',
                needsNetworkRestriction: false,
                readConfig: null,
                writeConfig: writeConfig,
              ),
            );
            final result = _spawnSync(wrappedCommand);

            // The move should fail because TEST_ALLOWED_DIR is an ancestor
            expect(result.exitCode, isNot(0));
            final output = (result.stderr as String).toLowerCase();
            expect(output, contains('operation not permitted'));

            // Verify the directory was NOT moved
            expect(_exists(TEST_ALLOWED_DIR), isTrue);
            expect(_exists(movedAllowedDir), isFalse);
          },
        );

        test('should block moving the grandparent directory', () {
          final writeConfig = FsWriteRestrictionConfig(
            allowOnly: [TEST_ALLOWED_DIR],
            denyWithinAllow: [TEST_DENIED_FILE],
          );
          final movedBaseDir = path.join(
            Directory.systemTemp.path,
            'moved-write-base-${DateTime.now().millisecondsSinceEpoch}',
          );

          // Try to move the grandparent directory (TEST_BASE_DIR)
          final wrappedCommand = wrapCommandWithSandboxMacOS(
            MacOSSandboxParams(
              command: 'mv $TEST_BASE_DIR $movedBaseDir',
              needsNetworkRestriction: false,
              readConfig: null,
              writeConfig: writeConfig,
            ),
          );
          final result = _spawnSync(wrappedCommand);

          // The move should fail because TEST_BASE_DIR is an ancestor
          expect(result.exitCode, isNot(0));
          final output = (result.stderr as String).toLowerCase();
          expect(output, contains('operation not permitted'));

          // Verify the directory was NOT moved
          expect(_exists(TEST_BASE_DIR), isTrue);
          expect(_exists(movedBaseDir), isFalse);
        });
      });

      group('Glob Pattern - File Move Prevention', () {
        test('should block write bypass via moving glob-matched files', () {
          // Allow writing to TEST_ALLOWED_DIR but deny *.txt files in glob-test
          final globPattern = path.join(TEST_GLOB_DIR, '*.txt');
          final writeConfig = FsWriteRestrictionConfig(
            allowOnly: [TEST_ALLOWED_DIR],
            denyWithinAllow: [globPattern],
          );

          // Try to move a .txt file
          final mvCommand = wrapCommandWithSandboxMacOS(
            MacOSSandboxParams(
              command:
                  'mv $TEST_GLOB_SECRET1 ${path.join(TEST_BASE_DIR, 'moved-secret.txt')}',
              needsNetworkRestriction: false,
              readConfig: null,
              writeConfig: writeConfig,
            ),
          );
          final result = _spawnSync(mvCommand);

          // The move should fail
          expect(result.exitCode, isNot(0));
          final output = (result.stderr as String).toLowerCase();
          expect(output, contains('operation not permitted'));

          // Verify the file was NOT moved
          expect(_exists(TEST_GLOB_SECRET1), isTrue);
        });

        test('should still block direct writes to glob-matched files', () {
          final globPattern = path.join(TEST_GLOB_DIR, '*.txt');
          final writeConfig = FsWriteRestrictionConfig(
            allowOnly: [TEST_ALLOWED_DIR],
            denyWithinAllow: [globPattern],
          );

          // Try to write to a glob-matched file
          final wrappedCommand = wrapCommandWithSandboxMacOS(
            MacOSSandboxParams(
              command: 'echo "$TEST_MODIFIED_CONTENT" > $TEST_GLOB_SECRET1',
              needsNetworkRestriction: false,
              readConfig: null,
              writeConfig: writeConfig,
            ),
          );
          final result = _spawnSync(wrappedCommand);

          // The write should fail
          expect(result.exitCode, isNot(0));
          final output = (result.stderr as String).toLowerCase();
          expect(output, contains('operation not permitted'));

          // Verify the file was NOT modified
          expect(_read(TEST_GLOB_SECRET1), TEST_ORIGINAL_CONTENT);
        });

        test(
          'should block moving the parent directory containing glob-matched files',
          () {
            final globPattern = path.join(TEST_GLOB_DIR, '*.txt');
            final writeConfig = FsWriteRestrictionConfig(
              allowOnly: [TEST_ALLOWED_DIR],
              denyWithinAllow: [globPattern],
            );

            // Try to move the parent directory
            final wrappedCommand = wrapCommandWithSandboxMacOS(
              MacOSSandboxParams(
                command: 'mv $TEST_GLOB_DIR $TEST_GLOB_RENAMED',
                needsNetworkRestriction: false,
                readConfig: null,
                writeConfig: writeConfig,
              ),
            );
            final result = _spawnSync(wrappedCommand);

            // The move should fail
            expect(result.exitCode, isNot(0));
            final output = (result.stderr as String).toLowerCase();
            expect(output, contains('operation not permitted'));

            // Verify the directory was NOT moved
            expect(_exists(TEST_GLOB_DIR), isTrue);
            expect(_exists(TEST_GLOB_RENAMED), isFalse);
          },
        );
      });

      group('Glob Pattern - Recursive Patterns', () {
        test(
          'should block moving files matching a recursive glob pattern (**/*.txt)',
          () {
            // Create nested directory structure
            final nestedDir = path.join(TEST_GLOB_DIR, 'nested');
            final nestedFile = path.join(nestedDir, 'nested-secret.txt');
            _mkdir(nestedDir);
            _write(nestedFile, TEST_ORIGINAL_CONTENT);

            // Use recursive glob pattern
            final globPattern = path.join(TEST_GLOB_DIR, '**', '*.txt');
            final writeConfig = FsWriteRestrictionConfig(
              allowOnly: [TEST_ALLOWED_DIR],
              denyWithinAllow: [globPattern],
            );
            final movedNested = path.join(TEST_BASE_DIR, 'moved-nested.txt');

            // Try to move the nested file
            final wrappedCommand = wrapCommandWithSandboxMacOS(
              MacOSSandboxParams(
                command: 'mv $nestedFile $movedNested',
                needsNetworkRestriction: false,
                readConfig: null,
                writeConfig: writeConfig,
              ),
            );
            final result = _spawnSync(wrappedCommand);

            // The move should fail
            expect(result.exitCode, isNot(0));
            final output = (result.stderr as String).toLowerCase();
            expect(output, contains('operation not permitted'));

            // Verify the file was NOT moved
            expect(_exists(nestedFile), isTrue);
            expect(_exists(movedNested), isFalse);
          },
        );
      });
    },
  );

  ///
  /// Tests for Seatbelt symlink-creation bypass on protected ancestors.
  ///
  /// Issue: generateMoveBlockingRules() emitted (deny file-write-unlink) for
  /// protected paths and their ancestor directories, but not file-write-create.
  /// If a protected path's ancestor directory did not yet exist, a sandboxed
  /// command could create it as a symlink pointing at attacker-controlled content,
  /// since (allow file-write* (subpath <cwd>)) is not overridden by a
  /// file-write-unlink-only deny on the ancestor literal.
  ///
  /// Fix: Emit (deny file-write-create ...) alongside every (deny file-write-unlink ...)
  /// in generateMoveBlockingRules(), and re-allow it for write-allowed paths in
  /// generateReadRules() to preserve normal file creation in the project directory.
  ///
  group(
    'macOS Seatbelt Symlink Creation Bypass Prevention',
    skip: Platform.isMacOS ? false : 'requires macOS Seatbelt',
    () {
      // Use the canonical tmpdir (/private/var/... on macOS) so the deny rules —
      // whose paths cannot be realpath-resolved because they don't exist yet —
      // match the canonical syscall paths Seatbelt evaluates.
      final TEST_BASE_DIR = path.join(
        Directory.systemTemp.resolveSymbolicLinksSync(),
        'seatbelt-create-test-${DateTime.now().millisecondsSinceEpoch}',
      );
      final TEST_ALLOWED_DIR = path.join(TEST_BASE_DIR, 'allowed');
      // Protected directory that does NOT exist on disk
      final TEST_DENIED_PARENT = path.join(TEST_ALLOWED_DIR, '.claude');
      final TEST_DENIED_FILE = path.join(TEST_DENIED_PARENT, 'settings.json');
      final TEST_DECOY_DIR = path.join(TEST_ALLOWED_DIR, 'decoy');

      setUpAll(() {
        _mkdir(TEST_ALLOWED_DIR);
        _mkdir(TEST_DECOY_DIR);
        _write(path.join(TEST_DECOY_DIR, 'settings.json'), '{"evil":true}');
      });

      tearDownAll(() {
        if (_exists(TEST_BASE_DIR)) _remove(TEST_BASE_DIR);
      });

      test(
        'should emit file-write-create deny rules for protected ancestors',
        () {
          final writeConfig = FsWriteRestrictionConfig(
            allowOnly: [TEST_ALLOWED_DIR],
            denyWithinAllow: [TEST_DENIED_FILE],
          );
          final wrappedCommand = wrapCommandWithSandboxMacOS(
            MacOSSandboxParams(
              command: 'true',
              needsNetworkRestriction: false,
              readConfig: null,
              writeConfig: writeConfig,
            ),
          );

          expect(
            wrappedCommand,
            contains(
              '(deny file-write-unlink file-write-create\n'
              '  (subpath ${jsonEncode(TEST_DENIED_FILE)})\n'
              '  (literal ${jsonEncode(TEST_DENIED_PARENT)})\n',
            ),
          );
        },
      );

      test(
        'should block creating a symlink at a non-existent protected ancestor',
        () {
          final writeConfig = FsWriteRestrictionConfig(
            allowOnly: [TEST_ALLOWED_DIR],
            denyWithinAllow: [TEST_DENIED_FILE],
          );
          expect(_exists(TEST_DENIED_PARENT), isFalse);
          final wrappedCommand = wrapCommandWithSandboxMacOS(
            MacOSSandboxParams(
              command: 'ln -s $TEST_DECOY_DIR $TEST_DENIED_PARENT',
              needsNetworkRestriction: false,
              readConfig: null,
              writeConfig: writeConfig,
            ),
          );
          final result = _spawnSync(wrappedCommand);

          expect(result.exitCode, isNot(0));
          final output = (result.stderr as String).toLowerCase();
          expect(output, contains('operation not permitted'));
          expect(_exists(TEST_DENIED_PARENT), isFalse);
        },
      );

      test(
        'should still allow creating ordinary files in the write-allowed directory',
        () {
          final writeConfig = FsWriteRestrictionConfig(
            allowOnly: [TEST_ALLOWED_DIR],
            denyWithinAllow: [TEST_DENIED_FILE],
          );
          final newFile = path.join(TEST_ALLOWED_DIR, 'ordinary.txt');
          final wrappedCommand = wrapCommandWithSandboxMacOS(
            MacOSSandboxParams(
              command: 'echo hello > $newFile',
              needsNetworkRestriction: false,
              readConfig: null,
              writeConfig: writeConfig,
            ),
          );
          final result = _spawnSync(wrappedCommand);

          expect(result.exitCode, 0);
          expect(_exists(newFile), isTrue);
          expect(_read(newFile).trim(), 'hello');
        },
      );
    },
  );

  ///
  /// Tests for Unix domain socket support in network-restricted sandbox.
  ///
  /// Issue: When allowedDomains is set, the sandbox enters restricted network mode.
  /// The previous implementation used (allow network* (subpath "/")) to allow Unix
  /// sockets, but socket(AF_UNIX, SOCK_STREAM, 0) is a system-socket operation that
  /// doesn't reference a filesystem path, so (subpath ...) can't match it.
  /// This caused Gradle (FileLockContentionHandler), Docker, and other tools that
  /// create Unix domain sockets to fail with "Operation not permitted".
  ///
  /// Fix: Use (allow system-socket (socket-domain AF_UNIX)) for socket creation,
  /// and (allow network-bind/network-outbound (local/remote unix-socket ...)) for
  /// bind/connect operations.
  ///
  group(
    'macOS Seatbelt Unix Domain Socket Support',
    skip: Platform.isMacOS ? false : 'requires macOS Seatbelt',
    () {
      final TEST_BASE_DIR = path.join(
        Directory.systemTemp.path,
        'seatbelt-unix-socket-test-${DateTime.now().millisecondsSinceEpoch}',
      );

      setUpAll(() => _mkdir(TEST_BASE_DIR));
      tearDownAll(() {
        if (_exists(TEST_BASE_DIR)) _remove(TEST_BASE_DIR);
      });

      test(
        'should allow Unix domain socket creation and communication with allowAllUnixSockets',
        () {
          final socketPath = path.join(TEST_BASE_DIR, 'test.sock');
          final scriptPath = path.join(TEST_BASE_DIR, 'test_socket.py');

          // Write Python script to a file to avoid shell quoting issues
          _write(
            scriptPath,
            [
              'import socket, os',
              "sock_path = '$socketPath'",
              'if os.path.exists(sock_path):',
              '    os.unlink(sock_path)',
              'server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)',
              'server.bind(sock_path)',
              'server.listen(1)',
              'client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)',
              'client.connect(sock_path)',
              'conn, _ = server.accept()',
              "client.send(b'SOCKET_OK')",
              'data = conn.recv(1024)',
              'print(data.decode())',
              'client.close()',
              'conn.close()',
              'server.close()',
              'os.unlink(sock_path)',
            ].join('\n'),
          );

          final writeConfig = FsWriteRestrictionConfig(
            allowOnly: [TEST_BASE_DIR],
            denyWithinAllow: [],
          );
          final wrappedCommand = wrapCommandWithSandboxMacOS(
            MacOSSandboxParams(
              command: 'python3 $scriptPath',
              needsNetworkRestriction: true,
              allowAllUnixSockets: true,
              readConfig: null,
              writeConfig: writeConfig,
            ),
          );
          final result = _spawnSync(wrappedCommand);

          expect(result.exitCode, 0);
          expect((result.stdout as String).trim(), 'SOCKET_OK');
        },
      );

      test(
        'should allow Unix domain socket creation with specific allowUnixSockets paths',
        () {
          final socketPath = path.join(TEST_BASE_DIR, 'specific.sock');
          final scriptPath = path.join(
            TEST_BASE_DIR,
            'test_specific_socket.py',
          );
          _write(
            scriptPath,
            [
              'import socket, os',
              "sock_path = '$socketPath'",
              'if os.path.exists(sock_path):',
              '    os.unlink(sock_path)',
              'server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)',
              'server.bind(sock_path)',
              'server.listen(1)',
              'client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)',
              'client.connect(sock_path)',
              'conn, _ = server.accept()',
              "client.send(b'SPECIFIC_OK')",
              'data = conn.recv(1024)',
              'print(data.decode())',
              'client.close()',
              'conn.close()',
              'server.close()',
              'os.unlink(sock_path)',
            ].join('\n'),
          );

          final writeConfig = FsWriteRestrictionConfig(
            allowOnly: [TEST_BASE_DIR],
            denyWithinAllow: [],
          );
          final wrappedCommand = wrapCommandWithSandboxMacOS(
            MacOSSandboxParams(
              command: 'python3 $scriptPath',
              needsNetworkRestriction: true,
              allowUnixSockets: [TEST_BASE_DIR],
              readConfig: null,
              writeConfig: writeConfig,
            ),
          );
          final result = _spawnSync(wrappedCommand);

          expect(result.exitCode, 0);
          expect((result.stdout as String).trim(), 'SPECIFIC_OK');
        },
      );

      test(
        'should block Unix domain socket bind when neither allowAllUnixSockets nor allowUnixSockets is set',
        () {
          final socketPath = path.join(TEST_BASE_DIR, 'blocked.sock');
          final scriptPath = path.join(TEST_BASE_DIR, 'test_blocked_socket.py');
          // This script should fail at bind() because Unix socket paths are not allowed
          _write(
            scriptPath,
            [
              'import socket, os, sys',
              "sock_path = '$socketPath'",
              'if os.path.exists(sock_path):',
              '    os.unlink(sock_path)',
              'try:',
              '    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)',
              '    s.bind(sock_path)',
              "    print('BIND_OK')",
              '    s.close()',
              '    os.unlink(sock_path)',
              'except OSError as e:',
              "    print(f'BLOCKED:{e}')",
              '    sys.exit(1)',
            ].join('\n'),
          );

          final writeConfig = FsWriteRestrictionConfig(
            allowOnly: [TEST_BASE_DIR],
            denyWithinAllow: [],
          );
          final wrappedCommand = wrapCommandWithSandboxMacOS(
            MacOSSandboxParams(
              command: 'python3 $scriptPath',
              needsNetworkRestriction: true,
              // Neither allowAllUnixSockets nor allowUnixSockets
              readConfig: null,
              writeConfig: writeConfig,
            ),
          );
          final result = _spawnSync(wrappedCommand);

          // Socket bind should be blocked
          expect(result.exitCode, isNot(0));
          expect(result.stdout, contains('BLOCKED:'));
        },
      );
    },
  );

  group(
    'macOS Seatbelt Process Enumeration',
    skip: Platform.isMacOS ? false : 'requires macOS Seatbelt',
    () {
      test('should allow enumerating all process IDs (kern.proc.all sysctl)', () {
        // This tests that psutil.pids() and similar process enumeration works.
        // The kern.proc.all sysctl is used by psutil to list all PIDs on the system.
        // Use case: IPython kernel shutdown needs to enumerate child processes.
        final wrappedCommand = wrapCommandWithSandboxMacOS(
          MacOSSandboxParams(
            command: 'ps -axo pid=',
            needsNetworkRestriction: false,
            readConfig: null,
            writeConfig: null,
          ),
        );
        final result = _spawnSync(wrappedCommand);

        // The command should succeed
        expect(result.exitCode, 0);

        // Should return a list of PIDs (at least the current process)
        final pids = (result.stdout as String)
            .trim()
            .split('\n')
            .where((line) => line.trim().isNotEmpty)
            .toList();
        expect(pids.length, greaterThan(0));

        // Each line should be a valid PID (numeric)
        for (final pid in pids) {
          expect(int.parse(pid.trim()), greaterThan(0));
        }
      });
    },
  );

  group(
    'macOS Seatbelt allowMachLookup',
    skip: Platform.isMacOS ? false : 'requires macOS Seatbelt',
    () {
      test(
        'should emit global-name and global-name-prefix rules for configured services',
        () {
          final wrappedCommand = wrapCommandWithSandboxMacOS(
            MacOSSandboxParams(
              command: 'true',
              needsNetworkRestriction: true,
              allowMachLookup: [
                'com.apple.CoreSimulator.CoreSimulatorService',
                '2BUA8C4S2C.com.1password.*',
              ],
              readConfig: null,
              writeConfig: null,
            ),
          );

          expect(
            wrappedCommand,
            contains(
              '(allow mach-lookup (global-name "com.apple.CoreSimulator.CoreSimulatorService"))',
            ),
          );
          expect(
            wrappedCommand,
            contains(
              '(allow mach-lookup (global-name-prefix "2BUA8C4S2C.com.1password."))',
            ),
          );
        },
      );

      test(
        'should emit a syntactically valid profile with allowMachLookup set',
        () {
          final wrappedCommand = wrapCommandWithSandboxMacOS(
            MacOSSandboxParams(
              command: 'true',
              needsNetworkRestriction: true,
              allowMachLookup: [
                'com.example.service',
                'com.example.prefix.*',
                '*',
              ],
              readConfig: null,
              writeConfig: null,
            ),
          );
          final result = _spawnSync(wrappedCommand);

          expect(result.exitCode, 0);
        },
      );
    },
  );
}
