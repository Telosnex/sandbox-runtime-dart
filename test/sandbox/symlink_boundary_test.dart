// Ported from sandbox-runtime test/sandbox/symlink-boundary.test.ts @ 0bbebed.
// ignore_for_file: constant_identifier_names, non_constant_identifier_names

import 'dart:convert';
import 'dart:io';

import 'package:path/path.dart' as path;
import 'package:test/test.dart';

import 'package:sandbox_runtime/src/sandbox/macos_sandbox_utils.dart';
import 'package:sandbox_runtime/src/sandbox/sandbox_utils.dart'
    show isAtOrUnder, isSymlinkOutsideBoundary, normalizePathForSandbox;
import 'package:sandbox_runtime/src/sandbox/sandbox_schemas.dart';

/// Tests for macOS Seatbelt symlink boundary validation
///
/// These tests verify that symlink resolution in sandbox profile generation
/// correctly validates path boundaries. When a symlink points to a broader
/// scope (e.g., a parent directory or root), the original path should be
/// preserved rather than the resolved path.

bool _exists(String pathName) =>
    FileSystemEntity.typeSync(pathName, followLinks: false) !=
    FileSystemEntityType.notFound;

void _mkdir(String pathName) => Directory(pathName).createSync(recursive: true);
void _removeTree(String pathName) {
  final directory = Directory(pathName);
  if (directory.existsSync()) directory.deleteSync(recursive: true);
}

void _deleteEntity(String pathName) {
  final type = FileSystemEntity.typeSync(pathName, followLinks: false);
  switch (type) {
    case FileSystemEntityType.link:
      Link(pathName).deleteSync();
    case FileSystemEntityType.file:
      File(pathName).deleteSync();
    case FileSystemEntityType.directory:
      Directory(pathName).deleteSync(recursive: true);
    case FileSystemEntityType.pipe:
    case FileSystemEntityType.unixDomainSock:
    case FileSystemEntityType.notFound:
      break;
  }
}

ProcessResult _runShell(String command) => Process.runSync(
  '/bin/sh',
  ['-c', command],
  stdoutEncoding: utf8,
  stderrEncoding: utf8,
);

ProcessResult _runProcess(String command, List<String> args) =>
    Process.runSync(command, args, stdoutEncoding: utf8, stderrEncoding: utf8);

/// Safely remove /tmp/claude if it exists (file, directory, or symlink)
void _cleanupTmpClaude() {
  const paths = ['/tmp/claude', '/private/tmp/claude'];
  for (final pathName in paths) {
    try {
      _deleteEntity(pathName);
    } catch (_) {
      // Path doesn't exist, ignore
    }
  }
}

void main() {
  group(
    'macOS Seatbelt Symlink Boundary Validation',
    skip: Platform.isMacOS ? false : 'requires macOS Seatbelt',
    () {
      // Use unique test directories per run
      // Use /private/tmp (not os.tmpdir()) so test paths are outside any
      // default-allowed write location
      final TEST_ID = DateTime.now().millisecondsSinceEpoch;
      final TEST_BASE_DIR = '/private/tmp/symlink-boundary-test-$TEST_ID';
      final WORKSPACE_DIR = path.join(TEST_BASE_DIR, 'workspace');
      // Use a path that is outside the allowed write paths
      final OUTSIDE_WORKSPACE_FILE =
          '/private/tmp/outside-allowed-$TEST_ID.txt';
      const TEST_CONTENT = 'TEST_CONTENT';

      setUp(() {
        // Clean up any existing /tmp/claude symlink from previous runs
        _cleanupTmpClaude();

        // Create fresh test directory structure
        if (_exists(TEST_BASE_DIR)) _removeTree(TEST_BASE_DIR);
        _mkdir(WORKSPACE_DIR);
      });

      tearDown(() {
        // Clean up /tmp/claude
        _cleanupTmpClaude();

        // Clean up test directories and files
        if (_exists(TEST_BASE_DIR)) _removeTree(TEST_BASE_DIR);
        if (_exists(OUTSIDE_WORKSPACE_FILE))
          _deleteEntity(OUTSIDE_WORKSPACE_FILE);
      });

      group('Symlink Boundary Enforcement', () {
        test('should preserve original path when symlink points to root', () {
          // Step 1: Verify sandbox correctly blocks writes outside workspace
          print('\n=== Step 1: Initial write attempt (should be blocked) ===');

          final writeConfig = FsWriteRestrictionConfig(
            allowOnly: [WORKSPACE_DIR, '/tmp/claude', '/private/tmp/claude'],
            denyWithinAllow: [],
          );
          final initialWriteCommand = wrapCommandWithSandboxMacOS(
            MacOSSandboxParams(
              command: 'echo "$TEST_CONTENT" > $OUTSIDE_WORKSPACE_FILE',
              needsNetworkRestriction: false,
              readConfig: null,
              writeConfig: writeConfig,
            ),
          );
          final initialResult = _runShell(initialWriteCommand);

          // This should fail - can't write outside workspace
          expect(initialResult.exitCode, isNot(0));
          expect(_exists(OUTSIDE_WORKSPACE_FILE), isFalse);
          print('✓ Initial write correctly blocked');

          // Step 2: Create symlink /tmp/claude -> /
          print('\n=== Step 2: Creating symlink /tmp/claude -> / ===');
          final symlinkCommand = wrapCommandWithSandboxMacOS(
            MacOSSandboxParams(
              command: 'ln -s / /tmp/claude',
              needsNetworkRestriction: false,
              readConfig: null,
              writeConfig: writeConfig,
            ),
          );
          final symlinkResult = _runShell(symlinkCommand);

          // Creating the symlink should succeed (we're writing to /tmp/claude which is allowed)
          expect(symlinkResult.exitCode, 0);

          // Verify symlink was created
          expect(
            FileSystemEntity.typeSync('/tmp/claude', followLinks: false),
            FileSystemEntityType.link,
          );
          print('✓ Symlink created: /tmp/claude -> /');

          // Step 3: Verify sandbox still blocks writes outside workspace
          print(
            '\n=== Step 3: Second write attempt (should still be blocked) ===',
          );

          // Generate a NEW sandbox profile - symlink resolution should be bounded
          final secondWriteCommand = wrapCommandWithSandboxMacOS(
            MacOSSandboxParams(
              command: 'echo "$TEST_CONTENT" > $OUTSIDE_WORKSPACE_FILE',
              needsNetworkRestriction: false,
              readConfig: null,
              writeConfig: writeConfig,
            ),
          );
          final secondResult = _runShell(secondWriteCommand);

          // The symlink should NOT cause /tmp/claude to resolve to / in the profile
          expect(secondResult.exitCode, isNot(0));
          expect(_exists(OUTSIDE_WORKSPACE_FILE), isFalse);
          print('✓ Write correctly blocked with symlink boundary validation');

          print('\n=== Summary ===');
          print('Symlink boundary validation working correctly');
        });

        test(
          'should block writes outside workspace when /tmp/claude does not exist',
          () {
            // Ensure /tmp/claude doesn't exist
            _cleanupTmpClaude();
            expect(_exists('/tmp/claude'), isFalse);

            final writeConfig = FsWriteRestrictionConfig(
              allowOnly: [WORKSPACE_DIR, '/tmp/claude', '/private/tmp/claude'],
              denyWithinAllow: [],
            );
            final wrappedCommand = wrapCommandWithSandboxMacOS(
              MacOSSandboxParams(
                command: 'echo "test" > $OUTSIDE_WORKSPACE_FILE',
                needsNetworkRestriction: false,
                readConfig: null,
                writeConfig: writeConfig,
              ),
            );
            final result = _runShell(wrappedCommand);

            // Should fail - can't write outside workspace
            expect(result.exitCode, isNot(0));
            expect(_exists(OUTSIDE_WORKSPACE_FILE), isFalse);
          },
        );

        test(
          'should block writes outside workspace when /tmp/claude is a regular directory',
          () {
            // Create /tmp/claude as a regular directory
            _cleanupTmpClaude();
            _mkdir('/tmp/claude');

            final type = FileSystemEntity.typeSync(
              '/tmp/claude',
              followLinks: false,
            );
            expect(type, FileSystemEntityType.directory);
            expect(type, isNot(FileSystemEntityType.link));

            final writeConfig = FsWriteRestrictionConfig(
              allowOnly: [WORKSPACE_DIR, '/tmp/claude', '/private/tmp/claude'],
              denyWithinAllow: [],
            );
            final wrappedCommand = wrapCommandWithSandboxMacOS(
              MacOSSandboxParams(
                command: 'echo "test" > $OUTSIDE_WORKSPACE_FILE',
                needsNetworkRestriction: false,
                readConfig: null,
                writeConfig: writeConfig,
              ),
            );
            final result = _runShell(wrappedCommand);

            // Should fail - can't write outside workspace
            expect(result.exitCode, isNot(0));
            expect(_exists(OUTSIDE_WORKSPACE_FILE), isFalse);
          },
        );

        test('should block writes via symlink traversal path', () {
          // Create symlink /tmp/claude -> /
          _cleanupTmpClaude();
          _runProcess('ln', ['-s', '/', '/tmp/claude']);

          expect(
            FileSystemEntity.typeSync('/tmp/claude', followLinks: false),
            FileSystemEntityType.link,
          );

          // This file path goes through /tmp/claude (the symlink) to reach a location
          // that would be outside the allowed write paths if symlink was followed
          final traversalPath = '/tmp/claude/tmp/traversal-write-$TEST_ID.txt';
          final writeConfig = FsWriteRestrictionConfig(
            allowOnly: [WORKSPACE_DIR, '/tmp/claude', '/private/tmp/claude'],
            denyWithinAllow: [],
          );
          final wrappedCommand = wrapCommandWithSandboxMacOS(
            MacOSSandboxParams(
              command: 'echo "test" > $traversalPath',
              needsNetworkRestriction: false,
              readConfig: null,
              writeConfig: writeConfig,
            ),
          );
          final result = _runShell(wrappedCommand);

          // The sandbox should NOT resolve /tmp/claude to / in the profile
          final realPath = '/tmp/traversal-write-$TEST_ID.txt';
          expect(result.exitCode, isNot(0));
          expect(_exists(realPath), isFalse);
          print('✓ Symlink traversal write blocked');
        });
      });

      group('isSymlinkOutsideBoundary Integration', () {
        test('should reject symlink resolution that broadens scope', () {
          // Create symlink pointing to root
          _cleanupTmpClaude();
          _runProcess('ln', ['-s', '/', '/tmp/claude']);

          final writeConfig = FsWriteRestrictionConfig(
            allowOnly: [WORKSPACE_DIR, '/tmp/claude', '/private/tmp/claude'],
            denyWithinAllow: [],
          );

          // Writing outside workspace should fail regardless of symlink state
          final wrappedCommand = wrapCommandWithSandboxMacOS(
            MacOSSandboxParams(
              command: 'echo "should fail" > $OUTSIDE_WORKSPACE_FILE',
              needsNetworkRestriction: false,
              readConfig: null,
              writeConfig: writeConfig,
            ),
          );
          final result = _runShell(wrappedCommand);

          print('\nTesting symlink boundary validation:');
          print('Exit code: ${result.exitCode}');
          print('File exists: ${_exists(OUTSIDE_WORKSPACE_FILE)}');

          expect(result.exitCode, isNot(0));
          expect(_exists(OUTSIDE_WORKSPACE_FILE), isFalse);
          print('✓ Symlink boundary validation working correctly');
        });
      });
    },
  );

  ///
  /// Unit tests for isSymlinkOutsideBoundary() function
  ///
  group('isSymlinkOutsideBoundary Unit Tests', () {
    group('Outside Boundary Detection', () {
      test('should detect when symlink points to root', () {
        expect(isSymlinkOutsideBoundary('/tmp/claude', '/'), isTrue);
        expect(isSymlinkOutsideBoundary('/private/tmp/claude', '/'), isTrue);
        expect(isSymlinkOutsideBoundary('/home/user/data', '/'), isTrue);
      });

      test('should detect when symlink points to ancestor directory', () {
        expect(isSymlinkOutsideBoundary('/tmp/claude/data', '/tmp'), isTrue);
        expect(
          isSymlinkOutsideBoundary('/tmp/claude/data', '/tmp/claude'),
          isTrue,
        );
        expect(
          isSymlinkOutsideBoundary('/home/user/project/src', '/home'),
          isTrue,
        );
        expect(
          isSymlinkOutsideBoundary('/home/user/project/src', '/home/user'),
          isTrue,
        );
      });

      test('should detect when resolved path is very short', () {
        expect(isSymlinkOutsideBoundary('/tmp/claude', '/tmp'), isTrue);
        expect(isSymlinkOutsideBoundary('/var/data', '/var'), isTrue);
        expect(isSymlinkOutsideBoundary('/usr/local/bin', '/usr'), isTrue);
      });

      test('should detect when symlink points to unrelated directory', () {
        // Symlink pointing to home directory or other unrelated paths
        expect(
          isSymlinkOutsideBoundary('/tmp/claude', '/Users/dworken'),
          isTrue,
        );
        expect(isSymlinkOutsideBoundary('/tmp/claude', '/home/user'), isTrue);
        expect(isSymlinkOutsideBoundary('/tmp/claude', '/etc'), isTrue);
        expect(isSymlinkOutsideBoundary('/tmp/claude', '/opt/data'), isTrue);
        expect(
          isSymlinkOutsideBoundary('/var/data', '/Users/someone/data'),
          isTrue,
        );
      });
    });

    group('Valid Resolutions', () {
      test('should allow resolution to same path', () {
        expect(isSymlinkOutsideBoundary('/tmp/claude', '/tmp/claude'), isFalse);
        expect(isSymlinkOutsideBoundary('/home/user', '/home/user'), isFalse);
      });

      test('should allow macOS /tmp -> /private/tmp canonical resolution', () {
        expect(
          isSymlinkOutsideBoundary('/tmp/claude', '/private/tmp/claude'),
          isFalse,
        );
        expect(
          isSymlinkOutsideBoundary(
            '/tmp/claude/data',
            '/private/tmp/claude/data',
          ),
          isFalse,
        );
      });

      test('should allow macOS /var -> /private/var canonical resolution', () {
        expect(
          isSymlinkOutsideBoundary(
            '/var/folders/xx/yy',
            '/private/var/folders/xx/yy',
          ),
          isFalse,
        );
      });

      test('should allow resolution to deeper path (more specific)', () {
        expect(
          isSymlinkOutsideBoundary('/tmp/claude', '/tmp/claude/actual'),
          isFalse,
        );
        expect(
          isSymlinkOutsideBoundary('/home/user', '/home/user/real'),
          isFalse,
        );
      });
    });

    group('Edge Cases', () {
      test('should handle paths with trailing slashes', () {
        // path.normalize removes trailing slashes, so these should work
        expect(isSymlinkOutsideBoundary('/tmp/claude/', '/'), isTrue);
      });

      test('should handle private paths resolving to themselves', () {
        expect(
          isSymlinkOutsideBoundary(
            '/private/tmp/claude',
            '/private/tmp/claude',
          ),
          isFalse,
        );
        expect(
          isSymlinkOutsideBoundary('/private/var/data', '/private/var/data'),
          isFalse,
        );
      });
    });
  });

  group('isAtOrUnder', () {
    test('contains by path segment, root included', () {
      expect(isAtOrUnder('/a/b', '/a'), isTrue);
      expect(isAtOrUnder('/a', '/a'), isTrue);
      expect(isAtOrUnder('/ab', '/a'), isFalse);
      expect(isAtOrUnder('/x', '/'), isTrue);
      expect(isAtOrUnder('/', '/'), isTrue);
      expect(isAtOrUnder('/', '/a'), isFalse);
    });
  });

  ///
  /// Tests for glob pattern symlink boundary validation
  ///
  group(
    'Glob Pattern Symlink Boundary',
    skip: Platform.isMacOS ? false : 'requires macOS Seatbelt',
    () {
      test(
        'should preserve original glob pattern when base directory symlink points to root',
        () {
          // Clean up and create symlink
          _cleanupTmpClaude();
          _runProcess('ln', ['-s', '/', '/tmp/claude']);

          // Test that glob pattern doesn't resolve to /**
          final result = normalizePathForSandbox('/tmp/claude/**');

          // Should keep original pattern, not resolve to /**
          expect(result, '/tmp/claude/**');
          expect(result, isNot('/**'));

          // Clean up
          _cleanupTmpClaude();
        },
      );

      test(
        'should preserve original glob pattern when base directory symlink points to parent',
        () {
          // Clean up and create symlink pointing to /tmp (parent)
          _cleanupTmpClaude();
          _runProcess('ln', ['-s', '/tmp', '/tmp/claude']);

          // Test that glob pattern doesn't resolve to /tmp/**
          final result = normalizePathForSandbox('/tmp/claude/**');

          // Should keep original pattern
          expect(result, '/tmp/claude/**');
          expect(result, isNot('/tmp/**'));

          // Clean up
          _cleanupTmpClaude();
        },
      );
    },
  );
}
