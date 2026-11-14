// Ported from sandbox-runtime test/sandbox/symlink-write-path.test.ts @ 0bbebed.
// ignore_for_file: constant_identifier_names, non_constant_identifier_names, slash_for_doc_comments, prefer_interpolation_to_compose_strings
import 'dart:math';

import 'package:path/path.dart' show join;
import 'package:sandbox_runtime/src/node/child_process.dart' show spawnSync;
import 'package:sandbox_runtime/src/node/fs.dart'
    show
        existsSync,
        mkdirSync,
        readFileSync,
        rmSync,
        symlinkSync,
        writeFileSync;
import 'package:sandbox_runtime/src/node/os.dart' show tmpdir;
import 'package:sandbox_runtime/src/sandbox/linux_sandbox_utils.dart';
import 'package:sandbox_runtime/src/sandbox/sandbox_schemas.dart';
import 'package:test/test.dart';

import '../helpers/platform.dart' show isLinux;

void main() {
  /**
   * Unit tests for symlink write path detection in generateFilesystemArgs.
   *
   * When an allowWrite path is a symlink pointing outside its expected boundaries,
   * bwrap would follow the symlink and make the target writable. The fix detects
   * this and skips the path with a warning.
   */
  group(
    'Symlink write path detection (unit)',
    skip: isLinux ? null : 'describe.if(isLinux)',
    () {
      final TEST_ID =
          'symlink-write-${DateTime.now().millisecondsSinceEpoch}-${Random().nextInt(1 << 31).toRadixString(36).padLeft(6, '0').substring(0, 6)}';
      final TEST_BASE = join(tmpdir(), TEST_ID);
      final USER_AREA = join(TEST_BASE, 'user_area');
      final PROTECTED = join(TEST_BASE, 'protected');

      setUp(() {
        mkdirSync(USER_AREA, {'recursive': true});
        mkdirSync(PROTECTED, {'recursive': true});
        writeFileSync(join(PROTECTED, 'secret.txt'), 'secret data');
      });

      tearDown(() {
        rmSync(TEST_BASE, {'recursive': true, 'force': true});
      });

      test(
        'should include normal (non-symlink) write paths in bwrap args',
        () async {
          final result = await wrapCommandWithSandboxLinux(
            LinuxSandboxParams(
              command: 'echo hello',
              needsNetworkRestriction: false,
              readConfig: FsReadRestrictionConfig(denyOnly: []),
              writeConfig: FsWriteRestrictionConfig(
                allowOnly: [USER_AREA],
                denyWithinAllow: [],
              ),
            ),
          );

          // The normal path should be included as --bind
          expect(result, contains(USER_AREA));
          expect(result, contains('--bind'));
        },
      );

      test(
        'should skip symlink write paths pointing outside expected boundaries',
        () async {
          // Create symlink: user_area/evil -> protected/
          final evilLink = join(USER_AREA, 'evil');
          symlinkSync(PROTECTED, evilLink);

          final result = await wrapCommandWithSandboxLinux(
            LinuxSandboxParams(
              command: 'echo hello',
              needsNetworkRestriction: false,
              readConfig: FsReadRestrictionConfig(denyOnly: []),
              writeConfig: FsWriteRestrictionConfig(
                allowOnly: [evilLink],
                denyWithinAllow: [],
              ),
            ),
          );

          // The symlink path should NOT be bound writable
          // Since it's the only allowOnly path and it's skipped, the result should
          // still have bwrap but without --bind for this path
          expect(result, contains('bwrap'));
          // The evil link target (PROTECTED) should not appear as a --bind target
          expect(result, isNot(contains('--bind $evilLink $evilLink')));
        },
      );

      test(
        'should keep legitimate write paths while skipping symlink paths',
        () async {
          // Create symlink: user_area/evil -> protected/
          final evilLink = join(USER_AREA, 'evil');
          symlinkSync(PROTECTED, evilLink);

          final result = await wrapCommandWithSandboxLinux(
            LinuxSandboxParams(
              command: 'echo hello',
              needsNetworkRestriction: false,
              readConfig: FsReadRestrictionConfig(denyOnly: []),
              writeConfig: FsWriteRestrictionConfig(
                allowOnly: [USER_AREA, evilLink],
                denyWithinAllow: [],
              ),
            ),
          );

          // The legitimate path should be included
          expect(result, contains(USER_AREA));
          // The symlink path should NOT produce a --bind with its own path
          expect(result, isNot(contains('--bind $evilLink $evilLink')));
        },
      );

      test('should skip write paths that cannot be resolved', () async {
        // Create a broken symlink
        final brokenLink = join(USER_AREA, 'broken');
        symlinkSync('/nonexistent/path/that/does/not/exist', brokenLink);

        final result = await wrapCommandWithSandboxLinux(
          LinuxSandboxParams(
            command: 'echo hello',
            needsNetworkRestriction: false,
            readConfig: FsReadRestrictionConfig(denyOnly: []),
            writeConfig: FsWriteRestrictionConfig(
              allowOnly: [USER_AREA, brokenLink],
              denyWithinAllow: [],
            ),
          ),
        );

        // The broken symlink should be skipped (existsSync returns false for broken symlinks)
        // but the legitimate path should still work
        expect(result, contains(USER_AREA));
      });

      test(
        'should allow symlinks that resolve within the same directory',
        () async {
          // Create a subdirectory and a symlink within user_area pointing to it
          final subdir = join(USER_AREA, 'actual_data');
          mkdirSync(subdir, {'recursive': true});
          final link = join(USER_AREA, 'link_to_data');
          symlinkSync(subdir, link);

          final result = await wrapCommandWithSandboxLinux(
            LinuxSandboxParams(
              command: 'echo hello',
              needsNetworkRestriction: false,
              readConfig: FsReadRestrictionConfig(denyOnly: []),
              writeConfig: FsWriteRestrictionConfig(
                allowOnly: [link],
                denyWithinAllow: [],
              ),
            ),
          );

          // Symlink within same area should be allowed (resolves to deeper path)
          expect(result, contains('bwrap'));
        },
      );

      test(
        'should include write paths with trailing slashes (not treat them as symlinks)',
        () async {
          // When normalizedPath has a trailing slash, realpathSync returns it without one.
          // The comparison `resolvedPath !== normalizedPath` would incorrectly be true,
          // potentially causing the path to be skipped as if it were a symlink.
          final pathWithTrailingSlash = USER_AREA + '/';

          final result = await wrapCommandWithSandboxLinux(
            LinuxSandboxParams(
              command: 'echo hello',
              needsNetworkRestriction: false,
              readConfig: FsReadRestrictionConfig(denyOnly: []),
              writeConfig: FsWriteRestrictionConfig(
                allowOnly: [pathWithTrailingSlash],
                denyWithinAllow: [],
              ),
            ),
          );

          // The path should be included as --bind, not skipped
          expect(result, contains('--bind'));
          expect(result, contains(USER_AREA));
        },
      );
    },
  );

  /**
   * Integration tests for symlink write path detection.
   *
   * These tests create actual symlinks and verify that the sandbox correctly
   * prevents writes through symlinks pointing outside allowed boundaries.
   */
  group(
    'Symlink write path detection (integration)',
    skip: isLinux ? null : 'describe.if(isLinux)',
    () {
      final TEST_ID =
          'symlink-integ-${DateTime.now().millisecondsSinceEpoch}-${Random().nextInt(1 << 31).toRadixString(36).padLeft(6, '0').substring(0, 6)}';
      final TEST_BASE = join(tmpdir(), TEST_ID);
      final USER_AREA = join(TEST_BASE, 'user_area');
      final PROTECTED = join(TEST_BASE, 'protected');

      setUp(() {
        mkdirSync(USER_AREA, {'recursive': true});
        mkdirSync(PROTECTED, {'recursive': true});
        writeFileSync(join(PROTECTED, 'secret.txt'), 'secret data');
      });

      tearDown(() {
        rmSync(TEST_BASE, {'recursive': true, 'force': true});
      });

      test(
        'should block writes through symlink pointing to protected directory',
        () async {
          // Attack scenario: user_area/evil_symlink -> protected/
          final evilLink = join(USER_AREA, 'evil_symlink');
          symlinkSync(PROTECTED, evilLink);

          // Configure sandbox to allow writes to user_area and the evil symlink
          final command = await wrapCommandWithSandboxLinux(
            LinuxSandboxParams(
              command: 'echo "pwned" > $evilLink/secret.txt',
              needsNetworkRestriction: false,
              readConfig: FsReadRestrictionConfig(denyOnly: []),
              writeConfig: FsWriteRestrictionConfig(
                allowOnly: [USER_AREA, evilLink],
                denyWithinAllow: [],
              ),
            ),
          );

          spawnSync(command, [], {
            'shell': true,
            'encoding': 'utf8',
            'timeout': 5000,
          });

          // The write should fail because the symlink path was skipped
          final secretContent = readFileSync(
            join(PROTECTED, 'secret.txt'),
            'utf8',
          );
          expect(secretContent, 'secret data');
          expect(secretContent, isNot(contains('pwned')));
        },
      );

      test('should allow normal writes to non-symlink paths', () async {
        final testFile = join(USER_AREA, 'normal-write.txt');

        final command = await wrapCommandWithSandboxLinux(
          LinuxSandboxParams(
            command: 'echo "allowed content" > $testFile',
            needsNetworkRestriction: false,
            readConfig: FsReadRestrictionConfig(denyOnly: []),
            writeConfig: FsWriteRestrictionConfig(
              allowOnly: [USER_AREA],
              denyWithinAllow: [],
            ),
          ),
        );

        final result = spawnSync(command, [], {
          'shell': true,
          'encoding': 'utf8',
          'timeout': 5000,
        });

        expect(result.status, 0);
        expect(existsSync(testFile), true);
        expect(
          (readFileSync(testFile, 'utf8') as String).trim(),
          'allowed content',
        );
      });

      test('should block writes through symlink pointing to /etc', () async {
        // Classic attack: src -> /etc
        final srcLink = join(USER_AREA, 'src');
        symlinkSync('/etc', srcLink);

        final command = await wrapCommandWithSandboxLinux(
          LinuxSandboxParams(
            command: 'echo "malicious" > $srcLink/test-sandbox-escape.txt',
            needsNetworkRestriction: false,
            readConfig: FsReadRestrictionConfig(denyOnly: []),
            writeConfig: FsWriteRestrictionConfig(
              allowOnly: [USER_AREA, srcLink],
              denyWithinAllow: [],
            ),
          ),
        );

        spawnSync(command, [], {
          'shell': true,
          'encoding': 'utf8',
          'timeout': 5000,
        });

        // /etc should remain read-only
        expect(existsSync('/etc/test-sandbox-escape.txt'), false);
      });

      test(
        'should block writes through symlink pointing to parent directory',
        () async {
          // Symlink pointing to parent (broadens scope)
          final parentLink = join(USER_AREA, 'parent');
          symlinkSync(TEST_BASE, parentLink);

          final escapePath = join(TEST_BASE, 'escaped-file.txt');

          final command = await wrapCommandWithSandboxLinux(
            LinuxSandboxParams(
              command: 'echo "escaped" > $parentLink/escaped-file.txt',
              needsNetworkRestriction: false,
              readConfig: FsReadRestrictionConfig(denyOnly: []),
              writeConfig: FsWriteRestrictionConfig(
                allowOnly: [parentLink],
                denyWithinAllow: [],
              ),
            ),
          );

          spawnSync(command, [], {
            'shell': true,
            'encoding': 'utf8',
            'timeout': 5000,
          });

          // The escape file should not have been created via the symlink
          // (since the symlink is skipped, no write paths are available)
          expect(existsSync(escapePath), false);
        },
      );
    },
  );
}
