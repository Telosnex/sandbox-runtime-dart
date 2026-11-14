// Ported from sandbox-runtime test/sandbox/filesystem-disabled.test.ts @ 0bbebed.
// ignore_for_file: constant_identifier_names, non_constant_identifier_names, slash_for_doc_comments
import 'package:path/path.dart' as path;
import 'package:sandbox_runtime/src/node/child_process.dart' show spawnSync;
import 'package:sandbox_runtime/src/node/fs.dart'
    show existsSync, mkdirSync, readFileSync, rmSync, writeFileSync;
import 'package:sandbox_runtime/src/node/os.dart' show tmpdir;
import 'package:sandbox_runtime/src/node/process.dart' as process;
import 'package:sandbox_runtime/src/sandbox/sandbox_config.dart';
import 'package:sandbox_runtime/src/sandbox/sandbox_manager.dart';
import 'package:sandbox_runtime/src/sandbox/sandbox_schemas.dart';
import 'package:test/test.dart';

import '../helpers/platform.dart' show isSupportedPlatform;

/**
 * Tests for filesystem.disabled.
 *
 * When true, no filesystem policy is enforced: every path is readable
 * and writable, denyRead/allowRead/allowWrite/denyWrite are ignored,
 * and the mandatory deny patterns (.git/hooks, .bashrc, etc.) are not
 * applied. Network/credential-env restrictions are unaffected.
 */
void main() {
  group(
    'filesystem.disabled',
    skip: isSupportedPlatform ? false : 'unsupported platform',
    () {
      final TEST_DIR = path.join(
        tmpdir(),
        'srt-fs-disabled-${DateTime.now().millisecondsSinceEpoch}',
      );
      final TEST_WRITE_FILE = path.join(TEST_DIR, 'write.txt');
      final TEST_READ_FILE = path.join(TEST_DIR, 'read.txt');
      const TEST_CONTENT = 'disabled-ok';

      // allowWrite deliberately points somewhere ELSE so TEST_DIR is not
      // covered by any configured write rule. Without disabled, writing
      // to TEST_WRITE_FILE would be blocked.
      //
      // denyRead is NOT set on the shared base config: on Linux a directory
      // read-deny mounts a writable tmpfs over the path, which would let the
      // control test's redirect succeed (exit 0) inside the namespace. The
      // 'ignores denyRead' test supplies its own denyRead.
      SandboxRuntimeConfig baseConfig(bool disabled) => SandboxRuntimeConfig(
        network: NetworkConfig(allowedDomains: [], deniedDomains: []),
        filesystem: FilesystemConfig(
          disabled: disabled,
          denyRead: [],
          allowWrite: [
            const FilesystemPathSpelling('/nonexistent-allow-write'),
          ],
          denyWrite: [],
        ),
      );

      setUpAll(() {
        mkdirSync(TEST_DIR, {'recursive': true});
        writeFileSync(TEST_READ_FILE, TEST_CONTENT);
      });

      tearDownAll(() async {
        await SandboxManager.reset();
        if (existsSync(TEST_DIR)) {
          rmSync(TEST_DIR, {'recursive': true, 'force': true});
        }
      });

      test('getter shapes reflect no enforcement', () async {
        await SandboxManager.reset();
        await SandboxManager.initialize(baseConfig(true));

        expect(
          SandboxManager.getFsReadConfig(),
          isA<FsReadRestrictionConfig>()
              .having((c) => c.denyOnly, 'denyOnly', [])
              .having((c) => c.allowWithinDeny, 'allowWithinDeny', []),
        );
        expect(
          SandboxManager.getFsWriteConfig(),
          isA<FsWriteRestrictionConfig>()
              .having((c) => c.allowOnly, 'allowOnly', ['/'])
              .having((c) => c.denyWithinAllow, 'denyWithinAllow', []),
        );
      });

      test(
        'blocks writes outside allowWrite when disabled is false (control)',
        () async {
          await SandboxManager.reset();
          await SandboxManager.initialize(baseConfig(false));

          final wrapped = await SandboxManager.wrapWithSandbox(
            'printf %s $TEST_CONTENT > $TEST_WRITE_FILE',
          );
          final result = spawnSync(wrapped, [], {
            'shell': true,
            'encoding': 'utf8',
            'timeout': 10000,
          });

          // Write must fail (path is not in allowWrite or default write paths).
          expect(existsSync(TEST_WRITE_FILE), false);
          expect(result.status, isNot(0));
        },
      );

      test('allows writes anywhere when disabled is true', () async {
        await SandboxManager.reset();
        await SandboxManager.initialize(baseConfig(true));

        final wrapped = await SandboxManager.wrapWithSandbox(
          'printf %s $TEST_CONTENT > $TEST_WRITE_FILE',
        );
        final result = spawnSync(wrapped, [], {
          'shell': true,
          'encoding': 'utf8',
          'timeout': 10000,
        });

        expect(result.status, 0);
        expect(existsSync(TEST_WRITE_FILE), true);
        expect(readFileSync(TEST_WRITE_FILE, 'utf8'), TEST_CONTENT);
      });

      test('ignores denyRead when disabled is true', () async {
        await SandboxManager.reset();
        await SandboxManager.initialize(
          SandboxRuntimeConfig(
            network: baseConfig(true).network,
            filesystem: FilesystemConfig(
              disabled: baseConfig(true).filesystem.disabled,
              denyRead: [FilesystemPathSpelling(TEST_DIR)],
              allowWrite: baseConfig(true).filesystem.allowWrite,
              denyWrite: baseConfig(true).filesystem.denyWrite,
            ),
          ),
        );

        // TEST_READ_FILE is created in beforeAll; TEST_DIR is in denyRead.
        final wrapped = await SandboxManager.wrapWithSandbox(
          'cat $TEST_READ_FILE',
        );
        final result = spawnSync(wrapped, [], {
          'shell': true,
          'encoding': 'utf8',
          'timeout': 10000,
        });

        expect(result.status, 0);
        expect(result.stdout as String, contains(TEST_CONTENT));
      });

      test('leaves TMPDIR untouched when disabled is true', () async {
        await SandboxManager.reset();
        await SandboxManager.initialize(baseConfig(true));

        final marker = path.join(TEST_DIR, 'host-tmpdir');
        final wrapped = await SandboxManager.wrapWithSandbox(
          'printf %s "\$TMPDIR"',
        );
        final result = spawnSync(wrapped, [], {
          'shell': true,
          'encoding': 'utf8',
          'timeout': 10000,
          'env': {...process.env, 'TMPDIR': marker},
        });

        expect(result.status, 0);
        expect(result.stdout, marker);
      });

      test('overrides TMPDIR when disabled is false (control)', () async {
        await SandboxManager.reset();
        await SandboxManager.initialize(baseConfig(false));

        final marker = path.join(TEST_DIR, 'host-tmpdir');
        final wrapped = await SandboxManager.wrapWithSandbox(
          'printf %s "\$TMPDIR"',
        );
        final result = spawnSync(wrapped, [], {
          'shell': true,
          'encoding': 'utf8',
          'timeout': 10000,
          'env': {...process.env, 'TMPDIR': marker},
        });

        expect(result.status, 0);
        expect(result.stdout, isNot(marker));
      });

      test(
        'per-call customConfig.filesystem overrides global disabled',
        () async {
          await SandboxManager.reset();
          await SandboxManager.initialize(baseConfig(true));

          // Global has disabled=true, but the per-call override supplies a
          // restrictive filesystem block (without the disabled key). The
          // override must win — TEST_DIR is not in its allowWrite, so the write
          // must be blocked.
          final target = path.join(TEST_DIR, 'override.txt');
          final wrapped = await SandboxManager.wrapWithSandbox(
            'printf %s x > $target',
            null,
            PartialSandboxRuntimeConfig(
              filesystem: FilesystemConfig(
                denyRead: [],
                allowWrite: [
                  const FilesystemPathSpelling('/nonexistent-allow-write'),
                ],
                denyWrite: [],
              ),
            ),
          );
          final result = spawnSync(wrapped, [], {
            'shell': true,
            'encoding': 'utf8',
            'timeout': 10000,
          });

          expect(existsSync(target), false);
          expect(result.status, isNot(0));
        },
      );
    },
  );
}
