// Ported from sandbox-runtime test/sandbox/mandatory-deny-paths.test.ts @ 0bbebed.
// ignore_for_file: constant_identifier_names, non_constant_identifier_names, slash_for_doc_comments, no_leading_underscores_for_local_identifiers

import 'dart:async';
import 'dart:io' show Directory, Link;

import 'package:path/path.dart' as path;
import 'package:test/test.dart';

import 'package:sandbox_runtime/src/node/abort.dart';
import 'package:sandbox_runtime/src/node/child_process.dart'
    show spawn, spawnSync;
import 'package:sandbox_runtime/src/node/errno.dart' show NodeException;
import 'package:sandbox_runtime/src/node/fs.dart'
    show
        chmodSync,
        existsSync,
        mkdirSync,
        readFileSync,
        rmdirSync,
        rmSync,
        statSync,
        writeFileSync;
import 'package:sandbox_runtime/src/node/os.dart' show tmpdir;
import 'package:sandbox_runtime/src/node/process.dart' as process;
import 'package:sandbox_runtime/src/sandbox/linux_sandbox_utils.dart';
import 'package:sandbox_runtime/src/sandbox/macos_sandbox_utils.dart';
import 'package:sandbox_runtime/src/sandbox/sandbox_schemas.dart'
    show FsWriteRestrictionConfig;
import 'package:sandbox_runtime/src/sandbox/sandbox_utils.dart';
import 'package:sandbox_runtime/src/utils/platform.dart' show getPlatform;
import 'package:sandbox_runtime/src/utils/ripgrep.dart' show RipgrepConfig;

import '../helpers/platform.dart';

// Dart: dart:io has no string-list readdir or symlinkSync with Node's shape;
// these two stand in for the `node:fs` functions of the same name.
List<String> readdirSync(String directory) => [
  for (final entity in Directory(directory).listSync(followLinks: false))
    path.basename(entity.path),
];
void symlinkSync(String target, String linkPath) =>
    Link(linkPath).createSync(target);

/**
 * Integration tests for mandatory deny paths.
 *
 * These tests verify that dangerous files (.bashrc, .gitconfig, etc.) and
 * directories (.git/hooks, .vscode, etc.) are blocked from writes even when
 * they're within an allowed write path.
 *
 * IMPORTANT: The mandatory deny patterns are relative to process.cwd().
 * Tests must chdir to TEST_DIR before generating sandbox commands.
 */

void main() {
  group(
    'Mandatory Deny Paths - Integration Tests',
    skip: isWindows
        ? 'Windows not supported by this port'
        : (isSupportedPlatform ? false : 'unsupported platform'),
    () {
      final TEST_DIR = path.join(
        tmpdir(),
        'mandatory-deny-integration-${DateTime.now().millisecondsSinceEpoch}',
      );
      const ORIGINAL_CONTENT = 'ORIGINAL';
      const MODIFIED_CONTENT = 'MODIFIED';
      /** Written into every directory getDangerousDirectories() names. */
      const DIRECTORY_PROBE_FILE = 'probe.txt';
      late String originalCwd;

      setUpAll(() {
        originalCwd = process.cwd();
        mkdirSync(TEST_DIR, {'recursive': true});

        for (final name in DANGEROUS_FILES) {
          writeFileSync(path.join(TEST_DIR, name), ORIGINAL_CONTENT);
        }

        // Create .git with hooks and config
        mkdirSync(path.join(TEST_DIR, '.git', 'hooks'), {'recursive': true});
        writeFileSync(path.join(TEST_DIR, '.git', 'config'), ORIGINAL_CONTENT);
        writeFileSync(
          path.join(TEST_DIR, '.git', 'hooks', 'pre-commit'),
          ORIGINAL_CONTENT,
        );
        writeFileSync(
          path.join(TEST_DIR, '.git', 'HEAD'),
          'ref: refs/heads/main',
        );

        for (final dir in getDangerousDirectories()) {
          mkdirSync(path.join(TEST_DIR, dir), {'recursive': true});
          writeFileSync(
            path.join(TEST_DIR, dir, DIRECTORY_PROBE_FILE),
            ORIGINAL_CONTENT,
          );
        }

        // Create a safe file that SHOULD be writable
        writeFileSync(path.join(TEST_DIR, 'safe-file.txt'), ORIGINAL_CONTENT);

        // Create safe files within .git that SHOULD be writable (not hooks/config)
        mkdirSync(path.join(TEST_DIR, '.git', 'objects'), {'recursive': true});
        mkdirSync(path.join(TEST_DIR, '.git', 'refs', 'heads'), {
          'recursive': true,
        });
        writeFileSync(
          path.join(TEST_DIR, '.git', 'objects', 'test-obj'),
          ORIGINAL_CONTENT,
        );
        writeFileSync(
          path.join(TEST_DIR, '.git', 'refs', 'heads', 'main'),
          ORIGINAL_CONTENT,
        );
        writeFileSync(path.join(TEST_DIR, '.git', 'index'), ORIGINAL_CONTENT);

        // Create safe file within .claude that SHOULD be writable (not commands/agents)
        writeFileSync(
          path.join(TEST_DIR, '.claude', 'some-other-file.txt'),
          ORIGINAL_CONTENT,
        );
      });

      tearDownAll(() {
        Directory.current = originalCwd;
        rmSync(TEST_DIR, {'recursive': true, 'force': true});
      });

      setUp(() {
        // Must be in TEST_DIR for mandatory deny patterns to apply correctly
        Directory.current = TEST_DIR;
      });

      tearDown(() {
        // Reset the active-sandbox counter and scrub any leftover mount points so
        // each test starts clean. Tests that don't explicitly call
        // cleanupBwrapMountPoints() would otherwise leak the counter.
        cleanupBwrapMountPoints(force: true);
      });

      // Dart: runSandboxed comes first, as a local function cannot be used before it is declared.
      Future<({bool success, String stderr})> runSandboxed(
        String command, [
        List<String> ripgrepArgs = const [],
      ]) async {
        final platform = getPlatform();

        // Allow writes to current directory, but mandatory denies should still block dangerous files
        final writeConfig = FsWriteRestrictionConfig(
          allowOnly: ['.'],
          denyWithinAllow: [], // Empty - relying on mandatory denies
        );

        String wrappedCommand;
        if (platform == 'macos') {
          wrappedCommand = wrapCommandWithSandboxMacOS(
            MacOSSandboxParams(
              command: command,
              needsNetworkRestriction: false,
              readConfig: null,
              writeConfig: writeConfig,
            ),
          );
        } else {
          wrappedCommand = await wrapCommandWithSandboxLinux(
            LinuxSandboxParams(
              command: command,
              needsNetworkRestriction: false,
              readConfig: null,
              writeConfig: writeConfig,
              ripgrepConfig: RipgrepConfig(command: 'rg', args: ripgrepArgs),
            ),
          );
        }

        final result = spawnSync(wrappedCommand, [], {
          'shell': true,
          'encoding': 'utf8',
          'timeout': 10000,
        });

        return (
          success: result.status == 0,
          stderr: (result.stderr as String?) ?? '',
        );
      }

      Future<({bool success, String stderr})> runSandboxedWrite(
        String filePath,
        String content,
      ) {
        return runSandboxed("echo '$content' > '$filePath'");
      }

      group('Dangerous files should be blocked', () {
        for (final name in DANGEROUS_FILES) {
          test('blocks writes to $name', () async {
            final result = await runSandboxedWrite(name, MODIFIED_CONTENT);

            expect(result.success, false);
            expect(readFileSync(name, 'utf8'), ORIGINAL_CONTENT);
          });
        }
      });

      group('Git hooks and config should be blocked', () {
        test('blocks writes to .git/config', () async {
          final result = await runSandboxedWrite(
            '.git/config',
            MODIFIED_CONTENT,
          );

          expect(result.success, false);
          expect(readFileSync('.git/config', 'utf8'), ORIGINAL_CONTENT);
        });

        test('blocks writes to .git/hooks/pre-commit', () async {
          final result = await runSandboxedWrite(
            '.git/hooks/pre-commit',
            MODIFIED_CONTENT,
          );

          expect(result.success, false);
          expect(
            readFileSync('.git/hooks/pre-commit', 'utf8'),
            ORIGINAL_CONTENT,
          );
        });
      });

      group('Dangerous directories should be blocked', () {
        for (final dir in getDangerousDirectories()) {
          test('blocks writes to $dir/', () async {
            final target = '$dir/$DIRECTORY_PROBE_FILE';
            final result = await runSandboxedWrite(target, MODIFIED_CONTENT);

            expect(result.success, false);
            expect(readFileSync(target, 'utf8'), ORIGINAL_CONTENT);
          });
        }
      });

      group('The same names below the working directory', () {
        /** What holds files the host runs or trusts, and a file in each. */
        final heldIn = {
          '.git/hooks': 'pre-commit',
          ...{
            for (final dir in getDangerousDirectories())
              dir: DIRECTORY_PROBE_FILE,
          },
        };
        final existing = [
          ...DANGEROUS_FILES,
          '.git/config',
          ...heldIn.entries.map((e) => '${e.key}/${e.value}'),
        ];
        void populate(String container) {
          for (final dir in heldIn.keys) {
            mkdirSync(path.join(TEST_DIR, container, dir), {'recursive': true});
          }
          for (final name in [...existing, 'safe-file.txt']) {
            writeFileSync(
              path.join(TEST_DIR, container, name),
              ORIGINAL_CONTENT,
            );
          }
        }

        // How far the default depth reaches on Linux: every name in `sub`, and
        // the files alone in `a/b`.
        final covered = <(String, List<String>)>[
          ('sub', existing),
          ('a/b', DANGEROUS_FILES),
        ];
        const beyond = 'a/b/c';
        setUpAll(() => ['sub', 'a/b', beyond].map(populate).toList());

        for (final (container, names) in covered) {
          for (final name in names) {
            test('blocks writes to $container/$name', () async {
              final target = '$container/$name';
              final result = await runSandboxedWrite(target, MODIFIED_CONTENT);

              expect(result.success, false);
              expect(readFileSync(target, 'utf8'), ORIGINAL_CONTENT);
            });
          }
          test('allows writes to $container/safe-file.txt', () async {
            final target = '$container/safe-file.txt';
            final result = await runSandboxedWrite(target, MODIFIED_CONTENT);

            expect(result.success, true);
            expect(
              (readFileSync(target, 'utf8') as String).trim(),
              MODIFIED_CONTENT,
            );
          });
        }

        for (final dir in heldIn.keys) {
          test('blocks a new file in sub/$dir/', () async {
            final target = 'sub/$dir/new-file';
            final result = await runSandboxedWrite(target, MODIFIED_CONTENT);

            expect(result.success, false);
            expect(existsSync(target), false);
          });
        }

        for (final state in ['empty', 'missing']) {
          test(
            'blocks a new hook in a repository whose hooks directory is $state',
            () async {
              final repository = 'hooks-$state';
              final hooks = '$repository/.git/hooks';
              mkdirSync(path.join(TEST_DIR, repository, '.git'), {
                'recursive': true,
              });
              writeFileSync(
                path.join(TEST_DIR, repository, '.git', 'HEAD'),
                'ref: refs/heads/main',
              );
              if (state == 'empty') mkdirSync(path.join(TEST_DIR, hooks));

              final result = await runSandboxed(
                "mkdir -p '$hooks' && echo x > '$hooks/pre-commit'",
              );

              expect(result.success, false);
              expect(existsSync('$hooks/pre-commit'), false);
              // The rest of the repository is still the command's to write.
              expect(
                (await runSandboxedWrite('$repository/.git/HEAD', 'x')).success,
                true,
              );
            },
          );
        }

        for (final (file, line) in [('.gitignore', 'sub/'), ('.ignore', '*')]) {
          test('blocks them all the same when $file holds $line', () async {
            writeFileSync(path.join(TEST_DIR, file), '$line\n');
            try {
              for (final name in ['sub/.bashrc', 'sub/.git/hooks/pre-commit']) {
                final result = await runSandboxedWrite(name, MODIFIED_CONTENT);

                expect([name, result.success], [name, false]);
                expect(readFileSync(name, 'utf8'), ORIGINAL_CONTENT);
              }
            } finally {
              rmSync(path.join(TEST_DIR, file));
            }
          });
        }

        test(
          "blocks them all the same whatever ripgrep's configuration file says",
          () async {
            final configuration = path.join(TEST_DIR, 'ripgrep-configuration');
            writeFileSync(configuration, '--glob=!sub\n');
            process.env['RIPGREP_CONFIG_PATH'] = configuration;
            try {
              final result = await runSandboxedWrite(
                'sub/.bashrc',
                MODIFIED_CONTENT,
              );

              expect(result.success, false);
              expect(readFileSync('sub/.bashrc', 'utf8'), ORIGINAL_CONTENT);
            } finally {
              process.env.remove('RIPGREP_CONFIG_PATH');
              rmSync(configuration);
            }
          },
          skip: isLinux ? false : 'Linux only',
        );

        test(
          'blocks them all the same beside a directory that cannot be read',
          () async {
            final unreadable = path.join(TEST_DIR, 'unreadable');
            mkdirSync(unreadable, {"mode": 0});
            try {
              for (final name in ['sub/.bashrc', 'sub/.git/hooks/pre-commit']) {
                final result = await runSandboxedWrite(name, MODIFIED_CONTENT);

                expect([name, result.success], [name, false]);
                expect(readFileSync(name, 'utf8'), ORIGINAL_CONTENT);
              }
            } finally {
              rmdirSync(unreadable);
            }
          },
        );

        for (final (directory, mode) in [
          ('locked', 0),
          ('locked/.git', 0),
          // As deep as one of the names can itself lie.
          ('locked/.claude/commands', 0),
          // Can be listed, and nothing in it looked at.
          ('locked', 292), // 0o444
          // The other way about.
          ('locked', 73), // 0o111
        ]) {
          // With one thread, as on one CPU, ripgrep words what it says otherwise.
          for (final threads in [
            <String>[],
            ['-j1'],
          ]) {
            test(
              'blocks them all the same in locked/ when $directory has mode ${mode.toRadixString(8)} (rg ${threads.join(",")})',
              () async {
                final names = [
                  '.bashrc',
                  '.git/config',
                  '.git/hooks/pre-commit',
                  '.claude/commands/$DIRECTORY_PROBE_FILE',
                ];
                populate('locked');
                try {
                  for (final name in names) {
                    // Each time: a command that is not held gives the mode back.
                    chmodSync(path.join(TEST_DIR, directory), mode);
                    final result = await runSandboxed(
                      "chmod 755 locked '$directory'; echo x > 'locked/$name'",
                      threads,
                    );

                    expect([name, result.success], [name, false]);
                  }
                } finally {
                  chmodSync(path.join(TEST_DIR, directory), 493); // 0o755
                }
                for (final name in names) {
                  expect(
                    readFileSync('locked/$name', 'utf8'),
                    ORIGINAL_CONTENT,
                  );
                }
              },
            );
          }
        }

        // root reads a directory of any mode.
        test(
          'takes what ripgrep says it could not read for a hint only',
          () async {
            final project = path.join(TEST_DIR, 'hints');
            final outside = path.join(TEST_DIR, 'hints-outside');
            for (final directory in [
              path.join(project, 'is-readable'),
              path.join(project, 'really-locked'),
              path.join(project, 'locked: too'),
              path.join(project, 'locked\\so'),
              path.join(project, 'one-thread'),
              path.join(project, 'no-prefix'),
              path.join(project, 'listed-only/child'),
              path.join(project, 'entered-only'),
              path.join(project, 'a/b/c/too-deep'),
              path.join(outside, 'behind-a-link'),
            ]) {
              mkdirSync(directory, {'recursive': true});
            }
            symlinkSync(outside, path.join(project, 'link'));
            final locked = [
              path.join(project, 'really-locked'),
              path.join(project, 'locked: too'),
              path.join(project, 'locked\\so'),
              path.join(project, 'one-thread'),
              path.join(project, 'no-prefix'),
              path.join(project, 'a/b/c/too-deep'),
              path.join(outside, 'behind-a-link'),
            ];
            // What a name in the tree could make ripgrep say.
            final said =
                [
                      'is-readable',
                      'really-locked',
                      'a/b/c/too-deep',
                      'link/behind-a-link',
                      '../hints-outside/behind-a-link',
                      'not-there/at-all',
                      'entered-only/not-there',
                      'locked: too',
                      'locked\\so',
                      'listed-only/child',
                    ]
                    .map(
                      (name) =>
                          'rg: $project/$name: Permission denied (os error 13)',
                    )
                    .toList();
            said.addAll([
              'rg: $project/one-thread: IO error for operation on $project/one-thread: Permission denied (os error 13)',
              '$project/no-prefix: Permission denied (os error 13)',
            ]);
            final standIn = path.join(TEST_DIR, 'says-it-could-not-read');
            final asked = path.join(TEST_DIR, 'was-asked');
            writeFileSync(
              standIn,
              [
                '#!/bin/sh',
                "printf '%s\\n' \"\$@\" > '$asked'",
                ...said.map((line) => "echo '$line' >&2"),
                'exit 2',
              ].join('\n'),
              {'mode': 493}, // 0o755
            );
            Directory.current = project;
            for (final directory in locked) {
              chmodSync(directory, 0);
            }
            chmodSync(path.join(project, 'listed-only'), 292); // 0o444
            chmodSync(path.join(project, 'entered-only'), 73); // 0o111
            try {
              final wrapped = await wrapCommandWithSandboxLinux(
                LinuxSandboxParams(
                  command: 'true',
                  needsNetworkRestriction: false,
                  readConfig: null,
                  writeConfig: FsWriteRestrictionConfig(
                    allowOnly: ['.'],
                    denyWithinAllow: [],
                  ),
                  ripgrepConfig: RipgrepConfig(command: standIn),
                ),
              );

              expect(unreadableDirectories(said.join('\n'), project, 3), [
                path.join(project, 'really-locked'),
                path.join(project, 'locked: too'),
                path.join(project, 'locked\\so'),
                path.join(project, 'listed-only'),
                path.join(project, 'one-thread'),
                path.join(project, 'no-prefix'),
              ]);
              // Nobody else's mode can be given back from inside.
              final uid = process.getuid!();
              final getuid = process.getuid;
              process.getuid = () => uid + 1;
              try {
                expect(unreadableDirectories(said.join('\n'), project, 3), []);
              } finally {
                process.getuid = getuid;
              }
              expect(wrapped, contains('really-locked'));
              expect(
                (readFileSync(asked, 'utf8') as String).split('\n'),
                containsAll(['--no-ignore', '--no-config', '--line-buffered']),
              );
            } finally {
              for (final directory in [
                ...locked,
                path.join(project, 'listed-only'),
                path.join(project, 'entered-only'),
              ]) {
                chmodSync(directory, 493); // 0o755
              }
            }
          },
          skip: (isLinux && process.getuid?.call() != 0)
              ? false
              : 'requires Linux and a non-root user',
        );

        test(
          'takes no directory above the working directory for one of the names',
          () async {
            final project = path.join(TEST_DIR, 'above', '.idea', 'project');
            mkdirSync(path.join(project, 'sub'), {'recursive': true});
            writeFileSync(
              path.join(project, 'sub', '.bashrc'),
              ORIGINAL_CONTENT,
            );
            Directory.current = project;

            expect(
              (await runSandboxedWrite('sub/.bashrc', 'x')).success,
              false,
            );
            expect(
              (await runSandboxedWrite('safe-file.txt', 'x')).success,
              true,
            );
          },
          skip: isLinux ? false : 'Linux only',
        );

        for (final (container, names) in <(String, List<String>)>[
          ('a/b', existing.where((name) => name.contains('/')).toList()),
          (beyond, existing),
        ]) {
          test(
            'looks no deeper than the depth says: ${names.length} names in $container/',
            () async {
              for (final name in names) {
                final target = '$container/$name';
                final result = await runSandboxedWrite(
                  target,
                  MODIFIED_CONTENT,
                );

                expect([target, result.success], [target, true]);
              }
            },
            skip: isLinux ? false : 'Linux only',
            timeout: const Timeout(Duration(milliseconds: 60000)),
          );
        }
      });

      group('Safe files should still be writable', () {
        test('allows writes to regular files', () async {
          final result = await runSandboxedWrite(
            'safe-file.txt',
            MODIFIED_CONTENT,
          );

          expect(result.success, true);
          expect(
            (readFileSync('safe-file.txt', 'utf8') as String).trim(),
            MODIFIED_CONTENT,
          );
        });

        test('allows writes to .git/objects (not hooks/config)', () async {
          final result = await runSandboxedWrite(
            '.git/objects/test-obj',
            MODIFIED_CONTENT,
          );

          expect(result.success, true);
          expect(
            (readFileSync('.git/objects/test-obj', 'utf8') as String).trim(),
            MODIFIED_CONTENT,
          );
        });

        test('allows writes to .git/refs/heads (not hooks/config)', () async {
          final result = await runSandboxedWrite(
            '.git/refs/heads/main',
            MODIFIED_CONTENT,
          );

          expect(result.success, true);
          expect(
            (readFileSync('.git/refs/heads/main', 'utf8') as String).trim(),
            MODIFIED_CONTENT,
          );
        });

        test('allows writes to .git/index (not hooks/config)', () async {
          final result = await runSandboxedWrite(
            '.git/index',
            MODIFIED_CONTENT,
          );

          expect(result.success, true);
          expect(
            (readFileSync('.git/index', 'utf8') as String).trim(),
            MODIFIED_CONTENT,
          );
        });

        test(
          'allows writes to .claude/ files outside commands/agents',
          () async {
            final result = await runSandboxedWrite(
              '.claude/some-other-file.txt',
              MODIFIED_CONTENT,
            );

            expect(result.success, true);
            expect(
              (readFileSync('.claude/some-other-file.txt', 'utf8') as String)
                  .trim(),
              MODIFIED_CONTENT,
            );
          },
        );
      });

      group('allowGitConfig option', () {
        Future<({bool success, String stderr})> runSandboxedWriteWithGitConfig(
          String filePath,
          String content,
          bool allowGitConfig,
        ) async {
          final platform = getPlatform();
          final command = "echo '$content' > '$filePath'";

          final writeConfig = FsWriteRestrictionConfig(
            allowOnly: ['.'],
            denyWithinAllow: [],
          );

          String wrappedCommand;
          if (platform == 'macos') {
            wrappedCommand = wrapCommandWithSandboxMacOS(
              MacOSSandboxParams(
                command: command,
                needsNetworkRestriction: false,
                readConfig: null,
                writeConfig: writeConfig,
                allowGitConfig: allowGitConfig,
              ),
            );
          } else {
            wrappedCommand = await wrapCommandWithSandboxLinux(
              LinuxSandboxParams(
                command: command,
                needsNetworkRestriction: false,
                readConfig: null,
                writeConfig: writeConfig,
                allowGitConfig: allowGitConfig,
              ),
            );
          }

          final result = spawnSync(wrappedCommand, [], {
            'shell': true,
            'encoding': 'utf8',
            'timeout': 10000,
          });

          return (
            success: result.status == 0,
            stderr: (result.stderr as String?) ?? '',
          );
        }

        test(
          'blocks writes to .git/config when allowGitConfig is false (default)',
          () async {
            // Reset .git/config to original content
            writeFileSync('.git/config', ORIGINAL_CONTENT);

            final result = await runSandboxedWriteWithGitConfig(
              '.git/config',
              MODIFIED_CONTENT,
              false,
            );

            expect(result.success, false);
            expect(readFileSync('.git/config', 'utf8'), ORIGINAL_CONTENT);
          },
        );

        test(
          'allows writes to .git/config when allowGitConfig is true',
          () async {
            // Reset .git/config to original content
            writeFileSync('.git/config', ORIGINAL_CONTENT);

            final result = await runSandboxedWriteWithGitConfig(
              '.git/config',
              MODIFIED_CONTENT,
              true,
            );

            expect(result.success, true);
            expect(
              (readFileSync('.git/config', 'utf8') as String).trim(),
              MODIFIED_CONTENT,
            );
          },
        );

        test(
          'still blocks writes to .git/hooks even when allowGitConfig is true',
          () async {
            // Reset pre-commit to original content
            writeFileSync('.git/hooks/pre-commit', ORIGINAL_CONTENT);

            final result = await runSandboxedWriteWithGitConfig(
              '.git/hooks/pre-commit',
              MODIFIED_CONTENT,
              true,
            );

            expect(result.success, false);
            expect(
              readFileSync('.git/hooks/pre-commit', 'utf8'),
              ORIGINAL_CONTENT,
            );
          },
        );
      });

      group(
        'Non-existent deny path protection and cleanup (Linux only)',
        skip: isLinux ? false : 'Linux only',
        () {
          // This tests that:
          // 1. Non-existent deny paths within writable areas are blocked by mounting
          //    /dev/null at the first non-existent component
          // 2. The mount point artifacts bwrap creates on the host are cleaned up
          //    by cleanupBwrapMountPoints()
          //
          // Background: When bwrap does --ro-bind /dev/null /nonexistent/path, it
          // creates an empty file on the host as a mount point. Without cleanup,
          // these "ghost dotfiles" persist and pollute the working directory.

          Future<({bool success, String stdout, String stderr})>
          runSandboxedWriteWithDenyPaths(
            String command,
            List<String> denyPaths,
          ) async {
            final platform = getPlatform();
            if (platform != 'linux') {
              return (success: true, stdout: '', stderr: '');
            }

            final writeConfig = FsWriteRestrictionConfig(
              allowOnly: ['.'],
              denyWithinAllow: denyPaths,
            );

            final wrappedCommand = await wrapCommandWithSandboxLinux(
              LinuxSandboxParams(
                command: command,
                needsNetworkRestriction: false,
                readConfig: null,
                writeConfig: writeConfig,
                enableWeakerNestedSandbox: true,
              ),
            );

            final result = spawnSync(wrappedCommand, [], {
              'shell': true,
              'encoding': 'utf8',
              'timeout': 10000,
            });

            return (
              success: result.status == 0,
              stdout: (result.stdout as String?) ?? '',
              stderr: (result.stderr as String?) ?? '',
            );
          }

          // --- Security: deny path blocking ---

          test(
            'blocks creation of non-existent file when parent dir exists',
            () async {
              // .claude directory exists from beforeAll setup
              // .claude/settings.json does NOT exist
              const nonExistentFile = '.claude/settings.json';

              final result = await runSandboxedWriteWithDenyPaths(
                "echo '{\"hooks\":{}}' > '$nonExistentFile'",
                [path.join(TEST_DIR, nonExistentFile)],
              );

              expect(result.success, false);
              // Verify file content was NOT written (bwrap creates empty mount point)
              final content = readFileSync(nonExistentFile, 'utf8');
              expect(content, '');

              cleanupBwrapMountPoints();
            },
          );

          test(
            'blocks creation of non-existent file when parent dir also does not exist',
            () async {
              const nonExistentPath = 'nonexistent-dir/settings.json';

              final result = await runSandboxedWriteWithDenyPaths(
                "mkdir -p nonexistent-dir && echo '{\"hooks\":{}}' > '$nonExistentPath'",
                [path.join(TEST_DIR, nonExistentPath)],
              );

              expect(result.success, false);
              // bwrap mounts an empty read-only directory at first non-existent
              // intermediate component, blocking mkdir inside it
              final stat = statSync('nonexistent-dir');
              expect(stat.isDirectory(), true);

              cleanupBwrapMountPoints();
            },
          );

          test('blocks creation of deeply nested non-existent path', () async {
            const nonExistentPath = 'a/b/c/file.txt';

            final result = await runSandboxedWriteWithDenyPaths(
              "mkdir -p a/b/c && echo 'test' > '$nonExistentPath'",
              [path.join(TEST_DIR, nonExistentPath)],
            );

            expect(result.success, false);
            // bwrap mounts an empty read-only directory at 'a', blocking the
            // entire subtree
            final stat = statSync('a');
            expect(stat.isDirectory(), true);

            cleanupBwrapMountPoints();
          });

          // --- Cleanup: mount point artifact removal ---

          test(
            'cleanupBwrapMountPoints removes mount point artifacts',
            () async {
              const nonExistentPath = 'cleanup-test-dir/file.txt';

              await runSandboxedWriteWithDenyPaths(
                "echo test > '$nonExistentPath'",
                [path.join(TEST_DIR, nonExistentPath)],
              );

              // Mount point artifact should exist on host after bwrap exits
              expect(existsSync('cleanup-test-dir'), true);

              // Clean up
              cleanupBwrapMountPoints();

              // Artifact should be gone
              expect(existsSync('cleanup-test-dir'), false);
            },
          );

          test(
            'cleanupBwrapMountPoints removes multiple mount points from a single command',
            () async {
              // Two non-existent deny paths in different subtrees
              const path1 = 'ghost-dir-a/secret.txt';
              const path2 = 'ghost-dir-b/secret.txt';

              await runSandboxedWriteWithDenyPaths(
                'mkdir -p ghost-dir-a ghost-dir-b',
                [path.join(TEST_DIR, path1), path.join(TEST_DIR, path2)],
              );

              // Both mount point artifacts should exist
              expect(existsSync('ghost-dir-a'), true);
              expect(existsSync('ghost-dir-b'), true);

              cleanupBwrapMountPoints();

              // Both should be cleaned up
              expect(existsSync('ghost-dir-a'), false);
              expect(existsSync('ghost-dir-b'), false);
            },
          );

          test('cleanupBwrapMountPoints preserves non-empty directories', () async {
            const nonExistentPath = 'preserve-test-dir/file.txt';

            await runSandboxedWriteWithDenyPaths(
              "echo test > '$nonExistentPath'",
              [path.join(TEST_DIR, nonExistentPath)],
            );

            // Simulate something else creating content in the mount point directory
            // (e.g., another process created files here legitimately)
            final mountPoint = path.join(TEST_DIR, 'preserve-test-dir');
            if (existsSync(mountPoint)) {
              // Create a file inside — cleanup should NOT delete non-empty directories
              writeFileSync(
                path.join(mountPoint, 'real-file.txt'),
                'real content',
              );
            }

            cleanupBwrapMountPoints();

            // Directory with real content should be preserved
            if (existsSync(mountPoint)) {
              expect(statSync(mountPoint).isDirectory(), true);
              final content = readFileSync(
                path.join(mountPoint, 'real-file.txt'),
                'utf8',
              );
              expect(content, 'real content');
              // Manual cleanup for this test
              rmSync(mountPoint, {'recursive': true, 'force': true});
            }
          });

          test(
            'cleanupBwrapMountPoints is safe to call when there are no mount points',
            () {
              // Should not throw
              cleanupBwrapMountPoints();
              cleanupBwrapMountPoints();
            },
          );

          // --- Concurrent sandbox mount point cleanup ---
          //
          // When two sandboxed commands run concurrently and one finishes first,
          // cleanupBwrapMountPoints() must NOT delete mount point files that the
          // still-running sandbox depends on. Deleting a mountpoint's dentry on the
          // host detaches the bind mount in the child namespace, so the deny rule
          // stops applying inside the still-running sandbox.

          test(
            'defers mount point cleanup while another sandbox is still running',
            () async {
              final raceDir = path.join(TEST_DIR, 'race-test');
              mkdirSync(raceDir, {'recursive': true});
              mkdirSync(path.join(raceDir, '.claude'), {'recursive': true});

              final originalDir = process.cwd();
              Directory.current = raceDir;

              try {
                final protectedFile = path.join(
                  raceDir,
                  '.claude',
                  'settings.json',
                );
                final writeConfig = FsWriteRestrictionConfig(
                  allowOnly: ['.'],
                  denyWithinAllow: [protectedFile],
                );

                // Sandbox A: long-running command that sleeps then tries to write
                // to the denied path. The write should be blocked.
                // allowAllUnixSockets skips seccomp (environment-dependent) while
                // keeping the filesystem isolation we're testing.
                final wrappedA = await wrapCommandWithSandboxLinux(
                  LinuxSandboxParams(
                    command:
                        "sleep 2; echo '{\"hooks\":{}}' > .claude/settings.json",
                    needsNetworkRestriction: false,
                    readConfig: null,
                    writeConfig: writeConfig,
                    enableWeakerNestedSandbox: true,
                    allowAllUnixSockets: true,
                  ),
                );

                final childA = spawn(wrappedA, [], {'shell': true});
                final exitA = Completer<int?>();
                childA.on('exit', (int? code) => exitA.complete(code));

                // Wait for bwrap A to start and create the mount point on the host
                await Future<void>.delayed(const Duration(milliseconds: 500));
                expect(existsSync(protectedFile), true);

                // Sandbox B: short command. When it finishes, the caller invokes
                // cleanupBwrapMountPoints() — simulating the real-world race.
                final wrappedB = await wrapCommandWithSandboxLinux(
                  LinuxSandboxParams(
                    command: 'true',
                    needsNetworkRestriction: false,
                    readConfig: null,
                    writeConfig: writeConfig,
                    enableWeakerNestedSandbox: true,
                    allowAllUnixSockets: true,
                  ),
                );
                spawnSync(wrappedB, [], {
                  'shell': true,
                  'encoding': 'utf8',
                  'timeout': 10000,
                });

                // This is what the caller does after every command completes.
                // Without deferral, this would delete sandbox A's mount point too.
                cleanupBwrapMountPoints();

                // Wait for sandbox A to attempt its write
                await exitA.future;

                // The deny rule must have held — the file should not contain the
                // write from sandbox A. If cleanup had deleted the mount point
                // early, A's bind mount would have detached and the write would
                // have landed on the host.
                final content = existsSync(protectedFile)
                    ? readFileSync(protectedFile, 'utf8') as String
                    : '';
                expect(content, isNot(contains('hooks')));

                cleanupBwrapMountPoints();
              } finally {
                Directory.current = originalDir;
                rmSync(raceDir, {'recursive': true, 'force': true});
              }
            },
            timeout: const Timeout(Duration(milliseconds: 15000)),
          );

          test(
            'defers cleanup when two sandboxes share the same non-existent deny path',
            () async {
              final raceDir = path.join(TEST_DIR, 'race-test-2');
              mkdirSync(raceDir, {'recursive': true});
              mkdirSync(path.join(raceDir, '.claude'), {'recursive': true});

              final originalDir = process.cwd();
              Directory.current = raceDir;

              try {
                final protectedFile = path.join(
                  raceDir,
                  '.claude',
                  'settings.json',
                );
                final writeConfig = FsWriteRestrictionConfig(
                  allowOnly: ['.'],
                  denyWithinAllow: [protectedFile],
                );

                // Generate both wrapped commands BEFORE spawning, so both see the
                // deny path as non-existent and both add it to bwrapMountPoints.
                final wrappedA = await wrapCommandWithSandboxLinux(
                  LinuxSandboxParams(
                    command: 'sleep 2; echo WRITTEN > .claude/settings.json',
                    needsNetworkRestriction: false,
                    readConfig: null,
                    writeConfig: writeConfig,
                    enableWeakerNestedSandbox: true,
                    allowAllUnixSockets: true,
                  ),
                );
                final wrappedB = await wrapCommandWithSandboxLinux(
                  LinuxSandboxParams(
                    command: 'sleep 0.5',
                    needsNetworkRestriction: false,
                    readConfig: null,
                    writeConfig: writeConfig,
                    enableWeakerNestedSandbox: true,
                    allowAllUnixSockets: true,
                  ),
                );

                final childA = spawn(wrappedA, [], {'shell': true});
                final exitA = Completer<int?>();
                childA.on('exit', (int? code) => exitA.complete(code));

                // Sandbox B runs and finishes first
                spawnSync(wrappedB, [], {
                  'shell': true,
                  'encoding': 'utf8',
                  'timeout': 10000,
                });
                cleanupBwrapMountPoints();

                await exitA.future;

                final content = existsSync(protectedFile)
                    ? readFileSync(protectedFile, 'utf8') as String
                    : '';
                expect(content, isNot(contains('WRITTEN')));

                cleanupBwrapMountPoints();
              } finally {
                Directory.current = originalDir;
                rmSync(raceDir, {'recursive': true, 'force': true});
              }
            },
            timeout: const Timeout(Duration(milliseconds: 15000)),
          );

          test(
            'deferred cleanup runs once all concurrent sandboxes finish',
            () async {
              final raceDir = path.join(TEST_DIR, 'race-test-3');
              mkdirSync(raceDir, {'recursive': true});
              mkdirSync(path.join(raceDir, '.claude'), {'recursive': true});

              final originalDir = process.cwd();
              Directory.current = raceDir;

              try {
                final protectedFile = path.join(
                  raceDir,
                  '.claude',
                  'settings.json',
                );
                final writeConfig = FsWriteRestrictionConfig(
                  allowOnly: ['.'],
                  denyWithinAllow: [protectedFile],
                );

                final wrappedA = await wrapCommandWithSandboxLinux(
                  LinuxSandboxParams(
                    command: 'sleep 1',
                    needsNetworkRestriction: false,
                    readConfig: null,
                    writeConfig: writeConfig,
                    enableWeakerNestedSandbox: true,
                    allowAllUnixSockets: true,
                  ),
                );
                final wrappedB = await wrapCommandWithSandboxLinux(
                  LinuxSandboxParams(
                    command: 'true',
                    needsNetworkRestriction: false,
                    readConfig: null,
                    writeConfig: writeConfig,
                    enableWeakerNestedSandbox: true,
                    allowAllUnixSockets: true,
                  ),
                );

                final childA = spawn(wrappedA, [], {'shell': true});
                final exitA = Completer<void>();
                childA.on('exit', () => exitA.complete());

                await Future<void>.delayed(const Duration(milliseconds: 300));
                expect(existsSync(protectedFile), true);

                spawnSync(wrappedB, [], {
                  'shell': true,
                  'encoding': 'utf8',
                  'timeout': 10000,
                });
                cleanupBwrapMountPoints();

                // Cleanup deferred — mount point still present while A runs
                expect(existsSync(protectedFile), true);

                await exitA.future;
                cleanupBwrapMountPoints();

                // Both sandboxes done — mount point now cleaned up
                expect(existsSync(protectedFile), false);
              } finally {
                Directory.current = originalDir;
                rmSync(raceDir, {'recursive': true, 'force': true});
              }
            },
            timeout: const Timeout(Duration(milliseconds: 15000)),
          );

          // The caller runs no cleanup for a wrap that threw, so a removal
          // deferred to that wrap has nobody else to run it.

          // Dart: `Partial<LinuxSandboxParams>` is the named parameters.
          Future<String> wrapInCwd(
            String command, {
            AbortSignal? abortSignal,
            String? binShell,
            RipgrepConfig? ripgrepConfig,
          }) => wrapCommandWithSandboxLinux(
            LinuxSandboxParams(
              command: command,
              needsNetworkRestriction: false,
              readConfig: null,
              writeConfig: FsWriteRestrictionConfig(
                allowOnly: ['.'],
                denyWithinAllow: [],
              ),
              enableWeakerNestedSandbox: true,
              allowAllUnixSockets: true,
              abortSignal: abortSignal,
              binShell: binShell,
              ripgrepConfig: ripgrepConfig,
            ),
          );

          for (final how in ['aborted', 'refused']) {
            test(
              'runs the cleanup deferred to a wrap that is then $how',
              () async {
                final raceDir = path.join(TEST_DIR, 'race-test-4');
                mkdirSync(raceDir, {'recursive': true});
                Directory.current = raceDir;

                try {
                  spawnSync(await wrapInCwd('true'), [], {
                    'shell': true,
                    'timeout': 10000,
                  });
                  expect(readdirSync(raceDir), contains('.bashrc'));

                  // B is still looking for the mandatory denies when A's caller
                  // cleans up.
                  final controller = AbortController();
                  final wrappedB = wrapInCwd(
                    'true',
                    abortSignal: controller.signal,
                    binShell: how == 'refused' ? 'no-such-shell' : null,
                  );
                  cleanupBwrapMountPoints();
                  expect(readdirSync(raceDir), contains('.bashrc'));

                  if (how == 'aborted') {
                    controller.abort(NodeException('stopped'));
                  }
                  expect(
                    await wrappedB.then<Object>(
                      (v) => v,
                      onError: (Object e) => e,
                    ),
                    isA<Error>(),
                  );
                  expect(readdirSync(raceDir), <String>[]);
                } finally {
                  Directory.current = TEST_DIR;
                  rmSync(raceDir, {'recursive': true, 'force': true});
                }
              },
            );
          }

          test(
            'forgets the mount points planned by a wrap that is then refused',
            () async {
              final raceDir = path.join(TEST_DIR, 'race-test-6');
              mkdirSync(raceDir, {'recursive': true});
              Directory.current = raceDir;

              try {
                expect(
                  await wrapInCwd(
                    'true',
                    binShell: 'no-such-shell',
                  ).then<Object>((v) => v, onError: (Object e) => e),
                  isA<Error>(),
                );

                // bwrap never ran, so this is no mount point: the host made it.
                writeFileSync('.mcp.json', '');
                spawnSync(await wrapInCwd('true'), [], {
                  'shell': true,
                  'timeout': 10000,
                });
                cleanupBwrapMountPoints();
                expect(readdirSync(raceDir), ['.mcp.json']);
              } finally {
                Directory.current = TEST_DIR;
                rmSync(raceDir, {'recursive': true, 'force': true});
              }
            },
          );

          for (final (how, which) in [
            ('aborted', 'counted along with it'),
            ('aborted', 'started since a forced cleanup'),
            ('handed out', 'started since a forced cleanup'),
          ]) {
            test(
              'a wrap that is $how leaves the mount points of a running sandbox $which',
              () async {
                final raceDir = path.join(TEST_DIR, 'race-test-5');
                mkdirSync(raceDir, {'recursive': true});
                Directory.current = raceDir;
                // Stands in for ripgrep, and goes on until told to end.
                final heldScan = path.join(raceDir, 'held-scan');
                writeFileSync(
                  heldScan,
                  "#!/bin/sh\nuntil [ -e '$raceDir/scanned' ]; do sleep 0.1; done\n",
                  {'mode': 493}, // 0o755
                );

                try {
                  final controller = AbortController();
                  final wrappedB = wrapInCwd(
                    'true',
                    abortSignal: controller.signal,
                    ripgrepConfig: RipgrepConfig(command: heldScan),
                  );
                  if (which != 'counted along with it') {
                    cleanupBwrapMountPoints(force: true);
                  }

                  // C runs throughout, and tries a denied name once told to.
                  final childC = spawn(
                    await wrapInCwd(
                      'until [ -e go ]; do sleep 0.1; done; echo WRITTEN > .bashrc',
                    ),
                    [],
                    {'shell': true},
                  );
                  final exitC = Completer<void>();
                  childC.on('exit', () => exitC.complete());
                  while (!existsSync('.bashrc')) {
                    await Future<void>.delayed(
                      const Duration(milliseconds: 50),
                    );
                  }

                  if (how == 'aborted') {
                    controller.abort(NodeException('stopped'));
                    expect(
                      await wrappedB.then<Object>(
                        (v) => v,
                        onError: (Object e) => e,
                      ),
                      isA<Error>(),
                    );
                  } else {
                    writeFileSync('scanned', '');
                    spawnSync(await wrappedB, [], {
                      'shell': true,
                      'timeout': 10000,
                    });
                    cleanupBwrapMountPoints();
                  }
                  expect(existsSync('.bashrc'), true);

                  // C is still counted, so the next command to end defers to it.
                  spawnSync(await wrapInCwd('true'), [], {
                    'shell': true,
                    'timeout': 10000,
                  });
                  cleanupBwrapMountPoints();
                  expect(existsSync('.bashrc'), true);

                  writeFileSync('go', '');
                  await exitC.future;
                  expect(readFileSync('.bashrc', 'utf8'), '');

                  cleanupBwrapMountPoints();
                  expect(existsSync('.bashrc'), false);
                } finally {
                  Directory.current = TEST_DIR;
                  rmSync(raceDir, {'recursive': true, 'force': true});
                }
              },
              timeout: const Timeout(Duration(milliseconds: 15000)),
            );
          }

          test(
            'leaves nothing of a directory mount point that another sandbox was wrapped under',
            () async {
              final raceDir = path.join(TEST_DIR, 'race-test-7');
              mkdirSync(raceDir, {'recursive': true});
              Directory.current = raceDir;

              try {
                final childT = spawn(
                  await wrapInCwd('until [ -e go ]; do sleep 0.1; done'),
                  [],
                  {'shell': true},
                );
                final exitT = Completer<void>();
                childT.on('exit', () => exitT.complete());
                while (!existsSync('.claude')) {
                  await Future<void>.delayed(const Duration(milliseconds: 50));
                }

                // T's .claude is there by now, so X's mount points go inside it.
                spawnSync(await wrapInCwd('true'), [], {
                  'shell': true,
                  'timeout': 10000,
                });
                cleanupBwrapMountPoints();
                expect(readdirSync('.claude'), isNot(<String>[]));

                writeFileSync('go', '');
                await exitT.future;
                cleanupBwrapMountPoints();
                expect(readdirSync(raceDir), ['go']);

                spawnSync(await wrapInCwd('true'), [], {
                  'shell': true,
                  'timeout': 10000,
                });
                cleanupBwrapMountPoints();
                expect(readdirSync(raceDir), ['go']);
              } finally {
                Directory.current = TEST_DIR;
                rmSync(raceDir, {'recursive': true, 'force': true});
              }
            },
            timeout: const Timeout(Duration(milliseconds: 15000)),
          );

          test(
            'takes only its own where the host has written at a mount point or inside one',
            () async {
              final raceDir = path.join(TEST_DIR, 'race-test-8');
              mkdirSync(raceDir, {'recursive': true});
              Directory.current = raceDir;

              try {
                // The second is wrapped with the first's .claude there.
                spawnSync(await wrapInCwd('true'), [], {
                  'shell': true,
                  'timeout': 10000,
                });
                spawnSync(await wrapInCwd('true'), [], {
                  'shell': true,
                  'timeout': 10000,
                });
                expect(readdirSync('.claude'), isNot(<String>[]));
                writeFileSync('.claude/kept', '');
                rmSync('.bashrc');
                writeFileSync('.bashrc', 'kept');

                cleanupBwrapMountPoints();
                cleanupBwrapMountPoints();
                expect(readdirSync(raceDir)..sort(), ['.bashrc', '.claude']);
                expect(readdirSync('.claude'), ['kept']);
                expect(readFileSync('.bashrc', 'utf8'), 'kept');
              } finally {
                Directory.current = TEST_DIR;
                rmSync(raceDir, {'recursive': true, 'force': true});
              }
            },
          );

          test(
            'non-existent .git/hooks deny does not turn .git into a file, breaking git',
            () async {
              // When .git doesn't exist yet, denying .git/hooks causes
              // findFirstNonExistentComponent to return .git itself. bwrap then does
              // --ro-bind /dev/null .git, creating .git as a FILE (not a directory).
              // Inside the sandbox, every git command fails because .git is a file.

              // Use a clean directory with NO .git
              final noGitDir = path.join(TEST_DIR, 'no-git-dir');
              mkdirSync(noGitDir, {'recursive': true});

              final originalDir = process.cwd();
              Directory.current = noGitDir;

              try {
                final writeConfig = FsWriteRestrictionConfig(
                  allowOnly: ['.'],
                  denyWithinAllow: <String>[],
                );

                // This calls linuxGetMandatoryDenyPaths which unconditionally adds
                // .git/hooks to the deny list. When .git doesn't exist,
                // findFirstNonExistentComponent returns .git and bwrap mounts
                // /dev/null there — making .git a file.
                final wrappedCommand = await wrapCommandWithSandboxLinux(
                  LinuxSandboxParams(
                    command: 'git init && git status',
                    needsNetworkRestriction: false,
                    readConfig: null,
                    writeConfig: writeConfig,
                    enableWeakerNestedSandbox: true,
                  ),
                );

                final result = spawnSync(wrappedCommand, [], {
                  'shell': true,
                  'encoding': 'utf8',
                  'timeout': 10000,
                });

                // git init + git status should succeed — .git must be creatable as
                // a directory, not blocked by a /dev/null file mount.
                expect(result.status, 0);

                cleanupBwrapMountPoints();
              } finally {
                Directory.current = originalDir;
                rmSync(noGitDir, {'recursive': true, 'force': true});
              }
            },
          );

          test('git worktree with .git as a file does not break sandboxed commands', () async {
            // Reproduces the bug reported by nvidia/netflix with git worktrees:
            // In a worktree, .git is a FILE (e.g., "gitdir: /path/to/.git/worktrees/foo"),
            // not a directory. The mandatory deny list includes .git/hooks, but since
            // .git is a file, .git/hooks doesn't exist. The non-existent path handling
            // tries to mount /dev/null at .git/hooks, but bwrap can't create a mount
            // point under .git because it's a file — causing every command to fail.

            final worktreeDir = path.join(TEST_DIR, 'fake-worktree');
            mkdirSync(worktreeDir, {'recursive': true});

            // Simulate a git worktree: .git is a file, not a directory
            writeFileSync(
              path.join(worktreeDir, '.git'),
              'gitdir: /tmp/fake-main-repo/.git/worktrees/my-branch',
            );

            final originalDir = process.cwd();
            Directory.current = worktreeDir;

            try {
              final writeConfig = FsWriteRestrictionConfig(
                allowOnly: ['.'],
                denyWithinAllow: <String>[],
              );

              // linuxGetMandatoryDenyPaths adds .git/hooks to deny list.
              // .git exists as a file, so .git/hooks doesn't exist.
              // The code will try to mount /dev/null at .git/hooks, but bwrap
              // can't create a mount point there because .git is a file.
              final wrappedCommand = await wrapCommandWithSandboxLinux(
                LinuxSandboxParams(
                  command: 'echo hello',
                  needsNetworkRestriction: false,
                  readConfig: null,
                  writeConfig: writeConfig,
                  enableWeakerNestedSandbox: true,
                ),
              );

              final result = spawnSync(wrappedCommand, [], {
                'shell': true,
                'encoding': 'utf8',
                'timeout': 10000,
              });

              // A simple echo should succeed — the .git-as-file worktree layout
              // should not cause the sandbox to fail.
              expect(result.status, 0);
              expect((result.stdout as String).trim(), 'hello');

              cleanupBwrapMountPoints();
            } finally {
              Directory.current = originalDir;
              rmSync(worktreeDir, {'recursive': true, 'force': true});
            }
          });

          test('does not leave ghost dotfiles after command + cleanup cycle', () async {
            // This is the exact scenario from issue #85: running a sandboxed command
            // should NOT leave .bashrc, .gitconfig, etc. in the working directory.
            //
            // The mandatory deny list includes paths like ~/.bashrc, ~/.gitconfig.
            // When CWD is within an allowed write path and these dotfiles don't exist
            // in CWD, the old code left empty mount point files behind.

            // Use a clean subdirectory with no dotfiles
            final cleanDir = path.join(TEST_DIR, 'clean-subdir');
            mkdirSync(cleanDir, {'recursive': true});

            final originalDir = process.cwd();
            Directory.current = cleanDir;

            try {
              // Run a simple command through the sandbox
              final writeConfig = FsWriteRestrictionConfig(
                allowOnly: ['.'],
                denyWithinAllow: <String>[],
              );

              final wrappedCommand = await wrapCommandWithSandboxLinux(
                LinuxSandboxParams(
                  command: 'echo hello',
                  needsNetworkRestriction: false,
                  readConfig: null,
                  writeConfig: writeConfig,
                  enableWeakerNestedSandbox: true,
                ),
              );

              spawnSync(wrappedCommand, [], {
                'shell': true,
                'encoding': 'utf8',
                'timeout': 10000,
              });

              // Run cleanup (as the CLI / Claude Code would)
              cleanupBwrapMountPoints();

              // Verify no ghost dotfiles were left behind
              // Dart: readdirSync is already in scope, no dynamic import
              final files = readdirSync(cleanDir);
              final ghostDotfiles = files
                  .where((f) => f.startsWith('.'))
                  .toList();
              expect(ghostDotfiles, <String>[]);
            } finally {
              Directory.current = originalDir;
              rmSync(cleanDir, {'recursive': true, 'force': true});
            }
          });
        },
      );

      group(
        'Symlink replacement attack protection (Linux only)',
        skip: isLinux ? false : 'Linux only',
        () {
          // This tests the fix for symlink replacement attacks where an attacker
          // could delete a symlink and create a real directory with malicious content

          Future<({bool success, String stdout, String stderr})>
          runSandboxedCommandWithDenyPaths(
            String command,
            List<String> denyPaths,
          ) async {
            final platform = getPlatform();
            if (platform != 'linux') {
              return (success: true, stdout: '', stderr: '');
            }

            final writeConfig = FsWriteRestrictionConfig(
              allowOnly: ['.'],
              denyWithinAllow: denyPaths,
            );

            final wrappedCommand = await wrapCommandWithSandboxLinux(
              LinuxSandboxParams(
                command: command,
                needsNetworkRestriction: false,
                readConfig: null,
                writeConfig: writeConfig,
              ),
            );

            final result = spawnSync(wrappedCommand, [], {
              'shell': true,
              'encoding': 'utf8',
              'timeout': 10000,
            });

            return (
              success: result.status == 0,
              stdout: (result.stdout as String?) ?? '',
              stderr: (result.stderr as String?) ?? '',
            );
          }

          // bwrap mount destinations resolve symlinks, so a deny path crossing
          // a directory symlink is canonicalized and the deny applied to the
          // resolved target (resolve-before-mask). Masking the raw symlink
          // with /dev/null instead made bwrap abort at startup, failing every
          // sandboxed command whenever .claude was a symlink. The guarantees
          // around a deny path whose parent stays writable are unchanged from
          // the non-symlink case.
          test('denies writes through a symlinked .claude directory', () async {
            // Setup: Create a symlink .claude -> decoy (simulating malicious git repo)
            const decoyDir = 'symlink-decoy';
            const claudeSymlink = 'symlink-claude';
            mkdirSync(decoyDir, {'recursive': true});
            writeFileSync(path.join(decoyDir, 'settings.json'), '{}');
            symlinkSync(decoyDir, claudeSymlink);

            try {
              // The deny path is the settings.json through the symlink
              final denyPath = path.join(
                TEST_DIR,
                claudeSymlink,
                'settings.json',
              );

              // The sandbox must start despite the directory symlink in the
              // deny path (bwrap used to abort on the /dev/null symlink mask).
              final benign = await runSandboxedCommandWithDenyPaths('true', [
                denyPath,
              ]);
              expect(benign.success, true);

              // Writing through the symlink must fail: the deny lands on the
              // resolved target, the inode the write actually reaches.
              final result = await runSandboxedCommandWithDenyPaths(
                "echo '{\"hooks\":{}}' > $claudeSymlink/settings.json",
                [denyPath],
              );
              expect(result.success, false);
              expect(
                readFileSync(path.join(decoyDir, 'settings.json'), 'utf8'),
                '{}',
              );
            } finally {
              // Cleanup
              rmSync(claudeSymlink, {'force': true});
              rmSync(decoyDir, {'recursive': true, 'force': true});
            }
          });

          test(
            'denies writes to a file reached through a directory symlink',
            () async {
              // Setup: Create a symlink
              const targetDir = 'symlink-target-dir';
              const symlinkPath = 'protected-symlink';
              mkdirSync(targetDir, {'recursive': true});
              writeFileSync(path.join(targetDir, 'file.txt'), 'content');
              symlinkSync(targetDir, symlinkPath);

              try {
                final denyPath = path.join(TEST_DIR, symlinkPath, 'file.txt');

                // Assert the sandbox starts first: a write-denied assertion alone
                // also passes when bwrap aborts, which is the failure this deny
                // path used to cause.
                final benign = await runSandboxedCommandWithDenyPaths('true', [
                  denyPath,
                ]);
                expect(benign.success, true);

                // The file is write-protected both through the symlink and via
                // its resolved path.
                for (final writePath in [
                  '$symlinkPath/file.txt',
                  '$targetDir/file.txt',
                ]) {
                  final result = await runSandboxedCommandWithDenyPaths(
                    'echo tampered > $writePath',
                    [denyPath],
                  );
                  expect(result.success, false);
                }
                expect(
                  readFileSync(path.join(targetDir, 'file.txt'), 'utf8'),
                  'content',
                );
              } finally {
                rmSync(symlinkPath, {'force': true});
                rmSync(targetDir, {'recursive': true, 'force': true});
              }
            },
          );
        },
      );
    },
  );

  group('macGetMandatoryDenyEntries - Unit Tests', () {
    test(
      'includes .git/config in deny patterns when allowGitConfig is false',
      () {
        final patterns = macGetMandatoryDenyEntries(false).map((e) => e.path);

        // Should include .git/config pattern
        final hasGitConfigPattern = patterns.any(
          (p) => p.contains('.git/config') || p.endsWith('.git/config'),
        );
        expect(hasGitConfigPattern, true);
      },
    );

    test(
      'excludes .git/config from deny patterns when allowGitConfig is true',
      () {
        final patterns = macGetMandatoryDenyEntries(true).map((e) => e.path);

        // Should NOT include .git/config pattern
        final hasGitConfigPattern = patterns.any(
          (p) => p.contains('.git/config') || p.endsWith('.git/config'),
        );
        expect(hasGitConfigPattern, false);
      },
    );

    test(
      'always includes .git/hooks in deny patterns regardless of allowGitConfig',
      () {
        final patternsWithoutGitConfig = macGetMandatoryDenyEntries(
          false,
        ).map((e) => e.path);
        final patternsWithGitConfig = macGetMandatoryDenyEntries(
          true,
        ).map((e) => e.path);

        // Both should include .git/hooks pattern
        final hasHooksPatternFalse = patternsWithoutGitConfig.any(
          (p) => p.contains('.git/hooks'),
        );
        final hasHooksPatternTrue = patternsWithGitConfig.any(
          (p) => p.contains('.git/hooks'),
        );

        expect(hasHooksPatternFalse, true);
        expect(hasHooksPatternTrue, true);
      },
    );

    test('defaults to blocking .git/config when no argument provided', () {
      final patterns = macGetMandatoryDenyEntries().map((e) => e.path);

      final hasGitConfigPattern = patterns.any(
        (p) => p.contains('.git/config') || p.endsWith('.git/config'),
      );
      expect(hasGitConfigPattern, true);
    });
  });
}
