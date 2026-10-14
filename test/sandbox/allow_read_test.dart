// Ported from sandbox-runtime test/sandbox/allow-read.test.ts @ 24eb39e.
// ignore_for_file: constant_identifier_names, non_constant_identifier_names, slash_for_doc_comments
import 'dart:convert' show jsonEncode;

import 'package:sandbox_runtime/src/node/child_process.dart' show spawnSync;
import 'package:sandbox_runtime/src/node/fs.dart'
    show
        existsSync,
        mkdirSync,
        readFileSync,
        realpathSync,
        rmSync,
        writeFileSync;
import 'package:sandbox_runtime/src/node/os.dart' show homedir, tmpdir;
import 'package:sandbox_runtime/src/node/path.dart' show join;
import 'package:sandbox_runtime/src/sandbox/linux_sandbox_utils.dart'
    show LinuxSandboxParams, wrapCommandWithSandboxLinux;
import 'package:sandbox_runtime/src/sandbox/macos_sandbox_utils.dart'
    show MacOSSandboxParams, wrapCommandWithSandboxMacOS;
import 'package:sandbox_runtime/src/sandbox/mitm_ca.dart'
    show createMitmCA, disposeMitmCA;
import 'package:sandbox_runtime/src/sandbox/sandbox_schemas.dart'
    show FsReadRestrictionConfig, FsWriteRestrictionConfig;
import 'package:test/test.dart';

import '../helpers/platform.dart' show isLinux, isMacOS, isSupportedPlatform;

// Dart: upstream's `it.if(cond)` and `describe.if(cond)`, which `test` and
// `group` take as a skip.
Object? _only(bool cond, String why) => cond ? null : why;
final Object? _macOnly = _only(isMacOS, 'requires macOS');
final Object? _linuxOnly = _only(isLinux, 'requires Linux');

/**
 * Tests for the allowRead (allowWithinDeny) feature.
 *
 * allowRead re-allows read access within regions blocked by denyRead.
 * allowRead takes precedence over denyRead — the opposite of write,
 * where denyWrite takes precedence over allowWrite.
 */
void main() {
  group('allowRead precedence over denyRead', () {
    final TEST_BASE_DIR = join(
      tmpdir(),
      'allow-read-test-${DateTime.now().millisecondsSinceEpoch}',
    );
    final TEST_DENIED_DIR = join(TEST_BASE_DIR, 'denied');
    final TEST_ALLOWED_SUBDIR = join(TEST_DENIED_DIR, 'allowed');
    final TEST_SECRET_FILE = join(TEST_DENIED_DIR, 'secret.txt');
    final TEST_ALLOWED_FILE = join(TEST_ALLOWED_SUBDIR, 'visible.txt');
    const TEST_SECRET_CONTENT = 'TOP_SECRET';
    const TEST_ALLOWED_CONTENT = 'VISIBLE_DATA';

    setUpAll(() {
      if (!isSupportedPlatform) return;

      mkdirSync(TEST_ALLOWED_SUBDIR, {'recursive': true});
      writeFileSync(TEST_SECRET_FILE, TEST_SECRET_CONTENT);
      writeFileSync(TEST_ALLOWED_FILE, TEST_ALLOWED_CONTENT);
    });

    tearDownAll(() {
      if (existsSync(TEST_BASE_DIR)) {
        rmSync(TEST_BASE_DIR, {'recursive': true, 'force': true});
      }
    });

    group('macOS Seatbelt', () {
      test('should deny reading a file in a denied directory', () {
        final readConfig = FsReadRestrictionConfig(
          denyOnly: [TEST_DENIED_DIR],
          allowWithinDeny: [],
        );

        final wrappedCommand = wrapCommandWithSandboxMacOS(
          MacOSSandboxParams(
            command: 'cat $TEST_SECRET_FILE',
            needsNetworkRestriction: false,
            readConfig: readConfig,
            writeConfig: null,
          ),
        );

        final result = spawnSync(wrappedCommand, [], {
          'shell': true,
          'encoding': 'utf8',
          'timeout': 5000,
        });

        expect(result.status, isNot(0));
        expect(result.stdout as String, isNot(contains(TEST_SECRET_CONTENT)));
      }, skip: _macOnly);

      test(
        'should allow reading a file in an allowWithinDeny subdirectory',
        () {
          final readConfig = FsReadRestrictionConfig(
            denyOnly: [TEST_DENIED_DIR],
            allowWithinDeny: [TEST_ALLOWED_SUBDIR],
          );

          final wrappedCommand = wrapCommandWithSandboxMacOS(
            MacOSSandboxParams(
              command: 'cat $TEST_ALLOWED_FILE',
              needsNetworkRestriction: false,
              readConfig: readConfig,
              writeConfig: null,
            ),
          );

          final result = spawnSync(wrappedCommand, [], {
            'shell': true,
            'encoding': 'utf8',
            'timeout': 5000,
          });

          expect(result.status, 0);
          expect(result.stdout as String, contains(TEST_ALLOWED_CONTENT));
        },
        skip: _macOnly,
      );

      test(
        'should still deny reading files outside the re-allowed subdirectory',
        () {
          final readConfig = FsReadRestrictionConfig(
            denyOnly: [TEST_DENIED_DIR],
            allowWithinDeny: [TEST_ALLOWED_SUBDIR],
          );

          final wrappedCommand = wrapCommandWithSandboxMacOS(
            MacOSSandboxParams(
              command: 'cat $TEST_SECRET_FILE',
              needsNetworkRestriction: false,
              readConfig: readConfig,
              writeConfig: null,
            ),
          );

          final result = spawnSync(wrappedCommand, [], {
            'shell': true,
            'encoding': 'utf8',
            'timeout': 5000,
          });

          expect(result.status, isNot(0));
          expect(result.stdout as String, isNot(contains(TEST_SECRET_CONTENT)));
        },
        skip: _macOnly,
      );
    });

    group('Linux bwrap', () {
      test('should deny reading a file in a denied directory', () async {
        final readConfig = FsReadRestrictionConfig(
          denyOnly: [TEST_DENIED_DIR],
          allowWithinDeny: [],
        );

        final wrappedCommand = await wrapCommandWithSandboxLinux(
          LinuxSandboxParams(
            command: 'cat $TEST_SECRET_FILE',
            needsNetworkRestriction: false,
            readConfig: readConfig,
            writeConfig: null,
          ),
        );

        final result = spawnSync(wrappedCommand, [], {
          'shell': true,
          'encoding': 'utf8',
          'timeout': 5000,
        });

        expect(result.status, isNot(0));
        expect(result.stdout as String, isNot(contains(TEST_SECRET_CONTENT)));
      }, skip: _linuxOnly);

      test(
        'should allow reading a file in an allowWithinDeny subdirectory',
        () async {
          final readConfig = FsReadRestrictionConfig(
            denyOnly: [TEST_DENIED_DIR],
            allowWithinDeny: [TEST_ALLOWED_SUBDIR],
          );

          final wrappedCommand = await wrapCommandWithSandboxLinux(
            LinuxSandboxParams(
              command: 'cat $TEST_ALLOWED_FILE',
              needsNetworkRestriction: false,
              readConfig: readConfig,
              writeConfig: null,
            ),
          );

          final result = spawnSync(wrappedCommand, [], {
            'shell': true,
            'encoding': 'utf8',
            'timeout': 5000,
          });

          expect(result.status, 0);
          expect(result.stdout as String, contains(TEST_ALLOWED_CONTENT));
        },
        skip: _linuxOnly,
      );

      test(
        'should still deny reading files outside the re-allowed subdirectory',
        () async {
          final readConfig = FsReadRestrictionConfig(
            denyOnly: [TEST_DENIED_DIR],
            allowWithinDeny: [TEST_ALLOWED_SUBDIR],
          );

          final wrappedCommand = await wrapCommandWithSandboxLinux(
            LinuxSandboxParams(
              command: 'cat $TEST_SECRET_FILE',
              needsNetworkRestriction: false,
              readConfig: readConfig,
              writeConfig: null,
            ),
          );

          final result = spawnSync(wrappedCommand, [], {
            'shell': true,
            'encoding': 'utf8',
            'timeout': 5000,
          });

          expect(result.status, isNot(0));
          expect(result.stdout as String, isNot(contains(TEST_SECRET_CONTENT)));
        },
        skip: _linuxOnly,
      );

      // Regression: the write-path skip check in the allowRead re-bind loop was
      // too broad — it skipped any allowPath under ANY allowWrite, not just
      // writes actually re-bound under this tmpfs. With allowWrite as an
      // ancestor of denyRead (not wiped, not re-bound), allowRead under it was
      // skipped and left sitting in the empty tmpfs.
      // Shape: allowWrite: [~], denyRead: [~/.ssh], allowRead: [~/.ssh/known_hosts].
      test(
        'should re-allow under denyRead when allowWrite is an ancestor of the deny',
        () async {
          final wrappedCommand = await wrapCommandWithSandboxLinux(
            LinuxSandboxParams(
              command: 'cat $TEST_ALLOWED_FILE',
              needsNetworkRestriction: false,
              readConfig: FsReadRestrictionConfig(
                denyOnly: [TEST_DENIED_DIR],
                allowWithinDeny: [TEST_ALLOWED_SUBDIR],
              ),
              writeConfig: FsWriteRestrictionConfig(
                allowOnly: [TEST_BASE_DIR], // ancestor of denyRead
                denyWithinAllow: [],
              ),
            ),
          );

          final result = spawnSync(wrappedCommand, [], {
            'shell': true,
            'encoding': 'utf8',
            'timeout': 5000,
          });

          expect(result.status, 0);
          expect(result.stdout as String, contains(TEST_ALLOWED_CONTENT));
        },
        skip: _linuxOnly,
      );
    });
  });

  /**
   * Regression: denyRead: ['/'] + allowRead: [<project>] used to deny everything.
   *
   * macOS: (subpath "/") denies the root inode; no allowWithinDeny subpath covers
   *   "/", so dyld SIGABRTs before exec. Fix emits (allow file-read* (literal "/")).
   * Linux: --tmpfs / wiped all prior mounts, and the carve-out prefix check
   *   startsWith('/' + '/') never matched. Fix expands '/' into its children.
   *
   * Test dir lives under $HOME (not tmpdir) so the macOS /tmp → /private/tmp
   * symlink doesn't confuse Seatbelt path matching.
   */
  group('allowRead carve-out with denyRead at filesystem root (issue #10)', () {
    final TEST_DIR = join(
      homedir(),
      '.sandbox-runtime-test-root-deny-${DateTime.now().millisecondsSinceEpoch}',
    );
    final TEST_FILE = join(TEST_DIR, 'visible.txt');
    const TEST_CONTENT = 'ROOT_CARVE_OUT';
    // Paths needed for sh/cat to load at all when the whole filesystem is denied.
    // /private covers /tmp and /var (macOS symlinks). /lib* for Linux ld.so.
    const EXEC_DEPS = [
      '/bin',
      '/usr',
      '/lib',
      '/lib64',
      '/System',
      '/private',
      '/dev',
      '/etc',
    ];

    setUpAll(() {
      if (!isSupportedPlatform) return;
      mkdirSync(TEST_DIR, {'recursive': true});
      writeFileSync(TEST_FILE, TEST_CONTENT);
    });

    tearDownAll(() {
      if (existsSync(TEST_DIR)) {
        rmSync(TEST_DIR, {'recursive': true, 'force': true});
      }
    });

    test('macOS: re-allows carve-out under a root-level deny', () {
      final readConfig = FsReadRestrictionConfig(
        denyOnly: ['/'],
        allowWithinDeny: [TEST_DIR, ...EXEC_DEPS],
      );

      // EXEC_DEPS covers /bin and /usr but not /opt/homebrew — pin the shell
      // so denying the filesystem root doesn't break execvp on Homebrew-bash Macs.
      final wrappedCommand = wrapCommandWithSandboxMacOS(
        MacOSSandboxParams(
          command: 'cat $TEST_FILE',
          needsNetworkRestriction: false,
          readConfig: readConfig,
          writeConfig: null,
          binShell: '/bin/bash',
        ),
      );

      final result = spawnSync(wrappedCommand, [], {
        'shell': true,
        'encoding': 'utf8',
        'timeout': 5000,
      });

      expect(result.status, 0);
      expect(result.stdout as String, contains(TEST_CONTENT));
    }, skip: _macOnly);

    test(
      'macOS: still denies paths outside the carve-out under a root-level deny',
      () {
        final outside = join(homedir(), '.bashrc');
        final readConfig = FsReadRestrictionConfig(
          denyOnly: ['/'],
          allowWithinDeny: [TEST_DIR, ...EXEC_DEPS],
        );

        final wrappedCommand = wrapCommandWithSandboxMacOS(
          MacOSSandboxParams(
            command: 'cat $outside 2>/dev/null; true',
            needsNetworkRestriction: false,
            readConfig: readConfig,
            writeConfig: null,
            binShell: '/bin/bash',
          ),
        );

        final result = spawnSync(wrappedCommand, [], {
          'shell': true,
          'encoding': 'utf8',
          'timeout': 5000,
        });

        // Process must exec (no SIGABRT) and stdout must be empty (cat denied)
        expect(result.status, 0);
        expect(result.stdout, '');
      },
      skip: _macOnly,
    );

    test('Linux: re-allows carve-out under a root-level deny', () async {
      final readConfig = FsReadRestrictionConfig(
        denyOnly: ['/'],
        allowWithinDeny: [TEST_DIR, ...EXEC_DEPS],
      );

      // allowAllUnixSockets: true bypasses the seccomp path — otherwise the
      // apply-seccomp binary under <repo>/vendor/ is hidden by the root deny.
      final wrappedCommand = await wrapCommandWithSandboxLinux(
        LinuxSandboxParams(
          command: 'cat $TEST_FILE',
          needsNetworkRestriction: false,
          readConfig: readConfig,
          writeConfig: null,
          allowAllUnixSockets: true,
        ),
      );

      final result = spawnSync(wrappedCommand, [], {
        'shell': true,
        'encoding': 'utf8',
        'timeout': 5000,
      });

      expect(result.status, 0);
      expect(result.stdout as String, contains(TEST_CONTENT));
    }, skip: _linuxOnly);

    test(
      'Linux: still denies paths outside the carve-out under a root-level deny',
      () async {
        final outside = join(homedir(), '.bashrc');
        final readConfig = FsReadRestrictionConfig(
          denyOnly: ['/'],
          allowWithinDeny: [TEST_DIR, ...EXEC_DEPS],
        );

        final wrappedCommand = await wrapCommandWithSandboxLinux(
          LinuxSandboxParams(
            command: 'cat $outside 2>/dev/null; true',
            needsNetworkRestriction: false,
            readConfig: readConfig,
            writeConfig: null,
            allowAllUnixSockets: true,
          ),
        );

        final result = spawnSync(wrappedCommand, [], {
          'shell': true,
          'encoding': 'utf8',
          'timeout': 5000,
        });

        expect(result.status, 0);
        expect(result.stdout, '');
      },
      skip: _linuxOnly,
    );

    test(
      'Linux: preserves write binds when denyRead ancestor wipes them',
      () async {
        final writeTarget = join(TEST_DIR, 'written.txt');
        final wrappedCommand = await wrapCommandWithSandboxLinux(
          LinuxSandboxParams(
            command: 'echo WRITE_OK > $writeTarget && cat $writeTarget',
            needsNetworkRestriction: false,
            readConfig: FsReadRestrictionConfig(
              denyOnly: ['/'],
              allowWithinDeny: [...EXEC_DEPS],
            ),
            writeConfig: FsWriteRestrictionConfig(
              allowOnly: [TEST_DIR],
              denyWithinAllow: [],
            ),
            allowAllUnixSockets: true,
          ),
        );

        final result = spawnSync(wrappedCommand, [], {
          'shell': true,
          'encoding': 'utf8',
          'timeout': 5000,
        });

        expect(result.status, 0);
        expect(result.stdout as String, contains('WRITE_OK'));
      },
      skip: _linuxOnly,
    );
  });

  /**
   * Tests that allowRead-only configs (no denyRead) do not trigger sandbox overhead.
   */
  group('allowRead without denyRead does not trigger sandboxing', () {
    const command = 'echo hello';

    test(
      'returns command unchanged on macOS when only allowWithinDeny is set',
      () {
        final result = wrapCommandWithSandboxMacOS(
          MacOSSandboxParams(
            command: command,
            needsNetworkRestriction: false,
            readConfig: FsReadRestrictionConfig(
              denyOnly: [],
              allowWithinDeny: ['/some/path'],
            ),
            writeConfig: null,
          ),
        );

        expect(result, command);
      },
      skip: _macOnly,
    );

    test(
      'returns command unchanged on Linux when only allowWithinDeny is set',
      () async {
        final result = await wrapCommandWithSandboxLinux(
          LinuxSandboxParams(
            command: command,
            needsNetworkRestriction: false,
            readConfig: FsReadRestrictionConfig(
              denyOnly: [],
              allowWithinDeny: ['/some/path'],
            ),
            writeConfig: null,
          ),
        );

        expect(result, command);
      },
      skip: _linuxOnly,
    );
  });

  // A literal denyRead path nested under a literal allowRead subpath must keep
  // its deny: Seatbelt is last-match-wins, so the deny is re-emitted after the
  // allow. (Glob denies are re-emitted too — see macos-glob-deny-reemit.test.ts
  // for the profile text and 'macOS glob denyRead inside allowRead' below for
  // enforcement.)
  group('macOS denyRead nested under allowRead', skip: _macOnly, () {
    test('re-emits the deny after the allow so it stays denied', () {
      final result = wrapCommandWithSandboxMacOS(
        MacOSSandboxParams(
          command: 'cat /work/secrets/key',
          needsNetworkRestriction: false,
          readConfig: FsReadRestrictionConfig(
            denyOnly: ['/work/secrets'],
            allowWithinDeny: ['/work'],
          ),
          writeConfig: null,
        ),
      );
      // The profile is embedded in a shell command, so quotes are escaped —
      // match on the unquoted skeleton.
      final allowAt = result.indexOf('(allow file-read*\n  (subpath');
      final lastDenySecrets = result.lastIndexOf('/work/secrets');
      final firstDenySecrets = result.indexOf('/work/secrets');
      expect(allowAt, greaterThan(-1));
      // The deny on /work/secrets appears both before and after the allow:
      // original emit, then re-emit after allowWithinDeny.
      expect(firstDenySecrets, lessThan(allowAt));
      expect(lastDenySecrets, greaterThan(allowAt));
    });
  });

  group('rm in allowWrite under denyRead ancestor (issue #171)', () {
    final TEST_BASE_DIR = join(
      tmpdir(),
      'rm-under-denyread-${DateTime.now().millisecondsSinceEpoch}',
    );
    final TEST_PROJECT_DIR = join(TEST_BASE_DIR, 'project');
    final TEST_OUTSIDE_DIR = join(TEST_BASE_DIR, 'outside');

    setUpAll(() {
      if (!isSupportedPlatform) return;

      mkdirSync(TEST_PROJECT_DIR, {'recursive': true});
      mkdirSync(TEST_OUTSIDE_DIR, {'recursive': true});
    });

    tearDownAll(() {
      if (existsSync(TEST_BASE_DIR)) {
        rmSync(TEST_BASE_DIR, {'recursive': true, 'force': true});
      }
    });

    group('macOS Seatbelt', () {
      // The read section's move-blocking rules emit a broad
      // (deny file-write-unlink (subpath <denyRead>)) that a specific
      // (allow file-write*) does not override. Without a re-allow for
      // file-write-unlink on allowWrite paths, rm fails even though
      // touch/write succeed.

      test(
        'should allow rm inside an allowWrite path under a denyRead ancestor',
        () {
          final targetFile = join(TEST_PROJECT_DIR, 'deleteme.txt');
          writeFileSync(targetFile, 'data');

          final readConfig = FsReadRestrictionConfig(
            denyOnly: [TEST_BASE_DIR],
            allowWithinDeny: [TEST_PROJECT_DIR],
          );
          final writeConfig = FsWriteRestrictionConfig(
            allowOnly: [TEST_PROJECT_DIR],
            denyWithinAllow: [],
          );

          final wrappedCommand = wrapCommandWithSandboxMacOS(
            MacOSSandboxParams(
              command: 'rm $targetFile',
              needsNetworkRestriction: false,
              readConfig: readConfig,
              writeConfig: writeConfig,
            ),
          );

          final result = spawnSync(wrappedCommand, [], {
            'shell': true,
            'encoding': 'utf8',
            'timeout': 5000,
          });

          expect(result.status, 0);
          expect(existsSync(targetFile), false);
        },
        skip: _macOnly,
      );

      test(
        'should still block rm outside allowWrite under the same denyRead ancestor',
        () {
          final protectedFile = join(TEST_OUTSIDE_DIR, 'protected.txt');
          writeFileSync(protectedFile, 'data');

          final readConfig = FsReadRestrictionConfig(
            denyOnly: [TEST_BASE_DIR],
            allowWithinDeny: [TEST_PROJECT_DIR],
          );
          final writeConfig = FsWriteRestrictionConfig(
            allowOnly: [TEST_PROJECT_DIR],
            denyWithinAllow: [],
          );

          final wrappedCommand = wrapCommandWithSandboxMacOS(
            MacOSSandboxParams(
              command: 'rm $protectedFile',
              needsNetworkRestriction: false,
              readConfig: readConfig,
              writeConfig: writeConfig,
            ),
          );

          final result = spawnSync(wrappedCommand, [], {
            'shell': true,
            'encoding': 'utf8',
            'timeout': 5000,
          });

          expect(result.status, isNot(0));
          expect(existsSync(protectedFile), true);
        },
        skip: _macOnly,
      );

      test(
        'should still block rm of denyWithinAllow paths despite the re-allow',
        () {
          // The re-allow of file-write-unlink for allowWrite paths is emitted in
          // the read section. The write section's own move-blocking rules for
          // denyWithinAllow are emitted later and must win (last-match).
          final protectedDir = join(TEST_PROJECT_DIR, 'protected');
          final protectedFile = join(protectedDir, 'keep.txt');
          mkdirSync(protectedDir, {'recursive': true});
          writeFileSync(protectedFile, 'data');

          final readConfig = FsReadRestrictionConfig(
            denyOnly: [TEST_BASE_DIR],
            allowWithinDeny: [TEST_PROJECT_DIR],
          );
          final writeConfig = FsWriteRestrictionConfig(
            allowOnly: [TEST_PROJECT_DIR],
            denyWithinAllow: [protectedDir],
          );

          final wrappedCommand = wrapCommandWithSandboxMacOS(
            MacOSSandboxParams(
              command: 'rm $protectedFile',
              needsNetworkRestriction: false,
              readConfig: readConfig,
              writeConfig: writeConfig,
            ),
          );

          final result = spawnSync(wrappedCommand, [], {
            'shell': true,
            'encoding': 'utf8',
            'timeout': 5000,
          });

          expect(result.status, isNot(0));
          expect(existsSync(protectedFile), true);
        },
        skip: _macOnly,
      );
    });

    group('Linux bwrap', () {
      // #190 fixed the Linux analogue by re-binding allowWrite paths after
      // the denyRead tmpfs wipes them. Verify rm works end-to-end.

      test(
        'should allow rm inside an allowWrite path under a denyRead ancestor',
        () async {
          final targetFile = join(TEST_PROJECT_DIR, 'deleteme-linux.txt');
          writeFileSync(targetFile, 'data');

          final readConfig = FsReadRestrictionConfig(
            denyOnly: [TEST_BASE_DIR],
            allowWithinDeny: [TEST_PROJECT_DIR],
          );
          final writeConfig = FsWriteRestrictionConfig(
            allowOnly: [TEST_PROJECT_DIR],
            denyWithinAllow: [],
          );

          final wrappedCommand = await wrapCommandWithSandboxLinux(
            LinuxSandboxParams(
              command: 'rm $targetFile',
              needsNetworkRestriction: false,
              readConfig: readConfig,
              writeConfig: writeConfig,
            ),
          );

          final result = spawnSync(wrappedCommand, [], {
            'shell': true,
            'encoding': 'utf8',
            'timeout': 5000,
          });

          expect(result.status, 0);
          expect(existsSync(targetFile), false);
        },
        skip: _linuxOnly,
      );
    });
  });

  /**
   * Glob denyRead entries inside an allowRead region (the common shape is
   * denyRead: ["**\/.env"], allowRead: ["."]).
   *
   * Seatbelt is last-match-wins. The profile used to emit the glob denies,
   * then the allowRead allows, and re-emit only LITERAL denies afterwards —
   * so every glob deny landing inside an allowRead directory was silently
   * re-allowed. It now re-emits glob denies too (minus the allow entries the
   * glob itself covers), renders glob denies to cover the matched subtree,
   * and re-denies unlink of read-denied paths inside write roots so `mv`
   * can't carry them to a name the deny doesn't match. All of these run the
   * real profile under sandbox-exec.
   *
   * Config paths are built from the raw tmpdir() spelling (/var/folders/… on
   * macOS) while the commands use the realpath'd one (/private/var/…): the
   * glob's static prefix has to survive normalizePathForSandbox's realpath
   * for any of this to match.
   */
  group('macOS glob denyRead inside allowRead (deny wins)', skip: _macOnly, () {
    final NAME = 'glob-deny-reemit-${DateTime.now().millisecondsSinceEpoch}';
    final RAW_BASE = join(tmpdir(), NAME);
    final RAW_PROJECT = join(RAW_BASE, 'project');
    var BASE = '';
    var PROJECT = '';

    final SECRET = 'GLOB_DENY_SECRET_${DateTime.now().millisecondsSinceEpoch}';
    const PLAIN = 'PLAIN_CONTENT_OK';

    /**
     * Whether the volume holding the tree folds case in file names. Decided
     * while the block is collected, so the `.ENV` spelling below is skipped
     * where it cannot resolve rather than passing for the wrong reason.
     */
    final volumeFoldsCase = (() {
      final probeDir = join(
        tmpdir(),
        'case-fold-probe-${DateTime.now().millisecondsSinceEpoch}',
      );
      try {
        mkdirSync(probeDir, {'recursive': true});
        writeFileSync(join(probeDir, 'probe'), 'x');
        return existsSync(join(probeDir, 'PROBE'));
      } finally {
        rmSync(probeDir, {'recursive': true, 'force': true});
      }
    })();

    /** Second spelling of the data volume; absent before macOS 10.15. */
    const DATA_FIRMLINK = '/System/Volumes/Data';

    final TREE = <String, String>{
      '.env': SECRET,
      'sub/.env': SECRET,
      'secrets/key': SECRET,
      'secrets/deep/nested.txt': SECRET,
      'certs/a.key': SECRET,
      'conf/ok.pem': PLAIN,
      'conf/bad.pem': SECRET,
      'plain.txt': PLAIN,
      'deleteme.txt': 'x',
      'other/.keep': 'x',
    };

    void resetTree() {
      rmSync(RAW_BASE, {'recursive': true, 'force': true});
      mkdirSync(RAW_PROJECT, {'recursive': true});
      BASE = realpathSync(RAW_BASE);
      PROJECT = join(BASE, 'project');
      for (final MapEntry(key: rel, value: content) in TREE.entries) {
        final abs = join(PROJECT, rel);
        mkdirSync(join(abs, '..'), {'recursive': true});
        writeFileSync(abs, content);
      }
      writeFileSync(join(BASE, 'outside.txt'), SECRET);
    }

    setUpAll(resetTree);
    tearDownAll(() {
      rmSync(RAW_BASE, {'recursive': true, 'force': true});
    });

    FsReadRestrictionConfig PROJECT_READ() => FsReadRestrictionConfig(
      denyOnly: [
        join(RAW_PROJECT, '**', '.env'),
        // What `<project>/**/secrets/**` becomes after sandbox-manager strips
        // the trailing `/**`.
        join(RAW_PROJECT, '**', 'secrets'),
        // Root-anchored, as a credentials.files-style deny would be.
        '/**/*.key',
      ],
      allowWithinDeny: [RAW_PROJECT],
    );
    FsWriteRestrictionConfig PROJECT_WRITE() =>
        FsWriteRestrictionConfig(allowOnly: [RAW_PROJECT], denyWithinAllow: []);

    ({int? status, String stdout, String stderr}) run(
      String command,
      FsReadRestrictionConfig readConfig, [
      FsWriteRestrictionConfig? writeConfig,
    ]) {
      final wrapped = wrapCommandWithSandboxMacOS(
        MacOSSandboxParams(
          command: command,
          needsNetworkRestriction: false,
          readConfig: readConfig,
          writeConfig: writeConfig,
        ),
      );
      final r = spawnSync(wrapped, [], {
        'shell': true,
        'encoding': 'utf8',
        'timeout': 10000,
      });
      expect(r.error, isNull);
      return (
        status: r.status,
        stdout: r.stdout as String,
        stderr: r.stderr as String,
      );
    }

    group('reads are denied', () {
      for (final (label, rel) in <(String, String)>[
        ('.env at the project root', '.env'),
        ('.env in a subdirectory', 'sub/.env'),
        ('a file directly inside a **/secrets match', 'secrets/key'),
        ('a file deeper inside a **/secrets match', 'secrets/deep/nested.txt'),
        (
          'a root-anchored /**/*.key match inside the allowRead dir',
          'certs/a.key',
        ),
      ]) {
        test('cat: $label', () {
          final r = run('cat ${join(PROJECT, rel)}', PROJECT_READ());
          expect(r.status, isNot(0));
          expect(r.stdout, isNot(contains(SECRET)));
        });
      }

      test(
        'stat is denied too (file-read-metadata is only re-allowed for directories)',
        () {
          final r = run('stat ${join(PROJECT, '.env')}', PROJECT_READ());
          expect(r.status, isNot(0));
        },
      );

      test(
        'a non-matching file in the same allowRead dir is still readable',
        () {
          final r = run('cat ${join(PROJECT, 'plain.txt')}', PROJECT_READ());
          expect(r.status, 0);
          expect(r.stdout, contains(PLAIN));
        },
      );

      test(
        'a credentials-style *.pem glob denies siblings of an allowed file',
        () {
          // credentials.files {mode: 'deny'} entries are unioned into denyOnly
          // upstream, so this is the same shape they take by the time the
          // profile is built. ok.pem is a specific file allow the glob covers,
          // so it is carved out of the re-emitted deny; bad.pem is not.
          final readConfig = FsReadRestrictionConfig(
            denyOnly: [join(RAW_PROJECT, 'conf', '*.pem')],
            allowWithinDeny: [RAW_PROJECT, join(RAW_PROJECT, 'conf', 'ok.pem')],
          );
          final ok = run('cat ${join(PROJECT, 'conf/ok.pem')}', readConfig);
          expect(ok.status, 0);
          expect(ok.stdout, contains(PLAIN));
          final bad = run('cat ${join(PROJECT, 'conf/bad.pem')}', readConfig);
          expect(bad.status, isNot(0));
          expect(bad.stdout, isNot(contains(SECRET)));
        },
      );

      test(
        'keeps the tlsTerminate trust bundle readable under a /**/*.crt deny',
        () async {
          // sandbox-manager pushes certPath + trustBundlePath into
          // allowWithinDeny. The bundle is a specific file the glob covers, so
          // the re-emitted deny carves it out — without an allow after the
          // denies. A .crt the user did NOT allow stays denied.
          final ca = createMitmCA();
          final userCrt = join(PROJECT, 'conf', 'user.crt');
          writeFileSync(userCrt, SECRET);
          try {
            final readConfig = FsReadRestrictionConfig(
              denyOnly: ['/**/*.crt'],
              allowWithinDeny: [RAW_PROJECT, ca.certPath, ca.trustBundlePath],
            );
            final bundle = run('head -c 27 ${ca.trustBundlePath}', readConfig);
            expect(bundle.status, 0);
            expect(bundle.stdout, '-----BEGIN CERTIFICATE-----');
            final denied = run('cat $userCrt', readConfig);
            expect(denied.status, isNot(0));
            expect(denied.stdout, isNot(contains(SECRET)));
          } finally {
            await disposeMitmCA(ca);
          }
        },
      );
    });

    group('rename cannot carry a denied path to an unmatched name', () {
      setUpAll(resetTree);

      for (final (label, src, dst, probe) in <(String, String, String, String)>[
        ('glob-matched file (**/.env)', '.env', 'moved.txt', 'moved.txt'),
        ('glob-matched dir (**/secrets)', 'secrets', 's2', 's2/key'),
      ]) {
        test('$label: mv fails and the target stays unreadable', () {
          final r = run(
            'mv ${join(PROJECT, src)} ${join(PROJECT, dst)}; cat ${join(PROJECT, probe)}; true',
            PROJECT_READ(),
            PROJECT_WRITE(),
          );
          expect(r.stdout, isNot(contains(SECRET)));
          expect(existsSync(join(PROJECT, src)), true);
          expect(existsSync(join(PROJECT, dst)), false);
        });
      }

      test('literal deny nested under allowRead: mv of the dir fails', () {
        final readConfig = FsReadRestrictionConfig(
          denyOnly: [join(RAW_PROJECT, 'secrets')],
          allowWithinDeny: [RAW_PROJECT],
        );
        final r = run(
          'mv ${join(PROJECT, 'secrets')} ${join(PROJECT, 's3')}; cat ${join(PROJECT, 's3/key')}; true',
          readConfig,
          PROJECT_WRITE(),
        );
        expect(r.stdout, isNot(contains(SECRET)));
        expect(existsSync(join(PROJECT, 'secrets')), true);
      });

      test(
        'literal deny with no allowRead at all: mv of the dir still fails',
        () {
          // The pre-existing bypass did not need allowRead: the write root's
          // unlink re-allow alone re-opened any deny sitting inside it.
          final readConfig = FsReadRestrictionConfig(
            denyOnly: [join(RAW_PROJECT, 'secrets')],
            allowWithinDeny: [],
          );
          final r = run(
            'mv ${join(PROJECT, 'secrets')} ${join(PROJECT, 's4')}; cat ${join(PROJECT, 's4/key')}; true',
            readConfig,
            PROJECT_WRITE(),
          );
          expect(r.stdout, isNot(contains(SECRET)));
          expect(existsSync(join(PROJECT, 'secrets')), true);
        },
      );

      test(
        'the enclosing directory of a deeper deny cannot be renamed either',
        () {
          final readConfig = FsReadRestrictionConfig(
            denyOnly: [join(RAW_PROJECT, 'secrets', 'deep', 'nested.txt')],
            allowWithinDeny: [RAW_PROJECT],
          );
          final r = run(
            'mv ${join(PROJECT, 'secrets')} ${join(PROJECT, 's5')}; cat ${join(PROJECT, 's5/deep/nested.txt')}; true',
            readConfig,
            PROJECT_WRITE(),
          );
          expect(r.stdout, isNot(contains(SECRET)));
          expect(existsSync(join(PROJECT, 'secrets/deep/nested.txt')), true);
        },
      );
    });

    group('everything else inside the write root still works', () {
      setUpAll(resetTree);

      test('rm of a non-denied file', () {
        final target = join(PROJECT, 'deleteme.txt');
        final r = run('rm $target', PROJECT_READ(), PROJECT_WRITE());
        expect(r.status, 0);
        expect(existsSync(target), false);
      });

      test(
        'creating a new file at a read-denied name (unlink is re-denied, create is not)',
        () {
          final target = join(PROJECT, 'other', '.env');
          final r = run(
            'echo fresh > $target',
            PROJECT_READ(),
            PROJECT_WRITE(),
          );
          expect(r.status, 0);
          expect(readFileSync(target, 'utf8'), 'fresh\n');
        },
      );

      test('rm inside an allowRead carve-out nested in a literal deny', () {
        // denyRead <project>/secrets, allowRead <project>/secrets/deep,
        // allowWrite <project>: the trailing unlink re-deny on secrets must
        // subtract deep, or rm there regresses the way #171 did. (The project
        // dir itself is deliberately not in allowRead: a literal deny nested
        // under a literal allow is re-emitted after ALL allows — pre-existing
        // behavior — which would make deep unreadable and rm's lstat fail
        // before unlink is ever attempted.)
        final target = join(PROJECT, 'secrets', 'deep', 'nested.txt');
        final readConfig = FsReadRestrictionConfig(
          denyOnly: [join(RAW_PROJECT, 'secrets')],
          allowWithinDeny: [join(RAW_PROJECT, 'secrets', 'deep')],
        );
        final r = run('rm $target', readConfig, PROJECT_WRITE());
        expect(r.status, 0);
        expect(existsSync(target), false);
      });
    });

    group('region-shaped globs keep working', () {
      setUpAll(resetTree);

      // These two are also the mechanism check for the re-emitted deny's
      // shape: (require-all (regex …) (require-not (subpath …))) and
      // (require-all (regex …) (require-not (regex …))) both have to compile
      // under sandbox-exec AND leave exactly the carved entry readable.
      test(
        '<base>/**/* deny + literal allowRead carve-out: carve-out readable, rest denied',
        () {
          final readConfig = FsReadRestrictionConfig(
            denyOnly: [join(RAW_BASE, '**', '*')],
            allowWithinDeny: [RAW_PROJECT],
          );
          final inside = run('cat ${join(PROJECT, 'plain.txt')}', readConfig);
          expect(inside.status, 0);
          expect(inside.stdout, contains(PLAIN));
          final outside = run('cat ${join(BASE, 'outside.txt')}', readConfig);
          expect(outside.status, isNot(0));
          expect(outside.stdout, isNot(contains(SECRET)));
        },
      );

      test(
        '<base>/**/* deny + glob allowRead carve-out: matching file readable, rest denied',
        () {
          // A glob allow matches paths exactly (no subtree), so it has to name
          // the file itself; the region deny is carved by that allow's regex.
          final readConfig = FsReadRestrictionConfig(
            denyOnly: [join(RAW_BASE, '**', '*')],
            allowWithinDeny: [join(RAW_PROJECT, '*.txt')],
          );
          final wrapped = wrapCommandWithSandboxMacOS(
            MacOSSandboxParams(
              command: 'true',
              needsNetworkRestriction: false,
              readConfig: readConfig,
              writeConfig: null,
            ),
          );
          expect(wrapped, contains('(require-not (regex '));
          final inside = run('cat ${join(PROJECT, 'plain.txt')}', readConfig);
          expect(inside.status, 0);
          expect(inside.stdout, contains(PLAIN));
          final sibling = run(
            'cat ${join(PROJECT, 'secrets', 'key')}',
            readConfig,
          );
          expect(sibling.status, isNot(0));
          expect(sibling.stdout, isNot(contains(SECRET)));
        },
      );

      test(
        'rm inside the carve-out of a region glob that also sits in a write root',
        () {
          final target = join(PROJECT, 'deleteme.txt');
          final readConfig = FsReadRestrictionConfig(
            denyOnly: [join(RAW_BASE, '**', '*')],
            allowWithinDeny: [RAW_PROJECT],
          );
          final r = run('rm $target', readConfig, PROJECT_WRITE());
          expect(r.status, 0);
          expect(existsSync(target), false);
        },
      );
    });

    /**
     * Spellings that reach a denied file by another name. The deny is written
     * against one path; each case pins whether the alias gets past it, so a
     * build that starts leaking through one of them fails here.
     */
    group('adjacent aliasing behaviors', () {
      setUpAll(resetTree);

      test('hard link to a denied file (ln .env x; cat x)', () {
        final link = join(PROJECT, 'hardlink.txt');
        final r = run(
          'ln ${join(PROJECT, '.env')} $link 2>&1 && echo LN_OK; cat $link 2>&1; true',
          PROJECT_READ(),
          PROJECT_WRITE(),
        );
        expect(r.stdout, isNot(contains('LN_OK')));
        expect(existsSync(link), false);
        expect(r.stdout, isNot(contains(SECRET)));
      });

      test('(deny file-link …) compiles and blocks ln', () {
        // The hard link above is closed by the read deny on the source. This
        // pins that Seatbelt here also takes file-link, so a deny-only rule
        // could close it at the link itself the way unlink is closed.
        final link = join(PROJECT, 'hardlink2.txt');
        final profile =
            '(version 1) (allow default) '
            '(deny file-link (subpath ${jsonEncode(PROJECT)}))';
        final r = spawnSync(
          '/usr/bin/sandbox-exec',
          [
            '-p',
            profile,
            '/bin/sh',
            '-c',
            'ln ${join(PROJECT, 'plain.txt')} $link',
          ],
          {'encoding': 'utf8', 'timeout': 10000},
        );
        expect(r.status, isNot(0));
        // `ln` names itself in the denial. A profile Seatbelt refused to
        // parse or apply fails the same command without ever reaching it,
        // and says so under its own name instead.
        expect(r.stderr as String, contains('ln:'));
        expect(r.stderr as String, contains('Operation not permitted'));
        expect(existsSync(link), false);
      });

      test('clonefile of a denied file (cp -c .env x; cat x)', () {
        final clone = join(PROJECT, 'clone.txt');
        final r = run(
          'cp -c ${join(PROJECT, '.env')} $clone 2>&1 && echo CP_OK; cat $clone 2>&1; true',
          PROJECT_READ(),
          PROJECT_WRITE(),
        );
        expect(r.stdout, isNot(contains('CP_OK')));
        expect(existsSync(clone), false);
        expect(r.stdout, isNot(contains(SECRET)));
      });

      test('case-folded spelling on a case-insensitive volume (cat .ENV)', () {
        final spelling = join(PROJECT, '.ENV');
        final probe = spawnSync(
          '/bin/sh',
          ['-c', 'cat $spelling'],
          {'encoding': 'utf8'},
        );
        // Unsandboxed, the spelling reaches the file: the deny is what
        // stops the sandboxed read below, not a missing path.
        expect(probe.stdout as String, contains(SECRET));
        final r = run('cat $spelling 2>&1; true', PROJECT_READ());
        expect(r.stdout, isNot(contains(SECRET)));
      }, skip: volumeFoldsCase ? null : 'volume does not fold case');

      test('firmlink spelling (/System/Volumes/Data<path>)', () {
        final alias = join(DATA_FIRMLINK, join(PROJECT, '.env'));
        expect(existsSync(alias), true);
        final r = run('cat $alias 2>&1; true', PROJECT_READ());
        expect(r.stdout, isNot(contains(SECRET)));
      }, skip: existsSync(DATA_FIRMLINK) ? null : 'no firmlink');
    });
  });

  // Dart: a block comment here would nest at its `/*`, so it is line comments.
  //* denyRead: ['/'] plus a `/*` glob. The re-emitted `/*` (rendered as a
  //* subtree regex) matches "/" itself, so the root re-allow that keeps dyld
  //* alive has to land after it — otherwise nothing execs. Same fixture shape
  //* as the issue #10 test above.
  group('macOS root deny alongside a /* glob deny', skip: _macOnly, () {
    final TEST_DIR = join(
      homedir(),
      '.sandbox-runtime-test-root-glob-${DateTime.now().millisecondsSinceEpoch}',
    );
    final TEST_FILE = join(TEST_DIR, 'visible.txt');
    // Sibling of TEST_DIR: under $HOME, outside every carve-out.
    final OUTSIDE_FILE = '$TEST_DIR-outside.txt';
    const EXEC_DEPS = ['/bin', '/usr', '/System', '/private', '/dev', '/etc'];

    setUpAll(() {
      mkdirSync(TEST_DIR, {'recursive': true});
      writeFileSync(TEST_FILE, 'ROOT_GLOB_VISIBLE');
      writeFileSync(OUTSIDE_FILE, 'ROOT_GLOB_OUTSIDE');
    });
    tearDownAll(() {
      rmSync(TEST_DIR, {'recursive': true, 'force': true});
      rmSync(OUTSIDE_FILE, {'force': true});
    });

    test('still execs, reads the carve-out, and denies the rest', () {
      final readConfig = FsReadRestrictionConfig(
        denyOnly: ['/', '/*'],
        allowWithinDeny: [TEST_DIR, ...EXEC_DEPS],
      );
      final wrapped = wrapCommandWithSandboxMacOS(
        MacOSSandboxParams(
          command:
              'echo ROOT_GLOB_EXEC_OK; cat $TEST_FILE; cat $OUTSIDE_FILE 2>/dev/null; true',
          needsNetworkRestriction: false,
          readConfig: readConfig,
          writeConfig: null,
          binShell: '/bin/bash',
        ),
      );
      final r = spawnSync(wrapped, [], {
        'shell': true,
        'encoding': 'utf8',
        'timeout': 10000,
      });
      expect(r.status, 0);
      expect(r.stdout as String, contains('ROOT_GLOB_EXEC_OK'));
      expect(r.stdout as String, contains('ROOT_GLOB_VISIBLE'));
      expect(r.stdout as String, isNot(contains('ROOT_GLOB_OUTSIDE')));
    });
  });
}
