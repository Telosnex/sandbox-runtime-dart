// Ported from sandbox-runtime test/sandbox/credential-deny.test.ts @ 0bbebed.
// ignore_for_file: constant_identifier_names, non_constant_identifier_names, slash_for_doc_comments, prefer_interpolation_to_compose_strings
import 'dart:convert' show jsonEncode;

import 'package:path/path.dart' show join;
import 'package:sandbox_runtime/src/node/child_process.dart'
    show SpawnSyncResult, spawnSync;
import 'package:sandbox_runtime/src/node/fs.dart'
    show existsSync, mkdirSync, rmSync, symlinkSync, writeFileSync;
import 'package:sandbox_runtime/src/node/os.dart' show tmpdir;
import 'package:sandbox_runtime/src/node/process.dart' as process;
import 'package:sandbox_runtime/src/sandbox/macos_sandbox_utils.dart';
import 'package:sandbox_runtime/src/sandbox/sandbox_config.dart';
import 'package:sandbox_runtime/src/sandbox/sandbox_manager.dart';
import 'package:sandbox_runtime/src/sandbox/sandbox_schemas.dart';
import 'package:sandbox_runtime/src/sandbox/sandbox_utils.dart'
    show normalizePathForSandbox;
import 'package:sandbox_runtime/src/utils/config_loader.dart';
import 'package:test/test.dart';

import '../helpers/platform.dart' show isLinux, isMacOS, isSupportedPlatform;

/**
 * Tests for the `credentials` config section (mode: deny).
 *
 * File entries with mode: deny are unioned into the read-deny set; env var
 * entries with mode: deny are unset inside the sandbox. Only explicitly
 * declared sources are restricted — the block applies no implicit defaults.
 */

SandboxRuntimeConfig baseConfig([
  PartialSandboxRuntimeConfig overrides = const PartialSandboxRuntimeConfig(),
]) {
  return SandboxRuntimeConfig(
    network:
        overrides.network ??
        NetworkConfig(allowedDomains: [], deniedDomains: []),
    filesystem:
        overrides.filesystem ??
        FilesystemConfig(
          denyRead: [],
          allowWrite: [const FilesystemPathSpelling('/tmp')],
          denyWrite: [],
        ),
    credentials: overrides.credentials,
  );
}

void main() {
  group(
    'credential read-deny normalization (getFsReadConfig)',
    skip: isSupportedPlatform ? null : 'unsupported platform',
    () {
      tearDownAll(() async {
        await SandboxManager.reset();
      });

      test(
        'applies only caller-supplied denyRead without a credentials block',
        () async {
          await SandboxManager.reset();
          await SandboxManager.initialize(
            baseConfig(
              PartialSandboxRuntimeConfig(
                filesystem: FilesystemConfig(
                  denyRead: [const FilesystemPathSpelling('/some/secret')],
                  allowWrite: [const FilesystemPathSpelling('/tmp')],
                  denyWrite: [],
                ),
              ),
            ),
          );

          final readConfig = SandboxManager.getFsReadConfig();
          expect(readConfig.denyOnly, ['/some/secret']);

          await SandboxManager.reset();
        },
      );

      test('denies nothing beyond the declared entries', () async {
        await SandboxManager.reset();
        // Only an env var deny is declared — no implicit file read-denies
        // (e.g. ~/.netrc) may appear.
        await SandboxManager.initialize(
          baseConfig(
            PartialSandboxRuntimeConfig(
              credentials: CredentialsConfig(
                envVars: [
                  CredentialEnvVarConfig(name: 'GH_TOKEN', mode: 'deny'),
                ],
              ),
            ),
          ),
        );

        final readConfig = SandboxManager.getFsReadConfig();
        expect(readConfig.denyOnly, []);

        await SandboxManager.reset();
      });

      test(
        'unions credential deny entries with caller-supplied denyRead',
        () async {
          await SandboxManager.reset();
          await SandboxManager.initialize(
            baseConfig(
              PartialSandboxRuntimeConfig(
                filesystem: FilesystemConfig(
                  denyRead: [const FilesystemPathSpelling('/some/secret')],
                  allowWrite: [const FilesystemPathSpelling('/tmp')],
                  denyWrite: [],
                ),
                credentials: CredentialsConfig(
                  files: [
                    CredentialFileConfig(
                      path: '~/.config/gcloud',
                      mode: 'deny',
                    ),
                  ],
                ),
              ),
            ),
          );

          final readConfig = SandboxManager.getFsReadConfig();
          // Caller denyRead survives and the credential deny entry is added
          expect(readConfig.denyOnly, contains('/some/secret'));
          expect(readConfig.denyOnly, contains('~/.config/gcloud'));

          await SandboxManager.reset();
        },
      );

      test(
        'feeds credential deny paths into the macOS profile as file-read denies',
        () async {
          await SandboxManager.reset();
          await SandboxManager.initialize(
            baseConfig(
              PartialSandboxRuntimeConfig(
                credentials: CredentialsConfig(
                  files: [CredentialFileConfig(path: '~/.netrc', mode: 'deny')],
                ),
              ),
            ),
          );

          // Profile generation is pure string construction, so it can be
          // exercised on any platform even though sandbox-exec only runs on macOS.
          final wrapped = wrapCommandWithSandboxMacOS(
            MacOSSandboxParams(
              command: 'true',
              needsNetworkRestriction: false,
              readConfig: SandboxManager.getFsReadConfig(),
              writeConfig: null,
            ),
          );

          expect(wrapped, contains('deny file-read*'));
          expect(wrapped, contains('.netrc'));

          await SandboxManager.reset();
        },
      );
    },
  );

  group('macOS env -u preamble generation', () {
    test('emits env -u flags before sandbox-exec for denied env vars', () {
      final wrapped = wrapCommandWithSandboxMacOS(
        MacOSSandboxParams(
          command: 'true',
          needsNetworkRestriction: false,
          readConfig: null,
          writeConfig: FsWriteRestrictionConfig(
            allowOnly: ['/tmp'],
            denyWithinAllow: [],
          ),
          unsetEnvVars: ['GH_TOKEN', 'AWS_SECRET_ACCESS_KEY'],
        ),
      );

      expect(
        wrapped.startsWith('env -u GH_TOKEN -u AWS_SECRET_ACCESS_KEY '),
        true,
      );
      // The -u flags must precede the VAR=VALUE assignments and sandbox-exec.
      expect(
        wrapped.indexOf('-u GH_TOKEN'),
        lessThan(wrapped.indexOf('SANDBOX_RUNTIME')),
      );
      expect(
        wrapped.indexOf('-u GH_TOKEN'),
        lessThan(wrapped.indexOf('sandbox-exec')),
      );
    });

    test('still sandboxes when env unsets are the only restriction', () {
      const command = 'echo hello';
      final wrapped = wrapCommandWithSandboxMacOS(
        MacOSSandboxParams(
          command: command,
          needsNetworkRestriction: false,
          readConfig: null,
          writeConfig: null,
          unsetEnvVars: ['GH_TOKEN'],
        ),
      );

      expect(wrapped, isNot(command));
      expect(wrapped, contains('env -u GH_TOKEN'));
    });

    test('emits no -u flags when no env vars are denied', () {
      final wrapped = wrapCommandWithSandboxMacOS(
        MacOSSandboxParams(
          command: 'true',
          needsNetworkRestriction: false,
          readConfig: null,
          writeConfig: FsWriteRestrictionConfig(
            allowOnly: ['/tmp'],
            denyWithinAllow: [],
          ),
          unsetEnvVars: [],
        ),
      );

      expect(wrapped, isNot(contains(' -u ')));
    });
  });

  /**
   * Drive the same pipeline the CLI uses on macOS — settings file → loadConfig →
   * SandboxManager.initialize → wrapWithSandbox — with process.platform forced
   * to 'darwin' so the macOS branch is exercised on Linux CI too. Asserts the
   * credential restrictions actually reach the final wrapped command.
   */
  group(
    'macOS wrapped command via the manager (settings-file config)',
    skip: isSupportedPlatform ? null : 'unsupported platform',
    () {
      final TEST_DIR = join(
        tmpdir(),
        'credential-deny-darwin-${DateTime.now().millisecondsSinceEpoch}',
      );
      final SECRET_FILE = join(TEST_DIR, 'secret-token.txt');
      final SETTINGS_FILE = join(TEST_DIR, 'credentials.json');
      // Dart: the saved descriptor is the platform override, null for none.
      String? platformDescriptor;

      String escapeRegExp(String s) =>
          s.replaceAllMapped(RegExp(r'[.*+?^${}()|[\]\\]'), (m) => '\\${m[0]}');
      // Matches (subpath "<path>") as any of the filters listed under a
      // (deny file-read* …) rule. The profile is embedded byte-literal inside
      // a single-quoted argument, so the inner quotes appear exactly as
      // written (never backslash-escaped).
      RegExp denyReadRule(String p) => RegExp(
        r'\(deny file-read\*(\n  \([^\n]*\))*\n  \(subpath "' +
            escapeRegExp(p) +
            '"',
      );

      setUpAll(() async {
        mkdirSync(TEST_DIR, {'recursive': true});
        writeFileSync(SECRET_FILE, 'token-abc\n');
        writeFileSync(
          SETTINGS_FILE,
          '{"network":{"allowedDomains":[],"deniedDomains":[]},'
          '"filesystem":{"denyRead":[],"allowWrite":["."],"denyWrite":[]},'
          '"credentials":{'
          '"files":[{"path":${_json(SECRET_FILE)},"mode":"deny"}],'
          '"envVars":[{"name":"MY_API_TOKEN","mode":"deny"}]}}',
        );

        platformDescriptor = process.platform;
        process.setPlatformForTesting('darwin');

        final loaded = loadConfig(SETTINGS_FILE);
        if (loaded.kind != 'ok') {
          throw Exception(
            'Settings file failed to load (${loaded.kind}): $SETTINGS_FILE',
          );
        }
        await SandboxManager.reset();
        await SandboxManager.initialize((loaded as LoadConfigResultOk).config);
      });

      tearDownAll(() async {
        await SandboxManager.reset();
        if (platformDescriptor != null) {
          process.setPlatformForTesting(null);
        }
        if (existsSync(TEST_DIR)) {
          rmSync(TEST_DIR, {'recursive': true, 'force': true});
        }
      });

      test(
        'unsets the denied env var before assignments and sandbox-exec',
        () async {
          final wrapped = await SandboxManager.wrapWithSandbox(
            'printenv MY_API_TOKEN',
          );

          expect(wrapped.startsWith('env -u MY_API_TOKEN '), true);
          // -u must precede the first NAME=VALUE assignment and sandbox-exec so
          // BSD env still treats it as an option.
          expect(
            wrapped.indexOf('-u MY_API_TOKEN'),
            lessThan(wrapped.indexOf('SANDBOX_RUNTIME')),
          );
          expect(
            wrapped.indexOf('-u MY_API_TOKEN'),
            lessThan(wrapped.indexOf('sandbox-exec')),
          );
        },
      );

      test(
        'denies reads of the declared credential file in the profile',
        () async {
          final wrapped = await SandboxManager.wrapWithSandbox(
            'cat $SECRET_FILE',
          );

          expect(wrapped, contains('sandbox-exec'));
          expect(
            wrapped,
            matches(denyReadRule(normalizePathForSandbox(SECRET_FILE))),
          );
          // No implicit denies: undeclared credential paths stay out of the profile.
          expect(
            wrapped,
            isNot(matches(denyReadRule(normalizePathForSandbox('~/.netrc')))),
          );
        },
      );
    },
  );

  /**
   * macOS end-to-end: actually run sandbox-exec with a settings-file config and
   * verify the credential deny rules hold at runtime. Skipped on Linux; runs on
   * the macOS CI legs.
   */
  group(
    'credential deny on macOS (sandbox-exec)',
    skip: isMacOS ? null : 'macOS only',
    () {
      final TEST_DIR = join(
        tmpdir(),
        'credential-deny-macos-${DateTime.now().millisecondsSinceEpoch}',
      );
      final SECRET_FILE = join(TEST_DIR, 'secret-token.txt');
      final CONTROL_FILE = join(TEST_DIR, 'control.txt');
      final SETTINGS_FILE = join(TEST_DIR, 'credentials.json');
      const DENIED_ENV_VAR = 'SRT_TEST_SECRET_TOKEN';
      const ALLOWED_ENV_VAR = 'SRT_TEST_VISIBLE_VALUE';

      // process.env mutations don't reach children spawned by bun without an
      // explicit env option, so the credential vars are passed per-spawn instead.
      final childEnv = {
        ...process.env,
        DENIED_ENV_VAR: 'super-secret-value',
        ALLOWED_ENV_VAR: 'visible-value',
      };

      SpawnSyncResult runInSandbox(String wrappedCommand) {
        return spawnSync(wrappedCommand, [], {
          'shell': true,
          'encoding': 'utf8',
          'timeout': 10000,
          'env': childEnv,
        });
      }

      setUpAll(() async {
        mkdirSync(TEST_DIR, {'recursive': true});
        writeFileSync(SECRET_FILE, 'token-abc\n');
        writeFileSync(CONTROL_FILE, 'control-ok\n');
        writeFileSync(
          SETTINGS_FILE,
          '{"network":{"allowedDomains":[],"deniedDomains":[]},'
          '"filesystem":{"denyRead":[],'
          '"allowWrite":[${_json(TEST_DIR)},"/tmp"],"denyWrite":[]},'
          '"credentials":{'
          '"files":[{"path":${_json(SECRET_FILE)},"mode":"deny"}],'
          '"envVars":[{"name":"$DENIED_ENV_VAR","mode":"deny"}]}}',
        );

        final loaded = loadConfig(SETTINGS_FILE);
        if (loaded.kind != 'ok') {
          throw Exception(
            'Settings file failed to load (${loaded.kind}): $SETTINGS_FILE',
          );
        }
        await SandboxManager.reset();
        await SandboxManager.initialize((loaded as LoadConfigResultOk).config);
      });

      tearDownAll(() async {
        await SandboxManager.reset();
        if (existsSync(TEST_DIR)) {
          rmSync(TEST_DIR, {'recursive': true, 'force': true});
        }
      });

      test('a denied env var is absent inside the sandbox', () async {
        final wrapped = await SandboxManager.wrapWithSandbox(
          'printenv $DENIED_ENV_VAR',
        );
        final result = runInSandbox(wrapped);

        expect(result.status, isNot(0));
        expect(result.stdout as String, isNot(contains('super-secret-value')));
      });

      test(
        'a non-denied env var is still inherited inside the sandbox',
        () async {
          final wrapped = await SandboxManager.wrapWithSandbox(
            'printenv $ALLOWED_ENV_VAR',
          );
          final result = runInSandbox(wrapped);

          expect(result.status, 0);
          expect(result.stdout as String, contains('visible-value'));
        },
      );

      test(
        'a denied credential file is unreadable inside the sandbox',
        () async {
          final wrapped = await SandboxManager.wrapWithSandbox(
            'cat $SECRET_FILE',
          );
          final result = runInSandbox(wrapped);

          expect(result.status, isNot(0));
          expect(result.stdout as String, isNot(contains('token-abc')));
          expect(
            ((result.stderr as String?) ?? '').toLowerCase(),
            contains('operation not permitted'),
          );
        },
      );

      test(
        'a non-credential file in the same directory is still readable',
        () async {
          final wrapped = await SandboxManager.wrapWithSandbox(
            'cat $CONTROL_FILE',
          );
          final result = runInSandbox(wrapped);

          expect(result.status, 0);
          expect(result.stdout as String, contains('control-ok'));
        },
      );
    },
  );

  group('credential deny on Linux (bwrap)', skip: isLinux ? null : 'Linux only', () {
    final TEST_DIR = join(
      tmpdir(),
      'credential-deny-test-${DateTime.now().millisecondsSinceEpoch}',
    );
    final SECRET_FILE = join(TEST_DIR, 'fake-netrc');
    final SECRET_DIR = join(TEST_DIR, 'fake-aws');
    final SECRET_DIR_FILE = join(SECRET_DIR, 'credentials');
    // Symlinked credential file (dotfile-manager layout): the deny entry names
    // the symlink, the secret bytes live at the target.
    final SECRET_LINK_TARGET = join(TEST_DIR, 'dotfiles-netrc');
    final SECRET_LINK = join(TEST_DIR, 'symlinked-netrc');
    const SECRET_CONTENT = 'machine github.com password hunter2';
    const DENIED_ENV_VAR = 'SRT_TEST_SECRET_TOKEN';
    const ALLOWED_ENV_VAR = 'SRT_TEST_VISIBLE_VALUE';

    // process.env mutations don't reach children spawned by bun without an
    // explicit env option, so the credential vars are passed per-spawn instead.
    final childEnv = {
      ...process.env,
      DENIED_ENV_VAR: 'super-secret-value',
      ALLOWED_ENV_VAR: 'visible-value',
    };

    SpawnSyncResult runInSandbox(String wrappedCommand) {
      return spawnSync(wrappedCommand, [], {
        'shell': true,
        'encoding': 'utf8',
        'timeout': 10000,
        'env': childEnv,
      });
    }

    setUpAll(() async {
      mkdirSync(SECRET_DIR, {'recursive': true});
      writeFileSync(SECRET_FILE, SECRET_CONTENT);
      writeFileSync(SECRET_DIR_FILE, SECRET_CONTENT);
      writeFileSync(SECRET_LINK_TARGET, SECRET_CONTENT);
      symlinkSync(SECRET_LINK_TARGET, SECRET_LINK);

      await SandboxManager.reset();
      await SandboxManager.initialize(
        baseConfig(
          PartialSandboxRuntimeConfig(
            filesystem: FilesystemConfig(
              denyRead: [],
              allowWrite: [
                FilesystemPathSpelling(TEST_DIR),
                const FilesystemPathSpelling('/tmp'),
              ],
              denyWrite: [],
            ),
            credentials: CredentialsConfig(
              files: [
                CredentialFileConfig(path: SECRET_FILE, mode: 'deny'),
                CredentialFileConfig(path: SECRET_DIR, mode: 'deny'),
                CredentialFileConfig(path: SECRET_LINK, mode: 'deny'),
              ],
              envVars: [
                CredentialEnvVarConfig(name: DENIED_ENV_VAR, mode: 'deny'),
              ],
            ),
          ),
        ),
      );
    });

    tearDownAll(() async {
      await SandboxManager.reset();
      if (existsSync(TEST_DIR)) {
        rmSync(TEST_DIR, {'recursive': true, 'force': true});
      }
    });

    group('bwrap argv generation', () {
      test('emits a /dev/null bind for a denied credential file', () async {
        final wrapped = await SandboxManager.wrapWithSandbox('true');

        expect(wrapped, contains('--ro-bind /dev/null $SECRET_FILE'));
        expect(wrapped, contains('--tmpfs $SECRET_DIR'));
      });

      test(
        'denies the resolved target when a denied credential file is a symlink',
        () async {
          final wrapped = await SandboxManager.wrapWithSandbox('true');

          // bwrap rejects symlink bind destinations, so the deny bind lands on
          // the symlink's target instead of the symlink path itself.
          expect(wrapped, contains('--ro-bind /dev/null $SECRET_LINK_TARGET'));
          expect(wrapped, isNot(contains('--ro-bind /dev/null $SECRET_LINK ')));
        },
      );

      test('emits --unsetenv for a denied credential env var', () async {
        final wrapped = await SandboxManager.wrapWithSandbox('true');

        expect(wrapped, contains('--unsetenv $DENIED_ENV_VAR'));
        expect(wrapped, isNot(contains('--unsetenv $ALLOWED_ENV_VAR')));
      });

      test('honors a credentials block passed via customConfig', () async {
        final wrapped = await SandboxManager.wrapWithSandbox(
          'true',
          null,
          PartialSandboxRuntimeConfig(
            filesystem: FilesystemConfig(
              denyRead: [],
              allowWrite: [const FilesystemPathSpelling('/tmp')],
              denyWrite: [],
            ),
            credentials: CredentialsConfig(
              files: [CredentialFileConfig(path: SECRET_FILE, mode: 'deny')],
              envVars: [
                CredentialEnvVarConfig(name: 'CUSTOM_ONLY_TOKEN', mode: 'deny'),
              ],
            ),
          ),
        );

        expect(wrapped, contains('--ro-bind /dev/null $SECRET_FILE'));
        expect(wrapped, contains('--unsetenv CUSTOM_ONLY_TOKEN'));
      });
    });

    group('integration', () {
      test(
        'a denied credential file reads back empty inside the sandbox',
        () async {
          final wrapped = await SandboxManager.wrapWithSandbox(
            'cat $SECRET_FILE',
          );
          final result = runInSandbox(wrapped);

          // The /dev/null bind makes the file readable but empty
          expect(result.stdout as String, isNot(contains('hunter2')));
          expect((result.stdout as String).trim(), '');
        },
      );

      test(
        'a denied symlinked credential file reads back empty inside the sandbox',
        () async {
          final wrapped = await SandboxManager.wrapWithSandbox(
            'cat $SECRET_LINK',
          );
          final result = runInSandbox(wrapped);

          // The symlink resolves to the denied target inside the mount namespace
          expect(result.stdout as String, isNot(contains('hunter2')));
          expect((result.stdout as String).trim(), '');
        },
      );

      test(
        'a file inside a denied credential directory is unreadable inside the sandbox',
        () async {
          final wrapped = await SandboxManager.wrapWithSandbox(
            'cat $SECRET_DIR_FILE',
          );
          final result = runInSandbox(wrapped);

          // The tmpfs mount hides the directory contents entirely
          expect(result.status, isNot(0));
          expect(result.stdout as String, isNot(contains('hunter2')));
        },
      );

      test('a denied env var is absent inside the sandbox', () async {
        final wrapped = await SandboxManager.wrapWithSandbox(
          'printenv $DENIED_ENV_VAR',
        );
        final result = runInSandbox(wrapped);

        expect(result.status, isNot(0));
        expect(result.stdout as String, isNot(contains('super-secret-value')));
      });

      test(
        'a non-denied env var is still inherited inside the sandbox',
        () async {
          final wrapped = await SandboxManager.wrapWithSandbox(
            'printenv $ALLOWED_ENV_VAR',
          );
          final result = runInSandbox(wrapped);

          expect(result.status, 0);
          expect(result.stdout as String, contains('visible-value'));
        },
      );
    });
  });
}

// Dart: JSON.stringify of a string, for the settings files built inline.
String _json(String s) => jsonEncode(s);
