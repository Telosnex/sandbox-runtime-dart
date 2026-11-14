// Ported from sandbox-runtime test/sandbox/wrap-with-sandbox.test.ts @ 0bbebed.
// ignore_for_file: constant_identifier_names, non_constant_identifier_names, slash_for_doc_comments
import 'package:path/path.dart' show join;
import 'package:sandbox_runtime/src/node/fs.dart'
    show mkdirSync, rmSync, unlinkSync, writeFileSync;
import 'package:sandbox_runtime/src/node/os.dart' show tmpdir;
import 'package:sandbox_runtime/src/node/process.dart' as process;
import 'package:sandbox_runtime/src/sandbox/linux_sandbox_utils.dart'
    show LinuxSandboxParams, wrapCommandWithSandboxLinux;
import 'package:sandbox_runtime/src/sandbox/macos_sandbox_utils.dart'
    show MacOSSandboxParams, wrapCommandWithSandboxMacOS;
import 'package:sandbox_runtime/src/sandbox/sandbox_config.dart';
import 'package:sandbox_runtime/src/sandbox/sandbox_manager.dart';
import 'package:sandbox_runtime/src/sandbox/sandbox_schemas.dart'
    show FsReadRestrictionConfig, FsWriteRestrictionConfig;
import 'package:test/test.dart';

import '../helpers/platform.dart' show isLinux, isMacOS, isSupportedPlatform;

/**
 * Create a test configuration with network access
 */
SandboxRuntimeConfig createTestConfig() {
  return SandboxRuntimeConfig(
    network: NetworkConfig(
      allowedDomains: ['example.com', 'api.github.com'],
      deniedDomains: [],
    ),
    filesystem: FilesystemConfig(
      denyRead: [FilesystemPathSpelling('~/.ssh')],
      allowWrite: [FilesystemPathSpelling('.'), FilesystemPathSpelling('/tmp')],
      denyWrite: [FilesystemPathSpelling('.env')],
    ),
  );
}

// Dart: `describe.if(cond)` / `it.if(cond)` become `skip:` on group / test.
Object? _linuxOnly = isLinux ? null : 'Linux only';
Object? _macOnly = isMacOS ? null : 'macOS only';

void main() {
  group(
    'wrapWithSandbox customConfig',
    skip: isSupportedPlatform ? null : 'unsupported platform',
    () {
      setUpAll(() async {
        await SandboxManager.initialize(createTestConfig());
      });

      tearDownAll(() async {
        await SandboxManager.reset();
      });

      group('without customConfig', () {
        test('uses main config values', () async {
          final command = 'echo hello';
          final wrapped = await SandboxManager.wrapWithSandbox(command);

          // Should wrap the command (not return it as-is)
          expect(wrapped, isNot(command));
          expect(wrapped.length, greaterThan(command.length));
        });
      });

      group('with customConfig filesystem overrides', () {
        test('uses custom allowWrite when provided', () async {
          final command = 'echo hello';
          final wrapped = await SandboxManager.wrapWithSandbox(
            command,
            null,
            PartialSandboxRuntimeConfig(
              filesystem: FilesystemConfig(
                denyRead: [],
                allowWrite: [], // Override to block all writes
                denyWrite: [],
              ),
            ),
          );

          // Should still wrap the command
          expect(wrapped, isNot(command));
          expect(wrapped.length, greaterThan(command.length));
        });

        test('uses custom denyRead when provided', () async {
          final command = 'cat /etc/passwd';
          final wrapped = await SandboxManager.wrapWithSandbox(
            command,
            null,
            PartialSandboxRuntimeConfig(
              filesystem: FilesystemConfig(
                denyRead: [
                  FilesystemPathSpelling('/etc/passwd'),
                ], // Block this specific file
                allowWrite: [],
                denyWrite: [],
              ),
            ),
          );

          expect(wrapped, isNot(command));
        });
      });

      group('with customConfig network overrides', () {
        test('blocks network when allowedDomains is empty', () async {
          final command = 'curl https://example.com';
          final wrapped = await SandboxManager.wrapWithSandbox(
            command,
            null,
            PartialSandboxRuntimeConfig(
              network: NetworkConfig(
                allowedDomains: [], // Block all network
                deniedDomains: [],
              ),
            ),
          );

          // Should wrap but without proxy env vars when allowedDomains is empty
          expect(wrapped, isNot(command));

          // The wrapped command should not contain proxy port references
          // when there are no allowed domains (no network access needed)
          // Note: This is implementation-specific and may need adjustment
        });

        test(
          'uses main config network when customConfig.network is undefined',
          () async {
            final command = 'echo hello';
            final wrapped = await SandboxManager.wrapWithSandbox(
              command,
              null,
              PartialSandboxRuntimeConfig(
                filesystem: FilesystemConfig(
                  denyRead: [],
                  allowWrite: [],
                  denyWrite: [],
                ),
                // network is not provided, should use main config
              ),
            );

            expect(wrapped, isNot(command));
          },
        );
      });

      group('readonly mode simulation', () {
        test('can create a fully restricted sandbox config', () async {
          final command = 'ls -la';

          // This is what BashTool passes for readonly commands
          final readonlyConfig = PartialSandboxRuntimeConfig(
            network: NetworkConfig(
              allowedDomains: [], // Block all network
              deniedDomains: [],
            ),
            filesystem: FilesystemConfig(
              denyRead: [],
              allowWrite: [], // Block all writes
              denyWrite: [],
            ),
          );

          final wrapped = await SandboxManager.wrapWithSandbox(
            command,
            null,
            readonlyConfig,
          );

          // Should wrap the command with restrictions
          expect(wrapped, isNot(command));
          expect(wrapped.length, greaterThan(command.length));
        });
      });

      group('partial config merging', () {
        test('only overrides specified filesystem fields', () async {
          final command = 'echo test';

          // Only override allowWrite, should use main config for denyRead/denyWrite
          final wrapped = await SandboxManager.wrapWithSandbox(
            command,
            null,
            PartialSandboxRuntimeConfig(
              filesystem: FilesystemConfig(
                denyRead: [], // Override denyRead
                allowWrite: [
                  FilesystemPathSpelling('/custom/path'),
                ], // Override allowWrite
                denyWrite: [], // Override denyWrite
              ),
            ),
          );

          expect(wrapped, isNot(command));
        });

        test('only overrides specified network fields', () async {
          final command = 'echo test';

          // Only override allowedDomains
          final wrapped = await SandboxManager.wrapWithSandbox(
            command,
            null,
            PartialSandboxRuntimeConfig(
              network: NetworkConfig(
                allowedDomains: ['custom.example.com'],
                deniedDomains: [],
              ),
            ),
          );

          expect(wrapped, isNot(command));
        });
      });
    },
  );

  /**
   * Tests for restriction pattern semantics
   *
   * These test the platform functions directly to verify:
   * - Read (deny-only): undefined or empty denyOnly = no restrictions
   * - Write (allow-only): undefined = no restrictions, any config = restrictions
   * - Network: needsNetworkRestriction = false means no network sandbox
   */
  group('restriction pattern semantics', () {
    final command = 'echo hello';

    group('no sandboxing needed (early return)', () {
      test(
        'returns command unchanged when no restrictions on Linux',
        skip: _linuxOnly,
        () async {
          // No network, empty read deny, no write config = no sandboxing
          final result = await wrapCommandWithSandboxLinux(
            LinuxSandboxParams(
              command: command,
              needsNetworkRestriction: false,
              readConfig: FsReadRestrictionConfig(denyOnly: []),
              writeConfig: null,
            ),
          );

          expect(result, command);
        },
      );

      test(
        'returns command unchanged when no restrictions on macOS',
        skip: _macOnly,
        () {
          // No network, empty read deny, no write config = no sandboxing
          final result = wrapCommandWithSandboxMacOS(
            MacOSSandboxParams(
              command: command,
              needsNetworkRestriction: false,
              readConfig: FsReadRestrictionConfig(denyOnly: []),
              writeConfig: null,
            ),
          );

          expect(result, command);
        },
      );

      test(
        'returns command unchanged with undefined readConfig on Linux',
        skip: _linuxOnly,
        () async {
          final result = await wrapCommandWithSandboxLinux(
            LinuxSandboxParams(
              command: command,
              needsNetworkRestriction: false,
              readConfig: null,
              writeConfig: null,
            ),
          );

          expect(result, command);
        },
      );

      test(
        'returns command unchanged with undefined readConfig on macOS',
        skip: _macOnly,
        () {
          final result = wrapCommandWithSandboxMacOS(
            MacOSSandboxParams(
              command: command,
              needsNetworkRestriction: false,
              readConfig: null,
              writeConfig: null,
            ),
          );

          expect(result, command);
        },
      );
    });

    group('read restrictions (deny-only pattern)', () {
      test(
        'empty denyOnly means no read restrictions on Linux',
        skip: _linuxOnly,
        () async {
          // Only write restrictions, empty read = should sandbox but no read rules
          final result = await wrapCommandWithSandboxLinux(
            LinuxSandboxParams(
              command: command,
              needsNetworkRestriction: false,
              readConfig: FsReadRestrictionConfig(denyOnly: []),
              writeConfig: FsWriteRestrictionConfig(
                allowOnly: ['/tmp'],
                denyWithinAllow: [],
              ),
            ),
          );

          // Should wrap because of write restrictions
          expect(result, isNot(command));
          expect(result, contains('bwrap'));
        },
      );

      test(
        'secure branch always passes --unshare-user and --cap-drop ALL',
        skip: _linuxOnly,
        () async {
          // bwrap only auto-creates a userns when EUID != 0; a root parent
          // would otherwise leave the sandboxed command with initial-userns
          // caps and be able to remount over --ro-bind / /. The default
          // (secure) config must force the userns and drop caps explicitly.
          final result = await wrapCommandWithSandboxLinux(
            LinuxSandboxParams(
              command: command,
              needsNetworkRestriction: false,
              readConfig: FsReadRestrictionConfig(denyOnly: []),
              writeConfig: FsWriteRestrictionConfig(
                allowOnly: ['/tmp'],
                denyWithinAllow: [],
              ),
            ),
          );

          expect(result, contains('--unshare-user'));
          expect(result, contains('--cap-drop ALL'));
        },
      );

      test(
        'weaker branch passes --unshare-user and drops capabilities too',
        skip: _linuxOnly,
        () async {
          final result = await wrapCommandWithSandboxLinux(
            LinuxSandboxParams(
              command: command,
              needsNetworkRestriction: false,
              readConfig: FsReadRestrictionConfig(denyOnly: []),
              writeConfig: FsWriteRestrictionConfig(
                allowOnly: ['/tmp'],
                denyWithinAllow: [],
              ),
              enableWeakerNestedSandbox: true,
            ),
          );

          expect(result, contains('--unshare-user'));
          expect(result, contains('--cap-drop ALL'));
          expect(result, contains('--bind /proc /proc'));
          expect(result, isNot(contains('--proc /proc')));
          if (process.geteuid?.call() != 0) {
            expect(result, isNot(contains('--cap-add')));
          }
        },
      );

      test(
        'non-empty denyOnly means has read restrictions on Linux',
        skip: _linuxOnly,
        () async {
          final result = await wrapCommandWithSandboxLinux(
            LinuxSandboxParams(
              command: command,
              needsNetworkRestriction: false,
              readConfig: FsReadRestrictionConfig(denyOnly: ['/secret']),
              writeConfig: null,
            ),
          );

          // Should wrap because of read restrictions
          expect(result, isNot(command));
          expect(result, contains('bwrap'));
        },
      );
    });

    group('explicit binary paths (Linux)', () {
      test('uses bwrapPath for the outer command', skip: _linuxOnly, () async {
        final result = await wrapCommandWithSandboxLinux(
          LinuxSandboxParams(
            command: command,
            needsNetworkRestriction: false,
            readConfig: FsReadRestrictionConfig(denyOnly: []),
            writeConfig: FsWriteRestrictionConfig(
              allowOnly: ['/tmp'],
              denyWithinAllow: [],
            ),
            bwrapPath: '/opt/bw/bwrap',
          ),
        );

        expect(result.startsWith('/opt/bw/bwrap '), isTrue);
        expect(result.startsWith('bwrap '), isFalse);
      });

      test(
        'uses socatPath inside the sandbox script',
        skip: _linuxOnly,
        () async {
          final httpSock = join(tmpdir(), 'srt-test-http-${process.pid}.sock');
          final socksSock = join(
            tmpdir(),
            'srt-test-socks-${process.pid}.sock',
          );
          writeFileSync(httpSock, '');
          writeFileSync(socksSock, '');
          try {
            final result = await wrapCommandWithSandboxLinux(
              LinuxSandboxParams(
                command: command,
                needsNetworkRestriction: true,
                httpSocketPath: httpSock,
                socksSocketPath: socksSock,
                readConfig: FsReadRestrictionConfig(denyOnly: []),
                writeConfig: FsWriteRestrictionConfig(
                  allowOnly: ['/tmp'],
                  denyWithinAllow: [],
                ),
                socatPath: '/opt/sc/socat',
              ),
            );

            expect(result, contains('/opt/sc/socat'));
            expect(result, contains('TCP6-LISTEN:3128'));
          } finally {
            rmSync(httpSock, {'force': true});
            rmSync(socksSock, {'force': true});
          }
        },
      );
    });

    group('write restrictions (allow-only pattern)', () {
      test(
        'undefined writeConfig means no write restrictions on Linux',
        skip: _linuxOnly,
        () async {
          // Has read restrictions but no write = should sandbox
          final result = await wrapCommandWithSandboxLinux(
            LinuxSandboxParams(
              command: command,
              needsNetworkRestriction: false,
              readConfig: FsReadRestrictionConfig(denyOnly: ['/secret']),
              writeConfig: null,
            ),
          );

          expect(result, isNot(command));
        },
      );

      test(
        'empty allowOnly means maximally restrictive (has restrictions) on Linux',
        skip: _linuxOnly,
        () async {
          // Empty allowOnly = no writes allowed = has restrictions
          final result = await wrapCommandWithSandboxLinux(
            LinuxSandboxParams(
              command: command,
              needsNetworkRestriction: false,
              readConfig: FsReadRestrictionConfig(denyOnly: []),
              writeConfig: FsWriteRestrictionConfig(
                allowOnly: [],
                denyWithinAllow: [],
              ),
            ),
          );

          // Should wrap because empty allowOnly is still a restriction
          expect(result, isNot(command));
          expect(result, contains('bwrap'));
        },
      );

      test(
        'any writeConfig means has restrictions on macOS',
        skip: _macOnly,
        () {
          final result = wrapCommandWithSandboxMacOS(
            MacOSSandboxParams(
              command: command,
              needsNetworkRestriction: false,
              readConfig: FsReadRestrictionConfig(denyOnly: []),
              writeConfig: FsWriteRestrictionConfig(
                allowOnly: [],
                denyWithinAllow: [],
              ),
            ),
          );

          // Should wrap because writeConfig is defined
          expect(result, isNot(command));
          expect(result, contains('sandbox-exec'));
        },
      );
    });

    group('network restrictions', () {
      test(
        'needsNetworkRestriction false skips network sandbox on Linux',
        skip: _linuxOnly,
        () async {
          final result = await wrapCommandWithSandboxLinux(
            LinuxSandboxParams(
              command: command,
              needsNetworkRestriction: false,
              readConfig: FsReadRestrictionConfig(denyOnly: ['/secret']),
              writeConfig: null,
            ),
          );

          // Should wrap for filesystem but not include network args
          expect(result, isNot(command));
          expect(result, isNot(contains('--unshare-net')));
        },
      );

      test(
        'needsNetworkRestriction false skips network sandbox on macOS',
        skip: _macOnly,
        () {
          final result = wrapCommandWithSandboxMacOS(
            MacOSSandboxParams(
              command: command,
              needsNetworkRestriction: false,
              readConfig: FsReadRestrictionConfig(denyOnly: ['/secret']),
              writeConfig: null,
            ),
          );

          // Should wrap for filesystem
          expect(result, isNot(command));
          expect(result, contains('sandbox-exec'));
        },
      );

      // Tests for the empty allowedDomains fix (CVE fix)
      // Empty allowedDomains should block all network, not allow all
      test(
        'needsNetworkRestriction true without proxy sockets blocks all network on Linux',
        skip: _linuxOnly,
        () async {
          // Network restriction enabled but no proxy sockets = block all network
          final result = await wrapCommandWithSandboxLinux(
            LinuxSandboxParams(
              command: command,
              needsNetworkRestriction: true,
              httpSocketPath: null, // No proxy available
              socksSocketPath: null, // No proxy available
              readConfig: FsReadRestrictionConfig(denyOnly: []),
              writeConfig: FsWriteRestrictionConfig(
                allowOnly: ['/tmp'],
                denyWithinAllow: [],
              ),
            ),
          );

          // Should wrap with --unshare-net to block all network
          expect(result, isNot(command));
          expect(result, contains('bwrap'));
          expect(result, contains('--unshare-net'));
          // Should NOT contain proxy-related environment variables since no proxy
          expect(result, isNot(contains('HTTP_PROXY')));
        },
      );

      test(
        'needsNetworkRestriction true without proxy ports blocks all network on macOS',
        skip: _macOnly,
        () {
          // Network restriction enabled but no proxy ports = block all network
          final result = wrapCommandWithSandboxMacOS(
            MacOSSandboxParams(
              command: command,
              needsNetworkRestriction: true,
              httpProxyPort: null, // No proxy available
              socksProxyPort: null, // No proxy available
              readConfig: FsReadRestrictionConfig(denyOnly: []),
              writeConfig: FsWriteRestrictionConfig(
                allowOnly: ['/tmp'],
                denyWithinAllow: [],
              ),
            ),
          );

          // Should wrap with sandbox-exec
          expect(result, isNot(command));
          expect(result, contains('sandbox-exec'));
          // The sandbox profile should NOT contain "(allow network*)" since restrictions are enabled
          // Note: We can't easily check the profile content, but we verify it doesn't skip sandboxing
        },
      );

      test(
        'needsNetworkRestriction true with proxy allows filtered network on Linux',
        skip: _linuxOnly,
        () async {
          // Create temporary socket files for the test
          // Dart: the imports at the top stand for upstream's dynamic imports.
          final tmpDir = tmpdir();
          final httpSocket = join(
            tmpDir,
            'test-http-${DateTime.now().millisecondsSinceEpoch}.sock',
          );
          final socksSocket = join(
            tmpDir,
            'test-socks-${DateTime.now().millisecondsSinceEpoch}.sock',
          );

          // Create dummy socket files
          writeFileSync(httpSocket, '');
          writeFileSync(socksSocket, '');

          try {
            final result = await wrapCommandWithSandboxLinux(
              LinuxSandboxParams(
                command: command,
                needsNetworkRestriction: true,
                httpSocketPath: httpSocket,
                socksSocketPath: socksSocket,
                httpProxyPort: 3128,
                socksProxyPort: 1080,
                readConfig: FsReadRestrictionConfig(denyOnly: []),
                writeConfig: FsWriteRestrictionConfig(
                  allowOnly: ['/tmp'],
                  denyWithinAllow: [],
                ),
              ),
            );

            // Should wrap with network namespace isolation
            expect(result, isNot(command));
            expect(result, contains('bwrap'));
            expect(result, contains('--unshare-net'));
            // Should bind the socket files
            expect(result, contains(httpSocket));
            expect(result, contains(socksSocket));
          } finally {
            // Cleanup
            unlinkSync(httpSocket);
            unlinkSync(socksSocket);
          }
        },
      );

      test(
        'needsNetworkRestriction true with proxy allows filtered network on macOS',
        skip: _macOnly,
        () {
          final result = wrapCommandWithSandboxMacOS(
            MacOSSandboxParams(
              command: command,
              needsNetworkRestriction: true,
              httpProxyPort: 3128,
              socksProxyPort: 1080,
              readConfig: FsReadRestrictionConfig(denyOnly: []),
              writeConfig: FsWriteRestrictionConfig(
                allowOnly: ['/tmp'],
                denyWithinAllow: [],
              ),
            ),
          );

          // Should wrap with sandbox-exec and proxy env vars
          expect(result, isNot(command));
          expect(result, contains('sandbox-exec'));
          // Should set proxy environment variables
          expect(result, contains('HTTP_PROXY'));
          expect(result, contains('HTTPS_PROXY'));
        },
      );
    });
  });

  /**
   * Tests for the empty allowedDomains vulnerability fix
   *
   * These tests verify that when allowedDomains is explicitly set to an empty array [],
   * network access is blocked (as documented) rather than allowed (the bug).
   *
   * Documentation states: "Empty array = no network access"
   * Bug behavior: Empty array = full unrestricted network access
   * Fixed behavior: Empty array = network isolation enabled, all network blocked
   */
  group('empty allowedDomains network blocking (CVE fix)', () {
    final command = 'curl https://example.com';

    group('SandboxManager.wrapWithSandbox with empty allowedDomains', () {
      setUpAll(() async {
        // Initialize with domains so proxy starts, then test with empty customConfig
        await SandboxManager.initialize(
          SandboxRuntimeConfig(
            network: NetworkConfig(
              allowedDomains: ['example.com'],
              deniedDomains: [],
            ),
            filesystem: FilesystemConfig(
              denyRead: [],
              allowWrite: [FilesystemPathSpelling('/tmp')],
              denyWrite: [],
            ),
          ),
        );
      });

      tearDownAll(() async {
        await SandboxManager.reset();
      });

      test(
        'empty allowedDomains in customConfig triggers network restriction on Linux',
        skip: _linuxOnly,
        () async {
          final result = await SandboxManager.wrapWithSandbox(
            command,
            null,
            PartialSandboxRuntimeConfig(
              network: NetworkConfig(
                allowedDomains:
                    [], // Empty = block all network (documented behavior)
                deniedDomains: [],
              ),
              filesystem: FilesystemConfig(
                denyRead: [],
                allowWrite: [FilesystemPathSpelling('/tmp')],
                denyWrite: [],
              ),
            ),
          );

          // With the fix, empty allowedDomains should trigger network isolation
          expect(result, isNot(command));
          expect(result, contains('bwrap'));
          expect(result, contains('--unshare-net'));
        },
      );

      test(
        'empty allowedDomains in customConfig triggers network restriction on macOS',
        skip: _macOnly,
        () async {
          final result = await SandboxManager.wrapWithSandbox(
            command,
            null,
            PartialSandboxRuntimeConfig(
              network: NetworkConfig(
                allowedDomains:
                    [], // Empty = block all network (documented behavior)
                deniedDomains: [],
              ),
              filesystem: FilesystemConfig(
                denyRead: [],
                allowWrite: [FilesystemPathSpelling('/tmp')],
                denyWrite: [],
              ),
            ),
          );

          // With the fix, empty allowedDomains should trigger sandbox
          expect(result, isNot(command));
          expect(result, contains('sandbox-exec'));
        },
      );

      test('non-empty allowedDomains still works correctly', () async {
        final result = await SandboxManager.wrapWithSandbox(
          command,
          null,
          PartialSandboxRuntimeConfig(
            network: NetworkConfig(
              allowedDomains: ['example.com'], // Specific domain allowed
              deniedDomains: [],
            ),
            filesystem: FilesystemConfig(
              denyRead: [],
              allowWrite: [FilesystemPathSpelling('/tmp')],
              denyWrite: [],
            ),
          ),
        );

        // Should still wrap with sandbox
        expect(result, isNot(command));
        // Should have proxy environment variables for filtering
        expect(result, contains('HTTP_PROXY'));
      });

      test(
        'undefined network config in customConfig falls back to main config',
        () async {
          final result = await SandboxManager.wrapWithSandbox(
            command,
            null,
            PartialSandboxRuntimeConfig(
              // No network config - should fall back to main config which has example.com
              filesystem: FilesystemConfig(
                denyRead: [],
                allowWrite: [FilesystemPathSpelling('/tmp')],
                denyWrite: [],
              ),
            ),
          );

          // Should wrap with sandbox using main config's network settings
          expect(result, isNot(command));
          // Main config has example.com, so proxy should be set up
          expect(result, contains('HTTP_PROXY'));
        },
      );
    });
  });

  group('allowWrite glob suffix handling', () {
    final command = 'echo hello';

    test(
      'allowWrite with /** suffix includes path in sandbox command',
      () async {
        final testDir = join(
          tmpdir(),
          'srt-test-glob-allow-${DateTime.now().millisecondsSinceEpoch}',
        );
        mkdirSync(testDir, {'recursive': true});

        try {
          await SandboxManager.reset();
          await SandboxManager.initialize(
            SandboxRuntimeConfig(
              network: NetworkConfig(allowedDomains: [], deniedDomains: []),
              filesystem: FilesystemConfig(
                denyRead: [],
                allowWrite: [FilesystemPathSpelling('$testDir/**')],
                denyWrite: [],
              ),
            ),
          );

          final result = await SandboxManager.wrapWithSandbox(command);

          expect(result, isNot(command));
          expect(result, contains(testDir));
        } finally {
          await SandboxManager.reset();
          rmSync(testDir, {'recursive': true, 'force': true});
        }
      },
    );

    test(
      'denyWrite with /** suffix within allowed parent includes both paths',
      () async {
        final parentDir = join(
          tmpdir(),
          'srt-test-glob-deny-${DateTime.now().millisecondsSinceEpoch}',
        );
        final childDir = join(parentDir, 'denied');
        mkdirSync(childDir, {'recursive': true});

        try {
          await SandboxManager.reset();
          await SandboxManager.initialize(
            SandboxRuntimeConfig(
              network: NetworkConfig(allowedDomains: [], deniedDomains: []),
              filesystem: FilesystemConfig(
                denyRead: [],
                allowWrite: [FilesystemPathSpelling(parentDir)],
                denyWrite: [FilesystemPathSpelling('$childDir/**')],
              ),
            ),
          );

          final result = await SandboxManager.wrapWithSandbox(command);

          expect(result, isNot(command));
          expect(result, contains(parentDir));
          expect(result, contains(childDir));
        } finally {
          await SandboxManager.reset();
          rmSync(parentDir, {'recursive': true, 'force': true});
        }
      },
    );

    // Regression: two denyWrite entries that converge to the same path after
    // normalizePathForSandbox() produced a duplicate --ro-bind /dev/null <dest>.
    // Second bind finds a char device at <dest>; bwrap's ensure_file() doesn't
    // short-circuit on S_ISCHR and falls through to creat() on a read-only mount.
    test(
      'dedups denyWrite entries that normalize to the same path (Linux)',
      skip: _linuxOnly,
      () async {
        final parentDir = join(
          tmpdir(),
          'srt-test-dup-deny-${DateTime.now().millisecondsSinceEpoch}',
        );
        final childFile = join(parentDir, 'dup.txt');
        mkdirSync(parentDir, {'recursive': true});
        writeFileSync(childFile, '');

        try {
          await SandboxManager.reset();
          await SandboxManager.initialize(
            SandboxRuntimeConfig(
              network: NetworkConfig(allowedDomains: [], deniedDomains: []),
              filesystem: FilesystemConfig(
                denyRead: [],
                allowWrite: [FilesystemPathSpelling(parentDir)],
                // Trailing slash and bare form both realpath to childFile
                denyWrite: [
                  FilesystemPathSpelling(childFile),
                  FilesystemPathSpelling('$childFile/'),
                ],
              ),
            ),
          );

          final result = await SandboxManager.wrapWithSandbox(command);

          // One --ro-bind <path> <path> contains the path twice (src + dest);
          // the two spellings of the same file must not each emit a bind.
          final occurrences = result.split(childFile).length - 1;
          expect(occurrences, 2);
        } finally {
          await SandboxManager.reset();
          rmSync(parentDir, {'recursive': true, 'force': true});
        }
      },
    );

    // A path in both denyRead and denyWrite: the /dev/null read mask must win.
    // denyWrite's --ro-bind is emitted after the denyRead masks, so a host-file
    // bind at the same destination would re-expose the contents.
    test(
      'does not let denyWrite unmask a denyRead /dev/null bind (Linux)',
      skip: _linuxOnly,
      () async {
        final parentDir = join(
          tmpdir(),
          'srt-test-unmask-${DateTime.now().millisecondsSinceEpoch}',
        );
        final secret = join(parentDir, 'secret.txt');
        mkdirSync(parentDir, {'recursive': true});
        writeFileSync(secret, '');

        try {
          await SandboxManager.reset();
          await SandboxManager.initialize(
            SandboxRuntimeConfig(
              network: NetworkConfig(allowedDomains: [], deniedDomains: []),
              filesystem: FilesystemConfig(
                denyRead: [FilesystemPathSpelling(secret)],
                allowWrite: [FilesystemPathSpelling(parentDir)],
                denyWrite: [FilesystemPathSpelling(secret)],
              ),
            ),
          );

          final result = await SandboxManager.wrapWithSandbox(command);

          // The /dev/null mask is what we want; the host-file bind is what we don't.
          expect(result, contains('--ro-bind /dev/null $secret'));
          expect(result, isNot(contains('--ro-bind $secret $secret')));
        } finally {
          await SandboxManager.reset();
          rmSync(parentDir, {'recursive': true, 'force': true});
        }
      },
    );

    // A file listed in denyRead stays denied even when allowRead covers its
    // parent directory: a containing allow does not absorb a file-level deny.
    test(
      'file-level denyRead survives a parent-directory allowRead (Linux)',
      skip: _linuxOnly,
      () async {
        final parentDir = join(
          tmpdir(),
          'srt-test-file-deny-${DateTime.now().millisecondsSinceEpoch}',
        );
        final secret = join(parentDir, '.env');
        mkdirSync(parentDir, {'recursive': true});
        writeFileSync(secret, '');

        try {
          await SandboxManager.reset();
          await SandboxManager.initialize(
            SandboxRuntimeConfig(
              network: NetworkConfig(allowedDomains: [], deniedDomains: []),
              filesystem: FilesystemConfig(
                denyRead: [FilesystemPathSpelling(secret)],
                allowRead: [FilesystemPathSpelling(parentDir)],
                allowWrite: [FilesystemPathSpelling(parentDir)],
                denyWrite: [],
              ),
            ),
          );

          final result = await SandboxManager.wrapWithSandbox(command);

          expect(result, contains('--ro-bind /dev/null $secret'));
        } finally {
          await SandboxManager.reset();
          rmSync(parentDir, {'recursive': true, 'force': true});
        }
      },
    );

    // denyRead entries are sorted shallow-first before mounting, so a file-deny
    // listed before its ancestor dir-deny still lands on top of the ancestor's
    // tmpfs + re-allow binds.
    test(
      'file-deny survives ancestor dir-deny listed after it in denyRead (Linux)',
      skip: _linuxOnly,
      () async {
        final parentDir = join(
          tmpdir(),
          'srt-test-order-${DateTime.now().millisecondsSinceEpoch}',
        );
        final projectDir = join(parentDir, 'project');
        final envFile = join(projectDir, '.env');
        mkdirSync(projectDir, {'recursive': true});
        writeFileSync(envFile, '');

        try {
          await SandboxManager.reset();
          await SandboxManager.initialize(
            SandboxRuntimeConfig(
              network: NetworkConfig(allowedDomains: [], deniedDomains: []),
              filesystem: FilesystemConfig(
                // File deliberately listed before the dir that contains it
                denyRead: [
                  FilesystemPathSpelling(envFile),
                  FilesystemPathSpelling(parentDir),
                ],
                allowRead: [FilesystemPathSpelling(projectDir)],
                allowWrite: [FilesystemPathSpelling(projectDir)],
                denyWrite: [],
              ),
            ),
          );

          final result = await SandboxManager.wrapWithSandbox(command);

          // The /dev/null mask must come after the tmpfs + ro-bind in arg order.
          final tmpfsAt = result.indexOf('--tmpfs $parentDir');
          final maskAt = result.indexOf('--ro-bind /dev/null $envFile');
          expect(tmpfsAt, greaterThan(-1));
          expect(maskAt, greaterThan(tmpfsAt));
        } finally {
          await SandboxManager.reset();
          rmSync(parentDir, {'recursive': true, 'force': true});
        }
      },
    );

    // Regression: a directory in both denyRead and denyWrite (e.g. ~/.ssh with
    // Read + Edit/Write deny rules), under an allowed write root, got its
    // denyWrite --ro-bind <dir> <dir> emitted after its own denyRead --tmpfs,
    // exposing the real contents read-only. The tmpfs alone enforces both
    // denies: contents hidden, writes land in the ephemeral tmpfs.
    test(
      'denyWrite bind does not re-expose a denyRead tmpfs over the same dir (Linux)',
      skip: _linuxOnly,
      () async {
        final parentDir = join(
          tmpdir(),
          'srt-test-dir-both-${DateTime.now().millisecondsSinceEpoch}',
        );
        final sshDir = join(parentDir, '.ssh');
        mkdirSync(sshDir, {'recursive': true});
        writeFileSync(join(sshDir, 'id_rsa'), '');

        try {
          await SandboxManager.reset();
          await SandboxManager.initialize(
            SandboxRuntimeConfig(
              network: NetworkConfig(allowedDomains: [], deniedDomains: []),
              filesystem: FilesystemConfig(
                denyRead: [FilesystemPathSpelling(sshDir)],
                allowWrite: [FilesystemPathSpelling(parentDir)],
                denyWrite: [FilesystemPathSpelling(sshDir)],
              ),
            ),
          );

          final result = await SandboxManager.wrapWithSandbox(command);

          // The tmpfs is what we want; the host-dir bind is what we don't.
          expect(result, contains('--tmpfs $sshDir'));
          expect(result, isNot(contains('--ro-bind $sshDir $sshDir')));
        } finally {
          await SandboxManager.reset();
          rmSync(parentDir, {'recursive': true, 'force': true});
        }
      },
    );

    // The ancestor variant of the same stacking bug: a denyWrite dir that
    // contains a denyRead dir re-exposes it when the write-deny ro-bind lands
    // after the tmpfs. The tmpfs must be re-applied on top.
    test(
      'denyRead tmpfs survives a denyWrite bind over an ancestor dir (Linux)',
      skip: _linuxOnly,
      () async {
        final parentDir = join(
          tmpdir(),
          'srt-test-dir-ancestor-${DateTime.now().millisecondsSinceEpoch}',
        );
        final secretsDir = join(parentDir, 'secrets');
        final innerDir = join(secretsDir, 'inner');
        mkdirSync(innerDir, {'recursive': true});
        writeFileSync(join(innerDir, 'key.pem'), '');

        try {
          await SandboxManager.reset();
          await SandboxManager.initialize(
            SandboxRuntimeConfig(
              network: NetworkConfig(allowedDomains: [], deniedDomains: []),
              filesystem: FilesystemConfig(
                denyRead: [FilesystemPathSpelling(innerDir)],
                allowWrite: [FilesystemPathSpelling(parentDir)],
                denyWrite: [FilesystemPathSpelling(secretsDir)],
              ),
            ),
          );

          final result = await SandboxManager.wrapWithSandbox(command);

          // The write-deny bind on the ancestor stays, and the read-deny tmpfs
          // must land after it in arg order so the kernel stacks it on top.
          final bindAt = result.indexOf('--ro-bind $secretsDir $secretsDir');
          final tmpfsAt = result.lastIndexOf('--tmpfs $innerDir');
          expect(bindAt, greaterThan(-1));
          expect(tmpfsAt, greaterThan(bindAt));
        } finally {
          await SandboxManager.reset();
          rmSync(parentDir, {'recursive': true, 'force': true});
        }
      },
    );

    // File variant of the case above: a read-denied file gets a /dev/null bind,
    // and a denyWrite ro-bind over an ancestor would re-expose the real file.
    // The /dev/null mask must land again after the ancestor bind.
    test(
      'denyRead file mask survives a denyWrite bind over an ancestor dir (Linux)',
      skip: _linuxOnly,
      () async {
        final parentDir = join(
          tmpdir(),
          'srt-test-file-ancestor-${DateTime.now().millisecondsSinceEpoch}',
        );
        final secretsDir = join(parentDir, 'secrets');
        final keyFile = join(secretsDir, 'key.pem');
        mkdirSync(secretsDir, {'recursive': true});
        writeFileSync(keyFile, '');

        try {
          await SandboxManager.reset();
          await SandboxManager.initialize(
            SandboxRuntimeConfig(
              network: NetworkConfig(allowedDomains: [], deniedDomains: []),
              filesystem: FilesystemConfig(
                denyRead: [FilesystemPathSpelling(keyFile)],
                allowWrite: [FilesystemPathSpelling(parentDir)],
                denyWrite: [FilesystemPathSpelling(secretsDir)],
              ),
            ),
          );

          final result = await SandboxManager.wrapWithSandbox(command);

          final bindAt = result.indexOf('--ro-bind $secretsDir $secretsDir');
          final maskAt = result.lastIndexOf('--ro-bind /dev/null $keyFile');
          expect(bindAt, greaterThan(-1));
          expect(maskAt, greaterThan(bindAt));
        } finally {
          await SandboxManager.reset();
          rmSync(parentDir, {'recursive': true, 'force': true});
        }
      },
    );

    // The #190 case must keep working: a denyRead tmpfs over an ancestor of an
    // allowed write path wipes denyWrite binds under that write path; they are
    // restored by emitting denyWrite after the denyRead re-binds. The tmpfs
    // skip above must not drop them — the write path re-bind re-exposed them.
    test(
      'denyWrite under a re-bound write path survives an ancestor denyRead tmpfs (Linux)',
      skip: _linuxOnly,
      () async {
        final parentDir = join(
          tmpdir(),
          'srt-test-190-${DateTime.now().millisecondsSinceEpoch}',
        );
        final projectDir = join(parentDir, 'project');
        final hooksDir = join(projectDir, 'hooks');
        mkdirSync(hooksDir, {'recursive': true});

        try {
          await SandboxManager.reset();
          await SandboxManager.initialize(
            SandboxRuntimeConfig(
              network: NetworkConfig(allowedDomains: [], deniedDomains: []),
              filesystem: FilesystemConfig(
                denyRead: [FilesystemPathSpelling(parentDir)],
                allowWrite: [FilesystemPathSpelling(projectDir)],
                denyWrite: [FilesystemPathSpelling(hooksDir)],
              ),
            ),
          );

          final result = await SandboxManager.wrapWithSandbox(command);

          // Order must be: tmpfs ancestor → re-bind write path → deny hooks.
          // The write path is bound twice (allowWrite, then the re-bind after
          // the tmpfs wiped it) — the re-bind is the last occurrence.
          final tmpfsAt = result.indexOf('--tmpfs $parentDir');
          final rebindAt = result.lastIndexOf('--bind $projectDir $projectDir');
          final denyAt = result.indexOf('--ro-bind $hooksDir $hooksDir');
          expect(tmpfsAt, greaterThan(-1));
          expect(rebindAt, greaterThan(tmpfsAt));
          expect(denyAt, greaterThan(rebindAt));
        } finally {
          await SandboxManager.reset();
          rmSync(parentDir, {'recursive': true, 'force': true});
        }
      },
    );
  });
}
