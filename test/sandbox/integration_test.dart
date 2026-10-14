// Ported from sandbox-runtime test/sandbox/integration.test.ts @ 24eb39e.
// ignore_for_file: constant_identifier_names, non_constant_identifier_names, slash_for_doc_comments, prefer_interpolation_to_compose_strings, prefer_adjacent_string_concatenation
import 'dart:async';
import 'dart:io' as io;

import 'package:sandbox_runtime/src/node/console.dart' as console;
import 'package:sandbox_runtime/src/node/fs.dart';
import 'package:sandbox_runtime/src/node/net.dart' as net;
import 'package:sandbox_runtime/src/node/os.dart';
import 'package:sandbox_runtime/src/node/path.dart';
import 'package:sandbox_runtime/src/node/process.dart' as process;
import 'package:sandbox_runtime/src/sandbox/generate_seccomp_filter.dart';
import 'package:sandbox_runtime/src/sandbox/linux_sandbox_utils.dart'
    show LinuxSandboxParams, wrapCommandWithSandboxLinux;
import 'package:sandbox_runtime/src/sandbox/sandbox_config.dart';
import 'package:sandbox_runtime/src/sandbox/sandbox_manager.dart';
import 'package:sandbox_runtime/src/sandbox/sandbox_schemas.dart'
    show FsWriteRestrictionConfig;
import 'package:sandbox_runtime/src/utils/which.dart' show whichSync;
import 'package:test/test.dart';

import '../helpers/bwrap_namespace.dart';
import '../helpers/platform.dart';
import '../helpers/spawn.dart';

/**
 * Create a minimal test configuration for the sandbox with example.com allowed
 */
SandboxRuntimeConfig createTestConfig(String testDir) {
  return SandboxRuntimeConfig(
    network: const NetworkConfig(
      allowedDomains: ['example.com'],
      deniedDomains: [],
    ),
    filesystem: FilesystemConfig(
      denyRead: const [],
      allowWrite: [FilesystemPathSpelling(testDir)],
      denyWrite: const [],
    ),
  );
}

// ============================================================================
// Helper Function
// ============================================================================

/**
 * Assert that the built apply-seccomp binary is available from vendor/seccomp/.
 */
void assertPrecompiledBpfInUse() {
  final binary = getApplySeccompBinaryPath();

  expect(binary, isNotNull);
  expect(binary, contains('/vendor/seccomp/'));
  expect(existsSync(binary!), true);

  console.log('✓ Verified apply-seccomp binary: $binary');
}

// ============================================================================
// Main Test Suite
// ============================================================================

void main() {
  group('Sandbox Integration Tests', skip: isLinux ? null : 'Linux only', () {
    const TEST_SOCKET_PATH = '/tmp/claude-test.sock';
    // Use a directory within the repository (which is the CWD)
    final TEST_DIR = join(process.cwd(), '.sandbox-test-tmp');
    net.NodeServer? socketServer;

    setUpAll(() async {
      // Create test directory
      if (!existsSync(TEST_DIR)) {
        mkdirSync(TEST_DIR, {'recursive': true});
      }

      // Create a Unix socket server for testing
      // We'll use Node.js to create a simple socket server

      // Clean up any existing socket
      if (existsSync(TEST_SOCKET_PATH)) {
        unlinkSync(TEST_SOCKET_PATH);
      }

      // Create Unix socket server
      socketServer = net.createServer((net.NodeSocket socket) {
        socket.on('data', (Object? data) {
          socket.write('Echo: ' + String.fromCharCodes(data as List<int>));
        });
      });

      final listening = Completer<void>();
      socketServer!.listen(TEST_SOCKET_PATH, () {
        console.log('Test socket server listening on $TEST_SOCKET_PATH');
        listening.complete();
      });
      socketServer!.on('error', (Object e) {
        if (!listening.isCompleted) listening.completeError(e);
      });
      await listening.future;

      // Initialize sandbox (reset first to ensure clean state)
      await SandboxManager.reset();
      await SandboxManager.initialize(createTestConfig(TEST_DIR));
    });

    tearDownAll(() async {
      // Clean up socket server
      if (socketServer != null) {
        socketServer!.close();
      }

      // Clean up socket file
      if (existsSync(TEST_SOCKET_PATH)) {
        unlinkSync(TEST_SOCKET_PATH);
      }

      // Clean up test directory
      if (existsSync(TEST_DIR)) {
        rmSync(TEST_DIR, {'recursive': true, 'force': true});
      }

      // Reset sandbox
      await SandboxManager.reset();
    });

    // ==========================================================================
    // Scenario 1: With Pre-compiled BPF
    // ==========================================================================

    group('With Pre-compiled BPF', () {
      setUpAll(() {
        console.log('\n=== Testing with Pre-compiled BPF ===');
        assertPrecompiledBpfInUse();
      });

      group('Unix Socket Restrictions', () {
        test('should block Unix socket connections with seccomp', () async {
          // Wrap command with sandbox
          final command = await SandboxManager.wrapWithSandbox(
            'echo "Test message" | nc -U $TEST_SOCKET_PATH',
          );

          final result = await spawnAsync(
            command,
            const RunOpts(shell: true, encoding: 'utf8', timeout: 5000),
          );

          // Should fail due to seccomp filter blocking socket creation
          final output =
              (result.stderr.isNotEmpty
                      ? result.stderr
                      : result.stdout.isNotEmpty
                      ? result.stdout
                      : '')
                  .toLowerCase();
          // Different netcat versions report the error differently
          final hasExpectedError =
              output.contains('operation not permitted') ||
              output.contains('create unix socket failed');
          expect(hasExpectedError, true);
          expect(result.status, isNot(0));
        });
      });

      group('Network Restrictions', () {
        test('should block HTTP requests to non-allowlisted domains', () async {
          final command = await SandboxManager.wrapWithSandbox(
            'curl -s http://blocked-domain.example',
          );

          final result = await spawnAsync(
            command,
            const RunOpts(shell: true, encoding: 'utf8', timeout: 5000),
          );

          final output =
              (result.stderr.isNotEmpty
                      ? result.stderr
                      : result.stdout.isNotEmpty
                      ? result.stdout
                      : '')
                  .toLowerCase();
          expect(output, contains('blocked by network allowlist'));
        });

        test(
          'should block HTTP requests to anthropic.com (not in allowlist)',
          () async {
            // Use --max-time to timeout quickly, and --show-error to see proxy errors
            final command = await SandboxManager.wrapWithSandbox(
              'curl -s --show-error --max-time 2 https://www.anthropic.com',
            );

            final result = await spawnAsync(
              command,
              const RunOpts(shell: true, encoding: 'utf8', timeout: 3000),
            );

            // The proxy blocks the connection, causing curl to timeout or fail
            // Check that the request did not succeed
            final output =
                (result.stderr.isNotEmpty
                        ? result.stderr
                        : result.stdout.isNotEmpty
                        ? result.stdout
                        : '')
                    .toLowerCase();
            final didFail = result.status != 0 || result.status == null;
            expect(didFail, true);

            // The output should either contain an error or be empty (timeout)
            // It should NOT contain successful HTML response
            expect(output, isNot(contains('<!doctype html')));
            expect(output, isNot(contains('<html')));
          },
        );

        test('should allow HTTP requests to allowlisted domains', () async {
          // Note: example.com should be in the allowlist via .claude/settings.json
          final command = await SandboxManager.wrapWithSandbox(
            'curl -s http://example.com',
          );

          final result = await spawnAsync(
            command,
            const RunOpts(shell: true, encoding: 'utf8', timeout: 10000),
          );

          // Should succeed and return HTML
          final output = result.stdout;
          expect(result.status, 0);
          expect(output, contains('Example Domain'));
        });
      });

      group('Filesystem Restrictions', () {
        test('should block writes outside current working directory', () async {
          final testFile = join(tmpdir(), 'sandbox-blocked-write.txt');

          // Clean up if exists
          if (existsSync(testFile)) {
            unlinkSync(testFile);
          }

          final command = await SandboxManager.wrapWithSandbox(
            'echo "should fail" > $testFile',
          );

          final result = await spawnAsync(
            command,
            RunOpts(
              shell: true,
              encoding: 'utf8',
              cwd: TEST_DIR,
              timeout: 5000,
            ),
          );

          // Should fail with read-only file system error
          final output =
              (result.stderr.isNotEmpty
                      ? result.stderr
                      : result.stdout.isNotEmpty
                      ? result.stdout
                      : '')
                  .toLowerCase();
          expect(output, contains('read-only file system'));
          expect(existsSync(testFile), false);
        });

        test('should allow writes within current working directory', () async {
          // Ensure test directory exists
          if (!existsSync(TEST_DIR)) {
            mkdirSync(TEST_DIR, {'recursive': true});
          }

          final testFile = join(TEST_DIR, 'allowed-write.txt');
          const testContent = 'test content from sandbox';

          // Clean up if exists
          if (existsSync(testFile)) {
            unlinkSync(testFile);
          }

          final command = await SandboxManager.wrapWithSandbox(
            'echo "$testContent" > allowed-write.txt',
          );

          final result = await spawnAsync(
            command,
            RunOpts(
              shell: true,
              encoding: 'utf8',
              cwd: TEST_DIR,
              timeout: 5000,
            ),
          );

          // Debug output if failed
          if (result.status != 0) {
            console.error('Command failed:', command);
            console.error('Status:', result.status);
            console.error('Stdout:', result.stdout);
            console.error('Stderr:', result.stderr);
            console.error('CWD:', TEST_DIR);
            console.error('Test file path:', testFile);
          }

          // Should succeed
          expect(result.status, 0);
          expect(existsSync(testFile), true);

          // Verify content
          final content = io.File(testFile).readAsString();
          expect(await content, contains(testContent));

          // Clean up
          if (existsSync(testFile)) {
            unlinkSync(testFile);
          }
        });

        test('should allow reads from anywhere', () async {
          // Try reading from home directory
          final command = await SandboxManager.wrapWithSandbox(
            'head -n 5 ~/.bashrc',
          );

          final result = await spawnAsync(
            command,
            const RunOpts(shell: true, encoding: 'utf8', timeout: 5000),
          );

          // Should succeed (assuming .bashrc exists)
          expect(result.status, 0);

          // If .bashrc exists, should have some content
          if (existsSync('${process.env['HOME']}/.bashrc')) {
            expect(result.stdout, isNotEmpty);
          }
        });

        test(
          'should allow writes in seccomp-only mode (no network restrictions)',
          () async {
            // Import wrapCommandWithSandboxLinux to call directly

            final testFile = join(TEST_DIR, 'seccomp-only-write.txt');
            const testContent = 'seccomp-only test content';

            // Call wrapCommandWithSandboxLinux with no network restrictions
            // This forces the seccomp-only code path (line 629 in linux-sandbox-utils.ts)
            final command = await wrapCommandWithSandboxLinux(
              LinuxSandboxParams(
                command: 'echo "$testContent" > $testFile',
                needsNetworkRestriction:
                    false, // No network - forces seccomp-only path
                writeConfig: FsWriteRestrictionConfig(
                  allowOnly: [TEST_DIR], // Only allow writes to TEST_DIR
                  denyWithinAllow: [],
                ),
                allowAllUnixSockets: false, // Enable seccomp
              ),
            );

            final result = await spawnAsync(
              command,
              RunOpts(
                shell: true,
                encoding: 'utf8',
                cwd: TEST_DIR,
                timeout: 5000,
              ),
            );

            if (result.status != 0) {
              console.error('Command failed in seccomp-only mode');
              console.error('Status:', result.status);
              console.error('Stdout:', result.stdout);
              console.error('Stderr:', result.stderr);
              console.error('CWD:', TEST_DIR);
              console.error('Test file path:', testFile);
            }

            // Should succeed
            expect(result.status, 0);
            expect(existsSync(testFile), true);

            final content = readFileSync(testFile, 'utf8') as String;
            expect(content.trim(), testContent);

            // Clean up
            if (existsSync(testFile)) {
              unlinkSync(testFile);
            }
          },
        );
      });

      group('Command Execution', () {
        test('should execute basic commands successfully', () async {
          final command = await SandboxManager.wrapWithSandbox(
            'echo "Hello from sandbox"',
          );

          final result = await spawnAsync(
            command,
            const RunOpts(shell: true, encoding: 'utf8', timeout: 5000),
          );

          expect(result.status, 0);
          expect(result.stdout, contains('Hello from sandbox'));
        });

        test('should handle complex command pipelines', () async {
          final command = await SandboxManager.wrapWithSandbox(
            'echo "line1\nline2\nline3" | grep line2',
          );

          final result = await spawnAsync(
            command,
            const RunOpts(shell: true, encoding: 'utf8', timeout: 5000),
          );

          expect(result.status, 0);
          expect(result.stdout, contains('line2'));
          expect(result.stdout, isNot(contains('line1')));
        });
      });

      group('Shell Selection (binShell parameter)', () {
        test(
          'should execute commands with zsh when binShell is specified',
          () async {
            // Check if zsh is available
            final zshCheck = await spawnAsync(
              'which zsh',
              const RunOpts(shell: true, encoding: 'utf8'),
            );
            if (zshCheck.status != 0) {
              console.log('zsh not available, skipping test');
              return;
            }

            // Use a zsh-specific feature: $ZSH_VERSION
            final command = await SandboxManager.wrapWithSandbox(
              'echo "Shell: \$ZSH_VERSION"',
              'zsh',
            );

            final result = await spawnAsync(
              command,
              const RunOpts(shell: true, encoding: 'utf8', timeout: 5000),
            );

            expect(result.status, 0);
            // Should contain version number (e.g., "Shell: 5.8.1")
            expect(result.stdout, matches(RegExp(r'Shell: \d+\.\d+')));
          },
        );

        test('should use zsh syntax successfully with binShell=zsh', () async {
          // Check if zsh is available
          final zshCheck = await spawnAsync(
            'which zsh',
            const RunOpts(shell: true, encoding: 'utf8'),
          );
          if (zshCheck.status != 0) {
            console.log('zsh not available, skipping test');
            return;
          }

          // Use zsh parameter expansion feature
          final command = await SandboxManager.wrapWithSandbox(
            'VAR="hello world" && echo \${VAR:u}',
            'zsh',
          );

          final result = await spawnAsync(
            command,
            const RunOpts(shell: true, encoding: 'utf8', timeout: 5000),
          );

          expect(result.status, 0);
          expect(result.stdout, contains('HELLO WORLD'));
        });

        test('should default to bash when binShell is not specified', () async {
          // Check for bash-specific variable
          final command = await SandboxManager.wrapWithSandbox(
            'echo "Shell: \$BASH_VERSION"',
          );

          final result = await spawnAsync(
            command,
            const RunOpts(shell: true, encoding: 'utf8', timeout: 5000),
          );

          expect(result.status, 0);
          // Should contain bash version
          expect(result.stdout, matches(RegExp(r'Shell: \d+\.\d+')));
        });
      });

      group('Security Boundaries', () {
        test(
          'should isolate PID namespace - sandboxed processes cannot see host PIDs',
          () async {
            // Use /proc to check PID namespace isolation
            // Inside sandbox, should only see sandbox PIDs in /proc
            final command = await SandboxManager.wrapWithSandbox(
              'ls /proc | grep -E "^[0-9]+\$" | wc -l',
            );

            final result = await spawnAsync(
              command,
              const RunOpts(shell: true, encoding: 'utf8', timeout: 5000),
            );

            expect(result.status, 0);

            // Should see very few PIDs (only sandbox processes)
            final pidCount = int.parse(result.stdout.trim());
            expect(pidCount, lessThan(30)); // Host would have 100+
            expect(pidCount, greaterThan(0)); // But at least some processes
          },
        );

        test('should prevent symlink-based filesystem escape attempts', () async {
          // Note: Reads are allowed from anywhere, so test WRITE escape attempt
          final linkInAllowed = join(TEST_DIR, 'escape-link-write');
          final targetOutside =
              '/tmp/escape-test-' +
              DateTime.now().millisecondsSinceEpoch.toString() +
              '.txt';

          // Try to create symlink inside allowed dir pointing to restricted location
          // Then try to write through it
          final command = await SandboxManager.wrapWithSandbox(
            'ln -s $targetOutside $linkInAllowed 2>&1 && echo "escaped" > $linkInAllowed 2>&1',
          );

          final result = await spawnAsync(
            command,
            RunOpts(
              shell: true,
              encoding: 'utf8',
              cwd: TEST_DIR,
              timeout: 5000,
            ),
          );

          // Write should fail (read-only file system for /tmp)
          final output =
              (result.stderr.isNotEmpty
                      ? result.stderr
                      : result.stdout.isNotEmpty
                      ? result.stdout
                      : '')
                  .toLowerCase();
          expect(output, contains('read-only file system'));

          // Target file should NOT exist
          expect(existsSync(targetOutside), false);

          // Clean up
          if (existsSync(linkInAllowed)) {
            unlinkSync(linkInAllowed);
          }
          if (existsSync(targetOutside)) {
            unlinkSync(targetOutside);
          }
        });

        // The two network-allowlist tests below assert the proxy's 403 body
        // ("blocked by network allowlist"), so they must run while the
        // host→sandbox bridge is healthy. They are placed BEFORE the
        // process-lifecycle tests (terminate-background / SIGTERM / orphan /
        // privilege-escalation) because on the linux/x86-64 runner the bridge
        // socat → mux chain has been observed to stop delivering responses
        // after that block runs (curl gets `(52) empty reply` instead of the
        // 403 body). The chain works in isolation and on linux/arm64; the
        // x64-only degradation surfaced after 872e93a and is a test-ordering
        // sensitivity, not a product regression — the rejection body in
        // src/sandbox/http-proxy.ts is unchanged.
        test('should enforce network restrictions across protocols and ports', () async {
          // Test 1: HTTPS to blocked domain (not just HTTP)
          final command1 = await SandboxManager.wrapWithSandbox(
            'curl -s --show-error --max-time 2 --connect-timeout 2 https://blocked-domain.example 2>&1 || echo "curl_failed"',
          );

          final result1 = await spawnAsync(
            command1,
            const RunOpts(shell: true, encoding: 'utf8', timeout: 4000),
          );

          // Should fail - curl should not succeed
          final output1 = result1.stdout.toLowerCase();
          // Should either timeout, fail to resolve, or curl should fail
          final didNotSucceed =
              output1.contains('curl_failed') ||
              output1.contains('timeout') ||
              output1.contains('could not resolve') ||
              output1.contains('failed') ||
              output1.isEmpty; // Timeout with no output
          expect(didNotSucceed, true);

          // Test 2: Non-standard port should also be blocked
          final command2 = await SandboxManager.wrapWithSandbox(
            'curl -s --show-error --max-time 2 http://blocked-domain.example:8080 2>&1',
          );

          final result2 = await spawnAsync(
            command2,
            const RunOpts(shell: true, encoding: 'utf8', timeout: 3000),
          );

          // Should be blocked - check output contains block message
          final output2 = result2.stdout.toLowerCase();
          expect(output2, contains('blocked by network allowlist'));

          // Test 3: Direct IP addresses should also be blocked
          // The network allowlist blocks ALL domains/IPs not explicitly allowed
          final command3 = await SandboxManager.wrapWithSandbox(
            'curl -s --max-time 2 http://1.1.1.1 2>&1', // Cloudflare DNS
          );

          final result3 = await spawnAsync(
            command3,
            const RunOpts(shell: true, encoding: 'utf8', timeout: 3000),
          );

          // IP addresses should be blocked by the proxy
          // Note: curl may return 0 even when blocked if it receives a 403 response
          final output3 = result3.stdout.toLowerCase();
          expect(output3, contains('blocked by network allowlist'));

          // Test 4: Verify HTTPS to allowed domain still works
          final command4 = await SandboxManager.wrapWithSandbox(
            'curl -s --max-time 5 https://example.com 2>&1',
          );

          final result4 = await spawnAsync(
            command4,
            const RunOpts(shell: true, encoding: 'utf8', timeout: 10000),
          );

          // HTTPS should work for allowed domain (unless transient network issue)
          // At minimum, it shouldn't be blocked by our proxy
          final output4 = result4.stdout.toLowerCase();
          expect(output4, isNot(contains('blocked by network allowlist')));
          if (result4.status == 0) {
            expect(result4.stdout, contains('Example Domain'));
          }
        });

        test('should enforce wildcard domain pattern matching correctly', () async {
          // Swap allowedDomains in-place rather than reset()+initialize().
          // The proxy filter reads the live config on every request, so this
          // takes effect immediately and lets us keep the bridge/proxy that
          // every other test in this describe already uses.
          final baseConfig = createTestConfig(TEST_DIR);
          SandboxManager.updateConfig(
            SandboxRuntimeConfig(
              network: NetworkConfig(
                deniedDomains: baseConfig.network.deniedDomains,
                allowedDomains: ['*.github.com', 'example.com'],
              ),
              filesystem: baseConfig.filesystem,
            ),
          );
          try {
            // Test 1: Subdomain should match wildcard. We only assert the
            // proxy did NOT block it — the upstream response is irrelevant —
            // so cap the request tightly.
            final command1 = await SandboxManager.wrapWithSandbox(
              'curl -s --connect-timeout 2 --max-time 2 http://api.github.com 2>&1 | head -20',
            );

            final result1 = await spawnAsync(
              command1,
              const RunOpts(shell: true, encoding: 'utf8', timeout: 3000),
            );

            // Should NOT be blocked - api.github.com matches *.github.com
            final output1 = result1.stdout.toLowerCase();
            expect(output1, isNot(contains('blocked by network allowlist')));

            // Test 2: Base domain should NOT match wildcard (*.github.com doesn't match github.com)
            final command2 = await SandboxManager.wrapWithSandbox(
              'curl -s --max-time 2 http://github.com 2>&1',
            );

            final result2 = await spawnAsync(
              command2,
              const RunOpts(shell: true, encoding: 'utf8', timeout: 3000),
            );

            // Should be blocked - github.com does NOT match *.github.com
            final output2 = result2.stdout.toLowerCase();
            expect(output2, contains('blocked by network allowlist'));

            // Test 3: Malicious lookalike domain should NOT match
            final command3 = await SandboxManager.wrapWithSandbox(
              'curl -s --max-time 2 http://malicious-github.com 2>&1',
            );

            final result3 = await spawnAsync(
              command3,
              const RunOpts(shell: true, encoding: 'utf8', timeout: 3000),
            );

            // Should be blocked - malicious-github.com does NOT match *.github.com
            final output3 = result3.stdout.toLowerCase();
            expect(output3, contains('blocked by network allowlist'));

            // Test 4: Multiple subdomains should match
            final command4 = await SandboxManager.wrapWithSandbox(
              'curl -s --max-time 3 http://raw.githubusercontent.com 2>&1 | head -20',
            );

            final result4 = await spawnAsync(
              command4,
              const RunOpts(shell: true, encoding: 'utf8', timeout: 5000),
            );

            // githubusercontent.com should be blocked (doesn't match *.github.com)
            final output4 = result4.stdout.toLowerCase();
            expect(output4, contains('blocked by network allowlist'));
          } finally {
            // Restore the suite's default allowlist for subsequent tests.
            SandboxManager.updateConfig(baseConfig);
          }
        });

        test('should terminate background processes when sandbox exits', () async {
          // Create a unique marker file that a background process will touch
          final markerFile = join(TEST_DIR, 'background-process-marker.txt');

          if (existsSync(markerFile)) {
            unlinkSync(markerFile);
          }

          // Start a background process that writes every 0.5 second
          final command = await SandboxManager.wrapWithSandbox(
            '(while true; do echo "alive" >> $markerFile; sleep 0.5; done) & sleep 2',
          );

          final startTime = DateTime.now().millisecondsSinceEpoch;
          await spawnAsync(
            command,
            RunOpts(
              shell: true,
              encoding: 'utf8',
              cwd: TEST_DIR,
              timeout: 5000,
            ),
          );
          final endTime = DateTime.now().millisecondsSinceEpoch;

          // Wait a bit to ensure background process would continue if not killed
          await Future<void>.delayed(const Duration(milliseconds: 2000));

          if (existsSync(markerFile)) {
            final content = readFileSync(markerFile, 'utf8') as String;
            final lines = content.trim().split('\n').length;

            // Should have ~4 lines (2 seconds / 0.5s each), not 10+ (if process continued for 5s)
            expect(lines, lessThan(10));

            unlinkSync(markerFile);
          } else {
            // If file doesn't exist, that's also fine - process was killed
            expect(true, true);
          }

          // Verify total execution was ~2 seconds, not hanging
          expect(endTime - startTime, lessThan(4000));
        });

        test(
          'should kill child processes when sandbox is terminated via SIGTERM (--die-with-parent)',
          () async {
            // This test verifies the --die-with-parent flag is working.
            // Without it, child processes would continue running after timeout kills bwrap.
            final markerFile = join(TEST_DIR, 'sigterm-test-marker.txt');

            if (existsSync(markerFile)) {
              unlinkSync(markerFile);
            }

            // Start a long-running process that we'll kill with timeout
            // The process writes to a file every 0.2s - if it survives the kill,
            // we'll see many more writes than expected
            final command = await SandboxManager.wrapWithSandbox(
              'for i in \$(seq 1 50); do echo "tick \$i" >> $markerFile; sleep 0.2; done',
            );

            // Use timeout to kill the sandbox after 1 second
            // The inner command would take 10 seconds to complete
            final result = await spawnAsync('timeout', [
              '1',
              'bash',
              '-c',
              command,
            ], RunOpts(encoding: 'utf8', cwd: TEST_DIR, timeout: 5000));

            // timeout returns 124 when it kills the process
            expect(result.status, 124);

            // Wait a bit to let any orphaned processes continue (if they weren't killed)
            await Future<void>.delayed(const Duration(milliseconds: 1500));

            // Check how many ticks were written
            if (existsSync(markerFile)) {
              final content = readFileSync(markerFile, 'utf8') as String;
              final lines = content.trim().split('\n').length;

              // With 1 second timeout and 0.2s per tick, we expect ~5 ticks
              // If child survived, we'd see 5 + 7 (1.5s more) = 12+ ticks
              // Allow some margin for timing variance
              expect(lines, lessThan(10));

              unlinkSync(markerFile);
            }
          },
        );

        test(
          'should not leave orphan processes after timeout kills sandbox',
          () async {
            // Create a unique marker that only our test process would have
            final uniqueMarker =
                'sandbox-orphan-test-${DateTime.now().millisecondsSinceEpoch}';
            final markerFile = join(TEST_DIR, 'orphan-test.txt');

            if (existsSync(markerFile)) {
              unlinkSync(markerFile);
            }

            // Start a process that will be killed by timeout
            // Use a distinctive command that we can grep for
            final command = await SandboxManager.wrapWithSandbox(
              'export ORPHAN_MARKER="$uniqueMarker"; while true; do echo "\$ORPHAN_MARKER" >> $markerFile; sleep 0.5; done',
            );

            // Kill after 0.5 seconds
            await spawnAsync('timeout', [
              '0.5',
              'bash',
              '-c',
              command,
            ], RunOpts(encoding: 'utf8', cwd: TEST_DIR, timeout: 3000));

            // Wait to see if any orphan continues
            await Future<void>.delayed(const Duration(milliseconds: 1500));

            // Check for orphan processes with our marker
            final psResult = await spawnAsync('bash', [
              '-c',
              'ps aux | grep "$uniqueMarker" | grep -v grep || true',
            ], const RunOpts(encoding: 'utf8', timeout: 2000));

            // Should not find any orphan processes
            expect(psResult.stdout.trim(), '');

            // Cleanup
            if (existsSync(markerFile)) {
              unlinkSync(markerFile);
            }
          },
        );

        test('should prevent privilege escalation attempts', () async {
          // Test 1: Setuid binaries cannot actually elevate privileges
          // Note: The setuid bit CAN be set on files in writable directories,
          // but bwrap ensures it doesn't grant actual privilege escalation
          final setuidTest = join(TEST_DIR, 'setuid-test');

          final command1 = await SandboxManager.wrapWithSandbox(
            'cp /bin/bash $setuidTest 2>&1 && chmod u+s $setuidTest 2>&1 && $setuidTest -c "id -u" 2>&1',
          );

          final result1 = await spawnAsync(
            command1,
            RunOpts(
              shell: true,
              encoding: 'utf8',
              cwd: TEST_DIR,
              timeout: 5000,
            ),
          );

          // Should still run as the same UID (not root), proving setuid doesn't work
          final uid = result1.stdout.trim().split('\n').last;
          expect(
            int.parse(uid.isNotEmpty ? uid : '0'),
            greaterThan(0),
          ); // Not root (0)

          // Test 2: Cannot use sudo/su (should not be available or fail)
          final command2 = await SandboxManager.wrapWithSandbox(
            'sudo -n echo "elevated" 2>&1 || su -c "echo elevated" 2>&1 || echo "commands blocked"',
          );

          final result2 = await spawnAsync(
            command2,
            const RunOpts(shell: true, encoding: 'utf8', timeout: 5000),
          );

          // Should not successfully escalate
          final output = result2.stdout.toLowerCase();
          if (output.contains('elevated') &&
              !output.contains('commands blocked')) {
            // If "elevated" appears without "commands blocked", it should be in an error message
            expect(
              output,
              matches(
                RegExp(
                  r'not found|command not found|no such file|not permitted|password|cannot|no password',
                ),
              ),
            );
          }

          // Cleanup
          if (existsSync(setuidTest)) {
            unlinkSync(setuidTest);
          }
        });

        test(
          'should prevent creation of special file types that could bypass restrictions',
          () async {
            final fifoPath = join(TEST_DIR, 'test.fifo');
            final regularFile = join(TEST_DIR, 'regular.txt');
            final hardlinkPath = join(TEST_DIR, 'hardlink.txt');
            final devicePath = join(TEST_DIR, 'fake-device');

            // Clean up any existing test files
            for (final path in [
              fifoPath,
              regularFile,
              hardlinkPath,
              devicePath,
            ]) {
              if (existsSync(path)) {
                unlinkSync(path);
              }
            }

            // Test 1: FIFO (named pipe) creation in allowed location should work
            final command1 = await SandboxManager.wrapWithSandbox(
              'mkfifo $fifoPath && test -p $fifoPath && echo "FIFO created"',
            );

            final result1 = await spawnAsync(
              command1,
              const RunOpts(shell: true, encoding: 'utf8', timeout: 3000),
            );

            expect(result1.status, 0);
            expect(result1.stdout, contains('FIFO created'));
            expect(existsSync(fifoPath), true);

            // Test 2: Hard link pointing outside allowed location should fail
            // First create a file in allowed location
            final command2a = await SandboxManager.wrapWithSandbox(
              'echo "test content" > $regularFile',
            );

            await spawnAsync(
              command2a,
              const RunOpts(shell: true, encoding: 'utf8', timeout: 3000),
            );

            // Try to create hard link to /etc/passwd (outside allowed location)
            final command2b = await SandboxManager.wrapWithSandbox(
              'ln /etc/passwd $hardlinkPath 2>&1',
            );

            final result2b = await spawnAsync(
              command2b,
              const RunOpts(shell: true, encoding: 'utf8', timeout: 3000),
            );

            // Should fail - cannot create hard link to read-only location
            // Note: May fail with "invalid cross-device link" due to mount namespaces
            expect(result2b.status, isNot(0));
            final output2 = result2b.stdout.toLowerCase();
            expect(
              output2,
              matches(
                RegExp(
                  r'read-only|permission denied|not permitted|operation not permitted|cross-device',
                ),
              ),
            );

            // Test 3: Device node creation should fail (requires CAP_MKNOD which sandbox doesn't have)
            final command3 = await SandboxManager.wrapWithSandbox(
              'mknod $devicePath c 1 3 2>&1',
            );

            final result3 = await spawnAsync(
              command3,
              const RunOpts(shell: true, encoding: 'utf8', timeout: 3000),
            );

            // Should fail - mknod requires special privileges
            expect(result3.status, isNot(0));
            final output3 = result3.stdout.toLowerCase();
            expect(
              output3,
              matches(
                RegExp(
                  r'operation not permitted|permission denied|not permitted',
                ),
              ),
            );
            expect(existsSync(devicePath), false);

            // Cleanup
            for (final path in [
              fifoPath,
              regularFile,
              hardlinkPath,
              devicePath,
            ]) {
              if (existsSync(path)) {
                unlinkSync(path);
              }
            }
          },
        );
      });
    });
  });

  /**
   * Integration tests for the empty allowedDomains vulnerability fix
   *
   * These tests verify the ACTUAL network behavior when allowedDomains: [] is specified.
   * With the fix:
   * - Empty allowedDomains = ALL network access blocked (as documented)
   * - Non-empty allowedDomains = Only specified domains allowed
   *
   * The bug caused empty allowedDomains to allow ALL network access instead.
   */
  group(
    'Empty allowedDomains Network Blocking Integration',
    skip: isLinux ? null : 'Linux only',
    () {
      final TEST_DIR = join(process.cwd(), '.sandbox-test-empty-domains');

      setUpAll(() async {
        // Create test directory
        if (!existsSync(TEST_DIR)) {
          mkdirSync(TEST_DIR, {'recursive': true});
        }
      });

      tearDownAll(() async {
        // Clean up test directory
        if (existsSync(TEST_DIR)) {
          rmSync(TEST_DIR, {'recursive': true, 'force': true});
        }

        await SandboxManager.reset();
      });

      group('Network blocked with empty allowedDomains', () {
        setUpAll(() async {
          // Initialize with empty allowedDomains - should block ALL network
          await SandboxManager.reset();
          await SandboxManager.initialize(
            SandboxRuntimeConfig(
              network: const NetworkConfig(
                allowedDomains:
                    [], // Empty = block all network (documented behavior)
                deniedDomains: [],
              ),
              filesystem: FilesystemConfig(
                denyRead: const [],
                allowWrite: [FilesystemPathSpelling(TEST_DIR)],
                denyWrite: const [],
              ),
            ),
          );
        });

        test(
          'should block all HTTP requests when allowedDomains is empty',
          () async {
            // Try to access example.com - should be blocked
            final command = await SandboxManager.wrapWithSandbox(
              'curl -s --max-time 2 --connect-timeout 2 http://example.com 2>&1 || echo "network_failed"',
            );

            final result = await spawnAsync(
              command,
              const RunOpts(shell: true, encoding: 'utf8', timeout: 5000),
            );

            // With empty allowedDomains, network should be completely blocked
            // curl should fail with network-related error
            final output = (result.stdout + result.stderr).toLowerCase();

            // Network should fail - either connection error, timeout, proxy rejection, or "network_failed" echo
            final networkBlocked =
                output.contains('network_failed') ||
                output.contains("couldn't connect") ||
                output.contains('connection refused') ||
                output.contains('network is unreachable') ||
                output.contains('name or service not known') ||
                output.contains('timed out') ||
                output.contains('connection timed out') ||
                output.contains('blocked by') ||
                result.status != 0;

            expect(networkBlocked, true);

            // Should NOT contain successful HTML response
            expect(output, isNot(contains('example domain')));
            expect(output, isNot(contains('<!doctype')));
          },
        );

        test(
          'should block all HTTPS requests when allowedDomains is empty',
          () async {
            final command = await SandboxManager.wrapWithSandbox(
              'curl -s --max-time 2 --connect-timeout 2 https://example.com 2>&1 || echo "network_failed"',
            );

            final result = await spawnAsync(
              command,
              const RunOpts(shell: true, encoding: 'utf8', timeout: 5000),
            );

            final output = (result.stdout + result.stderr).toLowerCase();

            // Network should fail
            final networkBlocked =
                output.contains('network_failed') ||
                output.contains("couldn't connect") ||
                output.contains('connection refused') ||
                output.contains('network is unreachable') ||
                output.contains('name or service not known') ||
                output.contains('timed out') ||
                output.contains('blocked by') ||
                result.status != 0;

            expect(networkBlocked, true);
          },
        );

        test('should block DNS lookups when allowedDomains is empty', () async {
          // Try DNS lookup - should fail with no network
          final command = await SandboxManager.wrapWithSandbox(
            'host example.com 2>&1 || nslookup example.com 2>&1 || echo "dns_failed"',
          );

          final result = await spawnAsync(
            command,
            const RunOpts(shell: true, encoding: 'utf8', timeout: 5000),
          );

          final output = (result.stdout + result.stderr).toLowerCase();

          // DNS should fail when network is blocked
          final dnsBlocked =
              output.contains('dns_failed') ||
              output.contains('connection timed out') ||
              output.contains('no servers could be reached') ||
              output.contains('network is unreachable') ||
              output.contains('name or service not known') ||
              output.contains('temporary failure') ||
              result.status != 0;

          expect(dnsBlocked, true);
        });

        test('should block wget when allowedDomains is empty', () async {
          final command = await SandboxManager.wrapWithSandbox(
            'wget -q --timeout=2 -O - http://example.com 2>&1 || echo "wget_failed"',
          );

          final result = await spawnAsync(
            command,
            const RunOpts(shell: true, encoding: 'utf8', timeout: 5000),
          );

          final output = (result.stdout + result.stderr).toLowerCase();

          // wget should fail
          final wgetBlocked =
              output.contains('wget_failed') ||
              output.contains('failed') ||
              output.contains('network is unreachable') ||
              output.contains('unable to resolve') ||
              result.status != 0;

          expect(wgetBlocked, true);
        });

        test(
          'should allow local filesystem operations when network is blocked',
          () async {
            // Even with network blocked, filesystem should work
            final testFile = join(TEST_DIR, 'network-blocked-test.txt');
            const testContent = 'test content with network blocked';

            final command = await SandboxManager.wrapWithSandbox(
              'echo "$testContent" > $testFile && cat $testFile',
            );

            final result = await spawnAsync(
              command,
              RunOpts(
                shell: true,
                encoding: 'utf8',
                cwd: TEST_DIR,
                timeout: 5000,
              ),
            );

            expect(result.status, 0);
            expect(result.stdout, contains(testContent));

            // Cleanup
            if (existsSync(testFile)) {
              unlinkSync(testFile);
            }
          },
        );
      });

      group('Network allowed with specific domains', () {
        setUpAll(() async {
          // Reinitialize with specific domain allowed
          await SandboxManager.reset();
          await SandboxManager.initialize(
            SandboxRuntimeConfig(
              network: const NetworkConfig(
                allowedDomains: ['example.com'], // Only example.com allowed
                deniedDomains: [],
              ),
              filesystem: FilesystemConfig(
                denyRead: const [],
                allowWrite: [FilesystemPathSpelling(TEST_DIR)],
                denyWrite: const [],
              ),
            ),
          );
        });

        test('should allow HTTP to explicitly allowed domain', () async {
          final command = await SandboxManager.wrapWithSandbox(
            'curl -s --max-time 5 http://example.com 2>&1',
          );

          final result = await spawnAsync(
            command,
            const RunOpts(shell: true, encoding: 'utf8', timeout: 10000),
          );

          // Should succeed and return HTML
          expect(result.status, 0);
          expect(result.stdout, contains('Example Domain'));
        });

        test('should block HTTP to non-allowed domain', () async {
          final command = await SandboxManager.wrapWithSandbox(
            'curl -s --max-time 2 http://anthropic.com 2>&1',
          );

          final result = await spawnAsync(
            command,
            const RunOpts(shell: true, encoding: 'utf8', timeout: 5000),
          );

          final output = result.stdout.toLowerCase();
          // Should be blocked by proxy
          expect(output, contains('blocked by network allowlist'));
        });
      });

      group('Contrast: empty vs undefined network config', () {
        test('empty allowedDomains should block network', () async {
          await SandboxManager.reset();
          await SandboxManager.initialize(
            SandboxRuntimeConfig(
              network: const NetworkConfig(
                allowedDomains: [], // Explicitly empty
                deniedDomains: [],
              ),
              filesystem: FilesystemConfig(
                denyRead: const [],
                allowWrite: [FilesystemPathSpelling(TEST_DIR)],
                denyWrite: const [],
              ),
            ),
          );

          final command = await SandboxManager.wrapWithSandbox(
            'curl -s --max-time 2 http://example.com 2>&1 || echo "blocked"',
          );

          final result = await spawnAsync(
            command,
            const RunOpts(shell: true, encoding: 'utf8', timeout: 5000),
          );

          // Should be blocked
          final output = (result.stdout + result.stderr).toLowerCase();
          final isBlocked =
              output.contains('blocked') ||
              output.contains("couldn't connect") ||
              output.contains('network is unreachable') ||
              result.status != 0;

          expect(isBlocked, true);
          expect(output, isNot(contains('example domain')));
        });
      });
    },
  );

  // ============================================================================
  // Git over SSH through proxy (GIT_SSH_COMMAND)
  // Regression test for https://github.com/anthropics/sandbox-runtime/issues/161
  // ============================================================================

  group('Git over SSH through sandbox proxy', skip: isLinux ? null : 'Linux only', () {
    final TEST_DIR = join(process.cwd(), '.sandbox-git-ssh-test-tmp');

    setUpAll(() async {
      if (!existsSync(TEST_DIR)) {
        mkdirSync(TEST_DIR, {'recursive': true});
      }

      await SandboxManager.reset();
      await SandboxManager.initialize(
        SandboxRuntimeConfig(
          network: const NetworkConfig(
            allowedDomains: ['github.com'],
            deniedDomains: [],
          ),
          filesystem: FilesystemConfig(
            denyRead: const [],
            allowWrite: [FilesystemPathSpelling(TEST_DIR)],
            denyWrite: const [],
          ),
        ),
      );
    });

    tearDownAll(() async {
      if (existsSync(TEST_DIR)) {
        rmSync(TEST_DIR, {'recursive': true, 'force': true});
      }
      await SandboxManager.reset();
    });

    test(
      'should set GIT_SSH_COMMAND to route SSH through socat proxy on Linux',
      () async {
        final command = await SandboxManager.wrapWithSandbox(
          'echo "\$GIT_SSH_COMMAND"',
        );

        final result = await spawnAsync(
          command,
          const RunOpts(shell: true, encoding: 'utf8', timeout: 5000),
        );

        expect(result.status, 0);
        final gitSshCommand = result.stdout.trim();
        // Must be set (issue #161: was empty on Linux)
        expect(gitSshCommand, isNot(''));
        // Must route through socat HTTP CONNECT proxy
        expect(gitSshCommand, contains('-o ProxyCommand='));
        expect(gitSshCommand, contains('socat - PROXY:localhost:'));
        // Must disable SSH connection multiplexing: a mux socket configured in the
        // user's ssh config can't be used inside the sandbox, and OpenSSH treats
        // mux socket failures as fatal.
        expect(
          gitSshCommand,
          contains('-o ControlMaster=no -o ControlPath=none'),
        );
      },
    );

    test('should resolve DNS and connect when running git over SSH', () async {
      // Use /dev/null as identity to force clean publickey rejection without
      // depending on whatever keys or ssh-agent happen to be present in CI.
      // -o StrictHostKeyChecking=no + UserKnownHostsFile=/dev/null avoids known_hosts writes.
      // GIT_SSH_COMMAND is already set by the sandbox; these options stack on top.
      final command = await SandboxManager.wrapWithSandbox(
        'GIT_SSH_COMMAND="\$GIT_SSH_COMMAND -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o IdentitiesOnly=yes -i /dev/null" ' +
            'git ls-remote ssh://git@github.com/anthropics/sandbox-runtime.git HEAD 2>&1',
      );

      final result = await spawnAsync(
        command,
        const RunOpts(shell: true, encoding: 'utf8', timeout: 15000),
      );

      final output = (result.stdout + result.stderr).toLowerCase();

      // This is the bug from #161. If GIT_SSH_COMMAND isn't set, ssh tries to
      // resolve github.com inside the --unshare-net namespace and fails here.
      expect(output, isNot(contains('could not resolve hostname')));
      expect(output, isNot(contains('temporary failure in name resolution')));

      // With /dev/null as the only identity, github rejects auth after a
      // successful TCP connect + SSH handshake. Reaching this error proves
      // DNS resolution and the proxy tunnel both worked.
      expect(output, contains('permission denied (publickey)'));
    }, timeout: const Timeout(Duration(milliseconds: 20000)));

    test(
      'should run git over SSH when the user ssh config enables ControlMaster',
      () async {
        // SSH connection multiplexing breaks inside the sandbox: with a ControlPath
        // configured, ssh creates an AF_UNIX socket for the mux client before
        // connecting, and the seccomp filter blocks socket(AF_UNIX, ...), which
        // ssh treats as fatal — it dies before the SSH handshake even starts.
        // The injected GIT_SSH_COMMAND must neutralize ControlMaster/ControlPath
        // from the user's ssh config (command-line options take precedence).
        final sshConfigPath = join(TEST_DIR, 'ssh_config_controlmaster');
        writeFileSync(
          sshConfigPath,
          'Host *\n  ControlMaster auto\n  ControlPath $TEST_DIR/mux-%C\n',
        );

        final command = await SandboxManager.wrapWithSandbox(
          'GIT_SSH_COMMAND="\$GIT_SSH_COMMAND -F $sshConfigPath -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o IdentitiesOnly=yes -i /dev/null" ' +
              'git ls-remote ssh://git@github.com/anthropics/sandbox-runtime.git HEAD 2>&1',
        );

        final result = await spawnAsync(
          command,
          const RunOpts(shell: true, encoding: 'utf8', timeout: 15000),
        );

        final output = (result.stdout + result.stderr).toLowerCase();

        // Without the ControlMaster override, ssh exits before authentication:
        // "muxclient: socket(): Operation not permitted".
        expect(output, isNot(contains('muxclient')));
        expect(output, isNot(contains('control socket')));

        // Reaching the publickey rejection proves the SSH handshake completed
        // through the proxy despite the ControlMaster config.
        expect(output, contains('permission denied (publickey)'));
      },
      timeout: const Timeout(Duration(milliseconds: 20000)),
    );
  });

  // ============================================================================
  // Exit status of a network-restricted wrap
  // ============================================================================

  /**
   * With network restrictions the command runs as the last line of an inner
   * script that starts the two socat bridges and stops them from an EXIT trap.
   * Shells disagree on what `exit` without an operand means inside that trap:
   * bash and dash exit with the status the script was already exiting with,
   * zsh exits with the status of the trap's own last command. The inner script
   * runs under the caller's binShell, so each shell is its own case, and so is
   * each form the script's last line takes: through the seccomp helper, or
   * `eval` when allowAllUnixSockets leaves the helper out.
   */
  group(
    'Exit status of a network-restricted wrap',
    skip: isLinux ? null : 'Linux only',
    () {
      // Dart: package:test runs a skipped group's body, so probe bwrap only on Linux.
      final CAN_RESTRICT_NETWORK =
          isLinux && bwrapCanNamespaceNetwork() && whichSync('socat') != null;

      SandboxRuntimeConfig configFor(bool allowAllUnixSockets) =>
          SandboxRuntimeConfig(
            network: NetworkConfig(
              allowedDomains: const ['example.com'],
              deniedDomains: const [],
              allowAllUnixSockets: allowAllUnixSockets,
            ),
            filesystem: const FilesystemConfig(
              denyRead: [],
              allowWrite: [],
              denyWrite: [],
            ),
          );

      setUpAll(() async {
        await SandboxManager.reset();
        if (CAN_RESTRICT_NETWORK) {
          await SandboxManager.initialize(configFor(false));
        }
      });

      tearDownAll(() async {
        await SandboxManager.reset();
      });

      Future<int?> exitStatusOf(String command, String shell) async {
        final wrapped = await SandboxManager.wrapWithSandbox(command, shell);
        // Only the script that bridges the network carries the trap.
        expect(wrapped, contains('--unshare-net'));
        expect(wrapped, contains('TCP-LISTEN:3128'));
        final result = await spawnAsync(
          wrapped,
          const RunOpts(shell: true, encoding: 'utf8', timeout: 10000),
        );
        return result.status;
      }

      for (final shell in ['bash', 'zsh']) {
        for (final allowAllUnixSockets in [false, true]) {
          final lastLine = allowAllUnixSockets ? 'eval' : 'the seccomp helper';
          test(
            "$shell, command run through $lastLine: reports the command's own status",
            () async {
              SandboxManager.updateConfig(configFor(allowAllUnixSockets));
              expect(await exitStatusOf("sh -c 'exit 7'", shell), 7);
              expect(await exitStatusOf('true', shell), 0);
            },
            timeout: const Timeout(Duration(milliseconds: 30000)),
            skip: !CAN_RESTRICT_NETWORK || whichSync(shell) == null
                ? true
                : null,
          );
        }
      }
    },
  );
}
