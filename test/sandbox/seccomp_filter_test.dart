// Ported from sandbox-runtime test/sandbox/seccomp-filter.test.ts @ 24eb39e.

import 'package:sandbox_runtime/src/node/fs.dart' as fs;
import 'package:sandbox_runtime/src/node/process.dart' as process;
import 'package:sandbox_runtime/src/sandbox/generate_seccomp_filter.dart';
import 'package:test/test.dart';

import '../helpers/platform.dart';

void main() {
  group('Linux Sandbox Dependencies', skip: isLinux ? false : 'Linux only', () {
    test(
      'checkLinuxDependencies reports no errors with bwrap + socat + apply-seccomp',
      () {
        // Pending the linux-sandbox-utils.ts port, the upstream body is:
        // const depCheck = checkLinuxDependencies()
        // expect(depCheck).toHaveProperty('warnings')
        // expect(depCheck.errors).toEqual([])
        // expect(whichSync('bwrap')).not.toBeNull()
        // expect(whichSync('socat')).not.toBeNull()
      },
      skip: 'pending port: linux-sandbox-utils.ts',
    );
  });

  group('Apply Seccomp Binary', skip: isLinux ? false : 'Linux only', () {
    test('resolves the built apply-seccomp binary on x64/arm64', () {
      final arch = process.arch;
      if (arch != 'x64' && arch != 'arm64') {
        expect(getApplySeccompBinaryPath(), isNull);
        return;
      }

      final binaryPath = getApplySeccompBinaryPath();
      expect(binaryPath, isNotNull);
      expect(fs.existsSync(binaryPath!), isTrue);
      expect(binaryPath, contains('vendor/seccomp'));
    });

    test('prefers an explicit valid path over the default', () {
      final real = getApplySeccompBinaryPath();
      final arch = process.arch;
      if (arch != 'x64' && arch != 'arm64') {
        expect(real, isNull);
        return;
      }

      expect(real, isNotNull);
      expect(getApplySeccompBinaryPath(real!), real);
    });

    test('falls back to the default when an explicit path does not exist', () {
      final result = getApplySeccompBinaryPath(
        '/tmp/nonexistent-apply-seccomp',
      );
      final arch = process.arch;
      if (arch == 'x64' || arch == 'arm64') {
        expect(result, isNotNull);
        expect(result, contains('vendor/seccomp'));
      } else {
        expect(result, isNull);
      }
    });
  });

  group('Sandbox Integration', skip: isLinux ? false : 'Linux only', () {
    setUpAll(() {
      // Every test below wraps a command with bwrap. Without the dependencies
      // they would each pass having wrapped nothing, which is the failure
      // this block exists to catch.
      // Pending the linux-sandbox-utils.ts port, the upstream body is:
      // expect(checkLinuxDependencies().errors).toEqual([])
    });

    test('wraps filesystem-restricted commands with bwrap', () async {
      // Pending the linux-sandbox-utils.ts port, the upstream body is:
      // const wrappedCommand = await wrapCommandWithSandboxLinux({
      //   command: 'ls /',
      //   needsNetworkRestriction: false,
      //   writeConfig: { allowOnly: ['/tmp'], denyWithinAllow: [] },
      // })
      //
      // expect(wrappedCommand).toBeTruthy()
      // expect(wrappedCommand).toContain('bwrap')
    }, skip: 'pending port: linux-sandbox-utils.ts');

    test('threads a custom apply-seccomp path through seccompConfig', () async {
      // Pending the linux-sandbox-utils.ts port, the upstream body is:
      // const real = getApplySeccompBinaryPath()
      // expect(real).toBeTruthy()
      // if (real === null) throw new Error('apply-seccomp path did not resolve')
      //
      // const wrappedCommand = await wrapCommandWithSandboxLinux({
      //   command: 'echo test',
      //   needsNetworkRestriction: false,
      //   writeConfig: { allowOnly: ['/tmp'], denyWithinAllow: [] },
      //   seccompConfig: { applyPath: real },
      // })
      //
      // expect(wrappedCommand).toContain(real)
    }, skip: 'pending port: linux-sandbox-utils.ts');

    test('argv0 mode: builds ARGV0 prefix and uses applyPath verbatim', () async {
      // Pending the linux-sandbox-utils.ts port, the upstream body is:
      // const wrappedCommand = await wrapCommandWithSandboxLinux({
      //   command: 'echo test',
      //   needsNetworkRestriction: false,
      //   writeConfig: { allowOnly: ['/tmp'], denyWithinAllow: [] },
      //   seccompConfig: { argv0: 'apply-seccomp', applyPath: '/proc/self/fd/3' },
      // })
      //
      // expect(wrappedCommand).toContain('ARGV0=apply-seccomp /proc/self/fd/3 ')
      // expect(wrappedCommand).not.toContain('vendor/seccomp')
    }, skip: 'pending port: linux-sandbox-utils.ts');

    test('argv0 mode: shell-quotes argv0 and applyPath', () async {
      // Pending the linux-sandbox-utils.ts port, the upstream body is:
      // const wrappedCommand = await wrapCommandWithSandboxLinux({
      //   command: 'echo test',
      //   needsNetworkRestriction: false,
      //   writeConfig: { allowOnly: ['/tmp'], denyWithinAllow: [] },
      //   seccompConfig: { argv0: 'x; rm -rf /', applyPath: '/path with space' },
      // })
      //
      // // Assert the values flow into the prefix, not the quoter's exact
      // // serialization: the inner prefix is later quoted AGAIN into the outer
      // // bwrap argv string, which re-escapes the inner quotes. The child's
      // // argv is what matters and is covered by the round-trip tests in
      // // test/utils/shell-quote.test.ts.
      // expect(wrappedCommand).toContain('ARGV0=')
      // expect(wrappedCommand).toContain('x; rm -rf /')
      // expect(wrappedCommand).toContain('/path with space')
    }, skip: 'pending port: linux-sandbox-utils.ts');

    test('argv0 mode: rejects argv0 without applyPath', () async {
      // Pending the linux-sandbox-utils.ts port, the upstream body is:
      // expect(
      //   wrapCommandWithSandboxLinux({
      //     command: 'echo test',
      //     needsNetworkRestriction: false,
      //     writeConfig: { allowOnly: ['/tmp'], denyWithinAllow: [] },
      //     seccompConfig: { argv0: 'apply-seccomp' },
      //   }),
      // ).rejects.toThrow('seccompConfig.argv0 requires seccompConfig.applyPath')
    }, skip: 'pending port: linux-sandbox-utils.ts');
  });
}
