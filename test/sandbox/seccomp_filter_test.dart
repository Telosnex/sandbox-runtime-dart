// Ported from sandbox-runtime test/sandbox/seccomp-filter.test.ts @ 24eb39e.

import 'package:sandbox_runtime/src/node/fs.dart' as fs;
import 'package:sandbox_runtime/src/node/process.dart' as process;
import 'package:sandbox_runtime/src/sandbox/generate_seccomp_filter.dart';
import 'package:sandbox_runtime/src/sandbox/linux_sandbox_utils.dart';
import 'package:sandbox_runtime/src/sandbox/sandbox_config.dart'
    show SeccompConfig;
import 'package:sandbox_runtime/src/sandbox/sandbox_schemas.dart'
    show FsWriteRestrictionConfig;
import 'package:sandbox_runtime/src/utils/which.dart' show whichSync;
import 'package:test/test.dart';

import '../helpers/platform.dart';

void main() {
  group('Linux Sandbox Dependencies', skip: isLinux ? false : 'Linux only', () {
    test(
      'checkLinuxDependencies reports no errors with bwrap + socat + apply-seccomp',
      () {
        final depCheck = checkLinuxDependencies();
        expect(depCheck.warnings, isA<List<String>>());
        expect(depCheck.errors, isEmpty);
        expect(whichSync('bwrap'), isNotNull);
        expect(whichSync('socat'), isNotNull);
      },
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
      expect(checkLinuxDependencies().errors, isEmpty);
    });

    test('wraps filesystem-restricted commands with bwrap', () async {
      final wrappedCommand = await wrapCommandWithSandboxLinux(
        LinuxSandboxParams(
          command: 'ls /',
          needsNetworkRestriction: false,
          writeConfig: FsWriteRestrictionConfig(
            allowOnly: ['/tmp'],
            denyWithinAllow: [],
          ),
        ),
      );

      expect(wrappedCommand, isNotEmpty);
      expect(wrappedCommand, contains('bwrap'));
    });

    test('threads a custom apply-seccomp path through seccompConfig', () async {
      final real = getApplySeccompBinaryPath();
      expect(real, isNotNull);
      if (real == null) throw StateError('apply-seccomp path did not resolve');

      final wrappedCommand = await wrapCommandWithSandboxLinux(
        LinuxSandboxParams(
          command: 'echo test',
          needsNetworkRestriction: false,
          writeConfig: FsWriteRestrictionConfig(
            allowOnly: ['/tmp'],
            denyWithinAllow: [],
          ),
          seccompConfig: SeccompConfig(applyPath: real),
        ),
      );

      expect(wrappedCommand, contains(real));
    });

    test(
      'argv0 mode: builds ARGV0 prefix and uses applyPath verbatim',
      () async {
        final wrappedCommand = await wrapCommandWithSandboxLinux(
          LinuxSandboxParams(
            command: 'echo test',
            needsNetworkRestriction: false,
            writeConfig: FsWriteRestrictionConfig(
              allowOnly: ['/tmp'],
              denyWithinAllow: [],
            ),
            seccompConfig: SeccompConfig(
              argv0: 'apply-seccomp',
              applyPath: '/proc/self/fd/3',
            ),
          ),
        );

        expect(
          wrappedCommand,
          contains('ARGV0=apply-seccomp /proc/self/fd/3 '),
        );
        expect(wrappedCommand, isNot(contains('vendor/seccomp')));
      },
    );

    test('argv0 mode: shell-quotes argv0 and applyPath', () async {
      final wrappedCommand = await wrapCommandWithSandboxLinux(
        LinuxSandboxParams(
          command: 'echo test',
          needsNetworkRestriction: false,
          writeConfig: FsWriteRestrictionConfig(
            allowOnly: ['/tmp'],
            denyWithinAllow: [],
          ),
          seccompConfig: SeccompConfig(
            argv0: 'x; rm -rf /',
            applyPath: '/path with space',
          ),
        ),
      );

      // Assert the values flow into the prefix, not the quoter's exact
      // serialization: the inner prefix is later quoted AGAIN into the outer
      // bwrap argv string, which re-escapes the inner quotes. The child's
      // argv is what matters and is covered by the round-trip tests in
      // test/utils/shell-quote.test.ts.
      expect(wrappedCommand, contains('ARGV0='));
      expect(wrappedCommand, contains('x; rm -rf /'));
      expect(wrappedCommand, contains('/path with space'));
    });

    test('argv0 mode: rejects argv0 without applyPath', () async {
      await expectLater(
        wrapCommandWithSandboxLinux(
          LinuxSandboxParams(
            command: 'echo test',
            needsNetworkRestriction: false,
            writeConfig: FsWriteRestrictionConfig(
              allowOnly: ['/tmp'],
              denyWithinAllow: [],
            ),
            seccompConfig: SeccompConfig(argv0: 'apply-seccomp'),
          ),
        ),
        throwsA(
          predicate(
            (e) => '$e'.contains(
              'seccompConfig.argv0 requires seccompConfig.applyPath',
            ),
          ),
        ),
      );
    });
  });
}
