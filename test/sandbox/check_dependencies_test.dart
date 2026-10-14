// Ported from sandbox-runtime test/sandbox/check-dependencies.test.ts @ 24eb39e.
import 'package:test/test.dart';

import 'package:sandbox_runtime/src/node/process.dart' as process;
import 'package:sandbox_runtime/src/sandbox/sandbox_manager.dart';
import 'package:sandbox_runtime/src/utils/which.dart' as which;

// SandboxManager.checkDependencies() must only require ripgrep on Linux,
// where linuxGetMandatoryDenyPaths() actually invokes it. macOS seatbelt
// profiles take regex patterns directly and never spawn rg — see #156.

void main() {
  // spyOn(which, 'whichSync') is the whichSync variable; spyOn(platform,
  // 'getPlatform') is a process.platform override.
  late String? Function(String bin) originalWhichSync;

  setUp(() {
    originalWhichSync = which.whichSync;
  });

  tearDown(() {
    which.whichSync = originalWhichSync;
    process.setPlatformForTesting(null);
  });

  group('SandboxManager.checkDependencies: ripgrep', () {
    test('macOS: no error when rg is missing', () {
      process.setPlatformForTesting('darwin');
      which.whichSync = (String bin) => bin == 'rg' ? null : '/usr/bin/$bin';

      final result = SandboxManager.checkDependencies();

      expect(result.errors, isNot(contains('ripgrep (rg) not found')));
    });

    test('linux: errors when rg is missing', () {
      process.setPlatformForTesting('linux');
      which.whichSync = (String bin) => bin == 'rg' ? null : '/usr/bin/$bin';

      final result = SandboxManager.checkDependencies();

      expect(result.errors, contains('ripgrep (rg) not found'));
    });

    test('linux: honours explicit ripgrepConfig.command', () {
      process.setPlatformForTesting('linux');
      which.whichSync = (String bin) =>
          bin == 'custom-rg' ? null : '/usr/bin/$bin';

      final result = SandboxManager.checkDependencies((
        command: 'custom-rg',
        args: null,
      ));

      expect(result.errors, contains('ripgrep (custom-rg) not found'));
    });
  });

  group('SandboxManager.checkDependenciesAsync', () {
    test('returns a Promise and matches the sync result (POSIX)', () async {
      process.setPlatformForTesting('linux');
      which.whichSync = (String bin) => bin == 'rg' ? null : '/usr/bin/$bin';

      final p = SandboxManager.checkDependenciesAsync();
      expect(p, isA<Future<SandboxDependencyCheck>>());
      final awaited = await p;
      final sync = SandboxManager.checkDependencies();
      // Dart: SandboxDependencyCheck has no ==; toEqual compares both fields.
      expect(awaited.errors, equals(sync.errors));
      expect(awaited.warnings, equals(sync.warnings));
    });

    test('honours explicit ripgrepConfig.command', () async {
      process.setPlatformForTesting('linux');
      which.whichSync = (String bin) =>
          bin == 'custom-rg' ? null : '/usr/bin/$bin';

      final result = await SandboxManager.checkDependenciesAsync((
        command: 'custom-rg',
        args: null,
      ));

      expect(result.errors, contains('ripgrep (custom-rg) not found'));
    });
  });
}
