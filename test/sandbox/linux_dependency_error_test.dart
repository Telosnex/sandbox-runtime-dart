// Ported from sandbox-runtime test/sandbox/linux-dependency-error.test.ts @ 0bbebed.
// ignore_for_file: constant_identifier_names
library;

import 'package:test/test.dart';

import 'package:sandbox_runtime/src/node/child_process.dart' as child_process;
import 'package:sandbox_runtime/src/node/console.dart' as console;
import 'package:sandbox_runtime/src/node/process.dart' as process;
import 'package:sandbox_runtime/src/sandbox/generate_seccomp_filter.dart'
    as seccomp;
import 'package:sandbox_runtime/src/sandbox/linux_sandbox_utils.dart';
import 'package:sandbox_runtime/src/sandbox/sandbox_config.dart'
    show SeccompConfig;
import 'package:sandbox_runtime/src/utils/which.dart' as which;

// The uid-0 path reads this process's real bounding set, so gate the tests
// that need it absent on the same predicate the code uses. True for a
// bounding set without CAP_SETFCAP, and on platforms without /proc.
final lacksSetfcap = !processHasBoundingCapability(CAP_SETFCAP);

// Spies set up in beforeEach, torn down in afterEach. Each test overrides
// just the piece it's exercising. spyOn patches the export binding, so
// linux-sandbox-utils' own imports see the replacement.
// Dart: each spyOn is a replaced variable; its mock state is kept here.
late String? Function(String bin) whichImpl;
late List<String> whichCalls;
late String? applyReturn;
late List<String?> applyCalls;
int? euidReturn;
late child_process.SpawnSyncResult spawnSyncReturn;
late List<List<Object?>> spawnSyncCalls;

late String? Function(String bin) originalWhichSync;
late String? Function([String? seccompBinaryPath])
originalGetApplySeccompBinaryPath;
late int Function()? originalGeteuid;
late child_process.SpawnSyncResult Function(
  String command, [
  List<String> args,
  Map<String, Object?> options,
])
originalSpawnSync;

// A bwrap that exits `status`, so the uid-0 probe never runs a real binary.
child_process.SpawnSyncResult bwrapExiting(int status, [String stderr = '']) =>
    child_process.SpawnSyncResult(
      status: status,
      signal: null,
      pid: 1,
      output: [],
      stdout: '',
      stderr: stderr,
    );

// The spawns that are not the `bwrap --version` probe every caller runs:
// the ones that ask about capabilities.
List<Object?> capabilityProbes() => spawnSyncCalls
    .where(
      (call) => !(call[1] is List && (call[1] as List).contains('--version')),
    )
    .toList();

void main() {
  setUp(() {
    originalWhichSync = which.whichSync;
    originalGetApplySeccompBinaryPath = seccomp.getApplySeccompBinaryPath;
    originalGeteuid = process.geteuid;
    originalSpawnSync = child_process.spawnSync;

    whichCalls = [];
    whichImpl = (String bin) => '/usr/bin/$bin';
    which.whichSync = (String bin) {
      whichCalls.add(bin);
      return whichImpl(bin);
    };
    applyCalls = [];
    applyReturn = '/path/to/apply-seccomp';
    seccomp.getApplySeccompBinaryPath = ([String? seccompBinaryPath]) {
      applyCalls.add(seccompBinaryPath);
      return applyReturn;
    };
    // Pin the euid so only the tests that ask for uid 0 reach that branch;
    // otherwise the result depends on who runs the suite.
    euidReturn = 1000;
    if (process.geteuid != null) {
      process.geteuid = () => euidReturn!;
    }
    spawnSyncCalls = [];
    spawnSyncReturn = bwrapExiting(0);
    child_process.spawnSync =
        (
          String command, [
          List<String> args = const [],
          Map<String, Object?> options = const {},
        ]) {
          spawnSyncCalls.add([command, args, options]);
          return spawnSyncReturn;
        };
  });

  tearDown(() {
    which.whichSync = originalWhichSync;
    seccomp.getApplySeccompBinaryPath = originalGetApplySeccompBinaryPath;
    process.geteuid = originalGeteuid;
    child_process.spawnSync = originalSpawnSync;
  });

  group('checkLinuxDependencies', () {
    test('returns no errors or warnings when all dependencies present', () {
      final result = checkLinuxDependencies();

      expect(result.errors, equals([]));
      expect(result.warnings, equals([]));
      // A non-root caller is never asked about capabilities.
      expect(capabilityProbes(), equals([]));
    });

    test('returns error when bwrap missing', () {
      whichImpl = (String bin) => bin == 'bwrap' ? null : '/usr/bin/$bin';

      final result = checkLinuxDependencies();

      expect(result.errors, contains('bubblewrap (bwrap) not installed'));
      expect(result.errors.length, 1);
    });

    test('returns error when socat missing', () {
      whichImpl = (String bin) => bin == 'socat' ? null : '/usr/bin/$bin';

      final result = checkLinuxDependencies();

      expect(result.errors, contains('socat not installed'));
      expect(result.errors.length, 1);
    });

    test('returns multiple errors when both bwrap and socat missing', () {
      whichImpl = (String bin) => null;

      final result = checkLinuxDependencies();

      expect(result.errors, contains('bubblewrap (bwrap) not installed'));
      expect(result.errors, contains('socat not installed'));
      expect(result.errors.length, 2);
    });

    test('returns warning when apply-seccomp missing', () {
      applyReturn = null;

      final result = checkLinuxDependencies();

      expect(
        result.warnings,
        contains('seccomp not available - unix socket access not restricted'),
      );
    });

    // Wired both ways without gating on the box: a uid-0 caller probes exactly
    // when this process's own bounding set lacks CAP_SETFCAP.
    test(
      'a uid-0 caller probes bubblewrap iff its bounding set lacks CAP_SETFCAP',
      () {
        euidReturn = 0;
        whichImpl = (String bin) =>
            bin == 'bwrap' ? '/usr/bin/bwrap-wiring' : '/usr/bin/$bin';

        final result = checkLinuxDependencies();

        expect(capabilityProbes().isNotEmpty, lacksSetfcap);
        expect(result.errors, equals([]));
        expect(result.warnings, equals([]));
      },
      skip: process.geteuid != null ? null : 'process.geteuid is undefined',
    );

    test('a missing bwrap is blamed on the binary, not on capabilities', () {
      euidReturn = 0;
      whichImpl = (String bin) => bin == 'bwrap' ? null : '/usr/bin/$bin';

      final result = checkLinuxDependencies();

      expect(result.errors, equals(['bubblewrap (bwrap) not installed']));
      expect(spawnSyncCalls, isEmpty);
    });

    test('passes custom applyPath through to the resolver', () {
      checkLinuxDependencies(
        seccompConfig: const SeccompConfig(applyPath: '/custom/apply'),
      );

      expect(applyCalls, contains('/custom/apply'));
    });

    test(
      'argv0 mode: no seccomp warning even when binary lookup would fail',
      () {
        applyReturn = null;

        final result = checkLinuxDependencies(
          seccompConfig: const SeccompConfig(
            argv0: 'apply-seccomp',
            applyPath: '/proc/self/fd/3',
          ),
        );

        expect(result.warnings, equals([]));
        expect(applyCalls, isEmpty);
      },
    );

    test(
      'explicit bwrapPath: skips PATH lookup, errors when not executable',
      () {
        final result = checkLinuxDependencies(bwrapPath: '/no/such/bwrap');

        expect(
          result.errors,
          contains('bubblewrap (bwrap) not executable at /no/such/bwrap'),
        );
        // socat still falls back to PATH
        expect(result.errors.length, 1);
        expect(whichCalls, isNot(contains('bwrap')));
      },
    );

    test(
      'explicit socatPath: skips PATH lookup, errors when not executable',
      () {
        final result = checkLinuxDependencies(socatPath: '/no/such/socat');

        expect(
          result.errors,
          contains('socat not executable at /no/such/socat'),
        );
        expect(whichCalls, isNot(contains('socat')));
      },
    );

    test('explicit bwrapPath: ok when path is executable', () {
      // /bin/sh exists and is executable on every Linux system
      final result = checkLinuxDependencies(bwrapPath: '/bin/sh');

      expect(result.errors, equals([]));
      expect(whichCalls, isNot(contains('bwrap')));
    });
  });

  // The euid, the capability and bubblewrap's own verdict are all injected
  // here, so these run on any box whatever capabilities the suite holds.
  group('uid0SandboxError', () {
    const REFUSAL = 'bwrap: setting up uid map: Operation not permitted';

    test('uid 0 without CAP_SETFCAP, bubblewrap refuses: the named error', () {
      spawnSyncReturn = bwrapExiting(1, '$REFUSAL\n');

      expect(
        uid0SandboxError(
          euid: 0,
          hasSetfcap: false,
          bwrap: '/usr/bin/bwrap-refuses',
        ),
        '$CAP_SETFCAP_MISSING_MESSAGE (bubblewrap: $REFUSAL)',
      );
      expect(
        spawnSyncCalls[0][1],
        equals(['--unshare-user', '--dev-bind', '/', '/', 'true']),
      );
    });

    test(
      'uid 0 without CAP_SETFCAP on a kernel that maps uid 0 anyway: nothing',
      () {
        spawnSyncReturn = bwrapExiting(0);

        expect(
          uid0SandboxError(
            euid: 0,
            hasSetfcap: false,
            bwrap: '/usr/bin/bwrap-allows',
          ),
          isNull,
        );
        expect(spawnSyncCalls, isNotEmpty);
      },
    );

    test('the probe that cannot run leaves the prediction unaided', () {
      spawnSyncReturn = child_process.SpawnSyncResult(
        status: null,
        signal: 'SIGTERM',
        pid: 1,
        output: [],
        stdout: '',
        stderr: '',
        error: Exception('spawnSync ETIMEDOUT'),
      );

      expect(
        uid0SandboxError(
          euid: 0,
          hasSetfcap: false,
          bwrap: '/usr/bin/bwrap-timeout',
        ),
        CAP_SETFCAP_MISSING_MESSAGE,
      );
    });

    test('probes each bwrap at most once, however often it is asked', () {
      spawnSyncReturn = bwrapExiting(1, REFUSAL);
      const args = (
        euid: 0,
        hasSetfcap: false,
        bwrap: '/usr/bin/bwrap-probed-once',
      );

      expect(
        uid0SandboxError(
          euid: args.euid,
          hasSetfcap: args.hasSetfcap,
          bwrap: args.bwrap,
        ),
        uid0SandboxError(
          euid: args.euid,
          hasSetfcap: args.hasSetfcap,
          bwrap: args.bwrap,
        ),
      );
      expect(spawnSyncCalls.length, 1);
    });

    test(
      'nothing to report without all three of uid 0, no capability, a bwrap',
      () {
        expect(
          uid0SandboxError(euid: 1000, hasSetfcap: false, bwrap: '/usr/bin/b'),
          isNull,
        );
        expect(
          uid0SandboxError(euid: null, hasSetfcap: false, bwrap: '/x'),
          isNull,
        );
        expect(
          uid0SandboxError(euid: 0, hasSetfcap: true, bwrap: '/usr/bin/b'),
          isNull,
        );
        expect(
          uid0SandboxError(euid: 0, hasSetfcap: false, bwrap: null),
          isNull,
        );
        expect(spawnSyncCalls, isEmpty);
      },
    );
  });

  // bwrap is reached by execve, and for a euid-0 caller the kernel recomputes
  // the permitted set from CapBnd | CapInh. CapPrm is therefore not the answer.
  group('boundingCapabilitiesFromStatus', () {
    String status({
      required String bnd,
      String inh = '0000000000000000',
      String prm = '0000000000000000',
    }) =>
        'Name:\tsrt\nCapInh:\t$inh\nCapPrm:\t$prm\nCapEff:\t$prm\nCapBnd:\t$bnd\n';
    const WITH = '00000000a82c75fb'; // bit 31 set
    const WITHOUT = '00000000282c75fb'; // same, bit 31 cleared
    bool hasSetfcap(String s) =>
        (((boundingCapabilitiesFromStatus(s) ?? BigInt.zero) >> CAP_SETFCAP) &
            BigInt.one) ==
        BigInt.one;

    test('bounding set has it, permitted set does not: exec restores it', () {
      expect(hasSetfcap(status(bnd: WITH, prm: WITHOUT)), isTrue);
    });

    test('permitted set has it, bounding set does not: exec drops it', () {
      expect(hasSetfcap(status(bnd: WITHOUT, prm: WITH)), isFalse);
    });

    test('inheritable set alone is enough', () {
      expect(hasSetfcap(status(bnd: WITHOUT, inh: WITH)), isTrue);
    });

    test('neither set has it', () {
      expect(hasSetfcap(status(bnd: WITHOUT, inh: WITHOUT)), isFalse);
    });

    test('a status without the lines is undefined, not zero', () {
      expect(boundingCapabilitiesFromStatus('Name:\tsrt\n'), isNull);
      expect(
        boundingCapabilitiesFromStatus(
          'Name:\tsrt\nCapBnd:\t00000000a82c75fb\n',
        ),
        isNull,
      );
    });
  });

  group('capabilityArgs', () {
    test('non-root caller: drops everything, never adds', () {
      for (final usesSeccompHelper in [true, false]) {
        expect(
          capabilityArgs(
            euid: 1000,
            hasSetfcap: true,
            usesSeccompHelper: usesSeccompHelper,
          ),
          equals(['--cap-drop', 'ALL']),
        );
      }
    });

    test('uid 0 under the helper, holding CAP_SETFCAP: keeps it', () {
      expect(
        capabilityArgs(euid: 0, hasSetfcap: true, usesSeccompHelper: true),
        equals(['--cap-drop', 'ALL', '--cap-add', 'CAP_SETFCAP']),
      );
    });

    test('uid 0 without the helper: nothing to keep it for', () {
      expect(
        capabilityArgs(euid: 0, hasSetfcap: true, usesSeccompHelper: false),
        equals(['--cap-drop', 'ALL']),
      );
    });

    // Pure: the missing-capability case is reported by the caller, once per
    // process, not from an argument builder run for every wrapped command.
    test('uid 0 missing CAP_SETFCAP: adds nothing and says nothing', () {
      final originalWarn = console.warn;
      final originalError = console.error;
      var warnCalls = 0;
      var errorCalls = 0;
      console.warn = ([a, b, c, d]) {
        warnCalls++;
      };
      console.error = ([a, b, c, d]) {
        errorCalls++;
      };
      final debug = process.env['SRT_DEBUG'];
      process.env['SRT_DEBUG'] = '1';
      try {
        for (final usesSeccompHelper in [true, false]) {
          expect(
            capabilityArgs(
              euid: 0,
              hasSetfcap: false,
              usesSeccompHelper: usesSeccompHelper,
            ),
            equals(['--cap-drop', 'ALL']),
          );
        }

        expect(warnCalls, 0);
        expect(errorCalls, 0);
      } finally {
        if (debug == null) {
          process.env.remove('SRT_DEBUG');
        } else {
          process.env['SRT_DEBUG'] = debug;
        }
        console.warn = originalWarn;
        console.error = originalError;
      }
    });
  });

  group('getLinuxDependencyStatus', () {
    test('reports all available when everything installed', () {
      final status = getLinuxDependencyStatus();

      expect(status.hasBwrap, isTrue);
      expect(status.hasSocat, isTrue);
      expect(status.hasSeccompApply, isTrue);
    });

    test('reports bwrap unavailable when not installed', () {
      whichImpl = (String bin) => bin == 'bwrap' ? null : '/usr/bin/$bin';

      final status = getLinuxDependencyStatus();

      expect(status.hasBwrap, isFalse);
      expect(status.hasSocat, isTrue);
    });

    test('reports socat unavailable when not installed', () {
      whichImpl = (String bin) => bin == 'socat' ? null : '/usr/bin/$bin';

      final status = getLinuxDependencyStatus();

      expect(status.hasSocat, isFalse);
      expect(status.hasBwrap, isTrue);
    });

    test('reports seccomp unavailable when apply binary missing', () {
      applyReturn = null;

      final status = getLinuxDependencyStatus();

      expect(status.hasSeccompApply, isFalse);
      expect(status.hasBwrap, isTrue);
      expect(status.hasSocat, isTrue);
    });

    test('argv0 mode: hasSeccompApply is true without touching disk', () {
      applyReturn = null;

      final status = getLinuxDependencyStatus(
        seccompConfig: const SeccompConfig(
          argv0: 'apply-seccomp',
          applyPath: '/does/not/exist',
        ),
      );

      expect(status.hasSeccompApply, isTrue);
      expect(applyCalls, isEmpty);
    });

    test('explicit binary paths bypass PATH lookup', () {
      whichImpl = (String bin) => null;

      final status = getLinuxDependencyStatus(
        bwrapPath: '/bin/sh',
        socatPath: '/no/such/socat',
      );

      expect(status.hasBwrap, isTrue);
      expect(status.hasSocat, isFalse);
      expect(whichCalls, isNot(contains('bwrap')));
      expect(whichCalls, isNot(contains('socat')));
    });
  });
}
