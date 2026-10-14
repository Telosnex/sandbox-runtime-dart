// Ported from sandbox-runtime test/sandbox/linux-violation-monitor.test.ts @ 24eb39e.
// ignore_for_file: constant_identifier_names, non_constant_identifier_names, slash_for_doc_comments, library_prefixes, prefer_interpolation_to_compose_strings
import 'dart:async';
import 'dart:convert';

import 'package:path/path.dart' show join;
import 'package:sandbox_runtime/src/node/child_process.dart' show spawnSync;
import 'package:sandbox_runtime/src/node/crypto.dart' show randomBytes;
import 'package:sandbox_runtime/src/node/fs.dart'
    show existsSync, mkdirSync, mkdtempSync, realpathSync, rmSync;
import 'package:sandbox_runtime/src/node/net.dart' show connect;
import 'package:sandbox_runtime/src/node/os.dart' show homedir, tmpdir;
import 'package:sandbox_runtime/src/node/process.dart' as process;
import 'package:sandbox_runtime/src/sandbox/generate_seccomp_filter.dart'
    show getApplySeccompBinaryPath;
import 'package:sandbox_runtime/src/sandbox/linux_violation_monitor.dart'
    as linuxViolationMonitorModule;
import 'package:sandbox_runtime/src/sandbox/linux_violation_monitor.dart'
    show LinuxViolationMonitor, LinuxViolationMonitorOptions;
import 'package:sandbox_runtime/src/sandbox/sandbox_config.dart';
import 'package:sandbox_runtime/src/sandbox/sandbox_manager.dart';
import 'package:sandbox_runtime/src/sandbox/sandbox_utils.dart'
    show MAX_ENCODED_COMMAND_BYTES, encodeSandboxedCommand;
import 'package:sandbox_runtime/src/sandbox/sandbox_violation_store.dart'
    show sanitizeUnregisteredCommandKey;
import 'package:test/test.dart';

import '../helpers/platform.dart' show isLinux;

// Dart: `isLinux ? describe : describe.skip`, as group's skip.
final String? _d = isLinux ? null : 'requires Linux';

/** Simulate apply-seccomp's outer stub: connect and write JSON lines. */
Future<void> send(String socketPath, List<String> lines) {
  final completer = Completer<void>();
  final res = completer.complete;
  final rej = completer.completeError;
  late final dynamic c;
  c = connect(socketPath, () {
    c.write(lines.join('\n') + '\n');
    c.end();
  });
  c.on('close', () => res());
  c.on('error', rej);
  return completer.future;
}

Future<void> _sleep(int ms) => Future<void>.delayed(Duration(milliseconds: ms));

void main() {
  group('linux-violation-monitor (listener)', skip: _d, () {
    late LinuxViolationMonitor mon;
    final violations =
        <({String line, String? encodedCommand, String? command})>[];
    const allow = '/tmp/srt-test-allow';
    const deny = '/tmp/srt-test-allow/deny';

    setUpAll(() async {
      mon = linuxViolationMonitorModule.startLinuxSandboxViolationMonitor(
        (v) => violations.add((
          line: v.line,
          encodedCommand: v.encodedCommand,
          command: v.command,
        )),
        LinuxViolationMonitorOptions(
          allowWritePaths: [allow, '/dev'],
          denyWritePaths: [deny],
          resolveCommandText: sanitizeUnregisteredCommandKey,
        ),
      );
      await mon.ready;
    });
    tearDownAll(() => mon.stop());

    test('binds a filesystem unix socket', () {
      expect(mon.observeSocketPath, isNotNull);
      expect(existsSync(mon.observeSocketPath!), true);
    });

    test('filters allowed writes, surfaces denied writes', () async {
      violations.clear();
      await send(mon.observeSocketPath!, [
        jsonEncode({'encodedCommand': 'dGVzdA=='}), // base64("test")
        jsonEncode({'nr': 257, 'syscall': 'openat', 'path': '$allow/ok'}),
        jsonEncode({'nr': 257, 'syscall': 'openat', 'path': '/dev/null'}),
        jsonEncode({'nr': 257, 'syscall': 'openat', 'path': '$deny/bad'}),
        jsonEncode({'nr': 263, 'syscall': 'unlinkat', 'path': '/etc/passwd'}),
      ]);
      await _sleep(50);
      expect(violations.map((v) => v.line).toList(), [
        'deny openat $deny/bad',
        'deny unlinkat /etc/passwd',
      ]);
      expect(violations[0].encodedCommand, 'dGVzdA==');
    });

    test('drops unresolved relative paths instead of guessing', () async {
      // apply-seccomp resolves relative paths before emitting; a relative
      // path here means resolution failed. Best-effort telemetry: never
      // classify what could not be evaluated against policy.
      violations.clear();
      await send(mon.observeSocketPath!, [
        jsonEncode({'nr': 83, 'syscall': 'mkdir', 'path': 'rel/dir'}),
        jsonEncode({'nr': 257, 'syscall': 'openat', 'path': '/etc/passwd'}),
      ]);
      await _sleep(50);
      expect(violations.map((v) => v.line).toList(), [
        'deny openat /etc/passwd',
      ]);
    });

    test(
      'reports the normalized path it classified, not the spelling',
      () async {
        violations.clear();
        await send(mon.observeSocketPath!, [
          // inside allow once collapsed → not a violation
          jsonEncode({'syscall': 'openat', 'path': '$allow/sub/../ok'}),
          // escapes allow once collapsed → violation, under the collapsed path
          jsonEncode({'syscall': 'openat', 'path': '$allow/../escape'}),
        ]);
        await _sleep(50);
        expect(violations.map((v) => v.line).toList(), [
          'deny openat /tmp/escape',
        ]);
      },
    );

    test(
      'suppresses by the normalized path, so a detour cannot evade it',
      () async {
        // `ignoreViolations` is matched against the same collapsed path the
        // policy check used: a `node_modules/..` detour neither smuggles a
        // suppression nor hides which file was written.
        final lines = <String>[];
        final mon2 = linuxViolationMonitorModule
            .startLinuxSandboxViolationMonitor(
              (v) => lines.add(v.line),
              LinuxViolationMonitorOptions(
                allowWritePaths: ['/tmp/srt-ignore-allow'],
                denyWritePaths: [],
                ignoreViolations: {
                  '*': ['node_modules'],
                },
                resolveCommandText: sanitizeUnregisteredCommandKey,
              ),
            );
        await mon2.ready;
        try {
          await send(mon2.observeSocketPath!, [
            jsonEncode({
              'syscall': 'openat',
              'path': '/home/u/.ssh/node_modules/../authorized_keys',
            }),
          ]);
          await _sleep(50);
          expect(lines, ['deny openat /home/u/.ssh/authorized_keys']);
        } finally {
          mon2.stop();
        }
      },
    );

    test('handles concurrent connections (one per command)', () async {
      violations.clear();
      await Future.wait([
        send(mon.observeSocketPath!, [
          jsonEncode({'syscall': 'openat', 'path': '/a'}),
        ]),
        send(mon.observeSocketPath!, [
          jsonEncode({'syscall': 'openat', 'path': '/b'}),
        ]),
        send(mon.observeSocketPath!, [
          jsonEncode({'syscall': 'openat', 'path': '/c'}),
        ]),
      ]);
      await _sleep(50);
      expect((violations.map((v) => v.line).toList()..sort()), [
        'deny openat /a',
        'deny openat /b',
        'deny openat /c',
      ]);
    });

    test(
      'reports an unregistered attribution key as untrusted bytes',
      () async {
        violations.clear();
        await send(mon.observeSocketPath!, [
          jsonEncode({
            'encodedCommand': encodeSandboxedCommand('x<a>\u202eb\ncdef'),
          }),
          jsonEncode({'syscall': 'openat', 'path': '/etc/passwd'}),
        ]);
        await _sleep(50);
        expect(violations.map((v) => v.command).toList(), ['xa b cdef']);
      },
    );

    test(
      'drops an attribution longer than a minted key, keeping the violation',
      () async {
        violations.clear();
        await send(mon.observeSocketPath!, [
          jsonEncode({'encodedCommand': 'A' * MAX_ENCODED_COMMAND_BYTES}),
          jsonEncode({'syscall': 'openat', 'path': '/etc/one'}),
        ]);
        await send(mon.observeSocketPath!, [
          jsonEncode({'encodedCommand': 'A' * (MAX_ENCODED_COMMAND_BYTES + 1)}),
          jsonEncode({'syscall': 'openat', 'path': '/etc/two'}),
        ]);
        await _sleep(50);
        expect((violations.map((v) => v.line).toList()..sort()), [
          'deny openat /etc/one',
          'deny openat /etc/two',
        ]);
        final oversized = violations.firstWhere(
          (v) => v.line.endsWith('/etc/two'),
        );
        expect(oversized.encodedCommand, isNull);
        expect(oversized.command, isNull);
        expect(
          violations
              .firstWhere((v) => v.line.endsWith('/etc/one'))
              .encodedCommand,
          isNotNull,
        );
      },
    );

    test('ignores malformed lines and observe_init_error', () async {
      violations.clear();
      await send(mon.observeSocketPath!, [
        'not json',
        jsonEncode({'observe_init_error': 'seccomp: EINVAL'}),
        jsonEncode({'nr': 257}), // no path
        jsonEncode({'syscall': 'openat', 'path': '/x'}),
      ]);
      await _sleep(50);
      expect(violations.map((v) => v.line).toList(), ['deny openat /x']);
    });
  });

  // End-to-end against the real binary. Skipped if the vendored binary is
  // missing for this arch (e.g. CI hasn't rebuilt it yet).
  final applyPath = isLinux ? getApplySeccompBinaryPath() : null;
  final String? de = applyPath != null && existsSync(applyPath)
      ? null
      : 'apply-seccomp binary missing';

  group('linux-violation-monitor + apply-seccomp (e2e)', skip: de, () {
    late final String work;
    late final String allow;
    late final String deny;
    late LinuxViolationMonitor mon;
    final violations = <String>[];

    setUpAll(() async {
      work = mkdtempSync(join(tmpdir(), 'srt-vmon-'));
      allow = join(work, 'rw');
      deny = join(work, 'ro');
      spawnSync('mkdir', ['-p', allow, deny]);
      mon = linuxViolationMonitorModule.startLinuxSandboxViolationMonitor(
        (v) => violations.add(v.line),
        LinuxViolationMonitorOptions(
          allowWritePaths: [allow, '/dev'],
          denyWritePaths: [deny],
          resolveCommandText: sanitizeUnregisteredCommandKey,
        ),
      );
      await mon.ready;
    });
    tearDownAll(() {
      mon.stop();
      rmSync(work, {'recursive': true, 'force': true});
    });

    test('captures write-intent paths from a real workload', () async {
      final r = spawnSync(
        applyPath!,
        ['/bin/sh', '-c', 'echo a > $allow/ok; echo b > $deny/bad'],
        {
          'env': {...process.env, 'SRT_OBSERVE_SOCK': mon.observeSocketPath!},
        },
      );
      expect(r.status, 0);
      await _sleep(100);
      expect(violations, contains('deny openat $deny/bad'));
      expect(violations.any((v) => v.contains('$allow/ok')), false);
    });

    test('resolves relative paths against the workload cwd', () async {
      violations.clear();
      final r = spawnSync(
        applyPath!,
        [
          '/bin/sh',
          '-c',
          // Allowed relative write, then a relative write that escapes into
          // the deny dir — both spelled relative, resolved by the supervisor.
          'cd $allow && echo a > rel-ok.txt && echo b > ../ro/rel-bad.txt',
        ],
        {
          'env': {...process.env, 'SRT_OBSERVE_SOCK': mon.observeSocketPath!},
        },
      );
      expect(r.status, 0);
      await _sleep(100);
      // The allowed relative write resolved inside allow → no violation.
      expect(violations.any((v) => v.contains('rel-ok.txt')), false);
      // The escaping relative write resolved into deny → violation, reported
      // under the collapsed path.
      expect(violations, contains('deny openat $deny/rel-bad.txt'));
    });

    test('does not hang when the listener stops reading (full pipe drops)', () {
      // The event pipe is a bounded queue; a stalled consumer must cost
      // log lines, never workload time. 3000 writes far exceeds the pipe
      // capacity — pre-fix this froze at the first full-pipe write.
      final stall = linuxViolationMonitorModule
          .startLinuxSandboxViolationMonitor(
            (_) {},
            LinuxViolationMonitorOptions(
              allowWritePaths: ['/'],
              denyWritePaths: [],
              resolveCommandText: sanitizeUnregisteredCommandKey,
            ),
          );
      return stall.ready.then((_) {
        final dir = mkdtempSync(join(tmpdir(), 'srt-vmon-stall-'));
        try {
          final t0 = DateTime.now().millisecondsSinceEpoch;
          final r = spawnSync(
            applyPath!,
            [
              '/bin/sh',
              '-c',
              'cd $dir && i=0; while [ \$i -lt 3000 ]; do echo x > f\$i; i=\$((i+1)); done && echo DONE',
            ],
            {
              'env': {
                ...process.env,
                'SRT_OBSERVE_SOCK': stall.observeSocketPath!,
              },
              'timeout': 20000,
            },
          );
          expect(r.status, 0);
          expect(r.stdout.toString(), contains('DONE'));
          expect(DateTime.now().millisecondsSinceEpoch - t0, lessThan(15000));
        } finally {
          stall.stop();
          rmSync(dir, {'recursive': true, 'force': true});
        }
      });
    }, timeout: const Timeout(Duration(milliseconds: 30000)));

    test('does not hang when the listener is unreachable', () {
      final t0 = DateTime.now().millisecondsSinceEpoch;
      final r = spawnSync(
        applyPath!,
        ['/bin/sh', '-c', 'echo a > $allow/ok2; exit 5'],
        {
          'env': {...process.env, 'SRT_OBSERVE_SOCK': '/nonexistent/sock'},
          'timeout': 5000,
        },
      );
      expect(r.status, 5);
      expect(DateTime.now().millisecondsSinceEpoch - t0, lessThan(3000));
    });

    test('reports signal death as 128+signal', () {
      // The namespace init cannot distinguish a worker's exit(128+N) from
      // a real signal death, so the status is relayed verbatim as an exit
      // code; the layer above (bwrap) applies its own normalization.
      final r = spawnSync(applyPath!, ['/bin/sh', '-c', r'kill -TERM $$']);
      expect(r.status, 128 + 15);
    });
  });

  group('the write configuration the manager hands the monitor', skip: _d, () {
    // `~`-spelled, relative and glob entries reach the monitor as configured,
    // while the paths it classifies come from the kernel; and bwrap refuses
    // more than the configuration names, because it adds the built-in write
    // denies on top. The fixture is a real tree: bwrap skips a write allow
    // path that does not exist, so a non-existent one would prove nothing.
    final NAME = 'srt-monitor-allow-${randomBytes(4).toString('hex')}';
    late final String HOME_SPELLING;
    late final String ALLOW;
    late final String DENY;
    late final String originalCwd;

    setUpAll(() {
      HOME_SPELLING = join(homedir(), NAME);
      originalCwd = process.cwd();
      mkdirSync(join(HOME_SPELLING, 'secrets'), {'recursive': true});
      mkdirSync(join(HOME_SPELLING, '.git', 'hooks'), {'recursive': true});
      ALLOW = realpathSync(HOME_SPELLING);
      DENY = join(ALLOW, 'secrets');
    });
    tearDownAll(
      () => rmSync(HOME_SPELLING, {'recursive': true, 'force': true}),
    );

    tearDown(() async {
      process.chdir(originalCwd);
      await SandboxManager.reset();
    });

    test(
      'classifies a ~ allow, a ~ deny and a built-in deny the way bwrap does',
      () async {
        LinuxViolationMonitorOptions? handedOver;
        final spy =
            linuxViolationMonitorModule.startLinuxSandboxViolationMonitor;
        linuxViolationMonitorModule.startLinuxSandboxViolationMonitor =
            (callback, opts) {
              handedOver = opts;
              return LinuxViolationMonitor(
                observeSocketPath: () => null,
                ready: Future<void>.value(),
                stop: () {},
              );
            };
        try {
          // The built-in denies are resolved against the cwd of the initialize()
          // call, so make that the tree the allow rule covers.
          process.chdir(ALLOW);
          await SandboxManager.initialize(
            SandboxRuntimeConfig(
              network: NetworkConfig(allowedDomains: [], deniedDomains: []),
              filesystem: FilesystemConfig(
                denyRead: [],
                allowWrite: [
                  FilesystemPathSpelling('~/$NAME'),
                  FilesystemPathSpelling('~/$NAME/g/*'),
                ],
                denyWrite: [FilesystemPathSpelling('~/$NAME/secrets')],
              ),
            ),
            null,
            true,
          );
        } finally {
          process.chdir(originalCwd);
          linuxViolationMonitorModule.startLinuxSandboxViolationMonitor = spy;
        }
        expect(handedOver, isNotNull);
        // A glob is dropped, not kept as a prefix: bwrap never binds one, so
        // treating it as an allow would excuse writes bwrap refuses.
        expect(handedOver!.allowWritePaths.any((p) => p.contains('*')), false);

        // Drive the real listener with exactly what the manager handed over.
        final lines = <String>[];
        final monitor = linuxViolationMonitorModule
            .startLinuxSandboxViolationMonitor(
              (v) => lines.add(v.line),
              handedOver!,
            );
        await monitor.ready;
        try {
          await send(monitor.observeSocketPath!, [
            jsonEncode({'syscall': 'openat', 'path': '$ALLOW/file'}),
            jsonEncode({'syscall': 'openat', 'path': '$DENY/token'}),
            jsonEncode({
              'syscall': 'openat',
              'path': '$ALLOW/.git/hooks/pre-commit',
            }),
          ]);
          await _sleep(50);
          expect(lines, [
            'deny openat $DENY/token',
            'deny openat $ALLOW/.git/hooks/pre-commit',
          ]);
        } finally {
          monitor.stop();
        }
      },
      timeout: const Timeout(Duration(milliseconds: 30000)),
    );

    test(
      'hands over no built-in denies when the filesystem policy is off',
      () async {
        // filesystem.disabled reaches the wrapper as `writeConfig === undefined`,
        // which skips every bind and the built-in denies with them. A monitor
        // holding them would report writes bubblewrap was never asked to refuse.
        LinuxViolationMonitorOptions? handedOver;
        final spy =
            linuxViolationMonitorModule.startLinuxSandboxViolationMonitor;
        linuxViolationMonitorModule.startLinuxSandboxViolationMonitor =
            (callback, opts) {
              handedOver = opts;
              return LinuxViolationMonitor(
                observeSocketPath: () => null,
                ready: Future<void>.value(),
                stop: () {},
              );
            };
        try {
          process.chdir(ALLOW);
          await SandboxManager.initialize(
            SandboxRuntimeConfig(
              network: NetworkConfig(allowedDomains: [], deniedDomains: []),
              filesystem: FilesystemConfig(
                disabled: true,
                denyRead: [],
                allowWrite: [],
                denyWrite: [],
              ),
            ),
            null,
            true,
          );
        } finally {
          process.chdir(originalCwd);
          linuxViolationMonitorModule.startLinuxSandboxViolationMonitor = spy;
        }
        expect(handedOver!.allowWritePaths, ['/']);
        expect(handedOver!.denyWritePaths, <String>[]);
      },
      timeout: const Timeout(Duration(milliseconds: 30000)),
    );
  });
}
