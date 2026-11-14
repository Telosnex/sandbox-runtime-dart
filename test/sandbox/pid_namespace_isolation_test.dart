// Ported from sandbox-runtime test/sandbox/pid-namespace-isolation.test.ts @ 0bbebed.
// ignore_for_file: prefer_adjacent_string_concatenation
// ignore_for_file: constant_identifier_names, non_constant_identifier_names, slash_for_doc_comments
import 'dart:io' show Process;

import 'package:sandbox_runtime/src/node/child_process.dart' show spawnSync;
import 'package:sandbox_runtime/src/node/fs.dart' show existsSync;
import 'package:sandbox_runtime/src/sandbox/generate_seccomp_filter.dart'
    show getApplySeccompBinaryPath;
import 'package:sandbox_runtime/src/sandbox/linux_sandbox_utils.dart'
    show
        LinuxSandboxParams,
        checkLinuxDependencies,
        wrapCommandWithSandboxLinux;
import 'package:sandbox_runtime/src/sandbox/sandbox_schemas.dart'
    show FsWriteRestrictionConfig;
import 'package:test/test.dart';

import '../helpers/platform.dart' show isLinux;

/**
 * Tests for the nested PID namespace isolation in apply-seccomp.
 *
 * apply-seccomp creates a nested user+PID+mount namespace so that the
 * sandboxed command cannot see — and therefore cannot ptrace or patch
 * via /proc/N/mem — any process that runs without the seccomp filter
 * (bwrap's init, the bash wrapper, and the socat proxy helpers).
 *
 * These tests exercise apply-seccomp directly and through the full
 * bwrap wrapper to verify both layers hold.
 */

String? applySeccomp;

({int? status, String stdout, String stderr}) runApplySeccomp(
  List<String> args, {
  int? timeout,
}) {
  final r = spawnSync(applySeccomp!, args, {
    'stdio': 'pipe',
    'timeout': timeout ?? 10000,
  });
  return (
    status: r.status,
    stdout: r.stdout?.toString() ?? '',
    stderr: r.stderr?.toString() ?? '',
  );
}

// A uid-0 caller execs the workload with a full capability set (see the note
// in apply-seccomp.c), so capability-dependent denials cannot hold as root.
final String? rootSkip =
    isLinux && Process.runSync('id', ['-u']).stdout.toString().trim() == '0'
    ? 'caps are regained on exec when running as root'
    : null;

void main() {
  group('apply-seccomp PID namespace isolation', skip: isLinux ? null : 'not Linux', () {
    setUpAll(() {
      applySeccomp = getApplySeccompBinaryPath();
      // On Linux CI with the vendor binary present this always resolves.
      // If null, every test below would silently no-op — fail here.
      expect(applySeccomp, isNotNull);
      expect(existsSync(applySeccomp!), isTrue);
    });

    // ------------------------------------------------------------------
    // Basic process-model sanity
    // ------------------------------------------------------------------

    test('runs the command as PID 2 under an apply-seccomp init (PID 1)', () {
      final r = runApplySeccomp([
        'sh',
        '-c',
        r'echo "self=$$"; echo "init=$(cat /proc/1/comm)"',
      ]);
      expect(r.status, 0);
      expect(r.stdout, contains('self=2'));
      expect(r.stdout, matches(RegExp(r'init=apply-seccomp')));
    });

    test('shows only the inner namespace in /proc', () {
      final r = runApplySeccomp([
        'sh',
        '-c',
        'ls /proc | grep -E "^[0-9]+\$" | sort -n',
      ]);
      expect(r.status, 0);
      final pids = r.stdout
          .trim()
          .split('\n')
          .map((s) => int.parse(s, radix: 10))
          .toList();
      // PID 1 is apply-seccomp init, PID 2 is sh; ls/grep/sort add a few more.
      // What matters is that none of the host's PIDs leak in.
      expect(pids[0], 1);
      expect(pids.reduce((a, b) => a > b ? a : b), lessThan(20));
    });

    test('forwards exit codes from the inner command', () {
      expect(runApplySeccomp(['sh', '-c', 'exit 0']).status, 0);
      expect(runApplySeccomp(['sh', '-c', 'exit 1']).status, 1);
      expect(runApplySeccomp(['sh', '-c', 'exit 42']).status, 42);
      expect(runApplySeccomp(['sh', '-c', 'exit 127']).status, 127);
    });

    test('forwards signal exits as 128+signo', () {
      final r = runApplySeccomp(['sh', '-c', r'kill -TERM $$']);
      expect(r.status, 128 + 15);
    });

    test(
      'forwards SIGTERM from the outside through both inits to the command',
      () {
        // PID 1 drops signals it has no handler for. apply-seccomp's inner init
        // must install handlers so SIGTERM from the caller actually reaches the
        // workload.
        final r = spawnSync(
          'timeout',
          [
            '--preserve-status',
            '-s',
            'TERM',
            '1',
            applySeccomp!,
            'sleep',
            '10',
          ],
          {'stdio': 'pipe', 'timeout': 10000},
        );
        expect(r.status, 128 + 15);
      },
    );

    test('reaps orphaned grandchildren without leaking zombies', () {
      // Spawn a grandchild that outlives its parent; inner init (PID 1)
      // must reap it. If reaping is broken this either hangs or leaves
      // the grandchild running — the timeout catches both.
      final r = runApplySeccomp([
        'sh',
        '-c',
        '(sleep 0.2 &) ; exit 7',
      ], timeout: 5000);
      expect(r.status, 7);
    });

    test(
      'exits when the main command exits, even with a long-running background process',
      () {
        // Inner init must return as soon as the worker exits, not wait for
        // reparented background children. PID 1 exiting tears down the
        // namespace and SIGKILLs the straggler.
        final r = runApplySeccomp([
          'sh',
          '-c',
          'sleep 100 & exit 5',
        ], timeout: 3000);
        expect(r.status, 5);
      },
    );

    // ------------------------------------------------------------------
    // Seccomp still applies inside the nested namespace
    // ------------------------------------------------------------------

    test('blocks AF_UNIX socket creation', () {
      final r = runApplySeccomp([
        'python3',
        '-c',
        'import socket; socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)',
      ]);
      expect(r.status, isNot(0));
      expect(
        r.stderr.toLowerCase(),
        matches(RegExp(r'permission denied|operation not permitted')),
      );
    });

    test('allows AF_INET socket creation', () {
      final r = runApplySeccomp([
        'python3',
        '-c',
        'import socket; socket.socket(socket.AF_INET, socket.SOCK_STREAM); print("ok")',
      ]);
      expect(r.status, 0);
      expect(r.stdout, contains('ok'));
    });

    test(
      'blocks io_uring_setup (IORING_OP_SOCKET bypass of socket() filter)',
      () {
        // IORING_OP_SOCKET (Linux 5.19+) creates sockets in kernel context,
        // bypassing seccomp's socket() rule. The filter must block
        // io_uring_setup so no ring can be created.
        final r = runApplySeccomp([
          'python3',
          '-c',
          [
            'import ctypes, os',
            'libc = ctypes.CDLL(None, use_errno=True)',
            'p = (ctypes.c_byte * 256)()',
            'fd = libc.syscall(425, 4, p)  # __NR_io_uring_setup',
            'err = ctypes.get_errno()',
            'print(f"fd={fd} errno={err}")',
            'exit(1 if fd >= 0 else 0)',
          ].join('\n'),
        ]);
        expect(r.status, 0);
        expect(r.stdout, matches(RegExp(r'fd=-1 errno=1\b'))); // EPERM
      },
    );

    test('blocks io_uring_enter (covers inherited ring fd)', () {
      final r = runApplySeccomp([
        'python3',
        '-c',
        [
          'import ctypes',
          'libc = ctypes.CDLL(None, use_errno=True)',
          'r = libc.syscall(426, 99, 0, 0, 0, 0, 0)  # __NR_io_uring_enter',
          'print(f"r={r} errno={ctypes.get_errno()}")',
        ].join('\n'),
      ]);
      // EPERM (1) from seccomp, not EBADF (9) from a bad fd — seccomp runs first.
      expect(r.stdout, matches(RegExp(r'r=-1 errno=1\b')));
    });

    // ------------------------------------------------------------------
    // PID 1 is not controllable from the sandboxed command
    // ------------------------------------------------------------------

    test('denies ptrace(PTRACE_ATTACH) against PID 1', skip: rootSkip, () {
      final r = runApplySeccomp([
        'python3',
        '-c',
        [
          'import ctypes, os',
          'libc = ctypes.CDLL(None, use_errno=True)',
          'r = libc.ptrace(16, 1, 0, 0)  # PTRACE_ATTACH',
          'err = ctypes.get_errno()',
          'print(f"r={r} errno={err}")',
          'exit(0 if r != 0 else 1)',
        ].join('\n'),
      ]);
      expect(r.status, 0);
      expect(
        r.stdout,
        matches(RegExp(r'r=-1 errno=(1|13)')),
      ); // EPERM or EACCES
    });

    test('denies opening /proc/1/mem for writing', skip: rootSkip, () {
      final r = runApplySeccomp([
        'python3',
        '-c',
        [
          'try:',
          '    open("/proc/1/mem", "r+b")',
          '    print("OPENED")',
          '    exit(1)',
          'except PermissionError:',
          '    print("DENIED")',
          '    exit(0)',
        ].join('\n'),
      ]);
      expect(r.status, 0);
      expect(r.stdout, contains('DENIED'));
    });

    test(
      'runs the user command with zero effective capabilities',
      skip: rootSkip,
      () {
        // bwrap passes CAP_SYS_ADMIN (ambient) so apply-seccomp can nest a
        // PID+mount namespace. apply-seccomp must clear the ambient set before
        // exec so the workload cannot, e.g., umount /proc to reveal the outer
        // namespace underneath.
        final r = runApplySeccomp(['grep', 'CapEff', '/proc/self/status']);
        expect(r.status, 0);
        expect(r.stdout, matches(RegExp(r'CapEff:\s*0+$', multiLine: true)));
      },
    );

    test('denies umount(/proc) from the user command', skip: rootSkip, () {
      final r = runApplySeccomp([
        'python3',
        '-c',
        [
          'import ctypes, os',
          'libc = ctypes.CDLL(None, use_errno=True)',
          'r = libc.umount2(b"/proc", 0)',
          'print(f"r={r} errno={ctypes.get_errno()}")',
          'exit(0 if r < 0 else 1)',
        ].join('\n'),
      ]);
      expect(r.status, 0);
      expect(r.stdout, matches(RegExp(r'r=-1 errno=1\b'))); // EPERM
    });

    test('denies process_vm_writev against PID 1', () {
      final r = runApplySeccomp([
        'python3',
        '-c',
        [
          'import ctypes, os',
          'libc = ctypes.CDLL(None, use_errno=True)',
          'class iovec(ctypes.Structure):',
          '    _fields_ = [("base", ctypes.c_void_p), ("len", ctypes.c_size_t)]',
          'buf = ctypes.create_string_buffer(b"x")',
          'local = iovec(ctypes.cast(buf, ctypes.c_void_p).value, 1)',
          'remote = iovec(0x1000, 1)',
          'r = libc.process_vm_writev(1, ctypes.byref(local), 1, ctypes.byref(remote), 1, 0)',
          'err = ctypes.get_errno()',
          'print(f"r={r} errno={err}")',
          // EPERM (1) from PR_SET_DUMPABLE=0, or ESRCH (3) if check happens first.
          'exit(0 if r < 0 and err in (1, 3, 13) else 1)',
        ].join('\n'),
      ]);
      expect(r.status, 0);
    });
  });

  group(
    'Full bwrap integration — outer processes are unreachable',
    skip: isLinux ? null : 'not Linux',
    () {
      setUpAll(() {
        applySeccomp = getApplySeccompBinaryPath();
        expect(applySeccomp, isNotNull);
        // CI apt-installs bwrap and socat; if missing the suite would no-op.
        expect(checkLinuxDependencies().errors, equals([]));
      });

      test(
        'hides outer-namespace helpers (socat analogue) from the inner command',
        () async {
          // Spawn a background `sleep` in the outer bwrap namespace (stand-in for
          // socat), then run apply-seccomp. The inner command must not see `sleep`
          // in /proc.
          final wrapped = await wrapCommandWithSandboxLinux(
            LinuxSandboxParams(
              command: [
                'sleep 30 &',
                r'SLEEP_OUTER=$!',
                r'for p in /proc/[0-9]*; do cat "$p/comm" 2>/dev/null; done | grep -qx sleep',
                r'OUTER_SAW=$?',
                "$applySeccomp sh -c '" +
                    r'for p in /proc/[0-9]*; do cat "$p/comm" 2>/dev/null; done | grep -qx sleep; ' +
                    r'echo "INNER_SAW=$?"' +
                    "'",
                r'kill $SLEEP_OUTER 2>/dev/null',
                r'echo "OUTER_SAW=$OUTER_SAW"',
              ].join('\n'),
              needsNetworkRestriction: false,
              writeConfig: FsWriteRestrictionConfig(
                allowOnly: ['/tmp'],
                denyWithinAllow: [],
              ),
              allowAllUnixSockets:
                  true, // we invoke apply-seccomp ourselves here
              // ... and it makes a user namespace of its own, which a wrap with no
              // helper in it otherwise has bubblewrap refuse (--disable-userns).
              allowNestedUserNamespaces: true,
            ),
          );

          final r = spawnSync(
            'bash',
            ['-c', wrapped],
            {'stdio': 'pipe', 'timeout': 15000},
          );
          final out = r.stdout?.toString() ?? '';
          // Outer namespace sees the sleep (grep exit 0), inner does not (grep exit 1).
          expect(out, contains('OUTER_SAW=0'));
          expect(out, contains('INNER_SAW=1'));
        },
      );

      test(
        'cannot ptrace the real bwrap init from inside the sandbox',
        () async {
          // With the normal wrapper (seccomp on), PID 1 from the user command's
          // view is apply-seccomp's non-dumpable init, not bwrap.
          final wrapped = await wrapCommandWithSandboxLinux(
            LinuxSandboxParams(
              command: [
                'python3 -c "',
                'import ctypes, os',
                'libc = ctypes.CDLL(None, use_errno=True)',
                'r = libc.ptrace(16, 1, 0, 0)',
                'err = ctypes.get_errno()',
                'comm = open(\\"/proc/1/comm\\").read().strip()',
                'print(f\\"ptrace={r} errno={err} pid1={comm}\\")',
                '"',
              ].join('\n'),
              needsNetworkRestriction: false,
              writeConfig: FsWriteRestrictionConfig(
                allowOnly: ['/tmp'],
                denyWithinAllow: [],
              ),
            ),
          );

          final r = spawnSync(
            'bash',
            ['-c', wrapped],
            {'stdio': 'pipe', 'timeout': 15000},
          );
          final out = r.stdout?.toString() ?? '';
          expect(out, matches(RegExp(r'ptrace=-1')));
          expect(out, matches(RegExp(r'pid1=apply-seccomp')));
        },
      );

      test('cannot open bwrap /proc/1/mem from inside the sandbox', () async {
        final wrapped = await wrapCommandWithSandboxLinux(
          LinuxSandboxParams(
            command:
                'python3 -c "open(\\"/proc/1/mem\\", \\"r+b\\")" 2>&1 || echo BLOCKED',
            needsNetworkRestriction: false,
            writeConfig: FsWriteRestrictionConfig(
              allowOnly: ['/tmp'],
              denyWithinAllow: [],
            ),
          ),
        );

        final r = spawnSync(
          'bash',
          ['-c', wrapped],
          {'stdio': 'pipe', 'timeout': 15000},
        );
        final out = r.stdout?.toString() ?? '';
        expect(out, contains('BLOCKED'));
        expect(out.toLowerCase(), matches(RegExp(r'permission denied')));
      });
    },
  );
}
