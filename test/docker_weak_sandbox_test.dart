// Ported from sandbox-runtime test/docker-weak-sandbox.test.ts @ 24eb39e.
// ignore_for_file: constant_identifier_names, non_constant_identifier_names, prefer_adjacent_string_concatenation, dangling_library_doc_comments, slash_for_doc_comments, unintended_html_in_doc_comment
/**
 * End-to-end: run srt as uid 0 inside a container with
 * enableWeakerNestedSandbox and verify the sandbox enforces.
 *
 * Gated on SRT_E2E_DOCKER so `npm test` on the host jobs skips it. CI runs it
 * twice in one container — once holding CAP_SYS_ADMIN, once under
 * `capsh --drop=cap_sys_admin` — because a uid-0 caller is what the
 * capability drop exists for.
 *
 * Invoked by CI via:
 *   docker run --rm \
 *     --security-opt seccomp=unconfined --security-opt apparmor=unconfined \
 *     -v "$PWD:/work" -w /work -e SRT_E2E_DOCKER=1 \
 *     ubuntu:24.04 bash -c '<setup> && bun test test/docker-weak-sandbox.test.ts'
 */
import 'dart:convert';
import 'dart:io' show Platform;

import 'package:path/path.dart' show join;
import 'package:sandbox_runtime/src/node/child_process.dart' show spawnSync;
import 'package:sandbox_runtime/src/node/fs.dart' as fs;
import 'package:sandbox_runtime/src/node/os.dart' show tmpdir;
import 'package:sandbox_runtime/src/node/process.dart' as process;
import 'package:test/test.dart';

final inDocker = process.env['SRT_E2E_DOCKER'] == '1';

void main() {
  group(
    'srt end-to-end as uid 0 in a container',
    skip: inDocker ? null : 'requires SRT_E2E_DOCKER=1',
    () {
      final WORK = join(
        tmpdir(),
        'srt-e2e-${DateTime.now().millisecondsSinceEpoch}',
      );
      final ALLOWED = join(WORK, 'allowed');
      final DENIED = join(WORK, 'denied');
      final SECRET = join(WORK, 'secret');
      final CONFIG = join(WORK, 'srt.json');
      // Same policy without the seccomp helper: the command then runs in bwrap's
      // own namespaces, where --cap-drop ALL is the only thing between it and the
      // deny mounts.
      final CONFIG_NO_SECCOMP = join(WORK, 'srt-no-seccomp.json');
      // umount(8) reports through /proc/self/mountinfo, which under the helper
      // belongs to another pid namespace; call the syscall so the kernel's own
      // errno is what the test reads.
      final UMOUNT_PROBE = join(WORK, 'umount-probe.py');

      // Dart: the CLI is bin/srt.dart, run by the Dart executable in place of
      // `node dist/cli.js`.
      ({int? status, String stdout, String stderr}) srt(
        String cmd, [
        String? config,
      ]) {
        config ??= CONFIG;
        final r = spawnSync(
          Platform.resolvedExecutable,
          [join(process.cwd(), 'bin', 'srt.dart'), '-s', config, '-c', cmd],
          {'encoding': 'utf8', 'timeout': 15000},
        );
        return (
          status: r.status,
          stdout: r.stdout as String,
          stderr: r.stderr as String,
        );
      }

      // Marker first, so a run in which srt never launched cannot pass on the
      // negative assertions alone. Each step then labels its own exit status, so
      // one step succeeding cannot hide behind another's failure, and the script
      // exits with the write's status so `r.status` still reports the escape.
      String escapeAttempt(String out) =>
          'echo SANDBOX-RAN; python3 $UMOUNT_PROBE / $SECRET; ' +
          'mount -o remount,bind,rw / 2>&1; echo "remount-rc=\$?"; ' +
          'cat ${join(SECRET, 'key')} 2>&1; echo "read-secret-rc=\$?"; ' +
          'echo bad > $out 2>&1; w=\$?; echo "write-denied-rc=\$w"; exit \$w';

      // Each labelled step must have failed: present in the output, non-zero.
      void refusedEveryStep(String stdout) {
        expect(
          stdout,
          matches(RegExp(r'^remount-rc=[1-9][0-9]*$', multiLine: true)),
        );
        expect(
          stdout,
          matches(RegExp(r'^read-secret-rc=[1-9][0-9]*$', multiLine: true)),
        );
        expect(
          stdout,
          matches(RegExp(r'^write-denied-rc=[1-9][0-9]*$', multiLine: true)),
        );
      }

      setUpAll(() {
        fs.mkdirSync(ALLOWED, {'recursive': true});
        fs.mkdirSync(DENIED, {'recursive': true});
        fs.mkdirSync(SECRET, {'recursive': true});
        fs.writeFileSync(join(SECRET, 'key'), 'TOPSECRET');
        fs.writeFileSync(
          UMOUNT_PROBE,
          [
            'import ctypes, errno, os, sys',
            "libc = ctypes.CDLL('libc.so.6', use_errno=True)",
            'for target in sys.argv[1:]:',
            '    ctypes.set_errno(0)',
            '    rc = libc.umount2(target.encode(), 0)',
            '    e = ctypes.get_errno()',
            "    print('umount2 %s rc=%d errno=%s (%s)' % (",
            '        target, rc, errno.errorcode.get(e, str(e)), os.strerror(e)))',
            '',
          ].join('\n'),
        );
        final policy = {
          'filesystem': {
            'denyRead': [SECRET],
            'allowWrite': [ALLOWED],
            'denyWrite': [],
          },
          'enableWeakerNestedSandbox': true,
        };
        fs.writeFileSync(
          CONFIG,
          jsonEncode({
            ...policy,
            'network': {'allowedDomains': [], 'deniedDomains': []},
          }),
        );
        fs.writeFileSync(
          CONFIG_NO_SECCOMP,
          jsonEncode({
            ...policy,
            'network': {
              'allowedDomains': [],
              'deniedDomains': [],
              'allowAllUnixSockets': true,
            },
          }),
        );
      });

      tearDownAll(() {
        fs.rmSync(WORK, {'recursive': true, 'force': true});
      });

      test('writes to allowWrite dir', () {
        final out = join(ALLOWED, 'out');
        final r = srt('echo ok > $out');
        expect(r.status, 0);
        expect((fs.readFileSync(out, 'utf8') as String).trim(), 'ok');
      });

      test('blocks write outside allowWrite', () {
        final out = join(DENIED, 'out');
        final r = srt('echo bad > $out');
        expect(r.status, isNot(0));
        expect(fs.existsSync(out), isFalse);
      });

      test('seccomp blocks AF_UNIX socket creation', () {
        final r = srt(
          'python3 -c "import socket; socket.socket(socket.AF_UNIX)"',
        );
        expect(r.status, isNot(0));
        expect(
          r.stderr.toLowerCase(),
          matches(RegExp(r'permission denied|operation not permitted')),
        );
      });

      test('seccomp blocks AF_VSOCK socket creation', () {
        final r = srt(
          'python3 -c "import socket; socket.socket(socket.AF_VSOCK)"',
        );
        expect(r.status, isNot(0));
        expect(r.stderr.toLowerCase(), contains('operation not permitted'));
      });

      test('seccomp allows AF_INET socket creation', () {
        final r = srt(
          'python3 -c "import socket; socket.socket(socket.AF_INET)"',
        );
        expect(r.status, 0);
      });

      // Under the helper the command holds a full capability set in the helper's
      // nested user namespace, so what refuses the unmount is EINVAL: the mounts
      // it inherited were copied across a user-namespace boundary and are locked.
      test('leaves the command no way to unmount a deny (seccomp helper)', () {
        final out = join(DENIED, 'escaped');
        final r = srt(escapeAttempt(out));

        expect(r.stdout, contains('SANDBOX-RAN'));
        expect(r.stdout, contains('umount2 / rc=-1 errno=EINVAL'));
        expect(r.stdout, contains('umount2 $SECRET rc=-1 errno=EINVAL'));
        refusedEveryStep(r.stdout);
        expect(r.status, isNot(0));
        expect(r.stdout, isNot(contains('TOPSECRET')));
        expect(fs.existsSync(out), isFalse);
      });

      // Without the helper there is no nested namespace and no locked copies:
      // --cap-drop ALL is the whole barrier, and the kernel refuses with EPERM
      // because the command holds no CAP_SYS_ADMIN in bwrap's user namespace.
      test(
        'leaves the command no way to unmount a deny (no seccomp helper)',
        () {
          final out = join(DENIED, 'escaped-no-seccomp');
          final r = srt(escapeAttempt(out), CONFIG_NO_SECCOMP);

          expect(r.stdout, contains('SANDBOX-RAN'));
          expect(r.stdout, contains('umount2 / rc=-1 errno=EPERM'));
          expect(r.stdout, contains('umount2 $SECRET rc=-1 errno=EPERM'));
          refusedEveryStep(r.stdout);
          expect(r.status, isNot(0));
          expect(r.stdout, isNot(contains('TOPSECRET')));
          expect(fs.existsSync(out), isFalse);
        },
      );
    },
  );
}
