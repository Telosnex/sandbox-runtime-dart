// Ported from sandbox-runtime test/sandbox/linux-nested-userns.test.ts @ 0bbebed.

// ignore_for_file: prefer_function_declarations_over_variables, unnecessary_brace_in_string_interps, empty_statements, prefer_interpolation_to_compose_strings, curly_braces_in_flow_control_structures
// ignore_for_file: constant_identifier_names, non_constant_identifier_names, slash_for_doc_comments, prefer_adjacent_string_concatenation
import 'dart:async';
import 'dart:convert';
import 'dart:io' show Platform;
import 'package:test/test.dart';
import 'package:sandbox_runtime/src/node/child_process.dart';
import 'package:sandbox_runtime/src/node/fs.dart';
import 'package:sandbox_runtime/src/node/os.dart';
import 'package:sandbox_runtime/src/node/path.dart';
import 'package:sandbox_runtime/src/node/process.dart' as process;
import 'package:sandbox_runtime/src/sandbox/sandbox_schemas.dart';
import 'package:sandbox_runtime/src/sandbox/linux_sandbox_utils.dart';
import 'package:sandbox_runtime/src/sandbox/sandbox_manager.dart';
import 'package:sandbox_runtime/src/sandbox/sandbox_config.dart';
import 'package:sandbox_runtime/src/sandbox/generate_seccomp_filter.dart';
import 'package:sandbox_runtime/src/utils/which.dart';
import '../helpers/platform.dart';
import '../helpers/bwrap_namespace.dart';

// upstream: import { spawn, spawnSync } from 'node:child_process'
// upstream: import { chmodSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, statSync, writeFileSync, } from 'node:fs'
// upstream: import { tmpdir } from 'node:os'
// upstream: import { join } from 'node:path'

/**
 * A sandboxed command that can create a user namespace can undo the write
 * denies (see NESTED_USERNS_ENV in linux-sandbox-utils.ts), so it must not be
 * able to unless the caller allows it.
 *
 * CHAIN does the whole thing rather than stopping at the first call, so that
 * the arms which expect it to fail would see the file replaced if it did
 * not, and the arm which allows it shows that it then does replace the file.
 */
final CHAIN = r'''
import ctypes, errno, os, platform, sys
libc = ctypes.CDLL(None, use_errno=True)
CLONE_NEWNS, CLONE_NEWUSER = 0x00020000, 0x10000000
MS_REC, MS_PRIVATE, MNT_DETACH = 16384, 1 << 18, 2
PIVOT_ROOT = {'x86_64': 155, 'aarch64': 41}[platform.machine()]
project = sys.argv[1]
uid, gid = os.getuid(), os.getgid()
# Before anything else: a handle on the directory holding the denied file.
holder = os.open(os.path.join(project, '.git'), os.O_PATH | os.O_DIRECTORY)

def name(e):
    return errno.errorcode.get(e, str(e))

def replace():
    try:
        os.rename('config', 'config.aside', src_dir_fd=holder, dst_dir_fd=holder)
        fd = os.open('config', os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644, dir_fd=holder)
        os.write(fd, b'[core]\n\tplanted = true\n')
        os.close(fd)
        return 'replaced'
    except OSError as e:
        return 'refused ' + name(e.errno)

def call(what, rc):
    if rc != 0:
        raise OSError(ctypes.get_errno(), what)

print('in-the-sandbox-namespaces:', replace())
try:
    call('unshare', libc.unshare(CLONE_NEWUSER | CLONE_NEWNS))
    print('new-namespaces: ok')
    open('/proc/self/setgroups', 'w').write('deny')
    open('/proc/self/uid_map', 'w').write('0 %d 1' % uid)
    open('/proc/self/gid_map', 'w').write('0 %d 1' % gid)
    call('make-private', libc.mount(None, b'/', None, MS_REC | MS_PRIVATE, None))
    onto = b'/usr' if os.path.isdir('/usr') else b'/tmp'
    call('tmpfs', libc.mount(b'tmpfs', onto, b'tmpfs', 0, None))
    os.chdir(onto)
    os.mkdir('old')
    call('pivot_root', libc.syscall(PIVOT_ROOT, b'.', b'old'))
    call('detach', libc.umount2(b'/old', MNT_DETACH))
    print('in-its-own-namespaces:', replace())
except OSError as e:
    print('new-namespaces: refused %s at %s' % (name(e.errno), e.strerror))
''';

// What the other of the helper's two filters refuses. Allowing a command
// namespaces of its own takes one filter away, not both.
final UNIX_SOCKET = r'''
import errno, socket
try:
    socket.socket(socket.AF_UNIX).close()
    print('unix-socket: made')
except OSError as e:
    print('unix-socket: refused', errno.errorcode.get(e.errno, e.errno))
''';

void main() {
  group('Linux sandbox — the command stays in the namespaces made for it', () {
    late String BASE;
    late String PROJECT;
    late String SCRIPT;
    final savedCwd = process.cwd();
    final ORIGINAL = '[core]\n\trepositoryformatversion = 0\n';

    final BWRAP_CAN_NAMESPACE = isLinux && bwrapCanNamespace();
    // Built in CI; absent elsewhere, where the arms that need it must skip
    // visibly rather than quietly run without the seccomp stage.
    final APPLY_SECCOMP = getApplySeccompBinaryPath();
    final PYTHON = whichSync('python3');
    final CAN_RUN_CHAIN =
        BWRAP_CAN_NAMESPACE &&
        PYTHON != null &&
        (process.arch == 'x64' || process.arch == 'arm64');
    final BWRAP = whichSync('bwrap');
    // Bubblewrap's own word, had by using the option, not that of the function
    // under test: gated on that, a probe that wrongly said no would turn every
    // arm below that needs the option into a skip.
    final BWRAP_DISABLES_USERNS =
        isLinux &&
        BWRAP != null &&
        spawnSync(
              BWRAP,
              [
                '--unshare-user',
                '--disable-userns',
                '--ro-bind',
                '/',
                '/',
                'true',
              ],
              {'stdio': 'ignore', 'timeout': 5000},
            ).status ==
            0;

    setUp(() {
      BASE = realpathSync(mkdtempSync(join(tmpdir(), 'nested-userns-')));
      PROJECT = join(BASE, 'project');
      mkdirSync(join(PROJECT, '.git', 'hooks'), {'recursive': true});
      writeFileSync(join(PROJECT, '.git', 'config'), ORIGINAL);
      SCRIPT = join(BASE, 'chain.py');
      writeFileSync(SCRIPT, CHAIN);
      process.chdir(PROJECT);
    });

    tearDown(() {
      process.chdir(savedCwd);
      cleanupBwrapMountPoints(force: true);
      rmSync(BASE, {'recursive': true, 'force': true});
    });

    Future<String> wrap(
      String command, [
      Map<String, Object?> options = const {},
    ]) {
      return wrapCommandWithSandboxLinux(
        LinuxSandboxParams(
          command: command,
          needsNetworkRestriction: false,
          readConfig: FsReadRestrictionConfig(
            denyOnly: [],
            allowWithinDeny: [],
          ),
          writeConfig: FsWriteRestrictionConfig(
            allowOnly: [PROJECT],
            denyWithinAllow: [],
          ),
          allowNestedUserNamespaces:
              options['allowNestedUserNamespaces'] as bool?,
          allowAllUnixSockets: options['allowAllUnixSockets'] as bool?,
          enableWeakerNestedSandbox:
              options['enableWeakerNestedSandbox'] as bool?,
          bwrapPath: options['bwrapPath'] as String?,
        ),
      );
    }

    SpawnSyncResult run(String command, [Map<String, String>? env]) {
      return spawnSync(command, [], {
        'shell': true,
        'encoding': 'utf8',
        'timeout': 30000,
        'env': env ?? process.env,
      });
    }

    final hostConfig = () =>
        readFileSync(join(PROJECT, '.git', 'config'), 'utf8') as String;

    // A stand-in for bubblewrap that prints `help` whatever it is asked.
    String fakeBwrap(String name, String help, [int mode = 493]) {
      final path = join(BASE, name);
      writeFileSync(path, '#!/bin/sh\ncat <<\'EOF\'\n${help}\nEOF\n');
      // Not through writeFileSync's mode, which the umask would trim.
      chmodSync(path, mode);
      return path;
    }

    final HELP_WITHOUT = 'usage: bwrap [OPTIONS...] [--] COMMAND [ARGS...]\n';
    final HELP_WITH =
        HELP_WITHOUT +
        '    --disable-userns             Disable further use of user namespaces inside sandbox';

    // The seccomp lines of a process's status file, which anyone may read.
    ({int? mode, int? filters, int? noNewPrivs}) seccompStatus(Object pid) {
      final status = readFileSync('/proc/$pid/status', 'utf8') as String;
      int? line(String name) {
        final found = RegExp(
          '^$name:' + r'\s*(\d+)$',
          multiLine: true,
        ).firstMatch(status);
        return found != null ? int.parse(found[1]!) : null;
      }

      return (
        mode: line('Seccomp'),
        // Linux 5.9 and later.
        filters: line('Seccomp_filters'),
        noNewPrivs: line('NoNewPrivs'),
      );
    }

    // Starts the helper on its own with a command that stays a while, and
    // reads those lines for the process that was started: the outer half.
    Future<({int? mode, int? filters, int? noNewPrivs})> outerHalfSeccompStatus(
      bool allowNestedUserNamespaces,
    ) async {
      final env = {...process.env};
      env.remove('SRT_ALLOW_NESTED_USERNS');
      if (allowNestedUserNamespaces) env['SRT_ALLOW_NESTED_USERNS'] = '1';
      final child = spawn(
        APPLY_SECCOMP!,
        ['/bin/sleep', '3'],
        {
          'stdio': ['ignore', 'ignore', 'pipe'],
          'env': env,
        },
      );
      var stderr = '';
      child.stderr!.listen((d) => stderr += utf8.decode(d));
      // Listened for from the start: a helper that has already gone by the
      // time the wait below is over emitted its event then.
      final ended = Completer<String>();
      child.once('exit', (code, signal) {
        if (!ended.isCompleted)
          ended.complete('exited (code=$code, signal=$signal)');
      });
      child.once('error', (err) {
        if (!ended.isCompleted) ended.complete('failed to spawn: $err');
      });
      try {
        // Setting up is a handful of system calls.
        final early = await Future.any<String?>([
          ended.future,
          Future<String?>.delayed(const Duration(milliseconds: 500)),
        ]);
        if (early != null) {
          throw Exception(
            'the helper $early before it could be looked at; stderr: ${stderr.trim().isNotEmpty ? stderr.trim() : '(empty)'}',
          );
        }
        return seccompStatus(child.pid!);
      } finally {
        child.kill('SIGKILL');
        await ended.future;
      }
    }

    // ---- what the wrap emits -------------------------------------------

    test(
      'clears the helper variable on every wrap, whatever is asked for',
      () async {
        for (final allowNestedUserNamespaces in [null, false, true]) {
          final command = await wrap('true', {
            'allowNestedUserNamespaces': allowNestedUserNamespaces,
          });
          expect(command, contains('--unsetenv SRT_ALLOW_NESTED_USERNS'));
        }
      },
    );

    test(
      'gives bubblewrap --disable-userns exactly when there is no helper and namespaces are not allowed',
      () async {
        expect(
          await wrap('true', {'allowAllUnixSockets': true}),
          contains('--disable-userns'),
        );
        expect(
          await wrap('true', {
            'allowAllUnixSockets': true,
            'allowNestedUserNamespaces': true,
          }),
          isNot(contains('--disable-userns')),
        );
        // Nothing but true allows them, as with the helper.
        // for (const given of ['yes', 1]) {
        //   expect(
        //     await wrap('true', {
        //       allowAllUnixSockets: true,
        //       allowNestedUserNamespaces: given as unknown as boolean,
        //     }),
        //   ).toContain('--disable-userns')
        // }
        // Bubblewrap would die on an unprivileged container's /proc/sys.
        expect(
          await wrap('true', {
            'allowAllUnixSockets': true,
            'enableWeakerNestedSandbox': true,
          }),
          isNot(contains('--disable-userns')),
        );
      },
      skip:
          'Dart types reject a non-bool allowNestedUserNamespaces at compile time',
    );

    test(
      'never gives bubblewrap --disable-userns beside the helper, which makes a namespace of its own',
      () async {
        expect(await wrap('true'), isNot(contains('--disable-userns')));
      },
      skip: (APPLY_SECCOMP != null) ? false : 'requires APPLY_SECCOMP !== null',
    );

    // ---- what bubblewrap is found to support ----------------------------

    test(
      'takes the option from the help of a bubblewrap that is not setuid, and from nowhere else',
      () {
        expect(bwrapCanDisableUserns(fakeBwrap('old', HELP_WITHOUT)), isFalse);
        expect(bwrapCanDisableUserns(fakeBwrap('new', HELP_WITH)), isTrue);
        // Such a binary lists the option and refuses it.
        final setuid = fakeBwrap('setuid', HELP_WITH, 2541);
        expect(statSync(setuid).mode & 2048, 2048);
        expect(bwrapCanDisableUserns(setuid), isFalse);
        expect(bwrapCanDisableUserns(join(BASE, 'no-such-bwrap')), isFalse);
      },
    );

    test(
      'a bubblewrap that did not say is asked again, and one that did is not',
      () {
        final bwrap = fakeBwrap('silent-at-first', '');
        expect(bwrapCanDisableUserns(bwrap), isFalse);
        // Not having been able to ask is not an answer to keep.
        fakeBwrap('silent-at-first', HELP_WITH);
        expect(bwrapCanDisableUserns(bwrap), isTrue);
        // What a binary supports is: one answer for the life of the process.
        fakeBwrap('silent-at-first', HELP_WITHOUT);
        expect(bwrapCanDisableUserns(bwrap), isTrue);
      },
    );

    test(
      'with no helper, only a bubblewrap that can impose the limit is given the option',
      () async {
        for (final bwrapPath in [
          fakeBwrap('old', HELP_WITHOUT),
          fakeBwrap('setuid', HELP_WITH, 2541),
        ]) {
          expect(
            await wrap('true', {
              'allowAllUnixSockets': true,
              'bwrapPath': bwrapPath,
            }),
            isNot(contains('--disable-userns')),
          );
        }
        expect(
          await wrap('true', {
            'allowAllUnixSockets': true,
            'bwrapPath': fakeBwrap('new', HELP_WITH),
          }),
          contains('--disable-userns'),
        );
      },
    );

    test(
      'says once per process that nothing limits namespaces, and only where that is so',
      () {
        // A process of its own: the warning is given once in each.
        final script =
            """
          import 'package:sandbox_runtime/src/sandbox/linux_sandbox_utils.dart';
          import 'package:sandbox_runtime/src/sandbox/sandbox_schemas.dart';
          import 'dart:io';
          Future<void> main() async {
            Future<String> wrap(String bwrapPath) => wrapCommandWithSandboxLinux(LinuxSandboxParams(
              command: 'true', needsNetworkRestriction: false,
              writeConfig: FsWriteRestrictionConfig(allowOnly: [], denyWithinAllow: []),
              allowAllUnixSockets: true, bwrapPath: bwrapPath,
            ));
            await wrap(${jsonEncode(fakeBwrap('new', HELP_WITH))});
            stderr.writeln('-- limited above, not below --');
            await wrap(${jsonEncode(fakeBwrap('old', HELP_WITHOUT))});
            await wrap(${jsonEncode(fakeBwrap('setuid', HELP_WITH, 2541))});
          }
        """;
        final scriptFile = join(BASE, 'warning.dart');
        writeFileSync(scriptFile, script);
        final child = spawnSync(
          Platform.resolvedExecutable,
          [
            '--packages=${join(savedCwd, '.dart_tool/package_config.json')}',
            scriptFile,
          ],
          {
            'encoding': 'utf8',
            'timeout': 60000,
            'env': {...process.env, 'SRT_DEBUG': '1'},
          },
        );
        expect(child.status, 0);
        final split = (child.stderr as String).split(
          '-- limited above, not below --',
        );
        final limited = split[0];
        final notLimited = split.length > 1 ? split[1] : null;
        List<String> warnings(String? said) => (said ?? '')
            .split('\n')
            .where((l) => RegExp(r'undo the write denies').hasMatch(l))
            .toList();
        expect(warnings(limited), []);
        expect(warnings(notLimited), hasLength(1));
      },
    );

    // ---- the helper's outer half ------------------------------------------

    test(
      "the helper's outer half takes the namespaces filter as well, and leaves it out where namespaces are allowed",
      () async {
        // Counted from what this process is under itself, which a container
        // or a sandboxed shell may have put there.
        final own = seccompStatus('self');
        final kept = await outerHalfSeccompStatus(false);
        expect(kept.mode, 2);
        expect(kept.noNewPrivs, 1);
        if (own.filters != null) {
          expect(kept.filters, own.filters! + 1);
        }
        // The control: nothing is added, so the filter seen above is the
        // one the option takes away.
        final lifted = await outerHalfSeccompStatus(true);
        expect(lifted.mode, own.mode);
        expect(lifted.filters, own.filters);
      },
      skip: (APPLY_SECCOMP != null) ? false : 'requires APPLY_SECCOMP !== null',
      timeout: Timeout(Duration(milliseconds: 15000)),
    );

    // ---- from the configuration to the wrap -----------------------------

    // On the helper's own command line, which holds against a shell start-up
    // file the caller's environment names (see helperEnvironmentPrefix).
    test(
      'SandboxManager hands the option from its configuration to the wrap',
      () async {
        SandboxRuntimeConfig configured([bool? allowNestedUserNamespaces]) =>
            SandboxRuntimeConfig(
              network: NetworkConfig(allowedDomains: [], deniedDomains: []),
              filesystem: FilesystemConfig(
                denyRead: [],
                allowWrite: [FilesystemPathSpelling(PROJECT)],
                denyWrite: [],
              ),
              allowNestedUserNamespaces: allowNestedUserNamespaces,
            );
        final before = SandboxManager.getConfig();
        try {
          SandboxManager.updateConfig(configured(true));
          expect(
            await SandboxManager.wrapWithSandbox('true'),
            contains('SRT_ALLOW_NESTED_USERNS=1 ${APPLY_SECCOMP}'),
          );
          SandboxManager.updateConfig(configured());
          expect(
            await SandboxManager.wrapWithSandbox('true'),
            contains('SRT_ALLOW_NESTED_USERNS=0 ${APPLY_SECCOMP}'),
          );
        } finally {
          // The configuration outlives a reset, and the next file's tests.
          SandboxManager.updateConfig(before ?? configured());
        }
      },
      skip: (APPLY_SECCOMP != null) ? false : 'requires APPLY_SECCOMP !== null',
    );

    test(
      'a single wrap can be given the option, either way, and nothing but true lifts the limit',
      () async {
        SandboxRuntimeConfig configured([bool? allowNestedUserNamespaces]) =>
            SandboxRuntimeConfig(
              network: NetworkConfig(allowedDomains: [], deniedDomains: []),
              filesystem: FilesystemConfig(
                denyRead: [],
                allowWrite: [FilesystemPathSpelling(PROJECT)],
                denyWrite: [],
              ),
              allowNestedUserNamespaces: allowNestedUserNamespaces,
            );
        Future<String> wrapGiven(Object? allowNestedUserNamespaces) =>
            SandboxManager.wrapWithSandbox(
              'true',
              null,
              PartialSandboxRuntimeConfig(
                allowNestedUserNamespaces: allowNestedUserNamespaces as bool?,
              ),
            );
        final before = SandboxManager.getConfig();
        try {
          for (final (session, given, said) in <(bool?, Object?, int)>[
            (false, true, 1),
            (null, true, 1),
            (true, false, 0),
            (true, null, 1),
            (false, null, 0),
            // [false, 'yes', 0],
            // [false, 1, 0],
          ]) {
            SandboxManager.updateConfig(configured(session));
            expect(
              [session, given, await wrapGiven(given)],
              [
                session,
                given,
                contains('SRT_ALLOW_NESTED_USERNS=${said} ${APPLY_SECCOMP}'),
              ],
            );
          }
          // The one before it leaves nothing behind for the next.
          SandboxManager.updateConfig(configured(false));
          await wrapGiven(true);
          expect(
            await SandboxManager.wrapWithSandbox('true'),
            contains('SRT_ALLOW_NESTED_USERNS=0 ${APPLY_SECCOMP}'),
          );
        } finally {
          // The configuration outlives a reset, and the next file's tests.
          SandboxManager.updateConfig(before ?? configured());
        }
      },
      skip:
          'Dart types reject a non-bool allowNestedUserNamespaces at compile time',
    );

    // ---- live ------------------------------------------------------------

    test(
      'with the helper: a new user namespace is refused and the denied file is not replaced (live bwrap)',
      () async {
        // The caller's own environment must not be able to lift it.
        final result = run(await wrap('${PYTHON} ${SCRIPT} ${PROJECT}'), {
          ...process.env,
          'SRT_ALLOW_NESTED_USERNS': '1',
        });
        final said = '${result.stdout}${result.stderr}';
        expect(said, contains('in-the-sandbox-namespaces: refused EBUSY'));
        // EPERM, the filter's answer, which comes before the kernel looks at
        // the limit (that one reads ENOSPC).
        expect(said, contains('new-namespaces: refused EPERM at unshare'));
        expect(said, isNot(contains('in-its-own-namespaces: replaced')));
        expect(hostConfig(), ORIGINAL);
      },
      skip: (CAN_RUN_CHAIN && APPLY_SECCOMP != null)
          ? false
          : 'requires CAN_RUN_CHAIN && APPLY_SECCOMP !== null',
      timeout: Timeout(Duration(milliseconds: 60000)),
    );

    test(
      'with the helper: both means are in force, each call answered by the filter and not by the kernel (live bwrap)',
      () async {
        // Every call below is made so that the kernel, asked, would say
        // something other than EPERM to a command with no capabilities: bad
        // arguments are looked at before permission, open_tree of "/" needs
        // none, and a second user namespace under a limit of zero is ENOSPC.
        // So EPERM is the filter, and a filter missing the rule for one of
        // these shows here. The other five (pivot_root, move_mount, fsopen,
        // fsmount, fspick) the kernel itself answers with EPERM for a caller
        // without the capability, so only the generator's test pins them.
        final probe = [
          'import ctypes, errno, os, platform',
          'libc = ctypes.CDLL(None, use_errno=True)',
          'arch = platform.machine()',
          "NR = {'clone': {'x86_64': 56, 'aarch64': 220}[arch], 'setns': {'x86_64': 308, 'aarch64': 268}[arch],",
          "      'unshare': {'x86_64': 272, 'aarch64': 97}[arch], 'clone3': 435, 'open_tree': 428, 'fsconfig': 431,",
          "      'mount_setattr': 442}",
          'def said(label, rc):',
          "    print(label, 'ok' if rc >= 0 else errno.errorcode.get(ctypes.get_errno()))",
          "print('limit', open('/proc/sys/user/max_user_namespaces').read().strip())",
          'NEWUSER, SIGCHLD, AT_FDCWD = 0x10000000, 17, -100',
          "said('unshare', libc.unshare(NEWUSER))",
          // High bits set beside the flag: the rule masks, it does not compare.
          "said('unshare-high-bits', libc.syscall(NR['unshare'], ctypes.c_ulong(NEWUSER | (1 << 40))))",
          // A flag of unshare(2) alone, which a kernel without it calls EINVAL.
          "said('unshare-empty-mntns', libc.unshare(0x00100000))",
          "said('clone', libc.syscall(NR['clone'], ctypes.c_ulong(NEWUSER | SIGCHLD), None, None, None, None))",
          "said('clone3', libc.syscall(NR['clone3'], None, 0))",
          "said('setns', libc.syscall(NR['setns'], -1, 0))",
          "said('open_tree', libc.syscall(NR['open_tree'], AT_FDCWD, b'/', 0))",
          "said('mount', libc.mount(None, None, None, 0, None))",
          "said('umount2', libc.umount2(None, 0))",
          // The descriptor is looked at before the caller: EINVAL.
          "said('fsconfig', libc.syscall(NR['fsconfig'], -1, 0, None, None, 0))",
          "said('mount_setattr', libc.syscall(NR['mount_setattr'], -1, b'', 0, None, 0))",
          // Newer than the libseccomp the helper is commonly built with, so
          // it is in the filter by number; a kernel without it says ENOSYS.
          "said('open_tree_attr', libc.syscall(467, AT_FDCWD, b'/', 0, None, 0))",
          // Not refused: a plain fork.
          'pid = os.fork()',
          'if pid == 0: os._exit(0)',
          "said('fork', os.waitpid(pid, 0)[1])",
        ].join('\n');
        writeFileSync(join(BASE, 'probe.py'), probe);
        final result = run(await wrap('${PYTHON} ${join(BASE, 'probe.py')}'));
        final said = '${result.stdout}${result.stderr}';
        expect(said, contains('limit 0'));
        for (final call in [
          'unshare',
          'unshare-high-bits',
          'unshare-empty-mntns',
          'clone',
          'setns',
          'open_tree',
          'mount',
          'umount2',
          'fsconfig',
          'mount_setattr',
          'open_tree_attr',
        ]) {
          expect(said, contains('${call} EPERM'));
        }
        expect(said, contains('clone3 ENOSYS'));
        expect(said, contains('fork ok'));
      },
      skip: (CAN_RUN_CHAIN && APPLY_SECCOMP != null)
          ? false
          : 'requires CAN_RUN_CHAIN && APPLY_SECCOMP !== null',
      timeout: Timeout(Duration(milliseconds: 60000)),
    );

    test(
      "the same calls get the kernel's own answers where nothing refuses them, so EPERM above is the filter (live bwrap)",
      () async {
        // The control for the test above: no helper, and namespaces allowed,
        // so the filter is not there.
        final probe = [
          'import ctypes, errno, platform',
          'libc = ctypes.CDLL(None, use_errno=True)',
          'arch = platform.machine()',
          'def said(label, rc):',
          "    print(label, 'ok' if rc >= 0 else errno.errorcode.get(ctypes.get_errno()))",
          "said('setns', libc.syscall({'x86_64': 308, 'aarch64': 268}[arch], -1, 0))",
          "said('open_tree', libc.syscall(428, -100, b'/', 0))",
          "said('mount', libc.mount(None, None, None, 0, None))",
          "said('fsconfig', libc.syscall(431, -1, 0, None, None, 0))",
          "said('mount_setattr', libc.syscall(442, -1, b'', 0, None, 0))",
        ].join('\n');
        writeFileSync(join(BASE, 'control.py'), probe);
        writeFileSync(join(BASE, 'unix-socket.py'), UNIX_SOCKET);
        final result = run(
          await wrap(
            '${PYTHON} ${join(BASE, 'control.py')}; ${PYTHON} ${join(BASE, 'unix-socket.py')}',
            {'allowAllUnixSockets': true, 'allowNestedUserNamespaces': true},
          ),
        );
        final said = '${result.stdout}${result.stderr}';
        expect(said, contains('setns EBADF'));
        expect(said, contains('open_tree ok'));
        expect(said, isNot(contains('mount EPERM')));
        expect(said, contains('fsconfig EINVAL'));
        expect(said, isNot(contains('mount_setattr EPERM')));
        // And with neither filter there, a Unix socket can be had.
        expect(said, contains('unix-socket: made'));
      },
      skip: (CAN_RUN_CHAIN) ? false : 'requires CAN_RUN_CHAIN',
      timeout: Timeout(Duration(milliseconds: 60000)),
    );

    test(
      'with the helper: threads and child processes still start (live bwrap)',
      () async {
        final program = [
          'import subprocess, threading',
          'seen = []',
          'threads = [threading.Thread(target=lambda: seen.append(1)) for _ in range(8)]',
          '[t.start() for t in threads]; [t.join() for t in threads]',
          "print('threads', len(seen), subprocess.run(['echo', 'child'], capture_output=True, text=True).stdout.strip())",
        ].join('\n');
        writeFileSync(join(BASE, 'program.py'), program);
        final result = run(await wrap('${PYTHON} ${join(BASE, 'program.py')}'));
        expect(result.stdout, contains('threads 8 child'));
      },
      skip: (CAN_RUN_CHAIN && APPLY_SECCOMP != null)
          ? false
          : 'requires CAN_RUN_CHAIN && APPLY_SECCOMP !== null',
      timeout: Timeout(Duration(milliseconds: 60000)),
    );

    test(
      'with the helper and namespaces allowed: the same chain does replace the file (live bwrap)',
      () async {
        writeFileSync(join(BASE, 'unix-socket.py'), UNIX_SOCKET);
        final result = run(
          await wrap(
            'echo "seen=[\${SRT_ALLOW_NESTED_USERNS:-unset}]"; ' +
                '${PYTHON} ${join(BASE, 'unix-socket.py')}; ' +
                '${PYTHON} ${SCRIPT} ${PROJECT}',
            {'allowNestedUserNamespaces': true},
          ),
        );
        final said = '${result.stdout}${result.stderr}';
        // The helper was told, and took the variable out before the command.
        expect(said, contains('seen=[unset]'));
        // Only the namespaces filter is left out. The other one stays.
        expect(said, contains('unix-socket: refused EPERM'));
        expect(said, contains('new-namespaces: ok'));
        expect(said, contains('in-its-own-namespaces: replaced'));
        // This is what the refusals above prevent.
        expect(hostConfig(), contains('planted = true'));
      },
      skip: (CAN_RUN_CHAIN && APPLY_SECCOMP != null)
          ? false
          : 'requires CAN_RUN_CHAIN && APPLY_SECCOMP !== null',
      timeout: Timeout(Duration(milliseconds: 60000)),
    );

    test(
      'without the helper: bubblewrap refuses the new namespace and the file is not replaced (live bwrap)',
      () async {
        final result = run(
          await wrap('${PYTHON} ${SCRIPT} ${PROJECT}', {
            'allowAllUnixSockets': true,
          }),
        );
        final said = '${result.stdout}${result.stderr}';
        expect(said, isNot(contains('bwrap:')));
        expect(said, contains('in-the-sandbox-namespaces: refused EBUSY'));
        expect(
          said,
          matches(RegExp(r'new-namespaces: refused (ENOSPC|EPERM) at unshare')),
        );
        expect(hostConfig(), ORIGINAL);
      },
      skip: (CAN_RUN_CHAIN && BWRAP_DISABLES_USERNS)
          ? false
          : 'requires CAN_RUN_CHAIN && BWRAP_DISABLES_USERNS',
      timeout: Timeout(Duration(milliseconds: 60000)),
    );
  }, skip: (isLinux) ? false : 'requires isLinux');
}
