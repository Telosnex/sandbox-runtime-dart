// Ported from sandbox-runtime test/sandbox/linux-relays-listen.test.ts @ 24eb39e.
// ignore_for_file: constant_identifier_names, non_constant_identifier_names, slash_for_doc_comments
import 'package:path/path.dart' show join;
import 'package:sandbox_runtime/src/node/child_process.dart' show spawnSync;
import 'package:sandbox_runtime/src/node/fs.dart'
    show
        existsSync,
        mkdirSync,
        mkdtempSync,
        realpathSync,
        rmSync,
        writeFileSync;
import 'package:sandbox_runtime/src/node/os.dart' show tmpdir;
import 'package:sandbox_runtime/src/node/process.dart' as process;
import 'package:sandbox_runtime/src/sandbox/linux_sandbox_utils.dart'
    show
        LinuxSandboxParams,
        cleanupBwrapMountPoints,
        wrapCommandWithSandboxLinux;
import 'package:sandbox_runtime/src/sandbox/sandbox_schemas.dart'
    show FsReadRestrictionConfig, FsWriteRestrictionConfig;
import 'package:test/test.dart';

import '../helpers/bwrap_namespace.dart' show bwrapCanNamespaceNetwork;
import '../helpers/platform.dart' show isLinux;

bool has(String program) => spawnSync('which', [program]).status == 0;

void main() {
  /**
   * The two relays inside the sandbox are started in the background. Here a
   * stand-in for socat starts them late, not at all, or without ever listening,
   * and the command's first action is to connect to both ports.
   */
  // Dart: `describe.if(cond)` becomes a group with `skip`; the probes spawn
  // processes, so they run only on Linux.
  final cond = isLinux && bwrapCanNamespaceNetwork() && has('socat');
  group(
    'the relays listen before the command starts',
    skip: cond
        ? null
        : 'requires Linux with bwrap network namespaces and socat',
    () {
      late String dir;
      late String connectFirst;

      setUpAll(() {
        dir = realpathSync(mkdtempSync(join(tmpdir(), 'relays-listen-')));
        for (final socket in ['http.sock', 'socks.sock']) {
          writeFileSync(join(dir, socket), '');
        }
        connectFirst = join(dir, 'connect-first.sh');
        writeFileSync(
          connectFirst,
          'for p in 3128 1080; do\n'
          '  (exec 3<>/dev/tcp/127.0.0.1/\$p) 2>/dev/null && echo "\$p up" || echo "\$p refused"\n'
          'done\n',
        );
      });

      tearDownAll(() {
        cleanupBwrapMountPoints(force: true);
        rmSync(dir, {'recursive': true, 'force': true});
      });

      /** Runs `command` wrapped, with `script` standing in for socat. */
      Future<({List<String> lines, double ms})> run(
        String script, {
        String binShell = 'bash',
        String? command,
        /** A directory put first on the PATH the sandbox starts with. */
        String? firstOnPath,
        bool? allowAllUnixSockets,
      }) async {
        command ??= 'bash $connectFirst';
        final socatPath = join(dir, 'socat-stand-in');
        writeFileSync(socatPath, '#!/bin/sh\n$script\n', {'mode': 493});
        final wrapped = await wrapCommandWithSandboxLinux(
          LinuxSandboxParams(
            command: command,
            needsNetworkRestriction: true,
            httpSocketPath: join(dir, 'http.sock'),
            socksSocketPath: join(dir, 'socks.sock'),
            readConfig: FsReadRestrictionConfig(denyOnly: []),
            writeConfig: FsWriteRestrictionConfig(
              allowOnly: [dir],
              denyWithinAllow: [],
            ),
            socatPath: socatPath,
            binShell: binShell,
            allowAllUnixSockets: allowAllUnixSockets,
          ),
        );
        final started = Stopwatch()..start();
        final result = spawnSync(wrapped, [], {
          'shell': true,
          'encoding': 'utf8',
          'timeout': 30000,
          'env': firstOnPath != null
              ? {...process.env, 'PATH': '$firstOnPath:${process.env['PATH']}'}
              : process.env,
        });
        expect((result.stderr as String?) ?? '', isNot(contains('bwrap:')));
        return (
          lines: (result.stdout as String).trim().split('\n'),
          ms: started.elapsedMicroseconds / 1000,
        );
      }

      // Later than a command needs to get to its first connection, and well
      // within the wait's patience of 0.3 s.
      const late_ = 'sleep 0.1\nexec socat "\$@"';
      final shells = ['bash', 'sh', 'zsh'].where(has).toList();
      for (final binShell in shells) {
        test(
          'finds both relays listening when they start late, under $binShell',
          () async {
            expect((await run(late_, binShell: binShell)).lines, [
              '3128 up',
              '1080 up',
            ]);
          },
        );
      }

      for (final port in [3128, 1080]) {
        test('waits for the relay on $port when it is the later one', () async {
          final later =
              'case "\$1" in *:$port,*) sleep 0.15 ;; esac\nexec socat "\$@"';
          expect((await run(later)).lines, ['3128 up', '1080 up']);
        });
      }

      // There, and never listening.
      const stopped = 'kill -STOP \$\$';

      test(
        'runs out of patience only with a relay that is there and never listens',
        () async {
          final stuck = await run(stopped);
          expect(stuck.lines, ['3128 refused', '1080 refused']);
          // One that has exited is not waited for.
          final exited = await run('exit 1');
          expect(exited.lines, ['3128 refused', '1080 refused']);
          expect(stuck.ms - exited.ms, greaterThan(150));
          expect(stuck.ms - exited.ms, lessThan(1500));
          // And the wait ends when both listen, which every shell has to see.
          for (final binShell in shells) {
            final listening = await run('exec socat "\$@"', binShell: binShell);
            expect(listening.lines, ['3128 up', '1080 up']);
            expect(stuck.ms - listening.ms, greaterThan(150));
          }
        },
      );

      test(
        'starts no program of its own, which would run before the seccomp filter is on',
        () async {
          // What a wait might reach for is planted first on PATH, and the relays
          // stand still, so the wait goes on to the end of its patience.
          final planted = join(dir, 'planted');
          final marker = join(planted, 'RAN');
          mkdirSync(planted);
          for (final name in [
            'sleep',
            'cat',
            'grep',
            'sed',
            'awk',
            'cut',
            'date',
          ]) {
            writeFileSync(
              join(planted, name),
              '#!/bin/sh\necho $name >> $marker\nexit 1\n',
              {'mode': 493},
            );
          }
          for (final binShell in shells) {
            final (:lines, ms: _) = await run(
              stopped,
              binShell: binShell,
              command: 'echo ran',
              firstOnPath: planted,
            );
            expect(lines, ['ran']);
            expect(existsSync(marker), false);
          }
        },
        timeout: const Timeout(Duration(milliseconds: 20000)),
      );

      test(
        'leaves no variable of its own to a command run in the same shell',
        () async {
          // Without the seccomp helper the command is evaluated by the shell
          // that waited.
          final (:lines, ms: _) = await run(
            late_,
            command: "set | grep -c '^_srt_'; bash $connectFirst",
            allowAllUnixSockets: true,
          );
          expect(lines, ['0', '3128 up', '1080 up']);
        },
      );
    },
  );
}
