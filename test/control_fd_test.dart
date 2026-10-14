// Ported from sandbox-runtime test/control-fd.test.ts @ 24eb39e.
// ignore_for_file: constant_identifier_names, non_constant_identifier_names, prefer_adjacent_string_concatenation
@Tags(['pending'])
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io' show Platform;

import 'package:path/path.dart' as path;
import 'package:sandbox_runtime/src/node/child_process.dart'
    show ChildProcess, ChildStdin, execFileSync, spawn, spawnSync;
import 'package:sandbox_runtime/src/node/fs.dart' as fs;
import 'package:sandbox_runtime/src/node/os.dart' as os;
import 'package:sandbox_runtime/src/node/process.dart' as process;
import 'package:test/test.dart';

import 'helpers/platform.dart';

// Get the path to the built CLI
// Dart: the CLI is bin/srt.dart, run by the Dart executable in place of `node`.
final CLI_PATH = path.join(process.cwd(), 'bin', 'srt.dart');

// srt is expected to exit on its own shortly after the wrapped command
// (which runs for well under a second) finishes; a hang is a failure, not
// something to wait out. The cap is generous against CI load (the slowest
// job takes about a second per test) but stays under bun's 5 s default
// per-test timeout so the failure names the hang rather than the runner.
const EXIT_TIMEOUT_MS = 4500;

// Extra time for the stdio pipes to close after srt's own exit. It starts
// only once 'exit' has fired, and EXIT_TIMEOUT_MS + this stays under bun's
// 5 s per-test default so a stalled drain still names itself.
const DRAIN_TIMEOUT_MS = 400;

typedef Spawned = ({
  ChildProcess child,
  Future<int?> exited,
  List<String> stdout,
  List<String> stderr,
});

// Resolves on 'close', not 'exit': 'exit' fires while the stdio pipes may
// still hold the command's last chunk, which every stdout assertion here
// would then race. The code comes from 'exit', the only event that carries
// it.
Future<int?> waitForExit(ChildProcess child) {
  final completer = Completer<int?>();
  int? code;
  Timer? drainTimer;
  final exitTimer = Timer(
    const Duration(milliseconds: EXIT_TIMEOUT_MS),
    () => completer.completeError(
      Exception(
        'srt did not exit within ${EXIT_TIMEOUT_MS}ms of the wrapped command',
      ),
    ),
  );
  child.on('exit', (int? c) {
    code = c;
    // srt is gone; only the pipes are still open, which is a different
    // failure (something else holding them) and gets its own deadline.
    exitTimer.cancel();
    drainTimer = Timer(
      const Duration(milliseconds: DRAIN_TIMEOUT_MS),
      () => completer.completeError(
        Exception(
          'srt exited but its stdio did not close within ${DRAIN_TIMEOUT_MS}ms',
        ),
      ),
    );
  });
  child.on('close', () {
    exitTimer.cancel();
    drainTimer?.cancel();
    if (!completer.isCompleted) completer.complete(code);
  });
  child.on('error', (Object err) {
    exitTimer.cancel();
    drainTimer?.cancel();
    if (!completer.isCompleted) completer.completeError(err);
  });
  return completer.future;
}

// srt's own runtime is node (the bin shebang); under `bun test` the same
// dist is exercised through bun as well, whose net.Socket({ fd }) reads
// nothing and whose fs stream does not hold exit — the reason the CLI
// gates on the runtime.
final List<({String name, String bin})> RUNTIMES = [
  (name: 'node', bin: Platform.resolvedExecutable),
  if (process.versions['bun'] != null)
    (name: 'bun', bin: Platform.resolvedExecutable),
];

// One config update, with a domain the debug log will echo back.
final CONFIG_UPDATE = jsonEncode({
  'network': {
    'allowedDomains': ['updated-domain.com'],
    'deniedDomains': [],
  },
  'filesystem': {'denyRead': [], 'allowWrite': [], 'denyWrite': []},
});

// The same, as a sandboxed command would try to inject it.
final INJECTED_UPDATE = jsonEncode({
  'network': {
    'allowedDomains': ['injected-by-the-sandbox.com'],
    'deniedDomains': [],
  },
  'filesystem': {'denyRead': [], 'allowWrite': [], 'denyWrite': []},
});

void main() {
  // mkfifo and /bin/bash; the Windows CI legs run neither this suite nor
  // anything it shells out to.
  group('--control-fd', skip: isWindows ? 'Windows not supported by this port' : null, () {
    late String tmpDir;
    // Every process this file starts, so a test that fails with one still
    // running does not leave it behind.
    var spawned = <ChildProcess>[];
    // fds this side keeps open for the child (a FIFO writer, a file); closed
    // after each test.
    var heldFds = <int>[];

    // Spawn srt and start watching for its exit before anything else happens,
    // so an srt that dies early is reported by its real exit, not as a hang.
    Spawned spawnSrt(
      List<String> args,
      List<Object> stdio, [
      Map<String, String>? env,
      String? runtime,
    ]) {
      runtime ??= Platform.resolvedExecutable;
      final child = spawn(
        runtime,
        [CLI_PATH, ...args],
        {'stdio': stdio, 'env': env},
      );
      spawned.add(child);
      final exited = waitForExit(child);
      // Attached later; a rejection before then must not surface as unhandled.
      exited.then((_) {}, onError: (Object _) {});
      final stdout = <String>[];
      final stderr = <String>[];
      child.stdout?.listen((data) {
        stdout.add(utf8.decode(data));
      });
      child.stderr?.listen((data) {
        stderr.add(utf8.decode(data));
      });
      return (child: child, exited: exited, stdout: stdout, stderr: stderr);
    }

    // Resolves once srt has printed `needle` on stderr, so a test can act on
    // srt's own progress instead of waiting a guessed interval.
    Future<void> waitForStderr(Spawned spawnedSrt, String needle) {
      final completer = Completer<void>();
      final timer = Timer(
        const Duration(milliseconds: EXIT_TIMEOUT_MS),
        () => completer.completeError(
          Exception(
            'srt did not print ${jsonEncode(needle)} within ${EXIT_TIMEOUT_MS}ms',
          ),
        ),
      );
      // spawnSrt's own collector is attached first, so the buffer this
      // reads is already up to date when this runs.
      void check() {
        if (spawnedSrt.stderr.join('').contains(needle)) {
          timer.cancel();
          if (!completer.isCompleted) completer.complete();
        }
      }

      spawnedSrt.child.stderr?.listen((_) => check());
      check();
      return completer.future;
    }

    // For a run that needs nothing written to the control fd while it is in
    // progress: spawnSync keeps the runner's asynchronous child bookkeeping
    // out of it, which matters because this file spawns srt a dozen times
    // over, and it makes a hang a bounded failure rather than a wait.
    ({int? status, String stdout, String stderr}) runSrt(
      List<String> args,
      List<Object> stdio, [
      Map<String, String>? env,
    ]) {
      env ??= process.env;
      final result = spawnSync(
        Platform.resolvedExecutable,
        [CLI_PATH, ...args],
        {
          'stdio': stdio,
          'env': env,
          'encoding': 'utf8',
          'timeout': EXIT_TIMEOUT_MS,
          // srt traps SIGTERM and only forwards it, so the default timeout
          // signal would leave a hung srt alive and spawnSync waiting forever.
          'killSignal': 'SIGKILL',
        },
      );
      if (result.error != null) {
        throw Exception(
          'srt did not exit within ${EXIT_TIMEOUT_MS}ms of the wrapped command: ${(result.error as dynamic).message}',
        );
      }
      return (
        status: result.status,
        stdout: result.stdout as String,
        stderr: result.stderr as String,
      );
    }

    String writeScript(String body) {
      final testScript = path.join(tmpDir, 'test.sh');
      fs.writeFileSync(testScript, '#!/bin/bash\n$body\n', {'mode': 493});
      return testScript;
    }

    setUp(() {
      tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'control-fd-test-'));
      spawned = [];
      heldFds = [];
    });

    tearDown(() async {
      // A no-op once srt has exited on its own, which every test waits for;
      // it only bites when a test already failed with srt still running.
      for (final child in spawned) {
        if (child.exitCode == null && child.signalCode == null) {
          child.kill('SIGKILL');
        }
      }
      spawned = [];
      for (final fd in heldFds) {
        try {
          fs.closeSync(fd);
        } catch (_) {
          // One fd already closed by the test must not skip the rest.
        }
      }
      heldFds = [];
      fs.rmSync(tmpDir, {'recursive': true, 'force': true});
      // Bun's node:child_process shim implements extra stdio 'pipe' entries
      // (fd 3 here) via a unix socket torn down asynchronously after the
      // child exits, and a spawn that races that teardown throws `Failed to
      // connect` (connect ENOENT), so yield briefly before the next test's
      // spawn either way.
      await Future<void>.delayed(const Duration(milliseconds: 50));
    });

    for (final runtime in RUNTIMES) {
      test(
        'should update config when receiving valid JSON on control fd (${runtime.name})',
        () async {
          // Verify through the debug output that the update was applied.
          final testScript = writeScript('sleep 0.3\necho "DONE"');

          // Spawn srt with --control-fd 3, passing fd 3 as a pipe
          final (:child, :exited, :stdout, :stderr) = spawnSrt(
            ['--debug', '--control-fd', '3', '--', testScript],
            ['inherit', 'pipe', 'pipe', 'pipe'],
            {...process.env, 'SRT_DEBUG': 'true'},
            runtime.bin,
          );

          // No wait for srt to initialize: a line written now waits in the
          // pipe buffer until srt attaches its reader.
          final controlFd = child.stdio[3] as ChildStdin;
          controlFd.write('$CONFIG_UPDATE\n');

          // srt must exit by itself once the wrapped command finishes, with the
          // control fd still open on our side.
          expect(await exited, 0);

          // Applied, not rejected: the rejection path names the fd too, so the
          // domain alone would not tell the two apart.
          final allStderr = stderr.join('');
          expect(allStderr, contains('Config updated from control fd'));
          expect(allStderr, contains('updated-domain.com'));
          expect(allStderr, isNot(contains('Invalid config on control fd')));
        },
      );
    }

    test(
      'should apply an update written after the reader is listening',
      () async {
        // Every other case here writes before srt starts, so the line is
        // waiting in the descriptor's buffer when the reader attaches. This one
        // writes once srt has said it is listening, which is the live-update
        // path the flag exists for.
        final testScript = writeScript('sleep 0.3\necho "LIVE_DONE"');

        final spawnedSrt = spawnSrt(
          ['--debug', '--control-fd', '3', '--', testScript],
          ['inherit', 'pipe', 'pipe', 'pipe'],
          {...process.env, 'SRT_DEBUG': 'true'},
        );

        await waitForStderr(spawnedSrt, 'Listening for config updates on fd 3');
        final controlFd = spawnedSrt.child.stdio[3] as ChildStdin;
        controlFd.write('$CONFIG_UPDATE\n');

        expect(await spawnedSrt.exited, 0);
        expect(spawnedSrt.stdout.join(''), contains('LIVE_DONE'));
        final allStderr = spawnedSrt.stderr.join('');
        expect(allStderr, contains('Config updated from control fd'));
        expect(allStderr, contains('updated-domain.com'));
      },
    );

    test(
      'should ignore invalid JSON on control fd and continue running',
      () async {
        final testScript = writeScript('sleep 0.3\necho "COMPLETED"');

        final (:child, :exited, :stdout, stderr: _) = spawnSrt(
          ['--debug', '--control-fd', '3', '--', testScript],
          ['inherit', 'pipe', 'pipe', 'pipe'],
          {...process.env, 'SRT_DEBUG': 'true'},
        );

        final controlFd = child.stdio[3] as ChildStdin;
        controlFd.write('{ invalid json }\n');

        expect(await exited, 0);

        // Process should still complete successfully
        expect(stdout.join(''), contains('COMPLETED'));
      },
    );

    test(
      'should report a rejected update on stderr without SRT_DEBUG',
      () async {
        // The caller has to learn its update was dropped even when srt is not
        // running with --debug, and the line itself must not be echoed back.
        final testScript = writeScript('sleep 0.3\necho "COMPLETED"');
        final env = {...process.env};
        env.remove('SRT_DEBUG');

        final (:child, :exited, :stdout, :stderr) = spawnSrt(
          ['--control-fd', '3', '--', testScript],
          ['inherit', 'pipe', 'pipe', 'pipe'],
          env,
        );

        final controlFd = child.stdio[3] as ChildStdin;
        controlFd.write('{ "network": "not-an-object" }\n');

        expect(await exited, 0);
        expect(stdout.join(''), contains('COMPLETED'));
        final allStderr = stderr.join('');
        expect(allStderr, contains('Invalid config on control fd 3'));
        expect(allStderr, isNot(contains('not-an-object')));
      },
    );

    test('should ignore empty lines on control fd', () async {
      final testScript = writeScript('sleep 0.3\necho "DONE"');

      final (:child, :exited, :stdout, :stderr) = spawnSrt(
        ['--control-fd', '3', '--', testScript],
        ['inherit', 'pipe', 'pipe', 'pipe'],
      );

      final controlFd = child.stdio[3] as ChildStdin;
      controlFd.write('\n');
      controlFd.write('   \n');
      controlFd.write('\t\n');

      expect(await exited, 0);

      // Process should still complete successfully
      expect(stdout.join(''), contains('DONE'));
      expect(stderr.join(''), isNot(contains('Invalid config on control fd')));
    });

    test('should exit with a FIFO control fd the parent keeps open', () async {
      // stdio 'pipe' hands srt a unix socket; a named pipe is what pipe(2),
      // mkfifo and Python's pass_fds embedders hand it, and the fd kind the
      // hang was reported against. The write end stays open for the whole
      // test, so srt only exits if the fd does not keep it alive.
      final fifo = path.join(tmpDir, 'control.fifo');
      execFileSync('mkfifo', [fifo]);
      // O_RDWR: opens without a reader and never delivers EOF to srt.
      final writer = fs.openSync(fifo, fs.constants.O_RDWR);
      heldFds.add(writer);
      final readEnd = fs.openSync(fifo, fs.constants.O_RDONLY);
      heldFds.add(readEnd);

      fs.writeSync(writer, '$CONFIG_UPDATE\n');

      final testScript = writeScript('sleep 0.3\necho "FIFO_DONE"');
      final (:status, :stdout, :stderr) = runSrt(
        ['--debug', '--control-fd', '3', '--', testScript],
        ['inherit', 'pipe', 'pipe', readEnd],
        {...process.env, 'SRT_DEBUG': 'true'},
      );

      expect(status, 0);
      expect(stdout, contains('FIFO_DONE'));
      expect(stderr, contains('Config updated from control fd'));
    });

    test('should read a regular file on the control fd', () {
      // Not a pipe or socket: the fs stream path, which both the fd-kind gate
      // and its fallback lead to, so this pins the branch rather than the
      // choice between them. The update is read to EOF and applied before the
      // command finishes.
      final configFile = path.join(tmpDir, 'control.json');
      fs.writeFileSync(configFile, '$CONFIG_UPDATE\n');
      final fileFd = fs.openSync(configFile, fs.constants.O_RDONLY);
      heldFds.add(fileFd);

      final testScript = writeScript('sleep 0.3\necho "FILE_DONE"');
      final (:status, :stdout, :stderr) = runSrt(
        ['--debug', '--control-fd', '3', '--', testScript],
        ['inherit', 'pipe', 'pipe', fileFd],
        {...process.env, 'SRT_DEBUG': 'true'},
      );

      expect(status, 0);
      expect(stdout, contains('FILE_DONE'));
      expect(stderr, contains('Config updated from control fd'));
    });

    test('should work without --control-fd (backward compat)', () {
      final testScript = writeScript('echo "NO_CONTROL_FD"');

      final (:status, :stdout, stderr: _) = runSrt(
        ['--', testScript],
        ['inherit', 'pipe', 'pipe'],
      );

      expect(status, 0);
      expect(stdout, contains('NO_CONTROL_FD'));
    });

    test('should allow stdin to pass through to child process', () async {
      // Create a script that reads from stdin
      final testScript = writeScript('read line\necho "GOT: \$line"');

      // Spawn with stdin as pipe (not inherit) so we can write to it
      final (:child, :exited, :stdout, stderr: _) = spawnSrt(
        ['--control-fd', '3', '--', testScript],
        ['pipe', 'pipe', 'pipe', 'pipe'],
      );

      // Write to stdin (fd 0)
      final stdin = child.stdin!;
      stdin.write('hello from stdin\n');

      expect(await exited, 0);
      expect(stdout.join(''), contains('GOT: hello from stdin'));
    });

    // A descriptor number that cannot carry a control channel is refused
    // before the sandbox is built, so no command ever runs against a channel
    // that is not there.
    for (final bad in ['abc', '2', '-1']) {
      test('should refuse --control-fd $bad before running anything', () {
        final testScript = writeScript('echo "SHOULD_NOT_RUN"');

        final (:status, :stdout, :stderr) = runSrt(
          ['--control-fd', bad, '--', testScript],
          ['inherit', 'pipe', 'pipe'],
        );

        expect(status, 1);
        expect(stdout, isNot(contains('SHOULD_NOT_RUN')));
        // The flag name alone is in commander's own usage banner; this is the
        // text the parser rejects the value with.
        expect(stderr, contains('must be an integer file descriptor >= 3'));
      });
    }

    // A settings file that lets the wrapped command write to tmpDir, so a
    // marker it fails to leave is evidence that it never ran rather than
    // evidence that the sandbox denied the write.
    String writeWritableSettings() {
      final settings = path.join(tmpDir, 'settings.json');
      fs.writeFileSync(
        settings,
        jsonEncode({
          'network': {'allowedDomains': [], 'deniedDomains': []},
          'filesystem': {
            'denyRead': [],
            'allowRead': [],
            'allowWrite': [tmpDir],
            'denyWrite': [],
          },
        }),
      );
      return settings;
    }

    test('should refuse a control fd it cannot read from', () {
      // A descriptor open for writing only: fstat succeeds on it, so nothing
      // short of asking the kernel whether a read is permitted tells it from
      // a live channel. Running the command would give the caller a sandbox
      // whose updates — including the ones that tighten it — go nowhere.
      final marker = path.join(tmpDir, 'ran');
      final settings = writeWritableSettings();
      final sink = fs.openSync(path.join(tmpDir, 'sink'), 'w');
      heldFds.add(sink);
      final testScript = writeScript('touch $marker\necho "SHOULD_NOT_RUN"');

      final (:status, :stdout, :stderr) = runSrt(
        ['--settings', settings, '--control-fd', '3', '--', testScript],
        ['inherit', 'pipe', 'pipe', sink],
      );

      expect(status, 1);
      expect(stderr, contains('--control-fd 3 is not usable'));
      expect(stdout, isNot(contains('SHOULD_NOT_RUN')));
      expect(fs.existsSync(marker), isFalse);
    });

    test('should refuse to run when the control fd cannot be opened', () {
      // 200 is well past anything node opens for itself, so it is closed in
      // srt and fstat fails on it. Running the command anyway would give the
      // caller a sandbox whose updates — including the ones that tighten it —
      // go nowhere.
      final marker = path.join(tmpDir, 'ran');
      final settings = writeWritableSettings();
      final testScript = writeScript('touch $marker\necho "SHOULD_NOT_RUN"');

      final (:status, :stdout, :stderr) = runSrt(
        ['--settings', settings, '--control-fd', '200', '--', testScript],
        ['inherit', 'pipe', 'pipe'],
      );

      expect(status, 1);
      expect(stderr, contains('--control-fd 200 is not usable'));
      expect(stdout, isNot(contains('SHOULD_NOT_RUN')));
      expect(fs.existsSync(marker), isFalse);
    });

    test('should keep the control fd out of the sandboxed command', () {
      // The descriptor survives into the sandbox at fd 20, and one O_RDWR
      // open of the FIFO is both the caller's end and srt's control fd, so
      // a command that reaches it can write a config srt would then apply.
      final fifo = path.join(tmpDir, 'control.fifo');
      execFileSync('mkfifo', [fifo]);
      // The caller's own end, holding the fifo open and carrying the
      // caller's update, which waits there until srt attaches.
      final caller = fs.openSync(fifo, fs.constants.O_RDWR);
      heldFds.add(caller);
      fs.writeSync(caller, '$CONFIG_UPDATE\n');

      // `>&20` writes through the descriptor the command inherited.
      // `>/dev/fd/20` would not: that re-opens the symlink's target, which
      // succeeds whether the slot holds the fifo or /dev/null.
      final testScript = writeScript(
        'ls -l /proc/self/fd\n' +
            "printf '%s\\n' '$INJECTED_UPDATE' >&20 || echo \"WRITE_REFUSED\"\n" +
            'sleep 0.3\necho "SANDBOX_DONE"',
      );

      // Through a shell's `exec 20<>`, not this runner's stdio array: a
      // descriptor that arrived across an exec carries no close-on-exec
      // flag, which is what makes fd 20 reach the sandboxed command, and
      // it is how an embedder hands srt a control channel in the first
      // place. Descriptors the runner places in a stdio slot come with the
      // flag already set, so they could not show this either way.
      final result = spawnSync(
        'bash',
        [
          '-c',
          'exec 20<>$fifo; exec ${Platform.resolvedExecutable} $CLI_PATH --debug --control-fd 20 -- $testScript',
        ],
        {
          'stdio': ['inherit', 'pipe', 'pipe'],
          'env': {...process.env, 'SRT_DEBUG': 'true'},
          'encoding': 'utf8',
          'timeout': EXIT_TIMEOUT_MS,
          // As in runSrt: srt forwards SIGTERM rather than dying of it.
          'killSignal': 'SIGKILL',
        },
      );
      final status = result.status;
      final stdout = result.stdout as String;
      final stderr = result.stderr as String;

      expect(status, 0);
      expect(stdout, contains('SANDBOX_DONE'));
      // The slot holds srt's read-only /dev/null, so the write fails...
      expect(stdout, contains('WRITE_REFUSED'));
      // ...and that is what is in the slot, not merely something that is
      // not the fifo: an assertion on the fifo's absence alone would also
      // pass on an `ls` that printed nothing at all.
      expect(stdout, matches(RegExp(r'\b20 -> /dev/null')));
      // Nothing written there is ever applied...
      expect(stderr, isNot(contains('injected-by-the-sandbox.com')));
      // ...while the caller's line still is.
      expect(stderr, contains('updated-domain.com'));
    }, skip: isLinux ? null : 'requires Linux');
  });
}
