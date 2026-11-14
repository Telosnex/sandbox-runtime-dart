// Ported from sandbox-runtime test/helpers/spawn.ts @ 0bbebed.
// ignore_for_file: slash_for_doc_comments
import 'dart:async';
import 'dart:convert';
import 'dart:io';

class RunOpts {
  const RunOpts({this.shell, this.encoding, this.timeout, this.cwd, this.env});

  final bool? shell;
  final String? encoding; // 'utf8'
  final int? timeout;
  final String? cwd;
  final Map<String, String>? env;
}

typedef RunResult = ({
  String stdout,
  String stderr,
  int? status,
  String? signal,
});

/**
 * Async stand-in for spawnSync, for tests that drive a wrapped command
 * which talks back to the in-process HTTP/SOCKS proxy. spawnSync would
 * block this event loop while curl waits for that same proxy to respond,
 * which is a self-deadlock — bun 1.3.2+ runs spawnSync on an isolated
 * loop so the main loop's I/O never ticks during the wait.
 *
 * Mirrors enough of spawnSync's surface for the test call sites:
 *   - (cmd, opts)            → shell:true by default
 *   - (cmd, args[], opts)    → argv form, no shell
 *   - opts.timeout           → SIGTERM after N ms (like spawnSync)
 *   - stdin                  → closed immediately (EOF), like spawnSync
 *                              with no `input`
 */
Future<RunResult> spawnAsync(
  String cmd, [
  Object? argsOrOpts,
  RunOpts? maybeOpts,
]) async {
  final args = argsOrOpts is List<String> ? argsOrOpts : null;
  final opts =
      (argsOrOpts is List<String> ? maybeOpts : argsOrOpts as RunOpts?) ??
      const RunOpts();
  // Node's `env` replaces the environment; `shell: true` runs `/bin/sh -c`
  // (`cmd.exe /d /s /c` on Windows).
  final child = args != null
      ? await Process.start(
          cmd,
          args,
          workingDirectory: opts.cwd,
          environment: opts.env,
          includeParentEnvironment: opts.env == null,
        )
      : await Process.start(
          Platform.isWindows ? 'cmd.exe' : '/bin/sh',
          Platform.isWindows ? ['/d', '/s', '/c', cmd] : ['-c', cmd],
          workingDirectory: opts.cwd,
          environment: opts.env,
          includeParentEnvironment: opts.env == null,
        );

  // Match spawnSync's default: when no `input` is given, the child sees
  // EOF on stdin immediately. Without this, things like `su` wait for a
  // password on the open pipe.
  unawaited(child.stdin.close().catchError((Object _) {}));

  final stdout = child.stdout.transform(utf8.decoder).join();
  final stderr = child.stderr.transform(utf8.decoder).join();

  Timer? timer;
  String? signal;
  if (opts.timeout != null && opts.timeout != 0) {
    timer = Timer(Duration(milliseconds: opts.timeout!), () {
      signal = 'SIGTERM';
      child.kill(ProcessSignal.sigterm);
    });
  }

  // Node's 'close' comes after the exit and the end of both pipes; its code
  // is null when a signal ended the child (dart:io reports -signal).
  final exitCode = await child.exitCode;
  final out = await stdout;
  final err = await stderr;
  final status = exitCode < 0 && !Platform.isWindows ? null : exitCode;
  timer?.cancel();
  return (stdout: out, stderr: err, status: status, signal: signal);
}
