// Node `child_process` compatibility: spawn, execSync and exec as the ported
// files use them. No upstream counterpart.
import 'dart:async';
import 'dart:convert';
import 'dart:io' as io;

class NodeChildProcess {
  final Stream<List<int>> stdout;
  final Stream<List<int>> stderr;
  final Stream<Object> errors;
  final Future<int> exitCode;
  final bool Function(String signal) _kill;

  NodeChildProcess({
    required this.stdout,
    required this.stderr,
    required this.errors,
    required this.exitCode,
    required bool Function(String signal) kill,
  }) : _kill = kill;

  bool kill(String signal) => _kill(signal);
}

/// Node's `spawn(command, args)` boundary for a long-running utility process.
/// A start failure is an error event, as with Node's ChildProcess emitter.
NodeChildProcess spawn(String command, List<String> args) {
  final errors = StreamController<Object>.broadcast();
  io.Process? child;
  final stdoutController = StreamController<List<int>>.broadcast();
  final stderrController = StreamController<List<int>>.broadcast();
  final completer = Completer<int>();

  unawaited(() async {
    try {
      child = await io.Process.start(command, args);
      child!.stdout.listen(
        stdoutController.add,
        onError: stdoutController.addError,
        onDone: stdoutController.close,
      );
      child!.stderr.listen(
        stderrController.add,
        onError: stderrController.addError,
        onDone: stderrController.close,
      );
      final code = await child!.exitCode;
      if (!completer.isCompleted) completer.complete(code);
    } catch (error) {
      errors.add(error);
      if (!completer.isCompleted) completer.complete(-1);
      await stdoutController.close();
      await stderrController.close();
    }
  }());

  return NodeChildProcess(
    stdout: stdoutController.stream,
    stderr: stderrController.stream,
    errors: errors.stream,
    exitCode: completer.future,
    kill: (signal) {
      final process = child;
      if (process == null) return false;
      final sig = signal == 'SIGTERM'
          ? io.ProcessSignal.sigterm
          : io.ProcessSignal.sigkill;
      return process.kill(sig);
    },
  );
}

/// Synchronously run a command and return stdout, matching the used part of
/// Node's `execSync` (`encoding: 'utf8'`, with failures reported by throwing).
String execSync(String command, List<String> arguments, {Duration? timeout}) {
  var executable = command;
  var childArguments = arguments;
  if (timeout != null) {
    if (!io.Platform.isLinux && !io.Platform.isMacOS) {
      throw UnimplementedError(
        'A synchronous child timeout requires POSIX alarm/exec semantics.',
      );
    }
    if (timeout.inMilliseconds % 1000 != 0) {
      throw UnimplementedError(
        'The seccomp child-process shim only reproduces whole-second timeouts.',
      );
    }
    // io.Process.runSync has no timeout parameter. Perl's alarm remains armed
    // across exec, so the target is terminated at Node's timeout boundary.
    executable = 'perl';
    childArguments = [
      '-e',
      'alarm shift; exec @ARGV',
      '${timeout.inSeconds}',
      command,
      ...arguments,
    ];
  }
  final result = io.Process.runSync(
    executable,
    childArguments,
    stdoutEncoding: utf8,
    stderrEncoding: utf8,
    runInShell: false,
  );
  if (result.exitCode != 0) {
    throw io.ProcessException(
      command,
      arguments,
      result.stderr.toString(),
      result.exitCode,
    );
  }
  return result.stdout.toString();
}

/// Asynchronously run a command and return stdout, or null on an exec error.
/// This is the callback-error behavior needed by Node's `exec` call site.
Future<String?> exec(
  String command,
  List<String> arguments, {
  required Duration timeout,
}) async {
  io.Process child;
  try {
    child = await io.Process.start(command, arguments, runInShell: false);
  } on io.ProcessException {
    return null;
  }

  // Match execSync's closed stdin: npm never waits on it.
  await child.stdin.close();
  final stdout = child.stdout.transform(utf8.decoder).join();
  final status = await child.exitCode.timeout(
    timeout,
    onTimeout: () {
      child.kill();
      return -1;
    },
  );
  final output = await stdout;
  return status == 0 ? output : null;
}
