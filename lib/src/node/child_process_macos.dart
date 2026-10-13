// Node child_process behavior used by the macOS log monitor.
// No upstream counterpart: this keeps Process/Event details out of sandbox code.
import 'dart:async';
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
