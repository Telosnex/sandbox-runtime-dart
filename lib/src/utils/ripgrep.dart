// Ported from sandbox-runtime src/utils/ripgrep.ts @ 24eb39e.
// ignore_for_file: slash_for_doc_comments

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import '../node/abort.dart';

class RipgrepConfig {
  RipgrepConfig({required this.command, this.args, this.argv0});

  String command;
  List<String>? args;

  /// Override argv[0] when spawning (for multicall binaries that dispatch on argv[0]).
  String? argv0;
}

/**
 * Execute ripgrep with the given arguments
 * @param args Command-line arguments to pass to rg
 * @param target Target directory or file to search
 * @param abortSignal AbortSignal to cancel the operation
 * @param config Ripgrep configuration (command and optional args)
 * @returns Array of matching lines (one per line of output)
 * @throws RipgrepError if ripgrep exits with non-zero status (except exit code 1 which means no matches)
 */
Future<List<String>> ripGrep(
  List<String> args,
  String target,
  AbortSignal abortSignal, [
  RipgrepConfig? config,
]) async {
  final resolvedConfig = config ?? RipgrepConfig(command: 'rg');
  final command = resolvedConfig.command;
  final commandArgs = [...?resolvedConfig.args, ...args, target];
  final argv0 = resolvedConfig.argv0;

  // Dart's Process.start has no argv0 parameter. On POSIX, use Bash's exec -a
  // to preserve the Node spawn option without interpolating any arguments into
  // shell text. Windows has no corresponding Process.start option.
  final String executable;
  final List<String> processArgs;
  if (argv0 != null && !Platform.isWindows) {
    executable = '/bin/bash';
    processArgs = [
      '-c',
      'exec -a "\$1" "\$2" "\${@:3}"',
      '_ripgrep_argv0',
      argv0,
      command,
      ...commandArgs,
    ];
  } else {
    executable = command;
    processArgs = commandArgs;
  }

  final child = await Process.start(executable, processArgs);
  if (abortSignal.aborted) {
    child.kill();
    throw abortSignal.reason ?? AbortError();
  }
  // Node's spawn `timeout` sends the default termination signal after 10s.
  var timedOut = false;
  final timeout = Timer(const Duration(seconds: 10), () {
    timedOut = true;
    child.kill();
  });
  unawaited(abortSignal.whenAborted.then((_) => child.kill()));

  try {
    final stdoutFuture = _readText(child.stdout);
    final stderrFuture = _readText(child.stderr);
    final exitCodeFuture = child.exitCode;
    final stdout = await stdoutFuture;
    final stderr = await stderrFuture;
    final exitCode = await exitCodeFuture;
    if (abortSignal.aborted) {
      throw abortSignal.reason ?? AbortError();
    }

    if (exitCode == 0) {
      return stdout
          .trim()
          .split('\n')
          .where((line) => line.isNotEmpty)
          .toList();
    }
    if (exitCode == 1) {
      // Exit code 1 means "no matches found" - this is normal
      return [];
    }
    // Whole lines only: killed, it can leave half of one.
    final reportedCode = timedOut ? null : exitCode;
    throw RipgrepError(
      'ripgrep failed with exit code $reportedCode: $stderr',
      stdout
          .split('\n')
          .take(stdout.split('\n').length - 1)
          .where((line) => line.isNotEmpty)
          .toList(),
      stderr,
    );
  } finally {
    timeout.cancel();
  }
}

Future<String> _readText(Stream<List<int>> stream) =>
    stream.transform(const Utf8Decoder(allowMalformed: true)).join();

/** ripgrep ended otherwise than by finding something or nothing. */
class RipgrepError extends Error {
  RipgrepError(this.message, this.listed, this.stderr) : name = 'RipgrepError';

  String name;
  String message;
  /** What it had listed by then. */
  final List<String> listed;
  /** What it said went wrong. The paths in it are the tree's own text. */
  final String stderr;

  @override
  String toString() => 'RipgrepError: $message';
}
