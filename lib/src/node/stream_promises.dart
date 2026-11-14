// Node's `stream/promises`: promise-returning forms of node:stream APIs.
// No upstream counterpart; node:stream/promises is the spec.
import 'dart:async';

import 'stream.dart' as stream;

/// Node `stream/promises.finished(stream[, options])`. As in Node, listeners
/// stay attached unless the caller opts into `cleanup`.
Future<void> finished(
  stream.NodeStream source, [
  Map<String, Object?> options = const {},
]) {
  final completer = Completer<void>();
  late final void Function() cleanup;
  cleanup = stream.finished(source, options, ([Object? error]) {
    if (options['cleanup'] == true) cleanup();
    if (error != null) {
      completer.completeError(error);
    } else {
      completer.complete();
    }
  });
  return completer.future;
}
