// Ported from sandbox-runtime src/sandbox/listen-in-range.ts @ 0bbebed.
// ignore_for_file: slash_for_doc_comments

import 'dart:async';

import '../node/errno.dart';
import '../node/events.dart';

/**
 * Bind `server` to the first free port in `range`, retrying on EADDRINUSE.
 * With `range` undefined, binds to ephemeral port 0 once. The Windows WFP
 * loopback permit is installed by range, so proxy listeners on Windows must
 * land inside it; other platforms bake the actual ephemeral port into the
 * sandbox profile and pass `range = undefined`.
 */
Future<void> listenInRange(
  EventEmitter server,
  void Function(int port) doListen,
  List<int>? range,
  Set<int> exclude,
) {
  final completer = Completer<void>();
  void resolve() => completer.complete();
  void reject(Object error) => completer.completeError(error);
  final lo = range?[0] ?? 0;
  final hi = range?[1] ?? 0;
  var port = lo;
  late void Function() tryNext;
  tryNext = () {
    while (exclude.contains(port) && port <= hi) {
      port++;
    }
    if (port > hi) {
      reject(
        NodeException(
          'No free port in range $lo-$hi (excluding ${exclude.join(',')})',
        ),
      );
      return;
    }
    late final void Function([Object?]) onError;
    void onListening() {
      server.removeListener('error', onError);
      resolve();
    }

    onError = ([Object? err]) {
      // The paired 'listening' once-listener never fired; drop it
      // so retries don't accumulate stale listeners.
      server.removeListener('listening', onListening);
      if (range != null &&
          err is NodeError &&
          err.code == 'EADDRINUSE' &&
          port < hi) {
        port++;
        tryNext();
        return;
      }
      reject(err ?? NodeException('listen error'));
    };
    server.once('error', onError);
    server.once('listening', onListening);
    doListen(range != null ? port : 0);
  };
  tryNext();
  return completer.future;
}
