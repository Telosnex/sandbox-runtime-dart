// Ported from sandbox-runtime src/sandbox/listen-in-range.ts @ 24eb39e.
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
  NodeEventEmitter server,
  void Function(int port) doListen,
  List<int>? range,
  Set<int> exclude,
) async {
  final lo = range?[0] ?? 0;
  final hi = range?[1] ?? 0;
  var port = lo;
  while (true) {
    while (exclude.contains(port) && port <= hi) {
      port++;
    }
    if (port > hi) {
      throw NodeException(
        'No free port in range $lo-$hi (excluding ${exclude.join(',')})',
      );
    }

    final attempt = Completer<({bool listening, Object? error})>();
    StreamSubscription<Object?>? errorSubscription;
    StreamSubscription<void>? listeningSubscription;
    errorSubscription = server.errorEvents.listen((error) {
      if (!attempt.isCompleted) {
        attempt.complete((listening: false, error: error));
      }
    });
    listeningSubscription = server.listeningEvents.listen((_) {
      if (!attempt.isCompleted) {
        attempt.complete((listening: true, error: null));
      }
    });
    try {
      doListen(range == null ? 0 : port);
      final outcome = await attempt.future;
      await errorSubscription.cancel();
      await listeningSubscription.cancel();
      if (outcome.listening) return;
      final error = outcome.error ?? NodeException('listen error');
      if (range != null &&
          error is NodeError &&
          error.code == 'EADDRINUSE' &&
          port < hi) {
        port++;
        continue;
      }
      throw error;
    } catch (_) {
      await errorSubscription.cancel();
      await listeningSubscription.cancel();
      rethrow;
    }
  }
}
