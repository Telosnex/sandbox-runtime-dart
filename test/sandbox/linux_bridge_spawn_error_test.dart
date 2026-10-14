// Ported from sandbox-runtime test/sandbox/linux-bridge-spawn-error.test.ts @ 24eb39e.
// ignore_for_file: constant_identifier_names, non_constant_identifier_names, slash_for_doc_comments
import 'dart:async';

import 'package:sandbox_runtime/src/node/process.dart' as process;
import 'package:sandbox_runtime/src/sandbox/linux_sandbox_utils.dart'
    show initializeLinuxNetworkBridge;
import 'package:test/test.dart';

// When spawn() cannot start socat (e.g. the binary is missing or not
// executable), the ChildProcess gets no pid and emits an asynchronous
// 'error' event. initializeLinuxNetworkBridge must have an 'error'
// listener attached before it throws on the missing pid — otherwise the
// queued event fires with no listener and escalates to an
// uncaughtException, crashing the host process even though the caller
// handled the rejection.
void main() {
  group('initializeLinuxNetworkBridge spawn failure', () {
    final uncaught = <Object>[];
    void onUncaught(Object err, [Object? stack]) {
      uncaught.add(err);
    }

    setUp(() {
      uncaught.clear();
      process.on('uncaughtException', onUncaught);
    });

    tearDown(() {
      process.off('uncaughtException', onUncaught);
    });

    test(
      'rejects without an unhandled error event when socat cannot be spawned',
      () async {
        // bun-types declares .rejects matchers as returning void, but bun returns
        // a Promise at runtime — the await is load-bearing for the assertion.
        // eslint-disable-next-line @typescript-eslint/await-thenable
        await expectLater(
          initializeLinuxNetworkBridge(0, 0, '/nonexistent-for-test/socat'),
          throwsA(
            predicate(
              (e) =>
                  e.toString().contains('Failed to start HTTP bridge process'),
            ),
          ),
        );

        // Give the queued 'error' event a tick to fire so we can assert it was
        // absorbed by the bridge's own listener.
        await Future<void>.delayed(const Duration(milliseconds: 50));

        expect(uncaught, []);
      },
    );
  });
}
