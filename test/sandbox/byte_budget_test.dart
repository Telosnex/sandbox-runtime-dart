// Ported from sandbox-runtime test/sandbox/byte-budget.test.ts @ 0bbebed.
import 'package:sandbox_runtime/src/sandbox/emitted_connection.dart'
    show adjustByteBudget, createByteBudget, gateSocketOnBufferedBody;
import 'package:test/test.dart';
import 'package:sandbox_runtime/src/node/events.dart';

class _Socket extends EventEmitter {
  void pause() {}
}

class _Request extends EventEmitter {
  _Request(this.socket);
  final _Socket socket;
  final readableLength = 10;
}

void main() {
  test(
    'a drop in a byte budget wakes each waiter once and empties the set',
    () {
      final budget = createByteBudget(100);
      final woken = <String>[];
      adjustByteBudget(budget, 100);
      budget.waiters.add(() => woken.add('a'));
      budget.waiters.add(() => woken.add('b'));

      adjustByteBudget(budget, -40);

      expect(woken, ['a', 'b']);
      expect(budget.waiters.length, 0);
      expect(budget.used, 60);
    },
  );

  test('a rise in a byte budget wakes nobody', () {
    final budget = createByteBudget(100);
    var woken = 0;
    budget.waiters.add(() => woken++);

    adjustByteBudget(budget, 10);
    adjustByteBudget(budget, 0);

    expect(woken, 0);
    expect(budget.waiters.length, 1);
  });

  test(
    'a waiter that waits again while being woken is kept for the next drop',
    () {
      final budget = createByteBudget(100);
      var woken = 0;
      void waitAgain() {
        woken++;
        budget.waiters.add(waitAgain);
      }

      adjustByteBudget(budget, 100);
      budget.waiters.add(waitAgain);

      adjustByteBudget(budget, -1);
      expect(woken, 1);
      expect(budget.waiters.length, 1);
      adjustByteBudget(budget, -1);
      expect(woken, 2);
    },
  );

  test('many add and release cycles leave a byte budget empty', () {
    final budget = createByteBudget(1000);
    for (var i = 1; i <= 500; i++) {
      adjustByteBudget(budget, i);
      budget.waiters.add(() {});
      adjustByteBudget(budget, -i);
    }
    expect(budget.used, 0);
    expect(budget.waiters.length, 0);
  });
  for (final event in ['end', 'close']) {
    test(
      "what a gated request holds is given back at its $event, or its socket's close, and the socket is let go of",
      () {
        for (final from in ['req', 'socket']) {
          final budget = createByteBudget(1000);
          final socket = _Socket();
          final req = _Request(socket);
          gateSocketOnBufferedBody(req, 100, budget);
          socket.emit('data');
          expect(budget.used, 10);
          if (from == 'req') {
            req.emit(event);
          } else {
            socket.emit('close');
          }
          expect(budget.used, 0);
          expect(socket.eventNames(), []);
        }
      },
    );
  }
}
