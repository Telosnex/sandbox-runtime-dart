// Ported from sandbox-runtime test/sandbox/tls-terminate-tunnel-ends.test.ts @ 0bbebed.
// ignore_for_file: constant_identifier_names, non_constant_identifier_names, slash_for_doc_comments
import 'dart:async';
import 'dart:convert';
import 'dart:io' as io;

import 'package:sandbox_runtime/src/node/events.dart';
import 'package:sandbox_runtime/src/node/http.dart' as http;
import 'package:sandbox_runtime/src/node/net.dart' as net;
import 'package:sandbox_runtime/src/node/stream.dart' as stream;
import 'package:sandbox_runtime/src/node/tls.dart' as tls;
import 'package:sandbox_runtime/src/sandbox/tls_terminate_proxy.dart';
import 'package:test/test.dart';
import '../helpers/emitted_connections.dart' show canServeEmittedConnections;

// Every way a TLS-terminated tunnel can end frees its slot, its upstream
// connection and the bytes counted for it within a bounded time, whatever
// its client or its upstream does or leaves undone.
//
// The runtimes differ in what their servers do for a connection handed to
// them, so the scenarios (test/fixtures/tunnel-ends.mjs) run as children,
// under Node and under Bun, against dist/.
final FIXTURE =
    '${io.Directory.current.path}/test/fixtures/tunnel_ends_test.dart';
typedef Outcome = Map<String, dynamic>;
final RUNS = [
  (name: 'Node', bin: 'node', how: 'accepted'),
  if (canServeEmittedConnections) ...[
    (name: 'Dart', bin: io.Platform.resolvedExecutable, how: 'accepted'),
    (name: 'Dart', bin: io.Platform.resolvedExecutable, how: 'handed'),
  ],
];
/** The children run side by side, from the first that is asked for. */
List<Future<Map<String, Outcome>>>? runs;
Future<Map<String, Outcome>> outcomeOf(int i) =>
    (runs ??= RUNS.map((r) => run(r.bin, r.how)).toList())[i];
Future<Map<String, Outcome>> run(String bin, String how) async {
  // Dart: all proxy instances live in the Dart fixture; native Node clients
  // preserve TLS-over-Duplex and half-close behavior unavailable in dart:io.
  final child = await io.Process.start(io.Platform.resolvedExecutable, [
    'run',
    FIXTURE,
    how,
  ]);
  final out = child.stdout.transform(utf8.decoder).join();
  child.stderr.listen(io.stderr.add);
  final text = await out;
  await child.exitCode;
  return (jsonDecode(text) as Map<String, dynamic>).map(
    (k, v) => MapEntry(k, Map<String, dynamic>.from(v as Map)),
  );
}

/** Timers do not fire early, but the two ends do not start timing at once. */
const EARLY_MS = 100;
/** A busy machine. Well under the fixture's GIVE_UP_MS. */
const LATE_MS = 1500;
/** The tunnel closed `ms` (to `lastMs`) on, and nothing of it is left. */
void expectClosed(Outcome o, int ms, [int? lastMs]) {
  lastMs ??= ms;
  expect(o['closedAfterMs'], isA<num>());
  expect(o['closedAfterMs'] as num, greaterThanOrEqualTo(ms - EARLY_MS));
  expect(o['closedAfterMs'] as num, lessThan(lastMs + LATE_MS));
  expect((o['nextConnect'], o['heldBytes']), (200, 0));
  if (o['upstream'] != null) expect(o['upstream'], 0);
}

mixin _Fluent<T extends EventEmitter> on EventEmitter {
  @override
  T on(String e, Function f) {
    super.on(e, f);
    return this as T;
  }

  @override
  T once(String e, Function f) {
    super.once(e, f);
    return this as T;
  }

  @override
  T off(String e, Function f) {
    super.off(e, f);
    return this as T;
  }

  @override
  T addListener(String e, Function f) {
    super.addListener(e, f);
    return this as T;
  }

  @override
  T prependListener(String e, Function f) {
    super.prependListener(e, f);
    return this as T;
  }

  @override
  T removeListener(String e, Function f) {
    super.removeListener(e, f);
    return this as T;
  }

  @override
  T removeAllListeners([String? e]) {
    super.removeAllListeners(e);
    return this as T;
  }
}

class _Inner extends EventEmitter
    with _Fluent<_Inner>
    implements http.NodeHttpServer {
  @override
  dynamic noSuchMethod(Invocation i) => null;
}

class _Socket extends EventEmitter
    with _Fluent<_Socket>
    implements tls.TLSSocket {
  _Socket({this.paused = false, this.onDestroy, this.onEnd});
  bool paused;
  void Function()? onDestroy, onEnd;
  @override
  int bytesRead = 7;
  @override
  int bytesWritten = 0;
  @override
  int writableLength = 0;
  @override
  bool writableEnded = false;
  @override
  bool destroyed = false;
  @override
  bool isPaused() => paused;
  @override
  net.NodeSocket end([Object? data, Object? encoding, Function? callback]) {
    writableEnded = true;
    onEnd?.call();
    return this;
  }

  @override
  net.NodeSocket destroy([Object? error, Function? callback]) {
    onDestroy?.call();
    return this;
  }

  @override
  dynamic noSuchMethod(Invocation i) => null;
}

class _Request extends EventEmitter
    with _Fluent<_Request>
    implements http.IncomingMessage {
  @override
  bool get complete => true;
  @override
  stream.Readable unpipe([EventEmitter? destination]) => this;
  @override
  stream.Readable resume() => this;
  @override
  dynamic noSuchMethod(Invocation i) => null;
}

class _Response extends EventEmitter
    with _Fluent<_Response>
    implements http.ServerResponse {
  @override
  dynamic noSuchMethod(Invocation i) => null;
}

void main() {
  test('the default timeouts', () {
    expect(
      (
        TUNNEL_TIMEOUTS.firstRequestMs,
        TUNNEL_TIMEOUTS.keepAliveMs,
        TUNNEL_TIMEOUTS.keepAliveMarginMs,
        TUNNEL_TIMEOUTS.stalledMs,
      ),
      (10000, 5000, 1000, 300000),
    );
  });
  // Under Bun a tunnel's socket does not hold the process once the listener
  // is unref'd (under Node it does), so the tunnel's timers must not either.
  test(
    'an open tunnel does not keep a process from ending',
    () async {
      final child = await io.Process.start(io.Platform.resolvedExecutable, [
        'run',
        FIXTURE,
        'accepted',
        'exit with a tunnel open',
      ], mode: io.ProcessStartMode.inheritStdio);
      final giveUp = Timer(
        const Duration(seconds: 5),
        () => child.kill(io.ProcessSignal.sigkill),
      );
      final code = await child.exitCode;
      giveUp.cancel();
      expect(code, 0);
    },
    skip:
        'dart:io cannot unref sockets or timers; recorded shim state cannot release process liveness',
    timeout: const Timeout(Duration(seconds: 10)),
  );

  // What no client can be made to time, or Bun 1.4.2 to serve (a second
  // request while the first is owed its response), with stand-ins for the parts.
  group('with stand-ins', () {
    Future<void> sleep(int ms) =>
        Future<void>.delayed(Duration(milliseconds: ms));
    http.IncomingMessage request() => _Request();
    final sockets = <EventEmitter>[];
    tearDown(() {
      for (final socket in sockets.toList()) {
        socket.emit('close');
      }
      sockets.clear();
    });
    /**
     * A tunnel idle after `idleMs` and stalled after `stalledMs`, its parts,
     * and what is done to it.
     */
    ({
      List<String> done,
      _Socket socket,
      _Socket outbound,
      _Socket tls,
      void Function() Function() ask,
    })
    tunnel({
      int idleMs = 40,
      bool paused = false,
      bool Function()? handshakeDone,
      int stalledMs = 60000,
    }) {
      final done = <String>[];
      final inner = _Inner();
      final socket = _Socket(onDestroy: () => done.add('destroy'));
      sockets.add(socket);
      final outbound = _Socket();
      final t = _Socket(paused: paused, onEnd: () => done.add('end'));
      boundTunnel(
        inner,
        t,
        outbound,
        socket,
        TunnelTimeouts(
          firstRequestMs: idleMs,
          keepAliveMs: idleMs - 10,
          keepAliveMarginMs: 10,
          stalledMs: stalledMs,
        ),
        handshakeDone ?? () => true,
      );
      /** A request, whole, and its response; `answered()` closes that. */
      void Function() ask() {
        final res = _Response();
        inner.emit('request', request(), res);
        return () {
          res.emit('close');
        };
      }

      return (done: done, socket: socket, outbound: outbound, tls: t, ask: ask);
    }

    test(
      'a whole request whose last bytes paused its tunnel: closed once it has not moved',
      () async {
        final (:done, :socket, :ask, outbound: _, tls: _) = tunnel(
          paused: true,
          stalledMs: 40,
        );
        ask();
        await sleep(130);
        expect(done[0], 'destroy');
        // And left alone from then on.
        socket.emit('close');
        final calls = done.length;
        await sleep(100);
        expect(done, hasLength(calls));
      },
    );
    test('a handshake under way is left to its own deadline', () async {
      var shaken = false;
      final t = tunnel(handshakeDone: () => shaken);
      await sleep(100);
      expect(t.done, []);
      shaken = true;
      await sleep(40);
      expect(t.done, ['end']);
    });
    test('idle only once no response is owed', () async {
      final t = tunnel();
      final first = t.ask(), second = t.ask();
      first();
      await sleep(100);
      expect(t.done, []);
      second();
      await sleep(60);
      expect(t.done, ['end']);
      // And no longer there as long again after.
      await sleep(40);
      expect(t.done, ['end', 'destroy']);
    });
    for (final layer in ['tls', 'outbound', 'socket']) {
      test(
        'idle only a whole time after the last byte queued in $layer has gone, and not destroyed before',
        () async {
          final t = tunnel();
          final queue = switch (layer) {
            'tls' => t.tls,
            'outbound' => t.outbound,
            _ => t.socket,
          };
          queue.writableLength = 1;
          t.ask()();
          await sleep(120);
          expect(t.done, []);
          queue.writableLength = 0;
          await sleep(35);
          expect(t.done, []);
          await sleep(65);
          expect(t.done[0], 'end');
          // The same once it is ended.
          final ended = tunnel();
          ended.ask()();
          await sleep(60);
          expect(ended.done, ['end']);
          final q = switch (layer) {
            'tls' => ended.tls,
            'outbound' => ended.outbound,
            _ => ended.socket,
          };
          q.writableLength = 24;
          await sleep(120);
          expect(ended.done, ['end']);
          q.writableLength = 0;
          await sleep(100);
          expect(ended.done, ['end', 'destroy']);
        },
      );
    }
    test(
      'with bytes queued when the response ends, idle is counted from soon after the last has gone',
      () async {
        final t = tunnel(idleMs: 500);
        t.outbound.writableLength = 1;
        t.ask()();
        await sleep(50);
        t.outbound.writableLength = 0;
        await sleep(450);
        expect(t.done, []);
        // Seen gone within a fifth of the time, so ended by 650 ms.
        await sleep(300);
        expect(t.done, ['end']);
      },
    );
    test(
      'bytes queued for a client that takes none: closed once nothing has moved; one that takes some is left alone',
      () async {
        final stuck = tunnel(stalledMs: 40),
            slow = tunnel(stalledMs: 40),
            fed = tunnel(stalledMs: 40);
        for (final t in [stuck, slow, fed]) {
          t.ask();
          t.outbound.writableLength = 1000;
        }
        for (var i = 1; i <= 15; i++) {
          await sleep(10);
          // The queue shrinks; or stays as long, with as much written as taken.
          slow.outbound.writableLength = 1000 - i;
          fed.tls.bytesWritten = i;
        }
        expect([stuck.done[0], slow.done, fed.done], ['destroy', [], []]);
      },
    );
    test(
      'a stalled tunnel is closed between one and one and a fifth times the time allowed',
      () async {
        final t = tunnel(paused: true, stalledMs: 1000);
        t.ask();
        await sleep(20);
        t.tls.bytesRead = 8;
        await sleep(900);
        expect(t.done, []);
        await sleep(480);
        expect(t.done[0], 'destroy');
      },
    );
    test('a tunnel that has closed is not ended', () async {
      final before = tunnel();
      before.socket.emit('close');
      final after = tunnel();
      final answered = after.ask();
      after.socket.destroyed = true;
      after.socket.emit('close');
      answered();
      await sleep(100);
      expect([before.done, after.done], [[], []]);
    });
  });
  for (var i = 0; i < RUNS.length; i++) {
    final r = RUNS[i];
    group('${r.name}, connections ${r.how}', () {
      late Map<String, Outcome> outcome;
      setUpAll(() async {
        outcome = await outcomeOf(i);
      });
      test(
        'idle after a response: ended a margin later than the time it advertised',
        () {
          final o = outcome['idle after a response']!;
          expect((o['status'], o['advertised']), (200, 'timeout=1'));
          expectClosed(o, 1500);
          expect(o['closeNotify'], true);
        },
        skip:
            'dart:io SecureSocket.close sends a FIN without a TLS close_notify',
      );
      test('asked again when the advertised time is up: served', () {
        expect(
          outcome['asked again when the advertised time is up']!['status'],
          200,
        );
      });
      test(
        "ended by its own time alone, not the runtime's",
        () {
          final o = outcome['a margin longer than the runtime has']!;
          expectClosed(o, 2000);
          expect(o['closeNotify'], true);
        },
        skip:
            'dart:io SecureSocket.close sends a FIN without a TLS close_notify',
      );
      test(
        'idle, and its client answers no end: closed as long again after the end',
        () {
          final ms =
              outcome['idle, and the client answers no end']!['slotFreeAfterMs'];
          expect(ms, isA<num>());
          expect(ms as num, greaterThanOrEqualTo(500 - EARLY_MS));
          expect(ms, lessThan(1000 + LATE_MS));
        },
      );
      test('the time advertised by default is the default timeout', () {
        expect(
          outcome['the default Keep-Alive']!['advertised'],
          'timeout=${TUNNEL_TIMEOUTS.keepAliveMs ~/ 1000}',
        );
      });
      test(
        'each response starts the idle time anew',
        () {
          final o = outcome['each response starts the idle time anew']!;
          expect(o['statuses'], [200, 200, 200]);
          expectClosed(o, 800);
          expect(o['closeNotify'], true);
        },
        skip:
            'dart:io SecureSocket.close sends a FIN without a TLS close_notify',
      );
      // Timed from the end of the handshake; the proxy's time runs from its start.
      for (final name in ['no request after the handshake', 'half a head']) {
        test('%s'.replaceFirst('%s', name), () {
          expectClosed(outcome[name]!, 500, 800);
        });
      }
      test(
        'half a head after a response',
        () {
          final o = outcome['half a head after a response']!;
          expectClosed(o, 800);
          expect(o['closeNotify'], true);
        },
        skip:
            'dart:io SecureSocket.close sends a FIN without a TLS close_notify',
      );
      test(
        'half a body: closed once it has not moved for the time allowed',
        () {
          expectClosed(outcome['half a body']!, 500, 1000);
        },
      );
      test('a body that trickles in arrives', () {
        expect(outcome['a body that trickles in']!['status'], 200);
      });
      test(
        'a whole request may wait for its answer longer than every timeout',
        () {
          expect(
            outcome['an answer that takes longer than every timeout']!['status'],
            200,
          );
        },
      );
      // No timeout plays a part: the proxy reads on, and so sees its client go.
      for (final (what, status) in [
        ('answered early', 413),
        ('upstream port closed', 502),
        ('upstream certificate untrusted', 502),
        ('refused for its Host', 421),
        ('refused for its target', 400),
      ]) {
        test('an upload, $what, whose client leaves', () {
          final o = outcome['$what, the client leaves']!;
          expect(o['status'], status);
          expectClosed(o, EARLY_MS);
        });
      }
      test(
        'an upload answered early, whose client stays: idle from the answer on',
        () {
          final o = outcome['answered early, the client stays']!;
          // (The client, busy sending, may see the answer late.)
          expectClosed(o, EARLY_MS, 600);
          expect(o['closeNotify'], true);
        },
        skip:
            'dart:io SecureSocket.close sends a FIN without a TLS close_notify',
      );
      test(
        'an upload answered early, whose client sends it all: the next request is served',
        () {
          final o =
              outcome['answered early, the client sends on and asks again']!;
          expect((o['status'], o['second'], o['heldBytes']), (413, 200, 0));
        },
      );
      test(
        'readers that take nothing for a while, then everything, lose nothing',
        () {
          expect(
            outcome['readers that take nothing for a while, then everything']!['missing'],
            [],
          );
        },
      );
      test('a reader that takes an answer in bursts loses nothing', () {
        expect(
          outcome['a reader that takes an answer in bursts']!['missing'],
          0,
        );
      });
      test(
        'a client that never reads its answer: closed once nothing has moved for the time allowed',
        () {
          final o = outcome['a client that never reads its answer']!;
          expect(o['slotFreeAfterMs'], isA<num>());
          expect(
            o['slotFreeAfterMs'] as num,
            greaterThanOrEqualTo(500 - EARLY_MS),
          );
          expect(o['slotFreeAfterMs'], lessThan(1000 + LATE_MS));
          expect(o['upstream'], 0);
        },
      );
      test(
        'an upload the upstream stops taking: closed once it has not moved for the time allowed',
        () {
          final o = outcome['an upload the upstream stops taking']!;
          expectClosed(o, 500, 1000);
          expect(o['closeNotify'], false);
        },
      );
      test('an upload the upstream takes in bursts arrives', () {
        expect(
          outcome['an upload the upstream takes in bursts']!['status'],
          200,
        );
      });
    }, timeout: const Timeout(Duration(seconds: 120)));
  }
}
