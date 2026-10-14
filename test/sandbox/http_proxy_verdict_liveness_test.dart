// Ported from sandbox-runtime test/sandbox/http-proxy-verdict-liveness.test.ts @ 24eb39e.
// ignore_for_file: constant_identifier_names, non_constant_identifier_names, slash_for_doc_comments
import 'dart:async';
import 'dart:convert';

import 'package:sandbox_runtime/src/node/buffer.dart' show Buffer;
import 'package:sandbox_runtime/src/node/errno.dart' show NodeError;
import 'package:sandbox_runtime/src/node/net.dart';
import 'package:sandbox_runtime/src/node/stream.dart' as stream;
import 'package:sandbox_runtime/src/sandbox/http_proxy.dart';
import 'package:test/test.dart';

/**
 * Verdict-writer liveness regression tests for the HTTP proxy.
 *
 * Background (idle-CPU incident): the host-allowlist decision
 * (`options.filter`) can take tens of seconds — it may run a
 * model-classifier call or an interactive permission prompt. When the
 * sandboxed client gave up and half-closed mid-decision, the proxy left
 * the descriptor half-open (no close on the EOF path) and later wrote the
 * verdict to the dead descriptor; the resulting EPIPE fed a busy-loop in
 * the embedding runtime (fixed separately in Bun, oven-sh/bun#37076).
 * These tests pin the proxy-side contract:
 *  - CONNECT: EOF during the decision window closes the descriptor
 *    immediately (a CONNECT client that half-closed can never use the
 *    tunnel), and no verdict is ever written to a dead/destroyed socket.
 *  - CONNECT: a write error on the client socket (EPIPE to a peer whose
 *    death was never notified) releases the descriptor instead of only
 *    logging — the layered backstop for best-effort EOF notification.
 *  - CONNECT: verdicts still reach live clients, and established tunnels
 *    still pipe (the decision-window EOF handling is disarmed at handoff).
 *  - Plain HTTP: the verdict is dropped only for a destroyed socket. (The
 *    drop keys on `destroyed`, not on EOF, so a runtime that keeps
 *    half-closed request sockets open — legal HTTP half-close — still
 *    delivers the verdict. Bun 1.4's http.Server destroys the request
 *    socket on client FIN, so delivery is runtime-dependent; the
 *    half-close test below accepts either outcome and pins that neither
 *    crashes nor writes to a dead socket.)
 */

const HOST = '127.0.0.1';

// Dart: the object literal upstream hands createHttpProxyServer; every
// option not named here is absent (null).
class _HttpOptions implements HttpProxyServerOptions {
  _HttpOptions(this._filter);
  final FutureOr<bool> Function(int port, String host, stream.Duplex socket)
  _filter;
  @override
  FutureOr<bool> filter(
    int port,
    String host,
    stream.Duplex socket, [
    String? encodedCommand,
    void Function(String reason)? explain,
  ]) => _filter(port, host, socket);
  @override
  dynamic noSuchMethod(Invocation invocation) => null;
}

// Dart: spyOn(socket, 'end' | 'write'), built on the Writable.callObserver
// hook; records calls and calls through.
class _Spy {
  _Spy(this.socket, this.method) {
    final previous = socket.callObserver;
    socket.callObserver = (String m, List<Object?> args) {
      if (_active && m == method) calls.add(args);
      previous?.call(m, args);
    };
  }
  final stream.Writable socket;
  final String method;
  final List<List<Object?>> calls = [];
  bool _active = true;
  void mockClear() => calls.clear();
  void mockRestore() {
    _active = false;
  }
}

Future<int> listen(NodeServer server) {
  final completer = Completer<int>();
  server.once('error', (Object? e) => completer.completeError(e!));
  server.listen(0, HOST, () {
    final address = server.address();
    if (address == null || address is! NodeAddress) {
      completer.completeError(Exception('server has no port'));
      return;
    }
    completer.complete(address.port);
  });
  return completer.future;
}

NodeSocket connectClient(int port) {
  final client = connect(port, HOST);
  // A test client may be deliberately killed mid-exchange; without a
  // listener the resulting ECONNRESET would fail the test run as an
  // unhandled error.
  client.on('error', (Object? _) {});
  return client;
}

({String Function() received}) collectData(NodeSocket socket) {
  final chunks = <List<int>>[];
  socket.on('data', (Object? chunk) {
    chunks.add(chunk as List<int>);
  });
  return (received: () => Buffer.concat(chunks).toString('utf8'));
}

// Poll until `predicate` holds, with failure-time diagnostics so a
// timed-out wait explains itself in CI output.
Future<void> until(
  bool Function() predicate,
  String label, [
  String Function()? diagnose,
]) async {
  final deadline = DateTime.now().millisecondsSinceEpoch + 2000;
  while (!predicate()) {
    if (DateTime.now().millisecondsSinceEpoch > deadline) {
      final detail = diagnose != null ? ' [${diagnose()}]' : '';
      throw Exception('timed out waiting for $label$detail');
    }
    await Future<void>.delayed(const Duration(milliseconds: 10));
  }
}

typedef DecisionCapture = ({stream.Duplex socket, _Spy endSpy, _Spy writeSpy});

void main() {
  group('http-proxy verdict-writer liveness', () {
    final servers = <NodeServer>[];
    final sockets = <NodeSocket>[];
    // Spies are created inside per-connection filter callbacks, where a
    // `using` binding can't outlive the callback — so they register here and
    // are restored per-test.
    final spies = <_Spy>[];

    tearDown(() async {
      for (final spy in spies) {
        spy.mockRestore();
      }
      spies.clear();
      for (final socket in sockets) {
        socket.destroy();
      }
      sockets.clear();
      await Future.wait(
        servers.map((server) {
          final completer = Completer<void>();
          server.close(() => completer.complete());
          return completer.future;
        }),
      );
      servers.clear();
    });

    ({
      Future<int> portReady,
      Future<DecisionCapture> decision,
      void Function(bool allow) resolveVerdict,
    })
    startProxy() {
      void Function(DecisionCapture value) capture = (_) {};
      final decision = Completer<DecisionCapture>();
      capture = (value) => decision.complete(value);
      void Function(bool allow) resolveVerdict = (_) {};
      final verdict = Completer<bool>();
      resolveVerdict = (allow) => verdict.complete(allow);
      final server = createHttpProxyServer(
        _HttpOptions((port, host, socket) {
          // Spies installed before the decision await starts: every write the
          // proxy attempts after this point is recorded.
          final endSpy = _Spy(socket, 'end');
          final writeSpy = _Spy(socket, 'write');
          spies.addAll([endSpy, writeSpy]);
          capture((socket: socket, endSpy: endSpy, writeSpy: writeSpy));
          return verdict.future;
        }),
      );
      servers.add(server);
      return (
        portReady: listen(server),
        decision: decision.future,
        resolveVerdict: resolveVerdict,
      );
    }

    test(
      'CONNECT: client EOF mid-decision closes the descriptor immediately and drops the verdict write',
      () async {
        final (:portReady, :decision, :resolveVerdict) = startProxy();
        final client = connectClient(await portReady);
        sockets.add(client);
        client.write(
          'CONNECT blocked.decision.invalid:443 HTTP/1.1\r\n'
          'Host: blocked.decision.invalid:443\r\n\r\n',
        );

        final (:socket, :endSpy, :writeSpy) = await decision;
        expect(socket.destroyed, false);

        // The client gives up mid-decision and half-closes (FIN), exactly like
        // a sandboxed HTTP client hitting its own request timeout.
        client.end();

        // The EOF path must close the proxy-side descriptor NOW — before the
        // decision resolves — not leave it half-open awaiting the verdict.
        await until(
          () => socket.destroyed,
          'proxy-side socket destroy on EOF',
          () =>
              'destroyed=${socket.destroyed} readableFlowing=${socket.readableFlowing} endListeners=${socket.listenerCount('end')} closeListeners=${socket.listenerCount('close')}',
        );

        // The decision completes after the client is gone (deny, like the
        // incident's classifier verdict). Nothing may be written to the dead
        // descriptor.
        endSpy.mockClear();
        writeSpy.mockClear();
        resolveVerdict(false);
        await Future<void>.delayed(const Duration(milliseconds: 50));
        expect(endSpy.calls, isEmpty);
        expect(writeSpy.calls, isEmpty);
      },
    );

    test(
      'CONNECT: a write error on the client socket releases the descriptor (EPIPE backstop)',
      () async {
        // EOF notification on a paused socket is best-effort: a peer can die
        // without the proxy ever seeing 'end' or 'close', and the first sign is
        // the verdict write failing (EPIPE). The error handler must destroy the
        // socket — releasing the descriptor — not just log. This is the layer
        // the incident's busy-loop spun on: a logged-and-leaked dead fd.
        final (:portReady, :decision, :resolveVerdict) = startProxy();
        final client = connectClient(await portReady);
        sockets.add(client);
        client.write(
          'CONNECT blocked.decision.invalid:443 HTTP/1.1\r\n'
          'Host: blocked.decision.invalid:443\r\n\r\n',
        );

        final (:socket, endSpy: _, writeSpy: _) = await decision;
        expect(socket.destroyed, false);

        // Surface a write failure on the proxy-side socket. Emitted directly
        // because a real never-notified peer death is not reproducible
        // deterministically from a loopback test (the kernel usually delivers
        // FIN/RST notifications promptly); the handler's contract is the same
        // regardless of how the error arrives.
        final epipe = NodeError('write EPIPE', code: 'EPIPE');
        socket.emit('error', epipe);

        await until(
          () => socket.destroyed,
          'descriptor release after write error',
          () => 'destroyed=${socket.destroyed}',
        );
        resolveVerdict(false);
      },
    );

    test('CONNECT: a live client still receives the deny verdict', () async {
      final (:portReady, :decision, :resolveVerdict) = startProxy();
      final client = connectClient(await portReady);
      sockets.add(client);
      final (:received) = collectData(client);
      client.write(
        'CONNECT blocked.decision.invalid:443 HTTP/1.1\r\n'
        'Host: blocked.decision.invalid:443\r\n\r\n',
      );

      await decision;
      resolveVerdict(false);

      await until(() => received().contains('403 Forbidden'), 'deny verdict');
      await until(() => client.destroyed, 'client teardown after deny');
    });

    test(
      'CONNECT: a live client still gets its tunnel on allow (decision-window EOF handling disarms at handoff)',
      () async {
        final echo = createServer((NodeSocket socket) {
          socket.on('data', (Object? chunk) => socket.write(chunk!));
          socket.on('error', (Object? _) {});
        });
        servers.add(echo);
        final echoPort = await listen(echo);

        final (:portReady, :decision, :resolveVerdict) = startProxy();
        final client = connectClient(await portReady);
        sockets.add(client);
        final (:received) = collectData(client);
        client.write(
          'CONNECT $HOST:$echoPort HTTP/1.1\r\nHost: $HOST:$echoPort\r\n\r\n',
        );

        await decision;
        resolveVerdict(true);
        await until(
          () => received().contains('200 Connection Established'),
          'tunnel establishment',
        );

        client.write('ping-through-tunnel');
        await until(
          () => received().contains('ping-through-tunnel'),
          'echoed tunnel bytes',
        );
      },
    );

    // Whether this runtime's CLIENT sockets can still receive data after
    // their own end() — needed to assert reply delivery across a
    // half-closed tunnel. (bun 1.3.13 closes the client fully on end();
    // node and newer bun deliver the late reply.) Probed once against a
    // bare echo-on-FIN server so a client-side runtime limitation doesn't
    // read as a proxy regression.
    Future<bool> clientSupportsHalfOpenReceive() async {
      final probe = createServer((NodeSocket socket) {
        socket.allowHalfOpen = true;
        socket.on('error', (Object? _) {});
        socket.on('end', (Object? _) => socket.end('late'));
      });
      servers.add(probe);
      final client = connectClient(await listen(probe));
      sockets.add(client);
      final (:received) = collectData(client);
      client.end();
      await Future<void>.delayed(const Duration(milliseconds: 150));
      return received().contains('late');
    }

    test(
      'CONNECT: a client FIN through an established tunnel reaches the upstream as a clean FIN (EOF handling disarmed at handoff)',
      () async {
        // Upstream that answers only once the client's write side closes: the
        // final payload (and the clean 'end') would be lost if the
        // decision-window EOF handler were still armed at tunnel time (it
        // would destroy the client socket on FIN, surfacing upstream as an
        // abrupt close, never a clean FIN after the payload).
        var upstreamGot = '';
        var upstreamSawFin = false;
        final lastWord = createServer((NodeSocket socket) {
          socket.on('error', (Object? _) {});
          socket.on('data', (Object? chunk) {
            upstreamGot += utf8.decode(chunk as List<int>);
          });
          socket.on('end', (Object? _) {
            upstreamSawFin = true;
            socket.end('goodbye:$upstreamGot');
          });
        });
        servers.add(lastWord);
        final lastWordPort = await listen(lastWord);

        final (:portReady, :decision, :resolveVerdict) = startProxy();
        final client = connectClient(await portReady);
        sockets.add(client);
        final (:received) = collectData(client);
        client.write(
          'CONNECT $HOST:$lastWordPort HTTP/1.1\r\nHost: $HOST:$lastWordPort\r\n\r\n',
        );

        await decision;
        resolveVerdict(true);
        await until(
          () => received().contains('200 Connection Established'),
          'tunnel establishment',
        );

        client.write('ping');
        client
            .end(); // FIN through the tunnel — must NOT destroy the socket now
        await until(
          () => upstreamSawFin && upstreamGot == 'ping',
          'payload + clean FIN at the upstream',
          () => 'upstreamGot=${jsonEncode(upstreamGot)} fin=$upstreamSawFin',
        );

        // Reply delivery across the half-closed client side is only
        // assertable where the test client itself can receive after end().
        if (await clientSupportsHalfOpenReceive()) {
          await until(
            () => received().contains('goodbye:ping'),
            'reply across the half-closed tunnel',
          );
        }
      },
    );

    test(
      'plain HTTP: FIN mid-decision is delivered or dropped cleanly, never written to a dead socket',
      () async {
        final (:portReady, :decision, :resolveVerdict) = startProxy();
        final client = connectClient(await portReady);
        sockets.add(client);
        final (:received) = collectData(client);
        client.write(
          'GET http://blocked.decision.invalid/ HTTP/1.1\r\nHost: blocked.decision.invalid\r\n\r\n',
        );
        final (:socket, :endSpy, :writeSpy) = await decision;

        // HTTP half-close: the request is complete, the client shuts down its
        // write side and waits for the response.
        client.end();
        await Future<void>.delayed(const Duration(milliseconds: 50));

        endSpy.mockClear();
        writeSpy.mockClear();
        resolveVerdict(false);
        await Future<void>.delayed(const Duration(milliseconds: 100));

        if (socket.destroyed) {
          // Bun 1.4: http.Server destroys the request socket on client FIN, so
          // there is nothing to deliver to — the verdict must be dropped with
          // no write to the destroyed socket. (On a runtime with half-open
          // request sockets, the else-branch contract applies instead; a
          // branch flip on a runtime upgrade is expected, not a regression.)
          expect(endSpy.calls, isEmpty);
          expect(writeSpy.calls, isEmpty);
          expect(received(), isNot(contains('403')));
        } else {
          // Half-open-capable runtime: a half-closed client is NOT dead and
          // still receives its verdict.
          await until(
            () => received().contains('403 Forbidden'),
            'deny verdict to half-closed client',
          );
        }
      },
    );

    test(
      'plain HTTP: a destroyed client mid-decision gets no verdict write and no crash',
      () async {
        final (:portReady, :decision, :resolveVerdict) = startProxy();
        final client = connectClient(await portReady);
        sockets.add(client);
        client.write(
          'GET http://blocked.decision.invalid/ HTTP/1.1\r\nHost: blocked.decision.invalid\r\n\r\n',
        );
        final (:socket, endSpy: _, writeSpy: _) = await decision;

        client.destroy();
        await until(
          () => socket.destroyed,
          'proxy-side teardown after client destroy',
        );

        // Deny lands after the client is gone; the proxy must treat it as a
        // no-op rather than writing to the destroyed response.
        resolveVerdict(false);
        await Future<void>.delayed(const Duration(milliseconds: 50));
        // Reaching here without an unhandled error is the assertion; the
        // response was never written to a dead socket.
        expect(socket.destroyed, true);
      },
    );
  });
}
