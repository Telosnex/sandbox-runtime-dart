// Ported from sandbox-runtime src/sandbox/emitted-connection.ts @ 24eb39e.
// ignore_for_file: slash_for_doc_comments, dangling_library_doc_comments

import 'dart:async';

import '../node/http.dart' as http;
import '../node/errno.dart';
import '../node/net.dart' as net;
import '../node/process.dart' as process;

/**
 * Workarounds for a runtime whose http.Server, serving a connection handed
 * to it with emit('connection') (Bun's), falls short of Node's server.
 */

/** Whether this is Bun, whose http.Server these workarounds are for. */
bool runsOnBun() {
  // Dart: there is no globalThis.Bun; this is never Bun.
  return false;
}

bool Function()? _probeOverride;

/**
 * Whether this runtime's http.Server serves a connection handed to it with
 * emit('connection'): Node's and Bun's from 1.4 do, and such a server has
 * a 'connection' listener of its own. TLS termination in this process
 * hands each tunnel's decrypted connection to one.
 */
bool servesEmittedConnections() {
  return _probeOverride?.call() ??
      http.createServer().listenerCount('connection') > 0;
}

/**
 * @internal Test seam: answer servesEmittedConnections with `probe` in
 * place of the runtime's own answer (undefined restores it). Not exported
 * from the package.
 */
void overrideEmittedConnectionProbe(bool Function()? probe) {
  _probeOverride = probe;
}

/** The runtime, as the start-up error names it. */
String _runtimeName() {
  final bun = process.versions['bun'];
  return bun != null ? 'Bun $bun' : 'Node ${process.version}';
}

/**
 * Throw where TLS termination is asked for and this runtime cannot do it
 * in-process (Bun before 1.4, see servesEmittedConnections). Called before
 * anything is started: without it, every tunnel to be terminated would be
 * answered 200 and then closed.
 */
void assertTlsTerminationSupported() {
  if (servesEmittedConnections()) return;
  throw NodeException(
    'tlsTerminate needs Node, or Bun 1.4 or later (this is ${_runtimeName()})',
  );
}

/**
 * The HTTP parser hands a request's head over in batches when it has many
 * header lines (every 31 in Node's and Bun's), calling onHeaders for each
 * and then onHeadersComplete with no headers and no URL of its own. Bun's
 * server for an emitted connection installs no onHeaders, so all but the
 * last batch, the request target among them, would be lost. Where the
 * parser on the socket has no onHeaders, collect the batches as Node's
 * server does and hand them to onHeadersComplete.
 *
 * The parser reports a chunked request's trailers through onHeaders too
 * (with the request's own target again), after the body and before
 * onMessageComplete. Those are not a batch of the next request's head:
 * what is held when a message completes is dropped, as Node's server
 * clears its own, so a request's trailers and target never become part of
 * the request that follows it on the connection. Where the parser has no
 * onMessageComplete to tell the two apart, nothing is installed.
 */
void keepFlushedHeaderBatches(net.NodeSocket sock) {
  final net.HTTPParser? parser = sock.parser;
  if (parser == null) return;
  // Dart: the statics are HTTPParser's constants, so upstream's typeof checks
  // on parser.constructor are always true.
  const int onHeaders = net.HTTPParser.kOnHeaders;
  const int onHeadersComplete = net.HTTPParser.kOnHeadersComplete;
  const int onMessageComplete = net.HTTPParser.kOnMessageComplete;
  final Function? complete = parser[onHeadersComplete];
  final Function? messageComplete = parser[onMessageComplete];
  if (parser[onHeaders] is Function ||
      complete is! Function ||
      messageComplete is! Function) {
    return;
  }
  var headers = <String>[];
  var url = '';
  parser[onHeaders] = (List<String> batch, String part) {
    headers = [...headers, ...batch];
    url += part;
  };
  parser[onHeadersComplete] =
      ([
        Object? a0,
        Object? a1,
        Object? a2,
        Object? a3,
        Object? a4,
        Object? a5,
        Object? a6,
        Object? a7,
        Object? a8,
      ]) {
        final args = [a0, a1, a2, a3, a4, a5, a6, a7, a8];
        if (headers.isNotEmpty || url != '') {
          args[2] = args[2] is List
              ? [...headers, ...(args[2] as List)]
              : headers;
          args[4] = url + (args[4] is String ? args[4] as String : '');
          headers = [];
          url = '';
        }
        return Function.apply(complete, args);
      };
  parser[onMessageComplete] = () {
    // Whatever came through onHeaders since the head was the message's
    // trailers.
    headers = [];
    url = '';
    return Function.apply(messageComplete, []);
  };
}

/**
 * A header string holds one char per byte, as the HTTP parser read it from
 * the upstream, and Node's server names latin1 when it writes a response's
 * head. Bun's server for an emitted connection names no encoding, so the
 * socket's default applies: as UTF-8, every header byte from 0x80 up would
 * reach the client as two. So latin1 is made the default of a socket about
 * to be emitted. Anything else written to it with no encoding named has to
 * be bytes or ASCII (see respondDenied).
 */
void writeHeadsAsLatin1(net.NodeSocket sock) {
  if (runsOnBun()) sock.setDefaultEncoding('latin1');
}

/**
 * Bytes a proxy's connections together may hold for slow parties (request
 * bodies waiting for an upstream, responses waiting for a client). Each
 * connection adds what it holds to `used`; past `limit`, every one of
 * them holds no more than it must.
 */
class ByteBudget {
  ByteBudget({required this.limit, this.used = 0});

  int limit;
  int used;

  /// Holders paused on the budget; each is called once when `used` drops.
  Set<void Function()> waiters = {};
}

ByteBudget createByteBudget(int limit) => ByteBudget(limit: limit);

/**
 * Add `delta` to what `budget`'s holders hold. A drop wakes every waiter:
 * each re-counts for itself and waits again if there is still no room.
 */
void adjustByteBudget(ByteBudget budget, int delta) {
  budget.used += delta;
  if (delta >= 0 || budget.waiters.isEmpty) return;
  final woken = budget.waiters.toList();
  budget.waiters.clear();
  for (final wake in woken) {
    wake();
  }
}

/**
 * Pause req's socket whenever more than `cap` bytes of req's body sit in
 * req's buffer, or any do while `budget` is spent. Pausing the
 * IncomingMessage is not enough where the runtime keeps pushing into it
 * from a flowing socket; pausing the socket is. The server resumes the
 * socket itself when the body's reader pulls (IncomingMessage._read). Only
 * the socket is listened to: a 'data' listener on req would start the body
 * flowing before anyone reads it.
 */
void gateSocketOnBufferedBody(
  http.IncomingMessage req,
  int cap, [
  ByteBudget? budget,
]) {
  final socket = req.socket;
  var counted = 0;
  void check() {
    final held = req.readableLength;
    if (budget != null) adjustByteBudget(budget, held - counted);
    counted = held;
    if (held > cap ||
        (budget != null && budget.used > budget.limit && held > 0)) {
      socket.pause();
    }
  }

  void release() {
    socket.off('data', check);
    if (budget != null) adjustByteBudget(budget, -counted);
    counted = 0;
  }

  socket.on('data', check);
  req.once('end', release);
  req.once('close', release);
}

final Expando<bool> _endsGracefully = Expando<bool>();

/**
 * Mark a TLS-terminated tunnel's socket: once a response on it is done, the
 * request is ended by ending the socket (close_notify, then a FIN once the
 * queue is flushed), not by destroying it, which would drop what the TLS
 * layer has not yet written out.
 */
void markEndsGracefully(Object socket) {
  _endsGracefully[socket] = true;
}

/**
 * Stop a request whose response is out: end its socket where it is marked
 * (then destroy it after a second, for a client that keeps sending), else
 * destroy the request.
 */
void endRequestAfterResponse(http.IncomingMessage req) {
  final socket = req.socket;
  if (_endsGracefully[socket] != true || socket.destroyed) {
    req.destroy();
    return;
  }
  socket.end();
  final backstop = Timer(
    const Duration(milliseconds: 1000),
    () => req.destroy(),
  );
  // Dart: a Timer has no unref().
  socket.once('close', () => backstop.cancel());
}
