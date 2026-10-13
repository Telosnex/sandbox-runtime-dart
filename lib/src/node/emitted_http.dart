// Compatibility boundary for the Node HTTP/socket details used by emitted-connection.dart.
// Dart has no Node HTTP parser or EventEmitter-shaped IncomingMessage/Socket.
import 'dart:async';

/// Whether the current runtime is Bun (Dart is not Bun).
bool runsOnBun() => false;

/// Whether Dart's HTTP server can serve a connection handed to it directly.
/// dart:io exposes no equivalent of Node's `server.emit('connection', sock)`.
bool servesEmittedConnections() => false;

/// The Dart HTTP parser has no exposed header-batch parser callbacks to patch.
void keepFlushedHeaderBatches(Object sock) {}

/// dart:io sockets write bytes; there is no default string encoding to change.
void writeHeadsAsLatin1(Object sock) {}

/// Apply Node's buffered-body socket gate to a Node-shaped request/socket.
///
/// This boundary intentionally uses dynamic Node method names because there
/// is no dart:io IncomingMessage type. A caller must provide the Node-like
/// `socket`, `readableLength`, `on`, `off`, and `once` interface.
void gateSocketOnBufferedBody(
  Object req,
  int cap, {
  required void Function(int delta) adjustBudget,
  required bool Function() budgetExceeded,
  required bool hasBudget,
}) {
  dynamic request = req;
  final dynamic socket = request.socket;
  var counted = 0;
  void check() {
    final int held = request.readableLength as int;
    if (hasBudget) adjustBudget(held - counted);
    counted = held;
    if (held > cap || (hasBudget && budgetExceeded() && held > 0)) {
      socket.pause();
    }
  }

  void release() {
    socket.off('data', check);
    if (hasBudget) adjustBudget(-counted);
    counted = 0;
  }

  socket.on('data', check);
  request.once('end', release);
  request.once('close', release);
}

/// Apply Node's graceful-end-or-destroy request behavior to a Node-shaped request.
///
/// dart:io's HttpRequest is not an IncomingMessage and exposes neither
/// `destroy()` nor the underlying socket, so this remains a dynamic shim
/// boundary for callers that supply that interface.
void endRequestAfterResponse(Object req, {required bool endsGracefully}) {
  dynamic request = req;
  final dynamic socket = request.socket;
  if (!endsGracefully || socket.destroyed as bool) {
    request.destroy();
    return;
  }
  socket.end();
  final backstop = Timer(const Duration(seconds: 1), () => request.destroy());
  socket.once('close', ([dynamic _]) => backstop.cancel());
}
