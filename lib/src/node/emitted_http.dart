// Compatibility boundary for Node HTTP/socket details used by
// emitted-connection.dart. The supported operations delegate to the raw
// HTTP/1.1 parser and NodeSocket; unknown objects still fail closed.
import 'dart:async';

import 'http.dart' as http;
import 'net.dart' as net;

/// Whether the current runtime is Bun (Dart is not Bun).
bool runsOnBun() => false;

/// Whether the raw HTTP shim can parse a connection handed to it directly.
bool servesEmittedConnections() => true;

/// Keep Node's flushed HTTP parser header batches for an emitted connection.
/// The Dart parser already accumulates the complete raw header list per
/// IncomingMessage, so there is no second parser callback to patch.
void keepFlushedHeaderBatches(Object sock) {
  if (sock is net.NodeSocket) return;
  throw UnimplementedError(
    'Node HTTP parser callbacks on emitted connections are not exposed by '
    'dart:io; blocked on the raw HTTP/1.1 parser shim.',
  );
}

/// Configure Latin-1 writes for a Node socket handed to an emitted server.
/// NodeSocket.write(String) and ServerResponse serialize Latin-1 bytes.
void writeHeadsAsLatin1(Object sock) {
  if (sock is net.NodeSocket) return;
  throw UnimplementedError(
    'dart:io Socket has no Node-style default string encoding; blocked on the '
    'HTTP/socket shim.',
  );
}

/// Pause an emitted Node socket when an IncomingMessage body exceeds its gate.
void gateSocketOnBufferedBody(Object req, int cap, [Object? budget]) {
  if (req is http.IncomingMessage) {
    req.gateBufferedBody(cap: cap, budget: budget);
    return;
  }
  throw UnimplementedError(
    'dart:io HttpRequest exposes neither Node IncomingMessage.readableLength '
    'nor its EventEmitter socket; blocked on the HTTP/socket shim.',
  );
}

/// End or destroy the request socket after its response completes.
void endRequestAfterResponse(
  Object req, {
  required bool Function(Object socket) isMarkedEndsGracefully,
}) {
  if (req is http.IncomingMessage) {
    final socket = req.socket;
    if (isMarkedEndsGracefully(socket)) {
      socket.end();
      Timer(const Duration(seconds: 1), () {
        if (!socket.destroyed) socket.destroy();
      });
    } else {
      req.destroy();
    }
    return;
  }
  throw UnimplementedError(
    'dart:io HttpRequest has no Node IncomingMessage.destroy or underlying '
    'socket lifecycle; blocked on the HTTP/socket shim.',
  );
}
