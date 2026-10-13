// Compatibility boundary for Node HTTP/socket details used by
// emitted-connection.dart. Dart's dart:io has no equivalent APIs yet.

/// Whether the current runtime is Bun (Dart is not Bun).
bool runsOnBun() => false;

/// Whether Dart's HTTP server can serve a connection handed to it directly.
/// dart:io exposes no equivalent of Node's `server.emit('connection', sock)`.
bool servesEmittedConnections() => false;

/// Keep Node's flushed HTTP parser header batches for an emitted connection.
Never keepFlushedHeaderBatches(Object sock) => throw UnimplementedError(
  'Node HTTP parser callbacks on emitted connections are not exposed by '
  'dart:io; blocked on the raw HTTP/1.1 parser shim.',
);

/// Configure Latin-1 writes for a Node socket handed to an emitted server.
Never writeHeadsAsLatin1(Object sock) => throw UnimplementedError(
  'dart:io Socket has no Node-style default string encoding; blocked on the '
  'HTTP/socket shim.',
);

/// Pause an emitted Node socket when an IncomingMessage body exceeds its gate.
Never gateSocketOnBufferedBody(Object req, int cap, [Object? budget]) =>
    throw UnimplementedError(
      'dart:io HttpRequest exposes neither Node IncomingMessage.readableLength '
      'nor its EventEmitter socket; blocked on the HTTP/socket shim.',
    );

/// End or destroy the request socket after its response completes.
Never endRequestAfterResponse(
  Object req, {
  required bool Function(Object socket) isMarkedEndsGracefully,
}) => throw UnimplementedError(
  'dart:io HttpRequest has no Node IncomingMessage.destroy or underlying '
  'socket lifecycle; blocked on the HTTP/socket shim.',
);
