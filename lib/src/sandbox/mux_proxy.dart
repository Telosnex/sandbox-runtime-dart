// Ported from sandbox-runtime src/sandbox/mux-proxy.ts @ 24eb39e.
// ignore_for_file: slash_for_doc_comments, dangling_library_doc_comments, unused_element, constant_identifier_names, non_constant_identifier_names

import 'dart:io' show Directory, HttpServer, ServerSocket, Socket, pid;

import 'package:path/path.dart' show join;

/**
 * First-byte values that select the SOCKS handler. SOCKS5's greeting is
 * `VER NMETHODS METHODS...` with VER=0x05; SOCKS4's CONNECT is
 * `VN CD DSTPORT...` with VN=0x04. Everything else on this port is HTTP:
 * request methods start with an ASCII uppercase letter (>= 0x41 'A'),
 * h2-prior-knowledge starts `PRI ` (0x50), and a stray TLS ClientHello
 * starts 0x16 — none of which collide with 0x04/0x05. A one-byte peek is
 * therefore an unambiguous discriminator.
 */
final Set<int> _SOCKS_FIRST_BYTES = {0x04, 0x05};

class MuxProxyOptions {
  MuxProxyOptions({
    required this.httpServer,
    required this.handleSocksConnection,
    this.firstByteTimeoutMs,
    this.httpBackendPortRange,
  });

  /**
   * The HTTP CONNECT/absolute-URI proxy. Must NOT already be listening;
   * the mux owns its listen lifecycle (on a private unix socket on
   * macOS/Linux, or a localhost TCP port on Windows).
   */
  final HttpServer httpServer;

  /**
   * Per-connection SOCKS entry point. The mux calls this with a socket
   * whose peeked first byte has been restored to the readable stream, so
   * the handler sees the full SOCKS greeting starting at byte 0.
   */
  final void Function(Socket socket) handleSocksConnection;

  /**
   * How long to wait for the client's first byte before destroying the
   * connection. Guards against connect-then-stall clients holding a slot.
   */
  final int? firstByteTimeoutMs;

  /**
   * Windows only: range the HTTP backend's TCP port must fall inside, so
   * the WFP loopback permit covers the mux→backend hop. Ignored on other
   * platforms (unix socket needs no port).
   */
  final List<int>? httpBackendPortRange;
}

abstract interface class MuxProxyServer {
  /** The front-end TCP listener. Call `.listen()` on this. */
  ServerSocket get server;

  /** Bound front-end port, once listening. */
  int? getPort();

  /**
   * Start the HTTP backend listener (unix socket on macOS/Linux, localhost
   * TCP on Windows). Must be awaited before the front-end `.listen()`s so
   * an early HTTP connection never dispatches to an unbound backend.
   * Returns the backend's TCP port on Windows (so the caller can exclude
   * it when binding the front-end in the same range), or undefined on
   * unix-socket platforms.
   */
  Future<int?> listenHttpBackend();

  /** Tear down front-end, backend, and all open client sockets. */
  Future<void> close();

  /**
   * The part of close() left to a process 'exit' handler, where nothing
   * awaited runs: remove the backend's unix socket file (Windows has none).
   */
  void removeBackendSocketSync();

  /** unref() both listeners so they don't keep the event loop alive. */
  void unref();
}

const int _DEFAULT_FIRST_BYTE_TIMEOUT_MS = 10_000;

var _backendSeq = 0;
String _unixSocketPath() {
  // Keep it short — macOS sun_path is 104 bytes.
  return join(
    Directory.systemTemp.path,
    'srt-mux-$pid-${(_backendSeq++).toRadixString(36)}.sock',
  );
}

/**
 * Single-port proxy front-end that dispatches each connection to either the
 * SOCKS handler or the HTTP proxy based on the first byte the client sends.
 *
 * The HTTP leg cannot use `httpServer.emit('connection', socket)` because
 * Bun's `http.Server` does not implement that injection path (Node does).
 * Instead the HTTP backend listens on a private endpoint — a unix socket on
 * macOS/Linux, a localhost TCP port on Windows — and the mux pipes the
 * client socket to it. SOCKS connections are handed directly to the
 * library's per-connection entry, no extra hop.
 */
MuxProxyServer createMuxProxyServer(MuxProxyOptions opts) {
  // The Node net server/socket readable stream (including read(1), unshift,
  // pipe, close/error events, and unref), plus Node HTTP Server's Unix-socket
  // listen lifecycle, have no faithful Dart equivalent yet. Returning a
  // partially working mux could send HTTP or SOCKS traffic to the wrong leg.
  throw UnimplementedError(
    'mux-proxy requires the HTTP/socket shim: Node net first-byte peek/unshift, duplex socket piping and lifecycle, and HTTP backend Unix-socket listen/connect are not implemented',
  );
}
