// Ported from sandbox-runtime src/sandbox/mux-proxy.ts @ 24eb39e.
// ignore_for_file: slash_for_doc_comments, dangling_library_doc_comments, constant_identifier_names, non_constant_identifier_names

import 'dart:async';
import 'dart:io' show pid;
import 'dart:typed_data';

import 'package:path/path.dart' show join;

import '../node/errno.dart';
import '../node/fs.dart' as fs;
import '../node/fs_promises.dart' as fs_promises;
import '../node/http.dart' as http;
import '../node/net.dart' as net;
import '../node/os.dart' show tmpdir;
import '../utils/debug.dart';
import '../utils/platform.dart';
import 'listen_in_range.dart';

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
  const MuxProxyOptions({
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
  final http.NodeHttpServer httpServer;

  /**
   * Per-connection SOCKS entry point. The mux calls this with a socket
   * whose peeked first byte has been `unshift()`ed back, so the handler
   * sees the full SOCKS greeting starting at byte 0.
   */
  final void Function(net.NodeSocket socket) handleSocksConnection;

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
  final (int, int)? httpBackendPortRange;
}

abstract interface class MuxProxyServer {
  /** The front-end TCP listener. Call `.listen()` on this. */
  net.NodeServer get server;

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
    tmpdir(),
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
  final firstByteTimeoutMs =
      opts.firstByteTimeoutMs ?? _DEFAULT_FIRST_BYTE_TIMEOUT_MS;
  final isWindows = getPlatform() == 'windows';

  // Where the HTTP backend listens. Exactly one of these is set after
  // listenHttpBackend() resolves.
  String? backendSocketPath;
  int? backendTcpPort;

  // Track every accepted client socket so close() can tear them down
  // immediately rather than waiting for in-flight tunnels to drain.
  final openSockets = <net.NodeSocket>{};

  void dispatchHttp(net.NodeSocket client) {
    if (backendSocketPath == null && backendTcpPort == null) {
      // listenHttpBackend() must resolve before the front-end listens; this
      // guard is defense-in-depth in case a future caller reorders them.
      logForDebugging(
        'mux: HTTP dispatch before backend bound; dropping',
        level: 'error',
      );
      client.destroy();
      return;
    }
    final upstream = backendSocketPath != null && backendSocketPath != ''
        ? net.connect(backendSocketPath!)
        : net.connect(backendTcpPort!, '127.0.0.1');
    upstream.on('error', (Object err) {
      // Surface a 502 with the errno code so callers (and CI logs) can tell
      // *why* the backend was unreachable instead of an opaque empty-reply.
      // Full error (including path) goes to debug logging only — the client
      // is our own sandboxed child, but there's no need to echo host paths.
      final code = (err is NodeError ? err.code : null) ?? 'ERR';
      logForDebugging(
        'mux: HTTP backend dial failed: ${errorMessage(err)}',
        level: 'error',
      );
      if (!client.destroyed) {
        client.end(
          'HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n'
          'mux backend dial failed ($code)\n',
        );
      }
    });
    client.on('error', () => upstream.destroy());
    client.once('close', () => upstream.destroy());
    upstream.once('close', () => client.destroy());
    client.pipe(upstream);
    upstream.pipe(client);
  }

  final server = net.createServer((net.NodeSocket client) {
    openSockets.add(client);
    client.once('close', () => openSockets.remove(client));
    client.on(
      'error',
      (Object err) =>
          logForDebugging('mux: client socket error: ${errorMessage(err)}'),
    );

    final timer = Timer(Duration(milliseconds: firstByteTimeoutMs), () {
      logForDebugging('mux: first-byte timeout; destroying connection');
      client.destroy();
    });
    // Don't let a pending sniff keep the process alive.
    // Dart: a Timer has no unref(); upstream's typeof check is false here.

    client.once('readable', () {
      timer.cancel();
      final Uint8List? peek = client.read(1);
      if (peek == null || peek.isEmpty) {
        // EOF before any byte — client connected and closed.
        client.destroy();
        return;
      }
      client.unshift(peek);
      if (_SOCKS_FIRST_BYTES.contains(peek[0])) {
        opts.handleSocksConnection(client);
      } else {
        dispatchHttp(client);
      }
    });
  });

  return _MuxProxyServer(
    server: server,
    getPort: () {
      final addr = server.address();
      return addr is net.NodeAddress ? addr.port : null;
    },
    listenHttpBackend: () async {
      if (!isWindows) {
        final path = _unixSocketPath();
        // A prior process with the same PID may have crashed without
        // unlinking; clear any stale file so listen() doesn't EADDRINUSE.
        await fs_promises.unlink(path).catchError((_) {});
        final completer = Completer<void>();
        void reject(Object err) => completer.completeError(err);
        opts.httpServer.once('error', reject);
        opts.httpServer.listen(path, () {
          opts.httpServer.removeListener('error', reject);
          completer.complete();
        });
        await completer.future;
        backendSocketPath = path;
        logForDebugging('mux: HTTP backend listening on $path');
        return null;
      }
      // Windows: AF_UNIX support under Bun is unverified, so the backend
      // listens on a localhost TCP port inside the WFP-permitted range.
      // The mux→backend hop originates from the parent process (not the
      // sandboxed child), so WFP doesn't strictly require it; staying in
      // range just keeps the port surface predictable.
      await listenInRange(
        opts.httpServer,
        (p) => opts.httpServer.listen(p, '127.0.0.1'),
        opts.httpBackendPortRange == null
            ? null
            : [opts.httpBackendPortRange!.$1, opts.httpBackendPortRange!.$2],
        <int>{},
      );
      final addr = opts.httpServer.address();
      backendTcpPort = addr is net.NodeAddress ? addr.port : null;
      logForDebugging(
        'mux: HTTP backend listening on 127.0.0.1:$backendTcpPort',
      );
      return backendTcpPort;
    },
    close: () async {
      for (final s in openSockets.toList()) {
        s.destroy();
      }
      openSockets.clear();
      final serverClosed = Completer<void>();
      server.close(([_]) => serverClosed.complete());
      await serverClosed.future;
      // The mux owns httpServer's listen lifecycle, so it owns close too.
      // sandbox-manager.reset() additionally calls forceCloseHttpServer()
      // for closeAllConnections() semantics; double-close is a no-op.
      final httpClosed = Completer<void>();
      opts.httpServer.close(([_]) => httpClosed.complete());
      await httpClosed.future;
      if (backendSocketPath != null && backendSocketPath != '') {
        await fs_promises.unlink(backendSocketPath!).catchError((_) {});
        backendSocketPath = null;
      }
      backendTcpPort = null;
    },
    removeBackendSocketSync: () {
      try {
        if (backendSocketPath != null && backendSocketPath != '') {
          fs.rmSync(backendSocketPath!, {'force': true});
        }
      } catch (_) {
        // Best effort, as in close().
      }
    },
    unref: () {
      server.unref();
      opts.httpServer.unref();
    },
  );
}

// Dart: upstream returns an object literal; this class carries its methods.
class _MuxProxyServer implements MuxProxyServer {
  _MuxProxyServer({
    required this.server,
    required int? Function() getPort,
    required Future<int?> Function() listenHttpBackend,
    required Future<void> Function() close,
    required void Function() removeBackendSocketSync,
    required void Function() unref,
  }) : _getPort = getPort,
       _listenHttpBackend = listenHttpBackend,
       _close = close,
       _removeBackendSocketSync = removeBackendSocketSync,
       _unref = unref;

  @override
  final net.NodeServer server;
  final int? Function() _getPort;
  final Future<int?> Function() _listenHttpBackend;
  final Future<void> Function() _close;
  final void Function() _removeBackendSocketSync;
  final void Function() _unref;

  @override
  int? getPort() => _getPort();
  @override
  Future<int?> listenHttpBackend() => _listenHttpBackend();
  @override
  Future<void> close() => _close();
  @override
  void removeBackendSocketSync() => _removeBackendSocketSync();
  @override
  void unref() => _unref();
}
