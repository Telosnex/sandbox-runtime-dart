// Ported from sandbox-runtime src/sandbox/socks-proxy.ts @ 24eb39e.
// ignore_for_file: dangling_library_doc_comments, slash_for_doc_comments, constant_identifier_names

import 'dart:async';
import 'dart:typed_data';

import '../node/net.dart' as net;
import '../node/socks5_server.dart' as socks5;
import '../utils/debug.dart' show logForDebugging;
import 'parent_proxy.dart'
    show
        DirectLookup,
        ResolvedParentProxy,
        canonicalizeHost,
        connectViaParentProxy,
        dialDirect,
        isValidHost,
        selectParentProxyUrl,
        shouldBypassParentProxy;
import 'resolved_address_guard.dart' show isResolvedAddressDenied;
import 'sandbox_utils.dart' show encodedCommandFromProxyUser, PROXY_AUTH_USER;

abstract interface class SocksProxyServerOptions {
  /**
   * Host-allowlist decision. `encodedCommand` is the per-command suffix
   * parsed from the SOCKS5 username (`srt.<encodedCommand>`), so the
   * manager can attribute a denial to the invocation that made it.
   */
  FutureOr<bool> filter(int port, String host, [String? encodedCommand]);
  /**
   * Optional upstream HTTP proxy. When present, SOCKS CONNECT requests are
   * tunnelled through the parent's HTTP CONNECT instead of dialing directly.
   * NO_PROXY-matched hosts still connect directly.
   */
  ResolvedParentProxy? get parentProxy;
  /** Direct-dial name resolution (see HttpProxyServerOptions.lookupFor); a refusal is answered "not allowed by ruleset". */
  DirectLookup? get lookupFor;
  /**
   * Per-session token (same value as the HTTP proxy's). When set, the
   * server requires SOCKS5 username/password auth and only accepts
   * usernames of the form `srt` or `srt.<encodedCommand>` with this token
   * as the password. The `<encodedCommand>` suffix is passed to `filter()`
   * so denials can be attributed to a specific command.
   */
  String? get proxyAuthToken;
  /**
   * Consulted for a client that cannot authenticate (it offered no
   * username/password method — e.g. BSD `nc -X 5`, the stock macOS ssh
   * ProxyCommand). Such a connection is NEVER tunnelled; this decides what
   * the refusal says. Return `deniedReason` when the destination matches an
   * explicit deny rule (the caller may also record the violation);
   * return `{}` for everything else. Must not prompt the user — the peer is unauthenticated.
   *
   * Reason copy guidance: OpenSSH truncates the printed disconnect
   * description (~400 chars) and octal-escapes non-ASCII, so keep reasons
   * for SSH-ported deny entries short, imperative-first, and ASCII.
   */
  Future<({String? deniedReason})> Function(int port, String host)?
  get probeUnauthenticated;
  /**
   * When true, every SOCKS CONNECT is refused at the handshake with
   * "general SOCKS server failure", before the allowlist is consulted and
   * before anything is dialled. A SOCKS tunnel is opaque, so nothing sent
   * through it could pass the HTTP proxy's filterRequest. Set it together
   * with HttpProxyServerOptions.refuseOpaqueTunnels.
   */
  bool? get refuseOpaqueTunnels;
  /** Called for each CONNECT refused under refuseOpaqueTunnels. */
  void Function(int port, String host, String? encodedCommand)?
  get onTunnelRefused;
}

abstract interface class SocksProxyWrapper {
  /**
   * Hand an already-accepted socket to the SOCKS state machine. Used by the
   * mux front-end after first-byte sniffing. The socket must carry the full
   * SOCKS greeting starting at byte 0 (i.e. any peeked bytes already
   * `unshift()`ed back). Replicates the library's own accept path
   * (`setNoDelay()` + `_handleConnection`) and tracks the socket so
   * `close()` can force-destroy it.
   */
  void handleConnection(net.NodeSocket socket);
  /** Force-destroy all injected connections. */
  Future<void> close();
}

const _SOCKS_REPLY_GENERAL_FAILURE = [5, 1, 0, 1, 0, 0, 0, 0, 0, 0];

SocksProxyWrapper createSocksProxyServer(SocksProxyServerOptions options) {
  final socksServer = socks5.createServer();
  if (options.proxyAuthToken != null && options.proxyAuthToken!.isNotEmpty) {
    socksServer.setAuthHandler((conn, accept, deny) {
      final username = conn.username ?? '';
      if ((username == PROXY_AUTH_USER ||
              username.startsWith('$PROXY_AUTH_USER.')) &&
          conn.password == options.proxyAuthToken) {
        accept();
      } else {
        logForDebugging('SOCKS auth rejected', level: 'error');
        deny();
      }
      return null;
    });
  }
  socksServer.setRulesetValidator((conn) async {
    if (options.refuseOpaqueTunnels == true) {
      logForDebugging(
        'SOCKS CONNECT to ${conn.destAddress}:${conn.destPort} refused (refuseOpaqueTunnels)',
      );
      options.onTunnelRefused?.call(
        conn.destPort!,
        conn.destAddress!,
        encodedCommandFromProxyUser(conn.username),
      );
      conn.socket.end(
        Uint8List.fromList(_SOCKS_REPLY_GENERAL_FAILURE),
        () => conn.socket.destroy(),
      );
      return null;
    }
    final hostname = conn.destAddress!;
    final port = conn.destPort!;
    if (!isValidHost(hostname)) {
      logForDebugging(
        'Rejecting malformed SOCKS host: "$hostname"',
        level: 'error',
      );
      return false;
    }
    logForDebugging('Connection request to $hostname:$port');
    try {
      final allowed = await options.filter(
        port,
        hostname,
        encodedCommandFromProxyUser(conn.username),
      );
      if (!allowed) {
        logForDebugging(
          'Connection blocked to $hostname:$port',
          level: 'error',
        );
        return false;
      }
      logForDebugging('Connection allowed to $hostname:$port');
      return true;
    } catch (error) {
      logForDebugging('Error validating connection: $error', level: 'error');
      return false;
    }
  });
  socksServer.setConnectionHandler((conn, sendStatus) {
    final host = canonicalizeHost(conn.destAddress!) ?? conn.destAddress!;
    final port = conn.destPort!;
    var clientGone = false;
    net.NodeSocket? upstream;
    conn.socket.once('close', () {
      clientGone = true;
      upstream?.destroy();
    });
    conn.socket.on('error', (_) => upstream?.destroy());
    final parent = options.parentProxy;
    final parentUrl = parent != null && !shouldBypassParentProxy(parent, host)
        ? selectParentProxyUrl(parent, isHttps: true)
        : null;
    final opening = parentUrl != null
        ? connectViaParentProxy(parentUrl, host, port)
        : dialDirect(
            host,
            port,
            options.lookupFor?.call(
              port,
              encodedCommandFromProxyUser(conn.username),
            ),
          );
    opening.then(
      (socket) {
        upstream = socket;
        socket.on('error', (_) => conn.socket.destroy());
        if (clientGone) {
          socket.destroy();
          return;
        }
        sendStatus('REQUEST_GRANTED');
        socket.pipe(conn.socket);
        conn.socket.pipe(socket);
        socket.on('close', () => conn.socket.destroy());
      },
      onError: (Object err) {
        logForDebugging(
          'SOCKS connect to $host:$port failed: $err',
          level: 'error',
        );
        if (!clientGone) {
          try {
            sendStatus(
              isResolvedAddressDenied(err)
                  ? 'CONNECTION_NOT_ALLOWED'
                  : 'HOST_UNREACHABLE',
            );
          } catch (_) {}
        }
      },
    );
  });
  final openSockets = <net.NodeSocket>{};
  return _SocksWrapper(socksServer, options, openSockets);
}

class _SocksWrapper implements SocksProxyWrapper {
  _SocksWrapper(this.server, this.options, this.openSockets);
  final socks5.Socks5Server server;
  final SocksProxyServerOptions options;
  final Set<net.NodeSocket> openSockets;
  @override
  void handleConnection(net.NodeSocket socket) {
    socket.setNoDelay();
    openSockets.add(socket);
    socket.once('close', () => openSockets.remove(socket));
    server.handleConnection(socket);
  }

  @override
  Future<void> close() async {
    for (final socket in openSockets) socket.destroy();
    openSockets.clear();
  }
}
