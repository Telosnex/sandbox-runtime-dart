// Ported from sandbox-runtime src/sandbox/socks-proxy.ts @ 24eb39e.
// ignore_for_file: dangling_library_doc_comments, slash_for_doc_comments, constant_identifier_names, non_constant_identifier_names, unintended_html_in_doc_comment

import 'dart:async';
import 'dart:convert';
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

// VER, REP=0x01 (general SOCKS server failure), RSV, ATYP=IPv4, 0.0.0.0:0.
final _SOCKS_REPLY_GENERAL_FAILURE = Uint8List.fromList([
  5,
  1,
  0,
  1,
  0,
  0,
  0,
  0,
  0,
  0,
]);

SocksProxyWrapper createSocksProxyServer(SocksProxyServerOptions options) {
  final socksServer = socks5.createServer();

  final token = options.proxyAuthToken;
  if (token != null && token.isNotEmpty) {
    socksServer.setAuthHandler((conn, accept, deny) {
      if ((conn.username == PROXY_AUTH_USER ||
              conn.username!.startsWith('$PROXY_AUTH_USER.')) &&
          conn.password == options.proxyAuthToken) {
        accept();
      } else {
        logForDebugging('SOCKS auth rejected', level: 'error');
        deny();
      }
      return null;
    });
  }

  Future<bool> validateDestination(socks5.Socks5Connection conn) async {
    try {
      final hostname = conn.destAddress!;
      final port = conn.destPort!;

      // SOCKS5 DOMAINNAME is a raw length-prefixed byte string with zero
      // validation from the protocol or the library. Reject control chars
      // (null bytes, CRLF) here so they never reach the allowlist matcher,
      // where string suffix matching would be trivially fooled.
      if (!isValidHost(hostname)) {
        logForDebugging(
          'Rejecting malformed SOCKS host: ${jsonEncode(hostname)}',
          level: 'error',
        );
        return false;
      }

      logForDebugging('Connection request to $hostname:$port');

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
  }

  socksServer.setRulesetValidator((conn, _, _) {
    if (options.refuseOpaqueTunnels == true) {
      logForDebugging(
        'SOCKS CONNECT to ${jsonEncode(conn.destAddress)}:${conn.destPort} refused (refuseOpaqueTunnels)',
      );
      options.onTunnelRefused?.call(
        conn.destPort!,
        conn.destAddress!,
        encodedCommandFromProxyUser(conn.username),
      );
      // Answered here rather than through the library's deny, whose reply
      // claims a ruleset refusal of this destination.
      conn.socket.end(
        _SOCKS_REPLY_GENERAL_FAILURE,
        () => conn.socket.destroy(),
      );
      return null;
    }
    return validateDestination(conn);
  });

  // Override the default connection handler so we can route through a parent
  // HTTP proxy when one is configured. The default handler does a straight
  // net.connect() which fails when direct egress is blocked.
  socksServer.setConnectionHandler((conn, sendStatus) {
    // The ruleset validator above allowed this destination on its
    // canonical spelling; dial (and make the parent-proxy decision on)
    // that same spelling, as the HTTP proxy does, rather than the client's.
    final host = canonicalizeHost(conn.destAddress!) ?? conn.destAddress!;
    final port = conn.destPort!;

    // Track client liveness so we can abort the upstream dial if they bail.
    var clientGone = false;
    net.NodeSocket? upstreamRef;
    conn.socket.once('close', ([_]) {
      clientGone = true;
      upstreamRef?.destroy();
    });
    conn.socket.on('error', (_) => upstreamRef?.destroy());

    // SOCKS is an opaque TCP tunnel — semantically identical to HTTP
    // CONNECT — so always prefer HTTPS_PROXY if set, regardless of dest port.
    final parentProxy = options.parentProxy;
    final parentUrl =
        parentProxy != null && !shouldBypassParentProxy(parentProxy, host)
        ? selectParentProxyUrl(parentProxy, isHttps: true)
        : null;

    final open = parentUrl != null
        ? connectViaParentProxy(parentUrl, host, port)
        : dialDirect(
            host,
            port,
            options.lookupFor?.call(
              port,
              encodedCommandFromProxyUser(conn.username),
            ),
          );

    open
        .then((upstream) {
          upstreamRef = upstream;
          upstream.on('error', (_) => conn.socket.destroy());
          if (clientGone) {
            upstream.destroy();
            return;
          }
          sendStatus('REQUEST_GRANTED');
          upstream.pipe(conn.socket);
          conn.socket.pipe(upstream);
          upstream.on('close', ([_]) => conn.socket.destroy());
        })
        .catchError((Object err) {
          logForDebugging(
            'SOCKS connect to $host:$port failed: ${_message(err)}',
            level: 'error',
          );
          if (!clientGone) {
            try {
              sendStatus(
                isResolvedAddressDenied(err)
                    ? 'CONNECTION_NOT_ALLOWED'
                    : 'HOST_UNREACHABLE',
              );
            } catch (_) {
              // socket may have closed between the check and the write
            }
          }
        });
    return null;
  });

  // Track every injected client socket so close() can tear them down
  // immediately. A SOCKS connection still inside `dialDirect()`
  // (CONNECT_TIMEOUT_MS, parent-proxy.ts) or mid-relay would otherwise hold
  // reset() open until it expires. The library's internal net.Server is never
  // .listen()ed — the mux owns accept — so there's no listener to close; we
  // only destroy sockets.
  final openSockets = <net.NodeSocket>{};

  return _SocksProxyWrapper(
    handleConnection: (net.NodeSocket socket) {
      socket.setNoDelay();
      openSockets.add(socket);
      socket.once('close', ([_]) => openSockets.remove(socket));
      if (token == null || token.isEmpty) {
        socksServer.handleConnection(socket);
        return;
      }
      // Auth is required. Peek the greeting (VER NMETHODS METHODS...): a
      // client that does not offer method 0x02 (username/password) can never
      // authenticate — the library would reply 0xFF and the client dies with
      // an opaque "authentication method negotiation failed". Route it to
      // the refusal probe instead so the failure carries the policy reason
      // (for SSH, in-band — see refuseUnauthenticated). Clients that DO
      // offer 0x02 get the greeting unshifted back and the normal
      // authenticated path.
      _readSocksGreeting(socket, (canAuthenticate) {
        if (canAuthenticate) {
          socksServer.handleConnection(socket);
          return;
        }
        _refuseUnauthenticated(
          socket,
          options,
        ).catchError((Object _) => socket.destroy());
      });
    },
    close: () async {
      for (final socket in openSockets.toList()) {
        socket.destroy();
      }
      openSockets.clear();
    },
  );
}

String _message(Object err) {
  try {
    return (err as dynamic).message as String;
  } catch (_) {
    return err.toString();
  }
}

class _SocksProxyWrapper implements SocksProxyWrapper {
  _SocksProxyWrapper({
    required void Function(net.NodeSocket socket) handleConnection,
    required Future<void> Function() close,
  }) : _handleConnection = handleConnection,
       _close = close;
  final void Function(net.NodeSocket socket) _handleConnection;
  final Future<void> Function() _close;

  @override
  void handleConnection(net.NodeSocket socket) => _handleConnection(socket);

  @override
  Future<void> close() => _close();
}

const _SOCKS_METHOD_NO_AUTH = 0x00;
const _SOCKS_METHOD_USERPASS = 0x02;

/**
 * Peek the SOCKS5 greeting off the socket and report whether the client
 * offered username/password auth. Before the callback runs, the socket is
 * paused and every buffered byte is pushed back in a single `unshift` for
 * the authenticated path (the library re-reads the greeting itself), or
 * just the post-greeting surplus for the probe path (which consumed the
 * greeting by answering it). A single unshift on a paused socket is the
 * only ordering the stream API guarantees — two unshifts on a flowing
 * socket can drop or reorder pipelined bytes. Destroys the socket on
 * malformed input.
 */
void _readSocksGreeting(
  net.NodeSocket socket,
  void Function(bool canAuthenticate) done,
) {
  var buf = Uint8List(0);
  late void Function(Object?) onData;
  onData = (Object? data) {
    final chunk = data as Uint8List;
    buf = Uint8List.fromList([...buf, ...chunk]);
    if (buf.length < 2) return;
    if (buf[0] != 0x05) {
      socket.off('data', onData);
      socket.destroy();
      return;
    }
    final nMethods = buf[1];
    if (buf.length < 2 + nMethods) return;
    socket.off('data', onData);
    socket.pause();
    final methods = buf.sublist(2, 2 + nMethods);
    final canAuthenticate = methods.contains(_SOCKS_METHOD_USERPASS);
    final pushBack = canAuthenticate ? buf : buf.sublist(2 + nMethods);
    if (pushBack.isNotEmpty) socket.unshift(pushBack);
    done(canAuthenticate);
  };
  socket.on('data', onData);
  socket.once('error', (_) => socket.off('data', onData));
}

/**
 * Terminal handler for a SOCKS5 client that cannot authenticate. Completes
 * just enough of the protocol to learn the CONNECT destination, then
 * refuses — there is deliberately no code path here that dials upstream, so
 * an unauthenticated peer can never use the proxy as a relay.
 *
 * For an SSH destination (port 22) the refusal is delivered in-band: a
 * minimal SSH server identification plus a plaintext pre-key-exchange
 * SSH_MSG_DISCONNECT whose description is the policy reason. OpenSSH prints
 * that description verbatim ("Received disconnect from ...: <reason>"), so
 * a git-over-ssh user (or agent) sees WHY instead of an opaque
 * "authentication method negotiation failed". Non-SSH ports get the plain
 * SOCKS "connection not allowed" reply.
 */
Future<void> _refuseUnauthenticated(
  net.NodeSocket socket,
  SocksProxyServerOptions options,
) async {
  // Select the no-auth method so the client proceeds to its CONNECT request.
  socket.write(Uint8List.fromList([0x05, _SOCKS_METHOD_NO_AUTH]));
  final request = await _readSocksConnect(socket);
  if (request == null) {
    socket.destroy();
    return;
  }
  final (:host, :port) = request;
  if (!isValidHost(host)) {
    socket.end(_socksReply(0x02));
    return;
  }
  final probeFn = options.probeUnauthenticated;
  final probe = probeFn != null
      ? await probeFn(port, host)
      : (deniedReason: null);
  logForDebugging(
    'SOCKS unauthenticated client refused for $host:$port'
    '${probe.deniedReason != null ? ' (denied by policy)' : ''}',
  );
  if (port != 22) {
    socket.end(_socksReply(0x02));
    return;
  }
  // The built-in fallback states only what the proxy itself knows. An
  // embedder that wants environment-specific guidance (e.g. "use an
  // https:// remote") should express it as a deny rule with a reason —
  // a `*:22` deniedDomains entry covers every SSH destination.
  final reason =
      probe.deniedReason ??
      'This proxy requires authentication, and this client did not offer an '
          'authentication method, so the connection was refused.';
  // SOCKS success (bind address 0.0.0.0:0), then speak SSH.
  socket.write(_socksReply(0x00));
  socket.write(Uint8List.fromList(utf8.encode('SSH-2.0-policy_refusal\r\n')));
  socket.end(_sshDisconnectPacket(reason));
}

/** SOCKS5 reply with the given status and a zero bind address. */
Uint8List _socksReply(int status) =>
    Uint8List.fromList([0x05, status, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);

int _readUInt16BE(Uint8List buf, int offset) =>
    (buf[offset] << 8) | buf[offset + 1];

/** Parse the SOCKS5 CONNECT request (after method selection). */
Future<({String host, int port})?> _readSocksConnect(net.NodeSocket socket) {
  final completer = Completer<({String host, int port})?>();
  var buf = Uint8List(0);
  late void Function(Object?) onData;
  late Timer timer;
  void finish(({String host, int port})? value) {
    socket.off('data', onData);
    timer.cancel();
    if (!completer.isCompleted) completer.complete(value);
  }

  // An unauthenticated peer gets a short leash: if the CONNECT request
  // doesn't arrive promptly, drop the connection.
  timer = Timer(const Duration(milliseconds: 5000), () => finish(null));
  onData = (Object? data) {
    final chunk = data as Uint8List;
    buf = Uint8List.fromList([...buf, ...chunk]);
    if (buf.length < 4) return;
    if (buf[0] != 0x05 || buf[1] != 0x01 /* CONNECT */ ) {
      finish(null);
      return;
    }
    final atyp = buf[3];
    if (atyp == 0x01) {
      if (buf.length < 10) return;
      final host = buf.sublist(4, 8).join('.');
      finish((host: host, port: _readUInt16BE(buf, 8)));
    } else if (atyp == 0x03) {
      if (buf.length < 5) return;
      final len = buf[4];
      if (buf.length < 5 + len + 2) return;
      finish((
        host: utf8.decode(buf.sublist(5, 5 + len), allowMalformed: true),
        port: _readUInt16BE(buf, 5 + len),
      ));
    } else if (atyp == 0x04) {
      if (buf.length < 22) return;
      final parts = <String>[];
      for (var i = 0; i < 16; i += 2) {
        parts.add(_readUInt16BE(buf, 4 + i).toRadixString(16));
      }
      finish((host: parts.join(':'), port: _readUInt16BE(buf, 20)));
    } else {
      finish(null);
    }
  };
  socket.on('data', onData);
  // readSocksGreeting explicitly pause()d the socket; an explicit pause is
  // NOT lifted by attaching a 'data' listener, so resume by hand.
  socket.resume();
  socket.once('error', (_) => finish(null));
  socket.once('close', ([_]) => finish(null));
  return completer.future;
}

/**
 * A plaintext SSH_MSG_DISCONNECT, legal before key exchange (RFC 4253:
 * SSH_MSG_DISCONNECT may be sent at any time; pre-NEWKEYS packets carry no
 * MAC and no encryption). reason code 1 = HOST_NOT_ALLOWED_TO_CONNECT.
 * The description is what OpenSSH prints; collapse control characters so a
 * configured reason can't fabricate extra log lines, and cap the length.
 */
Uint8List _sshDisconnectPacket(String description) {
  var text = description.replaceAll(RegExp(r'[\x00-\x1f\x7f-\x9f]+'), ' ');
  // JS String#slice counts UTF-16 code units, as Dart's substring does.
  if (text.length > 1000) text = text.substring(0, 1000);
  final desc = utf8.encode(text);
  final lang = Uint8List(0);
  final payload = <int>[
    0x01, // SSH_MSG_DISCONNECT
    ..._uint32(1), // SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT
    ..._uint32(desc.length),
    ...desc,
    ..._uint32(lang.length),
    ...lang,
  ];
  // packet_length = padding_length byte + payload + padding;
  // (4 + packet_length) must be a multiple of 8, padding >= 4.
  var padding = 8 - ((4 + 1 + payload.length) % 8);
  if (padding < 4) padding += 8;
  return Uint8List.fromList([
    ..._uint32(1 + payload.length + padding),
    padding,
    ...payload,
    ...Uint8List(padding),
  ]);
}

Uint8List _uint32(int n) {
  final b = Uint8List(4);
  ByteData.sublistView(b).setUint32(0, n);
  return b;
}
