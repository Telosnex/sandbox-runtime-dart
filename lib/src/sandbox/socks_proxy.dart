// STUB: pending port of src/sandbox/socks-proxy.ts @ 24eb39e.
// ignore_for_file: dangling_library_doc_comments, slash_for_doc_comments

import '../node/net.dart' as net;
import 'parent_proxy.dart' show DirectLookup, ResolvedParentProxy;

abstract interface class SocksProxyServerOptions {
  /**
   * Host-allowlist decision. `encodedCommand` is the per-command suffix
   * parsed from the SOCKS5 username (`srt.<encodedCommand>`), so the
   * manager can attribute a denial to the invocation that made it.
   */
  Future<bool> filter(int port, String host, [String? encodedCommand]);

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
   * return `{}` for everything else. Must not prompt the user — the peer
   * is unauthenticated.
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

SocksProxyWrapper createSocksProxyServer(SocksProxyServerOptions options) {
  throw UnimplementedError('pending port of src/sandbox/socks-proxy.ts');
}
