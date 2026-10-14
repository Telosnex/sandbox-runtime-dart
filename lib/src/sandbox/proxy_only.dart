// Ported from sandbox-runtime src/sandbox/proxy-only.ts @ 24eb39e.
// ignore_for_file: dangling_library_doc_comments, slash_for_doc_comments
// ignore_for_file: constant_identifier_names

import 'dart:async';

import '../node/errno.dart';

import '../node/fs.dart' as fs;
import '../node/http.dart' as http;
import '../node/net.dart' as net;
import '../node/stream.dart' as stream;
import '../utils/debug.dart';
import 'body_substitution.dart' show GetBodySubstitutions;
import 'credential_aws_pairs.dart' show PlanSigv4;
import 'decider_client.dart'
    show
        CredentialPlacement,
        CredentialPlacementBasic,
        Decider,
        DeciderOptions,
        createDecider;
import 'domain_pattern.dart' show matchesDomainPatternWithPort;
import 'emitted_connection.dart'
    show ByteBudget, keepFlushedHeaderBatches, writeHeadsAsLatin1;
import 'http_proxy.dart'
    show HttpProxyServerOptions, createHttpProxyServer, markHandedInConnection;
import 'mitm_ca.dart' show MitmCA, createMitmCA, disposeMitmCA;
import 'parent_proxy.dart'
    show DirectLookup, ResolvedParentProxy, canonicalizeHost;
import 'request_filter.dart' show FilterRequestCallback, MutateForwardedHeaders;
import 'resolved_address_guard.dart' show createResolvedAddressGuard;

/**
 * Proxy-only mode: SRT's HTTP proxy with no sandboxed child, for a host
 * that runs the workload elsewhere (a VM, a container) and points it at
 * this proxy.
 *
 * - Serves a listening socket the host hands in as an inherited fd (the
 *   host binds it and owns its path), or a loopback port for tests. A
 *   net.Server accepts on it and passes each connection to the HTTP proxy
 *   server, so the runtime only needs net-level listen-on-fd support.
 * - Every request is decided by an external decider (decider-client.ts).
 *   There is no other policy source: the host allowlist comes from the
 *   decider's hello, and no request is forwarded without an allow verdict.
 * - Only TLS-terminated or plain-HTTP requests are served: CONNECTs that
 *   cannot be terminated are refused, so nothing bypasses the decider.
 * - A lifeline stream (the read end of a pipe the host holds) ending
 *   shuts the proxy down, as does the decider's stream ending.
 */

/** The largest request head proxy-only mode parses (see maxHeaderSize). */
const int REQUEST_HEAD_LIMIT = 2 << 20;

/** Private and shared address space a proxy-only upstream dial never reaches by name. */
const List<String> DEFAULT_DENIED_RESOLVED_ADDRESSES = [
  '10.0.0.0/8',
  '172.16.0.0/12',
  '192.168.0.0/16',
  '100.64.0.0/10',
  'fc00::/7',
];

/**
 * Where an allow's credential goes when its placement isn't configured:
 * `Authorization: Bearer <value>`, except that a credential of class
 * "github" sent to github.com's git transport goes as HTTP Basic with the
 * user "x-access-token", as that transport expects.
 */
const List<CredentialPlacement> DEFAULT_CREDENTIAL_PLACEMENTS = [
  CredentialPlacementBasic(
    credentialClass: 'github',
    host: 'github.com',
    user: 'x-access-token',
  ),
];

/**
 * Where the proxy accepts connections: an inherited listening socket
 * (`fd`), or a loopback address it binds itself (tests and development).
 */
sealed class ProxyListen {
  const ProxyListen();
}

class ProxyListenFd extends ProxyListen {
  const ProxyListenFd({required this.fd});
  final int fd;
}

class ProxyListenHostPort extends ProxyListen {
  const ProxyListenHostPort({required this.host, required this.port});
  final String host;
  final int port;
}

class ProxyOnlyOptions {
  const ProxyOnlyOptions({
    required this.listen,
    required this.decider,
    this.deciderTimeoutMs,
    this.caPem,
    this.lifeline,
    this.stripResponseHeaders,
    this.deniedResolvedAddresses,
    this.plaintextHeaderSet,
    this.credentialPlacements,
    this.upstreamCA,
    this.onClosed,
  });

  final ProxyListen listen;

  /** The decider's streams: required, the proxy forwards nothing without one. */
  final ({stream.Readable input, stream.Writable output}) decider;

  final int? deciderTimeoutMs;

  /** CA (PEM private key and certificate) for TLS termination. Without it, every CONNECT is refused. */
  final String? caPem;

  /** Stream whose end (or error) shuts the proxy down. */
  final stream.Readable? lifeline;

  final List<String>? stripResponseHeaders;

  final List<String>? deniedResolvedAddresses;

  /** Let allow verdicts set headers on plain-HTTP requests (cleartext). Default off. */
  final bool? plaintextHeaderSet;

  /** Where credential classes' values go (first match wins; default Bearer). */
  final List<CredentialPlacement>? credentialPlacements;

  /** Upstream CA override for the terminated leg. Test seam. */
  final String? upstreamCA;

  /** Called once when the proxy has shut down; `why` names the cause. */
  final void Function(String why)? onClosed;
}

abstract interface class ProxyOnly {
  /** The HTTP proxy server. It never listens itself; `listener` feeds it. */
  http.NodeHttpServer get server;

  /** The net.Server accepting on the handed fd (or loopback address). */
  net.NodeServer get listener;

  Decider get decider;

  /** Resolves once the decider's hello is in and the listener is serving. */
  Future<void> get ready;

  Future<void> close([String? why]);
}

bool isBunRuntime() {
  // Dart: there is no globalThis.Bun; this is never Bun.
  return false;
}

ProxyOnly startProxyOnly(ProxyOnlyOptions opts) {
  List<String> allowed = const [];
  List<String> denied = const [];
  var guard = createResolvedAddressGuard(
    deniedResolvedAddresses:
        opts.deniedResolvedAddresses ?? DEFAULT_DENIED_RESOLVED_ADDRESSES,
  );

  Future<void>? closing;
  late final Future<void> Function([String why]) close;
  final decider = createDecider(
    DeciderOptions(
      input: opts.decider.input,
      output: opts.decider.output,
      timeoutMs: opts.deciderTimeoutMs,
      credentialPlacements:
          opts.credentialPlacements ?? DEFAULT_CREDENTIAL_PLACEMENTS,
      onDead: (why) => unawaited(close('decider: $why')),
    ),
  );

  MitmCA? mitmCA;
  if (opts.caPem != null) {
    final key = RegExp(
      r'-----BEGIN (?:RSA )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA )?PRIVATE KEY-----',
    ).firstMatch(opts.caPem!);
    final cert = RegExp(
      r'-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----',
    ).firstMatch(opts.caPem!);
    if (key == null || cert == null) {
      throw NodeException(
        'proxy-only: the CA PEM needs a private key and a certificate',
      );
    }
    mitmCA = createMitmCA(caCertPem: '${cert[0]}\n', caKeyPem: '${key[0]}\n');
  }

  bool hostAllowed(int port, String host) {
    final h = canonicalizeHost(host);
    if (h == null) return false;
    if (denied.any((p) => matchesDomainPatternWithPort(h, port, p))) {
      return false;
    }
    return allowed.any((p) => matchesDomainPatternWithPort(h, port, p));
  }

  net.LookupFunction lookupFor(int port, [String? _]) => guard.lookupFor(port);

  final server = createHttpProxyServer(
    _HttpProxyServerOptions(
      filter: (port, host) => hostAllowed(port, host),
      mitmCA: mitmCA,
      shouldTerminateTLS: (_, _) => mitmCA != null,
      refuseOpaqueTunnels: true,
      requireHostMatch: true,
      // Above the decider's 1 MiB frame, so a request past the decider's
      // limits is refused by those limits (400) rather than by the runtime's
      // header parser; a head past this is answered 400 as well.
      maxHeaderSize: REQUEST_HEAD_LIMIT,
      // Every refusal the proxy answers itself says why in X-Deny-Reason
      // (host_not_allowed, misdirected, bad_request, ...; `decider` for the
      // decider's own deny), and the request-target goes to the decider and
      // upstream exactly as the client spelled it, for the decider to match.
      denyHeader: 'X-Deny-Reason',
      requestTargetAsSpelled: true,
      // Hosts are plain ASCII; only case and one trailing dot are
      // canonicalized before the allowlist and the decider see them.
      requireAsciiHost: true,
      // A slow upstream holds at most this much of an upload in the proxy.
      // Only Bun needs it; Node's server pauses the socket itself, and a
      // 'data' listener on its socket would move its parsing to JS midway.
      maxBufferedRequestBody: isBunRuntime() ? 4 << 20 : null,
      // The request goes upstream without the client's hop-by-hop headers
      // (RFC 9110 7.6.1, in any separator spelling) or its trailers, which
      // the forwarding never copies.
      foldHopByHop: true,
      plaintextHeaderSet: opts.plaintextHeaderSet ?? false,
      filterRequest: decider.filterRequest,
      stripResponseHeaders: opts.stripResponseHeaders,
      lookupFor: lookupFor,
      tlsTerminateUpstreamCA: opts.upstreamCA,
    ),
  );
  final takesEmittedConnections = server.listenerCount('connection') > 0;
  final sockets = <net.NodeSocket>{};
  server.on('connection', (net.NodeSocket s) {
    sockets.add(s);
    s.once('close', () => sockets.remove(s));
  });
  // Connections are accepted by a net.Server that passes each one to the
  // HTTP server. For a handed fd, http.Server.listen({ fd }) is not reliable
  // across runtimes (Bun reports success and never accepts), while
  // net.Server.listen({ fd }) either works or errors, and an error fails
  // the start. For both forms, a connection Bun's native HTTP listener
  // accepted keeps being read while paused once it is a CONNECT tunnel, so
  // a slow upstream would make the proxy buffer an upload whole; a
  // net.Socket pauses. Needs a runtime whose http.Server takes emitted
  // connections (Node, Bun >= 1.4: it has a 'connection' listener of its
  // own, counted before ours below); without one, only a loopback address
  // can be served, by the HTTP server directly.
  final net.NodeServer listener =
      opts.listen is ProxyListenFd || takesEmittedConnections
      ? net.createServer((net.NodeSocket sock) {
          if (closing != null) {
            sock.destroy();
            return;
          }
          markHandedInConnection(sock);
          writeHeadsAsLatin1(sock);
          server.emit('connection', sock);
          keepFlushedHeaderBatches(sock);
        })
      : server;

  final ready = () async {
    final hello = await decider.hello;
    allowed = hello.allowedDomains;
    denied = hello.deniedDomains;
    guard = createResolvedAddressGuard(
      allowedDomains: allowed,
      deniedDomains: denied,
      deniedResolvedAddresses:
          opts.deniedResolvedAddresses ?? DEFAULT_DENIED_RESOLVED_ADDRESSES,
    );
    final completer = Completer<void>();
    void reject(Object err) => completer.completeError(err);
    listener.once('error', reject);
    void done() {
      listener.off('error', reject);
      completer.complete();
    }

    final listen = opts.listen;
    if (listen is ProxyListenFd) {
      listener.listen({'fd': listen.fd}, done);
    } else if (listen is ProxyListenHostPort) {
      listener.listen(listen.port, listen.host, done);
    }
    await completer.future;
  }();
  ready.catchError(
    (Object err) => unawaited(
      close('start failed: ${err is NodeException ? err.message : err}'),
    ),
  );

  opts.lifeline?.on('data', (_) {});
  opts.lifeline?.on('end', () => unawaited(close('lifeline closed')));
  opts.lifeline?.on('error', (_) => unawaited(close('lifeline error')));

  close = ([String why = 'closed']) {
    if (closing != null) return closing!;
    logForDebugging('[proxy-only] shutting down: $why');
    closing = () async {
      await Future<void>.value();
      decider.close();
      // Stop accepting; give in-flight requests (including the denials a
      // dead decider just produced) a grace period to flush, then destroy.
      if (listener.listening) listener.close();
      server.closeIdleConnections();
      final completer = Completer<void>();
      late final Timer check;
      late final Timer t;
      void done() {
        check.cancel();
        t.cancel();
        if (!completer.isCompleted) completer.complete();
      }

      check = Timer.periodic(const Duration(milliseconds: 25), (_) {
        if (sockets.isEmpty) done();
      });
      t = Timer(const Duration(milliseconds: 1000), () {
        for (final s in sockets.toList()) {
          s.destroy();
        }
        done();
      });
      await completer.future;
      if (mitmCA != null) await disposeMitmCA(mitmCA);
      opts.onClosed?.call(why);
    }();
    return closing!;
  };

  return _ProxyOnly(
    server: server,
    listener: listener,
    decider: decider,
    ready: ready,
    closeFn: close,
  );
}

// Dart: upstream returns an object literal; this class carries it.
class _ProxyOnly implements ProxyOnly {
  _ProxyOnly({
    required this.server,
    required this.listener,
    required this.decider,
    required this.ready,
    required Future<void> Function([String why]) closeFn,
  }) : _close = closeFn;

  @override
  final http.NodeHttpServer server;
  @override
  final net.NodeServer listener;
  @override
  final Decider decider;
  @override
  final Future<void> ready;
  final Future<void> Function([String why]) _close;

  @override
  Future<void> close([String? why]) => why == null ? _close() : _close(why);
}

// Dart: upstream passes an object literal to createHttpProxyServer.
class _HttpProxyServerOptions implements HttpProxyServerOptions {
  _HttpProxyServerOptions({
    required bool Function(int port, String host) filter,
    this.mitmCA,
    this.shouldTerminateTLS,
    this.refuseOpaqueTunnels,
    this.requireHostMatch,
    this.maxHeaderSize,
    this.denyHeader,
    this.requestTargetAsSpelled,
    this.requireAsciiHost,
    this.maxBufferedRequestBody,
    this.foldHopByHop,
    this.plaintextHeaderSet,
    this.filterRequest,
    this.stripResponseHeaders,
    this.lookupFor,
    this.tlsTerminateUpstreamCA,
  }) : _filter = filter;

  final bool Function(int port, String host) _filter;

  @override
  FutureOr<bool> filter(
    int port,
    String host,
    stream.Duplex socket, [
    String? encodedCommand,
    void Function(String reason)? explain,
  ]) => _filter(port, host);

  @override
  String? Function(String host)? getMitmSocketPath;
  @override
  final MitmCA? mitmCA;
  @override
  bool Function(String hostname, int port)? shouldTerminateTLS;
  @override
  final FilterRequestCallback? filterRequest;
  @override
  final void Function(
    ({String method, String url, String reason, String? encodedCommand}),
  )?
  onFilterRequestDenied = null;
  @override
  final MutateForwardedHeaders? mutateHeaders = null;
  @override
  final MutateForwardedHeaders? mutateHeadersPlaintext = null;
  @override
  final GetBodySubstitutions? getBodySubstitutions = null;
  @override
  final GetBodySubstitutions? getBodySubstitutionsPlaintext = null;
  @override
  final PlanSigv4? planSigv4 = null;
  @override
  final int? maxSigv4ResignBodyBytes = null;
  @override
  final Object? tlsTerminateUpstreamCA;
  @override
  final ResolvedParentProxy? parentProxy = null;
  @override
  final DirectLookup? lookupFor;
  @override
  final String? proxyAuthToken = null;
  @override
  final bool? plaintextHeaderSet;
  @override
  final List<String>? stripResponseHeaders;
  @override
  final bool? refuseOpaqueTunnels;
  @override
  final bool? requireHostMatch;
  @override
  final int? maxHeaderSize;
  @override
  final String? denyHeader;
  @override
  final bool? requestTargetAsSpelled;
  @override
  final bool? requireAsciiHost;
  @override
  final bool? foldHopByHop;
  @override
  final int? maxBufferedRequestBody;
  @override
  final int? maxTerminatedTunnels = null;
  @override
  final int? tlsHandshakeTimeoutMs = null;
  @override
  final int? maxBufferedBytes = null;
  @override
  final ByteBudget? byteBudget = null;
}

/** Read a whole PEM from an inherited fd (a pipe the host closes after writing). */
String readPemFromFd(int fd) {
  return fs.readFileSync(fd, 'utf8') as String;
}

/**
 * Streams over an inherited fd (a pipe or a socket).
 *
 * Node: a net.Socket on the fd, which libuv drives non-blockingly. An
 * fs stream would park a threadpool thread in read(), and process.exit()
 * then waits for that read to return, so the proxy could not exit while
 * the peer keeps the fd open.
 * Bun: the runtime's own file streams, which poll the fd as Node's sockets
 * do. Bun's net.Socket({fd}) does not read or write an inherited fd, and an
 * fs stream parks a thread-pool thread in each blocking read(): with the
 * decider and the lifeline both waiting, a machine with one or two CPUs has
 * no thread left to write the next frame to the decider, and every request
 * times out. The writer is opened on first write, so an fd used only for
 * input (the lifeline) gets none.
 */
({stream.Readable input, stream.Writable output}) openFdStreams(int fd) {
  if (isBunRuntime()) {
    throw UnimplementedError('Bun only');
  }
  final sock = net.Socket({'fd': fd, 'readable': true, 'writable': true});
  return (input: sock, output: sock);
}
