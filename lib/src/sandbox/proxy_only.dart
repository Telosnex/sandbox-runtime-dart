// STUB: pending port of src/sandbox/proxy-only.ts @ 24eb39e.
// ignore_for_file: dangling_library_doc_comments, slash_for_doc_comments
// ignore_for_file: constant_identifier_names

import '../node/http.dart' as http;
import '../node/net.dart' as net;
import '../node/stream.dart' as stream;
import 'decider_client.dart'
    show CredentialPlacement, CredentialPlacementBasic, Decider;

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
  throw UnimplementedError('pending port of src/sandbox/proxy-only.ts');
}

ProxyOnly startProxyOnly(ProxyOnlyOptions opts) {
  throw UnimplementedError('pending port of src/sandbox/proxy-only.ts');
}

/** Read a whole PEM from an inherited fd (a pipe the host closes after writing). */
String readPemFromFd(int fd) {
  throw UnimplementedError('pending port of src/sandbox/proxy-only.ts');
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
  throw UnimplementedError('pending port of src/sandbox/proxy-only.ts');
}
