// PARTIAL: ported stripBrackets, canonicalizeHost; added API stubs for the rest; pending implementation of src/sandbox/parent-proxy.ts @ 24eb39e.
// ignore_for_file: slash_for_doc_comments, library_private_types_in_public_api

import '../node/http.dart' as http;
import '../node/net.dart' as net;
import '../node/url.dart' as url;
import 'sandbox_config.dart' show ParentProxyConfig;
import 'address.dart' show mappedIPv4;

/**
 * Parent/upstream HTTP proxy support.
 *
 * When SRT runs in an environment that requires an HTTP proxy for outbound
 * internet access (e.g. inside a VM on a host behind a corporate proxy),
 * SRT's own proxies must chain through that upstream rather than connecting
 * directly.
 *
 * This module provides:
 *   - config resolution (explicit config -> HTTP_PROXY/HTTPS_PROXY/NO_PROXY env)
 *   - NO_PROXY matching (hostname suffix + CIDR via net.BlockList). Follows
 *     golang.org/x/net/http/httpproxy semantics for suffix matching. Note:
 *     port-specific NO_PROXY entries (e.g. `host:8080`) are matched by host
 *     only; the port is ignored.
 *   - a generic CONNECT-tunnel helper that works over Unix socket, TCP, or TLS
 */

class ResolvedParentProxy {
  const ResolvedParentProxy({
    this.httpUrl,
    this.httpsUrl,
    required this.noProxy,
  });

  final url.URL? httpUrl;
  final url.URL? httpsUrl;
  final _NoProxyRules noProxy;
}

class _NoProxyRules {
  const _NoProxyRules({
    required this.all,
    required this.suffixes,
    required this.cidr,
  });

  final bool all;
  final List<String> suffixes;
  final net.BlockList cidr;
}

/**
 * Resolve the parent proxy config, falling back to the SRT process's own
 * environment. Note: SRT later overwrites HTTP_PROXY etc. in the *sandboxed
 * child's* environment to point at itself — but process.env here reflects the
 * environment SRT itself was launched with, which is what we want.
 */
ResolvedParentProxy? resolveParentProxy([ParentProxyConfig? cfg]) =>
    throw UnimplementedError('pending port of src/sandbox/parent-proxy.ts');

/**
 * Returns true if the given host should bypass the parent proxy and connect
 * directly. Always bypasses loopback.
 *
 * NB: the port is not consulted. NO_PROXY entries of the form `host:port` are
 * matched by host only (the port suffix is stripped during parsing).
 */
bool shouldBypassParentProxy(ResolvedParentProxy resolved, String host) =>
    throw UnimplementedError('pending port of src/sandbox/parent-proxy.ts');

/**
 * Pick which parent proxy URL to use for a given destination.
 */
url.URL? selectParentProxyUrl(
  ResolvedParentProxy resolved, {
  required bool isHttps,
}) => throw UnimplementedError('pending port of src/sandbox/parent-proxy.ts');

// ---------------------------------------------------------------------------
// CONNECT tunnelling
// ---------------------------------------------------------------------------

class ConnectTunnelOptions {
  const ConnectTunnelOptions({
    required this.dial,
    required this.readyEvent,
    required this.destHost,
    required this.destPort,
    this.authHeader,
    this.timeoutMs,
  });

  /** Establish the transport to the proxy. */
  final net.NodeSocket Function() dial;

  /** Fired when the transport is ready to write (e.g. 'connect'/'secureConnect'). */
  final String readyEvent;
  final String destHost;
  final int destPort;
  final String? authHeader;
  final int? timeoutMs;
}

/**
 * Generic CONNECT-tunnel: dial a proxy transport (unix/tcp/tls), send
 * `CONNECT host:port`, wait for a 2xx, and resolve with the tunnelled socket.
 * Validates destHost to prevent CRLF injection from untrusted callers.
 */
Future<net.NodeSocket> openConnectTunnel(ConnectTunnelOptions opts) =>
    throw UnimplementedError('pending port of src/sandbox/parent-proxy.ts');

/**
 * Open a CONNECT tunnel through a parent HTTP(S) proxy specified by URL.
 * Thin wrapper around openConnectTunnel that dials TCP or TLS based on the
 * proxy URL scheme.
 */
Future<net.NodeSocket> connectViaParentProxy(
  url.URL proxyUrl,
  String destHost,
  int destPort,
) => throw UnimplementedError('pending port of src/sandbox/parent-proxy.ts');

String? proxyAuthHeader(url.URL proxyUrl) =>
    throw UnimplementedError('pending port of src/sandbox/parent-proxy.ts');

/**
 * Write an upstream response's status line and headers to the client.
 *
 * An upstream can answer with a head that `writeHead` refuses to send: a
 * status code outside 100-999 (`HTTP/1.1 099 x`), or a header name or value
 * with characters that are not allowed on the wire. `writeHead` throws
 * synchronously, and from inside a response callback that exception would be
 * uncaught and end the proxy process. Such a response is answered with
 * `502 Bad Gateway` instead: nothing from the upstream head or body is
 * relayed, and the upstream connection is closed.
 *
 * `headers` is what to send in place of the upstream's own headers with the
 * hop-by-hop ones removed, for a caller that has filtered them further.
 *
 * Returns true when the head was written and the body should be piped,
 * false when the response was replaced by the 502.
 */
bool relayResponseHead(
  http.ServerResponse res,
  http.IncomingMessage upstreamRes, [
  http.IncomingHttpHeaders? headers,
]) => throw UnimplementedError('pending port of src/sandbox/parent-proxy.ts');

/**
 * Strip hop-by-hop and proxy-specific headers before forwarding upstream.
 * Also strips any headers named in the incoming `Connection` header, per
 * RFC 9110 §7.6.1. With `folded`, a name also matches in any spelling of
 * `-`, `_` and `.` (`Proxy_Authorization`, `keep.alive`), for upstreams
 * that read those separators as one.
 */
http.IncomingHttpHeaders stripHopByHop(
  http.IncomingHttpHeaders h, {
  bool folded = false,
}) => throw UnimplementedError('pending port of src/sandbox/parent-proxy.ts');

/** Remove surrounding square brackets from an IPv6 literal. */
String stripBrackets(String host) => host.startsWith('[') && host.endsWith(']')
    ? host.substring(1, host.length - 1)
    : host;

/** Redact userinfo from a URL for safe logging. */
String redactUrl(url.URL? u) =>
    throw UnimplementedError('pending port of src/sandbox/parent-proxy.ts');

/**
 * Hostname validation: accepts DNS names and IP literals (without zone IDs).
 * Primary purpose is to block control characters (CRLF injection, null-byte
 * DNS truncation) and zone-identifier allowlist bypasses from reaching the
 * wire or the allowlist matcher.
 *
 * IPv6 zone IDs (`fe80::1%eth0`) are rejected because `isIP` accepts a very
 * permissive zone charset including dots — `::ffff:1.2.3.4%x.allowed.com`
 * would pass `isIP`, pass a `.endsWith('.allowed.com')` wildcard check, and
 * then connect to 1.2.3.4 when the OS discards the bogus scope.
 */
bool isValidHost(String h) =>
    throw UnimplementedError('pending port of src/sandbox/parent-proxy.ts');

/**
 * Canonicalize a host string via the WHATWG URL parser so that string
 * comparisons in the allowlist agree with what `net.connect()`/`getaddrinfo()`
 * will actually dial. This normalizes:
 *   - inet_aton shorthand (`127.1` → `127.0.0.1`, `2130706433` → `127.0.0.1`)
 *   - hex/octal octets (`0x7f.0.0.1` → `127.0.0.1`)
 *   - IPv6 compression (`0:0:0:0:0:0:0:1` → `::1`)
 *   - trailing dots, case, brackets
 *
 * Returns undefined if the input is not a valid URL host.
 */
String? canonicalizeHost(String h) {
  try {
    final bare = stripBrackets(h);
    // WHATWG URL rejects zone IDs and most garbage; it normalizes inet_aton
    // forms and IPv6 compression. It does NOT strip trailing dots or IPv6
    // brackets from the output, so we do that ourselves.
    final bracketed = net.isIP(bare) == 6 ? '[$bare]' : bare;
    final out = stripBrackets(url.whatwgUrlHostname(bracketed));
    // An IPv4-mapped literal connects to that IPv4 address, so it is spelled
    // as one: allow/deny entries and requests then compare equal.
    return net.isIP(out) == 6
        ? (mappedIPv4(out) ?? out)
        : out.replaceFirst(RegExp(r'\.$'), '');
  } catch (_) {
    return null;
  }
}

/** Per-dial name resolution the proxies are handed: the guard's `lookup` for `port`, refusals recorded. */
typedef DirectLookup =
    net.LookupFunction Function(int port, [String? encodedCommand]);

/** `host[:port]` as it belongs in a Host header / URL authority: IPv6 bracketed, the default port elided. */
String formatAuthority(String host, int port, int defaultPort) =>
    throw UnimplementedError('pending port of src/sandbox/parent-proxy.ts');

class DirectRequestOptions {
  const DirectRequestOptions({
    required this.host,
    required this.port,
    this.servername,
    required this.agent,
  });

  final String host;
  final int port;
  final String? servername;
  final bool agent;
}

/**
 * Connection options for an `http(s).request` to `host:port` over the direct
 * route. The name is dialed exactly as a tunnel would be ({@link dialDirect}:
 * the guard's `lookup`, the connect timeout, the runtime's address-family
 * fallback), the address that answered is kept and that connection released;
 * the request then goes to the literal, with the name in SNI (callers keep it
 * in Host). So the vetted address is the one requested and `lookup` never
 * reaches the HTTP client: Bun's node:http client up to 1.3.x resolves through
 * a custom `lookup` but then drops or repeats a streamed request body, and
 * ignores `createConnection` (oven-sh/bun#7471), so the vetted socket cannot
 * simply be adopted. Bun 1.4 rewrote that client (oven-sh/bun#31587); once it
 * is the floor, hand the request the dialed socket and drop the second connect.
 * No agent: the global pool is shared with the embedding process (and Bun
 * caches the first request's `ca` on it), and the vetting dial runs per request
 * anyway. Without a `lookup`, or for an IP literal, the host is used as given.
 */
Future<DirectRequestOptions> directRequestOptions(
  String host,
  int port,
  net.LookupFunction? lookup,
  bool tls,
) => throw UnimplementedError('pending port of src/sandbox/parent-proxy.ts');

/**
 * Dial `host:port` directly with a bounded timeout. Shared by the HTTP and
 * SOCKS direct-connect paths so they get the same timeout behaviour as the
 * CONNECT-tunnelled paths. `lookup` is the resolved-address guard's (see
 * resolved-address-guard.ts); the runtime dials what it returns. It is a
 * required argument so no direct dial omits it by accident — pass
 * `undefined` explicitly to use the runtime's resolver unguarded.
 */
Future<net.NodeSocket> dialDirect(
  String host,
  int port,
  net.LookupFunction? lookup, [
  int timeoutMs = 30_000,
]) => throw UnimplementedError('pending port of src/sandbox/parent-proxy.ts');
