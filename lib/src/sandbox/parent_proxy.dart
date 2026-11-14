// Ported from sandbox-runtime src/sandbox/parent-proxy.ts @ 0bbebed.
// ignore_for_file: slash_for_doc_comments, library_private_types_in_public_api, dangling_library_doc_comments, constant_identifier_names, non_constant_identifier_names

import 'dart:async';
import 'dart:convert';

import '../node/errno.dart';
import '../node/http.dart' as http;
import '../node/net.dart' as net;
import '../node/process.dart' as process;
import '../node/tls.dart' as tls;
import '../node/url.dart' as url;
import '../utils/debug.dart';
import 'sandbox_config.dart' show ParentProxyConfig;
import 'address.dart'
    show addRange, addressInSet, isLoopbackAddress, mappedIPv4;

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
  _NoProxyRules({
    required this.all,
    required this.suffixes,
    required this.cidr,
  });

  bool all;
  final List<String> suffixes;
  final net.BlockList cidr;
}

const _CONNECT_TIMEOUT_MS = 30_000;

/**
 * Hop-by-hop headers per RFC 7230 §6.1, plus proxy-specific headers that
 * MUST NOT be forwarded to the upstream. `transfer-encoding` is included
 * because we re-frame bodies via Node's client; Content-Length is preserved
 * end-to-end (Node's llhttp already rejects the TE+CL smuggling vector).
 */
final Set<String> _HOP_BY_HOP = {
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'proxy-connection',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
};

/**
 * Resolve the parent proxy config, falling back to the SRT process's own
 * environment. Note: SRT later overwrites HTTP_PROXY etc. in the *sandboxed
 * child's* environment to point at itself — but process.env here reflects the
 * environment SRT itself was launched with, which is what we want.
 */
ResolvedParentProxy? resolveParentProxy([ParentProxyConfig? cfg]) {
  final http =
      cfg?.http ?? process.env['HTTP_PROXY'] ?? process.env['http_proxy'];
  final https =
      cfg?.https ??
      process.env['HTTPS_PROXY'] ??
      process.env['https_proxy'] ??
      // Fall back to HTTP_PROXY for HTTPS if HTTPS_PROXY is unset — this is
      // the de-facto behaviour of curl and most tooling.
      http;
  final noProxyRaw =
      cfg?.noProxy ?? process.env['NO_PROXY'] ?? process.env['no_proxy'] ?? '';

  if ((http == null || http.isEmpty) && (https == null || https.isEmpty)) {
    return null;
  }

  url.URL? parse(String? u) {
    if (u == null || u.isEmpty) return null;
    // Accept schemeless `host:port` like curl does, but reject any scheme
    // other than http/https.
    final hasScheme = RegExp(
      r'^[a-z][a-z0-9+.-]*:\/\/',
      caseSensitive: false,
    ).hasMatch(u);
    final withScheme = hasScheme ? u : 'http://$u';
    try {
      final parsed = url.URL(withScheme);
      if ((parsed.protocol != 'http:' && parsed.protocol != 'https:') ||
          parsed.hostname.isEmpty) {
        throw NodeException('unsupported scheme or empty host');
      }
      return parsed;
    } catch (_) {
      logForDebugging(
        'Invalid parent proxy URL, ignoring: ${_redactUserinfo(u)}',
        level: 'error',
      );
      return null;
    }
  }

  final httpUrl = parse(http);
  final httpsUrl = parse(https);
  // If both parsed to undefined, behave as if no parent proxy was configured
  // rather than returning a husk object that makes callers do bypass checks
  // for nothing.
  if (httpUrl == null && httpsUrl == null) return null;

  return ResolvedParentProxy(
    httpUrl: httpUrl,
    httpsUrl: httpsUrl,
    noProxy: _parseNoProxy(noProxyRaw),
  );
}

_NoProxyRules _parseNoProxy(String raw) {
  final rules = _NoProxyRules(all: false, suffixes: [], cidr: net.BlockList());

  for (var entry in raw.split(',')) {
    entry = entry.trim();
    if (entry.isEmpty) continue;
    if (entry == '*') {
      rules.all = true;
      continue;
    }

    // CIDR? A malformed one is ignored (do NOT treat as suffix; `/` isn't
    // a valid hostname char).
    if (entry.contains('/')) {
      addRange(rules.cidr, entry);
      continue;
    }

    // Hostname suffix. Normalise: lowercase, strip brackets (handling the
    // `[v6]:port` form), strip leading `*.`, strip a trailing `:port` (unless
    // the entry is an IP literal — IPv6 addresses contain colons).
    var v = entry.toLowerCase();
    final bracketed = RegExp(r'^\[([^\]]+)\](?::\d+)?$').firstMatch(v);
    if (bracketed != null) v = bracketed[1]!;
    if (v.startsWith('*.')) v = v.substring(1);
    if (net.isIP(v) == 0) {
      final colon = v.lastIndexOf(':');
      if (colon != -1 && RegExp(r'^\d+$').hasMatch(v.substring(colon + 1))) {
        v = v.substring(0, colon);
      }
    } else if (addRange(rules.cidr, v)) {
      // Bare IP literal — an exact-match /32 or /128 rule, so lookups go
      // through BlockList rather than string suffix matching.
      continue;
    }
    rules.suffixes.add(v);
  }

  return rules;
}

/**
 * Returns true if the given host should bypass the parent proxy and connect
 * directly. Always bypasses loopback.
 *
 * NB: the port is not consulted. NO_PROXY entries of the form `host:port` are
 * matched by host only (the port suffix is stripped during parsing).
 */
bool shouldBypassParentProxy(ResolvedParentProxy resolved, String host) {
  final h = stripBrackets(host.toLowerCase().replaceFirst(RegExp(r'\.$'), ''));

  // Always bypass loopback — chaining localhost through an upstream proxy is
  // never what you want. Covers the whole 127/8 block and IPv4-mapped forms.
  if (h == 'localhost' || isLoopbackAddress(h)) return true;

  if (resolved.noProxy.all) return true;
  if (addressInSet(resolved.noProxy.cidr, h)) return true;

  for (final v in resolved.noProxy.suffixes) {
    if (v.startsWith('.')) {
      // .example.com matches foo.example.com and example.com
      if (h == v.substring(1) || h.endsWith(v)) return true;
    } else {
      // example.com matches example.com and foo.example.com (golang semantics)
      if (h == v || h.endsWith('.$v')) return true;
    }
  }
  return false;
}

/**
 * Pick which parent proxy URL to use for a given destination.
 */
url.URL? selectParentProxyUrl(
  ResolvedParentProxy resolved, {
  required bool isHttps,
}) {
  if (isHttps) return resolved.httpsUrl ?? resolved.httpUrl;
  // For plain HTTP we only fall back to HTTPS_PROXY if it was explicitly set
  // — matches curl's behaviour where HTTP requests go direct if only
  // HTTPS_PROXY is configured.
  return resolved.httpUrl;
}

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
Future<net.NodeSocket> openConnectTunnel(ConnectTunnelOptions opts) {
  final destHost = opts.destHost;
  final destPort = opts.destPort;

  // CRLF-injection guard: destHost may originate from an untrusted SOCKS5
  // DOMAINNAME field. Reject anything that isn't a plain hostname or IP.
  final bare = stripBrackets(destHost);
  if (!isValidHost(bare)) {
    return Future.error(
      NodeException(
        'Invalid destination host for CONNECT: ${jsonEncode(destHost)}',
      ),
    );
  }
  if (destPort < 1 || destPort > 65535) {
    return Future.error(NodeException('Invalid destination port: $destPort'));
  }

  final authority = net.isIP(bare) == 6
      ? '[$bare]:$destPort'
      : '$bare:$destPort';

  final completer = Completer<net.NodeSocket>();
  void resolve(net.NodeSocket s) => completer.complete(s);
  void reject(Object err) => completer.completeError(err);
  final sock = opts.dial();
  var settled = false;

  void fail(Object err) {
    if (settled) return;
    settled = true;
    sock.destroy();
    reject(err);
  }

  void onClose() =>
      fail(NodeException('Proxy closed during CONNECT handshake'));

  sock.setTimeout(
    opts.timeoutMs ?? _CONNECT_TIMEOUT_MS,
    () => fail(NodeException('CONNECT handshake timed out')),
  );
  sock.once('error', fail);
  sock.once('close', onClose);

  sock.once(opts.readyEvent, () {
    sock.write(
      'CONNECT $authority HTTP/1.1\r\n'
      'Host: $authority\r\n'
      '${opts.authHeader != null && opts.authHeader!.isNotEmpty ? 'Proxy-Authorization: ${opts.authHeader}\r\n' : ''}'
      '\r\n',
    );

    var buf = '';
    late void Function(List<int> chunk) onData;
    onData = (List<int> chunk) {
      buf += latin1.decode(chunk);
      final end = buf.indexOf('\r\n\r\n');
      if (end == -1) {
        // Cap header size to avoid unbounded buffering on a misbehaving proxy.
        if (buf.length > 16 * 1024) {
          fail(NodeException('CONNECT response header too large'));
        }
        return;
      }
      // Pause before detaching the data listener so the stream stops
      // flowing — otherwise the unshift below (or any bytes arriving
      // between now and the caller's pipe()) would be dropped.
      sock.pause();
      sock.removeListener('data', onData);

      final statusLine = buf.substring(0, buf.indexOf('\r\n'));
      if (!RegExp(r'^HTTP\/1\.[01] 2\d\d(?:\s|$)').hasMatch(statusLine)) {
        return fail(
          NodeException('Proxy refused CONNECT: ${statusLine.trim()}'),
        );
      }

      // Re-emit any bytes that arrived after the header terminator.
      final rest = buf.substring(end + 4);
      if (rest.isNotEmpty) sock.unshift(latin1.encode(rest));

      settled = true;
      sock.setTimeout(0);
      sock.removeListener('error', fail);
      sock.removeListener('close', onClose);
      resolve(sock);
    };
    sock.on('data', onData);
  });
  return completer.future;
}

/**
 * Open a CONNECT tunnel through a parent HTTP(S) proxy specified by URL.
 * Thin wrapper around openConnectTunnel that dials TCP or TLS based on the
 * proxy URL scheme.
 */
Future<net.NodeSocket> connectViaParentProxy(
  url.URL proxyUrl,
  String destHost,
  int destPort,
) {
  final proxyHost = stripBrackets(proxyUrl.hostname);
  final proxyPort = (int.tryParse(proxyUrl.port) ?? 0) != 0
      ? int.parse(proxyUrl.port)
      : (proxyUrl.protocol == 'https:' ? 443 : 80);
  final useTls = proxyUrl.protocol == 'https:';

  return openConnectTunnel(
    ConnectTunnelOptions(
      destHost: destHost,
      destPort: destPort,
      authHeader: proxyAuthHeader(proxyUrl),
      readyEvent: useTls ? 'secureConnect' : 'connect',
      dial: () => useTls
          ? tls.connect({
              'host': proxyHost,
              'port': proxyPort,
              // SNI must be a hostname, never an IP literal (RFC 6066 §3).
              if (net.isIP(proxyHost) == 0) 'servername': proxyHost,
            })
          : net.connect(proxyPort, proxyHost),
    ),
  );
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

String? proxyAuthHeader(url.URL proxyUrl) {
  if (proxyUrl.username.isEmpty && proxyUrl.password.isEmpty) return null;
  try {
    final creds =
        '${Uri.decodeComponent(proxyUrl.username)}:${Uri.decodeComponent(proxyUrl.password)}';
    return 'Basic ${base64.encode(utf8.encode(creds))}';
  } catch (_) {
    // Malformed percent-encoding in userinfo — fall back to raw values
    // rather than throwing synchronously into the caller.
    final creds = '${proxyUrl.username}:${proxyUrl.password}';
    return 'Basic ${base64.encode(utf8.encode(creds))}';
  }
}

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
]) {
  headers ??= stripHopByHop(upstreamRes.headers);
  try {
    res.writeHead(upstreamRes.statusCode ?? 502, headers);
    return true;
  } catch (err) {
    logForDebugging(
      'Invalid upstream response head (status ${upstreamRes.statusCode}): ${errorMessage(err)}',
      level: 'error',
    );
    upstreamRes.destroy();
    if (res.headersSent) {
      res.destroy();
      return false;
    }
    // A header rejected part-way can leave earlier upstream headers set.
    for (final name in res.getHeaderNames()) {
      res.removeHeader(name);
    }
    res.writeHead(502, {'Content-Type': 'text/plain'});
    res.end('Bad Gateway');
    return false;
  }
}

/**
 * Calls `fail` for an error of a forwarded request, unless its answer has
 * arrived whole by then. An upstream that sends more than the Content-Length
 * it declared (one that counts characters for bytes) has those bytes taken for
 * the start of a next answer, which is an error of the request: it comes after
 * the answer is complete and before that has been read. The answer is good,
 * and a client that asks the upstream itself takes it. The runtime has closed
 * the connection, so nothing that follows on it is read.
 */
void onUpstreamError(
  http.ClientRequest upstream,
  void Function(Object err) fail,
) {
  http.IncomingMessage? answer;
  upstream.once('response', (http.IncomingMessage res) {
    answer = res;
  });
  upstream.on('error', (Object err) {
    if (answer?.complete == true) {
      logForDebugging(
        'Upstream connection failed after a whole answer: ${errorMessage(err)}',
      );
      return;
    }
    fail(err);
  });
}

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
}) {
  String norm(String name) {
    final lower = name.trim().toLowerCase();
    return folded ? lower.replaceAll(RegExp(r'[_.]'), '-') : lower;
  }

  final extra = <String>{};
  final connHeader = h['connection'];
  if (connHeader != null && connHeader != '') {
    for (final tok in _jsString(connHeader).split(',')) {
      extra.add(norm(tok));
    }
  }
  final http.IncomingHttpHeaders out = {};
  for (final MapEntry(key: k, value: v) in h.entries) {
    final nk = norm(k);
    if (!_HOP_BY_HOP.contains(nk) && !extra.contains(nk)) out[k] = v;
  }
  return out;
}

// Dart: JS String() of a header value; an array joins with ','.
String _jsString(Object value) =>
    value is List ? value.join(',') : value.toString();

/** Remove surrounding square brackets from an IPv6 literal. */
String stripBrackets(String host) => host.startsWith('[') && host.endsWith(']')
    ? host.substring(1, host.length - 1)
    : host;

/** Redact userinfo from a URL for safe logging. */
String redactUrl(url.URL? u) {
  if (u == null) return '-';
  if (u.username.isEmpty && u.password.isEmpty) return u.href;
  final c = url.URL(u.href);
  c.username = '***';
  c.password = '***';
  return c.href;
}

String _redactUserinfo(String raw) {
  // Best-effort redaction for unparseable URLs.
  return raw.replaceFirst(RegExp(r'\/\/[^@/]*@'), '//***:***@');
}

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
bool isValidHost(String h) {
  if (h.isEmpty || h.length > 255) return false;
  final bare = stripBrackets(h);
  // Reject zone identifiers outright (see doc comment).
  if (bare.contains('%')) return false;
  if (net.isIP(bare) != 0) return true;
  // DNS label charset. Underscore is permitted for compatibility with real-
  // world DNS records (_dmarc, _acme-challenge, etc.).
  return RegExp(r'^[A-Za-z0-9._-]+$').hasMatch(bare);
}

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
String formatAuthority(String host, int port, int defaultPort) {
  final bracketed = net.isIP(host) == 6 ? '[$host]' : host;
  return port == defaultPort ? bracketed : '$bracketed:$port';
}

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
) async {
  var address = host;
  if (lookup != null && net.isIP(host) == 0) {
    final probe = await dialDirect(host, port, lookup);
    address = probe.remoteAddress ?? '';
    probe.destroy();
    if (address.isEmpty) {
      throw NodeException('connect $host:$port: no peer address');
    }
  }
  // SNI cannot carry an IP literal, and Bun treats `servername: undefined`
  // differently from an absent key.
  return DirectRequestOptions(
    host: address,
    port: port,
    servername: tls && net.isIP(host) == 0 ? host : null,
    agent: false,
  );
}

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
  int timeoutMs = _CONNECT_TIMEOUT_MS,
]) {
  final completer = Completer<net.NodeSocket>();
  final s = net.connect({'port': port, 'host': host, 'lookup': lookup});
  var settled = false;
  void done([Object? err]) {
    if (settled) return;
    settled = true;
    s.setTimeout(0);
    if (err != null) {
      s.destroy();
      completer.completeError(err);
    } else {
      completer.complete(s);
    }
  }

  s.setTimeout(timeoutMs, () => done(NodeException('connect timed out')));
  s.once('connect', () => done());
  s.once('error', done);
  s.once('close', () => done(NodeException('socket closed before connect')));
  return completer.future;
}
