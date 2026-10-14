// STUB: pending port of src/sandbox/http-proxy.ts @ 24eb39e.
// ignore_for_file: dangling_library_doc_comments, slash_for_doc_comments

import 'dart:async';

import '../node/http.dart' as http;
import '../node/stream.dart' as stream;
import 'body_substitution.dart' show GetBodySubstitutions;
import 'credential_aws_pairs.dart' show PlanSigv4;
import 'emitted_connection.dart' show ByteBudget;
import 'mitm_ca.dart' show MitmCA;
import 'parent_proxy.dart' show DirectLookup, ResolvedParentProxy;
import 'request_filter.dart' show FilterRequestCallback, MutateForwardedHeaders;

/**
 * Host-allowlist decision. `encodedCommand` is the per-command suffix
 * parsed from the Proxy-Authorization username (`srt.<encodedCommand>`),
 * so the manager can attribute a denial to the invocation that made it.
 *
 * Receives the host exactly as the client spelled it (so denials and
 * permission prompts show what the process asked for); the manager's
 * filter canonicalizes internally. Every other hook below, and the
 * upstream leg itself, get the {@link canonicalizeHost} spelling of an
 * allowed host — see the note at the CONNECT handler's routing step.
 *
 * `explain`, called before a refusal, gives the reason: the status phrase
 * a refused CONNECT is answered with.
 */
abstract interface class HttpProxyServerOptions {
  FutureOr<bool> filter(
    int port,
    String host,
    stream.Duplex socket, [
    String? encodedCommand,
    void Function(String reason)? explain,
  ]);

  /**
   * Optional function to get the MITM proxy socket path for a given host.
   * If returns a socket path, the request will be routed through that MITM proxy.
   * If returns undefined, the request will be handled directly.
   *
   * Called with the canonical host; the CONNECT authority / absolute URI
   * forwarded to the MITM socket carries the same canonical spelling, so
   * the proxy behind the socket never has to re-derive it.
   */
  String? Function(String host)? getMitmSocketPath;

  /**
   * If present, CONNECT requests are TLS-terminated in-process and the
   * decrypted HTTP forwarded upstream over real TLS, instead of opening an
   * opaque byte tunnel. Mutually exclusive with getMitmSocketPath at the
   * config layer (sandbox-manager rejects both being set). Needs Node, or
   * Bun 1.4 or later: on an older runtime createHttpProxyServer throws
   * (see assertTlsTerminationSupported).
   */
  MitmCA? get mitmCA;

  /**
   * Per-host opt-out of TLS termination; consulted only when `mitmCA` is
   * set. Return false to leave that CONNECT as an opaque byte tunnel
   * (still hostname-allowlisted via `filter`, but not content-inspected —
   * the same posture as the non-tlsTerminate path), so the sandboxed
   * client performs its own TLS handshake end-to-end with the upstream.
   *
   * Use for upstreams the proxy must not re-originate: mTLS services
   * (only the in-sandbox client holds the client certificate) and
   * certificate-pinning clients that reject the MITM CA. Note that
   * `filterRequest` and `mutateHeaders` never see the HTTPS traffic to
   * these hosts; plain-HTTP proxy requests to them are unaffected (those
   * are readable without termination and keep the normal request pipeline).
   *
   * Absent, or returning true, means today's behaviour: terminate.
   */
  bool Function(String hostname, int port)? shouldTerminateTLS;

  /**
   * Per-request filter; runs on plain-HTTP proxy requests and on terminated
   * HTTPS requests. See request-filter.ts.
   *
   * With `filterRequest`, the request target is normalised before the hook
   * sees it and that normalised target is what is forwarded. Without it,
   * the target is forwarded as it was before the hook existed: on plain
   * HTTP that is the URL-parsed path and query (so `/a/../b` still goes
   * out as `/b`), and on the TLS-terminated path it is the client's bytes
   * unchanged.
   */
  FilterRequestCallback? get filterRequest;

  /**
   * Called when `filterRequest` denies a request, with the verified
   * method/URL, the decision reason, and the encodedCommand parsed from
   * the Proxy-Authorization username. Lets the manager record the deny in
   * the SandboxViolationStore alongside the host-allowlist denials.
   */
  void Function(
    ({String method, String url, String reason, String? encodedCommand}),
  )?
  get onFilterRequestDenied;

  /**
   * Mutate forwarded headers on the TLS-terminated path, after the allow
   * decision and before the upstream request is built. The upstream leg is
   * always cert-verified (rejectUnauthorized defaults to true), so the TLS
   * handshake fails before any mutated header bytes reach an unverified
   * server. See {@link MutateForwardedHeaders}.
   */
  MutateForwardedHeaders? get mutateHeaders;

  /**
   * Mutate forwarded headers on the plain-HTTP path. Separate from
   * `mutateHeaders` so callers can wire the TLS path only — credential
   * injection over plaintext is opt-in.
   */
  MutateForwardedHeaders? get mutateHeadersPlaintext;

  /**
   * Per-destination sentinel→real byte pairs for masked-credential
   * substitution in request BODIES on the TLS-terminated path — the body
   * counterpart of `mutateHeaders`. Consulted once per body-carrying
   * request; an empty/undefined result keeps the existing bare body pipe,
   * byte-identical. See body-substitution.ts for gating and framing rules.
   */
  GetBodySubstitutions? get getBodySubstitutions;

  /**
   * Body substitution on the plain-HTTP path. Separate from
   * `getBodySubstitutions` for the same reason `mutateHeadersPlaintext` is
   * separate: credential injection over plaintext is opt-in.
   */
  GetBodySubstitutions? get getBodySubstitutionsPlaintext;

  /**
   * Per-request AWS SigV4 hook on the TLS-terminated path. Runs in
   * forwardUpstream around `mutateHeaders`: requests whose signature
   * references a masked credential pair are re-signed with the real
   * credentials (or denied per policy for shapes that cannot be
   * re-signed); everything else is untouched. See credential-aws-pairs.ts.
   */
  PlanSigv4? get planSigv4;

  /**
   * Override for the SigV4 literal-hash body buffering cap
   * (MAX_SIGV4_RESIGN_BODY_BYTES). Primarily a test seam — exercising the
   * over-cap denial with the production 64 MiB value would need a 64 MiB
   * fixture upload per test.
   */
  int? get maxSigv4ResignBodyBytes;

  /**
   * Additional trusted CA(s) for the terminating proxy's outbound TLS leg.
   * Unset → system roots + NODE_EXTRA_CA_CERTS. Primarily a test seam.
   */
  Object?
  get tlsTerminateUpstreamCA; // String | Uint8List | List<String | Uint8List>

  /**
   * Optional upstream HTTP proxy. When present, direct-connect traffic (i.e.
   * not routed via mitmProxy) is tunnelled through this parent instead of
   * connecting directly. NO_PROXY-matched hosts still connect directly.
   */
  ResolvedParentProxy? get parentProxy;

  /**
   * Name resolution for DIRECT dials (opaque CONNECT tunnel, plain-HTTP
   * forward, TLS-terminated upstream leg), bound per destination port and
   * requesting command. The manager returns the resolved-address guard's
   * lookup, which refuses (and records) an allow-listed hostname that
   * resolves into denied address space; the proxy answers that with a 403.
   * Not consulted for the mitmProxy or parentProxy routes — that hop
   * resolves the name.
   */
  DirectLookup? get lookupFor;

  /**
   * Per-session bearer token. When set, every CONNECT and absolute-URI
   * request must carry `Proxy-Authorization: Basic
   * base64("srt[.<encodedCommand>]:<token>")` or it gets a 407. Without
   * this, any host process can dial 127.0.0.1 and reach the filter
   * callback. The optional `<encodedCommand>` suffix is parsed and passed to
   * `filter()` / `onFilterRequestDenied` so denials can be attributed to a
   * specific command.
   */
  String? get proxyAuthToken;

  /**
   * Whether a filterRequest allow may SET headers on a plain-HTTP request.
   * Off by default: a header set there (a credential, say) would travel in
   * cleartext. While off, an allow that carries `setHeaders` is refused with
   * 403 and nothing is forwarded; an allow without sets is unaffected, and
   * removals always apply.
   */
  bool? get plaintextHeaderSet;

  /**
   * Response headers removed before a response is written to the client,
   * on both paths, matched as removeHeaders matches (case and `-` `_` `.`
   * folded). E.g. ['set-cookie', 'set-cookie2'] keeps upstream cookies
   * from the client.
   */
  List<String>? get stripResponseHeaders;

  /**
   * When true, a CONNECT is served only by in-process TLS termination: a
   * CONNECT whose first bytes are not a TLS ClientHello is closed, and one
   * that would not be terminated at all (no mitmCA, or shouldTerminateTLS
   * says no) is refused with 403, instead of either being tunnelled
   * opaquely past filterRequest. Each refusal is reported through
   * onFilterRequestDenied with method CONNECT. Use it when every request
   * must be seen by filterRequest; the SOCKS side of the same port needs
   * SocksProxyServerOptions.refuseOpaqueTunnels too. CONNECT-carried SSH
   * (e.g. a GIT_SSH_COMMAND through this proxy) stops working.
   */
  bool? get refuseOpaqueTunnels;

  /**
   * When true, a request whose Host header (or, on the TLS-terminated path,
   * whose TLS server name or absolute-form authority) does not name the
   * host and port it is being sent to is answered 421 Misdirected Request
   * before filterRequest is asked, and reported through
   * onFilterRequestDenied. See hostMismatch for the accepted shapes.
   */
  bool? get requireHostMatch;

  /**
   * The largest request head (request line and headers) the proxy parses,
   * on the plain path and inside a TLS-terminated tunnel, in place of the
   * runtime's default (16 KiB in Node). A head past it is answered 400.
   * Set it above any limit filterRequest enforces, so that limit is the
   * one that answers.
   */
  int? get maxHeaderSize;

  /**
   * When set, every refusal the proxy answers itself is marked
   * `<denyHeader>: <code>` in place of `X-Proxy-Error: <tag>`. The codes:
   * `host_not_allowed` (the host allowlist), `misdirected` (a 421 from
   * requireHostMatch), `bad_request` (a request-target or request the
   * proxy cannot forward), `opaque_tunnel` (refuseOpaqueTunnels),
   * `address_not_allowed` (a resolved-address refusal), and, for a
   * filterRequest deny, the decision's `mark` (`denied` when it has none).
   */
  String? get denyHeader;

  /**
   * Forward the request-target exactly as the client spelled it and show
   * filterRequest that same spelling (see requestTargetAsSpelled), instead
   * of normalizing it; a target in any other shape is answered 400, as is
   * absolute form inside a TLS-terminated tunnel.
   */
  bool? get requestTargetAsSpelled;

  /**
   * Refuse, with 400 and before the allowlist is consulted, a request
   * whose destination host is not spelled in plain ASCII: letters, digits,
   * `-` and `.` in non-empty labels (one trailing dot allowed), or an IP
   * literal (IPv6 in brackets). The URL parser would otherwise map
   * fullwidth, percent-encoded and other Unicode spellings onto an ASCII
   * name. Case and a single trailing dot are still canonicalized.
   */
  bool? get requireAsciiHost;

  /**
   * Drop the client's hop-by-hop headers (and those its Connection header
   * names) in any spelling of `-`, `_` and `.` too, not only in the exact
   * spelling, before forwarding, on both paths.
   */
  bool? get foldHopByHop;

  /**
   * On the plain path, for a connection handed to the server with
   * emit('connection') and marked with markHandedInConnection, pause the
   * client's socket whenever more than this many bytes of its request body
   * are buffered in the proxy, until the body's reader pulls again.
   * Bun's HTTP server keeps reading such a connection while its request is
   * paused, and would otherwise take a large upload into memory while the
   * upstream reads slowly. Connections the server accepted itself are left
   * alone.
   */
  int? get maxBufferedRequestBody;

  /**
   * At most this many CONNECT tunnels are TLS-terminated at once (default
   * 256); a CONNECT past it is answered 503 with `X-Proxy-Error:
   * too-many-tunnels`. Each holds a TLS session and an HTTP parser in this
   * process. A slot is taken when a CONNECT to a host that would be
   * terminated is accepted, before its first bytes are seen, and held until
   * the tunnel closes (an idle keep-alive tunnel holds one too), or until
   * the tunnel turns out not to carry TLS. So at the cap, a CONNECT that
   * would have been tunnelled opaquely as non-TLS is refused too.
   * SandboxManager sets it from network.tlsTerminate.maxTunnels.
   */
  int? get maxTerminatedTunnels;

  /**
   * A tunnel to be TLS-terminated must finish its TLS handshake this long
   * after its CONNECT (default 10 s), or it is closed and its slot freed.
   * A tunnel that finished its handshake is not timed out afterwards.
   * SandboxManager sets it from network.tlsTerminate.handshakeTimeoutMs.
   */
  int? get tlsHandshakeTimeoutMs;

  /**
   * Bytes all of this proxy's connections together may hold for slow
   * parties: request bodies waiting for an upstream, and responses waiting
   * for a client. Past it, each holds no more than it must (default
   * 256 MiB).
   *
   * Where it applies to request bodies: inside TLS-terminated tunnels under
   * Bun, on connections the proxy is handed with emit('connection'); and on
   * the plain path, for such a connection, when maxBufferedRequestBody is
   * set. Under Node the runtime's own server applies backpressure to an upload,
   * so nothing needs counting. A tunnel on a connection Bun's own listener
   * accepted (the proxy's listen(), which is how SandboxManager runs it) is
   * read on by the runtime while paused, so an upload to a stalled upstream
   * is buffered without bound there whatever this says; that is a
   * limitation of the runtime.
   */
  int? get maxBufferedBytes;

  /** @internal A budget to use in place of a new one, so a test can read its counter. */
  ByteBudget? get byteBudget;
}

/**
 * Mark a socket about to be handed to a proxy server with
 * emit('connection'), so maxBufferedRequestBody applies to it.
 */
void markHandedInConnection(Object socket) {
  throw UnimplementedError('pending port of src/sandbox/http-proxy.ts');
}

http.NodeHttpServer createHttpProxyServer(HttpProxyServerOptions options) {
  throw UnimplementedError('pending port of src/sandbox/http-proxy.ts');
}
