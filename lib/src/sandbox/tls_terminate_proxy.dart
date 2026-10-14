// STUB: pending port of src/sandbox/tls-terminate-proxy.ts @ 24eb39e.
// ignore_for_file: slash_for_doc_comments, dangling_library_doc_comments
// ignore_for_file: constant_identifier_names, doc_directive_unknown

import 'dart:typed_data';

import '../node/net.dart' as net;
import '../node/stream.dart' as stream;
import 'credential_aws_pairs.dart';
import 'emitted_connection.dart';
import 'mitm_ca.dart';
import 'request_filter.dart';
import 'body_substitution.dart';

/**
 * Upper bound on the request body the proxy will buffer to recompute a
 * literal SigV4 body hash. The signature must cover the exact bytes sent
 * upstream, so buffering is unavoidable for that shape — but without a
 * cap a sandboxed client could pin arbitrary host memory with one large
 * signed upload (awslabs/aws-sigv4-proxy buffers with no limit; we fail
 * closed instead). Bodies over the cap are denied with a 403; clients
 * with larger payloads should sign UNSIGNED-PAYLOAD, which streams.
 */
const MAX_SIGV4_RESIGN_BODY_BYTES = 64 * 1024 * 1024;

/**
 * True if `buf` starts with a TLS Handshake record header.
 *
 * Three bytes: content type 0x16 (Handshake) + legacy_record_version
 * 0x03,0x00–0x03. RFC 8446 §5.1 froze the record-layer version (TLS 1.3+
 * negotiate via the supported_versions extension, the wire header stays
 * ≤0x0303), so this holds for current and future TLS. Same predicate as
 * mitmproxy `starts_like_tls_record`; nginx `ssl_preread` routes on byte 0
 * alone and HAProxy `req.ssl_hello_type` reads 9 bytes to also extract the
 * handshake type — 3 is the established middle ground for "is this TLS".
 *
 * Routing heuristic, not a security check: a non-TLS stream that happens to
 * start 16 03 0x is handed to the TLS server, which then rejects it properly.
 */
bool looksLikeClientHello(Uint8List buf) => throw UnimplementedError(
  'pending port of src/sandbox/tls-terminate-proxy.ts',
);

/**
 * Wait for the client's first post-CONNECT bytes and report whether they look
 * like a TLS ClientHello. The caller must already have written the
 * `200 Connection Established` line — clients don't send until they see it.
 *
 * Any bytes consumed here are returned in `.head` so the caller can forward
 * them to whichever downstream (terminate or opaque tunnel) it picks. The
 * socket is left paused so further bytes buffer until the downstream
 * `pipe()` resumes it.
 */
Future<({bool isTLS, Uint8List head})> peekForClientHello(
  stream.Duplex socket,
  Uint8List head,
) => throw UnimplementedError(
  'pending port of src/sandbox/tls-terminate-proxy.ts',
);

class TerminateTarget {
  /**
   * Canonical (see canonicalizeHost) CONNECT target: what the allowlist
   * evaluated. Used verbatim for the minted leaf, the filterRequest URL,
   * the credential hooks' destHost, and the upstream host/SNI, so all of
   * them agree with the policy decision regardless of how the client
   * spelled the name.
   */
  final String hostname;
  final int port;

  /**
   * Additional trusted CA(s) for the proxy's outbound TLS leg. Unset → system
   * roots + NODE_EXTRA_CA_CERTS. Primarily a test seam (NODE_EXTRA_CA_CERTS
   * is read at process start, so tests can't set it from inside the suite).
   */
  final Object? upstreamCA; // String | Uint8List | List<String | Uint8List>

  /// Upstream-leg name resolution, already bound for this target (see HttpProxyServerOptions.lookupFor).
  final net.LookupFunction? lookup;

  /**
   * Called when filterRequest denies a parsed request, with the verified
   * method/URL and the decision reason. Carried on the target so the
   * per-connection request handler (which closes over `target`) can reach
   * it without an extra parameter on every layer.
   */
  final void Function(String method, String url, String reason)?
  onFilterRequestDeny;

  /// Response headers removed before the response reaches the client.
  final List<String>? stripResponseHeaders;

  /// Answer 421 when the Host header or TLS server name is not the target.
  final bool? requireHostMatch;

  /// The largest request head parsed in the tunnel; past it, 400 (see HttpProxyServerOptions.maxHeaderSize).
  final int? maxHeaderSize;

  /// Drop hop-by-hop headers in any separator spelling (see HttpProxyServerOptions.foldHopByHop).
  final bool? foldHopByHop;

  /// The header that marks the proxy's own refusals (see HttpProxyServerOptions.denyHeader).
  final String? denyHeader;

  /// Forward the request-target as spelled (see HttpProxyServerOptions.requestTargetAsSpelled).
  final bool? requestTargetAsSpelled;

  /// The TLS server name the client sent (set by terminateAndForward).
  final String? clientServerName;

  /// The ClientHello carries a server name that could not be read (see serverNameFromClientHello).
  final bool? clientServerNameUnreadable;

  /// Called once the tunnel's TLS handshake is done.
  final void Function()? onEstablished;

  /// Given a way to ask, at any later time, whether the tunnel's TLS handshake is done.
  final void Function(bool Function() isDone)? onHandshakeProbe;

  /// Shared across a proxy's tunnels: bytes they may hold for slow parties (see ByteBudget).
  final ByteBudget? byteBudget;

  const TerminateTarget({
    required this.hostname,
    required this.port,
    this.upstreamCA,
    this.lookup,
    this.onFilterRequestDeny,
    this.stripResponseHeaders,
    this.requireHostMatch,
    this.maxHeaderSize,
    this.foldHopByHop,
    this.denyHeader,
    this.requestTargetAsSpelled,
    this.clientServerName,
    this.clientServerNameUnreadable,
    this.onEstablished,
    this.onHandshakeProbe,
    this.byteBudget,
  });
}

/**
 * Terminate the client's TLS on `socket`, parse the decrypted HTTP/1.1
 * stream, and forward each request to `target` over an upstream TLS
 * connection kept alive for the life of the client's connection (see
 * {@link createUpstreamLeg}).
 *
 * Preconditions: the caller has already validated `target` against the
 * domain allowlist; this function does not re-check it.
 *
 * Implementation: the TLS runs in this process on the tunnel's own socket
 * (serverTlsOn), and the decrypted connection is handed with
 * `emit('connection')` to an http.Server that never listens, so nothing
 * another process can connect to exists. A server per tunnel lets the
 * request handler close over `target` (which carries the originally-
 * requested host:port) without socket-keyed lookups.
 */
void terminateAndForward(
  MitmCA ca,
  FilterRequestCallback? filterRequest,
  MutateForwardedHeaders? mutateHeaders,
  GetBodySubstitutions? getBodySubstitutions,
  stream.Duplex socket,
  Uint8List head,
  TerminateTarget target, [
  PlanSigv4? planSigv4,
  int maxSigv4BodyBytes = MAX_SIGV4_RESIGN_BODY_BYTES,
]) => throw UnimplementedError(
  'pending port of src/sandbox/tls-terminate-proxy.ts',
);

/** The server name a ClientHello carries: none, a plain DNS name, or one that cannot be read. */
sealed class ServerName {
  const ServerName();
  String get kind;
}

class ServerNameAbsent extends ServerName {
  const ServerNameAbsent();
  @override
  String get kind => 'absent';
}

class ServerNameName extends ServerName {
  final String name;
  const ServerNameName(this.name);
  @override
  String get kind => 'name';
}

class ServerNameUnreadable extends ServerName {
  const ServerNameUnreadable();
  @override
  String get kind => 'unreadable';
}

/**
 * The server name a TLS ClientHello record carries (the server_name
 * extension's host_name), lower-cased.
 *
 * `unreadable` whenever a name may be there but cannot be taken as a plain
 * DNS name: the extension is malformed, lists more than one name, or names
 * something other than a host; the name is empty, too long, not ASCII
 * letters, digits, - and . in non-empty labels, or ends in a dot; or the
 * record ends (a ClientHello split across records) before the extensions
 * have all been read. `absent` only when every extension was read and none
 * is server_name.
 */
ServerName serverNameFromClientHello(Uint8List record) =>
    throw UnimplementedError(
      'pending port of src/sandbox/tls-terminate-proxy.ts',
    );

/**
 * Close a socket once what is written to it has gone out and the client
 * has seen it: end it, and once the writes are flushed, destroy it when
 * the client ends its side, or after a grace period. Until then what the
 * client sends is read and dropped, since unread input when the socket
 * closes turns the close into a reset, and a reset discards what the
 * client has not read yet. A backstop covers a client that stops reading.
 */
void closeAfterFlush(stream.Duplex socket, void Function(String how) done) =>
    throw UnimplementedError(
      'pending port of src/sandbox/tls-terminate-proxy.ts',
    );
