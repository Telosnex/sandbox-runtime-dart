// Ported from sandbox-runtime src/sandbox/tls-terminate-proxy.ts @ 0bbebed.
// ignore_for_file: slash_for_doc_comments, dangling_library_doc_comments
// ignore_for_file: constant_identifier_names, doc_directive_unknown
// ignore_for_file: non_constant_identifier_names

/**
 * In-process TLS termination for HTTPS traffic through the forward proxy.
 *
 * When a MitmCA is configured, the forward proxy hands CONNECT requests here
 * instead of opening an opaque byte tunnel. We terminate the client's TLS
 * with a per-host leaf cert (see mitm-leaf.ts), parse the decrypted stream
 * as HTTP/1.1, and re-issue each request upstream over a real TLS
 * connection. The optional `filterRequest` callback runs on each parsed
 * request before it is forwarded.
 */
library;

import 'dart:async';
import 'dart:convert' show latin1;
import 'dart:math' as math;
import 'dart:typed_data';

import '../node/abort.dart' as abort;
import '../node/errno.dart';
import '../node/http.dart' as http;
import '../node/https.dart' as https;
import '../node/net.dart' as net;
import '../node/stream.dart' as stream;
import '../node/tls.dart' as tls;
import '../node/url.dart' as url;
import '../utils/debug.dart' show logForDebugging;
import 'emitted_connection.dart';
import 'mitm_ca.dart';
import 'request_filter.dart';
import 'body_substitution.dart';
import 'mitm_leaf.dart' show secureContextFor;
import 'parent_proxy.dart'
    show
        directRequestOptions,
        DirectRequestOptions,
        formatAuthority,
        onUpstreamError,
        relayResponseHead,
        stripHopByHop;
import 'aws_sigv4.dart' show sha256Hex;
import 'credential_aws_pairs.dart';

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

/** Rejection cause when a body exceeds {@link MAX_SIGV4_RESIGN_BODY_BYTES}. */
class _BodyTooLargeError extends NodeException {
  _BodyTooLargeError(super.message);
}

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
bool looksLikeClientHello(Uint8List buf) {
  return (buf.length >= 3 &&
      buf[0] == 0x16 &&
      buf[1] == 0x03 &&
      buf[2] <= 0x03);
}

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
) {
  if (head.length >= 3) {
    return Future.value((isTLS: looksLikeClientHello(head), head: head));
  }
  final resolve = Completer<({bool isTLS, Uint8List head})>();
  var buf = head;
  late final void Function([Object?]) done;
  late final void Function(Uint8List) onData;
  done = ([_]) {
    socket.removeListener('data', onData);
    socket.removeListener('close', done);
    // A Completer completes once; a Promise ignores a second resolve.
    if (!resolve.isCompleted) {
      resolve.complete((isTLS: looksLikeClientHello(buf), head: buf));
    }
  };
  onData = (Uint8List chunk) {
    // Pause synchronously so anything after this chunk buffers for the
    // downstream pipe() rather than being dropped in flowing mode.
    socket.pause();
    buf = buf.isNotEmpty ? Uint8List.fromList([...buf, ...chunk]) : chunk;
    if (buf.length >= 3) return done();
    socket.resume();
  };
  socket.on('data', onData);
  socket.once('close', done);
  return resolve.future;
}

/**
 * A duplex over a CONNECT socket that yields `head` first, for a TLS socket
 * to run on in this process.
 *
 * Reads are pull-mode (`'readable'` + `read()`), never `pause()`/`resume()`:
 * under Bun a socket delivered by an http server's `'connect'` event
 * corrupts its byte stream across those cycles once writes queue (the TLS
 * layer then fails record MAC verification). A write completes once the
 * socket has taken it, so the TLS socket above sees the client's
 * backpressure. Ending the duplex closes the socket with closeAfterFlush.
 *
 * Bun's TLS socket keeps reading the duplex under it while it is itself
 * paused, so once `consumer` (the TLS socket) is set, nothing more is read
 * from the client while that is paused: its uploads wait in the kernel.
 */
({stream.Duplex duplex, void Function(stream.Readable consumer) setConsumer})
_duplexOverSocket(
  stream.Duplex socket,
  Uint8List head,
  void Function(String how) onClosed,
) {
  var waiting = false;
  stream.Readable? consumer;
  var waitingForConsumer = false;
  late final void Function() pull;
  late final void Function([Object?]) onReadable;
  late final stream.Duplex d;
  void onConsumerResume([Object? _]) {
    waitingForConsumer = false;
    pull();
  }

  pull = () {
    if (consumer?.isPaused() == true) {
      if (!waitingForConsumer) {
        waitingForConsumer = true;
        consumer!.once('resume', onConsumerResume);
      }
      return;
    }
    Object? chunk;
    while ((chunk = socket.read()) != null) {
      if (!d.push(chunk)) return;
    }
    if (!waiting) {
      waiting = true;
      socket.once('readable', onReadable);
    }
  };
  onReadable = ([_]) {
    waiting = false;
    pull();
  };
  d = stream.Duplex(
    read: ([Object? _]) {
      pull();
    },
    write: (Uint8List chunk, Object? _encoding, void Function([Object?]) cb) {
      if (socket.write(chunk)) {
        cb();
      } else {
        socket.once('drain', ([_]) => cb());
      }
    },
    finalCallback: (void Function([Object?]) cb) {
      socket.off('readable', onReadable);
      closeAfterFlush(socket, onClosed);
      cb();
    },
    destroy: (Object? err, void Function([Object?]) cb) {
      socket.destroy();
      cb(err);
    },
  );
  if (head.isNotEmpty) d.push(head);
  socket.once('end', ([_]) => d.push(null));
  // The socket's own errors are handled where the tunnel starts; here they
  // only end the stream (an 'error' on it would have no listener).
  socket.once('close', ([_]) => d.destroy());
  d.on('error', ([_]) {});
  return (
    duplex: d,
    setConsumer: (c) {
      consumer = c;
    },
  );
}

/**
 * Start the server side of TLS on a tunnel's own socket, in this process:
 * no listener, so no other process can reach the tunnel's plaintext side.
 * Under Node the TLS socket runs on the socket itself. Under Bun it runs on
 * a duplex over it: Bun's TLS socket on a net.Socket leaves every byte it
 * reads in that socket's own buffer too, which grows by the whole upload.
 * `outbound` is the stream whose write queue holds what is on its way to
 * the client.
 *
 * @internal Exported for its test.
 */
({tls.TLSSocket tls, stream.Writable outbound}) serverTlsOn(
  stream.Duplex socket,
  Uint8List head,
  Map<String, Object?> options,
  void Function(String how) onClosed,
) {
  if (!runsOnBun()) {
    if (head.isNotEmpty) socket.unshift(head);
    final tls_ = tls.TLSSocket(socket as net.NodeSocket, {
      ...options,
      'isServer': true,
    });
    return (tls: tls_, outbound: tls_);
  }
  final (:duplex, :setConsumer) = _duplexOverSocket(socket, head, onClosed);
  final tls_ = tls.TLSSocket(duplex as net.NodeSocket, {
    ...options,
    'isServer': true,
  });
  setConsumer(tls_);
  // destroySoon() is to destroy a socket once all it was given is out. This
  // one has finished as soon as it has written to the stream under it, long
  // before the client has the bytes, and destroyed then it drops them. (A
  // runtime's http server may call it after an HTTP/1.0 response.) Ended, it
  // closes the tunnel too, after the flush. destroy() still cuts at once.
  tls_.destroySoonOverride = () {
    tls_.end();
  };
  return (tls: tls_, outbound: duplex);
}

/** What a tunnel's TLS socket writes goes out through this stream. */
final _outboundOf = Expando<stream.Writable>();

/** The proxy's shared byte budget, per tunnel TLS socket. */
final _budgetOf = Expando<ByteBudget>();

/**
 * Past this many bytes queued for a client, a response waits for the
 * queue to drain. Bun's server for an emitted connection lets a response
 * write on (its 'drain' comes at once) while the socket underneath queues
 * without bound, so the relay watches the socket's own queue.
 */
const _MAX_QUEUED_FOR_CLIENT = 1 << 20;

/**
 * On a TLS-terminated request, Bun's server keeps reading a request whose
 * stream is paused: past this many buffered body bytes, the TLS socket is
 * paused instead (gateSocketOnBufferedBody).
 */
const _MAX_BUFFERED_REQUEST_BODY = 4 << 20;

/** How long a tunnel may stay as it is before boundTunnel closes it. */
class TunnelTimeouts {
  const TunnelTimeouts({
    required this.firstRequestMs,
    required this.keepAliveMs,
    required this.keepAliveMarginMs,
    required this.stalledMs,
  });
  /** From the ClientHello to the first request's whole head. */
  final int firstRequestMs;
  /** What `Keep-Alive: timeout` says: from a response to the next request. */
  final int keepAliveMs;
  /** How much later than it says an idle tunnel is ended, for a client that takes it at its word. */
  final int keepAliveMarginMs;
  /** With a request or a response under way that does not move. */
  final int stalledMs;
}

const TUNNEL_TIMEOUTS = TunnelTimeouts(
  firstRequestMs: 10000,
  keepAliveMs: 5000,
  keepAliveMarginMs: 1000,
  stalledMs: 300000,
);

// Dart: Partial<TunnelTimeouts> has each field optional.
class PartialTunnelTimeouts {
  const PartialTunnelTimeouts({
    this.firstRequestMs,
    this.keepAliveMs,
    this.keepAliveMarginMs,
    this.stalledMs,
  });
  final int? firstRequestMs, keepAliveMs, keepAliveMarginMs, stalledMs;
}

/** A tunnel with something under way is looked at this many times in a timeout. */
const _LOOKS = 5;

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

  /** What becomes of an ambiguous request-target (see HttpProxyServerOptions.ambiguousRequestTarget). */
  final AmbiguousRequestTarget? ambiguousRequestTarget;

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

  /** In place of TUNNEL_TIMEOUTS (see HttpProxyServerOptions.tunnelTimeouts). */
  final PartialTunnelTimeouts? timeouts;

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
    this.ambiguousRequestTarget,
    this.clientServerName,
    this.clientServerNameUnreadable,
    this.onEstablished,
    this.onHandshakeProbe,
    this.byteBudget,
    this.timeouts,
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
  int? maxSigv4BodyBytes,
]) {
  // The tunnel's one connection is its client's, so the server name in its
  // ClientHello is the tunnel's (read below, before the handshake).
  ServerName serverName = const ServerNameAbsent();
  final timeouts = TunnelTimeouts(
    firstRequestMs:
        target.timeouts?.firstRequestMs ?? TUNNEL_TIMEOUTS.firstRequestMs,
    keepAliveMs: target.timeouts?.keepAliveMs ?? TUNNEL_TIMEOUTS.keepAliveMs,
    keepAliveMarginMs:
        target.timeouts?.keepAliveMarginMs ?? TUNNEL_TIMEOUTS.keepAliveMarginMs,
    stalledMs: target.timeouts?.stalledMs ?? TUNNEL_TIMEOUTS.stalledMs,
  );
  // Never listens: the TLS socket below is handed to it.
  final inner = http.createServer({
    'keepAliveTimeout': timeouts.keepAliveMs,
    if (target.maxHeaderSize != null) 'maxHeaderSize': target.maxHeaderSize,
  });

  // Needs an http.Server that serves a connection handed to it (Node, Bun
  // 1.4 and later: such a server has a 'connection' listener of its own).
  // Without one the tunnel is refused, never left hanging.
  if (inner.listenerCount('connection') == 0) {
    logForDebugging(
      '[tls-terminate] this runtime cannot terminate TLS in-process; tunnel refused',
      level: 'error',
    );
    socket.destroy();
    return;
  }

  final leg = _createUpstreamLeg(target);

  inner.on('request', (http.IncomingMessage req, http.ServerResponse res) {
    // A client abort mid-request destroys req/res with an error; with no
    // listener it escapes as an uncaughtException (the runtime emits it
    // from node:_http_server).
    req.on('error', (dynamic err) {
      logForDebugging(
        '[tls-terminate] client request error: ${errorMessage(err)}',
        level: 'error',
      );
    });
    res.on('error', (dynamic err) {
      logForDebugging(
        '[tls-terminate] client response error: ${errorMessage(err)}',
        level: 'error',
      );
    });
    if (runsOnBun()) {
      gateSocketOnBufferedBody(
        req,
        _MAX_BUFFERED_REQUEST_BODY,
        target.byteBudget,
      );
    }
    _forwardUpstreamGuarded(
      filterRequest,
      mutateHeaders,
      getBodySubstitutions,
      req,
      res,
      // `{...target, clientServerName, clientServerNameUnreadable}`.
      TerminateTarget(
        hostname: target.hostname,
        port: target.port,
        upstreamCA: target.upstreamCA,
        lookup: target.lookup,
        onFilterRequestDeny: target.onFilterRequestDeny,
        stripResponseHeaders: target.stripResponseHeaders,
        requireHostMatch: target.requireHostMatch,
        maxHeaderSize: target.maxHeaderSize,
        foldHopByHop: target.foldHopByHop,
        denyHeader: target.denyHeader,
        requestTargetAsSpelled: target.requestTargetAsSpelled,
        ambiguousRequestTarget: target.ambiguousRequestTarget,
        onEstablished: target.onEstablished,
        onHandshakeProbe: target.onHandshakeProbe,
        byteBudget: target.byteBudget,
        timeouts: target.timeouts,
        clientServerName: serverName.kind == 'name'
            ? (serverName as ServerNameName).name
            : null,
        clientServerNameUnreadable: serverName.kind == 'unreadable',
      ),
      leg,
      planSigv4,
      // null takes the default, as TS `undefined` does.
      maxSigv4BodyBytes ?? MAX_SIGV4_RESIGN_BODY_BYTES,
    );
  });
  // Responses under way on the tunnel's connection.
  var answering = 0;
  inner.on('request', (http.IncomingMessage _req, http.ServerResponse res) {
    answering++;
    res.once('close', () => answering--);
  });
  inner.on('clientError', (Object err, net.NodeSocket sock) {
    // Parse errors and resets on the tunnel would otherwise escalate to an
    // uncaughtException, same class as the request-stream errors handled
    // above.
    logForDebugging(
      '[tls-terminate] client connection error for ${target.hostname}: ${errorMessage(err)}',
      level: 'error',
    );
    // A request the parser refuses is refused like any other: answered, and
    // reported under the tunnel's own target.
    final refused = refuseUnparsedRequest(
      err,
      sock,
      answering == 0,
      target.denyHeader != null
          ? (name: target.denyHeader!, value: 'bad_request')
          : 'blocked-by-sandbox-runtime',
    );
    if (refused == null) return;
    target.onFilterRequestDeny?.call(
      refused.method,
      'https://${formatAuthority(target.hostname, target.port, 443)}${refused.target}',
      refused.reason,
    );
  });
  inner.on('upgrade', (Object? _req, net.NodeSocket sock) {
    // WebSocket / non-HTTP over TLS — out of scope for now.
    logForDebugging('[tls-terminate] upgrade request refused', level: 'warn');
    sock.destroy();
  });

  // A client that resets at any point (while its ClientHello is still being
  // read, too) only ends its own tunnel.
  socket.on('error', (dynamic err) {
    logForDebugging(
      '[tls-terminate] client connection error for ${target.hostname}: ${errorMessage(err)}',
    );
    socket.destroy();
  });
  socket.once('close', ([_]) => leg.agent.destroy());
  late final void Function(Uint8List hello) startTls;
  // The certificate is chosen from the ClientHello's server name before the
  // handshake, the same way under every runtime and on every socket (Bun's
  // TLS socket over a stream calls no SNICallback).
  unawaited(
    _readFirstRecord(socket, head)
        .then((hello) {
          if (socket.destroyed) return;
          serverName = serverNameFromClientHello(hello);
          startTls(hello);
        })
        .catchError((Object err) {
          logForDebugging(
            '[tls-terminate] tunnel setup failed for ${target.hostname}: ${errorMessage(err)}',
            level: 'error',
          );
          socket.destroy();
        }),
  );

  startTls = (Uint8List hello) {
    String? closedBy;
    // Where the Host and server name must name the target, the certificate
    // is the target's whatever the client asks for: a mismatched name gets
    // 421 anyway, and the names a client can have minted stay the targets.
    final leafFor = target.requireHostMatch != true && serverName.kind == 'name'
        ? (serverName as ServerNameName).name
        : target.hostname;
    final (:tls, :outbound) = serverTlsOn(
      socket,
      hello,
      {
        'ALPNProtocols': ['http/1.1'],
        'secureContext': secureContextFor(ca, leafFor),
      },
      (how) {
        closedBy = how;
      },
    );
    _outboundOf[tls] = outbound;
    if (target.byteBudget != null) _budgetOf[tls] = target.byteBudget;
    markEndsGracefully(tls);
    // The handshake is done at 'secure', or by the first decrypted byte
    // (Bun's TLS socket on a stream does not always say 'secure').
    var established = false;
    void onEstablished([Object? _]) {
      if (established) return;
      established = true;
      target.onEstablished?.call();
    }

    tls.once('data', onEstablished);
    // Neither event comes for a client that finishes the handshake and then
    // stays quiet where 'secure' is not said, so a deadline asks instead.
    bool handshakeDone() => established || _isTlsHandshakeDone(tls);
    target.onHandshakeProbe?.call(handshakeDone);
    boundTunnel(inner, tls, outbound, socket, timeouts, handshakeDone);
    tls.once('secure', ([_]) {
      onEstablished();
      // Where the runtime reports the name its TLS layer took, it must be
      // the one read from the ClientHello.
      final Object? negotiated = tls.servername;
      final read = serverName.kind == 'name'
          ? (serverName as ServerNameName).name
          : null;
      // (An unreadable name is already a mismatch where names are pinned.)
      if (serverName.kind != 'unreadable' &&
          negotiated is String &&
          negotiated != '' &&
          negotiated.toLowerCase() != read) {
        logForDebugging(
          '[tls-terminate] server name $negotiated is not the one read from the ClientHello (${read ?? 'none'}); tunnel closed',
          level: 'error',
        );
        socket.destroy();
      }
    });
    tls.on('error', (dynamic err) {
      logForDebugging(
        '[tls-terminate] client TLS error for ${target.hostname}: ${errorMessage(err)}',
        level: 'error',
      );
      socket.destroy();
    });
    if (identical(outbound, tls)) {
      // The server ends the connection once it is done with it; a client
      // that never closes its side is let go a while after the flush.
      tls.once('finish', ([_]) {
        final grace = Timer(const Duration(milliseconds: 5000), () {
          tls.destroy();
        });
        tls.once('close', ([_]) => grace.cancel());
      });
    }
    socket.once('close', ([_]) {
      if (!tls.destroyed) tls.destroy();
      // A tick later, so closeAfterFlush has said how it closed the socket.
      Timer.run(
        () => logForDebugging(
          '[tls-terminate] tunnel closed for ${target.hostname}:${target.port}: '
          'TLS on ${identical(outbound, tls) ? 'the socket' : 'a stream over the socket'}; '
          'to the client ${(socket as dynamic).bytesWritten ?? '?'} B, '
          '${outbound.writableLength} B still queued; closed by ${closedBy ?? 'the connection ending'}',
        ),
      );
    });
    writeHeadsAsLatin1(tls);
    inner.emit('connection', tls);
    keepFlushedHeaderBatches(tls);
  };
}

/**
 * Close a tunnel that would otherwise stay open, and hold its slot, for as
 * long as its client or its upstream leaves it so. Its server never listens,
 * so of a server's connection timeouts the runtime applies keepAliveTimeout
 * alone (Node) or none (Bun).
 *
 * - Idle, that is no response owed (no request yet, between two, part of a
 *   head) and nothing queued for the client: ended with close_notify and a
 *   FIN, and destroyed if it is still there, and idle, as long again.
 * - Under way, that is a request not all in, the tunnel paused for an
 *   upstream that takes no more of one (so that not even its client's
 *   leaving is seen), or bytes queued for a client: destroyed once nothing
 *   has moved for `stalledMs`. A client that goes on reading loses nothing.
 *   That it reads is seen when the kernel takes more, which it does once a
 *   good part of its send buffer is free: up to a megabyte or two at a time.
 *
 * A whole request that waits for its response is left alone: the tunnel is
 * read meanwhile, so it closes when its client does.
 *
 * @internal Exported for its test.
 */
void boundTunnel(
  http.NodeHttpServer inner,
  tls.TLSSocket tls,
  stream.Writable outbound,
  stream.Duplex socket,
  TunnelTimeouts timeouts,
  bool Function() handshakeDone,
) {
  final TunnelTimeouts(
    :firstRequestMs,
    :keepAliveMs,
    :keepAliveMarginMs,
    :stalledMs,
  ) = timeouts;
  // What is on its way to the client and still in this process. No layer
  // counts it all: a response is done, and Bun's TLS socket empty and
  // finished, with a megabyte in the stream under it. (Under Node two of
  // the three are one: all that is asked is whether it is zero, or changes.)
  int queued() =>
      tls.writableLength + outbound.writableLength + socket.writableLength;

  var owed = 0;
  late Timer idle;
  void endWhenIdleFor(int ms) {
    final busy = queued() > 0;
    idle = Timer(
      Duration(microseconds: ((busy ? ms / _LOOKS : ms) * 1000).round()),
      () {
        // Not idle for all of `ms`: a handshake under way has a deadline of
        // its own, and what is queued is the client's to take.
        if (!handshakeDone() || busy || queued() > 0) {
          endWhenIdleFor(ms);
          return;
        }
        // Ended, and still here: not every client answers an end, and not
        // every runtime closes the socket under a TLS socket it ends.
        if (tls.writableEnded) {
          socket.destroy();
          return;
        }
        logForDebugging('[tls-terminate] tunnel idle for $ms ms; closed');
        tls.end();
        endWhenIdleFor(ms);
      },
    );
  }

  endWhenIdleFor(firstRequestMs);
  // Node's own keep-alive timeout destroys the socket, whatever is queued.
  inner.on('timeout', () {});

  http.IncomingMessage? receiving;
  // A tunnel moves when bytes are read, when it is taken up again after a
  // pause (what is read then, a runtime may have read ahead and counted),
  // and when bytes written to it leave the queue.
  var resumed = 0;
  tls.on('resume', () => resumed++);
  var moved = 0;
  var still = 0;
  final stalled = Timer.periodic(
    Duration(microseconds: (stalledMs * 1000 / _LOOKS).round()),
    (_) {
      final before = moved;
      moved = tls.bytesRead + resumed + tls.bytesWritten - queued();
      final underWay =
          tls.isPaused() || receiving?.complete == false || queued() > 0;
      still = underWay && moved == before ? still + 1 : 0;
      if (still < _LOOKS) return;
      logForDebugging(
        '[tls-terminate] nothing has moved for $stalledMs ms; tunnel closed',
      );
      socket.destroy();
    },
  );

  inner.on('request', (http.IncomingMessage req, http.ServerResponse res) {
    owed++;
    idle.cancel();
    receiving = req;
    // Once the answer is out nothing reads the request on (an upstream that
    // answered or failed early took part of it), and a runtime's server
    // leaves alone a request that was being read. The rest is dropped, so
    // that the tunnel is read on: to the next request, or its client's end.
    res.once('finish', () => req.unpipe().resume());
    res.once('close', () {
      if (--owed == 0 && !socket.destroyed)
        endWhenIdleFor(keepAliveMs + keepAliveMarginMs);
    });
  });
  socket.once('close', () {
    idle.cancel();
    stalled.cancel();
  });
}

/**
 * Read on until `head` holds the whole first TLS record (the ClientHello,
 * at most 16 KiB of it), the client stops sending, or 5 s pass. Pull-mode
 * reads: nothing more is taken than is there.
 */
Future<Uint8List> _readFirstRecord(stream.Duplex socket, Uint8List head) {
  int want(Uint8List b) =>
      b.length >= 5 ? 5 + math.min((b[3] << 8) | b[4], 16 << 10) : 5;
  if (head.length >= want(head)) return Future.value(head);
  final resolve = Completer<Uint8List>();
  var buf = head;
  late final Timer timer;
  late final void Function([Object?]) pull;
  late final void Function([Object?]) done;
  done = ([_]) {
    timer.cancel();
    socket.off('readable', pull);
    socket.off('close', done);
    // A Completer completes once; a Promise ignores a second resolve.
    if (!resolve.isCompleted) resolve.complete(buf);
  };
  pull = ([_]) {
    Object? chunk;
    while ((chunk = socket.read()) != null) {
      buf = Uint8List.fromList([...buf, ...(chunk as Uint8List)]);
      if (buf.length >= want(buf)) {
        done();
        return;
      }
    }
  };
  timer = Timer(const Duration(milliseconds: 5000), done);
  socket.on('readable', pull);
  socket.once('close', done);
  pull();
  return resolve.future;
}

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
ServerName serverNameFromClientHello(Uint8List record) {
  const ServerName unreadable = ServerNameUnreadable();
  if (record.length < 9 || record[0] != 0x16 || record[5] != 0x01) {
    return unreadable;
  }
  final end = math.min(record.length, 5 + ((record[3] << 8) | record[4]));
  // Handshake header (4), client_version (2), random (32).
  var i = 5 + 4 + 2 + 32;
  bool skip(int lengthBytes) {
    if (i + lengthBytes > end) return false;
    final n = lengthBytes == 1 ? record[i] : (record[i] << 8) | record[i + 1];
    i += lengthBytes + n;
    return i <= end;
  }

  // session_id, cipher_suites, compression_methods.
  if (!skip(1) || !skip(2) || !skip(1)) return unreadable;
  // A ClientHello with no extensions at all carries no name.
  if (i == end && end == 5 + ((record[3] << 8) | record[4])) {
    return const ServerNameAbsent();
  }
  if (i + 2 > end) return unreadable;
  final declaredEnd = i + 2 + ((record[i] << 8) | record[i + 1]);
  final extensionsEnd = math.min(end, declaredEnd);
  i += 2;
  ServerName? found;
  while (i + 4 <= extensionsEnd) {
    final type = (record[i] << 8) | record[i + 1];
    final length = (record[i + 2] << 8) | record[i + 3];
    i += 4;
    if (i + length > extensionsEnd) {
      // Past the end of a record that is complete: malformed. Past where
      // the record was cut: the rest is in the next record.
      if (extensionsEnd == declaredEnd) return unreadable;
      break;
    }
    if (type == 0) {
      if (found != null) return unreadable;
      found = _hostNameEntry(Uint8List.sublistView(record, i, i + length));
    }
    i += length;
  }
  if (found != null) return found;
  // Every extension read and none a server_name, or the list was cut short.
  return i == declaredEnd ? const ServerNameAbsent() : unreadable;
}

/** The one host_name entry of a server_name extension's body. */
ServerName _hostNameEntry(Uint8List body) {
  if (body.length < 5 || ((body[0] << 8) | body[1]) != body.length - 2) {
    return const ServerNameUnreadable();
  }
  final nameType = body[2];
  final nameLength = (body[3] << 8) | body[4];
  if (nameType != 0 || 5 + nameLength != body.length) {
    return const ServerNameUnreadable();
  }
  final name = latin1.decode(Uint8List.sublistView(body, 5)).toLowerCase();
  final plain =
      name.length <= 253 &&
      name
          .split('.')
          .every(
            (label) =>
                RegExp(r'^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$').hasMatch(label),
          );
  return plain ? ServerNameName(name) : const ServerNameUnreadable();
}

/**
 * Close a socket once what is written to it has gone out and the client
 * has seen it: end it, and once the writes are flushed, destroy it when
 * the client ends its side, or after a grace period. Until then what the
 * client sends is read and dropped, since unread input when the socket
 * closes turns the close into a reset, and a reset discards what the
 * client has not read yet. A client that has not taken it all in
 * `stalledMs` is cut: what is queued leaves the queue all at once, so one
 * that reads slowly cannot be told from one that has stopped.
 */
void closeAfterFlush(
  stream.Duplex socket,
  void Function(String how) done, [
  int stalledMs = 300000,
]) {
  if (socket.destroyed) {
    done('the client, earlier');
    return;
  }
  var finished = socket.writableFinished;
  var clientEnded = socket.readableEnded;
  var settled = false;
  late final Timer stalled;
  Timer? grace;
  void close(String how) {
    if (settled) return;
    settled = true;
    stalled.cancel();
    grace?.cancel();
    if (!socket.destroyed) socket.destroy();
    done(how);
  }

  // Dart timers have no unref().
  stalled = Timer(
    Duration(milliseconds: stalledMs),
    () => close('not flushed in $stalledMs ms'),
  );
  void onFinish([Object? _]) {
    finished = true;
    if (clientEnded) {
      close('the client ending after the flush');
      return;
    }
    grace = Timer(
      const Duration(milliseconds: 5000),
      () => close('the 5 s grace after the flush'),
    );
  }

  socket.once('end', ([_]) {
    clientEnded = true;
    if (finished) close('the client ending after the flush');
  });
  socket.once('close', ([_]) => close('the client closing'));
  socket.on('data', ([_]) {});
  socket.resume();
  if (finished) {
    onFinish();
  } else {
    socket.once('finish', onFinish);
  }
  socket.end();
}

/**
 * The upstream leg of one client connection: a keep-alive agent capped at one
 * socket, and the vetted upstream address.
 *
 * One agent per client connection rather than a shared pool, so requests from
 * different client connections never share an upstream socket, and the
 * upstream connection lives exactly as long as the client's. One socket keeps
 * the client's request order on the wire: a pipelined request queues in the
 * agent until the previous response has finished.
 *
 * `ca` and `checkServerIdentity` are agent options, not request options — a
 * per-request `checkServerIdentity` makes Node open a new socket for every
 * request. The target is fixed for the connection, so nothing is lost.
 *
 * The address is vetted once (see directRequestOptions) and then reused: a
 * second probe could pick a different record of a multi-address name, which
 * is a different agent key and so a new socket. A redial after the upstream
 * closes an idle socket goes to the same vetted literal. Any upstream failure
 * forgets the address, so the next request vets again.
 */
abstract interface class _UpstreamLeg {
  https.Agent get agent;
  Future<DirectRequestOptions> address();
  void forgetAddress();
}

/// The object literal `createUpstreamLeg` returns.
class _UpstreamLegLiteral implements _UpstreamLeg {
  _UpstreamLegLiteral({
    required this.agent,
    required Future<DirectRequestOptions> Function() address,
    required void Function() forgetAddress,
  }) : _address = address,
       _forgetAddress = forgetAddress;

  @override
  final https.Agent agent;
  final Future<DirectRequestOptions> Function() _address;
  final void Function() _forgetAddress;

  @override
  Future<DirectRequestOptions> address() => _address();

  @override
  void forgetAddress() => _forgetAddress();
}

_UpstreamLeg _createUpstreamLeg(TerminateTarget target) {
  final agent = https.Agent(
    keepAlive: true,
    maxSockets: 1,
    // We're a TLS-terminating proxy, not a trust boundary for the upstream
    // server's identity — the runtime verifies it normally (system roots and
    // NODE_EXTRA_CA_CERTS). Pin the identity to the tunnel's target so the
    // check does not depend on how a runtime derives it from the Host header
    // (some verify against `Host` verbatim, so a non-default port would
    // never match a SAN); `servername` still carries the name for SNI.
    checkServerIdentity: (String _host, Object? cert) =>
        tls.checkServerIdentity(target.hostname, cert),
    ca: target.upstreamCA,
  );
  Future<DirectRequestOptions>? vetted;
  return _UpstreamLegLiteral(
    agent: agent,
    address: () {
      if (vetted == null) {
        final probe = directRequestOptions(
          target.hostname,
          target.port,
          target.lookup,
          true,
        );
        vetted = probe;
        unawaited(
          probe.then(
            (_) {},
            onError: (Object _) {
              if (identical(vetted, probe)) vetted = null;
            },
          ),
        );
      }
      return vetted!;
    },
    forgetAddress: () {
      vetted = null;
    },
  );
}

/**
 * True for the failure a reused keep-alive socket produces when the upstream
 * closed it while the request was on its way.
 */
bool _isStaleSocketError(Object err) {
  final code = err is NodeError ? err.code : null;
  return code == 'ECONNRESET' || code == 'EPIPE';
}

/**
 * Destroy a denied client's request only after the 403 has flushed —
 * destroying the shared socket in the same tick can RST the response away.
 */
void _destroyAfterDenial(http.IncomingMessage req, http.ServerResponse res) {
  if (res.destroyed) {
    req.destroy();
    return;
  }
  if (res.writableFinished) {
    endRequestAfterResponse(req);
    return;
  }
  res.once('finish', ([_]) => endRequestAfterResponse(req));
  res.once('close', ([_]) {
    if (!res.writableFinished) req.destroy();
  });
}

/**
 * After a deny: stop a forwarded body that is not the request itself (a
 * tee branch, a transform) at once, and the request once the answer is
 * out. A request without a body is its own body, and destroying it before
 * the answer is out would drop the answer.
 */
void _endDeniedRequest(
  http.IncomingMessage req,
  http.ServerResponse res,
  stream.Readable body,
) {
  if (!identical(body, req)) body.destroy();
  _destroyAfterDenial(req, res);
}

void _forwardUpstreamGuarded(
  FilterRequestCallback? filterRequest,
  MutateForwardedHeaders? mutateHeaders,
  GetBodySubstitutions? getBodySubstitutions,
  http.IncomingMessage req,
  http.ServerResponse res,
  TerminateTarget target,
  _UpstreamLeg leg, [
  PlanSigv4? planSigv4,
  int maxSigv4BodyBytes = MAX_SIGV4_RESIGN_BODY_BYTES,
]) {
  // Fire-and-forget from the request handler: a rejection (e.g. a
  // synchronous throw writing a denial to a client that already reset)
  // must not become an unhandledRejection, and the client still gets an
  // answer (502, or a reset once headers are out) instead of waiting for
  // a server timeout.
  unawaited(
    _forwardUpstream(
      filterRequest,
      mutateHeaders,
      getBodySubstitutions,
      req,
      res,
      target,
      leg,
      planSigv4,
      maxSigv4BodyBytes,
    ).catchError((Object err) {
      logForDebugging(
        '[tls-terminate] forwardUpstream failed: ${errorMessage(err)}',
        level: 'error',
      );
      respondUpstreamError(res, err, target.denyHeader);
      _destroyAfterDenial(req, res);
    }),
  );
}

Future<void> _forwardUpstream(
  FilterRequestCallback? filterRequest,
  MutateForwardedHeaders? mutateHeaders,
  GetBodySubstitutions? getBodySubstitutions,
  http.IncomingMessage req,
  http.ServerResponse res,
  TerminateTarget target,
  _UpstreamLeg leg, [
  PlanSigv4? planSigv4,
  int maxSigv4BodyBytes = MAX_SIGV4_RESIGN_BODY_BYTES,
]) async {
  // req.url is the request-target verbatim. Inside a CONNECT tunnel almost
  // every client sends origin-form (`/path?q`), but RFC 7230 §5.3.2 also
  // permits absolute-form (`https://host/path`) and servers MUST accept it.
  // Normalize to origin-form so concatenating onto `https://${host}` below
  // yields a well-formed URL, and discard any client-supplied authority so
  // the CONNECT-verified target stays authoritative (same rationale as the
  // Host-header note below).
  // With filterRequest, the hook gets the target as spelled and normalized,
  // and the spelling is what is forwarded: rewriting it would break a
  // signature over the path, or have a masked AWS credential re-signed for
  // a resource the client did not name. Where the two forms can name
  // different resources the hook may have judged another one than the
  // upstream acts on, so the request is refused unless
  // ambiguousRequestTarget says which form to send. A target of any other
  // shape could make the judged URL name another host, so it is refused.
  // Without filterRequest nothing judges the path, so the target is
  // forwarded unchanged. requestTargetAsSpelled comes first: it forwards the
  // target as the client spelled it.
  DenyMark? markFor(String code) => target.denyHeader != null
      ? (name: target.denyHeader!, value: code)
      : null;
  // The tunnel target as it goes on the wire: filterRequest URL, Host, SigV4.
  final authority = formatAuthority(target.hostname, target.port, 443);
  final read = filterRequest != null && target.requestTargetAsSpelled != true
      ? readRequestTarget(
          req.url ?? '/',
          req.method,
          target.ambiguousRequestTarget,
        )
      : null;
  final path = target.requestTargetAsSpelled == true
      ? requestTargetAsSpelled(req.url ?? '/')
      : read != null
      ? read.forwarded
      : _originFormPath(req.url);
  if (path == null) {
    final why = respondRefusedTarget(
      res,
      read?.refusal,
      markFor('bad_request'),
    );
    target.onFilterRequestDeny?.call(
      req.method ?? 'GET',
      'https://$authority${read?.spelled ?? ''}',
      why,
    );
    // Like a denial: a body still to come must not keep the tunnel.
    _destroyAfterDenial(req, res);
    return;
  }
  // RFC 9112 3.2: an HTTP/1.1 request without Host is answered 400. Not
  // every runtime's parser does it (Bun's for a handed-in connection
  // passes it on).
  if (req.httpVersion == '1.1' && hostHeaderValues(req.rawHeaders).isEmpty) {
    respondDenied(
      res,
      'HTTP/1.1 request without a Host header',
      markFor('bad_request') ?? 'blocked-by-sandbox-runtime',
      400,
    );
    return;
  }
  // RFC 9112 3.3: the target URI of the asterisk form (`OPTIONS *`) has an
  // empty path. Put behind the authority, the `*` would be read into the host.
  final url = 'https://$authority${path == '*' ? '' : path}';
  stream.Readable body = req;
  RequestDecision? decision;
  final sni = target.clientServerName ?? _serverNameOf(req);
  if (target.requireHostMatch == true &&
      target.clientServerNameUnreadable == true) {
    const why = 'TLS server name could not be read';
    target.onFilterRequestDeny?.call(req.method ?? 'GET', url, why);
    respondDenied(
      res,
      why,
      markFor('misdirected') ?? 'blocked-by-sandbox-runtime',
      421,
    );
    return;
  }
  if (target.requireHostMatch == true) {
    final why = hostMismatch(hostHeaderValues(req.rawHeaders), sni, (
      hostname: target.hostname,
      port: target.port,
      defaultPort: 443,
    ), _absoluteFormAuthority(req.url));
    if (why != null) {
      target.onFilterRequestDeny?.call(req.method ?? 'GET', url, why);
      respondDenied(
        res,
        why,
        markFor('misdirected') ?? 'blocked-by-sandbox-runtime',
        421,
      );
      return;
    }
  }
  if (filterRequest != null) {
    final ac = abort.AbortController();
    res.once('close', ([_]) => ac.abort());
    // Build the URL passed to filterRequest from the CONNECT target,
    // NOT from `req.headers.host`. The Host header is supplied by the
    // sandboxed client and can be spoofed: a sandboxed process can
    // CONNECT to allowlisted host A and then send a decrypted request
    // with `Host: B` (where B is some other allowlisted host). If we
    // built the filterRequest URL from req.headers.host the callback
    // would see "host=B" while the request is actually delivered to A.
    // A consumer using filterRequest for per-host method gating (e.g.
    // "POST allowed only to inference endpoints") would be bypassed —
    // the agent could spoof Host: api.example.com on a CONNECT to a
    // different allowlisted host, get the POST allowed, and have it
    // delivered to the CONNECT target instead.
    //
    // Always derive the URL from the verified CONNECT target so
    // filterRequest sees the actual upstream destination.
    final out = await decideAndRespond(
      filterRequest,
      req,
      res,
      url,
      ac.signal,
      target.onFilterRequestDeny,
      RequestInfo(
        sni: sni,
        target: (host: target.hostname, port: target.port),
        requestTarget: read?.spelled ?? path,
        normalizedRequestTarget: read?.normalized,
        requestTargetIsAmbiguous: read?.ambiguous,
        rawHeaders: [...req.rawHeaders],
        scheme: 'https',
      ),
      target.denyHeader,
    );
    if (out == null) return;
    body = out.body;
    decision = out.decision;
    // The client may have aborted during the filterRequest await — the tee
    // branch is already destroyed and res 'close' already fired, so the
    // teardown listeners attached below would never run. Don't dial an
    // upstream for a dead client. A COMPLETED request is also
    // destroyed=true (normal stream lifecycle after 'end'); only a
    // destroy without a clean end is an abort.
    if ((req.destroyed && !req.readableEnded) ||
        res.destroyed ||
        req.socket.destroyed ||
        body.destroyed) {
      body.destroy();
      return;
    }
  }

  // The upstream is dialed by vetted address (below), so Host and SNI are
  // what carry the name: rebuild Host from the tunnel's target — the name the
  // allowlist saw — rather than forwarding the client's spelling.
  final fwdHeaders = stripHopByHop(
    req.headers,
    folded: target.foldHopByHop ?? false,
  );
  fwdHeaders['host'] = authority;
  // The decision's edits go before the credential hooks below, so a value
  // a decision sets can itself carry a masked credential's sentinel.
  if (decision != null) applyHeaderEdits(fwdHeaders, decision);
  // SigV4 planning runs on the PRE-substitution headers (the trigger is
  // the fake access key id in the credential scope, which the header
  // substitution below replaces) but on the POST-strip view: the plan's
  // signed-header presence check must see exactly the set that will be
  // signed and forwarded, or a signed hop-by-hop header would pass the
  // check and then blow up inside the signer.
  final sigv4Plan = planSigv4?.call(
    req.method ?? 'GET',
    path,
    fwdHeaders,
    target.hostname,
  );
  // Header mutation runs after the allow decision and before httpsRequest.
  // The upstream TLS handshake (rejectUnauthorized defaults to true)
  // completes before any HTTP bytes are written, so mutated headers never
  // reach an unverified server.
  mutateHeaders?.call(fwdHeaders, target.hostname);
  // Masked-credential substitution in the request body, mirroring the
  // header substitution above. undefined → the bare pipe below, exactly as
  // before. May delete content-length from fwdHeaders (chunked fallback).
  final bodyTransform = prepareBodySubstitution(
    getBodySubstitutions,
    req,
    fwdHeaders,
    target.hostname,
  );

  // SigV4 re-signing runs after substitution so the new signature covers
  // the headers as they actually go upstream (real access key id, real
  // session token). Same denial surface as filterRequest.
  Uint8List? bufferedBody;
  if (sigv4Plan is Sigv4PlanDeny) {
    respondDenied(res, sigv4Plan.reason);
    _endDeniedRequest(req, res, body);
    return;
  }
  if (sigv4Plan is Sigv4PlanResign) {
    var payloadHash = sigv4Plan.payloadHash;
    if (payloadHash == null) {
      // The client signed a literal body hash: buffer the body and
      // recompute so the signature covers the bytes actually sent. Body
      // substitution runs FIRST — the buffered bytes (and therefore the
      // hash and signature) must be the substituted body, not the
      // sentinel-bearing one the client wrote.
      final stream.Readable bodySource = bodyTransform != null
          ? body.pipe<stream.Transform>(bodyTransform)
          : body;
      if (bodyTransform != null) {
        body.on('error', (Object err) => bodyTransform.destroy(err));
      }
      try {
        bufferedBody = await _collectBody(bodySource, maxSigv4BodyBytes);
      } catch (err) {
        if (err is _BodyTooLargeError) {
          respondDenied(
            res,
            'AWS SigV4 request uses a masked credential and signs a '
            'literal body hash, so the proxy must buffer the body to '
            're-sign it, but the body exceeds the '
            '$maxSigv4BodyBytes-byte buffering limit; denied. Sign '
            'the payload as UNSIGNED-PAYLOAD to stream it without '
            'buffering, or use an unmasked credential to have the '
            'request forwarded untouched.',
          );
          // Drain (discarding) whatever the client is still sending so it
          // can read the 403 instead of seeing a reset mid-upload.
          bodySource.resume();
          return;
        }
        logForDebugging(
          '[tls-terminate] failed to buffer body for SigV4 re-sign: ${errorMessage(err)}',
          level: 'error',
        );
        res.destroy();
        return;
      }
      payloadHash = sha256Hex(bufferedBody);
      // The body is fully buffered so its exact length is known — set the
      // header unconditionally. end(Buffer) only auto-computes a
      // content-length for methods that default to chunked encoding; on
      // bodyless-default methods it would raw-append the buffer unframed.
      fwdHeaders['content-length'] = '${bufferedBody.length}';
    }
    try {
      sigv4Plan.apply(fwdHeaders, authority, payloadHash);
    } catch (err) {
      // Fail closed on any signer error — a request the proxy claimed to
      // handle must not go upstream half-rewritten, and a client-crafted
      // header set must not become an unhandled rejection.
      respondDenied(res, 'AWS SigV4 re-signing failed: ${errorMessage(err)}');
      _endDeniedRequest(req, res, body);
      return;
    }
  }

  // When the client declared a body but the forwarded headers carry no
  // framing (chunked TE stripped as hop-by-hop, or a body transform
  // deleted content-length), the upstream leg must re-frame explicitly:
  // for bodyless-method requests the runtime would otherwise write the
  // piped body bytes raw after complete-framed headers — a
  // request-smuggling primitive. The SigV4 buffered path is exempt:
  // end(bufferedBody) computes its own content-length.
  // `Boolean(a || b)`: an absent or empty header is falsy.
  final clientDeclaredBody =
      (req.headers['content-length'] ?? '') != '' ||
      (req.headers['transfer-encoding'] ?? '') != '';
  if (clientDeclaredBody &&
      bufferedBody == null &&
      fwdHeaders['content-length'] == null &&
      fwdHeaders['transfer-encoding'] == null) {
    fwdHeaders['transfer-encoding'] = 'chunked';
  }

  void failUpstream(Object err, [http.ClientRequest? sent]) {
    logForDebugging(
      '[tls-terminate] upstream ${target.hostname}:${target.port} failed: ${errorMessage(err)}',
      level: 'error',
    );
    leg.forgetAddress();
    if (sent?.reusedSocket == true &&
        !res.headersSent &&
        _isStaleSocketError(err)) {
      // The upstream closed the kept-alive socket as this request went out.
      // Close the client's connection rather than answer 502: that is what
      // the client would see on a direct keep-alive connection, and what its
      // own retry policy is written for. Destroy the socket, not `res`: with
      // no headers sent yet, Bun's res.destroy() answers `200 OK` with an
      // empty body before closing, which would hand the client a fabricated
      // success.
      req.socket.destroy();
      return;
    }
    respondUpstreamError(res, err, target.denyHeader);
  }

  // Vet and pick the upstream address first (see createUpstreamLeg); the
  // name stays in Host and SNI.
  DirectRequestOptions direct;
  try {
    direct = await leg.address();
  } catch (err) {
    failUpstream(err);
    return;
  }
  if (res.destroyed || req.socket.destroyed) {
    // Client went away during the dial.
    body.destroy();
    return;
  }

  // TODO(terminating-tls): honour parentProxy for the upstream leg.
  final upstream = https.request(
    {
      // `...direct`.
      'host': direct.host,
      'port': direct.port,
      if (direct.servername != null) 'servername': direct.servername,
      'agent': leg.agent,
      'path': path,
      'method': req.method,
      'headers': fwdHeaders,
    },
    (http.IncomingMessage upRes) {
      // The response stream errors independently of the ClientRequest;
      // pipe() does not handle source errors.
      upRes.on('error', (dynamic err) {
        logForDebugging(
          '[tls-terminate] upstream response error: ${errorMessage(err)}',
          level: 'error',
        );
        res.destroy();
      });
      final outHeaders = stripHopByHop(upRes.headers);
      notifyResponse(decision, upRes.statusCode ?? 502, outHeaders);
      if (target.stripResponseHeaders != null) {
        removeHeadersFolded(outHeaders, target.stripResponseHeaders!);
      }
      if (relayResponseHead(res, upRes, outHeaders)) {
        _relayResponse(upRes, res);
      }
    },
  );

  onUpstreamError(upstream, (Object err) => failUpstream(err, upstream));

  res.on('close', ([_]) => upstream.destroy());
  if (bufferedBody != null) {
    // SigV4 literal-hash path: the buffered body already went through
    // bodyTransform above (when one applied), so send it verbatim.
    upstream.end(bufferedBody);
  } else if (bodyTransform != null) {
    // Errors on either side of the extra pipe stage tear the chain down —
    // a stalled half-open upstream would otherwise wait for the client.
    bodyTransform.on('error', (Object err) => upstream.destroy(err));
    body.on('error', (Object err) => bodyTransform.destroy(err));
    res.on('close', ([_]) => bodyTransform.destroy());
    body.pipe(bodyTransform).pipe(upstream);
  } else {
    // pipe() does not handle source errors. `body` may be a tee branch
    // from decideAndRespond (not `req` itself), so a client abort surfaces
    // here as an 'error' that would otherwise escape as an
    // uncaughtException.
    body.on('error', (Object err) => upstream.destroy(err));
    body.pipe(upstream);
  }
}

/**
 * Read a request body fully into memory (for SigV4 body-hash re-signing).
 * Rejects with {@link BodyTooLargeError} once more than `maxBytes` have
 * arrived, discarding everything buffered so far — the caller denies the
 * request, so holding the partial body would defeat the cap.
 */
Future<Uint8List> _collectBody(stream.Readable body, int maxBytes) {
  final completer = Completer<Uint8List>();
  void resolve(Uint8List v) {
    if (!completer.isCompleted) completer.complete(v);
  }

  void reject(Object e) {
    if (!completer.isCompleted) completer.completeError(e);
  }

  final chunks = <Uint8List>[];
  var total = 0;
  late final void Function(Uint8List) onData;
  onData = (Uint8List c) {
    total += c.length;
    if (total > maxBytes) {
      chunks.length = 0;
      body.removeListener('data', onData);
      reject(_BodyTooLargeError('request body exceeds $maxBytes bytes'));
      return;
    }
    chunks.add(c);
  };
  body.on('data', onData);
  body.once('end', ([_]) {
    final all = BytesBuilder(copy: false);
    for (final c in chunks) {
      all.add(c);
    }
    resolve(all.takeBytes());
  });
  body.once('error', reject);
  return completer.future;
}

/** The authority of an absolute-form request-target, as spelled; undefined for origin form. */
String? _absoluteFormAuthority(String? reqUrl) {
  final m = RegExp(
    r'^[a-zA-Z][a-zA-Z0-9+.-]*:\/\/([^/?#]*)',
  ).firstMatch(reqUrl ?? '');
  return m != null ? m.group(1) : null;
}

/** The TLS server name on the request's socket, where the runtime exposes it. */
String? _serverNameOf(http.IncomingMessage req) {
  final socket = req.socket;
  final Object? name = socket is tls.TLSSocket ? socket.servername : null;
  return name is String && name != '' ? name : null;
}

/**
 * Pipe an upstream response into `res`, waiting whenever the client's side
 * is full: `res` itself (its write() returning false), or the stream the
 * tunnel's TLS socket writes out through holding more than
 * MAX_QUEUED_FOR_CLIENT, or anything while the proxy's shared byte budget
 * is spent.
 */
void _relayResponse(stream.Readable src, http.ServerResponse res) {
  final outbound = _outboundOf[res.socket];
  final budget = _budgetOf[res.socket];
  var counted = 0;
  var released = false;
  void recount() {
    final queued = released ? 0 : (outbound?.writableLength ?? 0);
    final delta = queued - counted;
    counted = queued;
    if (budget != null && delta != 0) adjustByteBudget(budget, delta);
  }

  bool full() {
    if (outbound == null) return false;
    recount();
    return (outbound.writableLength > _MAX_QUEUED_FOR_CLIENT ||
        (budget != null &&
            budget.used > budget.limit &&
            outbound.writableLength > 0));
  }

  late final void Function() waitForRoom;
  void resumeWhenRoom([Object? _]) {
    if (released || res.destroyed) return;
    if (full()) {
      waitForRoom();
      return;
    }
    src.resume();
  }

  // 'drain' only follows a write() that returned false, so a queue below
  // the stream's high-water mark empties without one. An empty write's
  // callback runs once everything queued ahead of it has gone out, at any
  // queue size; a failed stream calls it too, and then `res` closes.
  var awaitingFlush = false;
  waitForRoom = () {
    budget?.waiters.add(resumeWhenRoom);
    if (awaitingFlush || outbound == null) return;
    awaitingFlush = true;
    outbound.write(_EMPTY_CHUNK, ([_]) {
      awaitingFlush = false;
      resumeWhenRoom();
    });
  };
  void release([Object? _]) {
    released = true;
    budget?.waiters.remove(resumeWhenRoom);
    recount();
  }

  src.on('data', (Uint8List chunk) {
    final ok = res.write(chunk);
    if (full()) {
      src.pause();
      waitForRoom();
    } else if (!ok) {
      src.pause();
      res.once('drain', resumeWhenRoom);
    }
  });
  src.once('end', ([_]) => res.end());
  res.once('close', release);
  res.once('finish', release);
}

/**
 * The request-target as forwarded when no filterRequest is configured:
 * origin form verbatim, an absolute URI reduced to its path and query, and
 * anything else (`OPTIONS *`) passed through.
 */
String _originFormPath(String? reqUrl) {
  final raw = reqUrl ?? '/';
  if (raw.startsWith('/')) return raw;
  try {
    final u = url.URL(raw);
    final s = '${u.pathname}${u.search}';
    return s != '' ? s : '/';
  } catch (_) {
    return raw;
  }
}

final _EMPTY_CHUNK = Uint8List(0);

/**
 * Whether the client has finished the TLS handshake: its Finished message
 * has been received and verified. Unlike the negotiated protocol or cipher,
 * which a runtime may report as soon as the ClientHello is read, neither
 * sign is there for a client that reads the server's flight and never
 * answers it.
 *
 * getPeerFinished() is the public way to ask, and is enough on Node. Bun's
 * TLS library reports no peer Finished for TLS 1.3, so there the socket's
 * own (private) record that the handshake is done is read as well; were
 * that field to go away, a quiet TLS 1.3 client on Bun would again be held
 * to the deadline until its first byte.
 */
bool _isTlsHandshakeDone(tls.TLSSocket tls_) {
  // The shim has no getPeerFinished() (Conventions: TLS on a socket you hold).
  return tls_.secureEstablished == true;
}
