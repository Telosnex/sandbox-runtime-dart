// Ported from sandbox-runtime src/sandbox/request-filter.ts @ 24eb39e.
// ignore_for_file: constant_identifier_names, dangling_library_doc_comments
// ignore_for_file: non_constant_identifier_names, slash_for_doc_comments
// ignore_for_file: unintended_html_in_doc_comment

/**
 * Request-level filter hook for the forward proxy.
 *
 * Library consumers supply a `filterRequest` callback via
 * `network.filterRequest`. It receives the parsed HTTP request (web-standard
 * `Request`) and returns a decision. Applies to plain HTTP through the proxy
 * and, when `tlsTerminate` is configured, to terminated HTTPS. The proxy
 * enforces the decision; the library does not bless any matching DSL.
 */

import 'dart:async';
import 'dart:typed_data';

import 'emitted_connection.dart' show endRequestAfterResponse;
import '../node/abort.dart' as abort;
import '../node/buffer.dart' show Buffer;
import '../node/errno.dart' show errorMessage;
import '../node/fetch.dart' as fetch;
import '../node/http.dart' as http;
import '../node/net.dart' show isIP;
import '../node/stream.dart' as stream;
import '../node/url.dart' show URL;
import '../utils/debug.dart' show logForDebugging;
import 'resolved_address_guard.dart' show isResolvedAddressDenied;
import 'sandbox_violation_store.dart' show sanitizeDenialReason;

class RequestDecision {
  const RequestDecision({
    required this.action,
    this.reason,
    this.status,
    this.mark,
    this.removeHeaders,
    this.setHeaders,
    this.onResponse,
  });

  /// Allowed values: `'allow'` | `'deny'`.
  final String action;
  /**
   * Human-readable reason. For denials this is surfaced to the sandboxed
   * client in the response body so the agent can tell a policy block from a
   * network failure.
   */
  final String? reason;
  /**
   * Deny only: the response status, 400 to 599. Anything else, or none,
   * answers 403.
   */
  final int? status;
  /**
   * Deny only: a short reason code for the refusal (an HTTP token, e.g.
   * `decider`). A proxy created with `denyHeader` sends it as that
   * header's value; `denied` when none is given. Otherwise it is unused.
   */
  final String? mark;
  /**
   * Allow only: headers to remove from the forwarded request. Names match
   * case-insensitively and with `-`, `_` and `.` treated as one character,
   * so `x-api-key` also removes `X_Api_Key` and `x.api.key`. Framing headers
   * (see setHeaders) are never removed.
   */
  final List<String>? removeHeaders;
  /**
   * Allow only: headers to set on the forwarded request, after
   * `removeHeaders`. A name given more than once gets every value, in
   * order; each name first removes every spelling of itself the client
   * sent. Framing headers (`host`, `content-length`, `transfer-encoding`,
   * `connection`, `upgrade`, `te`, `trailer`, `keep-alive`,
   * `proxy-connection`) are never set. A value holding a control character
   * other than tab, or a character above U+00FF, makes the whole decision
   * malformed and the request is denied. On the plain-HTTP path (`scheme`
   * is `'http'`) sets apply only when the proxy was created with
   * `plaintextHeaderSet`; without it an allow that carries any `setHeaders`
   * entry is refused with 403 rather than forwarded without them.
   */
  final List<(String, String)>? setHeaders;
  /**
   * Allow only: called once with the upstream response's status and
   * headers (hop-by-hop headers removed), just before the response is
   * written to the client. It gets a copy of the headers, so it observes
   * and cannot change the response. It may be async: a throw, or a
   * rejection of the promise it returns, is logged and ignored, and the
   * response is not held for it.
   */
  final FutureOr<void> Function(int status, http.IncomingHttpHeaders headers)?
  onResponse;
}

/**
 * Called once per HTTP request that the proxy parses.
 *
 * - `request` is a web-standard `Request`: method, URL, headers, and a lazy
 *   `request.body` stream (one branch of a tee — reading it does not consume
 *   the bytes that get forwarded upstream). `request.signal` aborts when the
 *   client disconnects.
 * - **Throwing or rejecting denies the request.** This is the failure
 *   contract for a security boundary: a buggy policy fails closed. So does
 *   a decision that is not well-formed: an unknown action, a header name
 *   that is not an HTTP token, or a header value holding a control
 *   character other than tab or a character above U+00FF.
 */
typedef FilterRequestCallback =
    Future<RequestDecision> Function(
      fetch.Request request, [
      RequestInfo? info,
    ]);

/** What the proxy knows about a request beyond the Request itself. */
class RequestInfo {
  const RequestInfo({
    this.scheme,
    this.sni,
    this.unshownBody,
    this.target,
    this.requestTarget,
    this.rawHeaders,
  });

  /**
   * How the proxy received the request: `'https'` on the TLS-terminated
   * path, `'http'` when it arrived in cleartext (an absolute `https://` URI
   * sent in cleartext included).
   */
  final String? scheme;
  /** The TLS server name the client sent, on the TLS-terminated path. */
  final String? sni;
  /**
   * Set only for GET, HEAD and OPTIONS requests that declare a body, whose
   * Request is built without one: resolves true once the request is known
   * to carry body bytes (a non-zero Content-Length, or the first decoded
   * byte of a chunked body) and false when the body ends empty. A callback
   * that needs to have seen the whole request must refuse when it is true.
   */
  final Future<bool> Function()? unshownBody;
  /**
   * Where the request goes: the CONNECT target on the TLS-terminated
   * path, or the absolute URI's host and port on the plain path, in the
   * canonical spelling the allowlist evaluated.
   */
  final ({String host, int port})? target;
  /**
   * The request-target in origin form (path and query), exactly as it is
   * forwarded upstream; path rules should key on this. It is normalized
   * once on both paths (see normalizeRequestTarget) and that exact value
   * is forwarded. (With no filterRequest configured there is no hook to
   * judge the target: plain HTTP forwards the URL-parsed path and query,
   * and the TLS-terminated path forwards the client's bytes unchanged.)
   */
  final String? requestTarget;
  /**
   * A copy of the client's header lines as received: name, value, name,
   * value, ... Some runtimes lower-case the names.
   */
  final List<String>? rawHeaders;
}

/**
 * Mutate the headers that will be sent upstream, in place.
 *
 * Runs after the allow/deny decision and hop-by-hop stripping, immediately
 * before the upstream request is built. `destHost` is the canonical
 * destination host (the CONNECT target on the TLS-terminated path, or the
 * absolute-URI host on the plain-HTTP path, after canonicalizeHost — the
 * spelling the allowlist evaluated) — never the client-supplied Host
 * header, which is spoofable.
 */
typedef MutateForwardedHeaders =
    void Function(http.IncomingHttpHeaders headers, String destHost);

final Set<String> BODYLESS_METHODS = {'GET', 'HEAD', 'OPTIONS'};

/** Methods whose response echoes the request; never forwarded. */
final Set<String> _ECHO_METHODS = {'TRACE', 'TRACK'};

/**
 * User-facing reason when a filterRequest denial doesn't supply one. This
 * text reaches the sandboxed client (403 body) and the model
 * (<sandbox_violations>), so it names the policy, not the internal hook.
 */
const String DEFAULT_DENY_REASON = 'denied by sandbox policy';

/**
 * Destroy a denied client's request only after the 403 has flushed —
 * destroying the shared socket in the same tick can RST the response
 * away (observed on Node; the unread request body makes close send RST).
 */
void _destroyAfterResponse(http.IncomingMessage req, http.ServerResponse res) {
  if (res.destroyed) {
    req.destroy();
    return;
  }
  if (res.writableFinished) {
    endRequestAfterResponse(req);
    return;
  }
  res.once('finish', () => endRequestAfterResponse(req));
  res.once('close', () {
    if (!res.writableFinished) req.destroy();
  });
}

/**
 * Build a `Request`, run the callback, and if denied write the 403 response
 * and return `null`. On allow, returns the body stream the caller must pipe
 * upstream — this is the original `IncomingMessage` when no tee was needed
 * (GET/HEAD/OPTIONS), or the upstream-side branch of the tee otherwise.
 * Callers must pipe the returned stream (not `req`) to the outbound request.
 *
 * For methods that carry a body, `req` is converted to a web stream and
 * `tee()`'d: one branch goes to the callback's `Request.body`, the other is
 * returned for the caller to forward. If the callback never reads its
 * branch, we cancel it after the decision so the tee does not buffer the
 * entire upload.
 */
Future<({stream.Readable body, RequestDecision decision})?> decideAndRespond(
  FilterRequestCallback filterRequest,
  http.IncomingMessage req,
  http.ServerResponse res,
  String url,
  abort.AbortSignal signal, [
  void Function(String method, String url, String reason)? onDeny,
  RequestInfo? info,
  String? denyHeader,
  bool canSetHeaders = true,
]) async {
  final method = req.method ?? 'GET';
  fetch.ReadableStream<Uint8List>? forCallback;
  stream.Readable forUpstream = req;
  stream.PassThrough? shim;
  // Gate on a declared body, not just the method: a GET/HEAD/OPTIONS with
  // Content-Length or Transfer-Encoding is legal HTTP and its body must go
  // through the tee like any other — skipping it here would hide the body
  // from filterRequest AND (with transfer-encoding stripped as hop-by-hop)
  // let its decoded bytes be written raw after a complete-framed bodyless
  // request upstream: a request-smuggling primitive.
  // Truthiness, not presence: an empty Content-Length/Transfer-Encoding
  // value declares nothing and must not trigger teeing or re-framing.
  final declaresBody =
      (req.headers['content-length'] as String? ?? '').isNotEmpty ||
      (req.headers['transfer-encoding'] as String? ?? '').isNotEmpty;
  final bodylessMethod = BODYLESS_METHODS.contains(method);
  if (!bodylessMethod || declaresBody) {
    // Never hand toWeb a stream that can error: when its source errors,
    // the toWeb/tee/fromWeb bridge leaks the error as internal promise
    // rejections (and, under Bun, uncaught exceptions) that no userland
    // listener can catch. A client abort mid-body becomes a clean EOF on
    // the shim instead, and the abort is propagated by destroying the
    // upstream branch directly — a truncated body must never be forwarded
    // framed as complete (chunked framing would otherwise emit a valid
    // terminator; on the SigV4 path a truncated buffer would be signed).
    // The shim's own error listener covers the tee cancelling it while
    // the client is still piping.
    final teeSource = stream.PassThrough();
    shim = teeSource;
    teeSource.on('error', () {});
    req.pipe(teeSource);
    final web = stream.Readable.toWeb(teeSource);
    final [a, b] = web.tee();
    forCallback = a;
    forUpstream = stream.Readable.fromWeb(b);
    final upstreamBranch = forUpstream;
    // The caller only wires its own 'error' handler after this function
    // resolves; a client abort during the filterRequest await must not
    // land on a listener-less stream.
    upstreamBranch.on('error', () {});
    req.on('error', (Object err) {
      teeSource.end();
      upstreamBranch.destroy(err);
    });
  }

  // TRACE (and TRACK, which some servers treat the same) asks the server
  // to echo the request back: forwarded with a credential the decision
  // attached, the echo would hand that credential to the client. Refused
  // here, before the callback is asked and before anything is dialled.
  // Node's and Bun's HTTP parsers reject TRACK as an unknown method (their
  // own 400) before this runs; it is listed for a parser that would not.
  if (_ECHO_METHODS.contains(method.toUpperCase())) {
    final reason = 'the $method method is not forwarded';
    onDeny?.call(method, url, reason);
    _deny(
      res,
      RequestDecision(
        action: 'deny',
        status: 405,
        reason: reason,
        mark: 'method_refused',
      ),
      denyHeader,
    );
    forCallback?.cancel().catchError((Object _) {});
    _endDeniedBody(req, res, forUpstream, shim);
    return null;
  }

  fetch.Request webReq;
  try {
    // Fetch-spec Requests reject a body on GET/HEAD (Node throws; Bun is
    // lenient) — a GET with a declared body is still teed above so the
    // upstream leg stays framed, but the callback sees a bodyless Request.
    final callbackBody = forCallback != null && !bodylessMethod
        ? (body: forCallback, duplex: 'half')
        : (body: null, duplex: null);
    webReq = fetch.Request(
      url,
      method: method,
      headers: _incomingHeaders(req),
      signal: signal,
      body: callbackBody.body,
      duplex: callbackBody.duplex,
    );
  } catch (err) {
    // Malformed URL/headers from the client — deny rather than crash.
    final reason = 'malformed request: ${errorMessage(err)}';
    onDeny?.call(method, url, reason);
    _deny(
      res,
      RequestDecision(action: 'deny', reason: reason, mark: 'bad_request'),
      denyHeader,
    );
    forCallback?.cancel().catchError((Object _) {});
    _endDeniedBody(req, res, forUpstream, shim);
    return null;
  }

  RequestDecision decision;
  try {
    decision = await filterRequest(
      webReq,
      forCallback != null && bodylessMethod
          ? RequestInfo(
              scheme: info?.scheme,
              sni: info?.sni,
              unshownBody: _unshownBodyProbe(req, forCallback),
              target: info?.target,
              requestTarget: info?.requestTarget,
              rawHeaders: info?.rawHeaders,
            )
          : info,
    );
  } catch (err) {
    decision = RequestDecision(
      action: 'deny',
      reason: 'sandbox policy check failed: ${errorMessage(err)}',
    );
  }
  final malformed = _malformedDecisionReason(decision);
  if (malformed != null) {
    decision = RequestDecision(
      action: 'deny',
      reason: 'malformed filterRequest decision: $malformed',
    );
  }
  // A caller that cannot apply header sets (cleartext, without the opt-in)
  // refuses the request: forwarding it without a header the decision relied
  // on would fail open, and the callback has no way to learn of the drop.
  if (!canSetHeaders &&
      decision.action == 'allow' &&
      (decision.setHeaders?.length ?? 0) > 0) {
    decision = const RequestDecision(
      action: 'deny',
      reason: _PLAINTEXT_HEADER_SET_REASON,
      mark: 'plaintext_header_set',
    );
  }

  // If the callback didn't read its branch, cancel it so tee() stops
  // buffering bytes nobody will consume. If it did, the tee already buffered
  // whatever was read; the upstream branch sees the same bytes.
  if (forCallback != null && !webReq.bodyUsed) {
    // cancel() rejects with the stream's stored error if it already
    // failed; that rejection must not escape.
    forCallback.cancel().catchError((Object _) {});
  }

  if (decision.action == 'allow') {
    logForDebugging('[request-filter] allow $method $url');
    return (body: forUpstream, decision: decision);
  }

  onDeny?.call(method, url, decision.reason ?? DEFAULT_DENY_REASON);
  _deny(res, decision, denyHeader);
  _endDeniedBody(req, res, forUpstream, shim);
  return null;
}

/**
 * After a deny, stop the request: destroy a teed body's upstream branch at
 * once, and the request itself once the answer is out. The shim breaks the
 * old fromWeb→tee→toWeb cancel cascade that used to destroy req; without
 * this a denied client keeps uploading into a stalled pipe and holds the
 * connection open. Destroying req before the answer is flushed loses the
 * answer under Node (for a request without a body, req is what destroys
 * the socket).
 *
 * A teed body's bytes stop going to the shim at once and are dropped from
 * then on: the tee is cancelled, and a byte the shim passed on to its
 * closed web stream would throw (Bun: "Controller is already closed").
 */
void _endDeniedBody(
  http.IncomingMessage req,
  http.ServerResponse res,
  stream.Readable forUpstream,
  stream.PassThrough? shim,
) {
  if (shim != null) {
    req.unpipe(shim);
    shim.pause();
    req.resume();
  }
  if (!identical(forUpstream, req)) forUpstream.destroy();
  _destroyAfterResponse(req, res);
}

/**
 * Whether a request whose body the callback's Request leaves out carries
 * any body bytes. A non-zero Content-Length answers at once; otherwise the
 * callback's branch of the tee is read, which holds decoded body bytes, so
 * empty reads are skipped and only the end of the body means "none".
 */
Future<bool> Function() _unshownBodyProbe(
  http.IncomingMessage req,
  fetch.ReadableStream<Uint8List> branch,
) {
  Future<bool>? answer;
  Future<bool> probe() async {
    if ((req.headers['transfer-encoding'] as String? ?? '').isEmpty &&
        (num.tryParse(req.headers['content-length'] as String? ?? '0') ??
                double.nan) >
            0) {
      return true;
    }
    final reader = branch.getReader();
    try {
      for (;;) {
        final (:done, :value) = await reader.read();
        if (done) return false;
        if (value!.lengthInBytes > 0) return true;
      }
    } finally {
      reader.cancel().catchError((Object _) {});
    }
  }

  return () => (answer ??= probe());
}

const String _PLAINTEXT_HEADER_SET_REASON =
    'the allow decision sets headers, and headers are not set on plain-HTTP '
    'requests unless plaintext header sets are enabled; nothing was forwarded';

// RFC 9110 token; the same set Node's own header-name check accepts.
final RegExp _HEADER_NAME = RegExp(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$");

/**
 * Why a decision cannot be applied as given, or undefined when it can. The
 * callback's return is only typed, not checked, and a decision that would
 * throw half-way through forwarding must deny instead.
 */
String? _malformedDecisionReason(Object? decision) {
  if (decision is! RequestDecision) return 'not an object';
  final d = decision;
  if (d.action != 'allow' && d.action != 'deny') return 'unknown action';
  final Object? reason = d.reason;
  if (reason != null && reason is! String) {
    return 'reason is not a string';
  }
  final Object? status = d.status;
  if (status != null && status is! num) {
    return 'status is not a number';
  }
  final Object? mark = d.mark;
  if (mark != null && (mark is! String || !_HEADER_NAME.hasMatch(mark))) {
    return 'mark is not a reason code';
  }
  if (d.action == 'deny') return null;
  final Object? onResponse = d.onResponse;
  if (onResponse != null && onResponse is! Function) {
    return 'onResponse is not a function';
  }
  final Object? removals = d.removeHeaders;
  if (removals != null) {
    if (removals is! List) return 'removeHeaders is not an array';
    for (final Object? name in removals) {
      if (name is! String || !_HEADER_NAME.hasMatch(name)) {
        return 'removeHeaders holds an invalid header name';
      }
    }
  }
  final Object? sets = d.setHeaders;
  if (sets != null) {
    if (sets is! List) return 'setHeaders is not an array';
    for (final Object? entry in sets) {
      if (entry is! (Object?, Object?)) {
        return 'setHeaders holds an entry that is not a [name, value] pair';
      }
      final (name, value) = entry;
      if (name is! String || !_HEADER_NAME.hasMatch(name)) {
        return 'setHeaders holds an invalid header name';
      }
      if (value is! String || !_isValidHeaderValue(value)) {
        return 'setHeaders holds an invalid header value';
      }
    }
  }
  return null;
}

/**
 * A field value may carry HTAB but no other control character, and no
 * character above U+00FF (Node's HTTP client throws on those).
 */
bool _isValidHeaderValue(String value) {
  for (var i = 0; i < value.length; i++) {
    final code = value.codeUnitAt(i);
    if ((code < 0x20 && code != 0x09) || code == 0x7f || code > 0xff) {
      return false;
    }
  }
  return true;
}

void _deny(
  http.ServerResponse res,
  RequestDecision decision,
  String? denyHeader,
) {
  final s = decision.status;
  final status = s != null && s >= 400 && s <= 599 ? s : 403;
  respondDenied(
    res,
    decision.reason ?? DEFAULT_DENY_REASON,
    denyHeader != null
        ? (name: denyHeader, value: decision.mark ?? 'denied')
        : null,
    status,
  );
}

/**
 * A request-target in origin form (path and query), normalized once: the
 * URL parser resolves dot segments and reads `%2e` as `.`, and a run of
 * leading slashes becomes one. Normalizing the result again changes
 * nothing, so an HTTP client that re-normalizes on the way out sends the
 * same bytes. Accepts origin form, an absolute http(s) URI (whose
 * authority is dropped; the caller names the host) and `*` for OPTIONS;
 * returns undefined for any other shape, which the caller refuses.
 */
String? normalizeRequestTarget(String raw, String? method) {
  if (raw == '*') return method == 'OPTIONS' ? raw : null;
  URL url;
  try {
    // The fixed prefix keeps an origin-form target in the path: a leading
    // `//` is never read as an authority.
    url = URL(raw.startsWith('/') ? 'http://origin.invalid$raw' : raw);
  } catch (_) {
    return null;
  }
  if (url.protocol != 'http:' && url.protocol != 'https:') return null;
  return '${url.pathname.replaceFirst(RegExp(r'^/{2,}'), '/')}${url.search}';
}

/**
 * A request-target as the client spelled it, for a proxy that forwards it
 * unchanged and lets its policy match it exactly: dot segments and
 * percent-escapes, encoded or not, are kept, so an unusual spelling of an
 * admitted path is simply not that path. Origin form only (`/` first, and
 * not `//` or `/\`), with no `#`, space, control byte or DEL; with
 * `absolute`, the path and query of an absolute http(s) URI, as spelled.
 * Any other shape (authority form, asterisk form, or absolute form where
 * origin form is required) is undefined, which the caller answers 400.
 */
String? requestTargetAsSpelled(String raw, {bool absolute = false}) {
  var target = raw;
  if (absolute) {
    final m = RegExp(
      r'^https?://[^/?#]*',
      caseSensitive: false,
    ).firstMatch(raw);
    if (m == null) return null;
    target = raw.substring(m[0]!.length);
    if (target == '' || target.startsWith('?')) target = '/$target';
  }
  if (!target.startsWith('/') || target.startsWith('//')) return null;
  if (target.startsWith('/\\')) return null;
  for (var i = 0; i < target.length; i++) {
    final c = target.codeUnitAt(i);
    if (c <= 0x20 || c == 0x7f || c == 0x23) return null;
  }
  return target;
}

/**
 * A header name folded for comparison: lower case, with `_` and `.` read
 * as `-`. Upstreams differ in which separators they treat as equivalent,
 * so a removal must cover every spelling.
 */
String foldHeaderName(String name) {
  return name.toLowerCase().replaceAll(RegExp(r'[_.]'), '-');
}

final Set<String> _UNSETTABLE_HEADERS = {
  'host',
  'connection',
  'keep-alive',
  'proxy-connection',
  'transfer-encoding',
  'te',
  'trailer',
  'upgrade',
  'content-length',
};

/** Remove every header whose folded name is one of `names`, in place. */
void removeHeadersFolded(
  http.IncomingHttpHeaders headers,
  Iterable<String> names,
) {
  final drop = <String>{};
  for (final n in names) {
    drop.add(foldHeaderName(n));
  }
  if (drop.isEmpty) return;
  for (final k in headers.keys.toList()) {
    if (drop.contains(foldHeaderName(k))) headers.remove(k);
  }
}

/**
 * Apply an allow decision's header edits to the headers about to be sent
 * upstream, in place: first remove every header whose folded name (see
 * foldHeaderName) is a removal or a name the decision sets, then add the
 * set values. Sets are grouped by folded name (`x-foo` and `x_foo` are one
 * header, emitted under the first spelling), and framing headers are
 * neither removed nor set.
 */
void applyHeaderEdits(
  http.IncomingHttpHeaders headers,
  RequestDecision decision,
) {
  // Grouped by folded name, emitted under the first spelling given.
  final sets = <String, ({String name, List<String> values})>{};
  for (final (name, value)
      in decision.setHeaders ?? const <(String, String)>[]) {
    final folded = foldHeaderName(name);
    if (_UNSETTABLE_HEADERS.contains(folded)) continue;
    final entry =
        sets[folded] ?? (name: name.toLowerCase(), values: <String>[]);
    if (!RegExp('[\r\n\x00]').hasMatch(value)) entry.values.add(value);
    sets[folded] = entry;
  }
  final removals = (decision.removeHeaders ?? const <String>[]).where(
    (n) => !_UNSETTABLE_HEADERS.contains(foldHeaderName(n)),
  );
  removeHeadersFolded(headers, [...removals, ...sets.keys]);
  for (final (:name, :values) in sets.values) {
    if (values.isNotEmpty) {
      headers[name] = values.length == 1 ? values[0] : values;
    }
  }
}

/** Call an allow decision's onResponse, containing its failures. */
void notifyResponse(
  RequestDecision? decision,
  int status,
  http.IncomingHttpHeaders headers,
) {
  if (decision?.onResponse == null) return;
  final http.IncomingHttpHeaders copy = {};
  for (final MapEntry(key: name, :value) in headers.entries) {
    copy[name] = value is List ? [...value] : value;
  }
  try {
    final Object? returned = decision!.onResponse!(status, copy);
    if (_isThenable(returned)) {
      (returned as Future<Object?>).then((_) {}, onError: _logResponseFailure);
    }
  } catch (err) {
    _logResponseFailure(err);
  }
}

bool _isThenable(Object? value) {
  return value is Future;
}

void _logResponseFailure(Object? err) {
  logForDebugging(
    '[request-filter] onResponse failed: ${errorMessage(err) ?? '$err'}',
    level: 'error',
  );
}

/**
 * The Host header of a request as a list of its values, from the raw
 * header lines (a runtime keeps only the first of repeated Host headers in
 * `headers`).
 */
List<String> hostHeaderValues(List<String> rawHeaders) {
  final out = <String>[];
  for (var i = 0; i + 1 < rawHeaders.length; i += 2) {
    if (rawHeaders[i].toLowerCase() == 'host') out.add(rawHeaders[i + 1]);
  }
  return out;
}

/**
 * Why a request's Host header, TLS server name or absolute-form authority
 * does not name the host and port it is being sent to, or undefined when
 * they agree.
 *
 * A server name must be the target's host, in any case. A Host header (or
 * the authority of an absolute-form request-target) names the target when
 * it is the target's host in any case, with the target's port after one
 * colon, or with no port when the target's port is the scheme's default,
 * and with brackets only around an IPv6 address; any other shape (an empty
 * value, a trailing colon or dot, brackets around a name) names no host.
 * More than one Host header is a mismatch; none is not (HTTP/1.1 parsers
 * already require one).
 */
String? hostMismatch(
  List<String> hostHeaders,
  String? serverName,
  ({String hostname, int port, int defaultPort}) target, [
  String? requestTargetAuthority,
]) {
  final want = target.hostname.toLowerCase();
  if (serverName != null && serverName.toLowerCase() != want) {
    return 'TLS server name does not match the request target';
  }
  if (requestTargetAuthority != null &&
      !_namesTarget(requestTargetAuthority, want, (
        port: target.port,
        defaultPort: target.defaultPort,
      ))) {
    return 'request-target authority does not match the request target';
  }
  if (hostHeaders.isEmpty) return null;
  if (hostHeaders.length > 1) return 'more than one Host header';
  if (!_namesTarget(hostHeaders[0], want, (
    port: target.port,
    defaultPort: target.defaultPort,
  ))) {
    return 'Host header does not match the request target';
  }
  return null;
}

bool _namesTarget(
  String authority,
  String want,
  ({int port, int defaultPort}) target,
) {
  final parsed = _hostAndPort(authority);
  if (parsed == null || parsed.host.toLowerCase() != want) return false;
  return parsed.port == ''
      ? target.port == target.defaultPort
      : parsed.port == '${target.port}';
}

/** A Host header's host and port ("" when none), or undefined for any other shape. */
({String host, String port})? _hostAndPort(String h) {
  var host = h;
  var rest = '';
  if (h.startsWith('[')) {
    final end = h.indexOf(']');
    if (end < 0) return null;
    host = h.substring(1, end);
    rest = h.substring(end + 1);
    if (isIP(host) != 6) return null;
  } else {
    final i = h.indexOf(':');
    if (i >= 0) {
      host = h.substring(0, i);
      rest = h.substring(i);
    }
    if (RegExp(r'[[\]]').hasMatch(host)) return null;
  }
  if (rest == '') return (host: host, port: '');
  final port = rest.substring(1);
  if (rest[0] != ':' || port == '' || RegExp(r'[[\]:]').hasMatch(port)) {
    return null;
  }
  return (host: host, port: port);
}

const String _DEFAULT_DENY_TAG = 'blocked-by-sandbox-runtime';

/**
 * The proxy's standard policy-denial response as raw bytes, for paths that
 * answer on a bare socket (CONNECT): 403 with an `X-Proxy-Error` tag and
 * the reason as the body. `phrase` is the status line's: of a refused CONNECT
 * that is the part clients show (the script in GIT_SSH_COMMAND among
 * them), not the body. It is cleaned and cut as a violation line's reason
 * is. What is not ASCII becomes `?`: many clients read a status line as
 * Latin-1, where UTF-8 shows as noise, C1 controls among it.
 */
/**
 * The header that marks a denial: `X-Proxy-Error: <tag>` for a tag, or a
 * caller's own header and value.
 */
typedef DenyMark = Object /* String | ({String name, String value}) */;

(String, String) _denyMarkHeader(DenyMark mark) {
  return mark is String
      ? ('X-Proxy-Error', mark)
      : ((mark as ({String name, String value})).name, mark.value);
}

String rawDenied(
  String reason, [
  DenyMark? tag = _DEFAULT_DENY_TAG,
  String? phrase,
]) {
  phrase ??= 'Forbidden';
  final (name, value) = _denyMarkHeader(tag ?? _DEFAULT_DENY_TAG);
  return 'HTTP/1.1 403 ${sanitizeDenialReason(phrase).replaceAll(RegExp(r'[^ -~]', unicode: true), '?')}\r\n'
      'Content-Type: text/plain\r\n'
      '$name: $value\r\n'
      '\r\n'
      '$reason';
}

/**
 * Write the proxy's standard policy-denial response: 403 with the reason
 * in the body, so the sandboxed client can tell a policy block from a
 * network failure. Shared by filterRequest denials and other in-proxy
 * policy decisions (e.g. SigV4 shapes that cannot be re-signed).
 */
void respondDenied(
  http.ServerResponse res,
  String reason, [
  DenyMark? tag = _DEFAULT_DENY_TAG,
  int status = 403,
]) {
  logForDebugging('[proxy] deny: $reason');
  if (res.headersSent || res.destroyed) {
    res.destroy();
    return;
  }
  final (name, value) = _denyMarkHeader(tag ?? _DEFAULT_DENY_TAG);
  res.writeHead(status, {'Content-Type': 'text/plain', name: value});
  // As bytes: a server may pass a string on to a socket whose default
  // encoding is not UTF-8 (see writeHeadsAsLatin1).
  res.end(Buffer.from('$reason\n').toUint8List());
}

/**
 * Answer a failed upstream leg: a resolved-address refusal is a policy
 * denial (403 with the reason); anything else is a 502, or a bare destroy
 * once headers are out.
 */
void respondUpstreamError(
  http.ServerResponse res,
  Object err, [
  String? denyHeader,
]) {
  if (isResolvedAddressDenied(err)) {
    respondDenied(
      res,
      errorMessage(err)!,
      denyHeader != null
          ? (name: denyHeader, value: 'address_not_allowed')
          : null,
    );
  } else if (!res.headersSent) {
    res.writeHead(502, {'Content-Type': 'text/plain'});
    res.end('Bad Gateway');
  } else {
    res.destroy();
  }
}

fetch.Headers _incomingHeaders(http.IncomingMessage req) {
  final h = fetch.Headers();
  for (final MapEntry(key: k, value: v) in req.headers.entries) {
    if (v == null) continue;
    if (v is List) {
      for (final vv in v) {
        h.append(k, vv as String);
      }
    } else {
      h.append(k, v as String);
    }
  }
  return h;
}
