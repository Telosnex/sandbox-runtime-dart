// STUB: pending port of src/sandbox/request-filter.ts @ 24eb39e.
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

import '../node/abort.dart' as abort;
import '../node/fetch.dart' as fetch;
import '../node/http.dart' as http;
import '../node/stream.dart' as stream;

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

/**
 * User-facing reason when a filterRequest denial doesn't supply one. This
 * text reaches the sandboxed client (403 body) and the model
 * (<sandbox_violations>), so it names the policy, not the internal hook.
 */
const String DEFAULT_DENY_REASON = 'denied by sandbox policy';

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
]) => throw UnimplementedError('pending port of src/sandbox/request-filter.ts');

/**
 * A request-target in origin form (path and query), normalized once: the
 * URL parser resolves dot segments and reads `%2e` as `.`, and a run of
 * leading slashes becomes one. Normalizing the result again changes
 * nothing, so an HTTP client that re-normalizes on the way out sends the
 * same bytes. Accepts origin form, an absolute http(s) URI (whose
 * authority is dropped; the caller names the host) and `*` for OPTIONS;
 * returns undefined for any other shape, which the caller refuses.
 */
String? normalizeRequestTarget(String raw, String? method) =>
    throw UnimplementedError('pending port of src/sandbox/request-filter.ts');

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
String? requestTargetAsSpelled(String raw, {bool absolute = false}) =>
    throw UnimplementedError('pending port of src/sandbox/request-filter.ts');

/**
 * A header name folded for comparison: lower case, with `_` and `.` read
 * as `-`. Upstreams differ in which separators they treat as equivalent,
 * so a removal must cover every spelling.
 */
String foldHeaderName(String name) =>
    throw UnimplementedError('pending port of src/sandbox/request-filter.ts');

/** Remove every header whose folded name is one of `names`, in place. */
void removeHeadersFolded(
  http.IncomingHttpHeaders headers,
  Iterable<String> names,
) => throw UnimplementedError('pending port of src/sandbox/request-filter.ts');

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
  ({List<String>? removeHeaders, List<(String, String)>? setHeaders}) decision,
) => throw UnimplementedError('pending port of src/sandbox/request-filter.ts');

/** Call an allow decision's onResponse, containing its failures. */
void notifyResponse(
  RequestDecision? decision,
  int status,
  http.IncomingHttpHeaders headers,
) => throw UnimplementedError('pending port of src/sandbox/request-filter.ts');

/**
 * The Host header of a request as a list of its values, from the raw
 * header lines (a runtime keeps only the first of repeated Host headers in
 * `headers`).
 */
List<String> hostHeaderValues(List<String> rawHeaders) =>
    throw UnimplementedError('pending port of src/sandbox/request-filter.ts');

/**
 * Why a request's Host header, TLS server name or absolute-form authority
 * does not name the host and port it is being sent to, or undefined when
 * they agree.
 *
 * A server name must be the target's host, in any case. A Host header (or
 * the authority of an absolute-form request-target) names the target when
 * it is the target's host in any case, with the target's port after one
 * colon, or with no port when the target's port is the scheme's default, and with
 * brackets only around an IPv6 address; any other shape (an empty value,
 * a trailing colon or dot, brackets around a name) names no host.
 * More than one Host header is a mismatch; none is not (HTTP/1.1 parsers
 * already require one).
 */
String? hostMismatch(
  List<String> hostHeaders,
  String? serverName,
  ({String hostname, int port, int defaultPort}) target, [
  String? requestTargetAuthority,
]) => throw UnimplementedError('pending port of src/sandbox/request-filter.ts');

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
sealed class DenyMark {
  const DenyMark();
}

class DenyMarkString extends DenyMark {
  const DenyMarkString(this.value);

  final String value;
}

class DenyMarkObject extends DenyMark {
  const DenyMarkObject({required this.name, required this.value});

  final String name;
  final String value;
}

String rawDenied(
  String reason, [
  DenyMark tag = const DenyMarkString('blocked-by-sandbox-runtime'),
  String phrase = 'Forbidden',
]) => throw UnimplementedError('pending port of src/sandbox/request-filter.ts');

/**
 * Write the proxy's standard policy-denial response: 403 with the reason
 * in the body, so the sandboxed client can tell a policy block from a
 * network failure. Shared by filterRequest denials and other in-proxy
 * policy decisions (e.g. SigV4 shapes that cannot be re-signed).
 */
void respondDenied(
  http.ServerResponse res,
  String reason, [
  DenyMark tag = const DenyMarkString('blocked-by-sandbox-runtime'),
  int status = 403,
]) => throw UnimplementedError('pending port of src/sandbox/request-filter.ts');

/**
 * Answer a failed upstream leg: a resolved-address refusal is a policy
 * denial (403 with the reason); anything else is a 502, or a bare destroy
 * once headers are out.
 */
void respondUpstreamError(
  http.ServerResponse res,
  Error err, [
  String? denyHeader,
]) => throw UnimplementedError('pending port of src/sandbox/request-filter.ts');
