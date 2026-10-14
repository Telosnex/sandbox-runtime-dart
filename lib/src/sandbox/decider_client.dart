// STUB: pending port of src/sandbox/decider-client.ts @ 24eb39e.
// ignore_for_file: constant_identifier_names, dangling_library_doc_comments
// ignore_for_file: non_constant_identifier_names, slash_for_doc_comments
// ignore_for_file: unintended_html_in_doc_comment

/**
 * External request decider: a FilterRequestCallback answered by another
 * process over a byte stream (an inherited socket, or a pair of pipes).
 *
 * Framing: a 4-byte big-endian length, then exactly that many bytes of one
 * UTF-8 JSON object whose `t` names the message. The proxy speaks first:
 *
 *   proxy   → decider  {"t":"hello","proto":1}
 *   decider → proxy    {"t":"hello","proto":1,"allowedDomains":[...],"deniedDomains":[...]}
 *   proxy   → decider  {"t":"req","id","method","host","port","hostHeader"?,"sni"?,
 *                       "path","query"?,"headers"?:{name:[values]}}
 *   decider → proxy    {"t":"verdict","id","action":"allow","setHeaders"?:{name:[values]},
 *                       "removeHeaders"?:[names],"cred"?,"credential"?}
 *                    | {"t":"verdict","id","action":"deny","status":400..599,"reason"?}
 *                    | {"t":"verdict","id","action":"need_body","max":1..32MiB}
 *   proxy   → decider  {"t":"body","id","data":"<base64>","cut"?:true}   (after need_body)
 *
 * The rules this end keeps:
 * - proto is the integer 1, and a hello states nothing else.
 * - Request ids start at 1 and strictly increase.
 * - Optional fields are left out rather than sent empty: an optional field
 *   that is false, "", {} or [] is refused, as is a null, a duplicate key, a
 *   field the message does not have, a header name that is not lower-case,
 *   and a header or reason value with a control character (tab aside, C1
 *   controls included).
 * - A request gets verdicts until a deny or an allow ends it; a need_body
 *   asks for the body once (a second one is a violation). While this end
 *   reads a body, the decider may end the request with a deny.
 * - This end's timer is the only one: it waits `timeoutMs` for each
 *   verdict, then answers the client itself and drops, silently, whatever
 *   comes later for that id. A message for any other id nothing waits on is
 *   a violation, except that ids more than 4096 below the newest are
 *   forgotten and their late messages dropped.
 * - It reads frames of at most 1 MiB, and sends no req over 1 MiB. In a
 *   req, headers are at most 190 values and 64 KiB of names and values;
 *   host, Host header, server name and path at most 8 KiB each; all counted
 *   in UTF-8 bytes. A request that doesn't fit is answered 400 here,
 *   without asking.
 *
 * An allow's removeHeaders and setHeaders are applied exactly, matched
 * *case-insensitively with `-`, `_` and `.` as one character (see
 * applyHeaderEdits). A credential (`cred` names its class, `credential`
 * carries the value for this one request) first removes every credential
 * header the client sent, then goes where its placement says.
 *
 * Fail-closed: a request is refused unless a well-formed allow for its id
 * arrives in time. Any violation, in either direction, kills the link:
 * every pending and later request is refused and `onDead` fires once.
 */

import 'dart:typed_data';

import '../node/fetch.dart' as fetch;
import '../node/stream.dart' as stream;
import 'request_filter.dart';

const int DECIDER_PROTO = 1;

/**
 * Bytes written to the decider and not yet taken by it before it counts as
 * gone. It has to clear every body frame the budget above allows at once
 * (base64, so four thirds of it) with room for request frames besides; past
 * that the decider is not reading, and one that is not reading cannot answer.
 */
int get MAX_QUEUED_BYTES =>
    throw UnimplementedError('pending port of src/sandbox/decider-client.ts');

class DeciderHello {
  const DeciderHello({
    required this.t,
    required this.proto,
    required this.allowedDomains,
    required this.deniedDomains,
  });

  final String t;
  final int proto;
  final List<String> allowedDomains;
  final List<String> deniedDomains;
}

/**
 * Where a credential class's value goes. The first rule whose class and
 * host (when given) match wins; with none, the value goes as
 * `Authorization: Bearer <value>`.
 */
sealed class CredentialPlacement {
  const CredentialPlacement({this.credentialClass, this.host});

  final String? credentialClass;
  final String? host;
}

class CredentialPlacementBearer extends CredentialPlacement {
  const CredentialPlacementBearer({super.credentialClass, super.host});

  final String scheme = 'bearer';
}

class CredentialPlacementBasic extends CredentialPlacement {
  const CredentialPlacementBasic({
    super.credentialClass,
    super.host,
    required this.user,
  });

  final String scheme = 'basic';
  final String user;
}

class DeciderOptions {
  const DeciderOptions({
    required this.input,
    required this.output,
    this.timeoutMs,
    this.credentialPlacements,
    this.onDead,
    this.maxBodyBytesHeld,
    this.maxQueuedBytes,
  });

  final stream.Readable input;
  final stream.Writable output;
  /** How long to wait for each verdict. */
  final int? timeoutMs;
  final List<CredentialPlacement>? credentialPlacements;
  final void Function(String why)? onDead;
  /** Overrides MAX_BODY_BYTES_HELD. */
  final int? maxBodyBytesHeld;
  /** Overrides MAX_QUEUED_BYTES. */
  final int? maxQueuedBytes;
}

abstract interface class Decider {
  /** Resolves with the decider's hello, or rejects when it never comes. */
  Future<DeciderHello> get hello;
  FilterRequestCallback get filterRequest;
  void close();
  /** Request-body bytes reserved for need_body reads still in flight. */
  int bodyBytesHeld();
}

Decider createDecider(DeciderOptions opts) =>
    throw UnimplementedError('pending port of src/sandbox/decider-client.ts');

/** One frame: the 4-byte big-endian length, then the JSON object. */
Uint8List encodeFrame(Map<String, Object?> msg) =>
    throw UnimplementedError('pending port of src/sandbox/decider-client.ts');

/**
 * The frame `encodeFrame({t:'body',id,data:<base64>,cut?})` gives, byte for
 * byte, built in place: the base64 goes into the frame a slice at a time, so
 * no base64 string, JSON string or second buffer of the whole body exists.
 */
Uint8List encodeBodyFrame(int id, Uint8List data, bool cut) =>
    throw UnimplementedError('pending port of src/sandbox/decider-client.ts');

/**
 * The req frame's fields (all but t and id), or why the request can't be
 * asked about: a req the protocol cannot carry (past its limits, or with a
 * value it refuses) would break the protocol, so the proxy answers such a
 * request 400 itself and sends nothing.
 */
Object reqFrameFields(fetch.Request request, RequestInfo? info) =>
    throw UnimplementedError('pending port of src/sandbox/decider-client.ts');

/**
 * Whether s is an entry of the decider's egress lists: a lower-case DNS
 * name, the same after `*.` (with two labels or more), or an IP literal,
 * then an optional `:port` (after `[...]` for an IPv6 literal). No scheme,
 * path, user or space.
 */
bool isEgressEntry(String s) =>
    throw UnimplementedError('pending port of src/sandbox/decider-client.ts');
