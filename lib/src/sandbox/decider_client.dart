// Ported from sandbox-runtime src/sandbox/decider-client.ts @ 24eb39e.
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
 * case-insensitively with `-`, `_` and `.` as one character (see
 * applyHeaderEdits). A credential (`cred` names its class, `credential`
 * carries the value for this one request) first removes every credential
 * header the client sent, then goes where its placement says.
 *
 * Fail-closed: a request is refused unless a well-formed allow for its id
 * arrives in time. Any violation, in either direction, kills the link:
 * every pending and later request is refused and `onDead` fires once.
 */

import 'dart:async';
import 'dart:convert';
import 'dart:math' as math;
import 'dart:typed_data';

import '../node/buffer.dart';
import '../node/errno.dart';
import '../node/fetch.dart' as fetch;
import '../node/net.dart' as net;
import '../node/stream.dart' as stream;
import '../node/url.dart';
import 'request_filter.dart';

const int DECIDER_PROTO = 1;
const int _MAX_READ_FRAME = 1 << 20;
const int _MAX_BODY = 32 << 20;
/**
 * Request-body bytes that may be held for the decider at once, across all
 * requests. Each held byte costs about two and a third in this process (the
 * body, then its base64 in the frame), so two full-size bodies keep what
 * this budget covers near 150 MiB. The reservation ends at the verdict,
 * before anything is sent upstream: the copy of an allowed body that then
 * waits to go upstream is not counted here, and is paced by the proxy's
 * relay limits. A need_body that would pass the budget is refused, not
 * queued: a queue of held bodies is the same memory.
 */
const int _MAX_BODY_BYTES_HELD = 2 * _MAX_BODY;
/**
 * Bytes written to the decider and not yet taken by it before it counts as
 * gone. It has to clear every body frame the budget above allows at once
 * (base64, so four thirds of it) with room for request frames besides; past
 * that the decider is not reading, and one that is not reading cannot answer.
 */
const int _QUEUED_REQUEST_FRAME_ROOM = 32 << 20;
int get MAX_QUEUED_BYTES =>
    ((_MAX_BODY_BYTES_HELD * 4) / 3).ceil() + _QUEUED_REQUEST_FRAME_ROOM;
// A multiple of three, so slices of base64 join with no padding between.
const int _BASE64_SLICE = 3 << 16;
// The protocol's limits (docs/srt-proxy.md, "Limits"), which both ends keep:
// header values and bytes, and an allow's removeHeaders names and bytes.
const int _MAX_HEADER_ENTRIES = 190;
const int _MAX_HEADER_BYTES = 64 << 10;
const int _MAX_REMOVE_NAMES = 190;
const int _MAX_REMOVE_BYTES = 64 << 10;
const int _MAX_HOST_PATH = 8 << 10;
const int _MAX_REASON_BYTES = 1 << 10;
const int _MAX_ID = 9007199254740991; // 2 ** 53 - 1
const int _ID_WINDOW = 4096;

/** Headers a credential travels in; removed (in any spelling) before one is placed. */
const List<String> _CREDENTIAL_HEADERS = [
  'authorization',
  'proxy-authorization',
  'cookie',
  'x-api-key',
];
/** Headers an allow may not set: framing, and credentials (which only `cred` places). */
final Set<String> _NEVER_SET = [
  ..._CREDENTIAL_HEADERS,
  'host',
  'content-length',
  'transfer-encoding',
  'connection',
  'upgrade',
  'te',
  'trailer',
  'keep-alive',
  'proxy-connection',
].map(foldHeaderName).toSet();
/** Headers an allow may not remove: framing. */
final Set<String> _NEVER_REMOVED = [
  'host',
  'content-length',
  'transfer-encoding',
  'connection',
  'upgrade',
  'te',
  'trailer',
  'keep-alive',
  'proxy-connection',
].map(foldHeaderName).toSet();

final RegExp _TOKEN = RegExp(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$");
final RegExp _LONE_SURROGATE = RegExp(
  r'[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]',
);
bool _wellFormed(String s) => !_LONE_SURROGATE.hasMatch(s);
/** A C0 control other than tab, DEL, or a C1 control. */
bool _hasControl(String s) {
  for (var i = 0; i < s.length; i++) {
    final c = s.codeUnitAt(i);
    if ((c < 0x20 && c != 0x09) || (c >= 0x7f && c <= 0x9f)) return true;
  }
  return false;
}

// zod schemas become predicates and parsers (Rule 3); z.number().int() is
// a JSON number (int or double) with an integer value.
bool _zInt(Object? v) =>
    v is int || (v is double && v.isFinite && v == v.truncateToDouble());
bool _lowerName(Object? n) =>
    n is String && _TOKEN.hasMatch(n) && n == n.toLowerCase();
bool _headerValue(Object? v) => v is String && !_hasControl(v);
Map<String, List<String>>? _nonEmptyHeaderObject(Object? o) {
  if (o is! Map<String, Object?>) return null;
  final out = <String, List<String>>{};
  for (final MapEntry(:key, :value) in o.entries) {
    if (!_lowerName(key) || value is! List<Object?>) return null;
    if (!value.every(_headerValue)) return null;
    out[key] = value.cast<String>();
  }
  return out.isNotEmpty ? out : null;
}

int? _id(Object? v) =>
    _zInt(v) && (v as num) >= 1 && v <= _MAX_ID ? v.toInt() : null;
List<String>? _uniqueList(Object? l, bool Function(Object? item) item) =>
    l is List<Object?> && l.every(item) && l.toSet().length == l.length
    ? l.cast<String>()
    : null;

DeciderHello? _helloSchema(Map<String, Object?> o) {
  if (!o.keys.every(
    {'t', 'proto', 'allowedDomains', 'deniedDomains'}.contains,
  )) {
    return null;
  }
  if (o['t'] != 'hello') return null;
  final proto = o['proto'];
  if (proto is! num || proto != DECIDER_PROTO) return null;
  bool entry(Object? s) => s is String && isEgressEntry(s);
  final allowedDomains = _uniqueList(o['allowedDomains'], entry);
  final deniedDomains = _uniqueList(o['deniedDomains'], entry);
  if (allowedDomains == null || deniedDomains == null) return null;
  return DeciderHello(
    t: 'hello',
    proto: DECIDER_PROTO,
    allowedDomains: allowedDomains,
    deniedDomains: deniedDomains,
  );
}

_Allow? _allowSchema(Map<String, Object?> o) {
  if (!o.keys.every(
    {
      't',
      'id',
      'action',
      'setHeaders',
      'removeHeaders',
      'cred',
      'credential',
    }.contains,
  )) {
    return null;
  }
  if (o['t'] != 'verdict' || o['action'] != 'allow') return null;
  final id = _id(o['id']);
  if (id == null) return null;
  Map<String, List<String>>? setHeaders;
  if (o.containsKey('setHeaders')) {
    setHeaders = _nonEmptyHeaderObject(o['setHeaders']);
    if (setHeaders == null) return null;
  }
  List<String>? removeHeaders;
  if (o.containsKey('removeHeaders')) {
    removeHeaders = _uniqueList(o['removeHeaders'], _lowerName);
    if (removeHeaders == null || !(removeHeaders.isNotEmpty)) return null;
  }
  String? cred;
  if (o.containsKey('cred')) {
    final c = o['cred'];
    if (c is! String || c.isEmpty) return null;
    cred = c;
  }
  // 1 to 8 KiB of printable ASCII, no space: placed in a header as is,
  // never trimmed or cleaned.
  String? credential;
  if (o.containsKey('credential')) {
    final c = o['credential'];
    if (c is! String || !RegExp(r'^[\x21-\x7e]{1,8192}$').hasMatch(c)) {
      return null;
    }
    credential = c;
  }
  final a = _Allow(
    id: id,
    setHeaders: setHeaders,
    removeHeaders: removeHeaders,
    cred: cred,
    credential: credential,
  );
  if ((a.cred == null) != (a.credential == null)) return null;
  if (!(a.setHeaders ?? {}).keys.every(
    (n) => !_NEVER_SET.contains(foldHeaderName(n)),
  )) {
    return null;
  }
  if (!(a.removeHeaders ?? []).every(
    (n) => !_NEVER_REMOVED.contains(foldHeaderName(n)),
  )) {
    return null;
  }
  // A verdict past the protocol's limits breaks the protocol.
  if (!_headersFit(a.setHeaders ?? {})) return null;
  if (!((a.removeHeaders ?? []).length <= _MAX_REMOVE_NAMES &&
      (a.removeHeaders ?? []).fold<int>(0, (n, h) => n + _utf8Bytes(h)) <=
          _MAX_REMOVE_BYTES)) {
    return null;
  }
  return a;
}

_Deny? _denySchema(Map<String, Object?> o) {
  if (!o.keys.every({'t', 'id', 'action', 'status', 'reason'}.contains)) {
    return null;
  }
  if (o['t'] != 'verdict' || o['action'] != 'deny') return null;
  final id = _id(o['id']);
  if (id == null) return null;
  final status = o['status'];
  if (!_zInt(status) || (status as num) < 400 || status > 599) return null;
  String? reason;
  if (o.containsKey('reason')) {
    final r = o['reason'];
    if (r is! String ||
        r.isEmpty ||
        !(Buffer.byteLength(r) <= _MAX_REASON_BYTES && !_hasControl(r))) {
      return null;
    }
    reason = r;
  }
  return _Deny(id: id, status: status.toInt(), reason: reason);
}

_NeedBody? _needBodySchema(Map<String, Object?> o) {
  if (!o.keys.every({'t', 'id', 'action', 'max'}.contains)) return null;
  if (o['t'] != 'verdict' || o['action'] != 'need_body') return null;
  final id = _id(o['id']);
  if (id == null) return null;
  final max = o['max'];
  if (!_zInt(max) || (max as num) < 1 || max > _MAX_BODY) return null;
  return _NeedBody(id: id, max: max.toInt());
}

sealed class _Verdict {
  const _Verdict(this.id, this.action);
  final int id;
  final String action;
}

class _Allow extends _Verdict {
  const _Allow({
    required int id,
    this.setHeaders,
    this.removeHeaders,
    this.cred,
    this.credential,
  }) : super(id, 'allow');
  final Map<String, List<String>>? setHeaders;
  final List<String>? removeHeaders;
  final String? cred;
  final String? credential;
}

class _Deny extends _Verdict {
  const _Deny({required int id, required this.status, this.reason})
    : super(id, 'deny');
  final int status;
  final String? reason;
}

class _NeedBody extends _Verdict {
  const _NeedBody({required int id, required this.max})
    : super(id, 'need_body');
  final int max;
}

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

typedef _Waiter = void Function(Object v);

// `{ dead: string }`, the other thing a waiter is given.
class _Dead {
  const _Dead(this.dead);
  final String dead;
}

class _Violation extends NodeException {
  _Violation(super.message);
}

// The object literal createDecider returns.
class _DeciderObject implements Decider {
  _DeciderObject({
    required this.hello,
    required this.filterRequest,
    required void Function() close,
    required int Function() bodyBytesHeld,
  }) : _close = close,
       _bodyBytesHeld = bodyBytesHeld;

  @override
  final Future<DeciderHello> hello;
  @override
  final FilterRequestCallback filterRequest;
  final void Function() _close;
  final int Function() _bodyBytesHeld;

  @override
  void close() => _close();
  @override
  int bodyBytesHeld() => _bodyBytesHeld();
}

Decider createDecider(DeciderOptions opts) {
  final timeoutMs = opts.timeoutMs ?? 5000;
  final waiters = <int, _Waiter>{};
  // Ids this end gave up on (timed out), with whether a need_body had
  // already been answered for them; late verdicts for them are dropped.
  final late = <int, String>{};
  var lastId = 0;
  String? dead;
  var gotHello = false;
  final helloCompleter = Completer<DeciderHello>();
  final hello = helloCompleter.future;
  hello.ignore();

  void die(String why) {
    if (dead != null) return;
    dead = why;
    helloCompleter.completeError(NodeException('decider unavailable: $why'));
    for (final w in waiters.values.toList()) {
      w(_Dead(why));
    }
    waiters.clear();
    opts.onDead?.call(why);
  }

  final maxHeld = opts.maxBodyBytesHeld ?? _MAX_BODY_BYTES_HELD;
  final maxQueued =
      opts.maxQueuedBytes ??
      (opts.maxBodyBytesHeld == null
          ? MAX_QUEUED_BYTES
          : ((maxHeld * 4) / 3).ceil() + _QUEUED_REQUEST_FRAME_ROOM);
  var held = 0;
  var queued = 0;

  void sendFrame(Uint8List frame) {
    if (dead != null) return;
    queued += frame.length;
    opts.output.write(frame, ([Object? _]) {
      queued -= frame.length;
    });
    if (queued > maxQueued) die('not reading: $queued bytes queued');
  }

  void send(Map<String, Object?> msg) {
    if (dead != null) return;
    sendFrame(encodeFrame(msg));
  }

  void onFrame(Uint8List frame) {
    Object? parsed;
    try {
      parsed = _parseStrictJson(frame);
    } on NodeException catch (e) {
      return die(e.message);
    }
    if (!gotHello) {
      final h = _helloSchema(parsed as Map<String, Object?>);
      if (h == null) return die('bad hello');
      gotHello = true;
      helloCompleter.complete(h);
      return;
    }
    final v = _verdictOf(parsed);
    if (v == null) return die('bad verdict frame');
    final waiter = waiters[v.id];
    if (waiter != null) {
      waiters.remove(v.id);
      waiter(v);
      return;
    }
    final state = late[v.id];
    if (state != null) {
      if (v.action == 'need_body' && state != 'verdict') {
        return die('need_body where none may come');
      }
      if (v.action != 'need_body') late.remove(v.id);
      return;
    }
    if (v.id < lastId && lastId - v.id >= _ID_WINDOW) return;
    die('verdict for id ${v.id}, which nothing waits on');
  }

  var buf = Uint8List(0);
  opts.input.on('data', (Uint8List chunk) {
    buf = buf.isEmpty
        ? chunk
        : (BytesBuilder(copy: false)
                ..add(buf)
                ..add(chunk))
              .takeBytes();
    while (buf.length >= 4 && dead == null) {
      final n = ByteData.sublistView(buf).getUint32(0, Endian.big);
      if (n > _MAX_READ_FRAME) return die('oversized frame');
      if (buf.length < 4 + n) break;
      final frame = Uint8List.sublistView(buf, 4, 4 + n);
      buf = Uint8List.sublistView(buf, 4 + n);
      onFrame(frame);
    }
  });
  opts.input.on('end', () => die('decider closed the stream'));
  opts.input.on('error', (Object err) => die('read error: ${_message(err)}'));
  opts.output.on('error', (Object err) => die('write error: ${_message(err)}'));
  // A stream destroyed without an error (Node's socket on a descriptor whose
  // peer closed) drops later writes without reporting one.
  opts.output.on('close', () => die('decider closed the output stream'));

  send({'t': 'hello', 'proto': DECIDER_PROTO});

  void pruneLate() {
    for (final k in late.keys.toList()) {
      if (lastId - k >= _ID_WINDOW) late.remove(k);
    }
  }

  /**
   * Wait for id's next verdict. With a timeout, running out records the id
   * as late; `cancel` stops waiting without that.
   */
  ({Future<_Verdict> promise, void Function() cancel}) awaitVerdict(
    int reqId,
    String? lateState,
  ) {
    void Function() cancel = () {};
    final completer = Completer<_Verdict>();
    final promise = completer.future;
    () {
      if (dead != null) return completer.completeError(NodeException(dead!));
      Timer? timer;
      late final _Waiter w;
      w = (v) {
        timer?.cancel();
        if (v is _Dead) {
          completer.completeError(NodeException(v.dead));
        } else {
          completer.complete(v as _Verdict);
        }
      };
      if (lateState != null) {
        timer = Timer(Duration(milliseconds: timeoutMs), () {
          if (identical(waiters[reqId], w)) waiters.remove(reqId);
          late[reqId] = lateState;
          pruneLate();
          if (!completer.isCompleted) {
            completer.completeError(NodeException('decider timed out'));
          }
        });
      }
      waiters[reqId] = w;
      cancel = () {
        timer?.cancel();
        if (identical(waiters[reqId], w)) waiters.remove(reqId);
      };
    }();
    promise.ignore();
    return (promise: promise, cancel: cancel);
  }

  final placements = opts.credentialPlacements ?? [];
  (String, String) placeCredential(String cls, String value, String host) {
    final rule = placements
        .where(
          (p) =>
              (p.credentialClass == null || p.credentialClass == cls) &&
              (p.host == null || p.host == host),
        )
        .firstOrNull;
    if (rule is CredentialPlacementBasic) {
      return (
        'authorization',
        'Basic ${Buffer.from('${rule.user}:$value').toString('base64')}',
      );
    }
    return ('authorization', 'Bearer $value');
  }

  RequestDecision toDecision(_Verdict v, String host) {
    if (v is _Deny) {
      return RequestDecision(
        action: 'deny',
        status: v.status,
        reason: v.reason,
        mark: 'decider',
      );
    }
    v as _Allow;
    final setHeaders = <(String, String)>[];
    for (final MapEntry(key: name, value: values)
        in (v.setHeaders ?? {}).entries) {
      for (final value in values) {
        setHeaders.add((name, value));
      }
    }
    final removeHeaders = [...(v.removeHeaders ?? <String>[])];
    if (v.cred != null && v.credential != null) {
      removeHeaders.addAll(_CREDENTIAL_HEADERS);
      setHeaders.add(placeCredential(v.cred!, v.credential!, host));
    }
    return RequestDecision(
      action: 'allow',
      setHeaders: setHeaders,
      removeHeaders: removeHeaders,
    );
  }

  Future<RequestDecision> filterRequest(
    fetch.Request request, [
    RequestInfo? info,
  ]) async {
    if (dead != null) {
      return const RequestDecision(
        action: 'deny',
        status: 503,
        mark: 'decider_unavailable',
        reason: 'request decider unavailable',
      );
    }
    if (!gotHello) {
      return const RequestDecision(
        action: 'deny',
        status: 503,
        mark: 'decider_unavailable',
        reason: 'request decider not ready',
      );
    }
    final req = reqFrameFields(request, info);
    if (req is String) {
      return RequestDecision(
        action: 'deny',
        status: 400,
        reason: req,
        mark: 'bad_request',
      );
    }
    req as Map<String, Object?>;
    final reqId = lastId + 1;
    if (reqId > _MAX_ID) {
      die('request ids exhausted');
      return const RequestDecision(
        action: 'deny',
        status: 503,
        mark: 'decider_unavailable',
        reason: 'request decider unavailable',
      );
    }
    lastId = reqId;
    final host = '${req['host']}';
    var reserved = 0;
    try {
      final first = awaitVerdict(reqId, 'verdict');
      send({'t': 'req', 'id': reqId, ...req});
      var v = await first.promise;
      if (v is _NeedBody) {
        // While the body is read the decider may end the request with a
        // deny; nothing else may come, and no timer runs here.
        if (request.body == null && info?.unshownBody != null) {
          // A GET, HEAD or OPTIONS whose Request carries no body may still
          // have one on the wire. Showing the decider an empty body and
          // forwarding the real one on its allow would send upstream what
          // it never saw, so such a request is refused. The decider still
          // waits for a body; whatever it says next for this id is for a
          // request already refused, or (when the body turns out empty)
          // ends a request that can no longer be decided.
          late[reqId] = 'verdict_shown';
          if (await info!.unshownBody!()) {
            return const RequestDecision(
              action: 'deny',
              reason: _BODYLESS_METHOD_BODY_REASON,
              mark: 'bodyless_method_body',
            );
          }
          if (late.remove(reqId) == null) {
            throw NodeException(
              'the decider answered before it was sent the body',
            );
          }
        }
        // JS Number(): '' is 0, and NaN when absent; num.tryParse stands in.
        final lengthText = request.headers.get('content-length');
        final length = lengthText == null
            ? double.nan
            : lengthText.trim().isEmpty
            ? 0
            : (num.tryParse(lengthText.trim()) ?? double.nan);
        final want = request.body == null
            ? 0
            : _zInt(length) && length >= 0
            ? (length < v.max ? length.toInt() : v.max)
            : v.max;
        if (held + want > maxHeld) {
          // The decider still waits for this body; whatever it says next
          // for this id is for a request already refused.
          late[reqId] = 'verdict_shown';
          throw NodeException('too many request bodies held for inspection');
        }
        held += reserved = want;
        final whileReading = awaitVerdict(reqId, null);
        final body = await Future.any<Object>([
          _readUpTo(request, v.max),
          whileReading.promise.then((d) => (verdict: d)),
        ]);
        if (body is ({_Verdict verdict})) {
          if (body.verdict.action != 'deny') {
            die('a verdict other than deny while the body was read');
            throw _Violation('decider broke the protocol');
          }
          return toDecision(body.verdict, host);
        }
        body as ({Uint8List data, bool cut});
        whileReading.cancel();
        final next = awaitVerdict(reqId, 'verdict_shown');
        sendFrame(encodeBodyFrame(reqId, body.data, body.cut));
        v = await next.promise;
        if (v is _NeedBody) {
          die('a second need_body');
          throw _Violation('decider broke the protocol');
        }
      }
      return toDecision(v, host);
    } catch (err) {
      return RequestDecision(
        action: 'deny',
        status: 503,
        mark: 'decider_unavailable',
        reason: 'request decider: ${_message(err)}',
      );
    } finally {
      held -= reserved;
    }
  }

  return _DeciderObject(
    hello: hello,
    filterRequest: filterRequest,
    close: () => die('closed'),
    bodyBytesHeld: () => held,
  );
}

// `(err as Error).message`.
String _message(Object err) => err is NodeException ? err.message : '$err';

const String _BODYLESS_METHOD_BODY_REASON =
    'the decider asked to see the body of a request whose method normally has none, and it has one';

/** One frame: the 4-byte big-endian length, then the JSON object. */
Uint8List encodeFrame(Map<String, Object?> msg) {
  final body = Buffer.from(jsonEncode(msg), 'utf8').toUint8List();
  final len = Uint8List(4);
  ByteData.sublistView(len).setUint32(0, body.length, Endian.big);
  return (BytesBuilder(copy: false)
        ..add(len)
        ..add(body))
      .takeBytes();
}

/**
 * The frame `encodeFrame({t:'body',id,data:<base64>,cut?})` gives, byte for
 * byte, built in place: the base64 goes into the frame a slice at a time, so
 * no base64 string, JSON string or second buffer of the whole body exists.
 */
Uint8List encodeBodyFrame(int id, Uint8List data, bool cut) {
  final head = latin1.encode('{"t":"body","id":$id,"data":"');
  final tail = latin1.encode(cut ? '","cut":true}' : '"}');
  final frame = Uint8List(
    4 + head.length + (data.length / 3).ceil() * 4 + tail.length,
  );
  ByteData.sublistView(frame).setUint32(0, frame.length - 4, Endian.big);
  frame.setRange(4, 4 + head.length, head);
  var at = 4 + head.length;
  for (var i = 0; i < data.length; i += _BASE64_SLICE) {
    final slice = latin1.encode(
      base64.encode(
        Uint8List.sublistView(
          data,
          i,
          i + _BASE64_SLICE < data.length ? i + _BASE64_SLICE : data.length,
        ),
      ),
    );
    frame.setRange(at, at + slice.length, slice);
    at += slice.length;
  }
  frame.setRange(at, at + tail.length, tail);
  return frame;
}

int _utf8Bytes(String v) => Buffer.byteLength(v);

/**
 * Whether headers (lower-case name -> values) are within the protocol's
 * caps, counted as the protocol counts them: values (a name with no
 * value counts as one) and UTF-8 bytes of each name once plus its values.
 */
bool _headersFit(Map<String, List<String>> headers) {
  var entries = 0;
  var bytes = 0;
  for (final MapEntry(key: name, value: values) in headers.entries) {
    entries += math.max(1, values.length);
    bytes += _utf8Bytes(name);
    for (final v in values) {
      bytes += _utf8Bytes(v);
    }
    if (entries > _MAX_HEADER_ENTRIES || bytes > _MAX_HEADER_BYTES) {
      return false;
    }
  }
  return true;
}

bool _validHeaderValue(String v) => !_hasControl(v) && _wellFormed(v);

/**
 * The req frame's fields (all but t and id), or why the request can't be
 * asked about: a req the protocol cannot carry (past its limits, or with a
 * value it refuses) would break the protocol, so the proxy answers such a
 * request 400 itself and sends nothing.
 */
Object reqFrameFields(fetch.Request request, RequestInfo? info) {
  final url = URL(request.url);
  final host =
      info?.target?.host ?? url.hostname.replaceAll(RegExp(r'^\[|\]$'), '');
  final port =
      info?.target?.port ??
      int.parse(
        url.port.isNotEmpty
            ? url.port
            : (url.protocol == 'https:' ? '443' : '80'),
      );
  final target = info?.requestTarget ?? url.pathname + url.search;
  final q = target.indexOf('?');
  final path = q >= 0 ? target.substring(0, q) : target;
  final query = q >= 0 ? target.substring(q + 1) : '';
  final raw = info?.rawHeaders ?? <String>[];
  final headers = <String, List<String>>{};
  String? hostHeader;
  var hostHeaders = 0;
  for (var i = 0; i + 1 < raw.length; i += 2) {
    final name = raw[i].toLowerCase();
    final value = raw[i + 1];
    if (!_TOKEN.hasMatch(name) || !_validHeaderValue(value)) {
      return 'request header the decider cannot be asked about';
    }
    if (name == 'host') {
      hostHeaders++;
      hostHeader = value;
      continue;
    }
    (headers[name] ??= []).add(value);
  }
  if (hostHeaders > 1) return 'more than one Host header';
  if (!_headersFit(headers)) return 'request headers too large';
  if (request.method == '' ||
      host == '' ||
      path == '' ||
      !(port >= 1 && port <= 65535)) {
    return 'request the decider cannot be asked about';
  }
  for (final v in [host, hostHeader ?? '', info?.sni ?? '', path]) {
    if (_utf8Bytes(v) > _MAX_HOST_PATH) return 'request target too large';
  }
  for (final v in [
    request.method,
    host,
    hostHeader ?? '',
    info?.sni ?? '',
    path,
    query,
  ]) {
    if (!_wellFormed(v)) return 'request the decider cannot be asked about';
  }
  final fields = <String, Object?>{
    'method': request.method,
    'host': host,
    'port': port,
    if (hostHeader != null) 'hostHeader': hostHeader,
    if (info?.sni != null && info!.sni!.isNotEmpty) 'sni': info.sni,
    'path': path,
    if (query != '') 'query': query,
    // A JS object lists array-index keys first; _jsKeyOrder does the same.
    if (headers.isNotEmpty) 'headers': _jsKeyOrder(headers),
  };
  // The whole frame, at the largest id, within what the decider reads.
  if (_utf8Bytes(jsonEncode({'t': 'req', 'id': _MAX_ID, ...fields})) >
      _MAX_READ_FRAME) {
    return 'request too large for the decider';
  }
  return fields;
}

/**
 * Whether s is an entry of the decider's egress lists: a lower-case DNS
 * name, the same after `*.` (with two labels or more), or an IP literal,
 * then an optional `:port` (after `[...]` for an IPv6 literal). No scheme,
 * path, user or space.
 */
bool isEgressEntry(String s) {
  if (net.isIP(s) != 0) return true;
  var host = s;
  String? port;
  if (s.startsWith('[')) {
    final end = s.indexOf(']');
    if (end < 0) return false;
    host = s.substring(1, end);
    final rest = s.substring(end + 1);
    if (rest != '') {
      if (!rest.startsWith(':')) return false;
      port = rest.substring(1);
    }
    return net.isIP(host) == 6 && (port == null || _isPort(port));
  }
  final i = s.lastIndexOf(':');
  if (i >= 0) {
    host = s.substring(0, i);
    port = s.substring(i + 1);
    if (!_isPort(port)) return false;
  }
  if (net.isIP(host) != 0) return net.isIP(host) == 4;
  final wild = host.startsWith('*.');
  final base = wild ? host.substring(2) : host;
  final labels = base.split('.');
  if (base == '' || base.length > 253 || (wild && labels.length < 2)) {
    return false;
  }
  for (final l in labels) {
    if (!RegExp(r'^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$').hasMatch(l)) {
      return false;
    }
  }
  // A name's last label starts with a letter, which keeps every spelling of
  // an IP address out of the names.
  return RegExp(r'^[a-z]').hasMatch(labels[labels.length - 1]);
}

bool _isPort(String s) =>
    RegExp(r'^[1-9][0-9]{0,4}$').hasMatch(s) && int.parse(s) <= 65535;

_Verdict? _verdictOf(Object? parsed) {
  final action = (parsed as Map<String, Object?>?)?['action'];
  final schema = action == 'allow'
      ? _allowSchema
      : action == 'deny'
      ? _denySchema
      : action == 'need_body'
      ? _needBodySchema
      : null;
  return schema?.call(parsed!);
}

/**
 * One JSON object from a frame, refusing what a lenient parser would let
 * through: invalid UTF-8, a lone surrogate, a duplicate key, anything but
 * one object, and a null anywhere.
 */
Object? _parseStrictJson(Uint8List frame) {
  String text;
  try {
    text = utf8.decode(frame);
    // TextDecoder drops a leading BOM; utf8.decode keeps it.
    if (text.startsWith('\uFEFF')) text = text.substring(1);
  } on FormatException {
    throw NodeException('frame is not UTF-8');
  }
  Object? value;
  try {
    // JSON.parse's objects list array-index keys first.
    value = _jsKeyOrder(jsonDecode(text));
  } on FormatException {
    throw NodeException('frame is not valid JSON');
  }
  if (value == null || value is! Map) {
    throw NodeException('frame is not one JSON object');
  }
  void check(Object? v) {
    if (v == null) throw NodeException('null in frame');
    if (v is String && !_wellFormed(v)) {
      throw NodeException('lone surrogate in frame');
    }
    if (v is Map) {
      for (final x in v.values) {
        check(x);
      }
    } else if (v is List) {
      for (final x in v) {
        check(x);
      }
    }
  }

  check(value);
  if (_hasDuplicateKey(text)) throw NodeException('duplicate key in frame');
  return value;
}

/** Whether a (valid) JSON text has an object with the same key twice. */
bool _hasDuplicateKey(String text) {
  final stack = <Set<String>?>[];
  var expectKey = false;
  for (var i = 0; i < text.length; i++) {
    final c = text[i];
    if (c == '"') {
      var j = i + 1;
      while (text[j] != '"') {
        j += text[j] == '\\' ? 2 : 1;
      }
      if (expectKey) {
        final key = jsonDecode(text.substring(i, j + 1)) as String;
        final keys = stack[stack.length - 1]!;
        if (keys.contains(key)) return true;
        keys.add(key);
        expectKey = false;
      }
      i = j;
    } else if (c == '{') {
      stack.add(<String>{});
      expectKey = true;
    } else if (c == '[') {
      stack.add(null);
    } else if (c == '}' || c == ']') {
      stack.removeLast();
    } else if (c == ',') {
      expectKey = stack[stack.length - 1] is Set;
    }
  }
  return false;
}

/** Up to `max` bytes of the request body, and whether there was more. */
Future<({Uint8List data, bool cut})> _readUpTo(
  fetch.Request request,
  int max,
) async {
  if (request.body == null) return (data: Uint8List(0), cut: false);
  final reader = request.body!.getReader();
  final chunks = BytesBuilder(copy: false);
  var total = 0;
  for (;;) {
    final (:done, :value) = await reader.read();
    if (done) break;
    // A view, not a copy: the chunk is this reader's own.
    final b = Uint8List.sublistView(value!);
    if (total + b.length > max) {
      chunks.add(Uint8List.sublistView(b, 0, max - total));
      total = max;
      // Not awaited: the body is one branch of a tee, and a branch's cancel
      // settles only once the other branch (the one going upstream) is done
      // too, so awaiting it would hold a body past max until the request
      // ended.
      reader.cancel().ignore();
      return (data: chunks.takeBytes(), cut: true);
    }
    chunks.add(b);
    total += b.length;
  }
  return (data: chunks.takeBytes(), cut: false);
}

// A JS object's key order: array-index keys (canonical integers below
// 2^32 - 1) first, ascending, then the rest in insertion order.
Object? _jsKeyOrder(Object? v) {
  if (v is List) return [for (final x in v) _jsKeyOrder(x)];
  if (v is! Map) return v;
  bool index(String k) =>
      RegExp(r'^(0|[1-9][0-9]{0,9})$').hasMatch(k) && int.parse(k) < 4294967295;
  final keys = v.keys.cast<String>().toList();
  final indexed = keys.where(index).toList()
    ..sort((a, b) => int.parse(a).compareTo(int.parse(b)));
  return <String, Object?>{
    for (final k in [...indexed, ...keys.where((k) => !index(k))])
      k: _jsKeyOrder(v[k]),
  };
}
