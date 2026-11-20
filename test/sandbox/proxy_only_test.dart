// Ported from sandbox-runtime test/sandbox/proxy-only.test.ts @ 0bbebed.
// ignore_for_file: constant_identifier_names, non_constant_identifier_names
// ignore_for_file: slash_for_doc_comments
import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:test/test.dart';

import 'package:sandbox_runtime/src/node/globals.dart'
    show clearTimeout, setTimeout;
import 'package:sandbox_runtime/src/node/http.dart' as http;
import 'package:sandbox_runtime/src/node/https.dart' as https;
import 'package:sandbox_runtime/src/node/net.dart' as net;
import 'package:sandbox_runtime/src/node/stream.dart' show PassThrough;
import 'package:sandbox_runtime/src/node/tls.dart' as tls;
import 'package:sandbox_runtime/src/node/url.dart' show URL;
import 'package:sandbox_runtime/src/sandbox/decider_client.dart'
    show MAX_QUEUED_BYTES;
import 'package:sandbox_runtime/src/sandbox/http_proxy.dart'
    show HttpProxyServerOptions, createHttpProxyServer, markHandedInConnection;
import 'package:sandbox_runtime/src/sandbox/mitm_ca.dart'
    show MitmCA, createMitmCA, generateCa;
import 'package:sandbox_runtime/src/sandbox/mitm_leaf.dart' show mintLeafCert;
import 'package:sandbox_runtime/src/sandbox/parent_proxy.dart'
    show stripHopByHop;
import 'package:sandbox_runtime/src/sandbox/proxy_only.dart'
    show
        ProxyListenFd,
        ProxyListenHostPort,
        ProxyOnly,
        ProxyOnlyOptions,
        REQUEST_HEAD_LIMIT,
        startProxyOnly;
import 'package:sandbox_runtime/src/sandbox/request_filter.dart'
    show foldHeaderName, requestTargetAsSpelled;

import '../helpers/emitted_connections.dart'
    show canServeEmittedConnections, testWithTls;
import '../helpers/fake_decider.dart' show Frame, fakeDecider, frameOf;

// Dart: Node's Buffer-to-string coercion of a chunk (`raw += d`).
String _utf8(Object? d) =>
    d is String ? d : utf8.decode(d as List<int>, allowMalformed: true);
String _latin1(Object? d) => d is String ? d : latin1.decode(d as List<int>);

// Dart: fakeDecider returns a Map; these read `d.streams` and `d.seen`.
({PassThrough input, PassThrough output}) _streams(Map<String, Object> d) {
  final streams = d['streams'] as Map;
  return (
    input: streams['input'] as PassThrough,
    output: streams['output'] as PassThrough,
  );
}

List<Frame> _seen(Map<String, Object> d) => d['seen'] as List<Frame>;

// Dart: the object literal upstream hands createHttpProxyServer; every
// option not named here is absent (null).
class _HttpOptions implements HttpProxyServerOptions {
  _HttpOptions({
    this.mitmCA,
    this.maxTerminatedTunnels,
    this.denyHeader,
    this.maxBufferedRequestBody,
    this.maxBufferedBytes,
    this.allow = true,
  });
  final bool allow;
  @override
  final MitmCA? mitmCA;
  @override
  final int? maxTerminatedTunnels;
  @override
  final String? denyHeader;
  @override
  final int? maxBufferedRequestBody;
  @override
  final int? maxBufferedBytes;
  @override
  FutureOr<bool> filter(
    int port,
    String host,
    dynamic socket, [
    String? encodedCommand,
    void Function(String reason)? explain,
  ]) => allow;
  @override
  dynamic noSuchMethod(Invocation invocation) => null;
}

typedef Upstream = ({
  http.NodeHttpServer server,
  int port,
  List<({String url, http.IncomingHttpHeaders headers, String body})> got,
});

Future<Upstream> upstream() async {
  final got = <({String url, http.IncomingHttpHeaders headers, String body})>[];
  final server = http.createServer((
    http.IncomingMessage req,
    http.ServerResponse res,
  ) {
    var body = '';
    req.on('data', (Object? c) => body += _utf8(c));
    req.on('end', () {
      got.add((url: req.url ?? '', headers: req.headers, body: body));
      res.writeHead(200, {
        'set-cookie': 'sid=upstream',
        'set_cookie2': 'x',
        'x-kept': 'yes',
      });
      res.end('upstream ok');
    });
  });
  final listening = Completer<void>();
  server.listen(0, '127.0.0.1', () => listening.complete());
  await listening.future;
  return (
    server: server,
    port: (server.address() as net.NodeAddress).port,
    got: got,
  );
}

typedef ProxyReply = ({
  int status,
  http.IncomingHttpHeaders headers,
  String body,
});

/**
 * One absolute-form request to the proxy over a raw socket. (Bun's
 * node:http client dials the URL in `path` itself rather than the proxy,
 * so it can't be used to talk to a forward proxy.)
 */
// Dart: opts is a map, not named parameters, because `host` tells absent
// (the URL's host) from null (no Host header).
Future<ProxyReply> viaProxy(
  int proxyPort,
  String target, [
  Map<String, Object?> opts = const {},
]) {
  final completer = Completer<ProxyReply>();
  final u = URL(target);
  final body = (opts['body'] as String?) ?? '';
  final lines = [
    '${(opts['method'] as String?) ?? 'GET'} $target HTTP/1.1',
    'Connection: close',
  ];
  if (opts['host'] != null || !opts.containsKey('host')) {
    lines.add('Host: ${(opts['host'] as String?) ?? u.host}');
  }
  for (final entry
      in ((opts['headers'] as Map<String, String>?) ?? {}).entries) {
    lines.add('${entry.key}: ${entry.value}');
  }
  if (body.isNotEmpty) lines.add('Content-Length: ${utf8.encode(body).length}');
  late final net.NodeSocket c;
  c = net.connect(
    proxyPort,
    '127.0.0.1',
    () => c.write('${lines.join('\r\n')}\r\n\r\n$body'),
  );
  var raw = '';
  c.on('data', (Object? d) => raw += _utf8(d));
  c.on('error', (Object e) {
    if (!completer.isCompleted) completer.completeError(e);
  });
  c.on('close', () {
    final parts = raw.split('\r\n\r\n');
    final head = parts.isNotEmpty ? parts[0] : '';
    final rest = parts.skip(1);
    final headParts = head.split('\r\n');
    final statusLine = headParts.isNotEmpty ? headParts[0] : '';
    final hl = headParts.skip(1);
    final http.IncomingHttpHeaders headers = {};
    for (final l in hl) {
      final i = l.indexOf(':');
      headers[l.substring(0, i).toLowerCase()] = l.substring(i + 1).trim();
    }
    var text = rest.join('\r\n\r\n');
    if (RegExp(
      'chunked',
      caseSensitive: false,
    ).hasMatch('${headers['transfer-encoding'] ?? ''}')) {
      var out = '';
      while (text.isNotEmpty) {
        final nl = text.indexOf('\r\n');
        final n = int.tryParse(text.substring(0, nl), radix: 16);
        if (n == null || n == 0) break;
        out += text.substring(nl + 2, nl + 2 + n);
        text = text.substring(nl + 2 + n + 2);
      }
      text = out;
    }
    final statusParts = statusLine.split(' ');
    if (!completer.isCompleted) {
      completer.complete((
        status:
            int.tryParse(statusParts.length > 1 ? statusParts[1] : '0') ?? -1,
        headers: headers,
        body: text,
      ));
    }
  });
  return completer.future;
}

final cleanup = <FutureOr<void> Function()>[];

Future<
  ({
    Upstream up,
    Map<String, Object> d,
    ProxyOnly proxy,
    int port,
    List<String> closed,
    PassThrough lifeline,
    String base,
  })
>
setup(
  Object Function(Frame f) decide, {
  int? timeoutMs,
  bool? plaintextHeaderSet,
  String? caPem,
}) async {
  final up = await upstream();
  cleanup.add(() {
    final closed = Completer<void>();
    up.server.close(() => closed.complete());
    return closed.future;
  });
  final d = fakeDecider(['127.0.0.1:${up.port}'], decide);
  final closed = <String>[];
  final lifeline = PassThrough();
  final ProxyOnly proxy = startProxyOnly(
    ProxyOnlyOptions(
      listen: ProxyListenHostPort(host: '127.0.0.1', port: 0),
      decider: _streams(d),
      lifeline: lifeline,
      deciderTimeoutMs: timeoutMs ?? 2000,
      stripResponseHeaders: ['set-cookie', 'set-cookie2'],
      // The credential cases go over plain HTTP with sets explicitly allowed,
      // so they run on every runtime; the TLS-terminated cases are separate.
      plaintextHeaderSet: plaintextHeaderSet ?? true,
      caPem: caPem,
      onClosed: (why) => closed.add(why),
    ),
  );
  cleanup.add(() => proxy.close());
  await proxy.ready;
  final port = (proxy.listener.address() as net.NodeAddress).port;
  return (
    up: up,
    d: d,
    proxy: proxy,
    port: port,
    closed: closed,
    lifeline: lifeline,
    base: 'http://127.0.0.1:${up.port}',
  );
}

final Map<String, Object?> allowWithCredential = {
  'action': 'allow',
  'cred': 'session-token',
  'credential': 'host-secret',
  'removeHeaders': ['x-api-key', 'cookie'],
};

/**
 * Whether this runtime's HTTP server takes a larger maxHeaderSize and
 * answers a head past it through clientError; probed on a loopback server.
 * (Bun 1.3 keeps its own limit.)
 */
Future<bool> probeMaxHeaderSize() async {
  final server = http.createServer({
    'maxHeaderSize': 64 << 10,
  }, (http.IncomingMessage req, http.ServerResponse res) => res.end('ok'));
  final listening = Completer<void>();
  server.listen(0, '127.0.0.1', () => listening.complete());
  await listening.future;
  final port = (server.address() as net.NodeAddress).port;
  final reply = await () {
    final completer = Completer<String>();
    void resolve(String v) {
      if (!completer.isCompleted) completer.complete(v);
    }

    late final net.NodeSocket c;
    c = net.connect(
      port,
      '127.0.0.1',
      () => c.write(
        'GET / HTTP/1.1\r\nHost: x\r\nX-Big: ${'a' * (20 << 10)}\r\nConnection: close\r\n\r\n',
      ),
    );
    var out = '';
    c.on('data', (Object? d) => out += _utf8(d));
    c.on('error', (Object _) => resolve(out));
    c.on('close', () => resolve(out));
    return completer.future;
  }();
  final closed = Completer<void>();
  server.close(() => closed.complete());
  await closed.future;
  return reply.startsWith('HTTP/1.1 200');
}

/** One request inside a TLS-terminated tunnel to the proxy; the status. */
Future<String> viaTunnel(
  int proxyPort,
  String target,
  String Function(String host) raw,
  String ca,
) {
  final completer = Completer<String>();
  void resolve(String v) {
    if (!completer.isCompleted) completer.complete(v);
  }

  late final net.NodeSocket c;
  c = net.connect(
    proxyPort,
    '127.0.0.1',
    () => c.write('CONNECT $target HTTP/1.1\r\nHost: $target\r\n\r\n'),
  );
  var head = '';
  void onData(Object? d) {
    head += _latin1(d);
    if (!head.contains('\r\n\r\n')) return;
    c.off('data', onData);
    if (!head.startsWith('HTTP/1.1 200')) return resolve(head);
    final t = tls.connect({
      'socket': c,
      'ca': ca,
      'servername': target.split(':')[0] == '127.0.0.1'
          ? null
          : target.split(':')[0],
      'checkServerIdentity': (Object? _, Object? __) => null,
      'ALPNProtocols': ['http/1.1'],
    });
    var out = '';
    t.on('secureConnect', () => t.write(raw(target)));
    t.on('data', (Object? x) => out += _utf8(x));
    t.on('error', (Object _) => resolve(out));
    t.on('close', () => resolve(out));
  }

  c.on('data', onData);
  c.on('error', (Object _) => resolve(''));
  return completer.future;
}

/**
 * Whether this runtime's HTTP server answers a request carrying an
 * `Upgrade` field without an upgrade handler; probed on a loopback server.
 * Bun 1.3 leaves it unanswered, and also stalls on the hop-by-hop request
 * below, so those tests need a runtime that passes this probe.
 */
Future<bool> probeServesUpgradeField() async {
  final server = http.createServer((
    http.IncomingMessage req,
    http.ServerResponse res,
  ) {
    req.resume();
    req.on('end', () => res.end('ok'));
  });
  final listening = Completer<void>();
  server.listen(0, '127.0.0.1', () => listening.complete());
  await listening.future;
  final port = (server.address() as net.NodeAddress).port;
  final reply = await () {
    final completer = Completer<String>();
    void resolve(String v) {
      if (!completer.isCompleted) completer.complete(v);
    }

    late final net.NodeSocket c;
    c = net.connect(
      port,
      '127.0.0.1',
      () => c.write(
        'GET / HTTP/1.1\r\nHost: x\r\nUpgrade: h2c\r\nConnection: close\r\n\r\n',
      ),
    );
    var out = '';
    final t = setTimeout(() {
      c.destroy();
      resolve(out);
    }, 1000);
    c.on('data', (Object? d) => out += _utf8(d));
    c.on('close', () {
      clearTimeout(t);
      resolve(out);
    });
    c.on('error', (Object _) => resolve(out));
    return completer.future;
  }();
  server.closeAllConnections();
  final closed = Completer<void>();
  server.close(() => closed.complete());
  await closed.future;
  return reply.startsWith('HTTP/1.1 200');
}

typedef Seen = ({
  String url,
  List<String> rawHeaders,
  List<String> rawTrailers,
  String body,
});

/** An HTTP or HTTPS upstream that records each request's raw header lines, raw trailers and body. */
Future<({List<Seen> seen, int port})> recordingUpstream([
  ({String cert, String key})? tlsOpts,
]) async {
  final seen = <Seen>[];
  void handler(http.IncomingMessage req, http.ServerResponse res) {
    var body = '';
    req.on('data', (Object? c) => body += _utf8(c));
    req.on('end', () {
      seen.add((
        url: req.url ?? '',
        rawHeaders: [...req.rawHeaders],
        rawTrailers: [...req.rawTrailers],
        body: body,
      ));
      res.end('ok');
    });
  }

  final http.NodeHttpServer server = tlsOpts != null
      ? https.createServer({'cert': tlsOpts.cert, 'key': tlsOpts.key}, handler)
      : http.createServer(handler);
  final listening = Completer<void>();
  server.listen(0, '127.0.0.1', () => listening.complete());
  await listening.future;
  cleanup.add(() {
    final closed = Completer<void>();
    server.close(() => closed.complete());
    return closed.future;
  });
  return (seen: seen, port: (server.address() as net.NodeAddress).port);
}

/** A CA, a TLS upstream that records requests, and a proxy-only proxy in front of it. */
Future<
  ({
    ({List<Seen> seen, int port}) up,
    Map<String, Object> d,
    Future<String> Function(String requestTarget, [String? host]) send,
    String target,
    int port,
    String ca,
  })
>
tlsSetup(Object Function(Frame f) decide) async {
  final ca = generateCa();
  final leaf = mintLeafCert(
    createMitmCA(caCertPem: ca.certPem, caKeyPem: ca.keyPem),
    '127.0.0.1',
  );
  final leafOnly = RegExp(
    r'-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----\r?\n?',
  ).firstMatch(leaf.certPem)![0]!;
  final up = await recordingUpstream((cert: leafOnly, key: leaf.keyPem));
  final d = fakeDecider(['127.0.0.1:${up.port}'], decide);
  final proxy = startProxyOnly(
    ProxyOnlyOptions(
      listen: ProxyListenHostPort(host: '127.0.0.1', port: 0),
      decider: _streams(d),
      caPem: ca.keyPem + ca.certPem,
      upstreamCA: ca.certPem,
      deciderTimeoutMs: 1000,
    ),
  );
  cleanup.add(() => proxy.close());
  await proxy.ready;
  final port = (proxy.listener.address() as net.NodeAddress).port;
  final target = '127.0.0.1:${up.port}';
  /** One GET in a tunnel, with Host (default: the target); the raw response. */
  Future<String> send(String requestTarget, [String? host]) {
    host ??= target;
    final completer = Completer<String>();
    void resolve(String v) {
      if (!completer.isCompleted) completer.complete(v);
    }

    late final net.NodeSocket c;
    c = net.connect(
      port,
      '127.0.0.1',
      () => c.write('CONNECT $target HTTP/1.1\r\nHost: $target\r\n\r\n'),
    );
    var head = '';
    void onData(Object? x) {
      head += _latin1(x);
      if (!head.contains('\r\n\r\n')) return;
      c.off('data', onData);
      final t = tls.connect({
        'socket': c,
        'ca': ca.certPem,
        'checkServerIdentity': (Object? _, Object? __) => null,
        'ALPNProtocols': ['http/1.1'],
      });
      var out = '';
      t.on(
        'secureConnect',
        () => t.write(
          'GET $requestTarget HTTP/1.1\r\nHost: $host\r\nConnection: close\r\n\r\n',
        ),
      );
      t.on('data', (Object? y) => out += _utf8(y));
      t.on('close', () => resolve(out));
      t.on('error', (Object _) => resolve(out));
    }

    c.on('data', onData);
    c.on('error', (Object _) => resolve(''));
    return completer.future;
  }

  return (up: up, d: d, send: send, target: target, port: port, ca: ca.certPem);
}

int statusOf(String raw) {
  final parts = raw.split(' ');
  return int.tryParse(parts.length > 1 ? parts[1] : '0') ?? -1;
}

String? denyReasonOf(String raw) => RegExp(
  r'\r\nx-deny-reason: ([^\r]*)\r\n',
  caseSensitive: false,
).firstMatch(raw)?[1];

/**
 * Whether this runtime's HTTP client sends a request path exactly as given
 * (Node and Bun 1.4 do; Bun 1.3 resolves dot segments itself), probed
 * against a loopback server.
 */
Future<bool> probeClientSendsPathAsGiven() async {
  var got = '';
  final server = http.createServer((
    http.IncomingMessage req,
    http.ServerResponse res,
  ) {
    got = req.url ?? '';
    res.end();
  });
  final listening = Completer<void>();
  server.listen(0, '127.0.0.1', () => listening.complete());
  await listening.future;
  // Dart: node:http is imported at the top; upstream imports it here.
  final done = Completer<void>();
  final r = http.request(
    {
      'host': '127.0.0.1',
      'port': (server.address() as net.NodeAddress).port,
      'path': '/a/%2e%2e/b',
    },
    (http.IncomingMessage res) {
      res.resume();
      res.on('end', () => done.complete());
    },
  );
  r.on('error', (Object _) {
    if (!done.isCompleted) done.complete();
  });
  r.end();
  await done.future;
  final closed = Completer<void>();
  server.close(() => closed.complete());
  await closed.future;
  return got == '/a/%2e%2e/b';
}

/**
 * A 128 MiB TLS-terminated response to a client that reads nothing for 2 s
 * and then reads it all: how much the upstream managed to write during the
 * stall (the rest waits on backpressure), and what the client got.
 */
Future<({int upstreamWroteDuringStall, int read, int size})>
stalledClientResponse() async {
  final size = 128 << 20;
  final ca = generateCa();
  final mitmCA = createMitmCA(caCertPem: ca.certPem, caKeyPem: ca.keyPem);
  final leaf = mintLeafCert(mitmCA, '127.0.0.1');
  final leafOnly = RegExp(
    r'-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----\r?\n?',
  ).firstMatch(leaf.certPem)![0]!;
  var written = 0;
  final up = https.createServer({'cert': leafOnly, 'key': leaf.keyPem}, (
    http.IncomingMessage req,
    http.ServerResponse res,
  ) {
    res.writeHead(200, {'content-length': size});
    final chunk = Uint8List(64 << 10)..fillRange(0, 64 << 10, 0x61);
    void pump() {
      while (written < size) {
        written += chunk.length;
        if (!res.write(chunk)) {
          res.once('drain', pump);
          return;
        }
      }
      res.end();
    }

    pump();
  });
  final listening = Completer<void>();
  up.listen(0, '127.0.0.1', () => listening.complete());
  await listening.future;
  cleanup.add(() {
    final closed = Completer<void>();
    up.close(() => closed.complete());
    return closed.future;
  });
  final target = '127.0.0.1:${(up.address() as net.NodeAddress).port}';
  final d = fakeDecider([target], (_) => {'action': 'allow'});
  final p = startProxyOnly(
    ProxyOnlyOptions(
      listen: ProxyListenHostPort(host: '127.0.0.1', port: 0),
      decider: _streams(d),
      caPem: ca.keyPem + ca.certPem,
      upstreamCA: ca.certPem,
      deciderTimeoutMs: 1000,
    ),
  );
  cleanup.add(() => p.close());
  await p.ready;
  final port = (p.listener.address() as net.NodeAddress).port;
  var duringStall = 0;
  final read = await () {
    final completer = Completer<int>();
    void resolve(int v) {
      if (!completer.isCompleted) completer.complete(v);
    }

    late final net.NodeSocket c;
    c = net.connect(
      port,
      '127.0.0.1',
      () => c.write('CONNECT $target HTTP/1.1\r\nHost: $target\r\n\r\n'),
    );
    c.once('data', () {
      final t = tls.connect({
        'socket': c,
        'ca': ca.certPem,
        'checkServerIdentity': (Object? _, Object? __) => null,
      });
      t.on('secureConnect', () {
        t.write(
          'GET /big HTTP/1.1\r\nHost: $target\r\nConnection: close\r\n\r\n',
        );
        t.pause();
        setTimeout(() {
          duringStall = written;
          t.resume();
        }, 2000);
      });
      var n = 0;
      t.on('data', (Object? d) => n += (d as List<int>).length);
      t.on('close', () => resolve(n));
      t.on('error', (Object _) => resolve(n));
    });
    c.on('error', (Object _) => resolve(0));
    return completer.future;
  }();
  return (upstreamWroteDuringStall: duringStall, read: read, size: size);
}

/** One GET in a tunnel with this SNI: the raw response and the certificate's CN. */
Future<({String raw, String? cn})> sendWithSni(
  ({int port, String target, String ca}) s,
  String servername,
) {
  final completer = Completer<({String raw, String? cn})>();
  void resolve(({String raw, String? cn}) v) {
    if (!completer.isCompleted) completer.complete(v);
  }

  String? cn;
  late final net.NodeSocket c;
  c = net.connect(
    s.port,
    '127.0.0.1',
    () => c.write('CONNECT ${s.target} HTTP/1.1\r\nHost: ${s.target}\r\n\r\n'),
  );
  c.on('error', (Object _) => resolve((raw: '', cn: cn)));
  c.once('data', () {
    final t = tls.connect({
      'socket': c,
      'ca': s.ca,
      'servername': servername,
      'checkServerIdentity': (Object? host, Object? cert) {
        cn = (cert as tls.PeerCertificate).subject.CN;
        return null;
      },
    });
    var out = '';
    t.on(
      'secureConnect',
      () => t.write(
        'GET /sni HTTP/1.1\r\nHost: ${s.target}\r\nConnection: close\r\n\r\n',
      ),
    );
    t.on('data', (Object? d) => out += _utf8(d));
    t.on('close', () => resolve((raw: out, cn: cn)));
    t.on('error', (Object _) => resolve((raw: out, cn: cn)));
  });
  return completer.future;
}

Future<void> main() async {
  tearDown(() async {
    while (cleanup.isNotEmpty) {
      await cleanup.removeLast()();
    }
  });

  group('proxy-only mode with an external decider', () {
    test(
      'allow: the decider sets the credential and strips the client auth in every spelling',
      () async {
        final s = await setup((_) => allowWithCredential);
        final r = await viaProxy(s.port, '${s.base}/ok', {
          'headers': {
            'Authorization': 'Bearer guest',
            'X_Api_Key': 'guest',
            'x.api.key': 'guest',
            'cookie': 'a=b',
          },
        });
        expect(r.status, 200);
        expect(r.body, 'upstream ok');
        expect(s.up.got, hasLength(1));
        final h = s.up.got[0].headers;
        expect(h['authorization'], 'Bearer host-secret');
        expect(
          h.keys.where(
            (k) => k.replaceAll(RegExp(r'[_.]'), '-') == 'x-api-key',
          ),
          isEmpty,
        );
        expect(h['cookie'], isNull);
        // Response: upstream cookies never reach the client, in either spelling.
        expect(r.headers['set-cookie'], isNull);
        expect(r.headers['set_cookie2'], isNull);
        expect(r.headers['x-kept'], 'yes');
        // The decider saw the client's request line and headers.
        expect(
          _seen(s.d)[0],
          allOf(
            containsPair('t', 'req'),
            containsPair('id', 1),
            containsPair('method', 'GET'),
            containsPair('host', '127.0.0.1'),
            containsPair('port', s.up.port),
            containsPair('path', '/ok'),
          ),
        );
      },
    );

    test(
      'plain HTTP: an allow that sets headers is refused and nothing is dialled',
      () async {
        final s = await setup(
          (_) => allowWithCredential,
          plaintextHeaderSet: false,
        );
        final r = await viaProxy(s.port, '${s.base}/ok', {
          'headers': {'authorization': 'Bearer guest'},
        });
        expect(r.status, 403);
        expect(r.headers['x-deny-reason'], 'plaintext_header_set');
        expect(r.body, contains('plain-HTTP'));
        expect(_seen(s.d), hasLength(1));
        expect(s.up.got, hasLength(0));
        final open = await () {
          final completer = Completer<int>();
          s.up.server.getConnections(
            (Object? _, int n) => completer.complete(n),
          );
          return completer.future;
        }();
        expect(open, 0);
      },
    );

    test(
      'plain HTTP: the same request allowed without sets is forwarded',
      () async {
        final s = await setup(
          (_) => {'action': 'allow'},
          plaintextHeaderSet: false,
        );
        final r = await viaProxy(s.port, '${s.base}/ok', {
          'headers': {'authorization': 'Bearer guest'},
        });
        expect(r.status, 200);
        expect(s.up.got, hasLength(1));
        expect(s.up.got[0].headers['authorization'], 'Bearer guest');
      },
    );

    test(
      'plain HTTP: with plaintext header sets on, the set header reaches the upstream',
      () async {
        final s = await setup(
          (_) => allowWithCredential,
          plaintextHeaderSet: true,
        );
        final r = await viaProxy(s.port, '${s.base}/ok', {
          'headers': {'authorization': 'Bearer guest'},
        });
        expect(r.status, 200);
        expect(s.up.got, hasLength(1));
        expect(s.up.got[0].headers['authorization'], 'Bearer host-secret');
      },
    );

    test(
      'deny: status and reason reach the client and nothing is dialled',
      () async {
        final s = await setup(
          (_) => {'action': 'deny', 'status': 451, 'reason': 'path refused'},
        );
        final r = await viaProxy(s.port, '${s.base}/deny', {
          'headers': {'authorization': 'Bearer guest'},
        });
        expect(r.status, 451);
        expect(r.body, contains('path refused'));
        expect(s.up.got, hasLength(0));
      },
    );

    test(
      'need_body: the decider reads the JSON body before deciding',
      () async {
        final s = await setup((f) {
          if (f['t'] == 'req') return {'action': 'need_body', 'max': 1024};
          final body = utf8.decode(base64Decode(f['data'].toString()));
          return (jsonDecode(body) as Map)['tool'] == 'forbidden'
              ? {'action': 'deny', 'status': 403, 'reason': 'body refused'}
              : allowWithCredential;
        });
        final bad = await viaProxy(s.port, '${s.base}/v1/x', {
          'method': 'POST',
          'headers': {'content-type': 'application/json'},
          'body': '{"tool":"forbidden"}',
        });
        expect(bad.status, 403);
        expect(s.up.got, hasLength(0));
        final good = await viaProxy(s.port, '${s.base}/v1/x', {
          'method': 'POST',
          'headers': {'content-type': 'application/json'},
          'body': '{"tool":"ok"}',
        });
        expect(good.status, 200);
        expect(s.up.got[0].body, '{"tool":"ok"}');
        expect(s.up.got[0].headers['authorization'], 'Bearer host-secret');
      },
    );

    test(
      'a second need_body is a protocol violation: denied, and the link dies',
      () async {
        final s = await setup((_) => {'action': 'need_body', 'max': 1024});
        final r = await viaProxy(s.port, '${s.base}/x', {
          'method': 'POST',
          'body': '{}',
        });
        expect(r.status, 503);
        expect(s.up.got, hasLength(0));
        await s.proxy.close();
        expect(s.closed[0], 'decider: a second need_body');
      },
    );

    test(
      'need_body: a body past max is sent cut at max, flagged cut',
      () async {
        final s = await setup(
          (f) => f['t'] == 'req'
              ? {'action': 'need_body', 'max': 4}
              : allowWithCredential,
        );
        final r = await viaProxy(s.port, '${s.base}/v1/x', {
          'method': 'POST',
          'body': 'abcdefgh',
        });
        expect(r.status, 200);
        final body = _seen(s.d).firstWhere((f) => f['t'] == 'body');
        expect(utf8.decode(base64Decode(body['data'].toString())), 'abcd');
        expect(body['cut'], true);
        // The upstream still gets the whole body.
        expect(s.up.got[0].body, 'abcdefgh');
      },
    );

    test(
      'the req frame: structured target, Host header apart, query without "?", headers as lower-case lists',
      () async {
        final s = await setup((_) => {'action': 'deny', 'status': 403});
        await viaProxy(s.port, '${s.base}/a/b?x=1&y=2', {
          'headers': {'X-Two': 'one', 'x-two': 'two', 'Accept': 'text/plain'},
        });
        final f = _seen(s.d)[0];
        expect(
          f,
          allOf(
            containsPair('t', 'req'),
            containsPair('id', 1),
            containsPair('method', 'GET'),
            containsPair('host', '127.0.0.1'),
            containsPair('port', s.up.port),
          ),
        );
        expect(
          f,
          allOf(
            containsPair('hostHeader', '127.0.0.1:${s.up.port}'),
            containsPair('path', '/a/b'),
            containsPair('query', 'x=1&y=2'),
          ),
        );
        // The frame carries no field beyond the documented ones: a decider may
        // reject a frame with a key it does not know.
        expect(f.containsKey('scheme'), false);
        final h = (f['headers'] as Map).cast<String, List<Object?>>();
        expect(h['x-two'], ['one', 'two']);
        expect(h['accept'], ['text/plain']);
        expect(h.containsKey('host'), false);
        expect(f.containsKey('url') || f.containsKey('sni'), false);
      },
    );

    test(
      'a header the decider could not be sent is refused here without asking',
      () async {
        final s = await setup((_) => allowWithCredential);
        final r = await viaProxy(s.port, '${s.base}/ok', {
          'headers': {'X-Big': 'a' * (70 * 1024)},
        });
        // 431 from the proxy, or the runtime's parser refusing first (400, or a closed connection)
        expect([0, 400, 431], contains(r.status));
        expect(_seen(s.d), hasLength(0));
        expect(s.up.got, hasLength(0));
      },
    );

    test(
      'decider timeout denies 503; a late verdict is dropped, not fatal',
      () async {
        var first = true;
        final s = await setup((_) {
          if (first) {
            first = false;
            return 'hang';
          }
          return allowWithCredential;
        }, timeoutMs: 300);
        final r = await viaProxy(s.port, '${s.base}/hang');
        expect(r.status, 503);
        expect(s.up.got, hasLength(0));
        // The allow for the request that timed out arrives now. Frames are read
        // in order, so the next request's answer shows it was read and dropped.
        _streams(s.d).input.write(
          frameOf(
            jsonEncode({
              't': 'verdict',
              'id': _seen(s.d)[0]['id'],
              'action': 'allow',
            }),
          ),
        );
        final r2 = await viaProxy(s.port, '${s.base}/ok');
        expect(r2.status, 200);
        expect(s.up.got.map((g) => g.url), ['/ok']);
        expect(s.closed, []);
      },
    );

    test('a malformed verdict frame denies and shuts the proxy down', () async {
      final s = await setup((_) => 'garbage');
      final r = await viaProxy(s.port, '${s.base}/garbage');
      expect(r.status, 503);
      expect(s.up.got, hasLength(0));
      await s.proxy.close();
      expect(s.closed[0], contains('decider'));
    });

    test('an unknown action or an extra field denies', () async {
      final s = await setup(
        (_) => {
          'action': 'allow',
          'removeHeaders': ['x-api-key'],
          'extra': true,
        },
      );
      final r = await viaProxy(s.port, '${s.base}/ok');
      expect(r.status, 503);
      expect(s.up.got, hasLength(0));
    });

    test(
      'decider crash (stream end) denies in-flight requests and stops the proxy',
      () async {
        final s = await setup((_) => 'end');
        final r = await viaProxy(s.port, '${s.base}/crash');
        expect(r.status, 503);
        expect(s.up.got, hasLength(0));
        await s.proxy.close();
        expect(s.closed, ['decider: decider closed the stream']);
      },
    );

    test(
      'hosts outside the decider allowlist are refused before the decider is asked',
      () async {
        final s = await setup((_) => allowWithCredential);
        final r = await viaProxy(s.port, 'http://127.0.0.2:9/x');
        expect(r.status, 403);
        expect(_seen(s.d), hasLength(0));
      },
    );

    test(
      'with no CA, a CONNECT to an allowed host is refused (no opaque tunnel past the decider)',
      () async {
        final s = await setup((_) => allowWithCredential);
        final reply = await () {
          final completer = Completer<String>();
          late final net.NodeSocket c;
          c = net.connect(s.port, '127.0.0.1', () {
            c.write(
              'CONNECT 127.0.0.1:${s.up.port} HTTP/1.1\r\nHost: 127.0.0.1:${s.up.port}\r\n\r\n',
            );
          });
          var out = '';
          c.on('data', (Object? d) => out += _utf8(d));
          c.on('close', () => completer.complete(out));
          c.on('error', (Object _) => completer.complete(out));
          return completer.future;
        }();
        expect(reply, startsWith('HTTP/1.1 403'));
        expect(_seen(s.d), hasLength(0));
      },
    );

    test('lifeline end shuts the proxy down', () async {
      final s = await setup((_) => allowWithCredential);
      s.lifeline.end();
      await Future<void>.delayed(const Duration(milliseconds: 50));
      await s.proxy.close();
      expect(s.closed, ['lifeline closed']);
      expect(s.proxy.listener.listening, false);
    });

    test(
      'a handed fd the runtime cannot listen on fails the start (never a silent listener)',
      () async {
        final d = fakeDecider([], (_) => allowWithCredential);
        final closed = <String>[];
        final p = startProxyOnly(
          ProxyOnlyOptions(
            listen: ProxyListenFd(fd: 987),
            decider: _streams(d),
            onClosed: (why) => closed.add(why),
          ),
        );
        // eslint-disable-next-line @typescript-eslint/await-thenable -- bun:test types .rejects.toThrow() as void; the await is required at runtime
        await expectLater(p.ready, throwsA(anything));
        await p.close();
        expect(closed[0], startsWith('start failed'));
      },
    );

    test(
      'a listen that fails ends the start (the proxy never runs without its listener)',
      () async {
        final up = await upstream();
        cleanup.add(() {
          final closed = Completer<void>();
          up.server.close(() => closed.complete());
          return closed.future;
        });
        final d = fakeDecider([], (_) => allowWithCredential);
        final closed = <String>[];
        final p = startProxyOnly(
          ProxyOnlyOptions(
            listen: ProxyListenHostPort(host: '127.0.0.1', port: up.port),
            decider: _streams(d),
            onClosed: (why) => closed.add(why),
          ),
        );
        // eslint-disable-next-line @typescript-eslint/await-thenable -- bun:test types .rejects.toThrow() as void; the await is required at runtime
        await expectLater(p.ready, throwsA(anything));
        await p.close();
        expect(closed[0], startsWith('start failed'));
      },
    );
    test(
      'a Host header that does not name the request target is refused 421 before the decider is asked',
      () async {
        final s = await setup((_) => allowWithCredential);
        final r = await viaProxy(s.port, '${s.base}/ok', {
          'host': 'other.example.test',
        });
        expect(r.status, 421);
        expect(_seen(s.d), hasLength(0));
        expect(s.up.got, hasLength(0));
        final wrongPort = await viaProxy(s.port, '${s.base}/ok', {
          'host': '127.0.0.1:1',
        });
        expect(wrongPort.status, 421);
        // HTTP/1.1 without Host: 400, from the runtime's HTTP parser or from
        // the proxy (Bun's parser for an emitted connection passes it on); a
        // closed connection under Bun 1.3. Either way nothing is decided or
        // dialled.
        final missing = await viaProxy(s.port, '${s.base}/ok', {'host': null});
        expect([0, 400], contains(missing.status));
        expect(s.up.got, hasLength(0));
        expect(_seen(s.d), hasLength(0));
      },
    );

    testWithTls(
      'the hello frame is byte for byte the pinned one, whatever descriptors are given',
      () async {
        // Dart: generateCa is imported at the top; upstream imports it here.
        final want = File(
          'test/fixtures/srt-proxy-hello.json',
        ).readAsStringSync();
        final ca = generateCa();
        final toProxy = PassThrough();
        final fromProxy = PassThrough();
        final first = Completer<Uint8List>();
        fromProxy.once('data', (Object? c) => first.complete(c as Uint8List));
        // As `srt-proxy --listen-fd 4 --lifeline-fd 3 --decider-fd 5 --ca-fd 6`:
        // a listen fd, a lifeline, the decider's streams and the CA PEM.
        final p = startProxyOnly(
          ProxyOnlyOptions(
            listen: ProxyListenFd(fd: 987654),
            lifeline: PassThrough(),
            decider: (input: toProxy, output: fromProxy),
            caPem: ca.keyPem + ca.certPem,
          ),
        );
        final frame = await first.future;
        expect(ByteData.sublistView(frame).getUint32(0), frame.length - 4);
        expect(utf8.decode(frame.sublist(4)), want);
        await p.close();
        // With nothing but the decider, the same bytes.
        final bare = fakeDecider([], (_) => {'action': 'deny', 'status': 403});
        final seenHello = Completer<Uint8List>();
        _streams(bare).output.once(
          'data',
          (Object? c) => seenHello.complete(c as Uint8List),
        );
        final q = startProxyOnly(
          ProxyOnlyOptions(
            listen: ProxyListenHostPort(host: '127.0.0.1', port: 0),
            decider: _streams(bare),
          ),
        );
        expect(utf8.decode((await seenHello.future).sublist(4)), want);
        await q.close();
      },
    );

    test(
      'a path past 8 KiB is answered 400 without asking, and the link stays up',
      () async {
        final s = await setup((_) => allowWithCredential);
        final r = await viaProxy(s.port, '${s.base}/${'a' * (8 * 1024)}');
        expect(r.status, 400);
        expect(_seen(s.d), hasLength(0));
        final ok = await viaProxy(s.port, '${s.base}/ok');
        expect(ok.status, 200);
        expect(s.closed, []);
      },
    );
  });

  final TAKES_MAX_HEADER_SIZE = await probeMaxHeaderSize();

  group(
    "requests past the decider's limits are answered 400 by the proxy, not by the parser",
    () {
      String big(String host) =>
          'GET /ok HTTP/1.1\r\nHost: $host\r\nX-Big: ${'a' * (65 << 10)}\r\nConnection: close\r\n\r\n';
      String longQuery(String host) =>
          'GET /ok?q=${'a' * (1100 << 10)} HTTP/1.1\r\nHost: $host\r\nConnection: close\r\n\r\n';
      String pastTheHead(String host) =>
          'GET /ok HTTP/1.1\r\nHost: $host\r\nX-Big: ${'a' * (REQUEST_HEAD_LIMIT + 1)}\r\nConnection: close\r\n\r\n';

      test(
        'plain HTTP: a 65 KiB header, a 1.1 MiB query, and a head past the parser limit',
        () async {
          final s = await setup((_) => {'action': 'allow'});
          final target = '127.0.0.1:${s.up.port}';
          for (final raw in [big, longQuery, pastTheHead]) {
            final reply = await () {
              final completer = Completer<String>();
              void resolve(String v) {
                if (!completer.isCompleted) completer.complete(v);
              }

              late final net.NodeSocket c;
              c = net.connect(
                s.port,
                '127.0.0.1',
                () => c.write(
                  raw(target).replaceFirst('GET /ok', 'GET http://$target/ok'),
                ),
              );
              var out = '';
              c.on('data', (Object? d) => out += _utf8(d));
              c.on('error', (Object _) => resolve(out));
              c.on('close', () => resolve(out));
              return completer.future;
            }();
            expect(int.tryParse(reply.split(' ')[1]), 400);
            // Past the head limit the runtime's parser refuses it, and the proxy
            // still says it did.
            expect(
              reply.toLowerCase(),
              contains('\r\nx-deny-reason: bad_request\r\n'),
            );
          }
          expect(_seen(s.d), hasLength(0));
          expect(s.up.got, hasLength(0));
          expect((await viaProxy(s.port, '${s.base}/ok')).status, 200);
        },
        skip: !TAKES_MAX_HEADER_SIZE ? 'maxHeaderSize not taken' : null,
        timeout: Timeout(Duration(milliseconds: 20000)),
      );

      test(
        'TLS-terminated: the same three',
        () async {
          final ca = generateCa();
          final s = await setup(
            (_) => {'action': 'allow'},
            caPem: ca.keyPem + ca.certPem,
          );
          final target = '127.0.0.1:${s.up.port}';
          for (final raw in [big, longQuery, pastTheHead]) {
            final reply = await viaTunnel(s.port, target, raw, ca.certPem);
            expect(int.tryParse(reply.split(' ')[1]), 400);
            expect(
              reply.toLowerCase(),
              contains('\r\nx-deny-reason: bad_request\r\n'),
            );
          }
          expect(_seen(s.d), hasLength(0));
          expect(s.up.got, hasLength(0));
          expect(s.closed, []);
        },
        skip: !TAKES_MAX_HEADER_SIZE ? 'maxHeaderSize not taken' : null,
        timeout: Timeout(Duration(milliseconds: 20000)),
      );
    },
  );

  group('a CONNECT the allowlist refuses', () {
    test('proxy-only mode marks it X-Deny-Reason: host_not_allowed', () async {
      final s = await setup((_) => {'action': 'allow'});
      final reply = await () {
        final completer = Completer<String>();
        late final net.NodeSocket c;
        c = net.connect(
          s.port,
          '127.0.0.1',
          () => c.write(
            'CONNECT denied.invalid:443 HTTP/1.1\r\nHost: denied.invalid:443\r\n\r\n',
          ),
        );
        var out = '';
        c.on('data', (Object? d) => out += _utf8(d));
        c.on('close', () {
          if (!completer.isCompleted) completer.complete(out);
        });
        c.on('error', (Object _) {
          if (!completer.isCompleted) completer.complete(out);
        });
        return completer.future;
      }();
      expect(reply, startsWith('HTTP/1.1 403'));
      expect(
        reply.toLowerCase(),
        contains('\r\nx-deny-reason: host_not_allowed\r\n'),
      );
      expect(reply.toLowerCase(), isNot(contains('x-proxy-error')));
      expect(_seen(s.d), hasLength(0));
      // An absolute-form request to such a host gets the same mark.
      final plain = await viaProxy(s.port, 'http://denied.invalid/x');
      expect(plain.status, 403);
      expect(plain.headers['x-deny-reason'], 'host_not_allowed');
    });

    test(
      'the ordinary proxy keeps X-Proxy-Error: blocked-by-allowlist',
      () async {
        final proxy = createHttpProxyServer(_HttpOptions(allow: false));
        final listening = Completer<void>();
        proxy.listen(0, '127.0.0.1', () => listening.complete());
        await listening.future;
        cleanup.add(() {
          final closed = Completer<void>();
          proxy.close(() => closed.complete());
          return closed.future;
        });
        final port = (proxy.address() as net.NodeAddress).port;
        final reply = await () {
          final completer = Completer<String>();
          late final net.NodeSocket c;
          c = net.connect(
            port,
            '127.0.0.1',
            () => c.write(
              'CONNECT denied.invalid:443 HTTP/1.1\r\nHost: denied.invalid:443\r\n\r\n',
            ),
          );
          var out = '';
          c.on('data', (Object? d) => out += _utf8(d));
          c.on('close', () {
            if (!completer.isCompleted) completer.complete(out);
          });
          c.on('error', (Object _) {
            if (!completer.isCompleted) completer.complete(out);
          });
          return completer.future;
        }();
        expect(reply, startsWith('HTTP/1.1 403'));
        expect(reply, contains('X-Proxy-Error: blocked-by-allowlist'));
        expect(reply.toLowerCase(), isNot(contains('x-deny-reason')));
      },
    );
  });

  final SERVES_UPGRADE_FIELD = await probeServesUpgradeField();

  group('hop-by-hop headers and request trailers never reach the upstream', () {
    // Every RFC 9110 7.6.1 hop-by-hop field, a field the Connection header
    // names, separator-folded spellings of two of them, and a chunked body
    // with a trailer.
    String hopRequest(String target, String path, String host) => [
      'POST $target HTTP/1.1',
      'Host: $host',
      'Connection: keep-alive, X-Conn-Named',
      'X-Conn-Named: named-in-connection',
      'Keep-Alive: timeout=5',
      'Proxy-Connection: keep-alive',
      'TE: trailers',
      'Trailer: X-Trail',
      'Upgrade: h2c',
      'Proxy-Authorization: Basic Z3Vlc3Q6Z3Vlc3Q=',
      'Proxy-Authenticate: Basic',
      'Proxy_Authorization: Basic Z3Vlc3Q6Z3Vlc3Q=',
      'Keep.Alive: timeout=5',
      'X-Kept: yes',
      'Transfer-Encoding: chunked',
      '',
      '5',
      'hello',
      '0',
      'X-Trail: trailer-value',
      '',
      '',
    ].join('\r\n').replaceFirst('POST $target', 'POST $path');

    final HOP = {
      'connection',
      'keep-alive',
      'proxy-connection',
      'te',
      'trailer',
      'transfer-encoding',
      'upgrade',
      'proxy-authorization',
      'proxy-authenticate',
      'x-conn-named',
    }.map(foldHeaderName).toSet();
    void expectClean(Seen? s) {
      expect(s, isNotNull);
      final names = [
        for (var i = 0; i < s!.rawHeaders.length; i++)
          if (i % 2 == 0) s.rawHeaders[i].toLowerCase(),
      ];
      // The proxy's own framing and connection handling may appear; nothing
      // the client sent among these names may.
      final values = [
        for (var i = 0; i < s.rawHeaders.length; i++)
          if (i % 2 == 1) s.rawHeaders[i],
      ];
      for (final v in [
        'named-in-connection',
        'timeout=5',
        'trailers',
        'X-Trail',
        'h2c',
        'Basic Z3Vlc3Q6Z3Vlc3Q=',
        'Basic',
      ]) {
        expect(values, isNot(contains(v)));
      }
      for (final n in names) {
        if (n == 'connection' ||
            n == 'transfer-encoding' ||
            n == 'content-length') {
          continue;
        }
        expect(HOP.contains(foldHeaderName(n)), false);
      }
      expect(names, contains('x-kept'));
      expect(s.rawTrailers, []);
      expect(s.body, 'hello');
    }

    test('plain HTTP', () async {
      final up = await recordingUpstream();
      final d = fakeDecider([
        '127.0.0.1:${up.port}',
      ], (_) => {'action': 'allow'});
      final proxy = startProxyOnly(
        ProxyOnlyOptions(
          listen: ProxyListenHostPort(host: '127.0.0.1', port: 0),
          decider: _streams(d),
        ),
      );
      cleanup.add(() => proxy.close());
      await proxy.ready;
      final port = (proxy.listener.address() as net.NodeAddress).port;
      final target = '127.0.0.1:${up.port}';
      final status = await () {
        final completer = Completer<String>();
        late final net.NodeSocket c;
        c = net.connect(
          port,
          '127.0.0.1',
          () => c.write(
            hopRequest('http://$target/hop', 'http://$target/hop', target),
          ),
        );
        var out = '';
        c.on('data', (Object? x) {
          out += _utf8(x);
          if (out.contains('ok')) c.end();
        });
        c.on('close', () {
          if (!completer.isCompleted) completer.complete(out.split('\r\n')[0]);
        });
        c.on('error', (Object _) {
          if (!completer.isCompleted) completer.complete(out.split('\r\n')[0]);
        });
        return completer.future;
      }();
      expect(status, 'HTTP/1.1 200 OK');
      expectClean(up.seen.isEmpty ? null : up.seen[0]);
    }, skip: !SERVES_UPGRADE_FIELD ? 'Upgrade field not answered' : null);

    test(
      'TLS-terminated',
      () async {
        final ca = generateCa();
        final leaf = mintLeafCert(
          createMitmCA(caCertPem: ca.certPem, caKeyPem: ca.keyPem),
          '127.0.0.1',
        );
        final leafOnly = RegExp(
          r'-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----\r?\n?',
        ).firstMatch(leaf.certPem)![0]!;
        final up = await recordingUpstream((cert: leafOnly, key: leaf.keyPem));
        final d = fakeDecider([
          '127.0.0.1:${up.port}',
        ], (_) => {'action': 'allow'});
        final proxy = startProxyOnly(
          ProxyOnlyOptions(
            listen: ProxyListenHostPort(host: '127.0.0.1', port: 0),
            decider: _streams(d),
            caPem: ca.keyPem + ca.certPem,
            upstreamCA: ca.certPem,
          ),
        );
        cleanup.add(() => proxy.close());
        await proxy.ready;
        final port = (proxy.listener.address() as net.NodeAddress).port;
        final target = '127.0.0.1:${up.port}';
        final status = await () {
          final completer = Completer<String>();
          void resolve(String v) {
            if (!completer.isCompleted) completer.complete(v);
          }

          late final net.NodeSocket c;
          c = net.connect(
            port,
            '127.0.0.1',
            () => c.write('CONNECT $target HTTP/1.1\r\nHost: $target\r\n\r\n'),
          );
          var head = '';
          void onData(Object? x) {
            head += _latin1(x);
            if (!head.contains('\r\n\r\n')) return;
            c.off('data', onData);
            final t = tls.connect({
              'socket': c,
              'ca': ca.certPem,
              'checkServerIdentity': (Object? _, Object? __) => null,
              'ALPNProtocols': ['http/1.1'],
            });
            var out = '';
            t.on(
              'secureConnect',
              () => t.write(hopRequest('/hop', '/hop', target)),
            );
            t.on('data', (Object? y) {
              out += _utf8(y);
              if (out.contains('ok')) t.end();
            });
            t.on('close', () => resolve(out.split('\r\n')[0]));
            t.on('error', (Object _) => resolve(out.split('\r\n')[0]));
          }

          c.on('data', onData);
          return completer.future;
        }();
        expect(status, 'HTTP/1.1 200 OK');
        expectClean(up.seen.isEmpty ? null : up.seen[0]);
      },
      skip: !SERVES_UPGRADE_FIELD ? 'Upgrade field not answered' : null,
      timeout: Timeout(Duration(milliseconds: 15000)),
    );
  });

  group('stripHopByHop', () {
    final h = <String, Object?>{
      'connection': 'close, X_Named',
      'x-named': '1',
      'keep-alive': '1',
      'proxy_authorization': 'b',
      'keep.alive': '1',
      'x-kept': 'yes',
    };
    test(
      'by default only the exact spellings (the ordinary proxy is unchanged)',
      () {
        expect(stripHopByHop(h), {
          'x-named': '1',
          'proxy_authorization': 'b',
          'keep.alive': '1',
          'x-kept': 'yes',
        });
      },
    );
    test(
      'folded: every spelling of - _ and ., for the fields and for the names Connection lists',
      () {
        expect(stripHopByHop(h, folded: true), {'x-kept': 'yes'});
      },
    );
  });

  group('requestTargetAsSpelled', () {
    for (final (raw, want) in [
      ('/v1/messages', '/v1/messages'),
      ('/v1/%2E/messages', '/v1/%2E/messages'),
      ('/v1/.%2e/messages', '/v1/.%2e/messages'),
      ('/v1/%2e%2e/messages', '/v1/%2e%2e/messages'),
      ('/v1//./messages', '/v1//./messages'),
      ('/v1/models?q=%2e', '/v1/models?q=%2e'),
      ('/a\\b', '/a\\b'),
    ]) {
      test('origin form $raw goes as spelled', () {
        expect(requestTargetAsSpelled(raw), want);
      });
    }
    for (final raw in [
      'https://other.example/v1/messages',
      'other.example:443',
      '*',
      '//v1/messages',
      '/\\v1/messages',
      '/v1/messages#frag',
      '/v1/mes sages',
      '/v1/\u0001',
      '',
    ]) {
      test('$raw is refused', () {
        expect(requestTargetAsSpelled(raw), isNull);
      });
    }
    test('absolute: the path and query of an http(s) URI, as spelled', () {
      String? abs(String raw) => requestTargetAsSpelled(raw, absolute: true);
      expect(abs('http://h.test/v1/%2E/x?y=1'), '/v1/%2E/x?y=1');
      expect(abs('http://h.test'), '/');
      expect(abs('http://h.test?x'), '/?x');
      expect(abs('ftp://h.test/x'), isNull);
      expect(abs('http://h.test//x'), isNull);
    });
  });

  final CLIENT_SENDS_PATH_AS_GIVEN = await probeClientSendsPathAsGiven();
  final SPELLINGS = [
    '/v1/%2E/messages',
    '/v1/.%2e/messages',
    '/v1/%2e%2e/messages',
    '/v1//./messages',
  ];
  final Object? emitSkip = canServeEmittedConnections
      ? null
      : 'emitted connections unavailable';

  Future<String> rawExchange(
    int port,
    String request, {
    bool endOnHead = false,
  }) {
    final completer = Completer<String>();
    late final net.NodeSocket c;
    c = net.connect(port, '127.0.0.1', () => c.write(request));
    var out = '';
    void done(Object? _) {
      if (!completer.isCompleted) completer.complete(out);
    }

    c.on('data', (Object? d) {
      out += _latin1(d);
      if (endOnHead && out.contains('\r\n\r\n')) c.end();
    });
    c.on('close', done);
    c.on('error', done);
    return completer.future;
  }

  group(
    'proxy-only mode: the request-target reaches the decider and the upstream as spelled',
    () {
      test(
        'TLS-terminated: the decider sees each spelling, and an allowed one goes upstream unchanged',
        () async {
          final s = await tlsSetup((_) => {'action': 'allow'});
          for (final p in SPELLINGS) {
            expect(statusOf(await s.send(p)), 200);
            expect(
              _seen(s.d).last,
              allOf(containsPair('t', 'req'), containsPair('path', p)),
            );
            expect(s.up.seen.last.url, p);
          }
        },
        skip: CLIENT_SENDS_PATH_AS_GIVEN ? null : 'client rewrites paths',
        timeout: Timeout(Duration(seconds: 20)),
      );

      test(
        'TLS-terminated: a decider that matches paths exactly refuses them, and nothing is dialled',
        () async {
          final s = await tlsSetup(
            (f) => f['path'] == '/v1/messages'
                ? {'action': 'allow'}
                : {'action': 'deny', 'status': 403, 'reason': 'not a route'},
          );
          for (final p in SPELLINGS) {
            final raw = await s.send(p);
            expect(statusOf(raw), 403);
            expect(denyReasonOf(raw), 'decider');
          }
          expect(s.up.seen, hasLength(0));
          expect(statusOf(await s.send('/v1/messages')), 200);
        },
        skip: emitSkip,
        timeout: Timeout(Duration(seconds: 20)),
      );

      test(
        r'TLS-terminated: //, /\ and absolute form are answered 400 without asking',
        () async {
          final s = await tlsSetup((_) => {'action': 'allow'});
          for (final p in [
            '//v1/messages',
            '/\\v1/messages',
            'https://${s.target}/v1/messages',
          ]) {
            final raw = await s.send(p);
            // A runtime's parser may refuse one of these itself (no answer).
            if (raw != '') {
              expect(statusOf(raw), 400);
              expect(denyReasonOf(raw), 'bad_request');
            }
          }
          expect(_seen(s.d), hasLength(0));
          expect(s.up.seen, hasLength(0));
        },
      );

      test(
        "plain HTTP: the absolute URI's path goes to the decider and upstream as spelled",
        () async {
          final up = await recordingUpstream();
          final d = fakeDecider([
            '127.0.0.1:${up.port}',
          ], (_) => {'action': 'allow'});
          final proxy = startProxyOnly(
            ProxyOnlyOptions(
              listen: ProxyListenHostPort(host: '127.0.0.1', port: 0),
              decider: _streams(d),
            ),
          );
          cleanup.add(() => proxy.close());
          await proxy.ready;
          final port = (proxy.listener.address() as net.NodeAddress).port;
          for (final p in SPELLINGS) {
            final r = await viaProxy(port, 'http://127.0.0.1:${up.port}$p');
            expect(r.status, 200);
            expect(
              _seen(d).last,
              allOf(containsPair('t', 'req'), containsPair('path', p)),
            );
            expect(up.seen.last.url, p);
          }
        },
        skip: CLIENT_SENDS_PATH_AS_GIVEN ? null : 'client rewrites paths',
      );
    },
  );

  group('proxy-only mode marks every refusal of its own with X-Deny-Reason', () {
    test(
      'a decider deny: X-Deny-Reason: decider, and no X-Proxy-Error',
      () async {
        final s = await tlsSetup(
          (_) => {'action': 'deny', 'status': 451, 'reason': 'no'},
        );
        final raw = await s.send('/v1/messages');
        expect(statusOf(raw), 451);
        expect(denyReasonOf(raw), 'decider');
        expect(raw.toLowerCase(), isNot(contains('x-proxy-error')));
      },
      skip: emitSkip,
      timeout: Timeout(Duration(seconds: 20)),
    );

    test(
      "the proxy's own: misdirected (421), bad_request (400 past the limits), decider_unavailable (503)",
      () async {
        var hang = false;
        final s = await tlsSetup((_) => hang ? 'hang' : {'action': 'allow'});
        final misdirected = await s.send('/v1/messages', 'other.example.test');
        expect(statusOf(misdirected), 421);
        expect(denyReasonOf(misdirected), 'misdirected');
        final past = await s.send('/${'a' * (9 << 10)}');
        expect(statusOf(past), 400);
        expect(denyReasonOf(past), 'bad_request');
        hang = true;
        final late = await s.send('/v1/messages');
        expect(statusOf(late), 503);
        expect(denyReasonOf(late), 'decider_unavailable');
        for (final raw in [misdirected, past, late]) {
          expect(raw.toLowerCase(), isNot(contains('x-proxy-error')));
        }
      },
      skip: emitSkip,
      timeout: Timeout(Duration(seconds: 20)),
    );

    test('the plain path: 421 misdirected', () async {
      final s = await setup((_) => {'action': 'allow'});
      final r = await viaProxy(s.port, '${s.base}/ok', {
        'host': 'other.example.test',
      });
      expect(r.status, 421);
      expect(r.headers['x-deny-reason'], 'misdirected');
      expect(r.headers['x-proxy-error'], isNull);
    });
  });

  group('proxy-only mode takes destination hosts in plain ASCII only', () {
    /** A CONNECT to target; the raw reply (the 200 or the refusal). */
    Future<String> connectTo(int port, String target) => rawExchange(
      port,
      'CONNECT $target HTTP/1.1\r\nHost: $target\r\n\r\n',
      endOnHead: true,
    );

    for (final (label, target) in [
      ('fullwidth', 'ａllowed.test:443'),
      ('percent-encoded dot', 'allowed%2etest:443'),
      ('double dot', 'allowed.test..:443'),
      ('leading dot', '.allowed.test:443'),
      ('empty label', 'allowed..test:443'),
      ('non-ASCII letter', 'allowéd.test:443'),
    ]) {
      test(
        'CONNECT with a $label is answered 400 bad_request, unasked',
        () async {
          final s = await setup((_) => {'action': 'allow'});
          final reply = await connectTo(s.port, target);
          expect(reply, startsWith('HTTP/1.1 400'));
          expect(
            reply.toLowerCase(),
            contains('\r\nx-deny-reason: bad_request\r\n'),
          );
          expect(_seen(s.d), hasLength(0));
        },
      );
    }

    testWithTls(
      'a single trailing dot and ASCII case are still canonicalized, and allowed',
      () async {
        final ca = generateCa();
        final d = fakeDecider([
          'allowed.test:443',
        ], (_) => {'action': 'deny', 'status': 403});
        final proxy = startProxyOnly(
          ProxyOnlyOptions(
            listen: ProxyListenHostPort(host: '127.0.0.1', port: 0),
            decider: _streams(d),
            caPem: ca.keyPem + ca.certPem,
          ),
        );
        cleanup.add(() => proxy.close());
        await proxy.ready;
        final port = (proxy.listener.address() as net.NodeAddress).port;
        for (final target in [
          'allowed.test:443',
          'allowed.test.:443',
          'ALLOWED.Test:443',
        ]) {
          expect(await connectTo(port, target), startsWith('HTTP/1.1 200'));
        }
        expect(
          await connectTo(port, 'other.test:443'),
          startsWith('HTTP/1.1 403'),
        );
      },
    );

    test('plain HTTP: the same rule for an absolute URI', () async {
      final s = await setup((_) => {'action': 'allow'});
      for (final url in [
        'http://ａllowed.test/x',
        'http://allowed%2etest/x',
        'http://allowed.test../x',
      ]) {
        final r = await viaProxy(s.port, url, {'host': 'allowed.test'});
        // A runtime's parser may refuse the raw bytes itself (no answer).
        if (r.status != 0) {
          expect(r.status, 400);
          expect(r.headers['x-deny-reason'], 'bad_request');
        }
      }
      expect(_seen(s.d), hasLength(0));
    });
  });

  group('a request the decider answers late', () {
    // The body gate must not start a body flowing before it is read: a
    // bodyless request would end before it is forwarded, and hang.
    test(
      'a GET and a POST are forwarded whole after a 300 ms verdict',
      () async {
        final s = await setup(
          (_) => Future<Frame>.delayed(
            const Duration(milliseconds: 300),
            () => {'action': 'allow'},
          ),
        );
        final get = await viaProxy(s.port, '${s.base}/late');
        expect(get.status, 200);
        final post = await viaProxy(s.port, '${s.base}/late', {
          'method': 'POST',
          'body': 'x' * 100000,
        });
        expect(post.status, 200);
        expect(s.up.got.map((g) => g.body.length), [0, 100000]);
      },
    );
  });

  group('a request with many header lines reaches the decider whole', () {
    // The HTTP parser hands such a head over in batches of 31 lines; Bun's
    // server for an emitted connection used to keep only the last batch.
    test(
      '70 header lines: the target, Host and every line are asked about, and forwarded',
      () async {
        final s = await setup((_) => {'action': 'allow'});
        final headers = {for (var i = 0; i < 70; i++) 'X-Line-$i': 'v$i'};
        final r = await viaProxy(s.port, '${s.base}/many?q=1', {
          'headers': headers,
        });
        expect(r.status, 200);
        final f = _seen(s.d)[0];
        expect(
          f,
          allOf(
            containsPair('hostHeader', '127.0.0.1:${s.up.port}'),
            containsPair('path', '/many'),
            containsPair('query', 'q=1'),
          ),
        );
        final h = (f['headers'] as Map).cast<String, List<Object?>>();
        for (var i = 0; i < 70; i++) {
          expect(h['x-line-$i'], ['v$i']);
        }
        expect(s.up.got[0].headers['x-line-0'], 'v0');
      },
    );
  });

  group("proxy-only mode keeps to the decider's header limit exactly", () {
    Map<String, String> pads(int n) => {
      for (var i = 0; i < n; i++) 'X-Pad-$i': 'v',
    };

    test(
      '190 header values (Host apart) are asked about; 191 are answered 400 bad_request, unasked',
      () async {
        final s = await setup((_) => {'action': 'allow'});
        // viaProxy adds Connection: close, the 190th value.
        final at = await viaProxy(s.port, '${s.base}/ok', {
          'headers': pads(189),
        });
        expect(at.status, 200);
        expect(_seen(s.d), hasLength(1));
        final past = await viaProxy(s.port, '${s.base}/ok', {
          'headers': pads(190),
        });
        expect(past.status, 400);
        expect(past.headers['x-deny-reason'], 'bad_request');
        expect(_seen(s.d), hasLength(1));
        expect(s.up.got, hasLength(1));
        // The link is up: the next request is asked as usual.
        expect((await viaProxy(s.port, '${s.base}/ok')).status, 200);
        expect(s.closed, []);
      },
    );
  });

  /// Upload [size] bytes in 64 KiB chunks on [w] (a socket); [sent] reports progress.
  void pumpUpload(net.NodeSocket w, int size, void Function(int) sent) {
    final chunk = Uint8List(64 << 10);
    var n = 0;
    void pump() {
      while (n < size) {
        n += chunk.length;
        sent(n);
        if (!w.write(chunk)) {
          w.once('drain', pump);
          return;
        }
      }
    }

    pump();
  }

  /// A plain HTTP upstream that reads 1 MiB, stalls [stallMs], then reads the rest.
  Future<http.NodeHttpServer> stallingUpstream(
    int stallMs, {
    bool tlsOn = false,
    Map<String, Object?>? tlsOpts,
  }) async {
    void handler(http.IncomingMessage req, http.ServerResponse res) {
      var n = 0;
      var stalled = false;
      req.on('data', (Object? c) {
        n += (c as List<int>).length;
        if (!stalled && n >= 1 << 20) {
          stalled = true;
          req.pause();
          setTimeout(() => req.resume(), stallMs);
        }
      });
      req.on('end', () => res.end('got $n'));
    }

    final up = tlsOpts != null
        ? https.createServer(tlsOpts, handler)
        : http.createServer(handler);
    final listening = Completer<void>();
    up.listen(0, '127.0.0.1', () => listening.complete());
    await listening.future;
    cleanup.add(() {
      final closed = Completer<void>();
      up.close(() => closed.complete());
      return closed.future;
    });
    return up;
  }

  group(
    'an upload to a slow upstream is not buffered whole (maxBufferedRequestBody)',
    () {
      test(
        'a connection handed in with emit("connection"): the proxy reads a few MiB ahead, not the whole body',
        () async {
          final size = 64 << 20;
          // The upstream reads 1 MiB, then nothing for 1.5 s, then the rest.
          final up = await stallingUpstream(1500);
          final upPort = (up.address() as net.NodeAddress).port;
          final proxy = createHttpProxyServer(
            _HttpOptions(maxBufferedRequestBody: 4 << 20),
          );
          // As proxy-only mode serves a handed fd: a net.Server passes each
          // connection to the HTTP server.
          net.NodeSocket? accepted;
          final front = net.createServer((net.NodeSocket sock) {
            accepted = sock;
            markHandedInConnection(sock);
            proxy.emit('connection', sock);
          });
          final listening = Completer<void>();
          front.listen(0, '127.0.0.1', () => listening.complete());
          await listening.future;
          cleanup.add(() {
            final closed = Completer<void>();
            front.close(() => closed.complete());
            return closed.future;
          });
          final port = (front.address() as net.NodeAddress).port;
          var readDuringStall = 0;
          final completer = Completer<String>();
          late final net.NodeSocket c;
          c = net.connect(port, '127.0.0.1', () {
            c.write(
              'POST http://127.0.0.1:$upPort/up HTTP/1.1\r\nHost: 127.0.0.1:$upPort\r\nContent-Length: $size\r\nConnection: close\r\n\r\n',
            );
            pumpUpload(c, size, (_) {});
            setTimeout(() => readDuringStall = accepted?.bytesRead ?? 0, 1200);
          });
          var out = '';
          c.on('data', (Object? d) => out += _utf8(d));
          c.on('close', (Object? _) => completer.complete(out));
          c.on('error', (Object _) {
            if (!completer.isCompleted) completer.complete(out);
          });
          expect(await completer.future, contains('got $size'));
          // The cap, the kernel's and the streams' own buffers: well under the body.
          expect(readDuringStall, lessThan(24 << 20));
        },
        skip: emitSkip,
        timeout: Timeout(Duration(seconds: 30)),
      );
    },
  );

  group(
    'an upload in a TLS-terminated tunnel to a slow upstream is not buffered whole',
    () {
      // Bun's native HTTP listener keeps reading a CONNECT socket that is
      // paused, so on a loopback listen too the proxy must accept through a
      // net.Server.
      // need_body: the decider is shown the first KiB; the rest streams with
      // the same backpressure.
      // The last column: the sizes of the body frames the decider must be sent.
      final deciders = <(String, Object Function(Frame), List<int>)>[
        ('allow', (_) => {'action': 'allow'}, <int>[]),
        (
          'need_body',
          (f) => f['t'] == 'req'
              ? {'action': 'need_body', 'max': 1024}
              : {'action': 'allow'},
          [1024],
        ),
      ];
      for (final (name, decide, shown) in deciders) {
        test(
          'a loopback listen, $name: the client stalls with the upstream, then the whole body arrives',
          () async {
            final size = 192 << 20;
            final ca = generateCa();
            final leaf = mintLeafCert(
              createMitmCA(caCertPem: ca.certPem, caKeyPem: ca.keyPem),
              '127.0.0.1',
            );
            final leafOnly = RegExp(
              r'-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----\r?\n?',
            ).firstMatch(leaf.certPem)![0]!;
            // Reads 1 MiB, then nothing for 3 s, then the rest.
            final up = await stallingUpstream(
              3000,
              tlsOpts: {'cert': leafOnly, 'key': leaf.keyPem},
            );
            final target =
                '127.0.0.1:${(up.address() as net.NodeAddress).port}';
            final d = fakeDecider([target], decide);
            final proxy = startProxyOnly(
              ProxyOnlyOptions(
                listen: ProxyListenHostPort(host: '127.0.0.1', port: 0),
                decider: _streams(d),
                caPem: ca.keyPem + ca.certPem,
                upstreamCA: ca.certPem,
                deciderTimeoutMs: 1000,
              ),
            );
            cleanup.add(() => proxy.close());
            await proxy.ready;
            final port = (proxy.listener.address() as net.NodeAddress).port;
            var sentDuringStall = 0;
            final completer = Completer<String>();
            void resolve(String v) {
              if (!completer.isCompleted) completer.complete(v);
            }

            late final net.NodeSocket c;
            c = net.connect(
              port,
              '127.0.0.1',
              () =>
                  c.write('CONNECT $target HTTP/1.1\r\nHost: $target\r\n\r\n'),
            );
            var head = '';
            void onData(Object? x) {
              head += _latin1(x);
              if (!head.contains('\r\n\r\n')) return;
              c.off('data', onData);
              final t = tls.connect({
                'socket': c,
                'ca': ca.certPem,
                'checkServerIdentity': (Object? _, Object? __) => null,
                'ALPNProtocols': ['http/1.1'],
              });
              var sent = 0;
              t.on('secureConnect', () {
                t.write(
                  'POST /up HTTP/1.1\r\nHost: $target\r\nContent-Length: $size\r\nConnection: close\r\n\r\n',
                );
                pumpUpload(t, size, (n) => sent = n);
                setTimeout(() => sentDuringStall = sent, 2500);
              });
              var out = '';
              t.on('data', (Object? y) => out += _utf8(y));
              t.on('close', (Object? _) => resolve(out));
              t.on('error', (Object _) => resolve(out));
            }

            c.on('data', onData);
            c.on('error', (Object _) => resolve(''));
            expect(await completer.future, contains('got $size'));
            final bodies = _seen(d).where((f) => f['t'] == 'body').toList();
            expect(
              bodies.map((f) => base64Decode(f['data'].toString()).length),
              shown,
            );
            // More body followed what the decider was shown.
            expect(bodies.every((f) => f['cut'] == true), true);
            // What the kernel's socket buffers on three loopback hops (up to some
            // 30 MiB here) and the streams hold: well under the body.
            expect(sentDuringStall, lessThan(64 << 20));
          },
          skip: emitSkip,
          timeout: Timeout(Duration(seconds: 30)),
        );
      }
    },
  );

  group('TLS termination opens nothing another process could reach', () {
    test(
      'a tunnel is terminated with no listener: no listen() from CONNECT to the end of the response',
      () async {
        final s = await tlsSetup((_) => {'action': 'allow'});
        final listened = <Object?>[];
        // Every server class a listener could come from (they need not share
        // a prototype chain).
        // Dart: HTTP and HTTPS servers are NodeServers, so the one
        // NodeServer.listenSpy seam covers all three prototypes.
        net.NodeServer.listenSpy = (first) => listened.add(first);
        cleanup.add(() => net.NodeServer.listenSpy = null);
        final raw = await s.send('/ok');
        expect(raw, startsWith('HTTP/1.1 200'));
        expect(s.up.seen.map((g) => g.url), ['/ok']);
        expect(listened, []);
      },
      skip: emitSkip,
    );
  });

  group('the terminated tunnels are capped', () {
    testWithTls(
      'past maxTerminatedTunnels, a CONNECT is answered 503 and marked too_many_tunnels',
      () async {
        final ca = generateCa();
        final mitmCA = createMitmCA(caCertPem: ca.certPem, caKeyPem: ca.keyPem);
        final proxy = createHttpProxyServer(
          _HttpOptions(
            mitmCA: mitmCA,
            maxTerminatedTunnels: 2,
            denyHeader: 'X-Deny-Reason',
          ),
        );
        final listening = Completer<void>();
        proxy.listen(0, '127.0.0.1', () => listening.complete());
        await listening.future;
        cleanup.add(() {
          final closed = Completer<void>();
          proxy.close(() => closed.complete());
          return closed.future;
        });
        final port = (proxy.address() as net.NodeAddress).port;
        Future<({String head, net.NodeSocket sock})> open() {
          final completer = Completer<({String head, net.NodeSocket sock})>();
          late final net.NodeSocket c;
          c = net.connect(
            port,
            '127.0.0.1',
            () => c.write(
              'CONNECT a.test:443 HTTP/1.1\r\nHost: a.test:443\r\n\r\n',
            ),
          );
          c.on('error', (Object _) {});
          var head = '';
          c.on('data', (Object? d) {
            head += _latin1(d);
            if (head.contains('\r\n\r\n') && !completer.isCompleted) {
              completer.complete((head: head, sock: c));
            }
          });
          return completer.future;
        }

        final first = await open();
        final second = await open();
        cleanup.add(() {
          first.sock.destroy();
          second.sock.destroy();
        });
        expect(first.head, startsWith('HTTP/1.1 200'));
        expect(second.head, startsWith('HTTP/1.1 200'));
        final third = await open();
        third.sock.destroy();
        expect(third.head, startsWith('HTTP/1.1 503'));
        expect(third.head, contains('X-Deny-Reason: too_many_tunnels'));
        // A slot frees when a tunnel closes.
        first.sock.destroy();
        await Future<void>.delayed(const Duration(milliseconds: 100));
        final fourth = await open();
        fourth.sock.destroy();
        expect(fourth.head, startsWith('HTTP/1.1 200'));
      },
    );
  });

  group('a TLS-terminated response waits for a stalled client', () {
    test(
      'proxy-only mode: the upstream is held back, and the client then gets every byte',
      () async {
        final r = await stalledClientResponse();
        expect(r.read, greaterThan(r.size));
        expect(r.read - r.size, lessThan(1024));
        // Kernel buffers and the queue caps: far below the body.
        expect(r.upstreamWroteDuringStall, lessThan(48 << 20));
      },
      skip: emitSkip,
      timeout: Timeout(Duration(seconds: 60)),
    );
  });

  group('a client that resets its tunnel only ends that tunnel', () {
    test(
      'a reset mid-handshake and a reset mid-request; the next tunnel is served',
      () async {
        final s = await tlsSetup((_) => {'action': 'allow'});
        for (final at in ['handshake', 'request']) {
          final done = Completer<void>();
          late final net.NodeSocket c;
          c = net.connect(
            s.port,
            '127.0.0.1',
            () => c.write(
              'CONNECT ${s.target} HTTP/1.1\r\nHost: ${s.target}\r\n\r\n',
            ),
          );
          c.on('error', (Object _) {});
          c.once('data', () {
            final t = tls.connect({
              'socket': c,
              'ca': s.ca,
              'checkServerIdentity': (Object? _, Object? __) => null,
            });
            t.on('error', (Object _) {});
            if (at == 'handshake') {
              Timer.run(() {
                c.resetAndDestroy();
                done.complete();
              });
              return;
            }
            t.on('secureConnect', () {
              t.write('GET /half HTTP/1.1\r\nHost: ${s.target}\r\n');
              setTimeout(() {
                c.resetAndDestroy();
                done.complete();
              }, 50);
            });
          });
          await done.future;
        }
        await Future<void>.delayed(const Duration(milliseconds: 200));
        expect(await s.send('/ok'), startsWith('HTTP/1.1 200'));
      },
      skip: emitSkip,
    );
  });

  group('the server name a tunnel is asked for', () {
    test(
      'one that cannot be read is a mismatch: 421, nothing asked or dialled',
      () async {
        final s = await tlsSetup((_) => {'action': 'allow'});
        final r = await sendWithSni((
          port: s.port,
          target: s.target,
          ca: s.ca,
        ), 'x_front.example');
        expect(statusOf(r.raw), 421);
        expect(denyReasonOf(r.raw), 'misdirected');
        expect(_seen(s.d), hasLength(0));
        expect(s.up.seen, hasLength(0));
      },
      skip: emitSkip,
    );

    test(
      "with requireHostMatch the certificate is the target's whatever name is asked for",
      () async {
        final s = await tlsSetup((_) => {'action': 'allow'});
        final r = await sendWithSni((
          port: s.port,
          target: s.target,
          ca: s.ca,
        ), 'other.example.test');
        expect(r.cn, '127.0.0.1');
        expect(statusOf(r.raw), 421);
        expect(s.up.seen, hasLength(0));
      },
      skip: emitSkip,
    );
  });

  group("a proxy's connections share one budget for what they hold", () {
    test(
      'two uploads to stalled upstreams together hold about the budget, then both arrive whole',
      () async {
        final size = 128 << 20;
        final up = await stallingUpstream(3000);
        final upPort = (up.address() as net.NodeAddress).port;
        // Each upload alone may hold far more than both together.
        final proxy = createHttpProxyServer(
          _HttpOptions(
            maxBufferedRequestBody: 512 << 20,
            maxBufferedBytes: 8 << 20,
          ),
        );
        final front = net.createServer((net.NodeSocket sock) {
          markHandedInConnection(sock);
          proxy.emit('connection', sock);
        });
        final listening = Completer<void>();
        front.listen(0, '127.0.0.1', () => listening.complete());
        await listening.future;
        cleanup.add(() {
          final closed = Completer<void>();
          front.close(() => closed.complete());
          return closed.future;
        });
        final port = (front.address() as net.NodeAddress).port;
        ({int Function() sentAt, Future<String> reply}) upload() {
          var sent = 0;
          final completer = Completer<String>();
          late final net.NodeSocket c;
          c = net.connect(port, '127.0.0.1', () {
            c.write(
              'POST http://127.0.0.1:$upPort/up HTTP/1.1\r\nHost: 127.0.0.1:$upPort\r\nContent-Length: $size\r\nConnection: close\r\n\r\n',
            );
            pumpUpload(c, size, (n) => sent = n);
          });
          var out = '';
          c.on('data', (Object? d) => out += _utf8(d));
          c.on('close', (Object? _) {
            if (!completer.isCompleted) completer.complete(out);
          });
          c.on('error', (Object _) {
            if (!completer.isCompleted) completer.complete(out);
          });
          return (sentAt: () => sent, reply: completer.future);
        }

        final a = upload();
        final b = upload();
        await Future<void>.delayed(const Duration(milliseconds: 2500));
        final heldDuringStall = a.sentAt() + b.sentAt();
        expect(await a.reply, contains('got $size'));
        expect(await b.reply, contains('got $size'));
        // The budget, the kernel's buffers on four loopback hops and the
        // streams': no more than the decider's queue may hold before it counts
        // as stalled, and far below the 256 MiB the two would hold without it.
        expect(heldDuringStall, lessThan(MAX_QUEUED_BYTES));
      },
      skip: emitSkip,
      timeout: Timeout(Duration(seconds: 60)),
    );
  });
}
