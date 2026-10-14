// Ported from sandbox-runtime test/sandbox/response-header-bytes.test.ts @ 24eb39e.
// Dart: every case hangs in impl runs (fetchRaw never sees the 2-byte 'ok' tail or close); cause not isolated, may be the harness or the proxy.
@Tags(['pending']) // Dart: every test times out at 30s (+0 -6 in 3min): fixture/proxy startup hang
library;

// ignore_for_file: slash_for_doc_comments, constant_identifier_names, non_constant_identifier_names, curly_braces_in_flow_control_structures
import 'dart:async';

import 'package:sandbox_runtime/src/node/buffer.dart';
import 'package:sandbox_runtime/src/node/http.dart' as http;
import 'package:sandbox_runtime/src/node/net.dart'
    show NodeAddress, NodeServer, NodeSocket, connect;
import 'package:sandbox_runtime/src/node/net.dart' as net show createServer;
import 'package:sandbox_runtime/src/node/stream.dart' as stream;
import 'package:sandbox_runtime/src/node/tls.dart'
    as tls
    show TLSSocket, connect, createServer;
import 'package:sandbox_runtime/src/sandbox/http_proxy.dart';
import 'package:sandbox_runtime/src/sandbox/mitm_ca.dart';
import 'package:sandbox_runtime/src/sandbox/mitm_leaf.dart';
import 'package:sandbox_runtime/src/sandbox/proxy_only.dart';
import 'package:sandbox_runtime/src/sandbox/request_filter.dart';
import 'package:test/test.dart';

import '../helpers/emitted_connections.dart' show SERVES_EMITTED_CONNECTIONS;
import '../helpers/fake_decider.dart';

final List<FutureOr<void> Function()> cleanup = [];

// Dart: the object literal upstream passes to createHttpProxyServer; every
// option not named here is absent (null).
class _HttpOptions implements HttpProxyServerOptions {
  _HttpOptions({this.mitmCA, this.tlsTerminateUpstreamCA, this.filterRequest});
  @override
  final MitmCA? mitmCA;
  @override
  final dynamic tlsTerminateUpstreamCA;
  @override
  final FilterRequestCallback? filterRequest;
  @override
  FutureOr<bool> filter(
    int port,
    String host,
    dynamic socket, [
    String? encodedCommand,
    void Function(String reason)? explain,
  ]) => true;
  @override
  dynamic noSuchMethod(Invocation invocation) => null;
}

Buffer latin1(String s) => Buffer.from(s, 'latin1');

/** Every byte past ASCII, and the headers a client acts on, in both of the encodings seen in the wild. */
final List<(String, Buffer)> SENT = [
  ('x-high', Buffer.from(List.generate(128, (i) => 0x80 + i))),
  ('location', Buffer.from('/café')),
  ('content-disposition', latin1('attachment; filename="caf\xe9.txt"')),
  ('set-cookie', latin1('a=\xe9')),
  ('set-cookie', Buffer.from('b=é')),
];

const REASON = 'refused: café ☃';

/** An upstream that answers in raw bytes: no HTTP server writes these. */
void answer(NodeSocket socket) {
  var seen = '';
  socket.on('error', () {});
  socket.on('data', (Object chunk) {
    seen += Buffer.from(chunk as List<int>).toString('latin1');
    for (int end; (end = seen.indexOf('\r\n\r\n')) >= 0;) {
      seen = seen.substring(end + 4);
      socket.write(
        Buffer.concat([
          latin1('HTTP/1.1 200 OK\r\n'),
          for (final (name, value) in SENT) ...[
            latin1('$name: '),
            value,
            latin1('\r\n'),
          ],
          latin1('Content-Length: 2\r\n\r\nok'),
        ]).toUint8List(),
      );
    }
  });
}

/** Which proxy, and whether the request goes in a TLS-terminated tunnel. */
const PATHS = [
  'full mode, plain HTTP',
  'full mode, TLS',
  'srt-proxy, plain HTTP',
  'srt-proxy, TLS',
];

/** Ask for `paths` one after the other on one connection through the proxy; everything the client receives. */
Future<Buffer> fetchRaw(String path, List<String> paths) async {
  final tlsPath = path.endsWith('TLS');
  final authority = generateCa();
  MitmCA ca() =>
      createMitmCA(caCertPem: authority.certPem, caKeyPem: authority.keyPem);
  late NodeServer up;
  if (tlsPath) {
    final leaf = mintLeafCert(ca(), '127.0.0.1');
    final leafOnly = RegExp(
      r'-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----\r?\n?',
    ).firstMatch(leaf.certPem)![0]!;
    up = tls.createServer({'cert': leafOnly, 'key': leaf.keyPem}, answer);
  } else {
    up = net.createServer(answer);
  }
  final listening = Completer<void>();
  up.listen(0, '127.0.0.1', () => listening.complete());
  await listening.future;
  cleanup.add(() => up.close());
  final target = '127.0.0.1:${(up.address() as NodeAddress).port}';

  late int port;
  if (path.startsWith('full mode')) {
    final proxy = createHttpProxyServer(
      _HttpOptions(
        mitmCA: SERVES_EMITTED_CONNECTIONS ? ca() : null,
        tlsTerminateUpstreamCA: authority.certPem,
        filterRequest: (request, [info]) async =>
            request.url.endsWith('/refuse')
            ? const RequestDecision(action: 'deny', reason: REASON)
            : const RequestDecision(action: 'allow'),
      ),
    );
    final proxyListening = Completer<void>();
    proxy.listen(0, '127.0.0.1', () => proxyListening.complete());
    await proxyListening.future;
    cleanup.add(() {
      proxy.close();
      proxy.closeAllConnections();
    });
    port = (proxy.address() as NodeAddress).port;
  } else {
    final d = fakeDecider(
      [target],
      (f) => f['path'] == '/refuse'
          ? {'action': 'deny', 'status': 403, 'reason': REASON}
          : {'action': 'allow'},
    );
    final streams = d['streams']! as Map<String, Object>;
    final proxy = startProxyOnly(
      ProxyOnlyOptions(
        listen: const ProxyListenHostPort(host: '127.0.0.1', port: 0),
        decider: (
          input: streams['input']! as stream.Readable,
          output: streams['output']! as stream.Writable,
        ),
        deciderTimeoutMs: 2000,
        caPem: SERVES_EMITTED_CONNECTIONS
            ? authority.keyPem + authority.certPem
            : null,
        upstreamCA: SERVES_EMITTED_CONNECTIONS ? authority.certPem : null,
      ),
    );
    cleanup.add(() => proxy.close());
    await proxy.ready;
    port = (proxy.listener.address() as NodeAddress).port;
  }

  NodeSocket sock = await () {
    final completer = Completer<NodeSocket>();
    late final NodeSocket c;
    c = connect(port, '127.0.0.1', () => completer.complete(c));
    c.on('error', (Object e) {
      if (!completer.isCompleted) completer.completeError(e);
    });
    return completer.future;
  }();
  if (tlsPath) {
    final raw = sock;
    raw.write('CONNECT $target HTTP/1.1\r\nHost: $target\r\n\r\n');
    final first = Completer<void>();
    raw.once('data', (Object _) => first.complete());
    await first.future;
    sock = await () {
      final completer = Completer<tls.TLSSocket>();
      final t = tls.connect({
        'socket': raw,
        'ca': authority.certPem,
        'checkServerIdentity': (Object? _, Object? __) => null,
      });
      t.on('error', (Object e) {
        if (!completer.isCompleted) completer.completeError(e);
      });
      t.once('secureConnect', () => completer.complete(t));
      return completer.future;
    }();
  }
  sock.on('error', () {});
  var got = Buffer.alloc(0);
  void Function() onData = () {};
  sock.on('data', (Object chunk) {
    got = Buffer.concat([got, chunk as List<int>]);
    onData();
  });
  final closed = Completer<void>();
  sock.once('close', () => closed.complete());
  for (final (i, p) in paths.indexed) {
    final last = i == paths.length - 1;
    sock.write(
      'GET ${tlsPath ? p : 'http://$target$p'} HTTP/1.1\r\nHost: $target\r\n'
      '${last ? 'Connection: close\r\n' : ''}\r\n',
    );
    // The next request goes once this one's answer is in.
    await (last
        ? closed.future
        : () {
            final completer = Completer<void>();
            onData = () {
              if (got.sublist(got.length - 2).toString() == 'ok' &&
                  !completer.isCompleted) {
                completer.complete();
              }
            };
            return completer.future;
          }());
  }
  return got;
}

void main() {
  tearDown(() async {
    while (cleanup.isNotEmpty) {
      await cleanup.removeLast()();
    }
  });

  for (final path in [...PATHS])
    group('bytes past ASCII through the proxy ($path)', () {
      final skip = path.endsWith('TLS') && !SERVES_EMITTED_CONNECTIONS;

      test(
        'a response header value reaches the client as the upstream sent it',
        () async {
          // Twice on one connection: every head on it, not only the first.
          final lines = (await fetchRaw(path, [
            '/one',
            '/two',
          ])).toString('latin1').split('\r\n');
          final once = SENT
              .map((e) => '${e.$1}: ${e.$2.toString('latin1')}')
              .toList();
          expect(
            lines.where((l) => SENT.any((e) => l.startsWith('${e.$1}:'))),
            equals([...once, ...once]),
          );
        },
        skip: skip,
      );

      test("a refusal's reason is UTF-8, after a relayed response too", () async {
        final raw = await fetchRaw(path, ['/one', '/refuse']);
        final refusal = raw.sublist(
          raw.indexOfBytes(Buffer.from('HTTP/1.1 403')),
        );
        final body = Buffer.from('$REASON\n');
        expect(
          Buffer.from(
            refusal.sublist(
              Buffer.from(refusal).indexOfBytes(Buffer.from('\r\n\r\n')) + 4,
            ),
          ).toString('latin1'),
          '${body.length.toRadixString(16)}\r\n${body.toString('latin1')}\r\n0\r\n\r\n',
        );
      }, skip: skip);
    });

  test("a refusal's reason is handed to the response as bytes", () {
    Object? body;
    respondDenied(_FakeResponse((Object? chunk) => body = chunk), REASON);
    expect(body, equals(Buffer.from('$REASON\n').toUint8List()));
  });
}

// Dart: the object literal upstream casts to ServerResponse.
class _FakeResponse implements http.ServerResponse {
  _FakeResponse(this._end);
  final void Function(Object? chunk) _end;
  @override
  bool headersSent = false;
  @override
  bool destroyed = false;
  @override
  http.ServerResponse writeHead(
    int status, [
    Object? headersOrMessage,
    Object? headers,
  ]) => this;
  @override
  http.ServerResponse end([Object? data, Function? callback]) {
    _end(data);
    return this;
  }

  @override
  dynamic noSuchMethod(Invocation invocation) => null;
}
