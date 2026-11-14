// Ported from sandbox-runtime test/sandbox/invalid-upstream-response.test.ts @ 0bbebed.
// ignore_for_file: constant_identifier_names, non_constant_identifier_names, no_leading_underscores_for_local_identifiers, slash_for_doc_comments
import 'dart:async';
import 'dart:convert';
import 'dart:io' show Directory;

import 'package:sandbox_runtime/src/node/dns.dart' as dns;
import 'package:sandbox_runtime/src/node/fs.dart' show readFileSync;
import 'package:sandbox_runtime/src/node/http.dart'
    as http
    show IncomingMessage, ServerResponse, createServer;
import 'package:sandbox_runtime/src/node/net.dart'
    as net
    show
        LookupCallback,
        NodeAddress,
        NodeServer,
        NodeSocket,
        connect,
        createServer;
import 'package:sandbox_runtime/src/node/path.dart' show join;
import 'package:sandbox_runtime/src/node/tls.dart'
    as tls
    show connect, createServer;
import 'package:sandbox_runtime/src/sandbox/http_proxy.dart';
import 'package:sandbox_runtime/src/sandbox/mitm_ca.dart';
import 'package:sandbox_runtime/src/sandbox/mitm_leaf.dart';
import 'package:sandbox_runtime/src/sandbox/parent_proxy.dart'
    show DirectLookup, relayResponseHead;
import 'package:test/test.dart';

import '../helpers/emitted_connections.dart' show SERVES_EMITTED_CONNECTIONS;

final FIXTURE_DIR = join(
  Directory.current.path, // import.meta.dir, '..'
  'test',
  'fixtures',
  'tls-terminate',
);
final CA_CERT = join(FIXTURE_DIR, 'ca.crt');
final CA_KEY = join(FIXTURE_DIR, 'ca.key');
final CA_PEM = readFileSync(CA_CERT, 'utf8') as String;

const TLS_UPSTREAM_NAME = 'badstatus.test';

/** By path: the body an upstream declares, which `EXCESS` then follows. */
const DECLARED = {
  '/more-than-declared': 'whole',
  '/more-in-one-write': 'whole',
};

// Dart: the object literal upstream hands createHttpProxyServer; every
// option not named here is absent (null).
class _HttpOptions implements HttpProxyServerOptions {
  _HttpOptions({this.mitmCA, this.tlsTerminateUpstreamCA, this.lookupFor});
  @override
  final MitmCA? mitmCA;
  @override
  final dynamic tlsTerminateUpstreamCA;
  @override
  final DirectLookup? lookupFor;
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

// Dart: stands for upstream's `{ statusCode, headers, destroy } as unknown as
// IncomingMessage`; the real class has no public constructor.
class _UpstreamRes implements http.IncomingMessage {
  _UpstreamRes(this.statusCode, this.headers, this._destroy);
  @override
  final int? statusCode;
  @override
  final Map<String, Object?> headers;
  final void Function() _destroy;
  @override
  http.IncomingMessage destroy([Object? error, Function? callback]) {
    _destroy();
    return this;
  }

  @override
  dynamic noSuchMethod(Invocation invocation) => null;
}

/**
 * Fake upstream speaking raw bytes, so it can send response heads a real
 * HTTP server would refuse to produce. The reply depends on the request path.
 */
void answer(net.NodeSocket socket) {
  var buf = '';
  socket.on('error', (_) {});
  socket.on('data', (Object? chunk) {
    buf += latin1.decode(chunk as List<int>);
    if (!buf.contains('\r\n\r\n')) return;
    final path = RegExp(r'^GET (\S+)').firstMatch(buf)?.group(1) ?? '';
    buf = '';
    if (path == '/status-099') {
      socket.write(
        'HTTP/1.1 099 x\r\nX-Up: 1\r\nContent-Length: 4\r\n\r\nleak',
      );
    } else if (path == '/status-000') {
      socket.write(
        'HTTP/1.1 000 x\r\nX-Up: 1\r\nContent-Length: 4\r\n\r\nleak',
      );
    } else if (DECLARED.containsKey(path)) {
      final body = DECLARED[path]!;
      final head = 'HTTP/1.1 200 OK\r\nContent-Length: ${body.length}\r\n\r\n';
      if (path == '/more-in-one-write') {
        socket.write('$head${body}EXCESS');
      } else {
        socket.write(head, () => socket.write('${body}EXCESS'));
      }
    } else if (path == '/bad-chunk') {
      socket.write(
        'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n',
        () => socket.write('5\r\nwhole\r\nnot a size\r\n'),
      );
    } else if (path == '/less-than-declared') {
      socket.write(
        'HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\n',
        () => socket.end('whole'),
      );
    } else {
      socket.write('HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok');
    }
  });
}

/** Send one request head, read the reply until the connection closes. */
Future<({int status, String raw})> exchange(
  net.NodeSocket socket,
  String head,
) {
  final completer = Completer<({int status, String raw})>();
  var raw = '';
  socket.on(
    'data',
    (Object? chunk) => raw += latin1.decode(chunk as List<int>),
  );
  socket.on('error', (_) {});
  socket.on(
    'close',
    (_) => completer.complete((
      status: int.parse(
        RegExp(r'^HTTP/1\.1 (\d+)').firstMatch(raw)?.group(1) ?? '0',
      ),
      raw: raw,
    )),
  );
  socket.write(head);
  return completer.future;
}

// On Bun the HTTP client rejects these status lines itself, so these cases
// pin the end-to-end 502 outcome without reaching writeHead. The
// relayResponseHead cases below exercise the writeHead failure directly.
void main() {
  group('invalid upstream status line', () {
    // Every case runs a TLS-terminating proxy: skipped where none can run.
    final Object? tlsSkip = SERVES_EMITTED_CONNECTIONS
        ? null
        : 'TLS termination unavailable';
    final ca = createMitmCA(caCertPath: CA_CERT, caKeyPath: CA_KEY);
    void lookup(
      String _hostname,
      dns.LookupOptions options,
      net.LookupCallback callback,
    ) {
      if (options.all == true) {
        callback(
          null,
          const dns.LookupResultAll([
            dns.LookupAddress(address: '127.0.0.1', family: 4),
          ]),
        );
      } else {
        callback(null, const dns.LookupResultAddress('127.0.0.1'), 4);
      }
    }

    late net.NodeServer plainUpstream;
    late net.NodeServer tlsUpstream;
    late net.NodeServer proxy;
    late int plainPort;
    late int tlsPort;
    late int proxyPort;

    Future<int> listen(net.NodeServer server) async {
      final listening = Completer<void>();
      server.listen(0, '127.0.0.1', () => listening.complete());
      await listening.future;
      return (server.address() as net.NodeAddress).port;
    }

    setUpAll(() async {
      plainUpstream = net.createServer(answer);
      plainPort = await listen(plainUpstream);
      final leaf = mintLeafCert(ca, TLS_UPSTREAM_NAME);
      final leafOnly = RegExp(
        r'-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----\r?\n?',
      ).firstMatch(leaf.certPem)![0]!;
      tlsUpstream =
          tls.createServer({
                'cert': leafOnly,
                'key': leaf.keyPem,
                'ALPNProtocols': ['http/1.1'],
              }, answer)
              as net.NodeServer;
      tlsUpstream.on('tlsClientError', (_, [__]) {});
      tlsPort = await listen(tlsUpstream);
      proxy = createHttpProxyServer(
        _HttpOptions(
          mitmCA: SERVES_EMITTED_CONNECTIONS ? ca : null,
          tlsTerminateUpstreamCA: CA_PEM,
          lookupFor: (int port, [String? encodedCommand]) => lookup,
        ),
      );
      proxyPort = await listen(proxy);
    });

    tearDownAll(() async {
      final a = Completer<void>();
      proxy.close(() => a.complete());
      await a.future;
      final b = Completer<void>();
      plainUpstream.close(() => b.complete());
      await b.future;
      final c = Completer<void>();
      tlsUpstream.close(() => c.complete());
      await c.future;
    });

    Future<({int status, String raw})> plainGet(String path) {
      final authority = '127.0.0.1:$plainPort';
      final socket = net.connect({'port': proxyPort, 'host': '127.0.0.1'});
      return exchange(
        socket,
        'GET http://$authority$path HTTP/1.1\r\nHost: $authority\r\nConnection: close\r\n\r\n',
      );
    }

    Future<({int status, String raw})> tlsGet(String path) {
      final authority = '$TLS_UPSTREAM_NAME:$tlsPort';
      final completer = Completer<({int status, String raw})>();
      late final net.NodeSocket raw;
      raw = net.connect({'port': proxyPort, 'host': '127.0.0.1'}, () {
        raw.write('CONNECT $authority HTTP/1.1\r\nHost: $authority\r\n\r\n');
      });
      raw.once('error', (Object e) => completer.completeError(e));
      raw.once('data', (_) {
        late final net.NodeSocket tlsSocket;
        tlsSocket = tls.connect(
          {'socket': raw, 'ca': CA_PEM, 'servername': TLS_UPSTREAM_NAME},
          () {
            completer.complete(
              exchange(
                tlsSocket,
                'GET $path HTTP/1.1\r\nHost: $authority\r\nConnection: close\r\n\r\n',
              ),
            );
          },
        );
        tlsSocket.once('error', (Object e) => completer.completeError(e));
      });
      return completer.future;
    }

    for (final (name, get) in [
      ('plain HTTP', plainGet),
      ('TLS-terminated', tlsGet),
    ]) {
      for (final path in ['/status-099', '/status-000']) {
        test('$name: $path becomes 502 and the proxy keeps serving', () async {
          final bad = await get(path);
          expect(bad.status, 502);
          // Nothing from the upstream head or body is relayed.
          expect(bad.raw.toLowerCase(), isNot(contains('x-up')));
          expect(bad.raw, isNot(contains('leak')));

          final good = await get('/ok');
          expect(good.status, 200);
          expect(good.raw.endsWith('ok'), true);
        }, skip: tlsSkip);
      }

      String bodyOf(String raw) => raw.substring(raw.indexOf('\r\n\r\n') + 4);
      // As from an upstream that counts characters for bytes. A client that asks
      // it directly takes what was declared.
      for (final path in DECLARED.keys) {
        test('$name: $path arrives as declared, and no more', () async {
          final got = await get(path);
          expect(got.status, 200);
          expect(bodyOf(got.raw) == DECLARED[path], true);
        });
      }
      test('$name: /less-than-declared stays short of it', () async {
        final got = await get('/less-than-declared');
        expect(
          got.raw,
          matches(RegExp(r'\r\ncontent-length: 9\r\n', caseSensitive: false)),
        );
        expect(bodyOf(got.raw), 'whole');
      });
      test('$name: /bad-chunk is not ended as a whole answer is', () async {
        final got = await get('/bad-chunk');
        expect(
          got.raw,
          isNot(matches(RegExp(r'\r\ncontent-length:', caseSensitive: false))),
        );
        expect(got.raw.endsWith('0\r\n\r\n'), false);
      });
    }
  });

  group('relayResponseHead', () {
    late net.NodeServer server;
    late int port;
    void Function(http.ServerResponse) handler = (res) => res.end();

    setUpAll(() async {
      server =
          http.createServer(
                (http.IncomingMessage _req, http.ServerResponse res) =>
                    handler(res),
              )
              as net.NodeServer;
      final listening = Completer<void>();
      server.listen(0, '127.0.0.1', () => listening.complete());
      await listening.future;
      port = (server.address() as net.NodeAddress).port;
    });

    tearDownAll(() async {
      final r = Completer<void>();
      server.close(() => r.complete());
      await r.future;
    });

    /**
     * Answer one request by relaying a stub upstream head, and report what the
     * client received and what relayResponseHead did. With `afterPartialHead`,
     * the server first sends its own 200 head and 5 of 10 body bytes, and
     * relays only once the client has them.
     */
    Future<
      ({int status, String raw, bool? returned, Object? threw, bool destroyed})
    >
    relay(
      ({int statusCode, Map<String, String> headers}) upstream, {
      bool afterPartialHead = false,
    }) async {
      var destroyed = false;
      bool? returned;
      Object? threw;
      // relayResponseHead uses only statusCode, headers and destroy().
      final upstreamRes = _UpstreamRes(
        upstream.statusCode,
        upstream.headers,
        () {
          destroyed = true;
        },
      );
      void run(http.ServerResponse res) {
        try {
          returned = relayResponseHead(res, upstreamRes);
        } catch (err) {
          // Recorded, so a throw fails the assertions instead of escaping the
          // request handler.
          threw = err;
          res.destroy();
          return;
        }
        if (returned == true) res.end('body');
      }

      http.ServerResponse? pending;
      handler = (res) {
        if (!afterPartialHead) return run(res);
        pending = res;
        res.writeHead(200, {'Content-Length': '10'});
        res.write('first');
      };
      final socket = net.connect({'port': port, 'host': '127.0.0.1'});
      var seen = '';
      socket.on('data', (Object? chunk) {
        seen += latin1.decode(chunk as List<int>);
        if (pending != null && seen.endsWith('first')) {
          run(pending!);
          pending = null;
        }
      });
      final (:status, :raw) = await exchange(
        socket,
        'GET / HTTP/1.1\r\nHost: 127.0.0.1:$port\r\nConnection: close\r\n\r\n',
      );
      return (
        status: status,
        raw: raw,
        returned: returned,
        threw: threw,
        destroyed: destroyed,
      );
    }

    for (final statusCode in [99, 1000]) {
      test(
        'status $statusCode becomes 502 and the upstream is destroyed',
        () async {
          final r = await relay((
            statusCode: statusCode,
            headers: {'x-up': '1'},
          ));
          expect(r.threw, isNull);
          expect(r.returned, false);
          expect(r.destroyed, true);
          expect(r.status, 502);
          expect(r.raw, contains('Bad Gateway'));
          expect(r.raw.toLowerCase(), isNot(contains('x-up')));
        },
      );
    }

    // x-up comes first, so a header accepted before the rejected one must not
    // reach the client with the 502.
    for (final (name, headers) in [
      (
        'a control character in a header value',
        {'x-up': '1', 'x-bad': 'a\x01b'},
      ),
      ('an invalid header name', {'x-up': '1', 'x(bad)': '1'}),
    ]) {
      test('$name becomes 502 and the upstream is destroyed', () async {
        final r = await relay((statusCode: 200, headers: headers));
        expect(r.threw, isNull);
        expect(r.returned, false);
        expect(r.destroyed, true);
        expect(r.status, 502);
        expect(r.raw, contains('Bad Gateway'));
        expect(r.raw.toLowerCase(), isNot(contains('x-up')));
      });
    }

    test('once a head was sent, the response is cut off instead', () async {
      final r = await relay((
        statusCode: 99,
        headers: {'x-up': '1'},
      ), afterPartialHead: true);
      expect(r.threw, isNull);
      expect(r.returned, false);
      expect(r.destroyed, true);
      // The client has the 200 head and 5 of 10 body bytes when the connection
      // closes: no 502, and no complete response.
      expect(r.status, 200);
      expect(r.raw.endsWith('\r\n\r\nfirst'), true);
      expect(r.raw, isNot(contains('Bad Gateway')));
    });

    test('a valid head is relayed', () async {
      final r = await relay((statusCode: 203, headers: {'x-up': '1'}));
      expect(r.threw, isNull);
      expect(r.returned, true);
      expect(r.destroyed, false);
      expect(r.status, 203);
      expect(r.raw.toLowerCase(), contains('\r\nx-up: 1\r\n'));
      expect(r.raw, contains('body'));
    });
  });
}
