// Ported from sandbox-runtime test/sandbox/canonical-host-routing.test.ts @ 0bbebed.
// ignore_for_file: constant_identifier_names, non_constant_identifier_names, no_leading_underscores_for_local_identifiers, slash_for_doc_comments
import 'dart:async';
import 'dart:typed_data';

import 'package:sandbox_runtime/src/node/buffer.dart' show Buffer;
import 'package:sandbox_runtime/src/node/events.dart' show once;
import 'package:sandbox_runtime/src/node/fs.dart' show unlinkSync;
import 'package:sandbox_runtime/src/node/http.dart'
    as http
    show IncomingMessage, NodeHttpServer, ServerResponse, createServer, request;
import 'package:sandbox_runtime/src/node/net.dart'
    as net
    show NodeAddress, NodeServer, NodeSocket, connect, createServer;
import 'package:sandbox_runtime/src/node/os.dart' show tmpdir;
import 'package:sandbox_runtime/src/node/path.dart' show join;
import 'package:sandbox_runtime/src/node/process.dart' as process;
import 'package:sandbox_runtime/src/sandbox/http_proxy.dart';
import 'package:sandbox_runtime/src/sandbox/mitm_ca.dart';
import 'package:sandbox_runtime/src/sandbox/parent_proxy.dart'
    show ResolvedParentProxy, resolveParentProxy;
import 'package:sandbox_runtime/src/sandbox/request_filter.dart'
    show MutateForwardedHeaders;
import 'package:sandbox_runtime/src/sandbox/sandbox_config.dart'
    show
        FilesystemConfig,
        MitmProxyConfig,
        NetworkConfig,
        ParentProxyConfig,
        SandboxRuntimeConfig;
import 'package:sandbox_runtime/src/sandbox/sandbox_manager.dart'
    show SandboxManager;
import 'package:sandbox_runtime/src/sandbox/socks_proxy.dart';
import 'package:test/test.dart';

import '../helpers/emitted_connections.dart' show canServeEmittedConnections;
import '../helpers/platform.dart' show isWindows;

// Dart: the object literal upstream hands createHttpProxyServer; every option
// not named here is absent (null).
class _HttpOptions implements HttpProxyServerOptions {
  _HttpOptions({
    required this.filterFn,
    this.getMitmSocketPath,
    this.mutateHeadersPlaintext,
    this.parentProxy,
    this.mitmCA,
    this.shouldTerminateTLS,
  });
  final bool Function(int port, String host) filterFn;
  @override
  String? Function(String host)? getMitmSocketPath;
  @override
  final MutateForwardedHeaders? mutateHeadersPlaintext;
  @override
  final ResolvedParentProxy? parentProxy;
  @override
  final MitmCA? mitmCA;
  @override
  bool Function(String hostname, int port)? shouldTerminateTLS;
  @override
  FutureOr<bool> filter(
    int port,
    String host,
    dynamic socket, [
    String? encodedCommand,
    void Function(String reason)? explain,
  ]) => filterFn(port, host);
  @override
  dynamic noSuchMethod(Invocation invocation) => null;
}

// Dart: the object literal upstream hands createSocksProxyServer.
class _SocksOptions implements SocksProxyServerOptions {
  _SocksOptions({
    required this.filterFn,
    this.parentProxy,
    this.getMitmSocketPath,
    this.refuseOpaqueTunnels,
  });
  @override
  final String? Function(String host)? getMitmSocketPath;
  @override
  final bool? refuseOpaqueTunnels;
  final bool Function(int port, String host) filterFn;
  @override
  final ResolvedParentProxy? parentProxy;
  @override
  FutureOr<bool> filter(int port, String host, [String? encodedCommand]) =>
      filterFn(port, host);
  @override
  dynamic noSuchMethod(Invocation invocation) => null;
}

/**
 * The allow/deny filter canonicalizes a destination before matching
 * (`Api.Example.com.` → `api.example.com`, `127.1` → `127.0.0.1`), so it
 * admits every spelling of an allowed name. Everything downstream of that
 * decision — MITM routing, parent-proxy bypass, TLS-termination exemption,
 * credential injection, and the authority actually put on the wire — has to
 * key off the same canonical spelling. When MITM routing matched the raw
 * spelling instead, `CONNECT api.example.com.:443` passed the allowlist,
 * matched no MITM pattern, and dialed straight out, skipping the MITM proxy
 * with a one-character change to the hostname.
 *
 * Every destination here is either loopback or a name under `.invalid`
 * (RFC 6761: never resolves), and every allowed request is answered by a
 * recording MITM / parent stand-in, so a regression shows up as a 502 (the
 * direct dial of an unresolvable name), never as real egress.
 */

var sockSeq = 0;
String shortSocketPath() {
  // macOS sun_path is 104 bytes; keep it short.
  return join(
    tmpdir(),
    'srt-chr-${process.pid}-${(sockSeq++).toRadixString(36)}.sock',
  );
}

typedef RecordedRequest = ({String method, String url, String? host});

class RecordingMitm {
  RecordingMitm({
    required this.socketPath,
    required this.connects,
    required this.requests,
    required this.close,
  });
  final String socketPath;
  final List<String> connects;
  final List<RecordedRequest> requests;
  final Future<void> Function() close;
}

/**
 * Stand-in for the external MITM proxy: an HTTP server on a unix socket
 * that records the authority of every CONNECT and the request-target +
 * Host header of every plain request it receives, and answers 200.
 */
Future<RecordingMitm> startRecordingMitm() async {
  final socketPath = shortSocketPath();
  final connects = <String>[];
  final requests = <RecordedRequest>[];
  final server = http.createServer((
    http.IncomingMessage req,
    http.ServerResponse res,
  ) {
    requests.add((
      method: req.method!,
      url: req.url!,
      host: req.headers['host'] as String?,
    ));
    res.writeHead(200, {'content-type': 'text/plain'});
    res.end('via-mitm');
  });
  server.on('connect', (http.IncomingMessage req, net.NodeSocket socket) {
    connects.add(req.url!);
    socket.on('error', (_) {});
    socket.end('HTTP/1.1 200 Connection Established\r\n\r\n');
  });
  server.listen(socketPath);
  await once(server, 'listening');
  return RecordingMitm(
    socketPath: socketPath,
    connects: connects,
    requests: requests,
    close: () async {
      final closed = Completer<void>();
      server.close(() => closed.complete());
      await closed.future;
      try {
        unlinkSync(socketPath);
      } catch (_) {
        // already gone
      }
    },
  );
}

class RecordingParent {
  RecordingParent({
    required this.port,
    required this.connects,
    required this.requests,
    required this.close,
  });
  final int port;
  final List<String> connects;
  final List<RecordedRequest> requests;
  final Future<void> Function() close;
}

/**
 * Stand-in for a parent (corporate) proxy on loopback TCP: records CONNECT
 * authorities and absolute-form plain requests, answers 200 to both. Also
 * used to observe the plain-HTTP path's forwarded authority — the MITM
 * recorder above cannot be, because Bun's http.request does not honour an
 * Agent's socketPath (a pre-existing gap in the plain-HTTP MITM leg under
 * Bun, unrelated to host spelling); the parent leg is ordinary TCP and the
 * proxy builds the forwarded request-target and Host header identically
 * for both.
 */
Future<RecordingParent> startRecordingParent() async {
  final connects = <String>[];
  final requests = <RecordedRequest>[];
  final server = http.createServer((
    http.IncomingMessage req,
    http.ServerResponse res,
  ) {
    requests.add((
      method: req.method!,
      url: req.url!,
      host: req.headers['host'] as String?,
    ));
    res.writeHead(200, {'content-type': 'text/plain'});
    res.end('via-parent');
  });
  server.on('connect', (http.IncomingMessage req, net.NodeSocket socket) {
    connects.add(req.url!);
    socket.on('error', (_) {});
    socket.end('HTTP/1.1 200 Connection Established\r\n\r\n');
  });
  final port = await listen(server);
  return RecordingParent(
    port: port,
    connects: connects,
    requests: requests,
    close: () => closeServer(server),
  );
}

/** Raw CONNECT through the proxy; resolves with the proxy's status line. */
Future<String> rawConnect(int proxyPort, String target, [String? authToken]) {
  final completer = Completer<String>();
  final auth = authToken != null && authToken.isNotEmpty
      ? 'Proxy-Authorization: Basic ${Buffer.from('srt:$authToken').toString('base64')}\r\n'
      : '';
  late final net.NodeSocket sock;
  sock = net.connect(proxyPort, '127.0.0.1', () {
    sock.write('CONNECT $target HTTP/1.1\r\nHost: $target\r\n$auth\r\n');
  });
  var buf = '';
  void finish() {
    sock.destroy();
    if (!completer.isCompleted) {
      completer.complete(buf.split('\r\n')[0]);
    }
  }

  sock.on('data', (Object? d) {
    buf += Buffer.wrap(d as Uint8List).toString('latin1');
    if (buf.contains('\r\n')) finish();
  });
  sock.on('close', ([_]) => finish());
  sock.on('error', (Object e) {
    if (!completer.isCompleted) completer.completeError(e);
  });
  sock.setTimeout(5000, finish);
  return completer.future;
}

/** Absolute-form plain-HTTP request through the proxy. */
Future<({int status, String body})> rawGet(
  int proxyPort,
  String absoluteUrl,
  String hostHeader, [
  String? authToken,
]) {
  final completer = Completer<({int status, String body})>();
  final req = http.request(
    {
      'host': '127.0.0.1',
      'port': proxyPort,
      'method': 'GET',
      'path': absoluteUrl,
      'headers': {
        'host': hostHeader,
        if (authToken != null && authToken.isNotEmpty)
          'proxy-authorization':
              'Basic ${Buffer.from('srt:$authToken').toString('base64')}',
      },
      'agent': false,
    },
    (http.IncomingMessage res) {
      var body = '';
      res.setEncoding('utf8');
      res.on('data', (Object? d) => body += d as String);
      res.on(
        'end',
        () => completer.complete((status: res.statusCode!, body: body)),
      );
      res.on('error', (Object e) => completer.completeError(e));
    },
  );
  req.on('error', (Object e) => completer.completeError(e));
  req.end();
  return completer.future;
}

/**
 * SOCKS5 CONNECT to a DOMAINNAME destination through the proxy, with
 * username/password auth when a token is given. Resolves with the reply's
 * REP byte (0 = granted), the socket (the tunnel, when granted), and
 * `received()`, the bytes that have come through the tunnel so far.
 */
Future<({int rep, net.NodeSocket sock, String Function() received})>
socksConnect(int proxyPort, String host, int port, [String? authToken]) async {
  final sock = net.connect(proxyPort, '127.0.0.1');
  sock.on('error', () {});
  await once(sock, 'connect');
  // Replies can arrive split or joined, so read them by length.
  var buf = Buffer.alloc(0);
  Completer<void>? wake;
  sock.on('data', (Uint8List d) {
    buf = Buffer.concat([buf, Buffer.wrap(d)]);
    final w = wake;
    wake = null;
    if (w != null && !w.isCompleted) w.complete();
  });
  sock.once('close', () {
    final w = wake;
    wake = null;
    if (w != null && !w.isCompleted) w.complete();
  });
  Future<Buffer> read(int n) async {
    while (buf.length < n) {
      if (sock.destroyed) throw StateError('SOCKS proxy closed mid-handshake');
      wake = Completer<void>();
      await wake!.future;
    }
    final out = buf.subarray(0, n);
    buf = buf.subarray(n);
    return out;
  }

  sock.write(Buffer.from([5, 1, authToken != null ? 2 : 0]).toUint8List());
  expect([...(await read(2))], [5, authToken != null ? 2 : 0]);
  if (authToken != null) {
    final token = Buffer.from(authToken);
    sock.write(
      Buffer.concat([
        Buffer.from([1, 3]),
        Buffer.from('srt'),
        Buffer.from([token.length]),
        token,
      ]).toUint8List(),
    );
    expect([...(await read(2))], [1, 0]);
  }
  final name = Buffer.from(host);
  sock.write(
    Buffer.concat([
      Buffer.from([5, 1, 0, 3, name.length]),
      name,
      Buffer.from([(port >> 8) & 255, port & 255]),
    ]).toUint8List(),
  );
  // VER REP RSV ATYP=IPv4 0.0.0.0:0. Every CONNECT reply this proxy sends is
  // 10 bytes.
  final reply = await read(10);
  return (rep: reply[1], sock: sock, received: () => buf.toString('latin1'));
}

Future<int> listen(net.NodeServer server) {
  final completer = Completer<int>();
  server.listen(
    0,
    '127.0.0.1',
    () => completer.complete((server.address() as net.NodeAddress).port),
  );
  return completer.future;
}

Future<void> closeServer(http.NodeHttpServer? server) {
  final completer = Completer<void>();
  if (server == null) {
    completer.complete();
    return completer.future;
  }
  server.close(() => completer.complete());
  // Idle keep-alive client connections would otherwise hold close() open.
  server.closeAllConnections();
  return completer.future;
}

final _200 = matches(RegExp(r'^HTTP/1\.1 200 '));
final _403 = matches(RegExp(r'^HTTP/1\.1 403 '));

void main() {
  group(
    'http-proxy: routes and dials the canonical host',
    skip: !isWindows ? null : 'Windows not supported by this port',
    () {
      late RecordingMitm mitm;
      late RecordingParent parent;
      http.NodeHttpServer? proxy;

      setUpAll(() async {
        mitm = await startRecordingMitm();
        parent = await startRecordingParent();
      });
      tearDownAll(() async {
        await mitm.close();
        await parent.close();
      });
      tearDown(() async {
        await closeServer(proxy);
        proxy = null;
        mitm.connects.clear();
        mitm.requests.clear();
        parent.connects.clear();
        parent.requests.clear();
      });

      test(
        'CONNECT: filter sees the raw spelling; MITM lookup and the forwarded authority are canonical',
        () async {
          final filterSaw = <String>[];
          final mitmLookups = <String>[];
          proxy = createHttpProxyServer(
            _HttpOptions(
              filterFn: (_port, host) {
                filterSaw.add(host);
                return true;
              },
              getMitmSocketPath: (host) {
                mitmLookups.add(host);
                return host == 'api.mitm.invalid' ? mitm.socketPath : null;
              },
            ),
          );
          final port = await listen(proxy!);

          expect(await rawConnect(port, 'Api.MITM.invalid.:443'), _200);
          expect(filterSaw, equals(['Api.MITM.invalid.']));
          expect(mitmLookups, equals(['api.mitm.invalid']));
          expect(mitm.connects, equals(['api.mitm.invalid:443']));
        },
      );

      test(
        'CONNECT: an inet_aton spelling reaches the MITM lookup in dotted-quad form',
        () async {
          final mitmLookups = <String>[];
          proxy = createHttpProxyServer(
            _HttpOptions(
              filterFn: (_, _) => true,
              getMitmSocketPath: (host) {
                mitmLookups.add(host);
                return mitm.socketPath;
              },
            ),
          );
          final port = await listen(proxy!);

          expect(await rawConnect(port, '127.1:443'), _200);
          expect(await rawConnect(port, '0x7f.0.0.1:443'), _200);
          expect(await rawConnect(port, '2130706433:443'), _200);
          expect(mitmLookups, equals(['127.0.0.1', '127.0.0.1', '127.0.0.1']));
          expect(
            mitm.connects,
            equals(['127.0.0.1:443', '127.0.0.1:443', '127.0.0.1:443']),
          );
        },
      );

      test(
        'plain HTTP: MITM lookup and injector destHost are canonical; forwarded request-target and Host are rebuilt from it',
        () async {
          final filterSaw = <String>[];
          final mitmLookups = <String>[];
          final injectorSaw = <String>[];
          proxy = createHttpProxyServer(
            _HttpOptions(
              filterFn: (_port, host) {
                filterSaw.add(host);
                return true;
              },
              getMitmSocketPath: (host) {
                mitmLookups.add(host);
                return null;
              },
              mutateHeadersPlaintext: (_headers, destHost) {
                injectorSaw.add(destHost);
              },
              parentProxy: resolveParentProxy(
                ParentProxyConfig(
                  http: 'http://127.0.0.1:${parent.port}',
                  noProxy: '',
                ),
              ),
            ),
          );
          final port = await listen(proxy!);

          final res = await rawGet(
            port,
            'http://Api.MITM.invalid./v1/thing?q=1',
            'Api.MITM.invalid.',
          );
          expect(res, equals((status: 200, body: 'via-parent')));
          // The URL parser lowercases; the trailing dot is what it leaves behind.
          expect(filterSaw, equals(['api.mitm.invalid.']));
          expect(mitmLookups, equals(['api.mitm.invalid']));
          expect(injectorSaw, equals(['api.mitm.invalid']));
          expect(
            parent.requests,
            equals([
              (
                method: 'GET',
                url: 'http://api.mitm.invalid/v1/thing?q=1',
                host: 'api.mitm.invalid',
              ),
            ]),
          );
        },
      );

      test(
        'plain HTTP: an explicit non-default port survives canonicalization',
        () async {
          proxy = createHttpProxyServer(
            _HttpOptions(
              filterFn: (_, _) => true,
              parentProxy: resolveParentProxy(
                ParentProxyConfig(
                  http: 'http://127.0.0.1:${parent.port}',
                  noProxy: '',
                ),
              ),
            ),
          );
          final port = await listen(proxy!);

          final res = await rawGet(
            port,
            'http://api.mitm.invalid.:8080/x',
            'api.mitm.invalid.:8080',
          );
          expect(res.status, 200);
          expect(
            parent.requests,
            equals([
              (
                method: 'GET',
                url: 'http://api.mitm.invalid:8080/x',
                host: 'api.mitm.invalid:8080',
              ),
            ]),
          );
        },
      );

      test(
        'plain HTTP: an IPv6 literal is bare for the hooks and re-bracketed on the wire',
        () async {
          final mitmLookups = <String>[];
          proxy = createHttpProxyServer(
            _HttpOptions(
              filterFn: (_, _) => true,
              getMitmSocketPath: (host) {
                mitmLookups.add(host);
                return null;
              },
              parentProxy: resolveParentProxy(
                ParentProxyConfig(
                  http: 'http://127.0.0.1:${parent.port}',
                  noProxy: '',
                ),
              ),
            ),
          );
          final port = await listen(proxy!);

          // Documentation prefix (RFC 3849): not loopback, so it is not
          // parent-bypassed, and never dialed because the parent answers.
          final res = await rawGet(
            port,
            'http://[2001:0db8:0000:0000:0000:0000:0000:0001]:8080/x',
            '[2001:0db8:0000:0000:0000:0000:0000:0001]:8080',
          );
          expect(res.status, 200);
          expect(mitmLookups, equals(['2001:db8::1']));
          expect(
            parent.requests,
            equals([
              (
                method: 'GET',
                url: 'http://[2001:db8::1]:8080/x',
                host: '[2001:db8::1]:8080',
              ),
            ]),
          );
        },
      );

      test(
        'CONNECT: the parent proxy is asked for the canonical authority',
        () async {
          proxy = createHttpProxyServer(
            _HttpOptions(
              filterFn: (_, _) => true,
              parentProxy: resolveParentProxy(
                ParentProxyConfig(
                  http: 'http://127.0.0.1:${parent.port}',
                  noProxy: '',
                ),
              ),
            ),
          );
          final port = await listen(proxy!);
          expect(await rawConnect(port, 'Upstream.invalid.:80'), _200);
          expect(parent.connects, equals(['upstream.invalid:80']));
        },
      );

      test(
        'CONNECT: the tlsTerminate exemption hook is consulted with the canonical host',
        skip: !canServeEmittedConnections
            ? 'TLS termination unavailable'
            : null,
        () async {
          final ca = createMitmCA();
          final exemptionSaw = <String>[];
          try {
            proxy = createHttpProxyServer(
              _HttpOptions(
                filterFn: (_, _) => true,
                mitmCA: ca,
                shouldTerminateTLS: (host, _port) {
                  exemptionSaw.add(host);
                  return false;
                },
                // Exempted → opaque tunnel → normal routing, which we point at the
                // recorder so the test needs no real upstream.
                getMitmSocketPath: (_) => mitm.socketPath,
              ),
            );
            final port = await listen(proxy!);
            expect(await rawConnect(port, 'Pinned.invalid.:443'), _200);
            expect(exemptionSaw, equals(['pinned.invalid']));
            expect(mitm.connects, equals(['pinned.invalid:443']));
          } finally {
            await disposeMitmCA(ca);
          }
        },
      );
    },
  );

  group(
    'socks-proxy: dials the canonical host',
    skip: !isWindows ? null : 'Windows not supported by this port',
    () {
      net.NodeServer? tcp;
      SocksProxyWrapper? wrapper;
      RecordingParent? parent;
      RecordingMitm? mitm;

      tearDown(() async {
        await wrapper?.close();
        tcp?.close();
        await parent?.close();
        await mitm?.close();
        wrapper = null;
        tcp = null;
        parent = null;
        mitm = null;
      });

      /** Serve `wrapper` on a loopback port, as the mux front-end would. */
      Future<int> listenSocks() async {
        final w = wrapper!;
        tcp = net.createServer((net.NodeSocket s) => w.handleConnection(s));
        tcp!.listen(0, '127.0.0.1');
        await once(tcp!, 'listening');
        return (tcp!.address() as net.NodeAddress).port;
      }

      test(
        'filter sees the raw spelling; the parent proxy is asked for the canonical authority',
        () async {
          parent = await startRecordingParent();
          final filterSaw = <String>[];
          wrapper = createSocksProxyServer(
            _SocksOptions(
              filterFn: (_port, host) {
                filterSaw.add(host);
                return true;
              },
              parentProxy: resolveParentProxy(
                ParentProxyConfig(
                  http: 'http://127.0.0.1:${parent!.port}',
                  noProxy: '',
                ),
              ),
            ),
          );
          final w = wrapper!;
          tcp = net.createServer((net.NodeSocket s) => w.handleConnection(s));
          tcp!.listen(0, '127.0.0.1');
          await once(tcp!, 'listening');
          final socksPort = (tcp!.address() as net.NodeAddress).port;

          final sock = net.connect(socksPort, '127.0.0.1');
          await once(sock, 'connect');
          final chunks = <Buffer>[];
          sock.on(
            'data',
            (Object? d) => chunks.add(Buffer.wrap(d as Uint8List)),
          );
          sock.on('error', (_) {});
          // Greeting offering no-auth (no token configured), then CONNECT.
          sock.write(Buffer.from([0x05, 0x01, 0x00]).toUint8List());
          final host = Buffer.from('Upstream.invalid.');
          sock.write(
            Buffer.concat([
              Buffer.from([0x05, 0x01, 0x00, 0x03, host.length]),
              host,
              Buffer.from([0x00, 0x50]), // 80
            ]).toUint8List(),
          );
          await once(sock, 'close');
          final reply = Buffer.concat(chunks);
          // method-select 05 00, then the CONNECT reply with REP=0 (granted).
          expect(reply.sublist(0, 2), equals([0x05, 0x00]));
          expect(reply[2], 0x05);
          expect(reply[3], 0x00);

          expect(filterSaw, equals(['Upstream.invalid.']));
          expect(parent!.connects, equals(['upstream.invalid:80']));
        },
      );
      test(
        'filter sees the raw spelling; the MITM lookup and the authority sent into the MITM socket are canonical, and the parent proxy is not used',
        () async {
          final m = mitm = await startRecordingMitm();
          parent = await startRecordingParent();
          final filterSaw = <String>[], mitmLookups = <String>[];
          wrapper = createSocksProxyServer(
            _SocksOptions(
              filterFn: (_port, host) {
                filterSaw.add(host);
                return true;
              },
              getMitmSocketPath: (host) {
                mitmLookups.add(host);
                return host == 'api.mitm.invalid' ? m.socketPath : null;
              },
              parentProxy: resolveParentProxy(
                ParentProxyConfig(
                  http: 'http://127.0.0.1:${parent!.port}',
                  noProxy: '',
                ),
              ),
            ),
          );
          final socksPort = await listenSocks();
          final (:rep, :sock, received: _) = await socksConnect(
            socksPort,
            'Api.MITM.invalid.',
            443,
          );
          sock.destroy();
          expect(rep, 0);
          expect(filterSaw, ['Api.MITM.invalid.']);
          expect(mitmLookups, ['api.mitm.invalid']);
          expect(m.connects, ['api.mitm.invalid:443']);
          expect(parent!.connects, []);
        },
      );
      test(
        'refuseOpaqueTunnels refuses a MITM host like any other, without asking for its socket',
        () async {
          final m = mitm = await startRecordingMitm();
          final mitmLookups = <String>[];
          wrapper = createSocksProxyServer(
            _SocksOptions(
              filterFn: (_, _) => true,
              getMitmSocketPath: (host) {
                mitmLookups.add(host);
                return m.socketPath;
              },
              refuseOpaqueTunnels: true,
            ),
          );
          final socksPort = await listenSocks();
          final (:rep, :sock, received: _) = await socksConnect(
            socksPort,
            'api.mitm.invalid',
            443,
          );
          sock.destroy();
          expect(rep, 0x01); // general SOCKS server failure
          expect(mitmLookups, []);
          expect(m.connects, []);
        },
      );
    },
  );

  group(
    'SandboxManager: mitmProxy routing vs allowlist spellings',
    skip: !isWindows ? null : 'Windows not supported by this port',
    () {
      late RecordingMitm mitm;
      late RecordingParent parent;
      late http.NodeHttpServer origin;
      late int originPort;
      var originConnections = 0, originProbes = 0;

      setUpAll(() async {
        mitm = await startRecordingMitm();
        parent = await startRecordingParent();
        origin = http.createServer((
          http.IncomingMessage _req,
          http.ServerResponse res,
        ) {
          res.end('origin');
        });
        origin.on('connection', () => originConnections++);
        originPort = await listen(origin);
      });
      tearDownAll(() async {
        await SandboxManager.reset();
        await mitm.close();
        await parent.close();
        await closeServer(origin);
      });
      tearDown(() async {
        await SandboxManager.reset();
        mitm.connects.clear();
        mitm.requests.clear();
        parent.connects.clear();
        parent.requests.clear();
        originConnections = originProbes = 0;
      });

      /**
     * Connections the origin has accepted, not counting the ones this opens.
     * The origin accepts in arrival order, so once it has answered this
     * request it has already counted every connection made before it.
     */
      Future<int> originConnectionCount() async {
        originProbes++;
        final probe = net.connect(originPort, '127.0.0.1');
        probe.on('error', () {});
        probe.write('GET / HTTP/1.1\r\nHost: origin\r\n\r\n');
        var answer = '';
        while (!answer.endsWith('origin')) {
          final chunks = await once(probe, 'data');
          answer += Buffer.from(chunks[0]!).toString('latin1');
        }
        probe.destroy();
        return originConnections - originProbes;
      }

      Future<({int port, String token})> start({
        required List<String> allowedDomains,
        List<String>? deniedDomains,
        required List<String> mitmDomains,
        bool? viaParent,
        String? mitmSocketPath,
      }) async {
        await SandboxManager.initialize(
          SandboxRuntimeConfig(
            network: NetworkConfig(
              allowedDomains: allowedDomains,
              deniedDomains: deniedDomains ?? [],
              mitmProxy: MitmProxyConfig(
                socketPath: mitmSocketPath ?? mitm.socketPath,
                domains: mitmDomains,
              ),
              parentProxy: viaParent == true
                  ? ParentProxyConfig(
                      http: 'http://127.0.0.1:${parent.port}',
                      noProxy: '',
                    )
                  : null,
            ),
            filesystem: FilesystemConfig(
              denyRead: [],
              allowWrite: [],
              denyWrite: [],
            ),
          ),
        );
        return (
          port: SandboxManager.getProxyPort()!,
          token: SandboxManager.getProxyAuthToken()!,
        );
      }

      for (final (_label, pattern) in [
        ('exact pattern', 'api.mitm.invalid'),
        ('wildcard pattern', '*.mitm.invalid'),
      ]) {
        test(
          'a trailing-dot spelling of a MITM host is routed to the MITM socket ($_label)',
          () async {
            final (:port, :token) = await start(
              allowedDomains: [pattern],
              mitmDomains: [pattern],
            );
            // Pre-fix this passed the allowlist, missed the MITM pattern, and
            // dialed `api.mitm.invalid.` directly — observable here as a 502,
            // since nothing under .invalid resolves.
            expect(
              await rawConnect(port, 'api.mitm.invalid.:443', token),
              _200,
            );
            expect(await rawConnect(port, 'API.Mitm.Invalid:443', token), _200);
            expect(
              mitm.connects,
              equals(['api.mitm.invalid:443', 'api.mitm.invalid:443']),
            );
          },
        );
      }

      test(
        'plain HTTP: a trailing-dot spelling is allowed and forwarded under its canonical authority',
        () async {
          // Observed at a parent proxy rather than the MITM socket: Bun's
          // http.request cannot speak to a unix-socket Agent (see
          // startRecordingParent), and the proxy builds the forwarded authority
          // the same way for both legs. The MITM-domain lookup itself is shared
          // with the CONNECT path pinned above.
          final (:port, :token) = await start(
            allowedDomains: ['files.example.invalid'],
            mitmDomains: ['api.mitm.invalid'],
            viaParent: true,
          );
          final res = await rawGet(
            port,
            'http://Files.Example.invalid./v1/files',
            'Files.Example.invalid.',
            token,
          );
          expect(res, equals((status: 200, body: 'via-parent')));
          expect(
            parent.requests,
            equals([
              (
                method: 'GET',
                url: 'http://files.example.invalid/v1/files',
                host: 'files.example.invalid',
              ),
            ]),
          );
          // ...and a spelling that canonicalizes to a non-allowed name is still
          // refused before anything is forwarded.
          final denied = await rawGet(
            port,
            'http://other.example.invalid./v1/files',
            'other.example.invalid.',
            token,
          );
          expect(denied.status, 403);
          expect(parent.requests, hasLength(1));
          expect(mitm.requests, equals([]));
        },
      );

      test(
        'CONNECT via a parent proxy: MITM domains still win, and the parent gets the canonical authority otherwise',
        () async {
          final (:port, :token) = await start(
            allowedDomains: ['api.mitm.invalid', 'other.example.invalid'],
            mitmDomains: ['api.mitm.invalid'],
            viaParent: true,
          );
          expect(await rawConnect(port, 'api.mitm.invalid.:443', token), _200);
          expect(
            await rawConnect(port, 'Other.Example.invalid.:443', token),
            _200,
          );
          expect(mitm.connects, equals(['api.mitm.invalid:443']));
          expect(parent.connects, equals(['other.example.invalid:443']));
        },
      );

      test(
        'inet_aton spellings of a MITM-pinned IP are routed to the MITM socket',
        () async {
          final (:port, :token) = await start(
            allowedDomains: ['127.0.0.1'],
            mitmDomains: ['127.0.0.1'],
          );
          for (final spelling in [
            '127.1',
            '0x7f.0.0.1',
            '2130706433',
            '127.0.0.1.',
          ]) {
            expect(
              await rawConnect(port, '$spelling:$originPort', token),
              _200,
            );
          }
          // Every spelling went to the MITM, none to the origin behind it.
          expect(
            mitm.connects,
            equals(List<String>.filled(4, '127.0.0.1:$originPort')),
          );
        },
      );

      test(
        'an allowed host that canonicalizes to a non-MITM name still dials directly',
        () async {
          final (:port, :token) = await start(
            allowedDomains: ['api.mitm.invalid', '127.0.0.1'],
            mitmDomains: ['api.mitm.invalid'],
          );
          expect(await rawConnect(port, '127.1:$originPort', token), _200);
          expect(await rawConnect(port, '127.0.0.1.:$originPort', token), _200);
          expect(mitm.connects, equals([]));
        },
      );

      test(
        'a host outside the allowlist is denied however it is spelled, and never reaches the MITM',
        () async {
          final (:port, :token) = await start(
            allowedDomains: ['api.mitm.invalid'],
            mitmDomains: ['*.mitm.invalid'],
          );
          for (final target in [
            'other.mitm.invalid:443',
            'other.mitm.invalid.:443',
            'OTHER.mitm.invalid.:443',
          ]) {
            expect(await rawConnect(port, target, token), _403);
          }
          expect(mitm.connects, equals([]));
        },
      );

      test(
        'an IPv4-mapped spelling of a deny-listed address is refused even when that spelling is allow-listed',
        () async {
          final (:port, :token) = await start(
            allowedDomains: ['[::ffff:127.0.0.1]'],
            deniedDomains: ['127.0.0.1'],
            mitmDomains: [],
          );
          for (final target in [
            '[::ffff:127.0.0.1]:$originPort',
            '[::FFFF:7F00:1]:$originPort',
            '[0:0:0:0:0:ffff:7f00:1]:$originPort',
          ]) {
            expect(await rawConnect(port, target, token), _403);
          }
        },
      );

      test(
        'deniedDomains wins over every spelling of the denied host',
        () async {
          final (:port, :token) = await start(
            allowedDomains: ['*.mitm.invalid', '127.0.0.1'],
            deniedDomains: ['evil.mitm.invalid', '127.0.0.1'],
            mitmDomains: ['*.mitm.invalid'],
          );
          for (final target in [
            'evil.mitm.invalid:443',
            'evil.mitm.invalid.:443',
            'EVIL.MITM.invalid.:443',
            '127.1:$originPort',
            '0x7f.0.0.1:$originPort',
            '2130706433:$originPort',
            '0177.0.0.1:$originPort',
          ]) {
            expect(await rawConnect(port, target, token), _403);
          }
          // ...while a sibling that is merely allowed still routes to the MITM
          // under any spelling — pinning that allow and MITM agree.
          expect(await rawConnect(port, 'ok.mitm.invalid.:443', token), _200);
          expect(mitm.connects, equals(['ok.mitm.invalid:443']));
        },
      );
      // The proxy port speaks SOCKS5 as well as HTTP. A SOCKS CONNECT to a MITM
      // host must take the same route as an HTTP CONNECT to it: dialed directly
      // or through the parent proxy, it would skip the MITM proxy.
      for (final (label, pattern) in [
        ('exact pattern', 'api.mitm.invalid'),
        ('wildcard pattern', '*.mitm.invalid'),
      ]) {
        test(
          'SOCKS: every spelling of a MITM host is routed to the MITM socket ($label)',
          () async {
            final (:port, :token) = await start(
              allowedDomains: [pattern],
              mitmDomains: [pattern],
            );
            for (final spelling in [
              'api.mitm.invalid',
              'api.mitm.invalid.',
              'API.Mitm.Invalid',
            ]) {
              final (:rep, :sock, received: _) = await socksConnect(
                port,
                spelling,
                443,
                token,
              );
              sock.destroy();
              expect(rep, 0);
            }
            expect(mitm.connects, List.filled(3, 'api.mitm.invalid:443'));
          },
        );
      }
      test(
        'SOCKS: a MITM-pinned IP is routed to the MITM socket and the address itself is never dialed',
        () async {
          final (:port, :token) = await start(
            allowedDomains: ['127.0.0.1'],
            mitmDomains: ['127.0.0.1'],
          );
          for (final spelling in ['127.0.0.1', '127.1', '127.0.0.1.']) {
            final (:rep, :sock, received: _) = await socksConnect(
              port,
              spelling,
              originPort,
              token,
            );
            sock.destroy();
            expect(rep, 0);
          }
          expect(mitm.connects, List.filled(3, '127.0.0.1:$originPort'));
          expect(await originConnectionCount(), 0);
        },
      );
      test(
        'SOCKS via a parent proxy: MITM domains still win, and the parent gets the canonical authority otherwise',
        () async {
          final (:port, :token) = await start(
            allowedDomains: ['api.mitm.invalid', 'other.example.invalid'],
            mitmDomains: ['api.mitm.invalid'],
            viaParent: true,
          );
          for (final host in ['api.mitm.invalid.', 'Other.Example.invalid.']) {
            final (:rep, :sock, received: _) = await socksConnect(
              port,
              host,
              443,
              token,
            );
            sock.destroy();
            expect(rep, 0);
          }
          expect(mitm.connects, ['api.mitm.invalid:443']);
          expect(parent.connects, ['other.example.invalid:443']);
        },
      );
      test(
        'SOCKS: an allowed host outside the MITM domains still dials directly',
        () async {
          final (:port, :token) = await start(
            allowedDomains: ['api.mitm.invalid', '127.0.0.1'],
            mitmDomains: ['api.mitm.invalid'],
          );
          final (:rep, :sock, :received) = await socksConnect(
            port,
            '127.0.0.1',
            originPort,
            token,
          );
          expect(rep, 0);
          sock.write(
            'GET / HTTP/1.1\r\nHost: origin\r\nConnection: close\r\n\r\n',
          );
          await once(sock, 'close');
          expect(received(), matches(RegExp(r'\r\n\r\norigin$')));
          expect(mitm.connects, []);
        },
      );
      test(
        'SOCKS: when the MITM socket cannot be reached the client gets a failure, and neither the parent proxy nor the host is dialed instead',
        () async {
          final (:port, :token) = await start(
            allowedDomains: ['api.mitm.invalid', '127.0.0.1'],
            mitmDomains: ['api.mitm.invalid', '127.0.0.1'],
            mitmSocketPath: shortSocketPath(), // nothing listens here
            viaParent: true,
          );
          // A fallback would send the first of these to the parent proxy and the
          // second, since loopback bypasses a parent, straight to the origin.
          for (final (host, destPort) in [
            ('api.mitm.invalid', 443),
            ('127.0.0.1', originPort),
          ]) {
            final (:rep, :sock, received: _) = await socksConnect(
              port,
              host,
              destPort,
              token,
            );
            sock.destroy();
            expect(rep, 0x04);
          } // host unreachable
          expect(parent.connects, []);
          expect(await originConnectionCount(), 0);
        },
      );
      test(
        'SOCKS: a host outside the allowlist is refused even when it is a MITM domain, and never reaches the MITM',
        () async {
          final (:port, :token) = await start(
            allowedDomains: ['api.mitm.invalid'],
            mitmDomains: ['*.mitm.invalid'],
          );
          for (final host in ['other.mitm.invalid', 'OTHER.mitm.invalid.']) {
            final (:rep, :sock, received: _) = await socksConnect(
              port,
              host,
              443,
              token,
            );
            sock.destroy();
            expect(rep, 0x02);
          } // connection not allowed by ruleset
          expect(mitm.connects, []);
        },
      );
    },
  );
}
