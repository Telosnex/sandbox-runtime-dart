// Ported from sandbox-runtime test/sandbox/tls-terminate-in-process.test.ts @ 0bbebed.
// ignore_for_file: constant_identifier_names, non_constant_identifier_names, slash_for_doc_comments
import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:sandbox_runtime/src/node/buffer.dart' show Buffer;
import 'package:sandbox_runtime/src/node/globals.dart' show setTimeout;
import 'package:sandbox_runtime/src/node/http.dart' as http;
import 'package:sandbox_runtime/src/node/https.dart' as https;
import 'package:sandbox_runtime/src/node/net.dart' as net;
import 'package:sandbox_runtime/src/node/tls.dart' as tls_;
import 'package:sandbox_runtime/src/sandbox/http_proxy.dart';
import 'package:sandbox_runtime/src/sandbox/mitm_ca.dart';
import 'package:sandbox_runtime/src/sandbox/mitm_leaf.dart';
import 'package:sandbox_runtime/src/sandbox/request_filter.dart';
import 'package:test/test.dart';

import '../helpers/emitted_connections.dart' show canServeEmittedConnections;

// Dart: the named imports upstream takes from node:http, node:https, node:net
// and node:tls, as aliases.
typedef Socket = net.NodeSocket;
typedef AddressInfo = net.NodeAddress;
typedef TLSSocket = tls_.TLSSocket;
final connect = net.connect;
final createNetServer = net.createServer;
final createServer = http.createServer;
final createHttpsServer = https.createServer;
final tlsConnect = tls_.connect;

// Dart: upstream's `test.skipIf(!canServeEmittedConnections)` and
// `testWithTls`, which `test` cannot alias (and whose helper takes no timeout).
final Object? _tlsSkip = canServeEmittedConnections
    ? null
    : 'TLS termination unavailable';

// Dart: the object literal upstream hands createHttpProxyServer; every
// option not named here is absent (null).
class _HttpOptions implements HttpProxyServerOptions {
  _HttpOptions({
    this.mitmCA,
    this.tlsTerminateUpstreamCA,
    this.requireHostMatch,
    this.filterRequest,
    this.maxTerminatedTunnels,
    this.tlsHandshakeTimeoutMs,
  });
  @override
  final MitmCA? mitmCA;
  @override
  final dynamic tlsTerminateUpstreamCA;
  @override
  final bool? requireHostMatch;
  @override
  final FilterRequestCallback? filterRequest;
  @override
  final int? maxTerminatedTunnels;
  @override
  final int? tlsHandshakeTimeoutMs;
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

// TLS termination in this process: a CONNECT tunnel's TLS runs on its own
// socket and the decrypted connection goes to an HTTP server that never
// listens, within the proxy's bounds on tunnels and the leaf caches.

void main() {
  // Dart: upstream's testWithTls (test/helpers/emitted-connections.ts) takes no
  // timeout or tags here, so it is this wrapper over `test`.
  void testWithTls(
    String description,
    Future<void> Function() body, {
    List<String>? tags,
  }) => test(description, body, skip: _tlsSkip, tags: tags);

  final cleanup = <FutureOr<void> Function()>[];
  tearDown(() async {
    while (cleanup.isNotEmpty) {
      await cleanup.removeLast()();
    }
  });

  /** An HTTP or HTTPS upstream that records each request's raw header lines, raw trailers and body. */
  Future<({List<Seen> seen, int port})> recordingUpstream([
    Map<String, String>? tlsOpts,
  ]) async {
    final seen = <Seen>[];
    void handler(http.IncomingMessage req, http.ServerResponse res) {
      var body = '';
      req.on(
        'data',
        (Object? c) => body += Buffer.from(c as List<int>).toString(),
      );
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

    final server = tlsOpts != null
        ? createHttpsServer(tlsOpts, handler)
        : createServer(handler);
    final listening = Completer<void>();
    server.listen(0, '127.0.0.1', () => listening.complete());
    await listening.future;
    cleanup.add(() {
      final r = Completer<void>();
      server.close(() => r.complete());
      return r.future;
    });
    return (seen: seen, port: (server.address() as AddressInfo).port);
  }

  /**
   * A proxy that terminates every tunnel, in front of an HTTPS upstream on
   * loopback, whose filterRequest allows every request and records its URL.
   */
  Future<
    ({
      ({List<Seen> seen, int port}) up,
      List<String> asked,
      Future<String> Function(String requestTarget, [String? host]) send,
      String target,
      int port,
      String ca,
    })
  >
  tlsSetup({bool? requireHostMatch}) async {
    final ca = generateCa();
    final leaf = mintLeafCert(
      createMitmCA(caCertPem: ca.certPem, caKeyPem: ca.keyPem),
      '127.0.0.1',
    );
    final leafOnly = RegExp(
      r'-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----\r?\n?',
    ).firstMatch(leaf.certPem)!.group(0)!;
    final up = await recordingUpstream({'cert': leafOnly, 'key': leaf.keyPem});
    final asked = <String>[];
    final proxy = createHttpProxyServer(
      _HttpOptions(
        mitmCA: createMitmCA(caCertPem: ca.certPem, caKeyPem: ca.keyPem),
        tlsTerminateUpstreamCA: ca.certPem,
        requireHostMatch: requireHostMatch,
        filterRequest: (request, [info]) async {
          asked.add(request.url);
          return const RequestDecision(action: 'allow');
        },
      ),
    );
    final proxyListening = Completer<void>();
    proxy.listen(0, '127.0.0.1', () => proxyListening.complete());
    await proxyListening.future;
    cleanup.add(() {
      final r = Completer<void>();
      proxy.close(() => r.complete());
      proxy.closeAllConnections();
      return r.future;
    });
    final port = (proxy.address() as AddressInfo).port;
    final target = '127.0.0.1:${up.port}';
    /** One GET in a tunnel, with Host (default: the target); the raw response. */
    Future<String> send(String requestTarget, [String? host]) {
      host ??= target;
      final resolve = Completer<String>();
      late final Socket c;
      c = connect({'port': port, 'host': '127.0.0.1'}, () {
        c.write('CONNECT $target HTTP/1.1\r\nHost: $target\r\n\r\n');
      });
      var head = '';
      late void Function(Object? x) onData;
      onData = (Object? x) {
        head += latin1.decode(x as List<int>);
        if (!head.contains('\r\n\r\n')) return;
        c.off('data', onData);
        final t = tlsConnect({
          'socket': c,
          'ca': ca.certPem,
          'checkServerIdentity': (Object? a, Object? b) => null,
          'ALPNProtocols': ['http/1.1'],
        });
        var out = '';
        t.on(
          'secureConnect',
          () => t.write(
            'GET $requestTarget HTTP/1.1\r\nHost: $host\r\nConnection: close\r\n\r\n',
          ),
        );
        t.on(
          'data',
          (Object? y) => out += Buffer.from(y as List<int>).toString(),
        );
        t.on('close', () {
          if (!resolve.isCompleted) resolve.complete(out);
        });
        t.on('error', (Object? _) {
          if (!resolve.isCompleted) resolve.complete(out);
        });
      };
      c.on('data', onData);
      c.on('error', (Object? _) {
        if (!resolve.isCompleted) resolve.complete('');
      });
      return resolve.future;
    }

    return (
      up: up,
      asked: asked,
      send: send,
      target: target,
      port: port,
      ca: ca.certPem,
    );
  }

  int statusOf(String raw) {
    final parts = raw.split(' ');
    return int.tryParse(parts.length > 1 ? parts[1] : '') ?? 0;
  }

  group('TLS termination opens nothing another process could reach', () {
    test(
      'a tunnel is terminated with no listener: no listen() from CONNECT to the end of the response',
      () async {
        final s = await tlsSetup();
        final listened = <Object?>[];
        // Every server class a listener could come from (they need not share
        // a prototype chain).
        // Dart: net, http and https servers share the one NodeServer.listen.
        net.NodeServer.listenSpy = (Object? firstArg) => listened.add(firstArg);
        cleanup.add(() => net.NodeServer.listenSpy = null);
        final raw = await s.send('/ok');
        expect(raw, startsWith('HTTP/1.1 200'));
        expect(s.up.seen.map((g) => g.url).toList(), ['/ok']);
        expect(listened, <Object?>[]);
      },
      skip: _tlsSkip,
    );
  });

  group('the terminated tunnels are capped', () {
    // Every case runs a TLS-terminating proxy: skipped where none can run.
    test(
      'past maxTerminatedTunnels, a CONNECT is answered 503 and marked too-many-tunnels',
      () async {
        final ca = generateCa();
        final mitmCA = createMitmCA(caCertPem: ca.certPem, caKeyPem: ca.keyPem);
        final proxy = createHttpProxyServer(
          _HttpOptions(mitmCA: mitmCA, maxTerminatedTunnels: 2),
        );
        final listening = Completer<void>();
        proxy.listen(0, '127.0.0.1', () => listening.complete());
        await listening.future;
        cleanup.add(() {
          final r = Completer<void>();
          proxy.close(() => r.complete());
          return r.future;
        });
        final port = (proxy.address() as AddressInfo).port;
        Future<({String head, Socket sock})> open() {
          final resolve = Completer<({String head, Socket sock})>();
          late final Socket c;
          c = connect({'port': port, 'host': '127.0.0.1'}, () {
            c.write('CONNECT a.test:443 HTTP/1.1\r\nHost: a.test:443\r\n\r\n');
          });
          c.on('error', (Object? _) {});
          var head = '';
          c.on('data', (Object? d) {
            head += latin1.decode(d as List<int>);
            if (head.contains('\r\n\r\n') && !resolve.isCompleted) {
              resolve.complete((head: head, sock: c));
            }
          });
          return resolve.future;
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
        expect(third.head, contains('X-Proxy-Error: too-many-tunnels'));
        // A slot frees when a tunnel closes.
        first.sock.destroy();
        await Future<void>.delayed(const Duration(milliseconds: 100));
        final fourth = await open();
        fourth.sock.destroy();
        expect(fourth.head, startsWith('HTTP/1.1 200'));
      },
      skip: _tlsSkip,
    );
  });

  group('the leaf caches keep the most recently used host names', () {
    test('past the limit the least recently used name goes', () {
      final ca = generateCa();
      final mitmCA = createMitmCA(caCertPem: ca.certPem, caKeyPem: ca.keyPem);
      mitmCA.cacheLimit = 2;
      mintLeafCert(mitmCA, 'a.test');
      mintLeafCert(mitmCA, 'b.test');
      mintLeafCert(mitmCA, 'a.test'); // a is now the most recent
      mintLeafCert(mitmCA, 'c.test');
      expect(mitmCA.leafCerts.keys.toList(), ['a.test', 'c.test']);
    });
  });

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
    ).firstMatch(leaf.certPem)!.group(0)!;
    var written = 0;
    final up = createHttpsServer({'cert': leafOnly, 'key': leaf.keyPem}, (
      http.IncomingMessage req_,
      http.ServerResponse res,
    ) {
      res.writeHead(200, {'content-length': size});
      final chunk = Uint8List.fromList(List.filled(64 << 10, 0x61));
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
    final upListening = Completer<void>();
    up.listen(0, '127.0.0.1', () => upListening.complete());
    await upListening.future;
    cleanup.add(() {
      final r = Completer<void>();
      up.close(() => r.complete());
      return r.future;
    });
    final target = '127.0.0.1:${(up.address() as AddressInfo).port}';
    final p = createHttpProxyServer(
      _HttpOptions(mitmCA: mitmCA, tlsTerminateUpstreamCA: ca.certPem),
    );
    final pListening = Completer<void>();
    p.listen(0, '127.0.0.1', () => pListening.complete());
    await pListening.future;
    cleanup.add(() {
      final r = Completer<void>();
      p.close(() => r.complete());
      return r.future;
    });
    final port = (p.address() as AddressInfo).port;
    var duringStall = 0;
    final resolve = Completer<int>();
    late final Socket c;
    c = connect({'port': port, 'host': '127.0.0.1'}, () {
      c.write('CONNECT $target HTTP/1.1\r\nHost: $target\r\n\r\n');
    });
    c.once('data', (Object? _) {
      final t = tlsConnect({
        'socket': c,
        'ca': ca.certPem,
        'checkServerIdentity': (Object? a, Object? b) => null,
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
      t.on('close', () {
        if (!resolve.isCompleted) resolve.complete(n);
      });
      t.on('error', (Object? _) {
        if (!resolve.isCompleted) resolve.complete(n);
      });
    });
    c.on('error', (Object? _) {
      if (!resolve.isCompleted) resolve.complete(0);
    });
    final read = await resolve.future;
    return (upstreamWroteDuringStall: duringStall, read: read, size: size);
  }

  group('a TLS-terminated response waits for a stalled client', () {
    test(
      "full mode (the runtime's own listener): the upstream is held back, and the client then gets every byte",
      () async {
        final r = await stalledClientResponse();
        expect(r.read, greaterThan(r.size));
        expect(r.read - r.size, lessThan(1024));
        // Kernel buffers and the queue caps: far below the body.
        expect(r.upstreamWroteDuringStall, lessThan(48 << 20));
      },
      skip: _tlsSkip,
      timeout: const Timeout(Duration(milliseconds: 60000)),
    );
  });

  group('a client that resets its tunnel only ends that tunnel', () {
    test(
      'a reset mid-handshake and a reset mid-request; the next tunnel is served',
      () async {
        final s = await tlsSetup();
        for (final at in ['handshake', 'request']) {
          final resolve = Completer<void>();
          late final Socket c;
          c = connect({'port': s.port, 'host': '127.0.0.1'}, () {
            c.write(
              'CONNECT ${s.target} HTTP/1.1\r\nHost: ${s.target}\r\n\r\n',
            );
          });
          c.on('error', (Object? _) {});
          c.once('data', (Object? _) {
            final t = tlsConnect({
              'socket': c,
              'ca': s.ca,
              'checkServerIdentity': (Object? a, Object? b) => null,
            });
            t.on('error', (Object? _) {});
            if (at == 'handshake') {
              Timer.run(() {
                c.resetAndDestroy();
                resolve.complete();
              });
              return;
            }
            t.on('secureConnect', () {
              t.write('GET /half HTTP/1.1\r\nHost: ${s.target}\r\n');
              setTimeout(() {
                c.resetAndDestroy();
                resolve.complete();
              }, 50);
            });
          });
          await resolve.future;
        }
        await Future<void>.delayed(const Duration(milliseconds: 200));
        expect(await s.send('/ok'), startsWith('HTTP/1.1 200'));
      },
      skip: _tlsSkip,
    );
  });

  /** One GET in a tunnel with this SNI: the raw response and the certificate's CN. */
  Future<({String raw, String? cn})> sendWithSni(
    ({int port, String target, String ca}) s,
    String servername,
  ) {
    final resolve = Completer<({String raw, String? cn})>();
    String? cn;
    late final Socket c;
    c = connect({'port': s.port, 'host': '127.0.0.1'}, () {
      c.write('CONNECT ${s.target} HTTP/1.1\r\nHost: ${s.target}\r\n\r\n');
    });
    c.on('error', (Object? _) {
      if (!resolve.isCompleted) resolve.complete((raw: '', cn: cn));
    });
    c.once('data', (Object? _) {
      final t = tlsConnect({
        'socket': c,
        'ca': s.ca,
        'servername': servername,
        'checkServerIdentity': (Object? host_, Object? cert) {
          cn = '${(cert as dynamic).subject.CN}';
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
      t.on(
        'data',
        (Object? d) => out += Buffer.from(d as List<int>).toString(),
      );
      t.on('close', () {
        if (!resolve.isCompleted) resolve.complete((raw: out, cn: cn));
      });
      t.on('error', (Object? _) {
        if (!resolve.isCompleted) resolve.complete((raw: out, cn: cn));
      });
    });
    return resolve.future;
  }

  group('the server name a tunnel is asked for', () {
    test(
      'one that cannot be read is a mismatch: 421, nothing asked or dialled',
      () async {
        final s = await tlsSetup(requireHostMatch: true);
        final r = await sendWithSni((
          port: s.port,
          target: s.target,
          ca: s.ca,
        ), 'x_front.example');
        expect(statusOf(r.raw), 421);
        expect(s.asked, hasLength(0));
        expect(s.up.seen, hasLength(0));
      },
      skip: _tlsSkip,
    );

    test(
      "with requireHostMatch the certificate is the target's whatever name is asked for",
      () async {
        final s = await tlsSetup(requireHostMatch: true);
        final r = await sendWithSni((
          port: s.port,
          target: s.target,
          ca: s.ca,
        ), 'other.example.test');
        expect(r.cn, '127.0.0.1');
        expect(statusOf(r.raw), 421);
        expect(s.up.seen, hasLength(0));
      },
      skip: _tlsSkip,
    );

    test('every leaf of a CA shares one key: a new name costs a signature', () {
      final ca = generateCa();
      final mitmCA = createMitmCA(caCertPem: ca.certPem, caKeyPem: ca.keyPem);
      final a = mintLeafCert(mitmCA, 'a.example');
      final b = mintLeafCert(mitmCA, 'b.example');
      expect(b.keyPem, a.keyPem);
      expect(b.certPem, isNot(a.certPem));
    });
  });

  /** A CONNECT to `target` on the proxy at `port`; resolves with its reply head and socket. */
  Future<({String head, Socket sock})> openConnect(int port, String target) {
    final resolve = Completer<({String head, Socket sock})>();
    late final Socket c;
    c = connect({'port': port, 'host': '127.0.0.1'}, () {
      c.write('CONNECT $target HTTP/1.1\r\nHost: $target\r\n\r\n');
    });
    c.on('error', (Object? _) {});
    var head = '';
    c.on('data', (Object? d) {
      head += latin1.decode(d as List<int>);
      if (head.contains('\r\n\r\n') && !resolve.isCompleted) {
        resolve.complete((head: head, sock: c));
      }
    });
    return resolve.future;
  }

  group('a tunnel to be terminated holds its slot only while it gets somewhere', () {
    // Every case runs a TLS-terminating proxy: skipped where none can run.
    Future<({int port, GeneratedCa ca, MitmCA mitmCA})> capped([
      Map<String, Object?> extra = const {},
    ]) async {
      final ca = generateCa();
      final mitmCA = createMitmCA(caCertPem: ca.certPem, caKeyPem: ca.keyPem);
      final proxy = createHttpProxyServer(
        _HttpOptions(
          mitmCA: mitmCA,
          tlsTerminateUpstreamCA: ca.certPem,
          maxTerminatedTunnels: 1,
          tlsHandshakeTimeoutMs:
              (extra['tlsHandshakeTimeoutMs'] as int?) ?? 300,
        ),
      );
      final listening = Completer<void>();
      proxy.listen(0, '127.0.0.1', () => listening.complete());
      await listening.future;
      cleanup.add(() {
        final r = Completer<void>();
        proxy.close(() => r.complete());
        return r.future;
      });
      return (
        port: (proxy.address() as AddressInfo).port,
        ca: ca,
        mitmCA: mitmCA,
      );
    }

    test(
      'a CONNECT that sends nothing is closed at the deadline, and its slot freed',
      () async {
        final p = await capped();
        final silent = await openConnect(p.port, 'a.test:443');
        expect(silent.head, startsWith('HTTP/1.1 200'));
        final resolve = Completer<bool>();
        silent.sock.once('close', (Object? _) {
          if (!resolve.isCompleted) resolve.complete(true);
        });
        setTimeout(() {
          if (!resolve.isCompleted) resolve.complete(false);
        }, 2000);
        final closed = await resolve.future;
        expect(closed, true);
        final next = await openConnect(p.port, 'a.test:443');
        next.sock.destroy();
        expect(next.head, startsWith('HTTP/1.1 200'));
      },
      skip: _tlsSkip,
    );

    testWithTls(
      'a tunnel that got going outlives the deadline: a request, an idle spell past it, another request',
      () async {
        final p = await capped();
        final leaf = mintLeafCert(p.mitmCA, '127.0.0.1');
        final up = await recordingUpstream({
          'cert': RegExp(
            r'-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----\r?\n?',
          ).firstMatch(leaf.certPem)!.group(0)!,
          'key': leaf.keyPem,
        });
        final target = '127.0.0.1:${up.port}';
        final resolveTls = Completer<TLSSocket>();
        unawaited(
          openConnect(p.port, target).then((conn) {
            final sock = conn.sock;
            late final TLSSocket tls;
            tls = tlsConnect({
              'socket': sock,
              'ca': p.ca.certPem,
              'checkServerIdentity': (Object? a, Object? b) => null,
            }, () => resolveTls.complete(tls));
            tls.on('error', (Object? _) {});
          }),
        );
        final t = await resolveTls.future;
        cleanup.add(() {
          t.destroy();
        });
        var out = '';
        t.on(
          'data',
          (Object? d) => out += Buffer.from(d as List<int>).toString(),
        );
        Future<void> request(String path) async {
          final before = RegExp('HTTP/1\\.1 ').allMatches(out).length;
          t.write('GET $path HTTP/1.1\r\nHost: $target\r\n\r\n');
          for (var i = 0; i < 100; i++) {
            if (RegExp('HTTP/1\\.1 200').allMatches(out).length > before) {
              return;
            }
            await Future<void>.delayed(const Duration(milliseconds: 20));
          }
        }

        await request('/first');
        await Future<void>.delayed(const Duration(milliseconds: 700));
        expect(t.destroyed, false);
        await request('/second');
        expect(up.seen.map((g) => g.url).toList(), ['/first', '/second']);
      },
    );

    test('a tunnel that turns out not to be TLS frees its slot', () async {
      final echo = createNetServer((Socket sock) => sock.pipe(sock));
      final echoListening = Completer<void>();
      echo.listen(0, '127.0.0.1', () => echoListening.complete());
      await echoListening.future;
      cleanup.add(() {
        final r = Completer<void>();
        echo.close(() => r.complete());
        return r.future;
      });
      final target = '127.0.0.1:${(echo.address() as AddressInfo).port}';
      final p = await capped();
      final plain = await openConnect(p.port, target);
      cleanup.add(() {
        plain.sock.destroy();
      });
      plain.sock.write('SSH-2.0-test\r\n');
      await Future<void>.delayed(const Duration(milliseconds: 100));
      final next = await openConnect(p.port, target);
      next.sock.destroy();
      expect(next.head, startsWith('HTTP/1.1 200'));
    }, skip: _tlsSkip);

    test(
      'a tunnel whose TLS setup throws is closed, and the proxy keeps serving',
      () async {
        final p = await capped({'tlsHandshakeTimeoutMs': 5000});
        // Minting a leaf now fails.
        p.mitmCA.keyPem = 'not a key';
        final broken = await openConnect(p.port, 'never-minted.test:443');
        final closedC = Completer<void>();
        broken.sock.once('close', (Object? _) => closedC.complete());
        final t = tlsConnect({
          'socket': broken.sock,
          'servername': 'never-minted.test',
          'rejectUnauthorized': false,
        });
        t.on('error', (Object? _) {});
        await closedC.future;
        final next = await openConnect(p.port, 'a.test:443');
        next.sock.destroy();
        expect(next.head, startsWith('HTTP/1.1 200'));
      },
      skip: _tlsSkip,
    );
  });
}

typedef Seen = ({
  String url,
  List<String> rawHeaders,
  List<String> rawTrailers,
  String body,
});
