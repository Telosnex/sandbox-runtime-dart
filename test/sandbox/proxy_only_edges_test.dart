// Ported from sandbox-runtime test/sandbox/proxy-only-edges.test.ts @ 24eb39e.
// ignore_for_file: constant_identifier_names, non_constant_identifier_names, prefer_interpolation_to_compose_strings, slash_for_doc_comments
import 'dart:async';
import 'dart:convert';

import 'package:sandbox_runtime/src/node/globals.dart' as globals;
import 'package:sandbox_runtime/src/node/http.dart' as http;
import 'package:sandbox_runtime/src/node/https.dart' as https;
import 'package:sandbox_runtime/src/node/net.dart' as net;
import 'package:sandbox_runtime/src/node/stream.dart' as stream;
import 'package:sandbox_runtime/src/node/tls.dart' as tls;
import 'package:sandbox_runtime/src/sandbox/mitm_ca.dart';
import 'package:sandbox_runtime/src/sandbox/mitm_leaf.dart';
import 'package:sandbox_runtime/src/sandbox/proxy_only.dart';
import 'package:test/test.dart';

import '../helpers/emitted_connections.dart'
    show SERVES_EMITTED_CONNECTIONS, testWithTls;
import '../helpers/fake_decider.dart' show Frame, fakeDecider;

typedef Path = String; // 'tls' | 'plain'

/** A tunnel is terminated only where the runtime can do it in-process. */
bool cannotServe(Path path) => path == 'tls' && !SERVES_EMITTED_CONNECTIONS;

/**
 * A proxy-only proxy in front of an upstream on loopback (HTTPS with a leaf
 * of the proxy's CA, or plain HTTP), and a way to open a connection to it
 * that is ready for a request: a TLS-terminated tunnel, or the bare socket.
 */
Future<
  ({
    Map<String, Object> d,
    int port,
    String target,
    Future<net.NodeSocket> Function() open,
    String Function(String p) requestTarget,
  })
>
serve({
  required Path path,
  required Function handler,
  required Object Function(Frame f) decide,
  List<String> deniedDomains = const [],
}) async {
  final ca = generateCa();
  http.NodeHttpServer up;
  if (path == 'tls') {
    final leaf = mintLeafCert(
      createMitmCA(caCertPem: ca.certPem, caKeyPem: ca.keyPem),
      '127.0.0.1',
    );
    final leafOnly = RegExp(
      r'-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----\r?\n?',
    ).firstMatch(leaf.certPem)!.group(0)!;
    up = https.createServer({'cert': leafOnly, 'key': leaf.keyPem}, handler);
  } else {
    up = http.createServer(handler);
  }
  final upListening = Completer<void>();
  up.listen(0, '127.0.0.1', () => upListening.complete());
  await upListening.future;
  cleanup.add(() {
    final r = Completer<void>();
    up.close(() => r.complete());
    up.closeAllConnections();
    return r.future;
  });
  final target = '127.0.0.1:${(up.address() as net.NodeAddress).port}';
  final d = fakeDecider(
    [target, 'denied.test:443'],
    decide,
    deniedDomains: deniedDomains,
  );
  final streams = d['streams'] as Map;
  final proxy = startProxyOnly(
    ProxyOnlyOptions(
      listen: const ProxyListenHostPort(host: '127.0.0.1', port: 0),
      decider: (
        input: streams['input'] as stream.Readable,
        output: streams['output'] as stream.Writable,
      ),
      // Only a tunnel needs the CA, and a proxy given one starts only where
      // the runtime can terminate TLS in-process.
      caPem: path == 'tls' ? ca.keyPem + ca.certPem : null,
      upstreamCA: path == 'tls' ? ca.certPem : null,
      deciderTimeoutMs: 1000,
    ),
  );
  cleanup.add(() => proxy.close());
  await proxy.ready;
  final port = (proxy.listener.address() as net.NodeAddress).port;
  /** For the plain path the request-target is absolute. */
  String requestTarget(String p) => path == 'tls' ? p : 'http://$target$p';
  Future<net.NodeSocket> open() {
    final completer = Completer<net.NodeSocket>();
    late final net.NodeSocket c;
    c = net.connect({'port': port, 'host': '127.0.0.1'}, () {
      if (path == 'plain') {
        completer.complete(c);
        return;
      }
      c.write('CONNECT $target HTTP/1.1\r\nHost: $target\r\n\r\n');
    });
    c.on('error', (Object e) {
      if (!completer.isCompleted) completer.completeError(e);
    });
    if (path == 'plain') return completer.future;
    var head = '';
    void onData(Object? x) {
      head += latin1.decode(x as List<int>);
      if (!head.contains('\r\n\r\n')) return;
      c.off('data', onData);
      final t = tls.connect({
        'socket': c,
        'ca': ca.certPem,
        'checkServerIdentity': (Object? a, Object? b) => null,
        'ALPNProtocols': ['http/1.1'],
      });
      // Dart: a Promise settles once; a Completer throws on the second.
      t.on('error', (Object e) {
        if (!completer.isCompleted) completer.completeError(e);
      });
      t.once('secureConnect', () {
        if (!completer.isCompleted) completer.complete(t);
      });
    }

    c.on('data', onData);
    return completer.future;
  }

  return (
    d: d,
    port: port,
    target: target,
    open: open,
    requestTarget: requestTarget,
  );
}

/** Everything a connection sends until it closes. */
Future<String> readAll(net.NodeSocket s) {
  final completer = Completer<String>();
  var out = '';
  // Dart: a Promise settles once; Completer.complete throws the second time.
  void resolve() {
    if (!completer.isCompleted) completer.complete(out);
  }

  s.on('data', (Object? x) => out += latin1.decode(x as List<int>));
  s.on('close', resolve);
  s.on('error', (_) => resolve());
  return completer.future;
}

final cleanup = <FutureOr<void> Function()>[];

void main() {
  tearDown(() async {
    while (cleanup.isNotEmpty) {
      await cleanup.removeLast()();
    }
  });

  group('a deny while the body is still arriving', () {
    // The decider answers in the same turn it is asked, and the client keeps
    // uploading after the answer. In a TLS-terminated tunnel the rest of the
    // body must be drained, not fed into the stream the decider would have
    // read the body from (Bun throws on that, uncaught, which ends the proxy).
    // The plain case passes without that drain, so it is not a regression
    // test for it: it checks only what the client and the next request see.
    for (final path in ['tls', 'plain']) {
      test(
        '$path: the client gets the whole deny, and the proxy keeps serving',
        () async {
          var upstreamHit = false;
          final s = await serve(
            path: path,
            handler: (http.IncomingMessage _, http.ServerResponse res) {
              upstreamHit = true;
              res.end('ok');
            },
            decide: (f) => '${f['path']}' == '/x'
                ? {
                    'action': 'deny',
                    'status': 403,
                    'reason': 'denied for the test',
                  }
                : {'action': 'allow'},
          );
          final sock = await s.open();
          final reply = readAll(sock);
          sock.write(
            'POST ${s.requestTarget('/x')} HTTP/1.1\r\nHost: ${s.target}\r\nContent-Length: 200000\r\n\r\n' +
                'a' * 1000,
          );
          for (var i = 1; i <= 20; i++) {
            globals.setTimeout(() {
              if (!sock.destroyed) sock.write('b' * 9950);
            }, i * 10);
          }
          final raw = await reply;
          expect(raw, startsWith('HTTP/1.1 403'));
          expect(raw, contains('denied for the test'));
          expect(upstreamHit, false);
          // The same proxy still answers.
          final again = await s.open();
          final next = readAll(again);
          again.write(
            'GET ${s.requestTarget('/y')} HTTP/1.1\r\nHost: ${s.target}\r\nConnection: close\r\n\r\n',
          );
          expect(await next, startsWith('HTTP/1.1 200'));
        },
        skip: cannotServe(path) ? 'TLS termination unavailable' : null,
      );
    }
  });

  group('a streamed response reaches the client as the upstream sends it', () {
    // Server-sent events, as a streaming API sends them: nothing may be held
    // back until more arrives or the response ends.
    for (final path in ['tls', 'plain']) {
      test(
        '$path: each event arrives before the next is sent',
        () async {
          const EVENTS = 5;
          // No clock decides this: the upstream sends an event only once the
          // client has the one before it, and gives up on a client that does not
          // get it. A proxy that held an event back would end the stream short.
          const GIVE_UP_MS = 5000;
          final arrived = <void Function()>[];
          final arrivals = List.generate(EVENTS, (_) {
            final c = Completer<void>();
            arrived.add(() => c.complete());
            return c.future;
          });
          var sent = 0;
          final sentOnArrival = <int>[];
          final s = await serve(
            path: path,
            handler: (http.IncomingMessage _, http.ServerResponse res) async {
              res.writeHead(200, {'content-type': 'text/event-stream'});
              for (var n = 0; n < EVENTS; n++) {
                res.write('data: $n\n\n');
                sent++;
                globals.Timeout? timer;
                final got = await Future.any([
                  arrivals[n].then((_) => true),
                  () {
                    final c = Completer<bool>();
                    timer = globals.setTimeout(
                      () => c.complete(false),
                      GIVE_UP_MS,
                    );
                    return c.future;
                  }(),
                ]);
                globals.clearTimeout(timer);
                if (!got) break;
              }
              res.end();
            },
            decide: (_) => {'action': 'allow'},
          );
          final sock = await s.open();
          var seen = '';
          sock.on('data', (Object? x) {
            seen += latin1.decode(x as List<int>);
            while (seen.contains('data: ${sentOnArrival.length}\n\n')) {
              sentOnArrival.add(sent);
              arrived[sentOnArrival.length - 1]();
            }
          });
          final done = readAll(sock);
          sock.write(
            'GET ${s.requestTarget('/events')} HTTP/1.1\r\nHost: ${s.target}\r\nConnection: close\r\n\r\n',
          );
          await done;
          // Event n arrived when n + 1 events had been sent, the next one not yet.
          expect(sentOnArrival, List.generate(EVENTS, (n) => n + 1));
        },
        skip: cannotServe(path) ? 'TLS termination unavailable' : null,
        timeout: const Timeout(Duration(milliseconds: 15000)),
      );
    }
  });

  group("the decider's denied entries", () {
    testWithTls(
      'a CONNECT to a denied entry is refused 403, unasked, even when an allowed entry covers it',
      () async {
        final s = await serve(
          path: 'tls',
          handler: (http.IncomingMessage _, http.ServerResponse res) =>
              res.end('ok'),
          decide: (_) => {'action': 'allow'},
          deniedDomains: ['denied.test:443'],
        );
        final c = net.connect({'port': s.port, 'host': '127.0.0.1'});
        final reply = readAll(c);
        c.write(
          'CONNECT denied.test:443 HTTP/1.1\r\nHost: denied.test:443\r\n\r\n',
        );
        final raw = await reply;
        expect(raw, startsWith('HTTP/1.1 403'));
        expect(raw.toLowerCase(), contains('x-deny-reason: host_not_allowed'));
        expect(
          (s.d['seen'] as List<Frame>).where((Frame f) => f['t'] == 'req'),
          hasLength(0),
        );
      },
    );
  });

  group('an allow that sets a header to several values', () {
    test('tls: every value reaches the upstream, in order', () async {
      var seen = <String>[];
      final s = await serve(
        path: 'tls',
        handler: (http.IncomingMessage req, http.ServerResponse res) {
          seen = [
            for (final (i, v) in req.rawHeaders.indexed)
              if (i % 2 == 1 && req.rawHeaders[i - 1].toLowerCase() == 'x-beta')
                v,
          ];
          res.end('ok');
        },
        decide: (_) => {
          'action': 'allow',
          'setHeaders': {
            'x-beta': ['one', 'two'],
          },
        },
      );
      final sock = await s.open();
      final reply = readAll(sock);
      sock.write(
        'GET /x HTTP/1.1\r\nHost: ${s.target}\r\nX-Beta: guest\r\nConnection: close\r\n\r\n',
      );
      expect(await reply, startsWith('HTTP/1.1 200'));
      expect(seen, ['one', 'two']);
    }, skip: cannotServe('tls') ? 'TLS termination unavailable' : null);
  });

  group('TRACE inside a terminated tunnel', () {
    test(
      'is refused 405 before the decider or the upstream sees it, and a new tunnel still works',
      () async {
        final reached = <String>[];
        final s = await serve(
          path: 'tls',
          handler: (http.IncomingMessage req, http.ServerResponse res) {
            reached.add(req.method ?? '');
            res.end('ok');
          },
          decide: (f) => {'t': 'verdict', 'id': f['id'], 'action': 'allow'},
        );
        List<Object?> requests() => (s.d['seen'] as List<Frame>)
            .where((f) => f['t'] == 'req')
            .map((f) => f['method'])
            .toList();

        final first = await s.open();
        final before = requests();
        first.write('TRACE /x HTTP/1.1\r\nHost: ${s.target}\r\n\r\n');
        // The proxy ends the connection once its own refusal has flushed, as
        // it does after its other refusals; readAll resolves only because it
        // does, so a further request needs a new tunnel.
        final refused = await readAll(first);
        expect(refused, matches(RegExp(r'^HTTP/1\.1 405 ')));
        expect(refused, contains('method_refused'));
        expect(requests(), before);
        expect(reached, []);

        final second = await s.open();
        second.write(
          'GET /x HTTP/1.1\r\nHost: ${s.target}\r\nConnection: close\r\n\r\n',
        );
        expect(await readAll(second), matches(RegExp(r'^HTTP/1\.1 200 ')));
        expect(requests(), [...before, 'GET']);
        expect(reached, ['GET']);
      },
      skip: cannotServe('tls') ? 'TLS termination unavailable' : null,
    );
  });
}
