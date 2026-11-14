// Ported from sandbox-runtime test/sandbox/proxy-only-whole.test.ts @ 0bbebed.
library;

// ignore_for_file: library_prefixes, slash_for_doc_comments, prefer_interpolation_to_compose_strings
import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:sandbox_runtime/src/node/http.dart' as http;
import 'package:sandbox_runtime/src/node/net.dart' as net;
import 'package:sandbox_runtime/src/node/stream.dart' show PassThrough;
import 'package:sandbox_runtime/src/node/url.dart' show URL;
import 'package:sandbox_runtime/src/sandbox/decider_client.dart'
    as deciderClient;
import 'package:sandbox_runtime/src/sandbox/proxy_only.dart';
import 'package:test/test.dart';

typedef Frame = Map<String, Object?>;

final cleanup = <FutureOr<Object?> Function()>[];

/** A decider on a pair of streams that does nothing on its own. */
({
  ({PassThrough input, PassThrough output}) streams,
  List<Frame> seen,
  void Function(Frame m) send,
  void Function() end,
  void Function(void Function(Frame f) fn) onFrame,
  void Function() stopReading,
})
manualDecider() {
  final toProxy = PassThrough();
  final fromProxy = PassThrough();
  final seen = <Frame>[];
  void Function(Frame f) onFrame = (f) {};
  var buf = Uint8List(0);
  void read(Object? chunk) {
    final c = chunk as List<int>;
    buf = Uint8List.fromList([...buf, ...c]);
    while (buf.length >= 4 &&
        buf.length >= 4 + ByteData.sublistView(buf).getUint32(0, Endian.big)) {
      final n = ByteData.sublistView(buf).getUint32(0, Endian.big);
      final f =
          jsonDecode(utf8.decode(buf.sublist(4, 4 + n)))
              as Map<String, Object?>;
      buf = Uint8List.fromList(buf.sublist(4 + n));
      seen.add(f);
      onFrame(f);
    }
  }

  fromProxy.on('data', read);
  return (
    streams: (input: toProxy, output: fromProxy),
    seen: seen,
    send: (Frame m) {
      final b = Uint8List.fromList(utf8.encode(jsonEncode(m)));
      final n = ByteData(4)..setUint32(0, b.length, Endian.big);
      toProxy.write(Uint8List.fromList([...n.buffer.asUint8List(), ...b]));
    },
    end: () {
      toProxy.end();
    },
    onFrame: (void Function(Frame f) fn) {
      onFrame = fn;
    },
    /** Keep the stream open and never take another byte from it. */
    stopReading: () {
      fromProxy.off('data', read);
      fromProxy.pause();
    },
  );
}

Future<
  ({
    int port,
    List<({String url, String body})> got,
    int Function() connections,
  })
>
upstream() async {
  final got = <({String url, String body})>[];
  var connections = 0;
  final http.NodeHttpServer server = http.createServer((
    http.IncomingMessage req,
    http.ServerResponse res,
  ) {
    var body = '';
    req.on('data', (Object? c) => body += utf8.decode(c as List<int>));
    req.on('end', () {
      got.add((url: req.url ?? '', body: body));
      res.end('upstream ok');
    });
  });
  server.on('connection', () => connections++);
  final listening = Completer<void>();
  server.listen(0, '127.0.0.1', () => listening.complete());
  await listening.future;
  cleanup.add(() {
    final r = Completer<void>();
    server.close(() => r.complete());
    return r.future;
  });
  final port = (server.address() as net.NodeAddress).port;
  return (port: port, got: got, connections: () => connections);
}

/** A loopback port nothing listens on (taken, then given back). */
Future<int> freePort() async {
  final s = net.createServer();
  final listening = Completer<void>();
  s.listen(0, '127.0.0.1', () => listening.complete());
  await listening.future;
  final port = (s.address() as net.NodeAddress).port;
  final closed = Completer<void>();
  s.close(() => closed.complete());
  await closed.future;
  return port;
}

/** One absolute-form request over a raw socket; the whole response text. */
Future<String> request(
  int proxyPort,
  String target, [
  ({String? body, Map<String, String>? headers}) opts = (
    body: null,
    headers: null,
  ),
]) {
  final completer = Completer<String>();
  void resolve(String v) {
    if (!completer.isCompleted) completer.complete(v);
  }

  final sock = net.connect(proxyPort, '127.0.0.1');
  var out = '';
  sock.on('data', (Object? c) => out += utf8.decode(c as List<int>));
  sock.on('close', (_) => resolve(out));
  // A connection the stopping proxy drops unanswered reads as a reset.
  sock.on('error', (_) => resolve(out.isNotEmpty ? out : 'reset'));
  final body = opts.body ?? '';
  final headers = <String, String>{
    'host': URL(target).host,
    'connection': 'close',
    ...(opts.body == null
        ? {}
        : {'content-length': '${utf8.encode(body).length}'}),
    ...?opts.headers,
  };
  sock.write(
    '${opts.body == null ? 'GET' : 'POST'} $target HTTP/1.1\r\n' +
        headers.entries.map((e) => '${e.key}: ${e.value}\r\n').join('') +
        '\r\n' +
        body,
  );
  return completer.future;
}

Future<String> refused(int port) {
  final completer = Completer<String>();
  final sock = net.connect(port, '127.0.0.1');
  sock.on('connect', (_) {
    sock.destroy();
    completer.complete('connected');
  });
  sock.on('error', (Object e) {
    if (!completer.isCompleted) {
      completer.complete((e as dynamic).code as String? ?? 'error');
    }
  });
  return completer.future;
}

({ProxyOnly proxy, List<String> closed, Future<String> whenStopped}) start(
  ({
    ({PassThrough input, PassThrough output}) streams,
    List<Frame> seen,
    void Function(Frame m) send,
    void Function() end,
    void Function(void Function(Frame f) fn) onFrame,
    void Function() stopReading,
  })
  d,
  int listenPort, [
  int deciderTimeoutMs = 5000,
]) {
  final closed = <String>[];
  late void Function(String why) stopped;
  final stoppedFuture = Completer<String>();
  stopped = (why) => stoppedFuture.complete(why);
  final whenStopped = stoppedFuture.future;
  final proxy = startProxyOnly(
    ProxyOnlyOptions(
      listen: ProxyListenHostPort(host: '127.0.0.1', port: listenPort),
      decider: d.streams,
      deciderTimeoutMs: deciderTimeoutMs,
      onClosed: (why) {
        closed.add(why);
        stopped(why);
      },
    ),
  );
  cleanup.add(() => proxy.close());
  return (proxy: proxy, closed: closed, whenStopped: whenStopped);
}

/** Limits reach the decider client only as createDecider options. */
void withDeciderLimits({int? maxBodyBytesHeld, int? maxQueuedBytes}) {
  final real = deciderClient.createDecider;
  deciderClient.createDecider = (o) => real(
    deciderClient.DeciderOptions(
      input: o.input,
      output: o.output,
      timeoutMs: o.timeoutMs,
      credentialPlacements: o.credentialPlacements,
      onDead: o.onDead,
      maxBodyBytesHeld: maxBodyBytesHeld ?? o.maxBodyBytesHeld,
      maxQueuedBytes: maxQueuedBytes ?? o.maxQueuedBytes,
    ),
  );
  cleanup.add(() => deciderClient.createDecider = real);
}

void main() {
  tearDown(() async {
    while (cleanup.isNotEmpty) {
      await cleanup.removeLast()();
    }
  });

  group('the whole proxy: start-up order and decider limits', () {
    test(
      'nothing listens until the decider has said hello; then requests are served',
      () async {
        final up = await upstream();
        final port = await freePort();
        final d = manualDecider();
        final firstFrame = Completer<Frame>();
        d.onFrame(firstFrame.complete);
        final (:proxy, closed: _, whenStopped: _) = start(d, port);

        expect(await firstFrame.future, {'t': 'hello', 'proto': 1});
        expect(await refused(port), 'ECONNREFUSED');
        expect(proxy.listener.listening, false);
        expect(up.connections(), 0);
        expect(d.seen, hasLength(1));

        d.onFrame(
          (f) => d.send({'t': 'verdict', 'id': f['id'], 'action': 'allow'}),
        );
        d.send({
          't': 'hello',
          'proto': 1,
          'allowedDomains': ['127.0.0.1:${up.port}'],
          'deniedDomains': [],
        });
        await proxy.ready;
        final res = await request(port, 'http://127.0.0.1:${up.port}/after');
        expect(res, startsWith('HTTP/1.1 200'));
        expect(up.got.map((g) => g.url).toList(), ['/after']);
        expect(d.seen.map((f) => f['t']).toList(), ['hello', 'req']);
      },
    );

    test(
      'a hello of another protocol version, or a decider that leaves without one, fails the start and never listens',
      () async {
        for (final badHello in [true, false]) {
          final port = await freePort();
          final d = manualDecider();
          final firstFrame = Completer<Frame>();
          d.onFrame(firstFrame.complete);
          final (:proxy, closed: _, :whenStopped) = start(d, port);
          await firstFrame.future;
          // There is no deadline for the hello itself: until it comes, or the
          // decider's stream ends, the proxy waits without listening.
          expect(proxy.listener.listening, false);
          if (badHello) {
            d.send({
              't': 'hello',
              'proto': 2,
              'allowedDomains': [],
              'deniedDomains': [],
            });
          } else {
            d.end();
          }
          final err = await proxy.ready.then<Object?>(
            (_) => null,
            onError: (Object e) => e,
          );
          expect(
            (err as dynamic)?.message,
            matches(
              badHello
                  ? RegExp(r'^decider unavailable: bad hello$')
                  : RegExp(r'^decider unavailable: '),
            ),
          );
          expect(
            await whenStopped,
            matches(
              badHello
                  ? RegExp(r'^decider: bad hello$')
                  : RegExp(r'^decider: '),
            ),
          );
          expect(proxy.listener.listening, false);
          expect(await refused(port), 'ECONNREFUSED');
          expect(d.seen.map((f) => f['t']).toList(), ['hello']);
        }
      },
    );

    test(
      'body inspection past the held-body budget is refused 503 and dials nothing; the budget is released',
      () async {
        const max = 2048;
        withDeciderLimits(maxBodyBytesHeld: 2 * max);
        final up = await upstream();
        final d = manualDecider();
        final gate = Completer<void>();
        void release() => gate.complete();
        var asked = 0;
        final threeAsked = Completer<void>();
        void allAsked() => threeAsked.complete();
        d.onFrame((f) {
          if (f['t'] == 'hello') {
            d.send({
              't': 'hello',
              'proto': 1,
              'allowedDomains': ['127.0.0.1:${up.port}'],
              'deniedDomains': [],
            });
          } else if (f['t'] == 'req') {
            d.send({
              't': 'verdict',
              'id': f['id'],
              'action': 'need_body',
              'max': max,
            });
            if (++asked == 3) allAsked();
          } else {
            unawaited(
              gate.future.then(
                (_) =>
                    d.send({'t': 'verdict', 'id': f['id'], 'action': 'allow'}),
              ),
            );
          }
        });
        final (:proxy, closed: _, whenStopped: _) = start(d, 0);
        await proxy.ready;
        final port = (proxy.listener.address() as net.NodeAddress).port;
        Future<String> post(int n) => request(
          port,
          'http://127.0.0.1:${up.port}/p$n',
          (body: '$n' * 1500, headers: null),
        );

        final pending = [post(1), post(2), post(3)];
        await threeAsked.future;
        // The one over the budget is answered while the other two are held.
        final over = await Future.any(pending);
        expect(over, startsWith('HTTP/1.1 503'));
        expect(over, contains('decider_unavailable'));
        expect(up.connections(), 0);

        release();
        final all = await Future.wait(pending);
        expect(
          all.where((r) => r.startsWith('HTTP/1.1 200')).toList(),
          hasLength(2),
        );
        expect(
          all.where((r) => r.startsWith('HTTP/1.1 503')).toList(),
          hasLength(1),
        );
        expect(up.got, hasLength(2));
        expect(up.connections(), 2);
        for (final g in up.got) {
          expect(g.body, g.url[2] * 1500);
        }

        expect(await post(4), startsWith('HTTP/1.1 200'));
        expect(up.got.last, (url: '/p4', body: '4' * 1500));
      },
    );

    test(
      'a decider that stops reading stops the proxy; requests in flight are refused and none is dialled',
      () async {
        withDeciderLimits(maxQueuedBytes: 64 * 1024);
        final up = await upstream();
        final d = manualDecider();
        d.onFrame((_) {
          d.stopReading();
          d.send({
            't': 'hello',
            'proto': 1,
            'allowedDomains': ['127.0.0.1:${up.port}'],
            'deniedDomains': [],
          });
        });
        final (:proxy, closed: _, :whenStopped) = start(d, 0);
        await proxy.ready;
        final port = (proxy.listener.address() as net.NodeAddress).port;

        final pending = List.generate(
          24,
          (i) => request(port, 'http://127.0.0.1:${up.port}/q$i', (
            body: null,
            headers: {'x-fill': 'f' * 8000},
          )),
        );
        expect(
          await whenStopped,
          matches(RegExp(r'^decider: not reading: \d+ bytes queued$')),
        );
        final all = await Future.wait(pending);
        // Those the decider client had taken are answered 503; a connection the
        // stopping proxy had not got to is dropped. Nothing gets a 2xx.
        final answered = all.where((r) => r != 'reset').toList();
        expect(answered.length, greaterThan(0));
        for (final r in answered) {
          expect(r, startsWith('HTTP/1.1 503'));
          expect(r, contains('decider_unavailable'));
        }
        expect(up.connections(), 0);
        expect(up.got, hasLength(0));
      },
    );
  });
}
