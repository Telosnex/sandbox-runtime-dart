// Ported from sandbox-runtime test/sandbox/proxy-only-methods.test.ts @ 24eb39e.
// ignore_for_file: slash_for_doc_comments, curly_braces_in_flow_control_structures
import 'dart:async';
import 'dart:convert';

import 'package:sandbox_runtime/src/node/http.dart' as http;
import 'package:sandbox_runtime/src/node/net.dart';
import 'package:sandbox_runtime/src/node/stream.dart' show PassThrough;
import 'package:sandbox_runtime/src/node/stream.dart' as stream;
import 'package:sandbox_runtime/src/sandbox/proxy_only.dart';
import 'package:test/test.dart';

import '../helpers/fake_decider.dart';

final List<FutureOr<Object?> Function()> cleanup = [];

Future<
  ({
    List<Map<String, String>> requests,
    Future<NodeSocket> Function() open,
    String Function(String method) head,
    List<Frame> Function(String t) frames,
  })
>
setup(Object Function(Frame f) decide) async {
  final requests = <Map<String, String>>[];
  final server = http.createServer((
    http.IncomingMessage req,
    http.ServerResponse res,
  ) {
    var body = '';
    req.on('data', (Object c) => body += utf8.decode(c as List<int>));
    req.on('end', () {
      requests.add({'method': req.method ?? '', 'body': body});
      res.end('ok');
    });
  });
  final listening = Completer<void>();
  server.listen(0, '127.0.0.1', () => listening.complete());
  await listening.future;
  cleanup.add(() {
    final r = Completer<void>();
    server.close(() => r.complete());
    return r.future;
  });
  final upPort = (server.address() as NodeAddress).port;
  final d = fakeDecider(['127.0.0.1:$upPort'], decide);
  final proxy = startProxyOnly(
    ProxyOnlyOptions(
      listen: const ProxyListenHostPort(host: '127.0.0.1', port: 0),
      decider: (
        input:
            (d['streams']! as Map<String, Object>)['input']! as stream.Readable,
        output:
            (d['streams']! as Map<String, Object>)['output']!
                as stream.Writable,
      ),
      lifeline: PassThrough(),
      deciderTimeoutMs: 2000,
      stripResponseHeaders: [],
      onClosed: (_) {},
    ),
  );
  cleanup.add(() => proxy.close());
  await proxy.ready;
  final port = (proxy.listener.address() as NodeAddress).port;
  Future<NodeSocket> open() async {
    final sock = connect(port, '127.0.0.1');
    cleanup.add(() => sock.destroy());
    final c = Completer<void>();
    sock.once('connect', () => c.complete());
    await c.future;
    return sock;
  }

  String head(String method) =>
      '$method http://127.0.0.1:$upPort/x HTTP/1.1\r\nHost: 127.0.0.1:$upPort\r\n';
  List<Frame> frames(String t) =>
      (d['seen']! as List<Frame>).where((f) => f['t'] == t).toList();
  return (requests: requests, open: open, head: head, frames: frames);
}

/** Writes one request and resolves with the whole response to it. */
Future<String> exchange(NodeSocket sock, String raw) {
  final completer = Completer<String>();
  var buf = '';
  late void Function(Object) onData;
  onData = (Object c) {
    buf += latin1.decode(c as List<int>);
    final end = buf.indexOf('\r\n\r\n');
    if (end < 0) return;
    final length = int.parse(
      RegExp(
            r'^content-length:\s*(\d+)',
            caseSensitive: false,
            multiLine: true,
          ).firstMatch(buf)?.group(1) ??
          '0',
    );
    if (buf.length - (end + 4) < length) return;
    sock.off('data', onData);
    completer.complete(buf);
  };
  sock.on('data', onData);
  sock.once('close', () {
    if (!completer.isCompleted) {
      completer.completeError(Exception('closed after: $buf'));
    }
  });
  sock.write(raw);
  return completer.future;
}

Frame allow(Frame f) => {'t': 'verdict', 'id': f['id'], 'action': 'allow'};

void main() {
  tearDown(() async {
    for (final f in cleanup.reversed.toList()) {
      await f();
    }
    cleanup.clear();
  });

  group('methods the proxy refuses itself', () {
    // The runtime's HTTP parser may reject TRACK as an unknown method (400)
    // before the proxy's own rule (405) is reached; both are refusals.
    for (final (method, status) in [
      ('TRACE', RegExp(r'^HTTP/1\.1 405 ')),
      ('TRACK', RegExp(r'^HTTP/1\.1 (405|400) ')),
    ])
      test(
        '$method over plain HTTP is refused before the decider or the upstream sees it',
        () async {
          final s = await setup(allow);
          final refused = await exchange(
            await s.open(),
            '${s.head(method)}\r\n',
          );
          expect(refused, matches(status));
          if (method == 'TRACE') expect(refused, contains('method_refused'));
          expect(s.frames('req'), hasLength(0));
          expect(s.requests, hasLength(0));
          // The refusal closes its connection; the proxy keeps serving.
          final next = await exchange(await s.open(), '${s.head('GET')}\r\n');
          expect(next, startsWith('HTTP/1.1 200 '));
          expect(s.frames('req'), hasLength(1));
          expect(
            s.requests,
            equals([
              {'method': 'GET', 'body': ''},
            ]),
          );
        },
      );
  });

  group('a body on a method that normally has none', () {
    // Asks for the body of every request, then allows whatever it is shown.
    Object askThenAllow(Frame f) => f['t'] == 'req'
        ? {'t': 'verdict', 'id': f['id'], 'action': 'need_body', 'max': 1024}
        : f['t'] == 'body'
        ? allow(f)
        : 'hang';
    List<String> shown(({List<Frame> Function(String t) frames}) s) => s
        .frames('body')
        .map((f) => utf8.decode(base64.decode(f['data'].toString())))
        .toList();

    for (final method in ['GET', 'HEAD', 'OPTIONS'])
      for (final (framing, tail) in [
        ('Content-Length', 'Content-Length: 5\r\n\r\nhello'),
        (
          'chunked',
          'Transfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n',
        ),
      ])
        test(
          '$method with a $framing body is refused when the decider asks to see the body',
          () async {
            final s = await setup(askThenAllow);
            final refused = await exchange(
              await s.open(),
              '${s.head(method)}$tail',
            );
            expect(refused, startsWith('HTTP/1.1 403 '));
            expect(refused, contains('bodyless_method_body'));
            // Nothing went upstream, and the decider was never shown a body
            // that was not the request's.
            expect(s.requests, hasLength(0));
            expect(s.frames('req'), hasLength(1));
            expect(s.frames('body'), hasLength(0));
          },
        );

    for (final (name, tail) in [
      ('no body', '\r\n'),
      ('Content-Length: 0', 'Content-Length: 0\r\n\r\n'),
      ('an empty chunked body', 'Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n'),
    ])
      test(
        'GET with $name still shows the decider an empty complete body and its allow is honoured',
        () async {
          final s = await setup(askThenAllow);
          final ok = await exchange(await s.open(), '${s.head('GET')}$tail');
          expect(ok, startsWith('HTTP/1.1 200 '));
          expect(shown((frames: s.frames)), equals(['']));
          expect(s.frames('body')[0]['cut'], isNull);
          expect(
            s.requests,
            equals([
              {'method': 'GET', 'body': ''},
            ]),
          );
        },
      );

    test(
      'GET with a body is forwarded as before when the decider allows without asking for it',
      () async {
        final s = await setup(allow);
        final ok = await exchange(
          await s.open(),
          '${s.head('GET')}Content-Length: 5\r\n\r\nhello',
        );
        expect(ok, startsWith('HTTP/1.1 200 '));
        expect(s.frames('body'), hasLength(0));
        expect(
          s.requests,
          equals([
            {'method': 'GET', 'body': 'hello'},
          ]),
        );
      },
    );

    test(
      'GET with a body is denied as before when the decider denies without asking for it',
      () async {
        final s = await setup(
          (f) => {
            't': 'verdict',
            'id': f['id'],
            'action': 'deny',
            'status': 403,
          },
        );
        final denied = await exchange(
          await s.open(),
          '${s.head('GET')}Content-Length: 5\r\n\r\nhello',
        );
        expect(denied, startsWith('HTTP/1.1 403 '));
        expect(denied, isNot(contains('bodyless_method_body')));
        expect(s.requests, hasLength(0));
      },
    );

    test(
      'POST is unchanged: the decider is shown the body and its allow forwards it',
      () async {
        final s = await setup(askThenAllow);
        final ok = await exchange(
          await s.open(),
          '${s.head('POST')}Content-Length: 5\r\n\r\nhello',
        );
        expect(ok, startsWith('HTTP/1.1 200 '));
        expect(shown((frames: s.frames)), equals(['hello']));
        expect(
          s.requests,
          equals([
            {'method': 'POST', 'body': 'hello'},
          ]),
        );
      },
    );
  });
}
