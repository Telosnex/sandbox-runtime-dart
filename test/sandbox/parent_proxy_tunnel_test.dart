// Ported from sandbox-runtime test/sandbox/parent-proxy-tunnel.test.ts @ 0bbebed.
// ignore_for_file: slash_for_doc_comments, no_leading_underscores_for_local_identifiers
import 'dart:async';
import 'dart:convert';

import 'package:sandbox_runtime/src/node/http.dart' as http;
import 'package:sandbox_runtime/src/node/net.dart' as net;
import 'package:sandbox_runtime/src/sandbox/http_proxy.dart';
import 'package:sandbox_runtime/src/sandbox/parent_proxy.dart';
import 'package:sandbox_runtime/src/sandbox/sandbox_config.dart';
import 'package:test/test.dart';

// Dart: the object literal upstream hands createHttpProxyServer; every
// option not named here is absent (null).
class _HttpOptions implements HttpProxyServerOptions {
  _HttpOptions({this.parentProxy});
  @override
  final ResolvedParentProxy? parentProxy;
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

/**
 * End-to-end: client -> SRT HTTP proxy -> parent HTTP proxy -> origin.
 * The parent proxy records every CONNECT it receives so we can assert SRT
 * chained through it rather than dialing the origin directly.
 */
void main() {
  group('parent-proxy: HTTP CONNECT tunnelling', () {
    late http.NodeHttpServer origin;
    late int originPort;
    late http.NodeHttpServer parent;
    late int parentPort;
    late http.NodeHttpServer srt;
    late int srtPort;
    final parentConnects = <String>[];

    setUpAll(() async {
      // Origin: plain HTTP server that responds with a marker body.
      origin = http.createServer((
        http.IncomingMessage _req,
        http.ServerResponse res,
      ) {
        res.writeHead(200, {'content-type': 'text/plain'});
        res.end('hello-from-origin');
      });
      await _listen(origin);
      originPort = (origin.address() as net.NodeAddress).port;

      // Parent proxy: handles CONNECT by dialing the requested host:port and
      // piping. Records each CONNECT target.
      parent = http.createServer();
      parent.on('connect', (
        http.IncomingMessage req,
        net.NodeSocket clientSock,
      ) {
        parentConnects.add(req.url!);
        final [h, p] = req.url!.split(':');
        late final net.NodeSocket up;
        up = net.connect(int.parse(p), h, () {
          clientSock.write('HTTP/1.1 200 OK\r\n\r\n');
          up.pipe(clientSock);
          clientSock.pipe(up);
        });
        up.on('error', (Object? _) => clientSock.destroy());
      });
      await _listen(parent);
      parentPort = (parent.address() as net.NodeAddress).port;

      // SRT proxy configured with the parent.
      srt = createHttpProxyServer(
        _HttpOptions(
          parentProxy: resolveParentProxy(
            ParentProxyConfig(
              http: 'http://127.0.0.1:$parentPort',
              // Deliberately NOT putting 127.0.0.1 in noProxy — we want to test
              // that the always-bypass-loopback rule works. But for this test we
              // need to tunnel to 127.0.0.1, so use a noProxy that excludes nothing
              // and reach origin via a name that isn't loopback-special-cased.
              // Simpler: just test that the CONNECT goes to the parent by using a
              // hostname alias. We'll use 'localtest.me' style by targeting the
              // literal IP but as a string the bypass check won't treat as loopback
              // — actually it will. So instead: put noProxy empty and connect to
              // 127.0.0.1, and assert it BYPASSES (direct). Then use a second test
              // for the tunnel path with a non-loopback target.
              noProxy: '',
            ),
          ),
        ),
      );
      await _listen(srt);
      srtPort = (srt.address() as net.NodeAddress).port;
    });

    tearDownAll(() async {
      await Future.wait([_close(origin), _close(parent), _close(srt)]);
    });

    test('loopback destination bypasses parent proxy', () async {
      parentConnects.clear();
      final body = await connectAndGet(srtPort, '127.0.0.1', originPort, '/');
      expect(body, contains('hello-from-origin'));
      // Parent should NOT have seen this — loopback always bypasses.
      expect(parentConnects, []);
    });

    test('non-loopback destination tunnels through parent', () async {
      // Spin up a second SRT proxy whose parentProxy has noProxy empty, and
      // hit a non-loopback hostname that resolves to the origin. We fake this
      // by having the parent proxy rewrite the CONNECT target to our origin.
      parentConnects.clear();

      final rewritingParent = http.createServer();
      rewritingParent.on('connect', (
        http.IncomingMessage req,
        net.NodeSocket clientSock,
      ) {
        parentConnects.add(req.url!);
        // Ignore requested target; always connect to our local origin.
        late final net.NodeSocket up;
        up = net.connect(originPort, '127.0.0.1', () {
          clientSock.write('HTTP/1.1 200 OK\r\n\r\n');
          up.pipe(clientSock);
          clientSock.pipe(up);
        });
        up.on('error', (Object? _) => clientSock.destroy());
      });
      await _listen(rewritingParent);
      final rpPort = (rewritingParent.address() as net.NodeAddress).port;

      final srt2 = createHttpProxyServer(
        _HttpOptions(
          parentProxy: resolveParentProxy(
            ParentProxyConfig(http: 'http://127.0.0.1:$rpPort', noProxy: ''),
          ),
        ),
      );
      await _listen(srt2);
      final srt2Port = (srt2.address() as net.NodeAddress).port;

      try {
        final body = await connectAndGet(srt2Port, 'upstream.example', 80, '/');
        expect(body, contains('hello-from-origin'));
        expect(parentConnects, ['upstream.example:80']);
      } finally {
        await _close(srt2);
        await _close(rewritingParent);
      }
    });
  });
}

// Dart: `new Promise<void>(r => s.listen(0, '127.0.0.1', r))`
Future<void> _listen(net.NodeServer s) {
  final c = Completer<void>();
  s.listen(0, '127.0.0.1', () => c.complete());
  return c.future;
}

// Dart: `new Promise<void>(r => s.close(() => r()))`
Future<void> _close(net.NodeServer s) {
  final c = Completer<void>();
  s.close(() => c.complete());
  return c.future;
}

/** Issue CONNECT to proxyPort, then GET path over the tunnel. Returns body. */
Future<String> connectAndGet(
  int proxyPort,
  String destHost,
  int destPort,
  String path,
) {
  final completer = Completer<String>();
  void resolve(String v) {
    if (!completer.isCompleted) completer.complete(v);
  }

  void reject(Object e) {
    if (!completer.isCompleted) completer.completeError(e);
  }

  late final net.NodeSocket sock;
  sock = net.connect(proxyPort, '127.0.0.1', () {
    sock.write(
      'CONNECT $destHost:$destPort HTTP/1.1\r\n'
      'Host: $destHost:$destPort\r\n\r\n',
    );
  });
  var phase = 'connect';
  var buf = '';
  sock.on('data', (Object? chunk) {
    buf += utf8.decode(chunk as List<int>);
    if (phase == 'connect') {
      final i = buf.indexOf('\r\n\r\n');
      if (i == -1) return;
      final status = buf.substring(0, buf.indexOf('\r\n'));
      if (!status.contains(' 200 ')) {
        return reject(Exception('CONNECT failed: $status'));
      }
      buf = buf.substring(i + 4);
      phase = 'body';
      sock.write(
        'GET $path HTTP/1.1\r\nHost: $destHost\r\nConnection: close\r\n\r\n',
      );
    }
  });
  sock.on('end', () => resolve(buf));
  sock.on('error', (Object? e) => reject(e!));
  return completer.future;
}
