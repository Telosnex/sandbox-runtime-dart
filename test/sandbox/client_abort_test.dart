// Ported from sandbox-runtime test/sandbox/client-abort.test.ts @ 0bbebed.
// ignore_for_file: constant_identifier_names, non_constant_identifier_names, no_leading_underscores_for_local_identifiers, slash_for_doc_comments
import 'dart:async';
import 'dart:io' show Directory;
import 'dart:typed_data';

import 'package:sandbox_runtime/src/node/buffer.dart' show Buffer;
import 'package:sandbox_runtime/src/node/fs.dart' show readFileSync;
import 'package:sandbox_runtime/src/node/globals.dart'
    show clearInterval, clearTimeout, setInterval, setTimeout;
import 'package:sandbox_runtime/src/node/http.dart' as http;
import 'package:sandbox_runtime/src/node/net.dart'
    show NodeAddress, NodeSocket, connect;
import 'package:sandbox_runtime/src/node/path.dart' show join;
import 'package:sandbox_runtime/src/node/process.dart' as process;
import 'package:sandbox_runtime/src/node/tls.dart' as tls;
import 'package:sandbox_runtime/src/sandbox/http_proxy.dart'
    show HttpProxyServerOptions, createHttpProxyServer;
import 'package:sandbox_runtime/src/sandbox/mitm_ca.dart'
    show MitmCA, createMitmCA, disposeMitmCA;
import 'package:sandbox_runtime/src/sandbox/request_filter.dart'
    show FilterRequestCallback, RequestDecision;
import 'package:test/test.dart';

import '../helpers/emitted_connections.dart'
    show SERVES_EMITTED_CONNECTIONS, testWithTls;

// Dart: the object literal upstream hands createHttpProxyServer; every
// option not named here is absent (null).
class _HttpOptions implements HttpProxyServerOptions {
  _HttpOptions({this.filterRequest, this.mitmCA, bool Function()? filter})
    : _filter = filter ?? (() => true);
  final bool Function() _filter;
  @override
  final FilterRequestCallback? filterRequest;
  @override
  final MitmCA? mitmCA;
  @override
  FutureOr<bool> filter(
    int port,
    String host,
    dynamic socket, [
    String? encodedCommand,
    void Function(String reason)? explain,
  ]) => _filter();
  @override
  dynamic noSuchMethod(Invocation invocation) => null;
}

void main() {
  // A sandboxed client whose process tree is torn down mid-exchange resets
  // its proxy connection. The runtime then destroys the server-side req/res
  // with an error (ECONNRESET / "aborted", emitted from node:_http_server);
  // without 'error' listeners on those streams the event escalates to an
  // uncaughtException. A burst of simultaneous teardowns — one aborted
  // subagent killing its whole process tree — crashes the host process.
  // These tests drive the plain-HTTP request path with clients that vanish
  // mid-request and assert nothing escapes to the process level.
  group('http proxy survives client aborts', () {
    final uncaught = <Object>[];
    void onUncaught(Object err, [Object? stack]) {
      uncaught.add(err);
    }

    late http.NodeHttpServer upstream;
    late int upstreamPort;
    late http.NodeHttpServer proxy;
    late int proxyPort;

    setUpAll(() async {
      process.on('uncaughtException', onUncaught);
      // Upstream stalls before responding so client aborts land while the
      // proxied exchange is still in flight.
      upstream = http.createServer(null, (
        http.IncomingMessage req,
        http.ServerResponse res,
      ) {
        req.resume();
        setTimeout(() {
          if (!res.writableEnded) {
            res.writeHead(200, {'content-type': 'text/plain'});
            res.end('ok');
          }
        }, 300);
      });
      await (() {
        final r = Completer<void>();
        upstream.listen(0, '127.0.0.1', () => r.complete());
        return r.future;
      })();
      upstreamPort = (upstream.address() as NodeAddress).port;

      proxy = createHttpProxyServer(_HttpOptions());
      await (() {
        final r = Completer<void>();
        proxy.listen(0, '127.0.0.1', () => r.complete());
        return r.future;
      })();
      proxyPort = (proxy.address() as NodeAddress).port;
    });

    tearDownAll(() async {
      // Abort tests may leave half-open request sockets after their assertions.
      // Release them explicitly before waiting for the listening servers.
      proxy.closeAllConnections();
      upstream.closeAllConnections();
      await (() {
        final r = Completer<void>();
        proxy.close(() => r.complete());
        return r.future;
      })();
      await (() {
        final r = Completer<void>();
        upstream.close(() => r.complete());
        return r.future;
      })();
      process.off('uncaughtException', onUncaught);
    });

    /** Open a raw connection to the proxy, write `data`, destroy after `ms`. */
    Future<void> abortAfter(String data, int ms) {
      final c = Completer<void>();
      // Dart: a Completer completes once; a later resolve() is a no-op.
      void resolve() {
        if (!c.isCompleted) c.complete();
      }

      late final NodeSocket sock;
      sock = connect(proxyPort, '127.0.0.1', () {
        sock.write(data);
        setTimeout(() {
          sock.destroy();
          resolve();
        }, ms);
      });
      sock.on('error', () {});
      return c.future;
    }

    test('client destroyed mid request body', () async {
      uncaught.length = 0;
      await abortAfter(
        'POST http://127.0.0.1:$upstreamPort/upload HTTP/1.1\r\n'
        'Host: 127.0.0.1:$upstreamPort\r\n'
        'Content-Length: 100000\r\n'
        '\r\n'
        'partial-body-then-gone',
        50,
      );
      await Future<void>.delayed(Duration(milliseconds: 500));
      expect(uncaught, equals([]));
    });

    test('client destroyed while awaiting the response', () async {
      uncaught.length = 0;
      await abortAfter(
        'GET http://127.0.0.1:$upstreamPort/slow HTTP/1.1\r\n'
        'Host: 127.0.0.1:$upstreamPort\r\n'
        '\r\n',
        50,
      );
      await Future<void>.delayed(Duration(milliseconds: 500));
      expect(uncaught, equals([]));
    });

    test('burst of simultaneous client aborts', () async {
      uncaught.length = 0;
      await Future.wait(
        List.generate(
          15,
          (i) => abortAfter(
            'POST http://127.0.0.1:$upstreamPort/burst-$i HTTP/1.1\r\n'
            'Host: 127.0.0.1:$upstreamPort\r\n'
            'Content-Length: 100000\r\n'
            '\r\n'
            'partial',
            30,
          ),
        ),
      );
      await Future<void>.delayed(Duration(milliseconds: 600));
      expect(uncaught, equals([]));
    });

    test(
      'malformed bytes then disconnect hits clientError, not the process',
      () async {
        uncaught.length = 0;
        await abortAfter('\x16\x03\x01 not http at all\r\n', 50);
        await Future<void>.delayed(Duration(milliseconds: 300));
        expect(uncaught, equals([]));
      },
    );
  });

  // With `filterRequest` configured (how SandboxManager wires the proxy in
  // production), body-carrying requests are teed via Readable.toWeb(req), so
  // the stream that gets piped upstream is a tee branch — not `req` itself.
  // A client abort then errors that branch, and pipe() does not handle source
  // errors: without an explicit listener the abort escapes as an
  // uncaughtException from node:_http_server.
  group('http proxy with filterRequest survives client aborts', () {
    final uncaught = <Object>[];
    void onUncaught(Object err, [Object? stack]) {
      uncaught.add(err);
    }

    late http.NodeHttpServer upstream;
    late int upstreamPort;
    late http.NodeHttpServer proxy;
    late int proxyPort;

    setUpAll(() async {
      process.on('uncaughtException', onUncaught);
      upstream = http.createServer(null, (
        http.IncomingMessage req,
        http.ServerResponse res,
      ) {
        req.resume();
        setTimeout(() {
          if (!res.writableEnded) {
            res.writeHead(200, {'content-type': 'text/plain'});
            res.end('ok');
          }
        }, 300);
      });
      await (() {
        final r = Completer<void>();
        upstream.listen(0, '127.0.0.1', () => r.complete());
        return r.future;
      })();
      upstreamPort = (upstream.address() as NodeAddress).port;

      proxy = createHttpProxyServer(
        _HttpOptions(
          filterRequest: (request, [info]) async =>
              const RequestDecision(action: 'allow'),
        ),
      );
      await (() {
        final r = Completer<void>();
        proxy.listen(0, '127.0.0.1', () => r.complete());
        return r.future;
      })();
      proxyPort = (proxy.address() as NodeAddress).port;
    });

    tearDownAll(() async {
      // Abort tests may leave half-open request sockets after their assertions.
      // Release them explicitly before waiting for the listening servers.
      proxy.closeAllConnections();
      upstream.closeAllConnections();
      await (() {
        final r = Completer<void>();
        proxy.close(() => r.complete());
        return r.future;
      })();
      await (() {
        final r = Completer<void>();
        upstream.close(() => r.complete());
        return r.future;
      })();
      process.off('uncaughtException', onUncaught);
    });

    Future<void> abortPostAfter(int ms, bool rst) {
      final c = Completer<void>();
      // Dart: a Completer completes once; a later resolve() is a no-op.
      void resolve() {
        if (!c.isCompleted) c.complete();
      }

      late final NodeSocket sock;
      sock = connect(proxyPort, '127.0.0.1', () {
        sock.write(
          'POST http://127.0.0.1:$upstreamPort/upload HTTP/1.1\r\n'
          'Host: 127.0.0.1:$upstreamPort\r\n'
          'Content-Length: 100000\r\n'
          '\r\n'
          'partial-body-then-gone',
        );
        setTimeout(() {
          if (rst) {
            sock.resetAndDestroy();
          } else {
            sock.destroy();
          }
          resolve();
        }, ms);
      });
      sock.on('error', () {});
      return c.future;
    }

    test('client FIN mid teed request body', () async {
      uncaught.length = 0;
      await abortPostAfter(50, false);
      await Future<void>.delayed(Duration(milliseconds: 500));
      expect(uncaught, equals([]));
    });

    test('client RST mid teed request body', () async {
      uncaught.length = 0;
      await abortPostAfter(50, true);
      await Future<void>.delayed(Duration(milliseconds: 500));
      expect(uncaught, equals([]));
    });

    test('burst of simultaneous aborts on teed bodies', () async {
      uncaught.length = 0;
      await Future.wait(
        List.generate(15, (i) => abortPostAfter(30, i % 2 == 0)),
      );
      await Future<void>.delayed(Duration(milliseconds: 600));
      expect(uncaught, equals([]));
    });
  });

  // The crash fixes must not weaken the proxy's delivery semantics: an
  // aborted upload must never reach the upstream framed as complete, denied
  // clients must still get their 403 and then lose the connection, and the
  // clientError 400 must actually arrive. These pin the guards a bare
  // "no uncaughtException" assertion cannot.
  group('client-abort delivery semantics', () {
    final uncaught = <Object>[];
    void onUncaught(Object err, [Object? stack]) {
      uncaught.add(err);
    }

    final upstreamEvents = <({String url, String event})>[];
    var upstreamRequests = 0;
    late http.NodeHttpServer upstream;
    late int upstreamPort;
    late http.NodeHttpServer proxy;
    late int proxyPort;
    var filterDelayMs = 0;
    var filterMode = 'allow'; // 'allow' | 'deny'

    setUpAll(() async {
      process.on('uncaughtException', onUncaught);
      upstream = http.createServer(null, (
        http.IncomingMessage req,
        http.ServerResponse res,
      ) {
        upstreamRequests++;
        req.on(
          'error',
          () => upstreamEvents.add((url: req.url!, event: 'error')),
        );
        req.on(
          'aborted',
          () => upstreamEvents.add((url: req.url!, event: 'aborted')),
        );
        req.on('end', () => upstreamEvents.add((url: req.url!, event: 'end')));
        req.resume();
        if (req.url == '/download') {
          res.writeHead(200, {'content-length': (64 * 1024 * 1024).toString()});
          final chunk = Uint8List(65536)..fillRange(0, 65536, 67);
          final iv = setInterval(() => res.write(chunk), 5);
          res.on('close', () => clearInterval(iv));
          res.on('error', () => clearInterval(iv));
          return;
        }
        setTimeout(() {
          if (!res.writableEnded) {
            try {
              res.end('ok');
            } catch (_) {
              // client already gone
            }
          }
        }, 300);
      });
      await (() {
        final r = Completer<void>();
        upstream.listen(0, '127.0.0.1', () => r.complete());
        return r.future;
      })();
      upstreamPort = (upstream.address() as NodeAddress).port;

      proxy = createHttpProxyServer(
        _HttpOptions(
          filterRequest: (request, [info]) async {
            if (filterDelayMs != 0) {
              await Future<void>.delayed(Duration(milliseconds: filterDelayMs));
            }
            return RequestDecision(action: filterMode, reason: 'semantics');
          },
        ),
      );
      await (() {
        final r = Completer<void>();
        proxy.listen(0, '127.0.0.1', () => r.complete());
        return r.future;
      })();
      proxyPort = (proxy.address() as NodeAddress).port;
    });

    tearDownAll(() async {
      // Lingering keep-alive client sockets (the malformed-bytes and smuggle
      // tests) would otherwise make close() wait out its own timeouts.
      proxy.closeAllConnections();
      upstream.closeAllConnections();
      await Future.wait([
        (() {
          final r = Completer<void>();
          void done() {
            if (!r.isCompleted) r.complete();
          }

          final t = setTimeout(done, 2000);
          proxy.close(() {
            clearTimeout(t);
            done();
          });
          return r.future;
        })(),
        (() {
          final r = Completer<void>();
          void done() {
            if (!r.isCompleted) r.complete();
          }

          final t = setTimeout(done, 2000);
          upstream.close(() {
            clearTimeout(t);
            done();
          });
          return r.future;
        })(),
      ]);
      process.off('uncaughtException', onUncaught);
    });

    test(
      'aborted chunked upload never reaches the upstream framed as complete',
      () async {
        uncaught.length = 0;
        upstreamEvents.length = 0;
        filterDelayMs = 0;
        filterMode = 'allow';
        await (() {
          final c = Completer<void>();
          void resolve() {
            if (!c.isCompleted) c.complete();
          }

          late final NodeSocket s;
          s = connect(proxyPort, '127.0.0.1', () {
            s.write(
              'POST http://127.0.0.1:$upstreamPort/truncated HTTP/1.1\r\n'
              'Host: 127.0.0.1:$upstreamPort\r\n'
              'Transfer-Encoding: chunked\r\n'
              '\r\n'
              '6\r\nchunk1\r\n',
            );
            setTimeout(() {
              s.destroy();
              resolve();
            }, 250);
          });
          s.on('error', () {});
          return c.future;
        })();
        await Future<void>.delayed(Duration(milliseconds: 800));
        final truncated = upstreamEvents
            .where((e) => e.url == '/truncated')
            .toList();
        expect(truncated.any((e) => e.event == 'end'), isFalse);
        expect(uncaught, equals([]));
      },
    );

    test(
      'abort during a slow filterRequest: no crash, no complete upstream delivery',
      () async {
        uncaught.length = 0;
        upstreamEvents.length = 0;
        filterDelayMs = 500;
        filterMode = 'allow';
        await (() {
          final c = Completer<void>();
          void resolve() {
            if (!c.isCompleted) c.complete();
          }

          late final NodeSocket s;
          s = connect(proxyPort, '127.0.0.1', () {
            s.write(
              'POST http://127.0.0.1:$upstreamPort/slowfilter HTTP/1.1\r\n'
              'Host: 127.0.0.1:$upstreamPort\r\n'
              'Content-Length: 100000\r\n'
              '\r\n'
              'partial',
            );
            setTimeout(() {
              s.destroy();
              resolve();
            }, 100);
          });
          s.on('error', () {});
          return c.future;
        })();
        await Future<void>.delayed(Duration(milliseconds: 1200));
        filterDelayMs = 0;
        final events = upstreamEvents
            .where((e) => e.url == '/slowfilter')
            .toList();
        expect(events.any((e) => e.event == 'end'), isFalse);
        expect(uncaught, equals([]));
      },
    );

    test('client abort mid-download does not crash the proxy', () async {
      uncaught.length = 0;
      filterMode = 'allow';
      await (() {
        final c = Completer<void>();
        void resolve() {
          if (!c.isCompleted) c.complete();
        }

        late final NodeSocket s;
        s = connect(proxyPort, '127.0.0.1', () {
          s.write(
            'GET http://127.0.0.1:$upstreamPort/download HTTP/1.1\r\n'
            'Host: 127.0.0.1:$upstreamPort\r\n'
            '\r\n',
          );
        });
        var got = 0;
        s.on('data', (Object? d) {
          got += (d as List<int>).length;
          if (got > 256 * 1024) {
            s.resetAndDestroy();
            resolve();
          }
        });
        s.on('error', () {});
        setTimeout(resolve, 3000);
        return c.future;
      })();
      await Future<void>.delayed(Duration(milliseconds: 800));
      expect(uncaught, equals([]));
    });

    test(
      'denied mid-upload client receives the 403 and then loses the connection',
      () async {
        uncaught.length = 0;
        filterMode = 'deny';
        var resp = '';
        var closed = false;
        await (() {
          final c = Completer<void>();
          void resolve() {
            if (!c.isCompleted) c.complete();
          }

          late final NodeSocket s;
          s = connect(proxyPort, '127.0.0.1', () {
            s.write(
              'POST http://127.0.0.1:$upstreamPort/denied HTTP/1.1\r\n'
              'Host: 127.0.0.1:$upstreamPort\r\n'
              'Content-Length: 9999999\r\n'
              '\r\n'
              'partial...',
            );
          });
          s.on('data', (Object? d) {
            resp += Buffer.from(d as List<int>).toString();
          });
          s.on('close', () {
            closed = true;
            resolve();
          });
          s.on('error', () {});
          setTimeout(resolve, 4000);
          return c.future;
        })();
        filterMode = 'allow';
        expect(resp, contains('403'));
        expect(resp, contains('semantics'));
        expect(closed, isTrue);
        expect(uncaught, equals([]));
      },
    );

    test(
      'malformed bytes get an HTTP 400 back (Node) or a prompt close (Bun), never a crash',
      () async {
        uncaught.length = 0;
        var resp = '';
        var closed = false;
        await (() {
          final c = Completer<void>();
          void resolve() {
            if (!c.isCompleted) c.complete();
          }

          late final NodeSocket s;
          s = connect(proxyPort, '127.0.0.1', () {
            s.write('GARBAGE REQUEST LINE\r\n\r\n');
          });
          s.on('data', (Object? d) {
            resp += Buffer.from(d as List<int>).toString();
          });
          s.on('close', () {
            closed = true;
            resolve();
          });
          s.on('error', () {});
          setTimeout(resolve, 2500);
          return c.future;
        })();
        // Node delivers the 400; Bun drops the write on a parse-errored socket
        // (verified empirically) and the handler's backstop closes it instead.
        expect(resp == '' || resp.startsWith('HTTP/1.1 400'), isTrue);
        expect(closed, isTrue);
        expect(uncaught, equals([]));
      },
    );

    test(
      'GET with a body: callback sees a bodyless Request, upstream gets the body',
      () async {
        uncaught.length = 0;
        final received = <String>[];
        final echo = http.createServer(null, (
          http.IncomingMessage req,
          http.ServerResponse res,
        ) {
          final chunks = <List<int>>[];
          req.on('error', () {});
          req.on('data', (Object? c) => chunks.add(c as List<int>));
          req.on('end', () {
            received.add(Buffer.concat(chunks).toString());
            res.end('ok');
          });
        });
        await (() {
          final r = Completer<void>();
          echo.listen(0, '127.0.0.1', () => r.complete());
          return r.future;
        })();
        final eport = (echo.address() as NodeAddress).port;
        Object? callbackBody = 'unset';
        final p2 = createHttpProxyServer(
          _HttpOptions(
            filterRequest: (r, [info]) async {
              callbackBody = r.body;
              return const RequestDecision(action: 'allow');
            },
          ),
        );
        await (() {
          final r = Completer<void>();
          p2.listen(0, '127.0.0.1', () => r.complete());
          return r.future;
        })();
        final pport = (p2.address() as NodeAddress).port;
        var resp = '';
        await (() {
          final c = Completer<void>();
          void resolve() {
            if (!c.isCompleted) c.complete();
          }

          late final NodeSocket s;
          s = connect(pport, '127.0.0.1', () {
            final body = 'get-body-payload';
            s.write(
              'GET http://127.0.0.1:$eport/g HTTP/1.1\r\n'
              'Host: 127.0.0.1:$eport\r\n'
              'Transfer-Encoding: chunked\r\n'
              '\r\n'
              '${body.length.toRadixString(16)}\r\n$body\r\n0\r\n\r\n',
            );
          });
          s.on('data', (Object? d) {
            resp += Buffer.from(d as List<int>).toString();
            if (resp.contains('ok')) {
              s.destroy();
              resolve();
            }
          });
          s.on('error', () {});
          setTimeout(resolve, 3000);
          return c.future;
        })();
        p2.closeAllConnections();
        echo.closeAllConnections();
        await (() {
          final r = Completer<void>();
          void done() {
            if (!r.isCompleted) r.complete();
          }

          final t = setTimeout(done, 1500);
          p2.close(() {
            clearTimeout(t);
            done();
          });
          return r.future;
        })();
        await (() {
          final r = Completer<void>();
          void done() {
            if (!r.isCompleted) r.complete();
          }

          final t = setTimeout(done, 1500);
          echo.close(() {
            clearTimeout(t);
            done();
          });
          return r.future;
        })();
        expect(resp.startsWith('HTTP/1.1 200'), isTrue);
        expect(callbackBody, isNull);
        expect(received, equals(['get-body-payload']));
        expect(uncaught, equals([]));
      },
    );

    test(
      'oversized header block gets 431 (Node) or a silent close (Bun), never a crash',
      () async {
        uncaught.length = 0;
        var resp = '';
        await (() {
          final c = Completer<void>();
          void resolve() {
            if (!c.isCompleted) c.complete();
          }

          late final NodeSocket s;
          s = connect(proxyPort, '127.0.0.1', () {
            s.write(
              'GET http://127.0.0.1:$upstreamPort/hdr HTTP/1.1\r\n'
              'Host: 127.0.0.1:$upstreamPort\r\n'
              'X-Big: '
              '${'a' * 40000}'
              '\r\n\r\n',
            );
          });
          s.on('data', (Object? d) {
            resp += Buffer.from(d as List<int>).toString();
          });
          s.on('close', resolve);
          s.on('error', () {});
          setTimeout(resolve, 2500);
          return c.future;
        })();
        expect(resp == '' || resp.startsWith('HTTP/1.1 431'), isTrue);
        expect(uncaught, equals([]));
      },
    );

    test('abort mid-upload to a blocked host does not crash', () async {
      uncaught.length = 0;
      final blocking = createHttpProxyServer(_HttpOptions(filter: () => false));
      await (() {
        final r = Completer<void>();
        blocking.listen(0, '127.0.0.1', () => r.complete());
        return r.future;
      })();
      final bport = (blocking.address() as NodeAddress).port;
      await (() {
        final c = Completer<void>();
        void resolve() {
          if (!c.isCompleted) c.complete();
        }

        late final NodeSocket s;
        s = connect(bport, '127.0.0.1', () {
          s.write(
            'POST http://127.0.0.1:$upstreamPort/blocked HTTP/1.1\r\n'
            'Host: 127.0.0.1:$upstreamPort\r\n'
            'Content-Length: 100000\r\n'
            '\r\n'
            'partial',
          );
          setTimeout(() {
            s.destroy();
            resolve();
          }, 80);
        });
        s.on('error', () {});
        return c.future;
      })();
      await Future<void>.delayed(Duration(milliseconds: 500));
      await (() {
        final r = Completer<void>();
        blocking.close(() => r.complete());
        return r.future;
      })();
      expect(uncaught, equals([]));
    });

    test('GET with Content-Length: 0 passes the filter and succeeds', () async {
      // Fetch-spec Requests reject a body on GET (Node throws; Bun is
      // lenient): the declared-body tee must not leak into the callback's
      // Request or innocent bodyless-framed GETs get 403'd as malformed.
      uncaught.length = 0;
      filterMode = 'allow';
      var resp = '';
      await (() {
        final c = Completer<void>();
        void resolve() {
          if (!c.isCompleted) c.complete();
        }

        late final NodeSocket s;
        s = connect(proxyPort, '127.0.0.1', () {
          s.write(
            'GET http://127.0.0.1:$upstreamPort/empty-get HTTP/1.1\r\n'
            'Host: 127.0.0.1:$upstreamPort\r\n'
            'Content-Length: 0\r\n'
            '\r\n',
          );
        });
        s.on('data', (Object? d) {
          resp += Buffer.from(d as List<int>).toString();
          if (resp.contains('ok')) {
            s.destroy();
            resolve();
          }
        });
        s.on('error', () {});
        setTimeout(resolve, 3000);
        return c.future;
      })();
      expect(resp.startsWith('HTTP/1.1 200'), isTrue);
      expect(uncaught, equals([]));
    });

    test(
      'empty Transfer-Encoding value does not trigger teeing or re-framing',
      () async {
        uncaught.length = 0;
        filterMode = 'allow';
        var resp = '';
        await (() {
          final c = Completer<void>();
          void resolve() {
            if (!c.isCompleted) c.complete();
          }

          late final NodeSocket s;
          s = connect(proxyPort, '127.0.0.1', () {
            s.write(
              'GET http://127.0.0.1:$upstreamPort/empty-te HTTP/1.1\r\n'
              'Host: 127.0.0.1:$upstreamPort\r\n'
              'Transfer-Encoding:\r\n'
              '\r\n',
            );
          });
          s.on('data', (Object? d) {
            resp += Buffer.from(d as List<int>).toString();
            if (resp.contains('ok')) {
              s.destroy();
              resolve();
            }
          });
          s.on('error', () {});
          setTimeout(resolve, 3000);
          return c.future;
        })();
        expect(resp.startsWith('HTTP/1.1 200'), isTrue);
        expect(uncaught, equals([]));
      },
    );

    test(
      'GET with a chunked body cannot smuggle even without filterRequest',
      () async {
        // The re-framing must not depend on the tee existing: a filterless
        // deployment forwards req directly, and TE is still stripped as
        // hop-by-hop.
        uncaught.length = 0;
        final bare = createHttpProxyServer(_HttpOptions());
        await (() {
          final r = Completer<void>();
          bare.listen(0, '127.0.0.1', () => r.complete());
          return r.future;
        })();
        final bport = (bare.address() as NodeAddress).port;
        upstreamEvents.length = 0;
        upstreamRequests = 0;
        await (() {
          final c = Completer<void>();
          void resolve() {
            if (!c.isCompleted) c.complete();
          }

          late final NodeSocket s;
          s = connect(bport, '127.0.0.1', () {
            final smuggled =
                'POST http://127.0.0.1:$upstreamPort/admin2 HTTP/1.1\r\n'
                'Host: 127.0.0.1:$upstreamPort\r\nContent-Length: 0\r\n\r\n';
            s.write(
              'GET http://127.0.0.1:$upstreamPort/legit2 HTTP/1.1\r\n'
              'Host: 127.0.0.1:$upstreamPort\r\n'
              'Transfer-Encoding: chunked\r\n'
              '\r\n'
              '${smuggled.length.toRadixString(16)}\r\n$smuggled\r\n'
              '0\r\n\r\n',
            );
          });
          s.on('data', () {});
          s.on('close', resolve);
          s.on('error', () {});
          setTimeout(resolve, 3000);
          return c.future;
        })();
        await Future<void>.delayed(Duration(milliseconds: 500));
        bare.closeAllConnections();
        await (() {
          final r = Completer<void>();
          void done() {
            if (!r.isCompleted) r.complete();
          }

          final t = setTimeout(done, 1500);
          bare.close(() {
            clearTimeout(t);
            done();
          });
          return r.future;
        })();
        expect(upstreamEvents.any((e) => e.url == '/admin2'), isFalse);
        expect(upstreamRequests, lessThanOrEqualTo(1));
        expect(uncaught, equals([]));
      },
    );

    test(
      'GET with a chunked body cannot smuggle a second request upstream',
      () async {
        uncaught.length = 0;
        upstreamEvents.length = 0;
        upstreamRequests = 0;
        filterMode = 'allow';
        await (() {
          final c = Completer<void>();
          void resolve() {
            if (!c.isCompleted) c.complete();
          }

          late final NodeSocket s;
          s = connect(proxyPort, '127.0.0.1', () {
            final smuggled =
                'POST http://127.0.0.1:$upstreamPort/admin HTTP/1.1\r\n'
                'Host: 127.0.0.1:$upstreamPort\r\nContent-Length: 0\r\n\r\n';
            s.write(
              'GET http://127.0.0.1:$upstreamPort/legit HTTP/1.1\r\n'
              'Host: 127.0.0.1:$upstreamPort\r\n'
              'Transfer-Encoding: chunked\r\n'
              '\r\n'
              '${smuggled.length.toRadixString(16)}\r\n$smuggled\r\n'
              '0\r\n\r\n',
            );
          });
          s.on('data', () {});
          s.on('close', resolve);
          s.on('error', () {});
          setTimeout(resolve, 3000);
          return c.future;
        })();
        await Future<void>.delayed(Duration(milliseconds: 500));
        expect(upstreamEvents.any((e) => e.url == '/admin'), isFalse);
        expect(upstreamRequests, lessThanOrEqualTo(1));
        expect(uncaught, equals([]));
      },
    );
  });

  // TLS-terminated path: the same abort classes must hold through the inner
  // HTTPS server (the request handler listeners, inner clientError, and the
  // teed-body wiring are otherwise unreachable by the plain-HTTP tests).
  group('client aborts through the TLS-terminating path', () {
    // Every case runs a TLS-terminating proxy: skipped where none can run.
    final test = testWithTls;
    final FIXTURE_DIR = join(
      Directory.current.path, // import.meta.dir, '..'
      'test',
      'fixtures',
      'tls-terminate',
    );
    final CA_PEM = readFileSync(join(FIXTURE_DIR, 'ca.crt'), 'utf8') as String;
    final ca = createMitmCA(
      caCertPath: join(FIXTURE_DIR, 'ca.crt'),
      caKeyPath: join(FIXTURE_DIR, 'ca.key'),
    );

    final uncaught = <Object>[];
    void onUncaught(Object err, [Object? stack]) {
      uncaught.add(err);
    }

    late http.NodeHttpServer proxy;
    late int proxyPort;

    setUpAll(() async {
      process.on('uncaughtException', onUncaught);
      proxy = createHttpProxyServer(
        _HttpOptions(
          mitmCA: SERVES_EMITTED_CONNECTIONS ? ca : null,
          filterRequest: (request, [info]) async =>
              const RequestDecision(action: 'allow'),
        ),
      );
      await (() {
        final r = Completer<void>();
        proxy.listen(0, '127.0.0.1', () => r.complete());
        return r.future;
      })();
      proxyPort = (proxy.address() as NodeAddress).port;
    });

    tearDownAll(() async {
      await (() {
        final r = Completer<void>();
        proxy.close(() => r.complete());
        return r.future;
      })();
      await disposeMitmCA(ca);
      process.off('uncaughtException', onUncaught);
    });

    /** CONNECT through the proxy, complete the TLS handshake, run fn. */
    Future<void> throughTunnel(
      void Function(NodeSocket tls, void Function() done) fn,
    ) {
      final c = Completer<void>();
      void resolve() {
        if (!c.isCompleted) c.complete();
      }

      late final NodeSocket raw;
      raw = connect(proxyPort, '127.0.0.1', () {
        raw.write(
          'CONNECT 127.0.0.1:443 HTTP/1.1\r\nHost: 127.0.0.1:443\r\n\r\n',
        );
      });
      raw.on('error', () {});
      raw.once('data', () {
        late final NodeSocket tlsSocket;
        tlsSocket = tls.connect({
          'socket': raw,
          'ca': CA_PEM,
          'servername': 'localhost',
        }, () => fn(tlsSocket, () => resolve()));
        tlsSocket.on('error', () => resolve());
      });
      setTimeout(resolve, 4000);
      return c.future;
    }

    test('TLS client destroyed mid request body', () async {
      uncaught.length = 0;
      await throughTunnel((tls, done) {
        tls.write(
          'POST /upload HTTP/1.1\r\nHost: localhost\r\n'
          'Content-Length: 100000\r\n\r\npartial',
        );
        setTimeout(() {
          tls.destroy();
          done();
        }, 150);
      });
      await Future<void>.delayed(Duration(milliseconds: 800));
      expect(uncaught, equals([]));
    });

    test('garbage bytes after the TLS handshake do not crash', () async {
      uncaught.length = 0;
      await throughTunnel((tls, done) {
        tls.write('\x00\x01 not http\r\n\r\n');
        setTimeout(() {
          tls.destroy();
          done();
        }, 150);
      });
      await Future<void>.delayed(Duration(milliseconds: 600));
      expect(uncaught, equals([]));
    });
  });
}
