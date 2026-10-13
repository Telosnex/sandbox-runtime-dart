import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:sandbox_runtime/src/node/http.dart' as http;
import 'package:sandbox_runtime/src/node/emitted_http.dart' as emitted_http;
import 'package:sandbox_runtime/src/node/net.dart' as net;
import 'package:test/test.dart';

Future<(int port, Future<void> Function())> _listen(
  http.NodeHttpServer server,
) async {
  await server.listen(0, '127.0.0.1');
  final address = server.address()! as net.NodeAddress;
  return (address.port, () => server.close());
}

Future<Uint8List> _rawExchange(int port, List<int> request) async {
  final socket = await Socket.connect('127.0.0.1', port);
  final response = BytesBuilder(copy: false);
  final done = Completer<Uint8List>();
  socket.listen(
    response.add,
    onError: done.completeError,
    onDone: () {
      if (!done.isCompleted) done.complete(response.takeBytes());
      socket.destroy();
    },
  );
  socket.add(request);
  await socket.flush();
  return done.future.timeout(const Duration(seconds: 5));
}

void main() {
  group('raw HTTP/1.1 shim', () {
    test(
      'keeps raw header order/spelling, streams chunked body, and isolates trailers',
      () async {
        final requestSeen =
            Completer<
              (List<String>, Map<String, Object?>, List<String>, List<int>)
            >();
        final server = http.createServer();
        server.on('request', (
          http.IncomingMessage request,
          http.ServerResponse response,
        ) {
          final body = BytesBuilder(copy: false);
          request.on('data', (List<int> bytes) => body.add(bytes));
          request.on('end', () {
            requestSeen.complete((
              request.rawHeaders,
              request.headers,
              request.rawTrailers,
              body.takeBytes(),
            ));
            response.writeHead(201, {'X-High': 'é'}).end('reply');
          });
        });
        final (port, close) = await _listen(server);
        final requestBytes = latin1.encode(
          'POST /upload HTTP/1.1\r\n'
          'Host: first.test\r\n'
          'X-MiXeD: one\r\n'
          'x-mixed: two\r\n'
          'Transfer-Encoding: chunked\r\n'
          'Connection: close\r\n\r\n'
          '3\r\nabc\r\n'
          '2\r\nde\r\n'
          '0\r\nX-Trace: done\r\n\r\n',
        );
        final responseBytes = await _rawExchange(port, requestBytes);
        final seen = await requestSeen.future.timeout(
          const Duration(seconds: 3),
        );
        expect(seen.$1, [
          'Host',
          'first.test',
          'X-MiXeD',
          'one',
          'x-mixed',
          'two',
          'Transfer-Encoding',
          'chunked',
          'Connection',
          'close',
        ]);
        expect(seen.$2['x-mixed'], 'one, two');
        expect(seen.$3, ['X-Trace', 'done']);
        expect(latin1.decode(seen.$4), 'abcde');
        expect(
          latin1.decode(responseBytes),
          startsWith('HTTP/1.1 201 Created\r\n'),
        );
        final responseText = latin1.decode(responseBytes);
        expect(responseText, contains('Transfer-Encoding: chunked\r\n'));
        expect(responseText, contains('X-High: é\r\n'));
        expect(responseText, contains('5\r\nreply\r\n0\r\n\r\n'));
        expect(responseBytes, isNot(contains(0xc3)));
        await close();
      },
    );

    test('CONNECT receives exact already-buffered head bytes', () async {
      final connectSeen = Completer<List<int>>();
      final server = http.createServer();
      server.on('connect', (
        http.IncomingMessage request,
        net.NodeSocket socket,
        Uint8List head,
      ) {
        expect(request.method, 'CONNECT');
        expect(request.url, 'example.test:443');
        connectSeen.complete(head);
        socket.write(
          ascii.encode('HTTP/1.1 200 Connection Established\r\n\r\n'),
        );
        socket.end();
      });
      final (port, close) = await _listen(server);
      final response = await _rawExchange(
        port,
        ascii.encode(
          'CONNECT example.test:443 HTTP/1.1\r\nHost: example.test:443\r\n\r\n\x16\x03\x01\x00\x05',
        ),
      );
      expect(await connectSeen.future.timeout(const Duration(seconds: 3)), [
        0x16,
        0x03,
        0x01,
        0x00,
        0x05,
      ]);
      expect(
        latin1.decode(response),
        startsWith('HTTP/1.1 200 Connection Established\r\n'),
      );
      await close();
    });

    test('upgrade receives the raw socket and exact buffered head', () async {
      final upgradeHead = Completer<List<int>>();
      final server = http.createServer();
      server.on('upgrade', (
        http.IncomingMessage request,
        net.NodeSocket socket,
        Uint8List head,
      ) {
        expect(request.url, '/chat');
        upgradeHead.complete(head);
        socket.write(
          ascii.encode(
            'HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n',
          ),
        );
        socket.end();
      });
      final (port, close) = await _listen(server);
      final response = await _rawExchange(
        port,
        ascii.encode(
          'GET /chat HTTP/1.1\r\nHost: example.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\npayload',
        ),
      );
      expect(
        await upgradeHead.future.timeout(const Duration(seconds: 3)),
        ascii.encode('payload'),
      );
      expect(
        latin1.decode(response),
        startsWith('HTTP/1.1 101 Switching Protocols\r\n'),
      );
      await close();
    });

    test('an unlistened server accepts a connection handed in by emit', () async {
      final served = Completer<void>();
      final httpServer = http.createServer();
      expect(emitted_http.servesEmittedConnections(), isTrue);
      httpServer.on('request', (
        http.IncomingMessage request,
        http.ServerResponse response,
      ) {
        expect(request.url, '/injected');
        served.complete();
        response.writeHead(200, {'Content-Length': '2'}).end('ok');
      });
      final transport = net.createServer((net.NodeSocket socket) {
        emitted_http.keepFlushedHeaderBatches(socket);
        emitted_http.writeHeadsAsLatin1(socket);
        expect(httpServer.emit('connection', socket), isTrue);
      });
      await transport.listen(0, '127.0.0.1');
      final address = transport.address()! as net.NodeAddress;
      final response = await _rawExchange(
        address.port,
        ascii.encode(
          'GET /injected HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n',
        ),
      );
      await served.future.timeout(const Duration(seconds: 3));
      expect(latin1.decode(response), contains('ok'));
      await transport.close();
      await httpServer.close();
    });

    test(
      'Expect: 100-continue is automatic unless checkContinue handles it',
      () async {
        final bodySeen = Completer<String>();
        final server = http.createServer();
        server.on('request', (
          http.IncomingMessage request,
          http.ServerResponse response,
        ) {
          final body = BytesBuilder(copy: false);
          request.on('data', (List<int> bytes) => body.add(bytes));
          request.on('end', () {
            bodySeen.complete(ascii.decode(body.takeBytes()));
            response.end('ok');
          });
        });
        final (port, close) = await _listen(server);
        final response = await _rawExchange(
          port,
          ascii.encode(
            'POST / HTTP/1.1\r\nHost: example.test\r\nExpect: 100-continue\r\nContent-Length: 4\r\nConnection: close\r\n\r\ndata',
          ),
        );
        expect(await bodySeen.future, 'data');
        final text = latin1.decode(response);
        expect(
          text,
          startsWith('HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\n'),
        );
        await close();

        final controlledBody = Completer<void>();
        final controlled = http.createServer();
        controlled.on('checkContinue', (
          http.IncomingMessage request,
          http.ServerResponse response,
        ) {
          response.writeContinue();
          controlled.emit('request', request, response);
        });
        controlled.on('request', (
          http.IncomingMessage request,
          http.ServerResponse response,
        ) {
          request.on('end', () {
            controlledBody.complete();
            response.end('handled');
          });
        });
        final (controlledPort, closeControlled) = await _listen(controlled);
        final controlledResponse = await _rawExchange(
          controlledPort,
          ascii.encode(
            'POST / HTTP/1.1\r\nHost: example.test\r\nExpect: 100-continue\r\nContent-Length: 0\r\nConnection: close\r\n\r\n',
          ),
        );
        await controlledBody.future.timeout(const Duration(seconds: 3));
        expect(latin1.decode(controlledResponse), contains('100 Continue'));
        await closeControlled();
      },
    );

    test('parses sequential keep-alive requests on one socket', () async {
      var requests = 0;
      final server = http.createServer();
      server.on('request', (
        http.IncomingMessage request,
        http.ServerResponse response,
      ) {
        requests++;
        response.end('r$requests');
      });
      final (port, close) = await _listen(server);
      final raw = await Socket.connect('127.0.0.1', port);
      final response = BytesBuilder(copy: false);
      final done = Completer<Uint8List>();
      raw.listen(
        response.add,
        onDone: () {
          if (!done.isCompleted) done.complete(response.takeBytes());
          raw.destroy();
        },
      );
      raw.add(
        ascii.encode(
          'GET /one HTTP/1.1\r\nHost: example.test\r\n\r\n'
          'GET /two HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n',
        ),
      );
      await raw.flush();
      final bytes = await done.future.timeout(const Duration(seconds: 5));
      final text = latin1.decode(bytes);
      expect(requests, 2);
      expect(RegExp('HTTP/1.1 200 OK').allMatches(text), hasLength(2));
      expect(text, contains('2\r\nr1\r\n0\r\n\r\n'));
      expect(text, contains('2\r\nr2\r\n0\r\n\r\n'));
      await close();
    });

    test('ClientRequest streams request bytes and response body', () async {
      final requestBody = Completer<String>();
      final server = http.createServer();
      var serverConnections = 0;
      server.on('connection', (net.NodeSocket socket) => serverConnections++);
      server.on('request', (
        http.IncomingMessage request,
        http.ServerResponse response,
      ) {
        final data = BytesBuilder(copy: false);
        request.on('data', (List<int> bytes) => data.add(bytes));
        request.on('end', () {
          if (!requestBody.isCompleted) {
            requestBody.complete(ascii.decode(data.takeBytes()));
          }
          response.writeHead(202, {'Content-Length': '6'}).end('answer');
        });
      });
      final (port, close) = await _listen(server);
      final responseBody = Completer<String>();
      final responseEnded = Completer<void>();
      final agent = http.Agent(keepAlive: true, maxSockets: 1);
      final request = http.request({
        'port': port,
        'host': '127.0.0.1',
        'method': 'POST',
        'path': '/stream',
        'agent': agent,
      });
      request.on('error', (Object error) {
        if (!responseEnded.isCompleted) responseEnded.completeError(error);
      });
      request.on('response', (http.IncomingMessage response) {
        final data = BytesBuilder(copy: false);
        response.on('data', (List<int> bytes) => data.add(bytes));
        response.on('end', () {
          responseBody.complete(ascii.decode(data.takeBytes()));
          responseEnded.complete();
        });
      });
      request.write('first-');
      await Future<void>.delayed(const Duration(milliseconds: 20));
      request.end('last');
      await responseEnded.future.timeout(const Duration(seconds: 5));
      expect(await requestBody.future, 'first-last');
      expect(await responseBody.future, 'answer');

      final reusedResponse = Completer<String>();
      final second = http.request({
        'port': port,
        'host': '127.0.0.1',
        'path': '/second',
        'agent': agent,
      });
      second.on('error', (Object error) {
        if (!reusedResponse.isCompleted) reusedResponse.completeError(error);
      });
      second.on('response', (http.IncomingMessage response) {
        final data = BytesBuilder(copy: false);
        response.on('data', (List<int> bytes) => data.add(bytes));
        response.on(
          'end',
          () => reusedResponse.complete(ascii.decode(data.takeBytes())),
        );
      });
      second.end();
      expect(
        await reusedResponse.future.timeout(const Duration(seconds: 5)),
        'answer',
      );
      expect(second.reusedSocket, isTrue);
      expect(serverConnections, 1);
      agent.destroy();
      await close();
    });

    test('oversized request headers become HTTP 431', () async {
      final server = http.createServer({'maxHeaderSize': 32});
      final (port, close) = await _listen(server);
      final response = await _rawExchange(
        port,
        ascii.encode('GET / HTTP/1.1\r\nX-Large: 12345678901234567890\r\n\r\n'),
      );
      expect(
        latin1.decode(response),
        startsWith('HTTP/1.1 431 Request Header Fields Too Large\r\n'),
      );
      await close();
    });

    test(
      'clientError exposes Node parser code and allows response-before-close',
      () async {
        final parserError = Completer<String>();
        final server = http.createServer();
        server.on('clientError', (
          http.NodeHttpError error,
          net.NodeSocket socket,
        ) {
          parserError.complete(error.code);
          socket.write(
            ascii.encode(
              'HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n',
            ),
            ([Object? _]) => socket.destroy(),
          );
        });
        final (port, close) = await _listen(server);
        final response = await _rawExchange(port, ascii.encode('BAD\r\n\r\n'));
        expect(
          await parserError.future.timeout(const Duration(seconds: 3)),
          startsWith('HPE_'),
        );
        expect(
          latin1.decode(response),
          startsWith('HTTP/1.1 400 Bad Request\r\n'),
        );
        await close();
      },
    );

    test(
      'rejects duplicate Content-Length instead of guessing framing',
      () async {
        final server = http.createServer();
        final (port, close) = await _listen(server);
        final response = await _rawExchange(
          port,
          ascii.encode(
            'POST / HTTP/1.1\r\nHost: example.test\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n',
          ),
        );
        expect(
          latin1.decode(response),
          startsWith('HTTP/1.1 400 Bad Request\r\n'),
        );
        await close();
      },
    );

    test(
      'body gate pauses parsing until buffered request bytes are consumed',
      () async {
        final received = Completer<String>();
        final sawBufferedBody = Completer<int>();
        final server = http.createServer();
        server.on('request', (
          http.IncomingMessage request,
          http.ServerResponse response,
        ) {
          emitted_http.gateSocketOnBufferedBody(request, 4);
          Timer(const Duration(milliseconds: 20), () {
            sawBufferedBody.complete(request.readableLength);
            final body = BytesBuilder(copy: false);
            request.on('data', (List<int> bytes) => body.add(bytes));
            request.on('end', () {
              received.complete(ascii.decode(body.takeBytes()));
              response.writeHead(200, {'Content-Length': '2'}).end('ok');
            });
          });
        });
        final (port, close) = await _listen(server);
        final response = await _rawExchange(
          port,
          ascii.encode(
            'POST /gate HTTP/1.1\r\nHost: example.test\r\nContent-Length: 16\r\nConnection: close\r\n\r\n0123456789abcdef',
          ),
        );
        expect(await sawBufferedBody.future, greaterThan(4));
        expect(await received.future, '0123456789abcdef');
        expect(latin1.decode(response), contains('ok'));
        await close();
      },
    );
  });
}
