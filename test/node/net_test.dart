import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:sandbox_runtime/src/node/dns.dart' as dns;
import 'package:sandbox_runtime/src/node/errno.dart';
import 'package:sandbox_runtime/src/node/events.dart' as events;
import 'package:sandbox_runtime/src/node/net.dart' as net;
import 'package:sandbox_runtime/src/sandbox/listen_in_range.dart';
import 'package:test/test.dart';

const _wait = Duration(seconds: 5);

/// `server.listen(...)` and wait for 'listening'.
Future<int> _listen(net.NodeServer server, [String host = '127.0.0.1']) async {
  server.listen(0, host);
  await events.once(server, 'listening').timeout(_wait);
  return (server.address()! as net.NodeAddress).port;
}

Future<void> _close(net.NodeServer server) {
  final done = Completer<void>();
  server.close(() => done.complete());
  return done.future.timeout(_wait);
}

/// A loopback port with nothing listening.
Future<int> _closedPort() async {
  final probe = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
  final port = probe.port;
  await probe.close();
  return port;
}

void main() {
  group('net Socket', () {
    test('a socket nobody reads stops reading past highWaterMark', () async {
      const sent = 16 << 20;
      final server = net.createServer();
      final accepted = Completer<net.NodeSocket>();
      server.on('connection', accepted.complete);
      final port = await _listen(server);
      final client = net.connect(port, '127.0.0.1');
      client.on('error', (Object _) {});
      for (var i = 0; i < sent ~/ (64 * 1024); i++) {
        client.write(Uint8List(64 * 1024));
      }
      final socket = await accepted.future.timeout(_wait);
      await Future<void>.delayed(const Duration(milliseconds: 200));
      final held = socket.readableLength;
      await Future<void>.delayed(const Duration(milliseconds: 100));
      // dart:io reads whatever the kernel holds at once, so one read can go
      // well past the mark; then reading stops and the rest waits.
      expect(held, greaterThanOrEqualTo(socket.readableHighWaterMark));
      expect(socket.readableLength, held);
      expect(held, lessThan(sent ~/ 4));
      var total = 0;
      socket.on('data', (List<int> bytes) => total += bytes.length);
      final end = Completer<void>();
      socket.on('end', end.complete);
      client.end();
      await end.future.timeout(_wait);
      expect(total, sent);
      socket.destroy();
      await _close(server);
    });

    test('a readable listener reads on after pause(), as in Node', () async {
      final server = net.createServer();
      final pulled = Completer<List<int>>();
      server.on('connection', (net.NodeSocket socket) {
        late void Function(Object?) onData;
        onData = (Object? first) {
          socket.pause();
          socket.off('data', onData);
          final all = [...first! as List<int>];
          void pull() {
            Uint8List? chunk;
            while ((chunk = socket.read() as Uint8List?) != null) {
              all.addAll(chunk!);
            }
            if (all.length >= 6 && !pulled.isCompleted) pulled.complete(all);
          }

          socket.on('readable', pull);
          pull();
        };
        socket.on('data', onData);
      });
      final port = await _listen(server);
      final client = net.connect(port, '127.0.0.1');
      client.write([1, 2, 3]);
      await Future<void>.delayed(const Duration(milliseconds: 50));
      client.write([4, 5, 6]);
      expect(await pulled.future.timeout(_wait), [1, 2, 3, 4, 5, 6]);
      client.destroy();
      await _close(server);
    });

    test('read(1) followed by unshift restores the byte', () async {
      final server = net.createServer();
      final received = Completer<List<int>>();
      server.on('connection', (net.NodeSocket socket) {
        socket.once('readable', () {
          final first = socket.read(1)!;
          socket.unshift(first);
          received.complete(socket.read()! as List<int>);
        });
      });
      final port = await _listen(server);
      final client = net.connect(port, '127.0.0.1');
      client.write([0x16, 0x03, 0x01, 0x41, 0x42]);
      expect(await received.future.timeout(_wait), [
        0x16,
        0x03,
        0x01,
        0x41,
        0x42,
      ]);
      client.destroy();
      await _close(server);
    });

    test(
      'pipe relays bytes and propagates EOF without dropping the reply',
      () async {
        final echo = net.createServer({'allowHalfOpen': true});
        echo.on('connection', (net.NodeSocket socket) {
          socket.on('data', (List<int> bytes) => socket.write(bytes));
          socket.on('end', () => socket.end());
        });
        final echoPort = await _listen(echo);

        final relay = net.createServer({'allowHalfOpen': true});
        relay.on('connection', (net.NodeSocket incoming) {
          final upstream = net.connect({
            'port': echoPort,
            'host': '127.0.0.1',
            'allowHalfOpen': true,
          });
          incoming.pipe(upstream);
          upstream.pipe(incoming);
        });
        final relayPort = await _listen(relay);

        final client = net.connect({
          'port': relayPort,
          'host': '127.0.0.1',
          'allowHalfOpen': true,
        });
        final answer = BytesBuilder(copy: false);
        final ended = Completer<void>();
        client.on('data', (List<int> bytes) => answer.add(bytes));
        client.once('end', ended.complete);
        final payload = List<int>.generate(128 * 1024, (index) => index & 255);
        client.write(payload);
        client.end();
        await ended.future.timeout(_wait);
        expect(answer.takeBytes(), payload);
        await _close(relay);
        await _close(echo);
      },
    );

    test('TCP server listen/address/close lifecycle', () async {
      final server = net.createServer();
      var closeEvents = 0;
      server.unref();
      expect(server.unrefed, isTrue);
      server.ref();
      expect(server.unrefed, isFalse);
      server.on('close', () => closeEvents++);
      expect(server.listen(0, '127.0.0.1'), same(server));
      expect(server.listening, isFalse, reason: 'listen binds later');
      await events.once(server, 'listening').timeout(_wait);
      expect(server.listening, isTrue);
      final address = server.address()! as net.NodeAddress;
      expect(address.port, greaterThan(0));
      expect(address.address, '127.0.0.1');
      expect(address.family, 'IPv4');
      await _close(server);
      expect(server.listening, isFalse);
      expect(closeEvents, 1);
    });

    test('connect returns a connecting socket and queues writes', () async {
      final server = net.createServer();
      final received = Completer<List<int>>();
      server.on('connection', (net.NodeSocket socket) {
        socket.on('data', (List<int> bytes) => received.complete(bytes));
      });
      final port = await _listen(server);
      final events_ = <String>[];
      final socket = net.connect(port, '127.0.0.1', () => events_.add('cb'));
      expect(socket.connecting, isTrue);
      expect(socket.remoteAddress, isNull);
      socket.on('connect', () => events_.add('connect'));
      socket.on('ready', () => events_.add('ready'));
      socket.write('early');
      expect(await received.future.timeout(_wait), 'early'.codeUnits);
      expect(events_, ['cb', 'connect', 'ready']);
      expect(socket.connecting, isFalse);
      expect(socket.remoteAddress, '127.0.0.1');
      expect(socket.remotePort, port);
      expect(socket.remoteFamily, 'IPv4');
      socket.destroy();
      await _close(server);
    });

    test(
      'connect, write-before-close, error, and close events are ordered',
      () async {
        final server = net.createServer();
        final port = await _listen(server);
        final socket = net.connect(port, '127.0.0.1');
        final order = <String>[];
        socket.once('connect', () => order.add('connect'));
        await events.once(socket, 'connect').timeout(_wait);
        final wrote = Completer<void>();
        socket.write('before-close', () {
          order.add('write');
          wrote.complete();
        });
        await wrote.future.timeout(_wait);
        socket.on('error', (Object error) => order.add('error'));
        final closed = Completer<void>();
        socket.once('close', (bool hadError) {
          order.add('close:$hadError');
          closed.complete();
        });
        socket.destroy(StateError('intentional test close'));
        await closed.future.timeout(_wait);
        expect(order, ['connect', 'write', 'error', 'close:true']);
        await _close(server);
      },
    );

    test('a refused connection emits a Node error, then close', () async {
      final port = await _closedPort();
      final socket = net.connect(port, '127.0.0.1');
      final order = <String>[];
      final closed = Completer<void>();
      Object? error;
      socket.on('error', (Object e) {
        error = e;
        order.add('error');
      });
      socket.on('close', (bool hadError) {
        order.add('close:$hadError');
        closed.complete();
      });
      await closed.future.timeout(_wait);
      expect(order, ['error', 'close:true']);
      final nodeError = error! as NodeError;
      expect(nodeError.code, 'ECONNREFUSED');
      expect(nodeError.syscall, 'connect');
      expect(nodeError.address, '127.0.0.1');
      expect(nodeError.port, port);
      expect(nodeError.message, 'connect ECONNREFUSED 127.0.0.1:$port');
    });

    test('events.once rejects with the connect error', () async {
      final port = await _closedPort();
      final socket = net.connect(port, '127.0.0.1');
      await expectLater(
        events.once(socket, 'connect'),
        throwsA(isA<NodeError>().having((e) => e.code, 'code', 'ECONNREFUSED')),
      );
    });

    test('destroy while connecting closes without error or connect', () async {
      final server = net.createServer();
      final port = await _listen(server);
      final socket = net.connect(port, '127.0.0.1');
      final order = <String>[];
      socket.on('connect', () => order.add('connect'));
      socket.on('error', (Object _) => order.add('error'));
      socket.on('close', (bool hadError) => order.add('close:$hadError'));
      socket.destroy();
      await Future<void>.delayed(const Duration(milliseconds: 200));
      expect(order, ['close:false']);
      await _close(server);
    });

    test('connect options call the typed Node lookup callback', () async {
      final server = net.createServer();
      final port = await _listen(server);
      var lookedUp = false;
      final socket = net.connect({
        'port': port,
        'host': 'proxy.test',
        'lookup':
            (
              String hostname,
              dns.LookupOptions options,
              net.LookupCallback callback,
            ) {
              lookedUp = true;
              expect(hostname, 'proxy.test');
              expect(options.family, 0);
              expect(options.all, isTrue);
              callback(
                null,
                const dns.LookupResultAll([
                  dns.LookupAddress(address: '127.0.0.1', family: 4),
                ]),
              );
            },
      });
      await events.once(socket, 'connect').timeout(_wait);
      expect(lookedUp, isTrue);
      socket.destroy();
      await _close(server);
    });

    test('an IP literal host skips lookup', () async {
      final server = net.createServer();
      final port = await _listen(server);
      final socket = net.connect({
        'port': port,
        'host': '127.0.0.1',
        'lookup': (String h, dns.LookupOptions o, net.LookupCallback cb) =>
            fail('lookup called for an IP literal'),
      });
      await events.once(socket, 'connect').timeout(_wait);
      socket.destroy();
      await _close(server);
    });

    test('a lookup error is the socket error', () async {
      final socket = net.connect({
        'port': 80,
        'host': 'nowhere.test',
        'lookup': (String h, dns.LookupOptions o, net.LookupCallback cb) => cb(
          dns.NodeLookupError('ENOTFOUND', 'getaddrinfo ENOTFOUND $h'),
          null,
        ),
      });
      await expectLater(
        events.once(socket, 'connect'),
        throwsA(
          isA<dns.NodeLookupError>().having((e) => e.code, 'code', 'ENOTFOUND'),
        ),
      );
    });

    test('an unsupported option throws', () {
      expect(
        () => net.connect({'port': 1, 'localAddress': '127.0.0.1'}),
        throwsUnimplementedError,
      );
    });

    test('listen on a used port emits EADDRINUSE', () async {
      final first = net.createServer();
      final port = await _listen(first);
      final second = net.createServer();
      second.listen(port, '127.0.0.1');
      await expectLater(
        events.once(second, 'listening'),
        throwsA(
          isA<NodeError>()
              .having((e) => e.code, 'code', 'EADDRINUSE')
              .having((e) => e.syscall, 'syscall', 'listen')
              .having(
                (e) => e.message,
                'message',
                'listen EADDRINUSE: address already in use 127.0.0.1:$port',
              ),
        ),
      );
      expect(second.listening, isFalse);
      await _close(first);
    });

    test('listenInRange skips a used port', () async {
      final first = net.createServer();
      final used = await _listen(first);
      final second = net.createServer();
      await listenInRange(second, (port) => second.listen(port, '127.0.0.1'), [
        used,
        used + 20,
      ], {}).timeout(_wait);
      final port = (second.address()! as net.NodeAddress).port;
      expect(port, greaterThan(used));
      expect(second.listenerCount('error'), 0);
      expect(second.listenerCount('listening'), 0);
      await _close(second);
      await _close(first);
    });

    test('close on a server that is not listening', () async {
      final server = net.createServer();
      final result = Completer<Object?>();
      server.close(([Object? error]) => result.complete(error));
      expect(
        await result.future.timeout(_wait),
        isA<NodeError>().having(
          (e) => e.code,
          'code',
          'ERR_SERVER_NOT_RUNNING',
        ),
      );
    });

    test('Unix-domain socket listen and connect', () async {
      if (Platform.isWindows) return;
      final directory = await Directory.systemTemp.createTemp('net-shim-');
      final path = '${directory.path}/listener.sock';
      final server = net.createServer((net.NodeSocket socket) {
        socket.on('data', (List<int> bytes) => socket.end(bytes));
      });
      server.listen(path);
      await events.once(server, 'listening').timeout(_wait);
      final duplicate = net.createServer();
      duplicate.listen(path);
      await expectLater(
        events.once(duplicate, 'listening'),
        throwsA(isA<NodeError>().having((e) => e.code, 'code', 'EADDRINUSE')),
      );
      expect(server.address(), path);
      final client = net.connect(path);
      expect(client.remoteAddress, isNull);
      final response = Completer<List<int>>();
      client.on('data', (List<int> bytes) => response.complete(bytes));
      client.write([1, 2, 3]);
      expect(await response.future.timeout(_wait), [1, 2, 3]);
      client.destroy();
      await _close(server);
      expect(File(path).existsSync(), isFalse, reason: 'close unlinks');
      await directory.delete(recursive: true);
    });

    test('connect to a missing Unix path emits ENOENT', () async {
      if (Platform.isWindows) return;
      final directory = await Directory.systemTemp.createTemp('net-shim-');
      final path = '${directory.path}/missing.sock';
      final socket = net.connect({'path': path});
      await expectLater(
        events.once(socket, 'connect'),
        throwsA(
          isA<NodeError>()
              .having((e) => e.code, 'code', 'ENOENT')
              .having((e) => e.message, 'message', 'connect ENOENT $path'),
        ),
      );
      await directory.delete(recursive: true);
    });
  });

  group('EventEmitter', () {
    test('a listener gets as many arguments as it accepts', () {
      final emitter = events.EventEmitter();
      final got = <Object?>[];
      emitter.on('x', () => got.add('none'));
      emitter.on('x', (Object? a) => got.add(a));
      emitter.on('x', (Object? a, Object? b, Object? c) => got.add([a, b, c]));
      emitter.emit('x', 1, 2);
      expect(got, [
        'none',
        1,
        [1, 2, null],
      ]);
    });

    test('off removes a once listener; once fires one time', () {
      final emitter = events.EventEmitter();
      var calls = 0;
      void listener() => calls++;
      emitter.once('x', listener);
      emitter.off('x', listener);
      emitter.emit('x');
      emitter.once('x', listener);
      emitter.emit('x');
      emitter.emit('x');
      expect(calls, 1);
      expect(emitter.listenerCount('x'), 0);
    });

    test('an unhandled error event is an uncaught error', () async {
      final errors = <Object>[];
      await runZonedGuarded(() async {
        events.EventEmitter().emit('error', StateError('boom'));
        await Future<void>.delayed(Duration.zero);
      }, (error, stack) => errors.add(error));
      expect(errors.single, isA<StateError>());
    });
  });
}
