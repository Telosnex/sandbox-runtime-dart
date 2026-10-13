import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:sandbox_runtime/src/node/net.dart' as net;
import 'package:sandbox_runtime/src/node/dns.dart' as dns;
import 'package:test/test.dart';

void main() {
  group('net Socket', () {
    test('read(1) followed by unshift restores the byte', () async {
      final server = net.createServer();
      final received = Completer<List<int>>();
      server.on('connection', (net.NodeSocket socket) {
        socket.once('readable', () {
          final first = socket.read(1)!;
          socket.unshift(first);
          received.complete(socket.read()!);
        });
      });
      await server.listen(0, '127.0.0.1');
      final address = server.address()! as net.NodeAddress;
      final client = await net.connect(address.port, '127.0.0.1');
      client.write([0x16, 0x03, 0x01, 0x41, 0x42]);
      expect(await received.future.timeout(const Duration(seconds: 3)), [
        0x16,
        0x03,
        0x01,
        0x41,
        0x42,
      ]);
      client.destroy();
      await server.close();
    });

    test(
      'pipe relays bytes and propagates EOF without dropping the reply',
      () async {
        final echo = net.createServer();
        echo.on('connection', (net.NodeSocket socket) {
          socket.allowHalfOpen = true;
          socket.on('data', (List<int> bytes) => socket.write(bytes));
          socket.on('end', () => socket.end());
        });
        await echo.listen(0, '127.0.0.1');
        final echoAddress = echo.address()! as net.NodeAddress;

        final relay = net.createServer();
        relay.on('connection', (net.NodeSocket incoming) async {
          incoming.allowHalfOpen = true;
          final upstream = await net.connect(echoAddress.port, '127.0.0.1');
          incoming.pipe(upstream);
          upstream.pipe(incoming);
        });
        await relay.listen(0, '127.0.0.1');
        final relayAddress = relay.address()! as net.NodeAddress;

        final client = await net.connect(relayAddress.port, '127.0.0.1');
        final answer = BytesBuilder(copy: false);
        final ended = Completer<void>();
        client.on('data', (List<int> bytes) => answer.add(bytes));
        client.once('end', ended.complete);
        final payload = List<int>.generate(128 * 1024, (index) => index & 255);
        client.write(payload);
        client.end();
        await ended.future.timeout(const Duration(seconds: 5));
        expect(answer.takeBytes(), payload);
        await relay.close();
        await echo.close();
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
      await server.listen(0, '127.0.0.1');
      expect(server.listening, isTrue);
      final address = server.address()! as net.NodeAddress;
      expect(address.port, greaterThan(0));
      expect(address.address, '127.0.0.1');
      await server.close();
      expect(server.listening, isFalse);
      expect(closeEvents, 1);
    });

    test(
      'connect, write-before-close, error, and close events are ordered',
      () async {
        final server = net.createServer();
        await server.listen(0, '127.0.0.1');
        final address = server.address()! as net.NodeAddress;
        final socket = await net.connect(address.port, '127.0.0.1');
        final events = <String>[];
        final connected = Completer<void>();
        socket.once('connect', () {
          events.add('connect');
          connected.complete();
        });
        await connected.future.timeout(const Duration(seconds: 3));
        final wrote = Completer<void>();
        socket.write('before-close', () {
          events.add('write');
          wrote.complete();
        });
        await wrote.future.timeout(const Duration(seconds: 3));
        socket.on('error', (Object error) => events.add('error'));
        final closed = Completer<void>();
        socket.once('close', (bool hadError) {
          events.add('close:$hadError');
          closed.complete();
        });
        socket.destroy(StateError('intentional test close'));
        await closed.future.timeout(const Duration(seconds: 3));
        expect(events, ['connect', 'write', 'error', 'close:true']);
        await server.close();
      },
    );

    test('connect options call the typed Node lookup callback', () async {
      final server = net.createServer();
      await server.listen(0, '127.0.0.1');
      final address = server.address()! as net.NodeAddress;
      var lookedUp = false;
      final socket = await net.connect({
        'port': address.port,
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
              callback(null, const dns.LookupResultAddress('127.0.0.1'), 4);
            },
      });
      expect(lookedUp, isTrue);
      socket.destroy();
      await server.close();
    });

    test('Unix-domain socket listen and connect', () async {
      if (Platform.isWindows) return;
      final directory = await Directory.systemTemp.createTemp('net-shim-');
      final path = '${directory.path}/listener.sock';
      final server = net.createServer((net.NodeSocket socket) {
        socket.on('data', (List<int> bytes) => socket.end(bytes));
      });
      await server.listen(path);
      final duplicate = net.createServer();
      await expectLater(
        duplicate.listen(path),
        throwsA(isA<SocketException>()),
      );
      expect(server.address(), path);
      final client = await net.connect(path);
      final response = Completer<List<int>>();
      client.on('data', (List<int> bytes) => response.complete(bytes));
      client.write([1, 2, 3]);
      expect(await response.future.timeout(const Duration(seconds: 3)), [
        1,
        2,
        3,
      ]);
      client.destroy();
      await server.close();
      await directory.delete(recursive: true);
    });
  });
}
