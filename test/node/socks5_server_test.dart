import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:sandbox_runtime/src/node/socks5_server.dart';
import 'package:test/test.dart';

Future<(Socket, StreamIterator<int>)> _dial(Socks5Server s) async {
  final c = Completer<void>();
  s.listen(0, '127.0.0.1', () => c.complete());
  await c.future;
  final port = (s.server.address() as dynamic).port as int;
  final sock = await Socket.connect('127.0.0.1', port);
  final bytes = StreamIterator(sock.expand((b) => b));
  return (sock, bytes);
}

Future<List<int>> _take(StreamIterator<int> it, int n) async {
  final out = <int>[];
  while (out.length < n && await it.moveNext()) {
    out.add(it.current);
  }
  return out;
}

Future<bool> _closed(StreamIterator<int> it) async => !(await it.moveNext());

void main() {
  late Socks5Server server;
  setUp(() => server = createServer());
  tearDown(() => server.close());

  test('no acceptable method: replies 05 FF and closes', () async {
    server.setAuthHandler((c, a, d) => true);
    final (sock, it) = await _dial(server);
    sock.add([5, 1, 0]);
    expect(await _take(it, 2), [5, 255]);
    expect(await _closed(it), isTrue);
    sock.destroy();
  });

  test('bad version: closes without a reply', () async {
    final (sock, it) = await _dial(server);
    sock.add([4, 1, 0]);
    expect(await _closed(it), isTrue);
    sock.destroy();
  });

  test(
    'auth handler sees username/password; false denies with 01 01',
    () async {
      String? user, pass;
      server.setAuthHandler((c, a, d) {
        user = c.username;
        pass = c.password;
        return false;
      });
      final (sock, it) = await _dial(server);
      sock.add([5, 1, 2, 1, 1, 0x75, 2, 0x70, 0x77]);
      expect(await _take(it, 4), [5, 2, 1, 1]);
      expect(await _closed(it), isTrue);
      expect((user, pass), ('u', 'pw'));
      sock.destroy();
    },
  );

  test(
    'ruleset deny replies 05 02 with zero bind address; domain parsed',
    () async {
      String? addr;
      int? port;
      server.setRulesetValidator((c, a, d) {
        addr = c.destAddress;
        port = c.destPort;
        d();
        return null;
      });
      final (sock, it) = await _dial(server);
      // Greeting and request pipelined in one write.
      sock.add([5, 1, 0, 5, 1, 0, 3, 3, 0x61, 0x2e, 0x62, 0x01, 0xbb]);
      expect(await _take(it, 12), [5, 0, 5, 2, 0, 1, 0, 0, 0, 0, 0, 0]);
      expect((addr, port), ('a.b', 443));
      sock.destroy();
    },
  );

  test('ipv6 address is lowercase hex pairs joined by colons', () async {
    String? addr;
    server.setRulesetValidator((c, a, d) {
      addr = c.destAddress;
      return false;
    });
    final (sock, it) = await _dial(server);
    sock.add([5, 1, 0, 5, 1, 0, 4, ...List.filled(15, 0), 1, 0, 80]);
    await _take(it, 12);
    expect(addr, '0000:0000:0000:0000:0000:0000:0000:0001');
    sock.destroy();
  });

  test('unsupported command (bind) replies 05 07', () async {
    final (sock, it) = await _dial(server);
    sock.add([5, 1, 0, 5, 2, 0, 1, 127, 0, 0, 1, 0, 80]);
    expect(await _take(it, 4), [5, 0, 5, 7]);
    expect(await _closed(it), isTrue);
    sock.destroy();
  });

  test('connection handler status reply; invalid status throws', () async {
    Object? thrown;
    server.setConnectionHandler((c, send) {
      try {
        send('NOPE');
      } catch (e) {
        thrown = e;
      }
      send('CONNECTION_REFUSED');
      return null;
    });
    final (sock, it) = await _dial(server);
    sock.add([5, 1, 0, 5, 1, 0, 1, 127, 0, 0, 1, 0, 80]);
    expect(await _take(it, 12), [5, 0, 5, 5, 0, 1, 0, 0, 0, 0, 0, 0]);
    expect('$thrown', contains('"NOPE" is not a valid status.'));
    sock.destroy();
  });

  test('default handler relays to the destination', () async {
    final echo = await ServerSocket.bind('127.0.0.1', 0);
    echo.listen((s) => s.listen(s.add));
    final (sock, it) = await _dial(server);
    final p = echo.port;
    sock.add([5, 1, 0, 5, 1, 0, 1, 127, 0, 0, 1, p >> 8, p & 0xff]);
    expect(await _take(it, 12), [5, 0, 5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    sock.add(Uint8List.fromList([9, 8, 7]));
    expect(await _take(it, 3), [9, 8, 7]);
    sock.destroy();
    await echo.close();
  });

  test('default handler maps ECONNREFUSED to 05 05', () async {
    final tmp = await ServerSocket.bind('127.0.0.1', 0);
    final p = tmp.port;
    await tmp.close();
    final (sock, it) = await _dial(server);
    sock.add([5, 1, 0, 5, 1, 0, 1, 127, 0, 0, 1, p >> 8, p & 0xff]);
    expect(await _take(it, 4), [5, 0, 5, 5]);
    sock.destroy();
  });
}
