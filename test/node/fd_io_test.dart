// net.Socket({fd}) and server.listen({fd}) over raw descriptors.
@TestOn('mac-os || linux')
library;

import 'dart:async';
import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';
import 'package:sandbox_runtime/src/node/fs.dart' as fs;
import 'package:sandbox_runtime/src/node/http.dart' as http;
import 'package:sandbox_runtime/src/node/net.dart' as net;
import 'package:test/test.dart';

final _lib = DynamicLibrary.process();
final _socketpair = _lib
    .lookupFunction<
      Int32 Function(Int32, Int32, Int32, Pointer<Int32>),
      int Function(int, int, int, Pointer<Int32>)
    >('socketpair');
final _socket = _lib
    .lookupFunction<
      Int32 Function(Int32, Int32, Int32),
      int Function(int, int, int)
    >('socket');
final _bind = _lib
    .lookupFunction<
      Int32 Function(Int32, Pointer<Uint8>, Uint32),
      int Function(int, Pointer<Uint8>, int)
    >('bind');
final _listen = _lib
    .lookupFunction<Int32 Function(Int32, Int32), int Function(int, int)>(
      'listen',
    );
final _write = _lib
    .lookupFunction<
      IntPtr Function(Int32, Pointer<Uint8>, IntPtr),
      int Function(int, Pointer<Uint8>, int)
    >('write');
final _recv = _lib
    .lookupFunction<
      IntPtr Function(Int32, Pointer<Uint8>, IntPtr, Int32),
      int Function(int, Pointer<Uint8>, int, int)
    >('recv');
// MSG_DONTWAIT
final _dontwait = Platform.isMacOS ? 0x80 : 0x40;
final _close = _lib.lookupFunction<Int32 Function(Int32), int Function(int)>(
  'close',
);

void main() {
  test('fs.createReadStream(path, {fd}) reads a descriptor', () async {
    final fds = calloc<Int32>(2);
    expect(_socketpair(1, 1, 0, fds), 0);
    final a = fds[0], b = fds[1];
    calloc.free(fds);
    final p = calloc<Uint8>(2)..asTypedList(2).setAll(0, [7, 6]);
    _write(b, p, 2);
    calloc.free(p);
    _close(b);
    final r = fs.createReadStream('', fd: a);
    final chunks = <int>[];
    final ended = Completer<void>();
    r.on('data', (List<int> c) => chunks.addAll(c));
    r.on('end', ended.complete);
    await ended.future.timeout(const Duration(seconds: 5));
    expect(chunks, [7, 6]);
  });

  test('Socket({fd}) reads and writes a socketpair end', () async {
    final fds = calloc<Int32>(2);
    expect(_socketpair(1, 1, 0, fds), 0); // AF_UNIX, SOCK_STREAM
    final a = fds[0], b = fds[1];
    calloc.free(fds);
    final socket = net.NodeSocket(fd: a, readable: true, writable: true);
    final got = Completer<List<int>>();
    socket.on('data', (List<int> d) => got.complete(d));
    final p = calloc<Uint8>(3)..asTypedList(3).setAll(0, [1, 2, 3]);
    _write(b, p, 3);
    calloc.free(p);
    expect(await got.future.timeout(const Duration(seconds: 5)), [1, 2, 3]);
    final closed = Completer<void>();
    socket.on('close', (bool _) => closed.complete());
    socket.destroy();
    await closed.future.timeout(const Duration(seconds: 5));
    _close(b);
  });

  test('Server.listen({fd}) accepts connections', () async {
    final fd = _socket(2, 1, 0); // AF_INET, SOCK_STREAM
    final addr = calloc<Uint8>(16);
    if (Platform.isMacOS) addr[0] = 16;
    addr[Platform.isMacOS ? 1 : 0] = 2;
    addr[4] = 127;
    addr[7] = 1;
    expect(_bind(fd, addr, 16), 0);
    calloc.free(addr);
    expect(_listen(fd, 8), 0);
    final server = net.createServer();
    final data = Completer<List<int>>();
    server.on('connection', (net.NodeSocket s) {
      s.on('data', (List<int> d) => data.complete(d));
    });
    final listening = Completer<void>();
    server.listen({'fd': fd}, listening.complete);
    await listening.future.timeout(const Duration(seconds: 5));
    final port = (server.address()! as net.NodeAddress).port;
    expect(port, greaterThan(0));
    final client = await Socket.connect('127.0.0.1', port);
    client.add([9, 8]);
    await client.flush();
    expect(await data.future.timeout(const Duration(seconds: 5)), [9, 8]);
    client.destroy();
    final closed = Completer<void>();
    server.close(closed.complete);
    await closed.future.timeout(const Duration(seconds: 5));
  });

  test('isIPv4 / isIPv6', () {
    expect(net.isIPv4('1.2.3.4'), isTrue);
    expect(net.isIPv4('::1'), isFalse);
    expect(net.isIPv6('::1'), isTrue);
    expect(net.isIPv6('1.2.3.4'), isFalse);
  });

  test(
    'large write does not block the isolate; callback waits for drain',
    () async {
      final fds = calloc<Int32>(2);
      expect(_socketpair(1, 1, 0, fds), 0);
      final a = fds[0], b = fds[1];
      calloc.free(fds);
      final socket = net.NodeSocket(fd: a, readable: true, writable: true);
      const total = 4 * 1024 * 1024;
      final flushed = Completer<void>();
      socket.write(Uint8List(total), null, (Object? _) => flushed.complete());
      var ticks = 0;
      final t = Timer.periodic(
        const Duration(milliseconds: 10),
        (_) => ticks++,
      );
      await Future<void>.delayed(const Duration(milliseconds: 300));
      t.cancel();
      expect(ticks, greaterThan(10));
      expect(flushed.isCompleted, isFalse);
      final buf = calloc<Uint8>(65536);
      var got = 0;
      while (got < total) {
        final n = _recv(b, buf, 65536, _dontwait);
        if (n > 0) {
          got += n;
        } else {
          await Future<void>.delayed(const Duration(milliseconds: 2));
        }
      }
      calloc.free(buf);
      await flushed.future.timeout(const Duration(seconds: 5));
      socket.destroy();
      _close(b);
    },
  );

  test('writable:false socket close does not shutdown the peer', () async {
    final fds = calloc<Int32>(2);
    expect(_socketpair(1, 1, 0, fds), 0);
    final a = fds[0], b = fds[1];
    calloc.free(fds);
    final socket = net.NodeSocket(fd: a, readable: true, writable: false);
    final closed = Completer<void>();
    socket.on('close', (bool _) => closed.complete());
    socket.destroy();
    await closed.future.timeout(const Duration(seconds: 5));
    _close(b);
  });

  test('Agent defaults match Node', () {
    final a = http.Agent();
    expect(a.keepAlive, isFalse);
    expect(a.maxSockets, greaterThan(1 << 20));
    expect(http.globalAgent.keepAlive, isTrue);
    expect(http.globalAgent.maxSockets, greaterThan(1 << 20));
    expect(http.Agent(maxSockets: 1).maxSockets, 1);
  });
}
