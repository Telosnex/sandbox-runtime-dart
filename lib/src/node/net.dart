// `node:net`: isIP, BlockList, Socket, Server, connect and createServer.
//
// Socket and Server keep Node's call shape. `connect` returns the socket at
// once, in the connecting state; it emits 'connect' (or 'error' then
// 'close') later, and writes made before then are queued. `listen` and
// `close` return the server at once; the result arrives as a 'listening',
// 'error' or 'close' event. Use `events.once(socket, 'connect')` where
// upstream awaits a Promise that wraps those events.
//
// Socket errors are NodeError values with Node's `code`, `syscall`,
// `address` and `port` (see errno.dart `socketError`).
import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'dns.dart' as dns;
import 'errno.dart';
import 'events.dart';

/// Node's net.connect DNS callback contract. `options` describes the requested
/// family/order and callback receives NodeLookupError plus a LookupResult.
typedef LookupCallback =
    void Function(
      dns.NodeLookupError? err,
      dns.LookupResult? address, [
      int? family,
    ]);
typedef LookupFunction =
    void Function(
      String hostname,
      dns.LookupOptions options,
      LookupCallback callback,
    );

/// Node `net.isIP`: 4 for strict dotted-decimal IPv4, 6 for an IPv6 literal,
/// and 0 otherwise. The regexes mirror Node's internal/net.js expressions.
int isIP(String input) {
  if (_ipv4Regex.hasMatch(input)) return 4;
  if (_ipv6Regex.hasMatch(input)) return 6;
  return 0;
}

const _v4Seg = r'(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])';
final _v4Str = '(?:$_v4Seg\\.){3}$_v4Seg';
final _ipv4Regex = RegExp('^$_v4Str\$');
const _v6Seg = r'(?:[0-9a-fA-F]{1,4})';
final _ipv6Pattern =
    '^(?:'
    '(?:$_v6Seg:){7}(?:$_v6Seg|:)|'
    '(?:$_v6Seg:){6}(?:$_v4Str|:$_v6Seg|:)|'
    '(?:$_v6Seg:){5}(?::$_v4Str|(?::$_v6Seg){1,2}|:)|'
    '(?:$_v6Seg:){4}(?:(?::$_v6Seg){0,1}:$_v4Str|(?::$_v6Seg){1,3}|:)|'
    '(?:$_v6Seg:){3}(?:(?::$_v6Seg){0,2}:$_v4Str|(?::$_v6Seg){1,4}|:)|'
    '(?:$_v6Seg:){2}(?:(?::$_v6Seg){0,3}:$_v4Str|(?::$_v6Seg){1,5}|:)|'
    '(?:$_v6Seg:){1}(?:(?::$_v6Seg){0,4}:$_v4Str|(?::$_v6Seg){1,6}|:)|'
    '(?::(?:(?::$_v6Seg){0,5}:$_v4Str|(?::$_v6Seg){1,7}|:))'
    ')(?:%[0-9a-zA-Z-.:]{1,})?\$';
final _ipv6Regex = RegExp(_ipv6Pattern);

bool _isIPv4(String input) => _ipv4Regex.hasMatch(input);

/// IPv6 bytes from the same strict literal grammar as `node:net.isIP`.
/// Exposed to address.dart so BlockList and address-group logic share parsing.
List<int>? ipv6Bytes(String address) {
  final groups = _ipv6Groups(address);
  if (groups == null) return null;
  return [
    for (final group in groups) ...[(group >> 8) & 255, group & 255],
  ];
}

List<int>? _ipv6Groups(String input) {
  if (!_ipv6Regex.hasMatch(input)) return null;
  final zone = input.indexOf('%');
  var address = zone < 0 ? input : input.substring(0, zone);
  if (address.contains('.')) {
    final colon = address.lastIndexOf(':');
    if (colon < 0) return null;
    final dotted = address.substring(colon + 1);
    if (!_isIPv4(dotted)) return null;
    final octets = dotted.split('.').map(int.parse).toList();
    final high = (octets[0] << 8) | octets[1];
    final low = (octets[2] << 8) | octets[3];
    address =
        '${address.substring(0, colon + 1)}${high.toRadixString(16)}:${low.toRadixString(16)}';
  }

  final compression = address.indexOf('::');
  final hasCompression = compression >= 0;
  final List<String> leading;
  final List<String> trailing;
  if (hasCompression) {
    final head = address.substring(0, compression);
    final tail = address.substring(compression + 2);
    leading = head.isEmpty ? [] : head.split(':');
    trailing = tail.isEmpty ? [] : tail.split(':');
  } else {
    leading = address.split(':');
    trailing = [];
  }
  final all = [...leading, ...trailing];
  if (all.any((group) => !RegExp(r'^[0-9a-fA-F]{1,4}$').hasMatch(group))) {
    return null;
  }
  final parsed = all.map((group) => int.parse(group, radix: 16)).toList();
  if (!hasCompression) return parsed.length == 8 ? parsed : null;
  final fill = 8 - parsed.length;
  if (fill < 1 || leading.length + trailing.length + fill != 8) return null;
  return [
    ...parsed.take(leading.length),
    ...List<int>.filled(fill, 0),
    ...parsed.skip(leading.length),
  ];
}

/// Dart representation of the Node `net.BlockList` subset used by this port.
class BlockList {
  final List<_Subnet> _subnets = [];

  /// Add the same address/prefix/family triple accepted by Node's addSubnet.
  void addSubnet(String address, int prefix, String family) {
    final bytes = _bytesFor(address, family);
    final max = family == 'ipv4'
        ? 32
        : family == 'ipv6'
        ? 128
        : -1;
    if (bytes == null || prefix < 0 || prefix > max) {
      throw ArgumentError('Invalid subnet');
    }
    _subnets.add(_Subnet(bytes, prefix, family));
  }

  /// Check membership, including Node's IPv4-rule match for IPv4-mapped IPv6.
  bool check(String address, String family) {
    final bytes = _bytesFor(address, family);
    if (bytes == null) return false;
    for (final subnet in _subnets) {
      if (subnet.family == family &&
          _matches(bytes, subnet.bytes, subnet.prefix)) {
        return true;
      }
      if (family == 'ipv6' && subnet.family == 'ipv4') {
        final mapped = _mappedIPv4Bytes(bytes);
        if (mapped != null && _matches(mapped, subnet.bytes, subnet.prefix)) {
          return true;
        }
      }
    }
    return false;
  }
}

class _Subnet {
  const _Subnet(this.bytes, this.prefix, this.family);
  final List<int> bytes;
  final int prefix;
  final String family;
}

List<int>? _bytesFor(String address, String family) {
  if ((family == 'ipv4' && isIP(address) != 4) ||
      (family == 'ipv6' && isIP(address) != 6)) {
    return null;
  }
  if (family == 'ipv4') {
    return address.split('.').map(int.parse).toList();
  }
  return ipv6Bytes(address);
}

List<int>? _mappedIPv4Bytes(List<int> bytes) {
  if (bytes.length != 16 ||
      bytes.take(10).any((byte) => byte != 0) ||
      bytes[10] != 255 ||
      bytes[11] != 255) {
    return null;
  }
  return bytes.sublist(12);
}

bool _matches(List<int> address, List<int> network, int prefix) {
  final wholeBytes = prefix ~/ 8;
  final remainingBits = prefix % 8;
  for (var index = 0; index < wholeBytes; index++) {
    if (address[index] != network[index]) return false;
  }
  if (remainingBits == 0) return true;
  final mask = (0xff << (8 - remainingBits)) & 0xff;
  return (address[wholeBytes] & mask) == (network[wholeBytes] & mask);
}

/// Node-like byte duplex over dart:io Socket. This is intentionally limited
/// to the event and stream operations consumed by the sandbox proxies.
/// Node `net.Socket`.
class NodeSocket extends EventEmitter {
  /// A socket with no connection yet. `net.connect` and `tls.connect` create
  /// one and then call [startConnect].
  NodeSocket.pending({this.allowHalfOpen = false}) : _connecting = true;

  /// Adopt a connected dart:io socket, as a server does with an accepted
  /// connection. No 'connect' event is emitted, as in Node.
  NodeSocket.fromSocket(Socket socket, {this.allowHalfOpen = false})
    : _connecting = false {
    _attach(socket);
  }

  static const int highWaterMark = 16 * 1024;
  Socket? _socket;
  StreamSubscription<Uint8List>? _subscription;
  ConnectionTask<Socket>? _task;
  final List<Uint8List> _readQueue = [];
  int _readOffset = 0;
  int _pendingBytes = 0;
  int _bytesWritten = 0;
  bool _flushing = false;
  final List<_PendingWrite> _writeQueue = [];
  bool _writeShutdownStarted = false;
  bool _writeShutdownComplete = false;
  bool _connecting;
  bool _readEnded = false;
  bool _writeEnded = false;
  bool _closed = false;
  bool _destroyed = false;
  bool _unrefed = false;
  bool _flowing = false;
  bool _paused = false;
  bool? _noDelay;
  bool allowHalfOpen;
  Timer? _timeoutTimer;
  int _timeoutMs = 0;
  bool _hadError = false;

  void _attach(Socket socket) {
    _socket = socket;
    _connecting = false;
    if (_noDelay != null) {
      socket.setOption(SocketOption.tcpNoDelay, _noDelay!);
    }
    _subscription = socket.listen(
      _received,
      onError: (Object error, StackTrace stack) {
        _hadError = true;
        emit('error', socketError(error, 'read'));
        _finishClose();
      },
      onDone: () {
        if (!_readEnded) {
          _readEnded = true;
          emit('end');
          emit('readable');
          if (!allowHalfOpen && !_writeEnded) end();
        }
        if (_writeShutdownComplete) _finishClose();
      },
      cancelOnError: false,
    );
    if (_paused) _subscription!.pause();
    socket.done.then<void>(
      (_) {},
      onError: (Object error) {
        _hadError = true;
        emit('error', socketError(error, 'write'));
        _finishClose();
      },
    );
    if (_writeQueue.isNotEmpty) {
      _flushWrites();
    } else if (_writeEnded && _pendingBytes == 0) {
      _shutdownWrite();
    }
  }

  /// Open the connection for a [NodeSocket.pending] socket. [secure], when
  /// given, wraps the connected socket in TLS: 'connect' is emitted when TCP
  /// connects, and 'secureConnect' when the handshake is done.
  void startConnect({
    String? path,
    int? port,
    String host = 'localhost',
    LookupFunction? lookup,
    Future<Socket> Function(Socket raw)? secure,
  }) {
    unawaited(_connect(path, port, host, lookup, secure));
  }

  Future<void> _connect(
    String? path,
    int? port,
    String host,
    LookupFunction? lookup,
    Future<Socket> Function(Socket raw)? secure,
  ) async {
    try {
      Socket? raw;
      if (path != null) {
        raw =
            await _dial(
              InternetAddress(path, type: InternetAddressType.unix),
              0,
            ).catchError(
              (Object e) => throw socketError(e, 'connect', address: path),
            );
      } else {
        final addresses = await _resolve(host, lookup);
        if (_destroyed) return;
        emit(
          'lookup',
          null,
          addresses.first.address,
          addresses.first.family,
          host,
        );
        Object? lastError;
        for (final candidate in addresses) {
          try {
            raw = await _dial(InternetAddress(candidate.address), port!);
            break;
          } catch (e) {
            if (_destroyed) return;
            lastError = socketError(
              e,
              'connect',
              address: candidate.address,
              port: port,
            );
          }
        }
        if (raw == null) throw lastError!;
      }
      if (_destroyed) {
        raw.destroy();
        return;
      }
      if (secure == null) {
        _attach(raw);
        emit('connect');
        emit('ready');
        return;
      }
      _connecting = false;
      emit('connect');
      final secured = await secure(raw);
      if (_destroyed) {
        secured.destroy();
        return;
      }
      _attach(secured);
      emit('secureConnect');
    } catch (error) {
      if (_destroyed) return;
      destroy(error is SocketException ? socketError(error, 'connect') : error);
    }
  }

  Future<Socket> _dial(InternetAddress address, int port) async {
    final task = await Socket.startConnect(address, port);
    _task = task;
    try {
      return await task.socket;
    } finally {
      _task = null;
    }
  }

  Future<List<dns.LookupAddress>> _resolve(
    String host,
    LookupFunction? lookup,
  ) {
    final family = isIP(host);
    if (family != 0) {
      return Future.value([dns.LookupAddress(address: host, family: family)]);
    }
    final result = Completer<List<dns.LookupAddress>>();
    // Node's default lookup is dns.lookup. With autoSelectFamily (the
    // default since Node 20) it asks for every address and tries each.
    final fn = lookup ?? dns.lookup;
    fn(host, dns.LookupAllOptions(family: 0), (
      dns.NodeLookupError? error,
      dns.LookupResult? value, [
      int? family,
    ]) {
      if (result.isCompleted) return;
      if (error != null) {
        result.completeError(error);
      } else if (value is dns.LookupResultAll && value.addresses.isNotEmpty) {
        result.complete(value.addresses);
      } else if (value is dns.LookupResultAddress) {
        result.complete([
          dns.LookupAddress(
            address: value.address,
            family: family ?? isIP(value.address),
          ),
        ]);
      } else {
        result.completeError(
          dns.NodeLookupError('ENOTFOUND', 'getaddrinfo ENOTFOUND $host'),
        );
      }
    });
    return result.future;
  }

  bool get connecting => _connecting;
  bool get pending => _socket == null;
  bool get destroyed => _destroyed;
  bool get readable => !_readEnded && !_destroyed;
  bool get writable => !_writeEnded && !_destroyed;
  bool get writableEnded => _writeEnded;
  bool get writableFinished => _writeEnded && _pendingBytes == 0;
  bool get readableEnded => _readEnded;
  bool get closed => _closed;
  int get writableLength => _pendingBytes;
  int get bytesWritten => _bytesWritten;
  bool get unrefed => _unrefed;

  bool get _isUnix => _socket?.address.type == InternetAddressType.unix;

  /// As in Node, these are null for a Unix-domain socket or before connect.
  String? get remoteAddress =>
      _socket == null || _isUnix ? null : _socket!.remoteAddress.address;
  int? get remotePort =>
      _socket == null || _isUnix ? null : _socket!.remotePort;
  String? get remoteFamily => _socket == null || _isUnix
      ? null
      : (_socket!.remoteAddress.type == InternetAddressType.IPv6
            ? 'IPv6'
            : 'IPv4');
  String? get localAddress =>
      _socket == null || _isUnix ? null : _socket!.address.address;
  int? get localPort => _socket == null || _isUnix ? null : _socket!.port;

  /// A 'data' listener puts the readable side in flowing mode, as in Node; a
  /// 'readable' listener can pull with [read].
  @override
  NodeSocket on(String event, Function listener) {
    super.on(event, listener);
    _listenerAdded(event);
    return this;
  }

  @override
  NodeSocket once(String event, Function listener) {
    super.once(event, listener);
    _listenerAdded(event);
    return this;
  }

  @override
  NodeSocket prependListener(String event, Function listener) {
    super.prependListener(event, listener);
    _listenerAdded(event);
    return this;
  }

  void _listenerAdded(String event) {
    if (event == 'data') {
      _flowing = true;
      _deliverQueued();
    }
    if (event == 'readable' && _readQueue.isNotEmpty) {
      scheduleMicrotask(() => emit('readable'));
    }
  }

  @override
  NodeSocket off(String event, Function listener) {
    super.off(event, listener);
    return this;
  }

  @override
  NodeSocket removeListener(String event, Function listener) =>
      off(event, listener);

  void _received(Uint8List bytes) {
    if (bytes.isEmpty || _destroyed) return;
    final copy = Uint8List.fromList(bytes);
    if (_flowing && !_paused) {
      emit('data', copy);
    } else {
      _readQueue.add(copy);
      emit('readable');
    }
    _resetTimeout();
  }

  /// Read up to [size] bytes synchronously, or null when no byte is ready.
  Uint8List? read([int? size]) {
    if (_readQueue.isEmpty) return null;
    if (size == null || size <= 0) {
      final parts = <Uint8List>[];
      while (_readQueue.isNotEmpty) {
        final part = _readQueue.removeAt(0);
        if (_readOffset != 0) {
          parts.add(Uint8List.sublistView(part, _readOffset));
          _readOffset = 0;
        } else {
          parts.add(part);
        }
      }
      return _concat(parts);
    }
    var remaining = size;
    final out = BytesBuilder(copy: false);
    while (remaining > 0 && _readQueue.isNotEmpty) {
      final first = _readQueue.first;
      final available = first.length - _readOffset;
      final take = available < remaining ? available : remaining;
      out.add(Uint8List.sublistView(first, _readOffset, _readOffset + take));
      remaining -= take;
      _readOffset += take;
      if (_readOffset == first.length) {
        _readQueue.removeAt(0);
        _readOffset = 0;
      }
    }
    return out.takeBytes();
  }

  /// Put bytes back at the head of the readable queue (Node `unshift`).
  void unshift(List<int> bytes) {
    if (bytes.isEmpty || _destroyed) return;
    if (_readQueue.isEmpty) {
      _readQueue.insert(0, Uint8List.fromList(bytes));
      _readOffset = 0;
    } else {
      final current = read();
      _readQueue
        ..clear()
        ..add(Uint8List.fromList([...bytes, if (current != null) ...current]));
      _readOffset = 0;
    }
    emit('readable');
  }

  /// Write a byte/string chunk. The boolean mirrors Node's high-water mark
  /// contract; callers must wait for `drain` before resuming after false.
  /// A string is written as Latin-1 bytes.
  bool write(Object data, [Function? callback]) {
    if (_destroyed) {
      // Node passes ERR_STREAM_DESTROYED to the callback and emits nothing.
      final error = NodeError(
        'Cannot call write after a stream was destroyed',
        code: 'ERR_STREAM_DESTROYED',
      );
      if (callback != null) {
        scheduleMicrotask(() => applyListener(callback, [error]));
      }
      return false;
    }
    if (_writeEnded) {
      final error = NodeError(
        'write after end',
        code: 'ERR_STREAM_WRITE_AFTER_END',
      );
      if (callback != null) {
        scheduleMicrotask(() => applyListener(callback, [error]));
      }
      scheduleMicrotask(() => emit('error', error));
      return false;
    }
    final bytes = data is String
        ? Uint8List.fromList(data.codeUnits.map((c) => c & 0xff).toList())
        : Uint8List.fromList(data as List<int>);
    if (bytes.isEmpty) {
      if (callback != null) {
        scheduleMicrotask(() => applyListener(callback, const []));
      }
      return _pendingBytes < highWaterMark;
    }
    _pendingBytes += bytes.length;
    _bytesWritten += bytes.length;
    _writeQueue.add(_PendingWrite(bytes, callback));
    _flushWrites();
    _resetTimeout();
    return _pendingBytes < highWaterMark;
  }

  void _flushWrites() {
    if (_flushing || _closed || _socket == null) return;
    _flushing = true;
    unawaited(_pumpWrites());
  }

  Future<void> _pumpWrites() async {
    final socket = _socket!;
    try {
      while (!_closed && _writeQueue.isNotEmpty) {
        final batch = List<_PendingWrite>.of(_writeQueue);
        _writeQueue.clear();
        for (final write in batch) {
          socket.add(write.bytes);
        }
        await socket.flush();
        final previous = _pendingBytes;
        for (final write in batch) {
          _pendingBytes = (_pendingBytes - write.bytes.length).clamp(
            0,
            1 << 62,
          );
          if (write.callback != null) applyListener(write.callback!, const []);
        }
        if (previous >= highWaterMark && _pendingBytes < highWaterMark) {
          emit('drain');
        }
      }
    } catch (error) {
      final nodeError = socketError(error, 'write');
      for (final write in _writeQueue) {
        if (write.callback != null) applyListener(write.callback!, [nodeError]);
      }
      _writeQueue.clear();
      destroy(nodeError);
    } finally {
      _flushing = false;
      if (_writeQueue.isNotEmpty) {
        _flushWrites();
      } else if (_writeEnded && _pendingBytes == 0) {
        _shutdownWrite();
      }
    }
  }

  /// Flush [data] then half-close the write direction while retaining reads.
  NodeSocket end([Object? data, Function? callback]) {
    if (data != null) write(data);
    if (callback != null) once('finish', callback);
    if (!_writeEnded) {
      _writeEnded = true;
      if (_pendingBytes == 0) _shutdownWrite();
    }
    return this;
  }

  void _shutdownWrite() {
    if (_closed || _writeShutdownStarted || _socket == null) return;
    _writeShutdownStarted = true;
    try {
      // dart:io Socket.close() flushes, then shuts down only the send side.
      _socket!.close().then<void>((_) {
        _writeShutdownComplete = true;
        emit('finish');
        if (_readEnded) _finishClose();
      }, onError: (Object error) => destroy(socketError(error, 'shutdown')));
    } catch (error) {
      destroy(socketError(error, 'shutdown'));
    }
  }

  /// Close the descriptor at once. With [error], 'error' is emitted before
  /// 'close'. A connection still being opened is abandoned.
  NodeSocket destroy([Object? error]) {
    if (_destroyed) return this;
    _destroyed = true;
    _timeoutTimer?.cancel();
    _task?.cancel();
    if (error != null) {
      _hadError = true;
      emit('error', error);
    }
    _socket?.destroy();
    _subscription?.cancel();
    _finishClose();
    return this;
  }

  void _finishClose() {
    if (_closed) return;
    _closed = true;
    _destroyed = true;
    _timeoutTimer?.cancel();
    emit('close', _hadError);
  }

  NodeSocket pause() {
    if (!_paused) _subscription?.pause();
    _paused = true;
    return this;
  }

  NodeSocket resume() {
    final wasPaused = _paused;
    _paused = false;
    if (_flowing) _deliverQueued();
    if (wasPaused) _subscription?.resume();
    return this;
  }

  void _deliverQueued() {
    while (_flowing && !_paused && _readQueue.isNotEmpty) {
      final data = read();
      if (data == null || data.isEmpty) break;
      emit('data', data);
    }
  }

  NodeSocket setNoDelay([bool noDelay = true]) {
    _noDelay = noDelay;
    _socket?.setOption(SocketOption.tcpNoDelay, noDelay);
    return this;
  }

  /// As in Node, the idle timer also runs while the socket is connecting.
  NodeSocket setTimeout(int milliseconds, [Function? callback]) {
    _timeoutMs = milliseconds;
    if (callback != null) once('timeout', callback);
    _resetTimeout();
    return this;
  }

  void _resetTimeout() {
    _timeoutTimer?.cancel();
    if (_timeoutMs > 0 && !_closed) {
      _timeoutTimer = Timer(Duration(milliseconds: _timeoutMs), () {
        emit('timeout');
      });
    }
  }

  /// Dart has no isolate-level `unref`; retain the Node contract as lifecycle
  /// bookkeeping without allowing a timer to keep the process alive.
  NodeSocket unref() {
    _unrefed = true;
    return this;
  }

  NodeSocket ref() {
    _unrefed = false;
    return this;
  }

  /// Pipe bytes with destination backpressure and Node's default end policy.
  NodeSocket pipe(NodeSocket destination, {bool end = true}) {
    var blocked = false;
    void onData(Object? value) {
      final bytes = value! as List<int>;
      if (!destination.write(bytes)) {
        blocked = true;
        pause();
        destination.once('drain', () {
          blocked = false;
          if (!destroyed) resume();
        });
      }
    }

    void onEnd() {
      if (end) destination.end();
    }

    void onClose() {
      if (blocked && !destination.destroyed) destination.destroy();
    }

    on('data', onData);
    once('end', onEnd);
    once('close', onClose);
    return destination;
  }

  Uint8List _concat(List<Uint8List> parts) {
    final builder = BytesBuilder(copy: false);
    for (final part in parts) {
      builder.add(part);
    }
    return builder.takeBytes();
  }
}

class _PendingWrite {
  const _PendingWrite(this.bytes, this.callback);
  final Uint8List bytes;
  final Function? callback;
}

/// Node `net.Server` for TCP and Unix-domain listeners.
class NodeServer extends EventEmitter {
  NodeServer({this.allowHalfOpen = false});

  final bool allowHalfOpen;
  ServerSocket? _tcp;
  bool _listening = false;
  bool _binding = false;
  bool _closeEmitted = true;
  bool _unrefed = false;
  final Set<NodeSocket> _connections = {};
  String? _unixPath;
  int? _port;
  String? _host;

  bool get listening => _listening;
  bool get unrefed => _unrefed;

  @override
  NodeServer on(String event, Function listener) {
    super.on(event, listener);
    return this;
  }

  @override
  NodeServer once(String event, Function listener) {
    super.once(event, listener);
    return this;
  }

  @override
  NodeServer off(String event, Function listener) {
    super.off(event, listener);
    return this;
  }

  @override
  NodeServer removeListener(String event, Function listener) =>
      off(event, listener);

  /// Node's forms: `listen(port[, host][, backlog][, cb])`,
  /// `listen(path[, cb])`, `listen({port, host, path}[, cb])` and
  /// `listen([cb])` (port 0). The result is a 'listening' or 'error' event.
  NodeServer listen([Object? a, Object? b, Object? c, Object? d]) {
    if (_listening || _binding) {
      throw NodeError(
        'Listen method has been called more than once without closing.',
        code: 'ERR_SERVER_ALREADY_LISTEN',
      );
    }
    final args = [a, b, c, d].where((x) => x != null).toList();
    final callback = args.isNotEmpty && args.last is Function
        ? args.removeLast() as Function
        : null;
    String? path;
    int? port;
    String? host;
    final first = args.isEmpty ? null : args.first;
    if (first is Map) {
      for (final key in first.keys) {
        if (!const {'port', 'host', 'path'}.contains(key)) {
          throw UnimplementedError('net.Server.listen option "$key"');
        }
      }
      path = first['path'] as String?;
      port = first['port'] as int?;
      host = first['host'] as String?;
    } else if (first is String) {
      path = first;
    } else if (first is int) {
      port = first;
      if (args.length > 1 && args[1] is String) host = args[1] as String;
    } else if (first != null) {
      throw ArgumentError.value(first, 'listen');
    }
    if (callback != null) once('listening', callback);
    _binding = true;
    unawaited(_bind(path, port ?? 0, host));
    return this;
  }

  Future<void> _bind(String? path, int port, String? host) async {
    try {
      if (path != null) {
        _unixPath = path;
        if (Platform.isWindows) {
          // Windows has no Unix-domain listener here: bind loopback TCP.
          _tcp = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
          _port = _tcp!.port;
          _host = '127.0.0.1';
        } else {
          _tcp =
              await ServerSocket.bind(
                InternetAddress(path, type: InternetAddressType.unix),
                0,
              ).catchError(
                (Object e) => throw socketError(e, 'listen', address: path),
              );
          _port = null;
        }
      } else if (host == null) {
        // Node binds the IPv6 wildcard, dual-stack, and falls back to IPv4.
        try {
          _tcp = await ServerSocket.bind(
            InternetAddress.anyIPv6,
            port,
            v6Only: false,
          );
          _host = '::';
        } on SocketException {
          _tcp = await ServerSocket.bind(InternetAddress.anyIPv4, port)
              .catchError(
                (Object e) => throw socketError(
                  e,
                  'listen',
                  address: '0.0.0.0',
                  port: port,
                ),
              );
          _host = '0.0.0.0';
        }
        _port = _tcp!.port;
      } else {
        _tcp = await ServerSocket.bind(host, port).catchError(
          (Object e) =>
              throw socketError(e, 'listen', address: host, port: port),
        );
        _host = _tcp!.address.address;
        _port = _tcp!.port;
      }
    } catch (error) {
      _binding = false;
      _unixPath = null;
      emit('error', socketError(error, 'listen'));
      return;
    }
    _binding = false;
    _listening = true;
    _closeEmitted = false;
    _tcp!.listen((socket) {
      final wrapped = NodeSocket.fromSocket(
        socket,
        allowHalfOpen: allowHalfOpen,
      );
      _connections.add(wrapped);
      wrapped.once('close', () {
        _connections.remove(wrapped);
        _emitCloseIfDrained();
      });
      emit('connection', wrapped);
    }, onError: (Object error) => emit('error', socketError(error, 'accept')));
    emit('listening');
  }

  /// Node `server.address()`: the path for a Unix-domain listener.
  Object? address() => !_listening
      ? null
      : _unixPath != null && !Platform.isWindows
      ? _unixPath
      : NodeAddress(_host ?? '127.0.0.1', _port!);

  /// Stop accepting. 'close' is emitted once every open connection has
  /// closed. [callback] gets ERR_SERVER_NOT_RUNNING when the server was not
  /// listening, as in Node.
  NodeServer close([Function? callback]) {
    if (callback != null) {
      if (!_listening) {
        once(
          'close',
          () => applyListener(callback, [
            NodeError('Server is not running.', code: 'ERR_SERVER_NOT_RUNNING'),
          ]),
        );
      } else {
        once('close', callback);
      }
    }
    if (_listening) {
      _listening = false;
      final tcp = _tcp!;
      final unixPath = _unixPath;
      _tcp = null;
      _unixPath = null;
      unawaited(
        tcp.close().then((_) async {
          // libuv unlinks a Unix-domain listener's path on close.
          if (unixPath != null && !Platform.isWindows) {
            try {
              await File(unixPath).delete();
            } on FileSystemException {
              // Another process may already have removed it.
            }
          }
          _emitCloseIfDrained();
        }),
      );
    } else {
      _closeEmitted = false;
      scheduleMicrotask(_emitCloseIfDrained);
    }
    return this;
  }

  void _emitCloseIfDrained() {
    if (_listening || _tcp != null || _closeEmitted) return;
    if (_connections.isNotEmpty) return;
    _closeEmitted = true;
    emit('close');
  }

  NodeServer unref() {
    _unrefed = true;
    return this;
  }

  NodeServer ref() {
    _unrefed = false;
    return this;
  }
}

class NodeAddress {
  const NodeAddress(this.address, this.port);
  final String address;
  final int port;
  String get family => isIP(address) == 6 ? 'IPv6' : 'IPv4';
}

/// Node `net.createServer([options][, connectionListener])`.
NodeServer createServer([Object? optionsOrListener, Function? listener]) {
  var allowHalfOpen = false;
  if (optionsOrListener is Function) {
    listener = optionsOrListener;
  } else if (optionsOrListener is Map) {
    for (final key in optionsOrListener.keys) {
      if (key != 'allowHalfOpen') {
        throw UnimplementedError('net.createServer option "$key"');
      }
    }
    allowHalfOpen = optionsOrListener['allowHalfOpen'] == true;
  }
  final server = NodeServer(allowHalfOpen: allowHalfOpen);
  if (listener != null) server.on('connection', listener);
  return server;
}

const _connectOptions = {
  'port',
  'host',
  'path',
  'lookup',
  'timeout',
  'allowHalfOpen',
  'noDelay',
};

/// Node `net.connect` / `net.createConnection`. Forms: `connect(options[,
/// listener])`, `connect(path[, listener])`, `connect(port[, host][,
/// listener])`. Returns the socket at once; [listener] is added for
/// 'connect'.
NodeSocket connect(Object portPathOrOptions, [Object? b, Object? c]) {
  final options = portPathOrOptions is Map
      ? Map<Object?, Object?>.of(portPathOrOptions)
      : <Object?, Object?>{
          if (portPathOrOptions is String) 'path': portPathOrOptions,
          if (portPathOrOptions is int) 'port': portPathOrOptions,
          if (b is String) 'host': b,
        };
  final listener = c is Function ? c : (b is Function ? b : null);
  options.removeWhere((key, value) => value == null);
  for (final key in options.keys) {
    if (!_connectOptions.contains(key)) {
      throw UnimplementedError('net.connect option "$key"');
    }
  }
  final socket = NodeSocket.pending(
    allowHalfOpen: options['allowHalfOpen'] == true,
  );
  if (options['noDelay'] == true) socket.setNoDelay();
  if (options['timeout'] is int) socket.setTimeout(options['timeout'] as int);
  if (listener != null) socket.once('connect', listener);
  final path = options['path'] as String?;
  final port = options['port'] as int?;
  if (path == null && port == null) {
    throw ArgumentError('net.connect requires a port or a path');
  }
  socket.startConnect(
    path: path,
    port: port,
    host: options['host'] as String? ?? 'localhost',
    lookup: options['lookup'] as LookupFunction?,
  );
  return socket;
}

/// Node `net.createConnection`, the same function as [connect].
NodeSocket createConnection(Object portPathOrOptions, [Object? b, Object? c]) =>
    connect(portPathOrOptions, b, c);
