// Minimal `node:net` equivalents for address.dart: Node's strict isIP result
// and the subnet/IPv4-mapped matching behavior used by net.BlockList.
import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

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
class NodeSocket {
  NodeSocket._(this._socket, {required bool connecting}) {
    _subscription = _socket.listen(
      _received,
      onError: (Object error, StackTrace stack) {
        _emit('error', error);
        _finishClose();
      },
      onDone: () {
        if (!_readEnded) {
          _readEnded = true;
          _emit('end');
          _emit('readable');
        }
        _finishClose();
      },
      cancelOnError: false,
    );
    _socket.done.then<void>((_) => _finishClose(), onError: (Object error) {
      _emit('error', error);
      _finishClose();
    });
    if (!connecting) scheduleMicrotask(() => _emit('connect'));
  }

  static const int highWaterMark = 16 * 1024;
  final Socket _socket;
  late final StreamSubscription<Uint8List> _subscription;
  final Map<String, List<Function>> _listeners = {};
  final List<Uint8List> _readQueue = [];
  int _readOffset = 0;
  int _pendingBytes = 0;
  int _bytesWritten = 0;
  bool _flushing = false;
  bool _readEnded = false;
  bool _writeEnded = false;
  bool _closed = false;
  bool _destroyed = false;
  bool _unrefed = false;
  bool _flowing = false;
  bool _paused = false;
  Timer? _timeoutTimer;
  int _timeoutMs = 0;

  /// Create a socket connected to a TCP endpoint or a Unix-domain path.
  static Future<NodeSocket> connect(Object pathOrPort, [String? host]) async {
    if (pathOrPort is String) {
      final address = InternetAddress(pathOrPort, type: InternetAddressType.unix);
      return NodeSocket._(await Socket.connect(address, 0), connecting: false);
    }
    final port = pathOrPort as int;
    return NodeSocket._(
      await Socket.connect(host ?? 'localhost', port),
      connecting: false,
    );
  }

  bool get connecting => false;
  bool get destroyed => _destroyed;
  bool get readable => !_readEnded && !_destroyed;
  bool get writable => !_writeEnded && !_destroyed;
  bool get writableEnded => _writeEnded;
  bool get writableFinished => _writeEnded && _pendingBytes == 0;
  bool get readableEnded => _readEnded;
  bool get closed => _closed;
  int get writableLength => _pendingBytes;
  int get bytesWritten => _bytesWritten;
  InternetAddress get remoteAddress => _socket.remoteAddress;
  int get remotePort => _socket.remotePort;
  InternetAddress get localAddress => _socket.address;
  int get localPort => _socket.port;
  bool get unrefed => _unrefed;

  /// Install an event listener. `data` listeners put the readable side in
  /// flowing mode; `readable` listeners can pull with [read].
  NodeSocket on(String event, Function listener) {
    (_listeners[event] ??= []).add(listener);
    if (event == 'data') {
      _flowing = true;
      _deliverQueued();
    }
    if (event == 'readable' && _readQueue.isNotEmpty) {
      scheduleMicrotask(() => _emit('readable'));
    }
    return this;
  }

  NodeSocket once(String event, Function listener) {
    late Function wrapped;
    wrapped = (Object? value) {
      off(event, wrapped);
      Function.apply(listener, value == null ? const [] : [value]);
    };
    return on(event, wrapped);
  }

  NodeSocket off(String event, Function listener) {
    _listeners[event]?.remove(listener);
    return this;
  }

  NodeSocket removeListener(String event, Function listener) => off(event, listener);

  int listenerCount(String event) => _listeners[event]?.length ?? 0;

  void _emit(String event, [Object? value]) {
    for (final listener in List<Function>.of(_listeners[event] ?? const [])) {
      try {
        Function.apply(listener, value == null ? const [] : [value]);
      } catch (error, stack) {
        scheduleMicrotask(() => Zone.current.handleUncaughtError(error, stack));
      }
    }
  }

  void _received(Uint8List bytes) {
    if (bytes.isEmpty || _destroyed) return;
    final copy = Uint8List.fromList(bytes);
    _bytesWritten += 0;
    if (_flowing && !_paused) {
      _emit('data', copy);
    } else {
      _readQueue.add(copy);
      _emit('readable');
    }
    _resetTimeout();
  }

  /// Read up to [size] bytes synchronously, or null when no byte is ready.
  Uint8List? read([int? size]) {
    if (_flowing) _flowing = false;
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
    _emit('readable');
  }

  /// Write a byte/string chunk. The boolean mirrors Node's high-water mark
  /// contract; callers must wait for `drain` before resuming after false.
  bool write(Object data, [Function? callback]) {
    if (!writable) {
      final error = SocketException('write after end', osError: const OSError('Broken pipe', 32));
      if (callback != null) scheduleMicrotask(() => callback(error));
      _emit('error', error);
      return false;
    }
    final bytes = data is String
        ? Uint8List.fromList(data.codeUnits.map((c) => c & 0xff).toList())
        : Uint8List.fromList(data as List<int>);
    if (bytes.isEmpty) {
      if (callback != null) scheduleMicrotask(() => Function.apply(callback, const []));
      return _pendingBytes < highWaterMark;
    }
    _pendingBytes += bytes.length;
    _bytesWritten += bytes.length;
    try {
      _socket.add(bytes);
    } catch (error) {
      _emit('error', error);
      destroy(error);
      return false;
    }
    if (callback != null) {
      _socket.flush().then<void>((_) => callback(), onError: (Object error) {
        callback(error);
      });
    }
    _flushWrites();
    _resetTimeout();
    return _pendingBytes < highWaterMark;
  }

  void _flushWrites() {
    if (_flushing || _closed) return;
    _flushing = true;
    final snapshot = _pendingBytes;
    _socket.flush().then<void>((_) {
      final previous = _pendingBytes;
      _pendingBytes = (_pendingBytes - snapshot).clamp(0, 1 << 62);
      if (previous >= highWaterMark && _pendingBytes < highWaterMark) {
        _emit('drain');
      }
      _flushing = false;
      if (_pendingBytes > 0) _flushWrites();
      if (_writeEnded && _pendingBytes == 0) _shutdownWrite();
    }, onError: (Object error) {
      _flushing = false;
      _emit('error', error);
      destroy(error);
    });
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
    if (_closed) return;
    try {
      // dart:io Socket.close() flushes, then shuts down only the send side.
      _socket.close().then<void>((_) {
        _emit('finish');
      }, onError: (Object error) {
        _emit('error', error);
        destroy(error);
      });
    } catch (error) {
      _emit('error', error);
      destroy(error);
    }
  }

  /// Abruptly close the descriptor. Error is emitted before close.
  NodeSocket destroy([Object? error]) {
    if (_destroyed) return this;
    _destroyed = true;
    _timeoutTimer?.cancel();
    if (error != null) _emit('error', error);
    _socket.destroy();
    _subscription.cancel();
    _finishClose();
    return this;
  }

  void _finishClose() {
    if (_closed) return;
    _closed = true;
    _destroyed = true;
    _timeoutTimer?.cancel();
    _emit('close', _hadError);
  }

  bool _hadError = false;

  NodeSocket pause() {
    _paused = true;
    _subscription.pause();
    return this;
  }

  NodeSocket resume() {
    _paused = false;
    if (_flowing) _deliverQueued();
    _subscription.resume();
    return this;
  }

  void _deliverQueued() {
    while (_flowing && !_paused && _readQueue.isNotEmpty) {
      final data = read();
      if (data == null || data.isEmpty) break;
      _emit('data', data);
    }
  }

  NodeSocket setNoDelay([bool noDelay = true]) {
    _socket.setOption(SocketOption.tcpNoDelay, noDelay);
    return this;
  }

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
        _emit('timeout');
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

    void onClose(Object? _) {
      if (blocked && !destination.destroyed) destination.destroy();
    }

    on('data', onData);
    once('end', onEnd);
    once('close', onClose);
    return destination;
  }

  Uint8List _concat(List<Uint8List> parts) {
    final builder = BytesBuilder(copy: false);
    for (final part in parts) { builder.add(part); }
    return builder.takeBytes();
  }
}

/// Node-like net.Server for TCP and Unix-domain listeners.
class NodeServer {
  NodeServer({this.allowHalfOpen = false, this.highWaterMark = NodeSocket.highWaterMark});

  final bool allowHalfOpen;
  final int highWaterMark;
  final Map<String, List<Function>> _listeners = {};
  ServerSocket? _tcp;
  bool _listening = false;
  bool _closed = false;
  bool _unrefed = false;
  String? _unixPath;
  int? _port;
  String? _host;

  bool get listening => _listening;
  bool get unrefed => _unrefed;
  NodeServer on(String event, Function listener) {
    (_listeners[event] ??= []).add(listener);
    return this;
  }
  NodeServer once(String event, Function listener) {
    late Function wrapped;
    wrapped = ([Object? value]) {
      off(event, wrapped);
      Function.apply(listener, value == null ? const [] : [value]);
    };
    return on(event, wrapped);
  }
  NodeServer off(String event, Function listener) {
    _listeners[event]?.remove(listener);
    return this;
  }
  NodeServer removeListener(String event, Function listener) => off(event, listener);
  void _emit(String event, [Object? value]) {
    for (final listener in List<Function>.of(_listeners[event] ?? const [])) {
      Function.apply(listener, value == null ? const [] : [value]);
    }
  }

  Future<void> listen(Object address, [String? host, Function? callback]) async {
    if (_listening) throw StateError('Server is already listening');
    if (address is String) {
      _unixPath = address;
      if (Platform.isWindows) {
        final server = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
        _tcp = server;
        _port = server.port;
        _host = '127.0.0.1';
      } else {
        final socketAddress = InternetAddress(address, type: InternetAddressType.unix);
        _tcp = await ServerSocket.bind(socketAddress, 0);
        _port = null;
      }
    } else {
      _port = address as int;
      _host = host ?? '0.0.0.0';
      _tcp = await ServerSocket.bind(_host!, _port!);
      _port = _tcp!.port;
    }
    _closed = false;
    _listening = true;
    _tcp!.listen((socket) {
      final wrapped = NodeSocket._(socket, connecting: false);
      _emit('connection', wrapped);
    }, onError: (Object error) => _emit('error', error), onDone: () {
      if (_closed) _emit('close');
    });
    scheduleMicrotask(() {
      _emit('listening');
      if (callback != null) callback();
    });
  }

  /// Node `server.address()` subset. Unix listeners return their path.
  Object? address() => _unixPath != null && !Platform.isWindows
      ? _unixPath
      : (_port == null ? null : NodeAddress(_host ?? '127.0.0.1', _port!));

  Future<void> close([Function? callback]) async {
    if (_closed) {
      callback?.call();
      return;
    }
    _closed = true;
    _listening = false;
    await _tcp?.close();
    if (_unixPath != null && !Platform.isWindows) {
      try { await File(_unixPath!).delete(); } on FileSystemException {} 
    }
    _emit('close');
    callback?.call();
  }

  NodeServer unref() { _unrefed = true; return this; }
  NodeServer ref() { _unrefed = false; return this; }
}

class NodeAddress {
  const NodeAddress(this.address, this.port);
  final String address;
  final int port;
  final String family = 'IPv4';
}

NodeServer createServer([Function? connectionListener, bool allowHalfOpen = false]) {
  final server = NodeServer(allowHalfOpen: allowHalfOpen);
  if (connectionListener != null) server.on('connection', connectionListener);
  return server;
}

/// Node-style net.connect helper; a String means Unix socket path.
Future<NodeSocket> connect(Object portOrPath, [String? host]) =>
    NodeSocket.connect(portOrPath, host);
