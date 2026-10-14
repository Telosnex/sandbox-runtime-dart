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
import 'stream.dart' as stream;

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
class NodeSocket extends stream.Duplex {
  /// A socket with no connection yet. `net.connect` and `tls.connect` create
  /// one and then call [startConnect].
  NodeSocket.pending({bool allowHalfOpen = false})
    : _connecting = true,
      super(
        allowHalfOpen: allowHalfOpen,
        emitClose: false,
        autoDestroy: true,
      );

  /// Adopt a connected dart:io socket, as a server does with an accepted
  /// connection. No 'connect' event is emitted, as in Node.
  NodeSocket.fromSocket(Socket socket, {bool allowHalfOpen = false})
    : _connecting = false,
      super(
        allowHalfOpen: allowHalfOpen,
        emitClose: false,
        autoDestroy: true,
      ) {
    _attach(socket);
  }

  /// A socket that will run over another, already connected one; see
  /// [startServerTlsOver]. Not connecting, as in Node.
  NodeSocket.over({bool allowHalfOpen = false})
    : _connecting = false,
      super(
        allowHalfOpen: allowHalfOpen,
        emitClose: false,
        autoDestroy: true,
      );

  Socket? _socket;
  StreamSubscription<Uint8List>? _subscription;
  ConnectionTask<Socket>? _task;
  bool _connecting;
  bool _unrefed = false;
  bool _reading = false;
  bool _closeEmitted = false;
  int _bytesRead = 0;
  int _bytesDispatched = 0;
  int _inFlight = 0;

  // Work waiting for the connection: Node queues a write, `_final` and
  // `_read` on 'connect'.
  final List<void Function()> _onAttach = [];

  // Set once a TLS socket has taken this connection over ([_wrapper]), and
  // on that TLS socket, the socket under it ([_under]).
  bool _handedOver = false;
  NodeSocket? _wrapper;
  NodeSocket? _under;
  bool _securing = false;
  Completer<void>? _writesSettled;
  bool? _noDelay;
  Timer? _timeoutTimer;
  int _timeoutMs = 0;

  void _attach(Socket socket) {
    _socket = socket;
    _connecting = false;
    if (_noDelay != null) {
      socket.setOption(SocketOption.tcpNoDelay, _noDelay!);
    }
    _subscription = socket.listen(
      _received,
      onError: (Object error, StackTrace stack) {
        destroy(socketError(error, 'read'));
      },
      onDone: () {
        _subscription = null;
        if (destroyed) return;
        // Node's onStreamRead at EOF.
        push(null);
        read(0);
      },
      cancelOnError: false,
    );
    _subscription!.pause();
    _reading = false;
    socket.done.then<void>(
      (_) {},
      onError: (Object error) => destroy(socketError(error, 'write')),
    );
    final pending = List<void Function()>.of(_onAttach);
    _onAttach.clear();
    for (final fn in pending) {
      fn();
    }
    // Node starts reading on connect (afterConnect / onconnection call
    // read(0)) so data fills the buffer up to the high-water mark.
    if (!isPaused()) scheduleMicrotask(() => read(0));
  }

  void _received(Uint8List bytes) {
    if (bytes.isEmpty || destroyed) return;
    _bytesRead += bytes.length;
    _resetTimeout();
    // Node: a false push stops reading from the handle.
    if (!push(Uint8List.fromList(bytes))) _readStop();
  }

  void _readStart() {
    if (_reading || _handedOver) return;
    final sub = _subscription;
    if (sub == null) return;
    _reading = true;
    sub.resume();
  }

  void _readStop() {
    if (!_reading) return;
    _reading = false;
    _subscription?.pause();
  }

  @override
  void readImpl(int size) {
    if (_connecting || _socket == null) {
      _onAttach.add(() => readImpl(size));
      return;
    }
    _readStart();
  }

  @override
  bool get hasWritevImpl => true;

  @override
  void writeImpl(Object chunk, String encoding, Function callback) =>
      writevImpl([(chunk: chunk, encoding: encoding)], callback);

  @override
  void writevImpl(
    List<({Object chunk, String encoding})> chunks,
    Function callback,
  ) {
    if (_connecting || _socket == null) {
      _onAttach.add(() => writevImpl(chunks, callback));
      return;
    }
    final socket = _socket!;
    var n = 0;
    try {
      for (final c in chunks) {
        final bytes = c.chunk as Uint8List;
        n += bytes.length;
        socket.add(bytes);
      }
    } catch (error) {
      applyListener(callback, [socketError(error, 'write')]);
      return;
    }
    _bytesDispatched += n;
    _inFlight += n;
    _resetTimeout();
    socket.flush().then(
      (_) {
        _inFlight -= n;
        _settleWrites();
        applyListener(callback, const []);
      },
      onError: (Object error) {
        _inFlight -= n;
        _settleWrites();
        applyListener(callback, [socketError(error, 'write')]);
      },
    );
  }

  void _settleWrites() {
    if (writableLength == 0 && _inFlight == 0) {
      final settled = _writesSettled;
      _writesSettled = null;
      settled?.complete();
    }
  }

  @override
  bool get hasFinalImpl => true;

  @override
  void finalImpl(Function callback) {
    if (_connecting || _socket == null) {
      _onAttach.add(() => finalImpl(callback));
      return;
    }
    try {
      // dart:io Socket.close() flushes, then shuts down only the send side.
      _socket!.close().then<void>(
        (_) => applyListener(callback, const []),
        onError: (Object error) =>
            applyListener(callback, [socketError(error, 'shutdown')]),
      );
    } catch (error) {
      applyListener(callback, [socketError(error, 'shutdown')]);
    }
  }

  @override
  void destroyImpl(Object? error, Function callback) {
    _timeoutTimer?.cancel();
    _task?.cancel();
    _onAttach.clear();
    final wrapper = _wrapper;
    if (_handedOver && wrapper != null) {
      // The connection is the TLS socket's now; as in Node, destroying the
      // socket under it destroys it too.
      wrapper.destroy();
    } else {
      _socket?.destroy();
      _subscription?.cancel();
      _subscription = null;
      final under = _under;
      if (under != null && _socket == null && !_securing) {
        // A TLS socket whose handshake has not begun: the connection is
        // still the socket under it.
        under._socket?.destroy();
        under._subscription?.cancel();
      }
    }
    applyListener(callback, [error]);
    final hadError = error != null;
    scheduleMicrotask(() => _emitClose(hadError));
  }

  void _emitClose(bool hadError) {
    if (_closeEmitted) return;
    _closeEmitted = true;
    emit('close', hadError);
    // A TLS socket and the socket under it share one connection: when one
    // closes, so does the other.
    final under = _under;
    if (under != null && !under._closeEmitted) {
      if (!under.destroyed) {
        under.destroy();
      } else {
        under._emitClose(false);
      }
    }
    final wrapper = _wrapper;
    if (wrapper != null && !wrapper.destroyed) wrapper.destroy();
  }

  /// Node `socket.write`: after a TLS socket took the connection over, use
  /// that socket.
  @override
  bool write(Object chunk, [Object? encoding, Function? callback]) {
    _checkNotHandedOver();
    _resetTimeout();
    return super.write(chunk, encoding, callback);
  }

  @override
  NodeSocket end([Object? chunk, Object? encoding, Function? cb]) {
    _checkNotHandedOver();
    super.end(chunk, encoding, cb);
    return this;
  }

  @override
  Object? read([int? n]) {
    if (_handedOver && n != 0) _checkNotHandedOver();
    return super.read(n);
  }

  @override
  bool unshift(Object? chunk, [String? encoding]) {
    _checkNotHandedOver();
    return super.unshift(chunk, encoding);
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
        if (destroyed) return;
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
            if (destroyed) return;
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
      if (destroyed) {
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
      if (destroyed) {
        secured.destroy();
        return;
      }
      _attach(secured);
      emit('secureConnect');
    } catch (error) {
      if (destroyed) return;
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

  /// Node `socket.readyState`.
  String get readyState => _connecting
      ? 'opening'
      : readable && writable
      ? 'open'
      : readable
      ? 'readOnly'
      : writable
      ? 'writeOnly'
      : 'closed';

  /// Node `socket.bytesRead`.
  int get bytesRead => _bytesRead;

  /// Node `socket.bytesWritten`: bytes handed to the connection, plus
  /// bytes still queued.
  int get bytesWritten => _bytesDispatched + writableLength;
  bool get unrefed => _unrefed;

  /// Node `socket.resetAndDestroy()`: close with a TCP RST. dart:io cannot
  /// send a RST, so this closes the connection at once (a FIN, after any
  /// unsent bytes are dropped).
  NodeSocket resetAndDestroy() {
    if (_connecting) {
      destroy(
        NodeError(
          'Socket is still connecting',
          code: 'ERR_SOCKET_CLOSED_BEFORE_CONNECTION',
        ),
      );
    } else {
      destroy(
        NodeError('Socket closed', code: 'ERR_SOCKET_CLOSED'),
      );
    }
    return this;
  }

  /// Node `socket.destroySoon()`.
  void destroySoon() {
    if (writable) end();
    if (writableFinished) {
      destroy();
    } else {
      once('finish', () => destroy());
    }
  }

  /// The dart:io socket for address queries: this socket's own, or, once a
  /// TLS socket has taken the connection over, that socket's.
  Socket? get _addressSource => _handedOver ? _wrapper?._socket : _socket;

  /// As in Node, these are null for a Unix-domain socket or before connect.
  String? get remoteAddress => _addressed((s) => s.remoteAddress.address);
  int? get remotePort => _addressed((s) => s.remotePort);
  String? get remoteFamily => _addressed(
    (s) => s.remoteAddress.type == InternetAddressType.IPv6 ? 'IPv6' : 'IPv4',
  );
  String? get localAddress => _addressed((s) => s.address.address);
  int? get localPort => _addressed((s) => s.port);

  T? _addressed<T>(T Function(Socket socket) read) {
    final socket = _addressSource;
    if (socket == null || socket.address.type == InternetAddressType.unix) {
      return null;
    }
    try {
      return read(socket);
    } on SocketException {
      return null; // Closed.
    }
  }

  @override
  NodeSocket on(String event, Function listener) {
    super.on(event, listener);
    return this;
  }

  @override
  NodeSocket addListener(String event, Function listener) =>
      on(event, listener);

  @override
  NodeSocket once(String event, Function listener) {
    super.once(event, listener);
    return this;
  }

  @override
  NodeSocket prependListener(String event, Function listener) {
    super.prependListener(event, listener);
    return this;
  }

  @override
  NodeSocket off(String event, Function listener) {
    super.off(event, listener);
    return this;
  }

  @override
  NodeSocket removeListener(String event, Function listener) =>
      off(event, listener);

  @override
  NodeSocket removeAllListeners([String? event]) {
    super.removeAllListeners(event);
    return this;
  }

  @override
  NodeSocket destroy([Object? error, Function? callback]) {
    super.destroy(error, callback);
    return this;
  }

  @override
  NodeSocket pause() {
    super.pause();
    return this;
  }

  @override
  NodeSocket resume() {
    super.resume();
    return this;
  }

  @override
  NodeSocket setEncoding(String encoding) {
    super.setEncoding(encoding);
    return this;
  }

  void _checkNotHandedOver() {
    if (_handedOver) {
      throw StateError(
        'This socket is under a TLSSocket; read and write the TLSSocket.',
      );
    }
  }

  /// Node `new tls.TLSSocket(socket, { isServer: true })`, for node/tls.dart:
  /// run this socket as the server side of TLS over [under], which must be
  /// connected.
  ///
  /// [under] stops reading at once. Once its queued writes have gone out,
  /// its connection and every byte it holds unread (bytes put back with
  /// `unshift` first) go to [secure], which does the handshake. Then this
  /// socket emits 'secure' and reads and writes the decrypted stream; writes
  /// made before then are queued. A failed handshake is an 'error'.
  ///
  /// Afterwards [under] is a view of this socket, as in Node: its 'close'
  /// follows this socket's, destroying it destroys this socket, and writing
  /// to it is a [StateError].
  void startServerTlsOver(
    NodeSocket under,
    Future<Socket> Function(Socket raw, Uint8List buffered) secure,
  ) {
    if (under._socket == null || under.destroyed) {
      throw StateError('A TLSSocket needs a connected socket under it');
    }
    if (under._handedOver) {
      throw StateError('This socket is already under a TLSSocket');
    }
    if (under.writableEnded) {
      throw UnimplementedError('TLSSocket over a socket that has ended');
    }
    under
      .._handedOver = true
      .._wrapper = this
      .._readStop();
    _under = under;
    unawaited(_serverTlsOver(under, secure));
  }

  Future<void> _serverTlsOver(
    NodeSocket under,
    Future<Socket> Function(Socket raw, Uint8List buffered) secure,
  ) async {
    try {
      if (under._inFlight > 0 || under.writableLength > 0) {
        await (under._writesSettled ??= Completer<void>()).future;
      }
      if (destroyed) return;
      final buffered = under.takeBufferedBytes();
      final raw = under._socket!;
      final Socket secured;
      _securing = true;
      try {
        // Gap: dart:io offers no way to abort a server handshake. destroy()
        // during it closes both sockets at once, but the connection itself
        // stays open until the handshake ends, which a silent client can
        // put off until it closes its side.
        secured = await secure(raw, buffered);
      } finally {
        // dart:io has detached the connection from [raw]; the subscription
        // on [raw] gets nothing more.
        unawaited(under._subscription?.cancel());
        under._subscription = null;
      }
      if (destroyed) {
        secured.destroy();
        return;
      }
      _attach(secured);
      emit('secure');
    } catch (error) {
      if (destroyed) return;
      destroy(error is SocketException ? socketError(error, 'read') : error);
    }
  }

  NodeSocket setNoDelay([bool noDelay = true]) {
    _noDelay = noDelay;
    if (!_handedOver) _socket?.setOption(SocketOption.tcpNoDelay, noDelay);
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
    if (_timeoutMs > 0 && !_closeEmitted) {
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
