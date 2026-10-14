// Descriptor-backed dart:io sockets for `net.Socket({fd})` and
// `server.listen({fd})`. dart:io cannot adopt a file descriptor, so reading,
// writing and accepting go to libc through FFI: a reader isolate polls and
// reads (so a stop request is honoured within 100 ms), writes are
// nonblocking write(2) calls drained from the event loop, and an accept isolate does the same for a listening
// descriptor. macOS and Linux only; anything else fails closed.
import 'dart:async';
import 'dart:convert';
import 'dart:ffi';
import 'dart:io';
import 'dart:isolate';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'errno.dart';

typedef _IntIntN = Int32 Function(Int32);
typedef _IntInt = int Function(int);
typedef _ReadN = IntPtr Function(Int32, Pointer<Uint8>, IntPtr);
typedef _ReadD = int Function(int, Pointer<Uint8>, int);
typedef _PollN = Int32 Function(Pointer<Uint8>, Uint64, Int32);
typedef _PollD = int Function(Pointer<Uint8>, int, int);
typedef _AcceptN = Int32 Function(Int32, Pointer<Uint8>, Pointer<Uint32>);
typedef _AcceptD = int Function(int, Pointer<Uint8>, Pointer<Uint32>);
typedef _SockNameN = Int32 Function(Int32, Pointer<Uint8>, Pointer<Uint32>);
typedef _SockNameD = int Function(int, Pointer<Uint8>, Pointer<Uint32>);
typedef _SockOptN =
    Int32 Function(Int32, Int32, Int32, Pointer<Uint8>, Pointer<Uint32>);
typedef _SockOptD =
    int Function(int, int, int, Pointer<Uint8>, Pointer<Uint32>);
typedef _ShutdownN = Int32 Function(Int32, Int32);
typedef _ShutdownD = int Function(int, int);
typedef _FcntlN = Int32 Function(Int32, Int32, VarArgs<(Int32,)>);
typedef _FcntlD = int Function(int, int, int);
typedef _Accept4N =
    Int32 Function(Int32, Pointer<Uint8>, Pointer<Uint32>, Int32);
typedef _Accept4D = int Function(int, Pointer<Uint8>, Pointer<Uint32>, int);
typedef _ErrnoN = Pointer<Int32> Function();

class _Libc {
  _Libc() {
    if (!(Platform.isMacOS || Platform.isLinux)) {
      throw NodeError(
        'Descriptor sockets are not supported on this platform',
        code: 'ERR_FEATURE_UNAVAILABLE_ON_PLATFORM',
      );
    }
    final lib = DynamicLibrary.process();
    read = lib.lookupFunction<_ReadN, _ReadD>('read');
    write = lib.lookupFunction<_ReadN, _ReadD>('write');
    close = lib.lookupFunction<_IntIntN, _IntInt>('close');
    poll = lib.lookupFunction<_PollN, _PollD>('poll');
    accept = lib.lookupFunction<_AcceptN, _AcceptD>('accept');
    getsockname = lib.lookupFunction<_SockNameN, _SockNameD>('getsockname');
    getpeername = lib.lookupFunction<_SockNameN, _SockNameD>('getpeername');
    getsockopt = lib.lookupFunction<_SockOptN, _SockOptD>('getsockopt');
    getdtablesize = lib.lookupFunction<Int32 Function(), int Function()>(
      'getdtablesize',
    );
    shutdown = lib.lookupFunction<_ShutdownN, _ShutdownD>('shutdown');
    fcntl = lib.lookupFunction<_FcntlN, _FcntlD>('fcntl');
    if (Platform.isLinux) {
      accept4 = lib.lookupFunction<_Accept4N, _Accept4D>('accept4');
    }
    final loc = lib.lookupFunction<_ErrnoN, Pointer<Int32> Function()>(
      Platform.isMacOS ? '__error' : '__errno_location',
    );
    errno = () => loc().value;
  }
  late final _ReadD read, write;
  late final _IntInt close;
  late final _PollD poll;
  late final _AcceptD accept;
  late final _SockNameD getsockname, getpeername;
  late final _SockOptD getsockopt;
  late final int Function() getdtablesize;
  late final _ShutdownD shutdown;
  late final _FcntlD fcntl;
  _Accept4D? accept4;
  late final int Function() errno;
}

const int _fGetfl = 3, _fSetfl = 4, _fSetfd = 2, _fdCloexec = 1;
const int _sockCloexec = 0x80000; // Linux accept4 flag
int get _oNonblock => Platform.isMacOS ? 4 : 0x800;

void _setNonblocking(_Libc c, int fd) {
  final fl = c.fcntl(fd, _fGetfl, 0);
  if (fl >= 0) c.fcntl(fd, _fSetfl, fl | _oNonblock);
}

final Finalizer<int> _fdFinalizer = Finalizer<int>((fd) {
  try {
    _Libc().close(fd);
  } catch (_) {}
});

const int _eintr = 4;
const int _eagain = 35; // macOS; Linux is 11 (both handled below)

bool _again(int e) => e == _eintr || e == 11 || e == _eagain;

/// poll(2) one descriptor for readability: true when readable (or hung up).
bool _pollIn(_Libc c, int fd, int ms) {
  final pfd = calloc<Uint8>(8);
  try {
    final view = pfd
        .asTypedList(8)
        .buffer
        .asByteData(pfd.asTypedList(8).offsetInBytes);
    view.setInt32(0, fd, Endian.host);
    view.setInt16(4, 1, Endian.host); // POLLIN
    final r = c.poll(pfd, 1, ms);
    return r > 0;
  } finally {
    calloc.free(pfd);
  }
}

Never _fail(String syscall, int errno) =>
    throw SocketException('$syscall failed', osError: OSError('', errno));

void _readEntry(List<Object> args) async {
  final out = args[0] as SendPort;
  final fd = args[1] as int;
  final c = _Libc();
  final inbox = ReceivePort();
  out.send(inbox.sendPort);
  var stopped = false;
  var credits = 1;
  inbox.listen((Object? m) {
    if (m == 'stop') {
      stopped = true;
    } else if (m == 'more') {
      credits++;
    }
  });
  final buf = malloc<Uint8>(65536);
  try {
    while (!stopped) {
      if (credits <= 0 || !_pollIn(c, fd, 100)) {
        await Future<void>.delayed(const Duration(milliseconds: 1));
        continue;
      }
      final n = c.read(fd, buf, 65536);
      if (n < 0) {
        final e = c.errno();
        if (_again(e)) continue;
        out.send(e);
        break;
      }
      if (n == 0) {
        out.send(null);
        break;
      }
      credits--;
      out.send(
        TransferableTypedData.fromList([
          Uint8List.fromList(buf.asTypedList(n)),
        ]),
      );
      await Future<void>.delayed(Duration.zero);
    }
  } finally {
    malloc.free(buf);
    out.send('exit');
    inbox.close();
  }
}

/// A connected stream descriptor as a dart:io [Socket].
Socket fdSocket(int fd, {bool readable = true, bool writable = true}) =>
    _FdSocket(fd, readable, writable);

/// The descriptor of this process's listening socket bound to [address] and
/// [port] (for a Unix-domain socket, [address] is the path), or null.
/// dart:io does not expose it; this finds it by asking each descriptor.
int? listeningFd(String address, int port) {
  final c = _Libc();
  for (final fd in _openFds()) {
    // macOS rejects getsockopt(SO_ACCEPTCONN) (ENOPROTOOPT); there the
    // unconnected-stream check below stands in for it.
    final accepting = _sockOpt(c, fd, Platform.isMacOS ? 2 : 30);
    if (!Platform.isMacOS && accepting != 1) continue;
    if (_sockOpt(c, fd, Platform.isMacOS ? 0x1008 : 3) != 1)
      continue; // SOCK_STREAM
    try {
      final name = _name(c, fd, false);
      if (name.$2 != port || name.$1.address != address) continue;
    } catch (_) {
      continue;
    }
    try {
      _name(c, fd, true);
    } catch (_) {
      return fd;
    }
  }
  return null;
}

/// Shuts down both directions of this process's connected TCP socket whose
/// local end is [local]:[localPort] and remote end [remote]:[remotePort]
/// (the pair names one connection). Returns whether one was found.
///
/// Dart: dart:io cannot abort a server TLS handshake, nor close the
/// connection while one runs; Node's destroy() closes the handle at once.
/// The peer then sees the connection end, and the pending handshake fails.
bool shutdownConnection(
  InternetAddress local,
  int localPort,
  InternetAddress remote,
  int remotePort,
) {
  final c = _Libc();
  for (final fd in _openFds()) {
    if (_sockOpt(c, fd, Platform.isMacOS ? 0x1008 : 3) != 1) continue;
    try {
      final me = _name(c, fd, false);
      if (me.$2 != localPort || me.$1.address != local.address) continue;
      final peer = _name(c, fd, true);
      if (peer.$2 != remotePort || peer.$1.address != remote.address) {
        continue;
      }
    } catch (_) {
      continue;
    }
    c.shutdown(fd, 2);
    return true;
  }
  return false;
}

/// getsockopt(SOL_SOCKET, [option]) as an int, or -1 on failure.
int _sockOpt(_Libc c, int fd, int option) {
  final buf = calloc<Uint8>(8);
  final len = calloc<Uint32>()..value = 4;
  try {
    final r = c.getsockopt(fd, Platform.isMacOS ? 0xffff : 1, option, buf, len);
    return r != 0
        ? -1
        : ByteData.sublistView(buf.asTypedList(8)).getInt32(0, Endian.host);
  } finally {
    calloc.free(buf);
    calloc.free(len);
  }
}

/// A listening stream descriptor as a dart:io [ServerSocket].
ServerSocket fdServerSocket(int fd) => _FdServerSocket(fd);

(InternetAddress, int) _name(_Libc c, int fd, bool peer) {
  final buf = calloc<Uint8>(128);
  final len = calloc<Uint32>()..value = 128;
  try {
    final r = peer ? c.getpeername(fd, buf, len) : c.getsockname(fd, buf, len);
    if (r != 0) _fail(peer ? 'getpeername' : 'getsockname', c.errno());
    final b = buf.asTypedList(128);
    final view = ByteData.sublistView(b);
    final family = Platform.isMacOS ? b[1] : view.getUint16(0, Endian.host);
    if (family == 2) {
      return (
        InternetAddress.fromRawAddress(Uint8List.fromList(b.sublist(4, 8))),
        view.getUint16(2, Endian.big),
      );
    }
    if (family == 10 || family == 30) {
      return (
        InternetAddress.fromRawAddress(Uint8List.fromList(b.sublist(8, 24))),
        view.getUint16(2, Endian.big),
      );
    }
    if (family == 1) {
      final start = Platform.isMacOS ? 2 : 2;
      var end = start;
      while (end < len.value && b[end] != 0) {
        end++;
      }
      return (
        InternetAddress(
          utf8.decode(b.sublist(start, end)),
          type: InternetAddressType.unix,
        ),
        0,
      );
    }
    return (InternetAddress.loopbackIPv4, 0);
  } finally {
    calloc.free(buf);
    calloc.free(len);
  }
}

class _FdSocket extends Stream<Uint8List> implements Socket {
  _FdSocket(this._fd, this._readable, this._writable) {
    _libc = _Libc();
    if (_writable) _setNonblocking(_libc, _fd);
    _fdFinalizer.attach(this, _fd, detach: this);
    _controller = StreamController<Uint8List>(
      onListen: _startReading,
      onResume: () => _more(),
      onCancel: _stopReading,
    );
    if (!_readable) _controller.close();
  }

  final int _fd;
  final bool _readable, _writable;
  late final _Libc _libc;
  late final StreamController<Uint8List> _controller;
  final Completer<void> _done = Completer<void>();
  ReceivePort? _port;
  SendPort? _toReader;
  bool _closed = false;
  bool _readerGone = true;
  bool _writeClosed = false;

  void _startReading() {
    if (!_readable || _port != null || _closed) return;
    final port = _port = ReceivePort();
    _readerGone = false;
    port.listen((Object? m) {
      if (m is SendPort) {
        _toReader = m;
        // A stop sent before the reader isolate was up was lost.
        if (_closed || _stopRequested) m.send('stop');
      } else if (m is TransferableTypedData) {
        if (!_controller.isClosed) {
          _controller.add(m.materialize().asUint8List());
          _more();
        }
      } else if (m == null) {
        if (!_controller.isClosed) _controller.close();
      } else if (m is int) {
        if (!_controller.isClosed) {
          _controller.addError(
            SocketException('read failed', osError: OSError('', m)),
          );
          _controller.close();
        }
      } else if (m == 'exit') {
        _readerGone = true;
        port.close();
        _port = null;
        _maybeFinish();
      }
    });
    Isolate.spawn(_readEntry, <Object>[port.sendPort, _fd]);
  }

  void _more() {
    if (!_controller.isPaused) _toReader?.send('more');
  }

  bool _stopRequested = false;

  Future<void> _stopReading() async {
    _stopRequested = true;
    _toReader?.send('stop');
    if (_readerGone) _maybeFinish();
  }

  void _maybeFinish() {
    if (_closed && _readerGone && !_done.isCompleted) {
      _fdFinalizer.detach(this);
      _libc.close(_fd);
      _done.complete();
    }
  }

  @override
  StreamSubscription<Uint8List> listen(
    void Function(Uint8List event)? onData, {
    Function? onError,
    void Function()? onDone,
    bool? cancelOnError,
  }) => _controller.stream.listen(
    onData,
    onError: onError,
    onDone: onDone,
    cancelOnError: cancelOnError,
  );

  // Pending writes, drained from the event loop; flush() completes when empty.
  final List<Uint8List> _queue = <Uint8List>[];
  int _queueOff = 0;
  Timer? _writeTimer;
  final List<Completer<void>> _flushWaiters = <Completer<void>>[];
  Object? _writeError;

  @override
  void add(List<int> data) {
    if (!_writable || _writeClosed) {
      throw StateError('Socket is not writable');
    }
    if (_closed) throw StateError('Socket is closed');
    final bytes = data is Uint8List ? data : Uint8List.fromList(data);
    if (bytes.isEmpty) return;
    _queue.add(Uint8List.fromList(bytes));
    if (_queue.length == 1) _drain();
  }

  void _drain() {
    _writeTimer?.cancel();
    _writeTimer = null;
    while (_queue.isNotEmpty && !_closed) {
      final chunk = _queue.first;
      final p = malloc<Uint8>(chunk.length - _queueOff);
      int n;
      try {
        p
            .asTypedList(chunk.length - _queueOff)
            .setAll(0, chunk.sublist(_queueOff));
        n = _libc.write(_fd, p, chunk.length - _queueOff);
      } finally {
        malloc.free(p);
      }
      if (n < 0) {
        final e = _libc.errno();
        if (_again(e)) {
          if (e == _eintr) continue;
          _writeTimer = Timer(const Duration(milliseconds: 2), _drain);
          return;
        }
        _writeError = SocketException('write failed', osError: OSError('', e));
        _queue.clear();
        break;
      }
      _queueOff += n;
      if (_queueOff >= chunk.length) {
        _queue.removeAt(0);
        _queueOff = 0;
      }
    }
    if (_closed) _queue.clear();
    final waiters = List<Completer<void>>.of(_flushWaiters);
    _flushWaiters.clear();
    // Kept for the next flush() when nobody waits yet.
    final err = waiters.isEmpty ? null : _writeError;
    if (waiters.isNotEmpty) _writeError = null;
    for (final w in waiters) {
      err == null ? w.complete() : w.completeError(err);
    }
  }

  @override
  Future<void> flush() {
    if (_queue.isEmpty) {
      final err = _writeError;
      _writeError = null;
      return err == null ? Future<void>.value() : Future<void>.error(err);
    }
    final c = Completer<void>();
    _flushWaiters.add(c);
    return c.future;
  }

  @override
  Future<void> close() async {
    await flush();
    if (!_writeClosed && _writable) {
      _writeClosed = true;
      _libc.shutdown(_fd, 1); // SHUT_WR
    }
    _writeClosed = true;
    if (!_readable) destroy();
  }

  Future<void> destroyAndWait() async {
    destroy();
    await _done.future;
  }

  @override
  void destroy() {
    if (_closed) return;
    _closed = true;
    _writeTimer?.cancel();
    _toReader?.send('stop');
    if (_port == null) _readerGone = true;
    if (!_controller.isClosed) _controller.close();
    _maybeFinish();
  }

  @override
  Future<void> get done => _done.future;

  @override
  InternetAddress get address => _name(_libc, _fd, false).$1;

  @override
  int get port => _name(_libc, _fd, false).$2;

  @override
  InternetAddress get remoteAddress => _name(_libc, _fd, true).$1;

  @override
  int get remotePort => _name(_libc, _fd, true).$2;

  @override
  bool setOption(SocketOption option, bool enabled) => false;

  @override
  Encoding encoding = utf8;

  @override
  void write(Object? object) => add(encoding.encode('$object'));

  @override
  void writeln([Object? object = '']) => write('$object\n');

  @override
  void writeAll(Iterable<Object?> objects, [String separator = '']) =>
      write(objects.join(separator));

  @override
  void writeCharCode(int charCode) => write(String.fromCharCode(charCode));

  @override
  void addError(Object error, [StackTrace? stackTrace]) =>
      throw UnsupportedError('addError on a descriptor socket');

  @override
  Future<void> addStream(Stream<List<int>> stream) async {
    await for (final chunk in stream) {
      add(chunk);
    }
  }

  @override
  dynamic noSuchMethod(Invocation invocation) => throw UnsupportedError(
    'Descriptor sockets do not support ${invocation.memberName}',
  );
}

class _FdServerSocket extends Stream<Socket> implements ServerSocket {
  _FdServerSocket(this._fd) {
    _libc = _Libc();
    final name = _name(_libc, _fd, false);
    address = name.$1;
    port = name.$2;
    _controller = StreamController<Socket>(onListen: _start);
  }

  final int _fd;
  late final _Libc _libc;
  late final StreamController<Socket> _controller;
  Timer? _timer;
  bool _closed = false;

  @override
  late final InternetAddress address;
  @override
  late final int port;

  void _start() {
    _timer = Timer.periodic(const Duration(milliseconds: 20), (_) {
      while (!_closed && _pollIn(_libc, _fd, 0)) {
        final a4 = _libc.accept4;
        final fd = a4 != null
            ? a4(_fd, nullptr.cast(), nullptr.cast(), _sockCloexec)
            : _libc.accept(_fd, nullptr.cast(), nullptr.cast());
        if (fd >= 0 && a4 == null) _libc.fcntl(fd, _fSetfd, _fdCloexec);
        if (fd < 0) {
          final e = _libc.errno();
          if (_again(e)) return;
          _controller.addError(
            SocketException('accept failed', osError: OSError('', e)),
          );
          return;
        }
        _controller.add(_FdSocket(fd, true, true));
      }
    });
  }

  @override
  StreamSubscription<Socket> listen(
    void Function(Socket event)? onData, {
    Function? onError,
    void Function()? onDone,
    bool? cancelOnError,
  }) => _controller.stream.listen(
    onData,
    onError: onError,
    onDone: onDone,
    cancelOnError: cancelOnError,
  );

  @override
  Future<ServerSocket> close() async {
    if (!_closed) {
      _closed = true;
      _timer?.cancel();
      _libc.close(_fd);
      await _controller.close();
    }
    return this;
  }

  @override
  dynamic noSuchMethod(Invocation invocation) => throw UnsupportedError(
    'Descriptor server sockets do not support ${invocation.memberName}',
  );
}

/// True for a [Socket] made by [fdSocket] or accepted from [fdServerSocket]:
/// dart:io's TLS cannot take it over, as it is not one of dart:io's own.
bool isFdSocket(Socket s) => s is _FdSocket;

/// Open descriptors of this process, from /proc/self/fd or /dev/fd.
List<int> _openFds() {
  try {
    final d = Directory(Platform.isMacOS ? '/dev/fd' : '/proc/self/fd');
    return [
      for (final e in d.listSync())
        if (int.tryParse(e.uri.pathSegments.where((x) => x.isNotEmpty).last)
            case final n? when n >= 3)
          n,
    ]..sort();
  } catch (_) {
    return [for (var i = 3; i < 1024; i++) i];
  }
}
