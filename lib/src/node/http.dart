// Node-shaped HTTP/1.1 subset used by sandbox-runtime proxy modules.
// This is a byte parser/serializer over NodeSocket; dart:io HttpServer is not
// used because it discards raw-header spelling and CONNECT head bytes.
// ignore_for_file: curly_braces_in_flow_control_structures
import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'net.dart' as net;
import 'tls.dart' as node_tls;

const int defaultMaxHeaderSize = 16 * 1024;

/// Node parser error subset. `code` and `message` are stable for clientError.
class NodeHttpError implements Exception {
  NodeHttpError(this.code, this.message);
  final String code;
  final String message;
  @override
  String toString() => 'Error: $message';
}

/// Node's `IncomingHttpHeaders`: header values by lowercase name; a
/// repeated header is a list.
typedef IncomingHttpHeaders = Map<String, Object?>;

/// A Node IncomingMessage-like request or response message.
class IncomingMessage {
  IncomingMessage._({
    required this.socket,
    required this.rawHeaders,
    required this.headers,
    required this.httpVersion,
    this.method,
    this.url,
    this.statusCode,
    this.statusMessage,
  }) : _body = StreamController<Uint8List>(
         sync: true,
         onPause: socket.pause,
         onResume: socket.resume,
       );

  final net.NodeSocket socket;
  final String? method;
  final String? url;
  final int? statusCode;
  final String? statusMessage;
  final String httpVersion;
  final List<String> rawHeaders;
  final Map<String, Object?> headers;
  final Map<String, Object?> trailers = {};
  final List<String> rawTrailers = [];
  final StreamController<Uint8List> _body;
  bool _destroyed = false;
  bool _readableEnded = false;
  int _bodyBuffered = 0;
  int? _bodyGateCap;
  Object? _bodyGateBudget;
  Completer<void>? _bodyGateWaiter;
  void Function()? _budgetWake;

  bool get destroyed => _destroyed;
  bool get readableEnded => _readableEnded;
  bool get complete => _readableEnded;
  Stream<Uint8List> get body => _body.stream.transform(
    StreamTransformer<Uint8List, Uint8List>.fromHandlers(
      handleData: (bytes, sink) {
        _bodyBuffered = (_bodyBuffered - bytes.length).clamp(0, 1 << 62);
        _adjustBudget(-bytes.length);
        _updateBodyGate();
        sink.add(bytes);
      },
      handleDone: (sink) {
        _finalizeEnd();
        sink.close();
      },
    ),
  );
  int get readableLength => _bodyBuffered;

  void gateBufferedBody({required int cap, Object? budget}) {
    if (cap < 0) throw ArgumentError.value(cap, 'cap');
    _bodyGateCap = cap;
    _bodyGateBudget = budget;
    _updateBodyGate();
  }

  Future<void> _waitForBodyGate() async {
    if (_bodyGateCap == null || !_isBodyGateBlocked()) return;
    _bodyGateWaiter ??= Completer<void>();
    await _bodyGateWaiter!.future;
  }

  bool _isBodyGateBlocked() {
    if (_bodyGateCap != null && _bodyBuffered > _bodyGateCap!) return true;
    final budget = _bodyGateBudget;
    if (budget != null) {
      final dynamic value = budget;
      if ((value.used as int) >= (value.limit as int)) return true;
    }
    return false;
  }

  void _updateBodyGate() {
    if (_bodyGateCap == null) return;
    if (_isBodyGateBlocked()) {
      socket.pause();
      _bodyGateWaiter ??= Completer<void>();
      final budget = _bodyGateBudget;
      if (budget != null && _budgetWake == null) {
        void wake() => _updateBodyGate();
        _budgetWake = wake;
        (budget as dynamic).waiters.add(wake);
      }
    } else {
      final budget = _bodyGateBudget;
      final wake = _budgetWake;
      if (budget != null && wake != null) {
        (budget as dynamic).waiters.remove(wake);
        _budgetWake = null;
      }
      socket.resume();
      final waiter = _bodyGateWaiter;
      _bodyGateWaiter = null;
      if (waiter != null && !waiter.isCompleted) waiter.complete();
    }
  }

  void _adjustBudget(int delta) {
    final budget = _bodyGateBudget;
    if (budget == null || delta == 0) return;
    final dynamic value = budget;
    value.used = (value.used as int) + delta;
    if (delta < 0) {
      final waiters = value.waiters as Set<void Function()>;
      if (waiters.isNotEmpty) {
        final ready = waiters.toList();
        waiters.clear();
        for (final wake in ready) {
          wake();
        }
      }
    }
  }

  IncomingMessage on(String event, Function listener) {
    switch (event) {
      case 'data':
        body.listen((bytes) => Function.apply(listener, [bytes]));
      case 'end':
        if (_readableEnded) {
          scheduleMicrotask(() => Function.apply(listener, const []));
        } else {
          _endListeners.add(listener);
        }
      case 'error':
        _errorListeners.add(listener);
      case 'aborted':
        _abortedListeners.add(listener);
      case 'close':
        _closeListeners.add(listener);
    }
    return this;
  }

  final Map<String, List<Function>> _eventListeners = {};
  List<Function> get _endListeners =>
      _eventListeners.putIfAbsent('end', () => []);
  List<Function> get _errorListeners =>
      _eventListeners.putIfAbsent('error', () => []);
  List<Function> get _abortedListeners =>
      _eventListeners.putIfAbsent('aborted', () => []);
  List<Function> get _closeListeners =>
      _eventListeners.putIfAbsent('close', () => []);

  IncomingMessage once(String event, Function listener) {
    late Function wrapper;
    wrapper = ([Object? value]) {
      off(event, wrapper);
      Function.apply(listener, value == null ? const [] : [value]);
    };
    return on(event, wrapper);
  }

  IncomingMessage off(String event, Function listener) {
    _eventListeners[event]?.remove(listener);
    return this;
  }

  IncomingMessage removeListener(String event, Function listener) =>
      off(event, listener);

  void _emit(String event, [Object? value]) {
    for (final listener in List<Function>.of(
      _eventListeners[event] ?? const [],
    )) {
      Function.apply(listener, value == null ? const [] : [value]);
    }
  }

  void _add(List<int> bytes) {
    if (bytes.isNotEmpty && !_body.isClosed) {
      _bodyBuffered += bytes.length;
      _adjustBudget(bytes.length);
      _updateBodyGate();
      _body.add(Uint8List.fromList(bytes));
    }
  }

  void _finish() {
    if (_body.isClosed) return;
    if (!_body.isClosed) _body.close();
    if (_bodyBuffered == 0) _finalizeEnd();
  }

  void _finalizeEnd() {
    if (_readableEnded) return;
    _readableEnded = true;
    _emit('end');
  }

  void _fail(Object error) {
    if (!_body.isClosed) _body.addError(error);
    _emit('error', error);
    _emit('aborted');
    _destroyed = true;
    _emit('close');
  }

  IncomingMessage pipe(Object destination, {bool end = true}) {
    if (destination is ServerResponse) {
      body.listen(
        (bytes) {
          if (!destination.write(bytes)) {
            socket.pause();
            destination.once('drain', () {
              if (!destroyed) socket.resume();
            });
          }
        },
        onError: destination.destroy,
        onDone: () {
          if (end) destination.end();
          socket.resume();
        },
        cancelOnError: false,
      );
    } else if (destination is net.NodeSocket) {
      body.listen(
        (bytes) {
          if (!destination.write(bytes)) {
            socket.pause();
            destination.once('drain', () {
              if (!destroyed) socket.resume();
            });
          }
        },
        onError: destination.destroy,
        onDone: () {
          if (end) destination.end();
        },
      );
    } else {
      throw ArgumentError('Unsupported IncomingMessage.pipe destination');
    }
    return this;
  }

  IncomingMessage pause() {
    socket.pause();
    return this;
  }

  IncomingMessage resume() {
    socket.resume();
    return this;
  }

  IncomingMessage destroy([Object? error]) {
    if (_destroyed) return this;
    _destroyed = true;
    if (error != null) _fail(error);
    socket.destroy(error);
    return this;
  }
}

/// Node ServerResponse subset with byte-preserving Latin-1 head serialization.
class ServerResponse {
  ServerResponse._(this.socket, this._request);

  final net.NodeSocket socket;
  final IncomingMessage _request;
  final Map<String, _HeaderValue> _headers = {};
  final Map<String, Object?> _trailers = {};
  final Map<String, List<Function>> _listeners = {};
  final Completer<void> _done = Completer<void>();
  int statusCode = 200;
  String? statusMessage;
  bool headersSent = false;
  bool writableEnded = false;
  bool writableFinished = false;
  bool destroyed = false;
  bool _chunked = false;
  bool _noBody = false;
  bool _ended = false;
  int _bodyBytesWritten = 0;

  Future<void> get done => _done.future;
  bool get finished => writableFinished;

  ServerResponse on(String event, Function listener) {
    (_listeners[event] ??= []).add(listener);
    return this;
  }

  ServerResponse once(String event, Function listener) {
    late Function wrapped;
    wrapped = ([Object? value]) {
      off(event, wrapped);
      Function.apply(listener, value == null ? const [] : [value]);
    };
    return on(event, wrapped);
  }

  ServerResponse off(String event, Function listener) {
    _listeners[event]?.remove(listener);
    return this;
  }

  ServerResponse removeListener(String event, Function listener) =>
      off(event, listener);
  void _emit(String event, [Object? value]) {
    for (final listener in List<Function>.of(_listeners[event] ?? const [])) {
      Function.apply(listener, value == null ? const [] : [value]);
    }
  }

  void setHeader(String name, Object? value) {
    _checkHeaderName(name);
    _checkHeaderValue(value);
    if (headersSent) throw StateError('Cannot set headers after they are sent');
    _headers[name.toLowerCase()] = _HeaderValue(name, value);
  }

  Object? getHeader(String name) => _headers[name.toLowerCase()]?.value;
  List<String> getHeaderNames() => [
    for (final value in _headers.values) value.name,
  ];
  bool hasHeader(String name) => _headers.containsKey(name.toLowerCase());
  void removeHeader(String name) {
    if (headersSent)
      throw StateError('Cannot remove headers after they are sent');
    _headers.remove(name.toLowerCase());
  }

  ServerResponse writeHead(
    int status, [
    Object? headersOrMessage,
    Object? headers,
  ]) {
    if (headersSent) throw StateError('writeHead called after headers sent');
    statusCode = status;
    Object? actualHeaders = headers;
    if (headersOrMessage is String) {
      statusMessage = headersOrMessage;
    } else if (headersOrMessage is Map) {
      actualHeaders = headersOrMessage;
    }
    if (actualHeaders is Map) {
      actualHeaders.forEach((key, value) => setHeader('$key', value));
    }
    _sendHead();
    return this;
  }

  ServerResponse writeContinue() {
    if (!headersSent && !_ended)
      socket.write(ascii.encode('HTTP/1.1 100 Continue\r\n\r\n'));
    return this;
  }

  bool write(Object data, [Function? callback]) {
    if (_ended || destroyed) {
      final error = StateError('write after end');
      callback?.call(error);
      _emit('error', error);
      return false;
    }
    _sendHead(hasBody: true);
    final bytes = _bytes(data);
    if (!_noBody) _bodyBytesWritten += bytes.length;
    if (!_noBody && bytes.isNotEmpty) {
      socket.write(_chunked ? _chunk(bytes) : bytes, ([Object? error]) {
        if (callback != null)
          Function.apply(callback, error == null ? const [] : [error]);
      });
    } else if (callback != null) {
      scheduleMicrotask(() => Function.apply(callback, const []));
    }
    return socket.writableLength < net.NodeSocket.highWaterMark;
  }

  ServerResponse addTrailers(Map<String, Object?> trailers) {
    trailers.forEach((name, value) {
      _checkHeaderName(name);
      _checkHeaderValue(value);
      _trailers[name.toLowerCase()] = value;
    });
    return this;
  }

  ServerResponse end([Object? data, Function? callback]) {
    if (_ended) return this;
    if (data != null) write(data);
    final expectedLength = int.tryParse(
      getHeader('content-length')?.toString() ?? '',
    );
    if (!_noBody &&
        expectedLength != null &&
        expectedLength != _bodyBytesWritten) {
      final error = StateError(
        'Response Content-Length does not match bytes written',
      );
      _emit('error', error);
      destroy(error);
      return this;
    }
    _sendHead(hasBody: data != null);
    _ended = true;
    writableEnded = true;
    final terminal = _noBody
        ? Uint8List(0)
        : _chunked
        ? _serializeEndChunk(_trailers)
        : Uint8List(0);
    void finish([Object? error]) {
      if (error != null) {
        _emit('error', error);
      } else {
        writableFinished = true;
        _emit('finish');
      }
      if (!_done.isCompleted) _done.complete();
      if (callback != null)
        Function.apply(callback, error == null ? const [] : [error]);
    }

    if (terminal.isEmpty) {
      socket.write(Uint8List(0), finish);
    } else {
      socket.write(terminal, finish);
    }
    if (_request.headers['connection']?.toString().toLowerCase() == 'close' ||
        getHeader('connection')?.toString().toLowerCase() == 'close') {
      done.then((_) => socket.end());
    }
    return this;
  }

  ServerResponse destroy([Object? error]) {
    if (destroyed) return this;
    destroyed = true;
    if (error != null) _emit('error', error);
    socket.destroy(error);
    if (!_done.isCompleted) _done.complete();
    return this;
  }

  void _sendHead({bool hasBody = false}) {
    if (headersSent) return;
    final status = statusCode;
    final requestMethod = _request.method?.toUpperCase();
    _noBody =
        requestMethod == 'HEAD' ||
        (status >= 100 && status < 200) ||
        status == 204 ||
        status == 304;
    if (!hasHeader('date')) {
      _headers['date'] = _HeaderValue(
        'Date',
        HttpDate.format(DateTime.now().toUtc()),
      );
    }
    if (!hasHeader('connection')) {
      _headers['connection'] = _HeaderValue(
        'Connection',
        _request.headers['connection']?.toString() ?? 'keep-alive',
      );
    }
    final hasLength = hasHeader('content-length');
    final hasTransfer = hasHeader('transfer-encoding');
    if (hasLength && hasTransfer) {
      throw StateError(
        'Content-Length and Transfer-Encoding cannot both be set',
      );
    }
    _chunked = !_noBody && !hasLength && !hasTransfer;
    if (!_noBody &&
        hasTransfer &&
        getHeader(
              'transfer-encoding',
            )?.toString().toLowerCase().split(',').last.trim() ==
            'chunked') {
      _chunked = true;
    }
    if (_chunked)
      _headers['transfer-encoding'] = const _HeaderValue(
        'Transfer-Encoding',
        'chunked',
      );
    headersSent = true;
    final phrase = statusMessage ?? _defaultStatusMessage(status);
    final text = StringBuffer('HTTP/1.1 $status $phrase\r\n');
    for (final header in _headers.values) {
      for (final value in _headerValues(header.value)) {
        text.write('${header.name}: $value\r\n');
      }
    }
    text.write('\r\n');
    socket.write(_latin1(text.toString()));
  }
}

class _HeaderValue {
  const _HeaderValue(this.name, this.value);
  final String name;
  final Object? value;
}

/// Node-shaped HTTP server. `serveConnection` is the HTTP parser handoff used
/// for accepted TLS sockets that are not owned by a listening HTTP server.
class NodeHttpServer {
  NodeHttpServer({this.maxHeaderSize = defaultMaxHeaderSize});
  final int maxHeaderSize;
  final Map<String, List<Function>> _listeners = {};
  final Set<net.NodeSocket> _connections = {};
  final Set<net.NodeSocket> _idleConnections = {};
  net.NodeServer? _server;
  bool _closed = false;

  NodeHttpServer on(String event, Function listener) {
    (_listeners[event] ??= []).add(listener);
    if (event == 'connection' && _server != null) _server!.on(event, listener);
    return this;
  }

  NodeHttpServer once(String event, Function listener) {
    late Function wrapped;
    wrapped = ([Object? value]) {
      off(event, wrapped);
      Function.apply(listener, value == null ? const [] : [value]);
    };
    return on(event, wrapped);
  }

  NodeHttpServer off(String event, Function listener) {
    _listeners[event]?.remove(listener);
    _server?.off(event, listener);
    return this;
  }

  NodeHttpServer removeListener(String event, Function listener) =>
      off(event, listener);
  int listenerCount(String event) =>
      (_listeners[event]?.length ?? 0) + (event == 'connection' ? 1 : 0);
  bool get listening => _server?.listening ?? false;
  Object? address() => _server?.address();
  NodeHttpServer unref() {
    _server?.unref();
    return this;
  }

  NodeHttpServer ref() {
    _server?.ref();
    return this;
  }

  bool emit(String event, [Object? first, Object? second, Object? third]) {
    final listeners = List<Function>.of(_listeners[event] ?? const []);
    if (event == 'connection' && first is net.NodeSocket)
      serveConnection(first);
    for (final listener in listeners) {
      final args = <Object?>[first, second, third];
      while (args.isNotEmpty && args.last == null) {
        args.removeLast();
      }
      Function.apply(listener, args);
    }
    return listeners.isNotEmpty ||
        (event == 'connection' && first is net.NodeSocket);
  }

  Future<void> listen(
    Object address, [
    Object? hostOrCallback,
    Function? callback,
  ]) {
    _server = net.NodeServer()
      ..on('connection', (net.NodeSocket socket) => serveConnection(socket));
    for (final listener in (_listeners['connection'] ?? const <Function>[])) {
      _server!.on('connection', listener);
    }
    return _server!.listen(address, hostOrCallback, callback);
  }

  Future<void> close([Function? callback]) async {
    closeIdleConnections();
    await _server?.close(callback);
    _closed = true;
    if (_server == null) callback?.call();
  }

  void closeIdleConnections() {
    for (final socket in List<net.NodeSocket>.of(_idleConnections)) {
      _idleConnections.remove(socket);
      socket.destroy();
    }
  }

  void serveConnection(net.NodeSocket socket) {
    if (_closed) {
      socket.destroy();
      return;
    }
    _connections.add(socket);
    _idleConnections.add(socket);
    socket.allowHalfOpen = true;
    socket.once('close', ([Object? _]) {
      _connections.remove(socket);
      _idleConnections.remove(socket);
    });
    unawaited(_serve(socket));
  }

  Future<void> _serve(net.NodeSocket socket) async {
    final reader = _ByteReader(socket);
    final pendingResponses = <Future<void>>[];
    while (!_closed && !socket.destroyed) {
      try {
        final head = await _readHead(reader, maxHeaderSize);
        if (head == null) {
          await Future.wait(pendingResponses);
          if (!socket.destroyed) socket.end();
          return;
        }
        _idleConnections.remove(socket);
        final parsed = _parseHead(head, request: true);
        final request = IncomingMessage._(
          socket: socket,
          rawHeaders: parsed.rawHeaders,
          headers: parsed.headers,
          httpVersion: parsed.version,
          method: parsed.method,
          url: parsed.target,
        );
        final response = ServerResponse._(socket, request);
        pendingResponses.add(response.done);
        final connectionTokens = request.headers['connection']
            ?.toString()
            .toLowerCase()
            .split(',')
            .map((token) => token.trim())
            .toSet();
        if (listenerCount('upgrade') != 0 &&
            request.headers.containsKey('upgrade') &&
            (connectionTokens?.contains('upgrade') ?? false)) {
          final buffered = socket.read() ?? Uint8List(0);
          emit('upgrade', request, socket, buffered);
          return;
        }
        if (request.method == 'CONNECT') {
          _idleConnections.remove(socket);
          final buffered = socket.read() ?? Uint8List(0);
          emit('connect', request, socket, buffered);
          if (listenerCount('connect') == 0) {
            socket.write(
              ascii.encode(
                'HTTP/1.1 405 Method Not Allowed\r\nConnection: close\r\n\r\n',
              ),
            );
            socket.end();
          }
          return;
        }
        final expect = request.headers['expect']?.toString().toLowerCase();
        if (expect == '100-continue' && listenerCount('checkContinue') == 0) {
          response.writeContinue();
          emit('request', request, response);
        } else if (expect == '100-continue') {
          emit('checkContinue', request, response);
        } else {
          emit('request', request, response);
        }
        if (listenerCount('request') == 0 &&
            listenerCount('checkContinue') == 0) {
          response.writeHead(404, {'Connection': 'close'}).end();
        }
        if (request.headers['connection']?.toString().toLowerCase() !=
            'close') {
          response.done.then((_) {
            if (!socket.destroyed && !_closed) _idleConnections.add(socket);
          });
        }
        await _readMessageBody(reader, request, parsed.headers);
        if (request.headers['connection']?.toString().toLowerCase() ==
            'close') {
          await response.done;
          socket.end();
          return;
        }
      } on NodeHttpError catch (error) {
        _clientError(error, socket);
        return;
      } on Object catch (error) {
        _clientError(
          NodeHttpError('HPE_INVALID_INTERNAL_STATE', '$error'),
          socket,
        );
        return;
      }
    }
  }

  void _clientError(NodeHttpError error, net.NodeSocket socket) {
    if (listenerCount('clientError') != 0) {
      emit('clientError', error, socket);
    } else {
      final status = error.code == 'HPE_HEADER_OVERFLOW' ? 431 : 400;
      socket.write(
        ascii.encode(
          'HTTP/1.1 $status ${status == 431 ? 'Request Header Fields Too Large' : 'Bad Request'}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n',
        ),
        ([Object? _]) => socket.destroy(),
      );
    }
  }
}

NodeHttpServer createServer([Object? options, Function? requestListener]) {
  var maxHeaderSize = defaultMaxHeaderSize;
  Function? listener = requestListener;
  if (options is Function) listener = options;
  if (options is Map && options['maxHeaderSize'] is int) {
    maxHeaderSize = options['maxHeaderSize'] as int;
  }
  final server = NodeHttpServer(maxHeaderSize: maxHeaderSize);
  if (listener != null) server.on('request', listener);
  return server;
}

/// A limited Agent with one active/idle socket per endpoint. It intentionally
/// serializes requests when maxSockets is one, matching the TLS proxy policy.
class Agent {
  Agent({
    this.keepAlive = true,
    this.maxSockets = 1,
    this.socketPath,
    this.secure = false,
    this.securityContext,
    this.ca,
    this.checkServerIdentity,
  });
  final bool keepAlive;
  final int maxSockets;
  final String? socketPath;
  final bool secure;
  final SecurityContext? securityContext;
  final Object? ca;
  final Function? checkServerIdentity;
  final Map<String, net.NodeSocket> _idle = {};
  final Set<net.NodeSocket> _active = {};
  final Map<String, Completer<void>> _locks = {};
  bool _destroyed = false;

  Future<_AgentLease> _acquire(
    String key,
    Future<net.NodeSocket> Function() create,
  ) async {
    if (_destroyed) throw StateError('Agent is destroyed');
    while (_locks.containsKey(key)) {
      await _locks[key]!.future;
      if (_destroyed) throw StateError('Agent is destroyed');
    }
    final lock = Completer<void>();
    _locks[key] = lock;
    try {
      final idle = _idle.remove(key);
      final reused = idle != null && !idle.destroyed && !idle.closed;
      final socket = reused ? idle : await create();
      _active.add(socket);
      return _AgentLease(socket, reused, () {
        _active.remove(socket);
        if (!_destroyed && keepAlive && !socket.destroyed && !socket.closed)
          _idle[key] = socket;
        else
          socket.destroy();
        _locks.remove(key);
        lock.complete();
      });
    } catch (_) {
      _locks.remove(key);
      lock.complete();
      rethrow;
    }
  }

  void destroy() {
    _destroyed = true;
    for (final socket in _active) {
      socket.destroy();
    }
    for (final socket in _idle.values) {
      socket.destroy();
    }
    _active.clear();
    _idle.clear();
  }
}

class _AgentLease {
  _AgentLease(this.socket, this.reused, this.release);
  final net.NodeSocket socket;
  final bool reused;
  final void Function() release;
}

final Agent globalAgent = Agent(keepAlive: true, maxSockets: 1);

/// Node ClientRequest subset. Writes are queued until a socket is assigned.
class ClientRequest {
  ClientRequest(Object options, [Function? responseListener])
    : _options = _requestOptions(options) {
    if (responseListener != null) on('response', responseListener);
    if (options is Map && options['agent'] is Agent) {
      _agent = options['agent'] as Agent;
    } else {
      _agent = _options['agent'] is Agent
          ? _options['agent'] as Agent
          : globalAgent;
    }
  }

  final Map<String, Object?> _options;
  final Map<String, List<Function>> _listeners = {};
  late final Agent _agent;
  final List<Uint8List> _body = [];
  net.NodeSocket? socket;
  _AgentLease? _lease;
  bool reusedSocket = false;
  bool destroyed = false;
  bool _ended = false;
  bool _started = false;
  bool _headersSent = false;
  bool _requestFinished = false;
  bool _chunked = false;
  int _requestBytesWritten = 0;
  int? _expectedContentLength;
  IncomingMessage? response;

  ClientRequest on(String event, Function listener) {
    (_listeners[event] ??= []).add(listener);
    if (event == 'response' && response != null)
      scheduleMicrotask(() => Function.apply(listener, [response]));
    return this;
  }

  ClientRequest once(String event, Function listener) {
    late Function wrapper;
    wrapper = ([Object? value]) {
      off(event, wrapper);
      Function.apply(listener, value == null ? const [] : [value]);
    };
    return on(event, wrapper);
  }

  ClientRequest off(String event, Function listener) {
    _listeners[event]?.remove(listener);
    return this;
  }

  ClientRequest removeListener(String event, Function listener) =>
      off(event, listener);
  void _emit(String event, [Object? value]) {
    for (final listener in List<Function>.of(_listeners[event] ?? const [])) {
      Function.apply(listener, value == null ? const [] : [value]);
    }
  }

  bool write(Object data, [Function? callback]) {
    if (_ended || destroyed) {
      final error = StateError('write after end');
      callback?.call(error);
      _emit('error', error);
      return false;
    }
    final bytes = _bytes(data);
    _requestBytesWritten += bytes.length;
    if (_headersSent) {
      if (bytes.isNotEmpty) socket!.write(_chunked ? _chunk(bytes) : bytes);
    } else {
      _body.add(bytes);
    }
    if (callback != null)
      scheduleMicrotask(() => Function.apply(callback, const []));
    _start();
    return (socket?.writableLength ??
            _body.fold<int>(0, (n, b) => n + b.length)) <
        net.NodeSocket.highWaterMark;
  }

  ClientRequest end([Object? data, Function? callback]) {
    if (data != null) write(data);
    _ended = true;
    _start();
    if (callback != null) once('finish', callback);
    if (_headersSent) _finishRequest();
    return this;
  }

  void _start() {
    if (_started || destroyed) return;
    _started = true;
    unawaited(_run());
  }

  Future<void> _run() async {
    try {
      final host = (_options['hostname'] ?? _options['host'] ?? 'localhost')
          .toString();
      final port =
          _options['port'] as int? ??
          (_options['protocol'] == 'https:' ? 443 : 80);
      final path = (_options['path'] ?? '/').toString();
      final protocol =
          (_options['protocol'] ?? (_agent.secure ? 'https:' : 'http:'))
              .toString();
      final secure =
          _options['secure'] == true || protocol == 'https:' || _agent.secure;
      final socketPath = _agent.socketPath ?? _options['socketPath'] as String?;
      final key = socketPath == null
          ? '$protocol//$host:$port'
          : 'unix:$socketPath';
      final lease = await _agent._acquire(key, () async {
        if (_options['socket'] is net.NodeSocket)
          return _options['socket'] as net.NodeSocket;
        if (_agent.socketPath != null || _options['socketPath'] != null) {
          return net.NodeSocket.connect(
            _agent.socketPath ?? _options['socketPath'] as String,
          );
        }
        if (secure) {
          final context = _securityContextFor(
            _options['ca'] ?? _agent.ca,
            _agent.securityContext,
          );
          final connected = await net.connectRaw(
            port,
            host,
            _options['lookup'] as net.LookupFunction?,
          );
          final raw = await SecureSocket.secure(
            connected,
            host: host,
            context: context,
            onBadCertificate: _options['rejectUnauthorized'] == false
                ? (_) => true
                : null,
            supportedProtocols: const ['http/1.1'],
          );
          final identityCheck =
              _options['checkServerIdentity'] as Function? ??
              _agent.checkServerIdentity;
          final identityError = identityCheck == null
              ? node_tls.checkServerIdentity(host, raw.peerCertificate)
              : Function.apply(identityCheck, [host, raw.peerCertificate]);
          if (identityError != null) {
            raw.destroy();
            throw identityError as Object;
          }
          return net.NodeSocket.fromSocket(raw, allowHalfOpen: true);
        }
        return net.NodeSocket.connect(
          port,
          host,
          _options['lookup'] as net.LookupFunction?,
        );
      });
      _lease = lease;
      reusedSocket = lease.reused;
      socket = lease.socket;
      socket!.on('error', (Object error) => _emit('error', error));
      final method = (_options['method'] ?? 'GET').toString().toUpperCase();
      final headers = <String, Object?>{};
      final passedHeaders = _options['headers'];
      if (passedHeaders is Map)
        passedHeaders.forEach((key, value) {
          headers['$key'] = value;
        });
      if (!headers.keys.any((key) => key.toLowerCase() == 'host'))
        headers['Host'] = host;
      if (!headers.keys.any((key) => key.toLowerCase() == 'connection'))
        headers['Connection'] = _agent.keepAlive ? 'keep-alive' : 'close';
      final contentLength = headers.entries.any(
        (entry) => entry.key.toLowerCase() == 'content-length',
      );
      final hasTransferEncoding = headers.entries.any(
        (entry) => entry.key.toLowerCase() == 'transfer-encoding',
      );
      if (contentLength && hasTransferEncoding) {
        throw NodeHttpError(
          'HPE_UNEXPECTED_CONTENT_LENGTH',
          'Invalid Content-Length and Transfer-Encoding combination',
        );
      }
      if (contentLength) {
        final text = headers.entries
            .firstWhere((entry) => entry.key.toLowerCase() == 'content-length')
            .value
            .toString();
        if (!RegExp(r'^\d+$').hasMatch(text)) {
          throw NodeHttpError(
            'HPE_INVALID_CONTENT_LENGTH',
            'Invalid request Content-Length',
          );
        }
        _expectedContentLength = int.parse(text);
      }
      final transferEntries = headers.entries
          .where((entry) => entry.key.toLowerCase() == 'transfer-encoding')
          .toList();
      final transferEncoding = transferEntries.isEmpty
          ? null
          : transferEntries.first.value.toString();
      final hasBody = _body.any((bytes) => bytes.isNotEmpty);
      _chunked =
          transferEncoding?.toLowerCase().split(',').last.trim() == 'chunked' ||
          ((!_ended || hasBody) && !contentLength && !hasTransferEncoding);
      if (_chunked) headers['Transfer-Encoding'] = 'chunked';
      final requestHead = StringBuffer('$method $path HTTP/1.1\r\n');
      headers.forEach((name, value) {
        for (final part in _headerValues(value))
          requestHead.write('$name: $part\r\n');
      });
      requestHead.write('\r\n');
      socket!.write(_latin1(requestHead.toString()));
      _headersSent = true;
      if (_chunked) {
        for (final chunk in _body) {
          if (chunk.isNotEmpty) socket!.write(_chunk(chunk));
        }
      } else {
        for (final chunk in _body) {
          if (chunk.isNotEmpty) socket!.write(chunk);
        }
      }
      _body.clear();
      if (_ended) _finishRequest();
      await _parseResponse(socket!, method, lease, key);
    } on Object catch (error) {
      _emit('error', error);
      _lease?.release();
    }
  }

  void _finishRequest() {
    if (_requestFinished || !_headersSent) return;
    if (_expectedContentLength != null &&
        _requestBytesWritten != _expectedContentLength) {
      final error = NodeHttpError(
        'ERR_HTTP_CONTENT_LENGTH_MISMATCH',
        'Request Content-Length does not match bytes written',
      );
      _emit('error', error);
      destroy(error);
      return;
    }
    _requestFinished = true;
    if (_chunked) socket!.write(ascii.encode('0\r\n\r\n'));
    _emit('finish');
  }

  Future<void> _parseResponse(
    net.NodeSocket socket,
    String method,
    _AgentLease lease,
    String key,
  ) async {
    final reader = _ByteReader(socket);
    try {
      while (!destroyed) {
        final head = await _readHead(reader, defaultMaxHeaderSize);
        if (head == null)
          throw const SocketException('Connection closed before response');
        final parsed = _parseHead(head, request: false);
        final message = IncomingMessage._(
          socket: socket,
          rawHeaders: parsed.rawHeaders,
          headers: parsed.headers,
          httpVersion: parsed.version,
          statusCode: parsed.statusCode,
          statusMessage: parsed.target,
        );
        response = message;
        _emit('response', message);
        final noBody =
            method == 'HEAD' ||
            (message.statusCode! >= 100 && message.statusCode! < 200) ||
            message.statusCode == 204 ||
            message.statusCode == 304;
        if (message.statusCode! >= 100 &&
            message.statusCode! < 200 &&
            message.statusCode != 101)
          continue;
        if (noBody) {
          message._finish();
        } else {
          await _readMessageBody(
            reader,
            message,
            parsed.headers,
            response: true,
          );
        }
        final connectionClose =
            message.headers['connection']?.toString().toLowerCase() == 'close';
        if (connectionClose || !_agent.keepAlive || message.statusCode == 101) {
          socket.destroy();
        }
        lease.release();
        return;
      }
    } catch (error) {
      messageError(error);
      socket.destroy(error);
      lease.release();
    }
  }

  void messageError(Object error) {
    if (response != null)
      response!._fail(error);
    else
      _emit('error', error);
  }

  void abort() => destroy(const SocketException('aborted'));
  ClientRequest destroy([Object? error]) {
    if (destroyed) return this;
    destroyed = true;
    socket?.destroy(error);
    _lease?.release();
    if (error != null) _emit('error', error);
    return this;
  }
}

ClientRequest request(Object options, [Function? responseListener]) =>
    ClientRequest(options, responseListener);
ClientRequest get(Object options, [Function? responseListener]) =>
    ClientRequest(options, responseListener)..end();

class _ParsedHead {
  _ParsedHead(
    this.rawHeaders,
    this.headers,
    this.version, {
    this.method,
    this.target,
    this.statusCode,
  });
  final List<String> rawHeaders;
  final Map<String, Object?> headers;
  final String version;
  final String? method;
  final String? target;
  final int? statusCode;
}

Future<List<Uint8List>?> _readHead(_ByteReader reader, int limit) async {
  final lines = <Uint8List>[];
  var size = 0;
  while (true) {
    final line = await reader.line(limit - size);
    if (line == null) {
      if (lines.isEmpty) return null;
      throw NodeHttpError(
        'HPE_INVALID_EOF_STATE',
        'Parse Error: Invalid EOF state',
      );
    }
    size += line.length + 2;
    if (size > limit)
      throw NodeHttpError(
        'HPE_HEADER_OVERFLOW',
        'Parse Error: Header overflow',
      );
    if (line.isEmpty) break;
    lines.add(line);
  }
  if (lines.isEmpty)
    throw NodeHttpError(
      'HPE_INVALID_CONSTANT',
      'Parse Error: Invalid HTTP constant',
    );
  return lines;
}

_ParsedHead _parseHead(List<Uint8List> lines, {required bool request}) {
  final start = latin1.decode(lines.first);
  final pieces = start.split(' ');
  if (request) {
    if (pieces.length != 3 ||
        pieces[0].isEmpty ||
        !pieces[2].startsWith('HTTP/')) {
      throw NodeHttpError(
        'HPE_INVALID_METHOD',
        'Parse Error: Invalid request line',
      );
    }
    final version = pieces[2].substring(5);
    final rawHeaders = <String>[];
    final values = <String, Object?>{};
    for (final lineBytes in lines.skip(1)) {
      final line = latin1.decode(lineBytes);
      final colon = line.indexOf(':');
      if (colon <= 0)
        throw NodeHttpError(
          'HPE_INVALID_HEADER_TOKEN',
          'Parse Error: Invalid header token',
        );
      final name = line.substring(0, colon);
      if (!_headerNamePattern.hasMatch(name))
        throw NodeHttpError(
          'HPE_INVALID_HEADER_TOKEN',
          'Parse Error: Invalid header token',
        );
      final value = line.substring(colon + 1).trim();
      _checkHeaderValue(value);
      rawHeaders
        ..add(name)
        ..add(value);
      _mergeParsedHeader(values, name, value);
    }
    return _ParsedHead(
      rawHeaders,
      values,
      version,
      method: pieces[0],
      target: pieces[1],
    );
  }
  if (pieces.length < 2 || !pieces[0].startsWith('HTTP/')) {
    throw NodeHttpError(
      'HPE_INVALID_CONSTANT',
      'Parse Error: Invalid status line',
    );
  }
  final status = int.tryParse(pieces[1]);
  if (status == null || status < 100 || status > 999)
    throw NodeHttpError(
      'HPE_INVALID_STATUS',
      'Parse Error: Invalid status code',
    );
  final rawHeaders = <String>[];
  final values = <String, Object?>{};
  for (final lineBytes in lines.skip(1)) {
    final line = latin1.decode(lineBytes);
    final colon = line.indexOf(':');
    if (colon <= 0)
      throw NodeHttpError(
        'HPE_INVALID_HEADER_TOKEN',
        'Parse Error: Invalid header token',
      );
    final name = line.substring(0, colon);
    if (!_headerNamePattern.hasMatch(name))
      throw NodeHttpError(
        'HPE_INVALID_HEADER_TOKEN',
        'Parse Error: Invalid header token',
      );
    final value = line.substring(colon + 1).trim();
    rawHeaders
      ..add(name)
      ..add(value);
    _mergeParsedHeader(values, name, value);
  }
  return _ParsedHead(
    rawHeaders,
    values,
    pieces[0].substring(5),
    statusCode: status,
    target: pieces.skip(2).join(' '),
  );
}

final _headerNamePattern = RegExp(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$");
void _mergeParsedHeader(
  Map<String, Object?> headers,
  String name,
  String value,
) {
  final lowerName = name.toLowerCase();
  if (lowerName == 'content-length') {
    if (!RegExp(r'^\d+$').hasMatch(value) || int.tryParse(value) == null) {
      throw NodeHttpError(
        'HPE_INVALID_CONTENT_LENGTH',
        'Parse Error: Invalid Content-Length',
      );
    }
    if (headers.containsKey('content-length') ||
        headers.containsKey('transfer-encoding')) {
      throw NodeHttpError(
        'HPE_UNEXPECTED_CONTENT_LENGTH',
        'Parse Error: Invalid Content-Length and Transfer-Encoding combination',
      );
    }
  } else if (lowerName == 'transfer-encoding') {
    if (headers.containsKey('content-length') ||
        headers.containsKey('transfer-encoding')) {
      throw NodeHttpError(
        'HPE_UNEXPECTED_CONTENT_LENGTH',
        'Parse Error: Invalid Content-Length and Transfer-Encoding combination',
      );
    }
  }
  _mergeHeader(headers, lowerName, value);
}

void _mergeHeader(Map<String, Object?> headers, String name, String value) {
  if (!headers.containsKey(name)) {
    headers[name] = value;
    return;
  }
  final previous = headers[name];
  if (name == 'set-cookie') {
    headers[name] = [
      ...(previous is List ? previous : [previous]),
      value,
    ];
  } else if (const {
    'content-length',
    'transfer-encoding',
    'host',
    'authorization',
    'proxy-authorization',
  }.contains(name)) {
    headers[name] = previous;
  } else {
    headers[name] = '$previous, $value';
  }
}

Future<void> _readMessageBody(
  _ByteReader reader,
  IncomingMessage message,
  Map<String, Object?> headers, {
  bool response = false,
}) async {
  if (headers['transfer-encoding']?.toString().toLowerCase().contains(
        'chunked',
      ) ==
      true) {
    while (true) {
      final line = await reader.line(defaultMaxHeaderSize);
      if (line == null)
        throw const SocketException('Unexpected EOF in chunked body');
      final text = latin1.decode(line).split(';').first.trim();
      final length = int.tryParse(text, radix: 16);
      if (length == null || length < 0)
        throw NodeHttpError(
          'HPE_INVALID_CHUNK_SIZE',
          'Parse Error: Invalid chunk size',
        );
      if (length == 0) {
        while (true) {
          final trailer = await reader.line(defaultMaxHeaderSize);
          if (trailer == null)
            throw const SocketException('EOF in trailer section');
          if (trailer.isEmpty) break;
          final text = latin1.decode(trailer);
          final colon = text.indexOf(':');
          if (colon <= 0)
            throw NodeHttpError(
              'HPE_INVALID_HEADER_TOKEN',
              'Parse Error: Invalid trailer',
            );
          final name = text.substring(0, colon);
          final value = text.substring(colon + 1).trim();
          message.rawTrailers
            ..add(name)
            ..add(value);
          _mergeHeader(message.trailers, name.toLowerCase(), value);
        }
        message._finish();
        return;
      }
      var remainingChunk = length;
      while (remainingChunk > 0) {
        final size = remainingChunk > 8192 ? 8192 : remainingChunk;
        final bytes = await reader.exact(size);
        if (bytes == null)
          throw const SocketException('Unexpected EOF in chunk data');
        remainingChunk -= bytes.length;
        message._add(bytes);
        await message._waitForBodyGate();
      }
      final crlf = await reader.exact(2);
      if (crlf == null || crlf[0] != 13 || crlf[1] != 10)
        throw NodeHttpError(
          'HPE_INVALID_CHUNK_SIZE',
          'Parse Error: Invalid chunk terminator',
        );
    }
  }
  final contentLength = int.tryParse(
    headers['content-length']?.toString() ?? '',
  );
  if (contentLength != null) {
    var remaining = contentLength;
    while (remaining > 0) {
      final bytes = await reader.exact(remaining > 8192 ? 8192 : remaining);
      if (bytes == null) {
        message._fail(
          const SocketException(
            'Connection closed before complete message body',
          ),
        );
        throw const SocketException(
          'Connection closed before complete message body',
        );
      }
      remaining -= bytes.length;
      message._add(bytes);
      await message._waitForBodyGate();
    }
    message._finish();
    return;
  }
  if (response) {
    while (true) {
      final bytes = await reader.some(8192);
      if (bytes == null) break;
      message._add(bytes);
    }
  }
  message._finish();
}

class _ByteReader {
  _ByteReader(this.socket);
  final net.NodeSocket socket;

  Future<int?> _byte() async {
    while (true) {
      final data = socket.read(1);
      if (data != null && data.isNotEmpty) return data[0];
      if (socket.readableEnded || socket.destroyed) return null;
      final wake = Completer<void>();
      void ready([Object? _]) {
        if (!wake.isCompleted) wake.complete();
      }

      socket.once('readable', ready);
      socket.once('end', ready);
      socket.once('close', ready);
      if (socket.readableEnded || socket.destroyed) ready();
      await wake.future;
      socket.off('readable', ready).off('end', ready).off('close', ready);
    }
  }

  Future<Uint8List?> line(int limit) async {
    final output = BytesBuilder(copy: false);
    var sawCr = false;
    while (true) {
      final value = await _byte();
      if (value == null)
        return output.isEmpty && !sawCr
            ? null
            : throw const SocketException('Unexpected EOF in line');
      if (sawCr) {
        if (value != 10)
          throw NodeHttpError(
            'HPE_LF_EXPECTED',
            'Parse Error: Missing expected LF after CR',
          );
        return output.takeBytes();
      }
      if (value == 13) {
        sawCr = true;
        continue;
      }
      if (value == 10)
        throw NodeHttpError(
          'HPE_STRICT',
          'Parse Error: Bare LF in HTTP message',
        );
      output.addByte(value);
      if (output.length > limit)
        throw NodeHttpError(
          'HPE_HEADER_OVERFLOW',
          'Parse Error: Header overflow',
        );
    }
  }

  Future<Uint8List?> exact(int count) async {
    if (count == 0) return Uint8List(0);
    final builder = BytesBuilder(copy: false);
    while (builder.length < count) {
      final value = await _byte();
      if (value == null) return null;
      builder.addByte(value);
    }
    return builder.takeBytes();
  }

  Future<Uint8List?> some(int max) async {
    final first = await _byte();
    if (first == null) return null;
    final bytes = BytesBuilder(copy: false)..addByte(first);
    while (bytes.length < max) {
      final next = socket.read(max - bytes.length);
      if (next == null || next.isEmpty) break;
      bytes.add(next);
    }
    return bytes.takeBytes();
  }
}

void _checkHeaderName(String name) {
  if (!_headerNamePattern.hasMatch(name))
    throw ArgumentError.value(name, 'name', 'Invalid HTTP header name');
}

void _checkHeaderValue(Object? value) {
  for (final part in _headerValues(value)) {
    if (part.codeUnits.any((unit) => (unit < 32 && unit != 9) || unit == 127)) {
      throw ArgumentError.value(value, 'value', 'Invalid HTTP header value');
    }
  }
}

List<String> _headerValues(Object? value) {
  if (value == null) return const [''];
  if (value is Iterable)
    return value.map((element) => element.toString()).toList();
  return [value.toString()];
}

Uint8List _bytes(Object data) {
  if (data is String) return _latin1(data);
  return Uint8List.fromList(data as List<int>);
}

Uint8List _latin1(String text) =>
    Uint8List.fromList(text.codeUnits.map((unit) => unit & 0xff).toList());
Uint8List _chunk(List<int> bytes) => _concat([
  ascii.encode('${bytes.length.toRadixString(16)}\r\n'),
  bytes,
  ascii.encode('\r\n'),
]);
Uint8List _serializeEndChunk(Map<String, Object?> trailers) {
  final out = BytesBuilder(copy: false)..add(ascii.encode('0\r\n'));
  trailers.forEach((name, value) {
    for (final part in _headerValues(value))
      out.add(_latin1('$name: $part\r\n'));
  });
  out.add(ascii.encode('\r\n'));
  return out.takeBytes();
}

Uint8List _concat(List<List<int>> lists) {
  final b = BytesBuilder(copy: false);
  for (final bytes in lists) {
    b.add(bytes);
  }
  return b.takeBytes();
}

String _defaultStatusMessage(int code) =>
    const {
      100: 'Continue',
      101: 'Switching Protocols',
      200: 'OK',
      201: 'Created',
      202: 'Accepted',
      204: 'No Content',
      301: 'Moved Permanently',
      302: 'Found',
      304: 'Not Modified',
      400: 'Bad Request',
      401: 'Unauthorized',
      403: 'Forbidden',
      404: 'Not Found',
      405: 'Method Not Allowed',
      408: 'Request Timeout',
      413: 'Payload Too Large',
      431: 'Request Header Fields Too Large',
      500: 'Internal Server Error',
      502: 'Bad Gateway',
      503: 'Service Unavailable',
    }[code] ??
    'unknown';
Map<String, Object?> _requestOptions(Object options) {
  if (options is Map)
    return {for (final entry in options.entries) '${entry.key}': entry.value};
  if (options is Uri)
    return {
      'protocol': options.scheme == 'https' ? 'https:' : 'http:',
      'hostname': options.host,
      'port': options.hasPort ? options.port : null,
      'path': '${options.path}${options.hasQuery ? '?${options.query}' : ''}',
    };
  if (options is String) return _requestOptions(Uri.parse(options));
  throw ArgumentError('http.request options must be a Map, Uri, or URL string');
}

SecurityContext _securityContextFor(Object? ca, SecurityContext? context) {
  if (context != null) {
    if (ca != null) {
      throw ArgumentError('Cannot combine a SecurityContext with a CA bundle');
    }
    return context;
  }
  if (ca == null) return node_tls.trustedRootContext();
  final custom = SecurityContext(withTrustedRoots: false);
  void addCertificate(Object certificate) {
    if (certificate is String) {
      custom.setTrustedCertificatesBytes(utf8.encode(certificate));
    } else if (certificate is List<int>) {
      custom.setTrustedCertificatesBytes(Uint8List.fromList(certificate));
    } else {
      throw ArgumentError.value(
        certificate,
        'ca',
        'Expected PEM certificate bytes or text',
      );
    }
  }

  if (ca is Iterable && ca is! String) {
    for (final certificate in ca) {
      addCertificate(certificate as Object);
    }
  } else {
    addCertificate(ca);
  }
  return custom;
}
