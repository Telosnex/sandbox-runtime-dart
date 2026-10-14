// Web Fetch API globals used by the port. No upstream counterpart.

import 'dart:async';
import 'dart:collection';
import 'dart:typed_data';

import 'abort.dart';
import 'events.dart' as events;
import 'url.dart';

/// The Fetch API's request object, retaining the web-global property names.
///
/// As in Node (undici): [url] is the parsed, serialized URL; a body on GET or
/// HEAD, or a stream body without `duplex: 'half'`, throws a TypeError
/// ([ArgumentError] here); [bodyUsed] is true once the body stream was read
/// from or cancelled.
class Request {
  Request(
    String url, {
    String method = 'GET',
    Object? headers,
    this.body,
    this.signal,
    this.duplex,
  }) : url = URL(url).href,
       method = _normalizeMethod(method),
       headers = headers is Headers ? Headers(headers) : Headers(headers) {
    if (body != null && (this.method == 'GET' || this.method == 'HEAD')) {
      throw ArgumentError('Request with GET/HEAD method cannot have body.');
    }
    if (body != null && duplex != 'half') {
      throw ArgumentError(
        'RequestInit: duplex option is required when sending a body.',
      );
    }
  }

  final String url;
  final String method;
  final Headers headers;
  final ReadableStream<Uint8List>? body;
  final AbortSignal? signal;
  final String? duplex;

  bool get bodyUsed => body != null && body!._disturbed;

  static String _normalizeMethod(String method) {
    if (!RegExp(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$").hasMatch(method)) {
      throw ArgumentError.value(
        method,
        'method',
        'is not a valid HTTP method.',
      );
    }
    final upper = method.toUpperCase();
    if (const {'CONNECT', 'TRACE', 'TRACK'}.contains(upper)) {
      throw ArgumentError.value(
        method,
        'method',
        "'$method' HTTP method is unsupported.",
      );
    }
    return const {
          'DELETE',
          'GET',
          'HEAD',
          'OPTIONS',
          'POST',
          'PUT',
          'PATCH',
        }.contains(upper)
        ? upper
        : method;
  }
}

/// Fetch API HTTP headers. Names are case-insensitive and appended values are
/// combined with `, `, as the Fetch standard specifies, except Set-Cookie.
class Headers extends IterableBase<MapEntry<String, String>> {
  Headers([Object? init]) {
    if (init == null) return;
    if (init is Headers) {
      for (final entry in init._values.entries) {
        _values[entry.key] = List<String>.of(entry.value);
      }
    } else if (init is Map) {
      for (final entry in init.entries) {
        if (entry.value is Iterable && entry.value is! String) {
          for (final value in entry.value as Iterable) {
            append('${entry.key}', '$value');
          }
        } else {
          append('${entry.key}', '${entry.value}');
        }
      }
    } else if (init is Iterable) {
      for (final entry in init) {
        if (entry is! Iterable) {
          throw ArgumentError.value(init, 'init', 'Invalid Headers init');
        }
        final pair = entry.toList();
        if (pair.length != 2) {
          throw ArgumentError.value(init, 'init', 'Invalid Headers init');
        }
        append('${pair[0]}', '${pair[1]}');
      }
    } else {
      throw ArgumentError.value(init, 'init', 'Invalid Headers init');
    }
  }

  final Map<String, List<String>> _values = {};

  void append(String name, String value) {
    final key = _normalizeName(name);
    final normalizedValue = _normalizeValue(value);
    if (key == 'set-cookie') {
      (_values[key] ??= []).add(normalizedValue);
    } else if (_values[key] == null) {
      _values[key] = [normalizedValue];
    } else {
      _values[key]![0] = '${_values[key]![0]}, $normalizedValue';
    }
  }

  String? get(String name) => _values[_normalizeName(name)]?.first;

  void set(String name, String value) {
    _values[_normalizeName(name)] = [_normalizeValue(value)];
  }

  bool has(String name) => _values.containsKey(_normalizeName(name));

  void delete(String name) => _values.remove(_normalizeName(name));

  /// Return each Set-Cookie value separately, without comma joining.
  List<String> getSetCookie() =>
      List<String>.of(_values['set-cookie'] ?? const []);

  Iterable<MapEntry<String, String>> entries() sync* {
    for (final name in _values.keys.toList()..sort()) {
      for (final value in _values[name]!) {
        yield MapEntry(name, value);
      }
    }
  }

  Iterable<String> keys() sync* {
    for (final entry in entries()) {
      yield entry.key;
    }
  }

  Iterable<String> values() sync* {
    for (final entry in entries()) {
      yield entry.value;
    }
  }

  /// Fetch's callback order is `(value, name, headers)`; [events.applyListener]
  /// also lets a shorter Dart callback ignore trailing arguments.
  @override
  void forEach(Function callback) {
    for (final entry in entries()) {
      events.applyListener(callback, [entry.value, entry.key, this]);
    }
  }

  @override
  Iterator<MapEntry<String, String>> get iterator => entries().iterator;

  static String _normalizeName(String name) {
    if (name.isEmpty ||
        !RegExp(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$").hasMatch(name)) {
      throw ArgumentError.value(
        name,
        'name',
        'Invalid character in header field name',
      );
    }
    return name.toLowerCase();
  }

  static String _normalizeValue(String value) {
    if (value.codeUnits.any(
      (unit) => (unit < 32 && unit != 9) || unit == 127,
    )) {
      throw ArgumentError.value(
        value,
        'value',
        'Invalid character in header field value',
      );
    }
    return value.trim();
  }
}

/// A Web ReadableStream source callback with its typed controller argument.
typedef ReadableStreamStart<T> =
    FutureOr<void> Function(ReadableStreamDefaultController<T> controller);
typedef ReadableStreamPull<T> =
    FutureOr<void> Function(ReadableStreamDefaultController<T> controller);
typedef ReadableStreamCancel = FutureOr<void> Function(Object? reason);

typedef ReadResult<T> = ({bool done, T? value});

/// A Web ReadableStream with a default (non-byte) controller and a
/// high-water mark of one chunk, as the WHATWG Streams standard specifies.
class ReadableStream<T> {
  ReadableStream({
    ReadableStreamStart<T>? start,
    ReadableStreamPull<T>? pull,
    ReadableStreamCancel? cancel,
  }) : _sourcePull = pull,
       _sourceCancel = cancel {
    _controller = ReadableStreamDefaultController<T>._(this);
    FutureOr<void> started;
    try {
      started = start?.call(_controller);
    } on Object catch (error) {
      _controller.error(error);
      return;
    }
    Future<void>.value(started).then((_) {
      _started = true;
      _pullIfNeeded();
    }, onError: (Object error) => _controller.error(error));
  }

  final ReadableStreamPull<T>? _sourcePull;
  final ReadableStreamCancel? _sourceCancel;
  late final ReadableStreamDefaultController<T> _controller;
  final Queue<T> _queue = Queue<T>();
  final Queue<Completer<ReadResult<T>>> _pending = Queue();
  // 'readable', 'closed' or 'errored'.
  String _state = 'readable';
  bool _closeRequested = false;
  Object? _error;
  ReadableStreamDefaultReader<T>? _reader;
  bool _started = false;
  bool _pulling = false;
  bool _pullAgain = false;
  bool _disturbed = false;

  bool get locked => _reader != null;

  int get _desiredSize => 1 - _queue.length;

  void _pullIfNeeded() {
    if (!_started || _state != 'readable' || _closeRequested) return;
    if (_sourcePull == null) return;
    if (!(_pending.isNotEmpty || _desiredSize > 0)) return;
    if (_pulling) {
      _pullAgain = true;
      return;
    }
    _pulling = true;
    Future<void>.sync(() => _sourcePull(_controller)).then((_) {
      _pulling = false;
      if (_pullAgain) {
        _pullAgain = false;
        _pullIfNeeded();
      }
    }, onError: (Object error) => _controller.error(error));
  }

  ReadableStreamDefaultReader<T> getReader() {
    if (locked) throw StateError('ReadableStream is locked');
    return _reader = ReadableStreamDefaultReader<T>._(this);
  }

  /// The standard's ReadableStreamDefaultTee: both branches see every chunk
  /// the source yields; the source is cancelled only once both are.
  List<ReadableStream<T>> tee() {
    final reader = getReader();
    var reading = false;
    var readAgain = false;
    var canceled1 = false;
    var canceled2 = false;
    Object? reason1;
    Object? reason2;
    late ReadableStream<T> branch1;
    late ReadableStream<T> branch2;
    final cancelPromise = Completer<void>();

    Future<void> pullAlgorithm(ReadableStreamDefaultController<T> _) async {
      if (reading) {
        readAgain = true;
        return;
      }
      reading = true;
      reader._readRaw().then(
        (result) {
          scheduleMicrotask(() {
            readAgain = false;
            if (result.done) {
              reading = false;
              if (!canceled1) branch1._controller.close();
              if (!canceled2) branch2._controller.close();
              if (!canceled1 || !canceled2) {
                if (!cancelPromise.isCompleted) cancelPromise.complete();
              }
              return;
            }
            final chunk = result.value as T;
            if (!canceled1) branch1._controller.enqueue(chunk);
            if (!canceled2) branch2._controller.enqueue(chunk);
            reading = false;
            if (readAgain) pullAlgorithm(branch1._controller);
          });
        },
        onError: (Object _) {
          reading = false;
        },
      );
    }

    Future<void> cancelBoth() async {
      try {
        await reader._stream._cancel([reason1, reason2]);
        if (!cancelPromise.isCompleted) cancelPromise.complete();
      } on Object catch (error) {
        if (!cancelPromise.isCompleted) cancelPromise.completeError(error);
      }
    }

    branch1 = ReadableStream<T>(
      pull: pullAlgorithm,
      cancel: (reason) {
        canceled1 = true;
        reason1 = reason;
        if (canceled2) cancelBoth();
        return cancelPromise.future;
      },
    );
    branch2 = ReadableStream<T>(
      pull: pullAlgorithm,
      cancel: (reason) {
        canceled2 = true;
        reason2 = reason;
        if (canceled1) cancelBoth();
        return cancelPromise.future;
      },
    );
    _closedFuture.then(
      (_) {},
      onError: (Object error) {
        branch1._controller._errorIfReadable(error);
        branch2._controller._errorIfReadable(error);
        if (!canceled1 || !canceled2) {
          if (!cancelPromise.isCompleted) cancelPromise.complete();
        }
      },
    );
    return [branch1, branch2];
  }

  /// Rejects when the stream is locked or already errored, as in the
  /// standard.
  Future<void> cancel([Object? reason]) {
    if (locked) {
      return Future.error(StateError('Cannot cancel a locked ReadableStream'));
    }
    return _cancel(reason);
  }

  final Completer<void> _closedCompleter = Completer<void>()..future.ignore();
  Future<void> get _closedFuture => _closedCompleter.future;

  Future<void> _cancel(Object? reason) async {
    _disturbed = true;
    if (_state == 'closed') return;
    if (_state == 'errored') throw _error!;
    _finishClose();
    _queue.clear();
    await _sourceCancel?.call(reason);
  }

  Future<ReadResult<T>> _read() {
    _disturbed = true;
    if (_state == 'errored') return Future.error(_error!);
    if (_queue.isNotEmpty) {
      final value = _queue.removeFirst();
      if (_closeRequested && _queue.isEmpty) {
        _finishClose();
      } else {
        _pullIfNeeded();
      }
      return Future.value((done: false, value: value));
    }
    if (_state == 'closed') return Future.value((done: true, value: null));
    final waiter = Completer<ReadResult<T>>();
    _pending.add(waiter);
    _pullIfNeeded();
    return waiter.future;
  }

  void _enqueue(T chunk) {
    if (_closeRequested || _state != 'readable') {
      throw StateError('Invalid state: Controller is already closed');
    }
    if (_pending.isNotEmpty) {
      _pending.removeFirst().complete((done: false, value: chunk));
    } else {
      _queue.add(chunk);
    }
    _pullIfNeeded();
  }

  void _close() {
    if (_closeRequested || _state != 'readable') {
      throw StateError('Invalid state: Controller is already closed');
    }
    _closeRequested = true;
    if (_queue.isEmpty) _finishClose();
  }

  void _finishClose() {
    if (_state != 'readable') return;
    _state = 'closed';
    while (_pending.isNotEmpty) {
      _pending.removeFirst().complete((done: true, value: null));
    }
    if (!_closedCompleter.isCompleted) _closedCompleter.complete();
  }

  void _setError(Object error) {
    if (_state != 'readable') return;
    _state = 'errored';
    _error = error;
    _queue.clear();
    while (_pending.isNotEmpty) {
      _pending.removeFirst().completeError(error);
    }
    if (!_closedCompleter.isCompleted) _closedCompleter.completeError(error);
  }
}

/// The controller supplied to a Web ReadableStream source callback.
class ReadableStreamDefaultController<T> {
  ReadableStreamDefaultController._(this._stream);
  final ReadableStream<T> _stream;
  void enqueue(T chunk) => _stream._enqueue(chunk);

  void close() => _stream._close();

  void error([Object? error]) => _stream._setError(error ?? StateError(''));

  void _errorIfReadable(Object error) => _stream._setError(error);

  num? get desiredSize => switch (_stream._state) {
    'errored' => null,
    'closed' => 0,
    _ => _stream._desiredSize,
  };
}

/// A default reader for a Web ReadableStream.
class ReadableStreamDefaultReader<T> {
  ReadableStreamDefaultReader._(this._stream);
  final ReadableStream<T> _stream;
  bool _released = false;

  Future<ReadResult<T>> read() {
    if (_released) {
      return Future.error(StateError('Reader has been released'));
    }
    return _stream._read();
  }

  Future<ReadResult<T>> _readRaw() => _stream._read();

  Future<void> get closed => _stream._closedFuture;

  Future<void> cancel([Object? reason]) {
    if (_released) {
      return Future.error(StateError('Reader has been released'));
    }
    return _stream._cancel(reason);
  }

  void releaseLock() {
    if (_released) return;
    _released = true;
    final pending = List.of(_stream._pending);
    _stream._pending.clear();
    for (final waiter in pending) {
      waiter.completeError(StateError('Reader was released'));
    }
    _stream._reader = null;
  }
}
