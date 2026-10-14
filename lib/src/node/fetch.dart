// Web Fetch API globals used by the port. No upstream counterpart.

import 'dart:async';
import 'dart:collection';
import 'dart:typed_data';

import 'abort.dart';
import 'events.dart' as events;

/// The Fetch API's request object, retaining the web-global property names.
class Request {
  Request(
    this.url, {
    this.method = 'GET',
    Headers? headers,
    this.body,
    this.signal,
    this.duplex,
  }) : headers = headers ?? Headers();

  final String url;
  final String method;
  final Headers headers;
  final ReadableStream<Uint8List>? body;
  final AbortSignal? signal;
  final String? duplex;
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

/// A Web ReadableStream declaration; its stream operations are pending.
class ReadableStream<T> {
  ReadableStream({
    ReadableStreamStart<T>? start,
    ReadableStreamPull<T>? pull,
    ReadableStreamCancel? cancel,
  }) : _sourcePull = pull,
       _sourceCancel = cancel {
    _controller = ReadableStreamDefaultController<T>._(this);
    if (start != null) {
      try {
        start(_controller);
      } on Object catch (error) {
        _controller.error(error);
      }
    }
  }

  final ReadableStreamPull<T>? _sourcePull;
  final ReadableStreamCancel? _sourceCancel;
  late final ReadableStreamDefaultController<T> _controller;
  final Queue<T> _queue = Queue<T>();
  final Queue<Completer<({bool done, T? value})>> _pending = Queue();
  bool _closed = false;
  Object? _error;
  bool _locked = false;
  bool _pulling = false;

  Future<void> _pull() async {
    if (_pulling || _closed || _sourcePull == null) return;
    _pulling = true;
    try {
      await _sourcePull(_controller);
    } on Object catch (error) {
      _controller.error(error);
    } finally {
      _pulling = false;
    }
  }

  ReadableStreamDefaultReader<T> getReader() {
    if (_locked) throw StateError('ReadableStream is already locked');
    _locked = true;
    return ReadableStreamDefaultReader<T>._(this);
  }

  List<ReadableStream<T>> tee() {
    final reader = getReader();
    late ReadableStream<T> a;
    late ReadableStream<T> b;
    a = ReadableStream<T>(
      start: (controller) async {
        while (true) {
          final result = await reader.read();
          if (result.done) {
            controller.close();
            return;
          }
          controller.enqueue(result.value as T);
          b._controller.enqueue(result.value as T);
        }
      },
    );
    b = ReadableStream<T>();
    return [a, b];
  }

  Future<void> cancel([Object? reason]) async {
    if (_locked) throw StateError('Cannot cancel a locked ReadableStream');
    await _cancel(reason);
  }

  Future<void> _cancel(Object? reason) async {
    if (_closed) return;
    _closed = true;
    _queue.clear();
    for (final waiter in _pending) {
      if (!waiter.isCompleted) waiter.complete((done: true, value: null));
    }
    _pending.clear();
    await _sourceCancel?.call(reason);
  }

  bool get locked => _locked;

  Future<({bool done, T? value})> _read() async {
    if (_error != null) throw _error!;
    if (_queue.isNotEmpty) {
      final value = _queue.removeFirst();
      unawaited(_pull());
      return (done: false, value: value);
    }
    if (_closed) return (done: true, value: null);
    final waiter = Completer<({bool done, T? value})>();
    _pending.add(waiter);
    unawaited(_pull());
    return waiter.future;
  }

  void _enqueue(T chunk) {
    if (_closed) throw StateError('ReadableStream is closed');
    if (_pending.isNotEmpty) {
      _pending.removeFirst().complete((done: false, value: chunk));
    } else {
      _queue.add(chunk);
    }
  }

  void _close() {
    if (_closed) return;
    _closed = true;
    while (_pending.isNotEmpty) {
      _pending.removeFirst().complete((done: true, value: null));
    }
  }

  void _setError(Object error) {
    _error = error;
    _closed = true;
    while (_pending.isNotEmpty) {
      _pending.removeFirst().completeError(error);
    }
  }
}

/// The controller supplied to a Web ReadableStream source callback.
class ReadableStreamDefaultController<T> {
  ReadableStreamDefaultController._(this._stream);
  final ReadableStream<T> _stream;
  void enqueue(T chunk) => _stream._enqueue(chunk);

  void close() => _stream._close();

  void error(Object error) => _stream._setError(error);

  num? get desiredSize => _stream._closed ? 0 : 1;
}

/// A default reader for a Web ReadableStream; operations are pending.
class ReadableStreamDefaultReader<T> {
  ReadableStreamDefaultReader._(this._stream);
  final ReadableStream<T> _stream;
  Future<({bool done, T? value})> read() => _stream._read();

  Future<void> cancel([Object? reason]) => _stream._cancel(reason);

  void releaseLock() => _stream._locked = false;
}
