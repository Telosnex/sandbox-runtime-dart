// Web Fetch API globals used by the port. No upstream counterpart.

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
    String? duplex,
  }) : headers = headers ?? Headers();

  final String url;
  final String method;
  final Headers headers;
  final ReadableStream<Uint8List>? body;
  final AbortSignal? signal;
}

/// Fetch API HTTP headers. Names are case-insensitive and appended values are
/// combined with `, `, as the Fetch standard specifies.
class Headers extends IterableBase<MapEntry<String, String>> {
  Headers([Object? init]) {
    if (init == null) return;
    if (init is Headers) {
      _values.addAll(init._values);
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

  final Map<String, String> _values = {};

  void append(String name, String value) {
    final key = _normalizeName(name);
    final normalizedValue = _normalizeValue(value);
    final previous = _values[key];
    _values[key] = previous == null
        ? normalizedValue
        : '$previous, $normalizedValue';
  }

  String? get(String name) => _values[_normalizeName(name)];

  void set(String name, String value) {
    _values[_normalizeName(name)] = _normalizeValue(value);
  }

  bool has(String name) => _values.containsKey(_normalizeName(name));

  void delete(String name) => _values.remove(_normalizeName(name));

  Iterable<MapEntry<String, String>> entries() sync* {
    for (final name in _values.keys.toList()..sort()) {
      yield MapEntry(name, _values[name]!);
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

/// A Web ReadableStream declaration; its stream operations are pending.
class ReadableStream<T> {
  ReadableStream({Function? start, Function? pull, Function? cancel});

  ReadableStreamDefaultReader<T> getReader() =>
      throw UnimplementedError('web ReadableStream: pending (wave 1)');

  List<ReadableStream<T>> tee() =>
      throw UnimplementedError('web ReadableStream: pending (wave 1)');

  Future<void> cancel([Object? reason]) =>
      throw UnimplementedError('web ReadableStream: pending (wave 1)');

  bool get locked =>
      throw UnimplementedError('web ReadableStream: pending (wave 1)');
}

/// A default reader for a Web ReadableStream; operations are pending.
class ReadableStreamDefaultReader<T> {
  Future<({bool done, T? value})> read() =>
      throw UnimplementedError('web ReadableStream: pending (wave 1)');

  Future<void> cancel([Object? reason]) =>
      throw UnimplementedError('web ReadableStream: pending (wave 1)');

  void releaseLock() =>
      throw UnimplementedError('web ReadableStream: pending (wave 1)');
}
