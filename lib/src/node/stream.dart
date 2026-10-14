// `node:stream`: stream classes and conversions. No upstream counterpart.
// Wave 1 declarations; methods are pending real stream behavior.

import 'dart:typed_data';

import 'events.dart';
import 'fetch.dart';

/// Node's `Readable` stream.
class Readable extends EventEmitter {
  Readable({Function? read, Function? destroy});

  /// Create a Node readable from a Web ReadableStream.
  static Readable fromWeb(ReadableStream<Object?> stream) =>
      throw UnimplementedError('node:stream: pending (wave 1)');

  /// Convert a Node readable to a Web ReadableStream.
  static ReadableStream<Uint8List> toWeb(Readable stream) =>
      throw UnimplementedError('node:stream: pending (wave 1)');

  @override
  Readable on(String event, Function listener) =>
      throw UnimplementedError('node:stream: pending (wave 1)');

  @override
  Readable once(String event, Function listener) =>
      throw UnimplementedError('node:stream: pending (wave 1)');

  @override
  Readable off(String event, Function listener) =>
      throw UnimplementedError('node:stream: pending (wave 1)');

  @override
  Readable removeListener(String event, Function listener) =>
      throw UnimplementedError('node:stream: pending (wave 1)');

  Readable unpipe([Writable? destination]) =>
      throw UnimplementedError('node:stream: pending (wave 1)');

  T pipe<T extends Writable>(T destination, {bool end = true}) =>
      throw UnimplementedError('node:stream: pending (wave 1)');

  Readable pause() => throw UnimplementedError('node:stream: pending (wave 1)');

  Readable resume() =>
      throw UnimplementedError('node:stream: pending (wave 1)');

  bool isPaused() => throw UnimplementedError('node:stream: pending (wave 1)');

  Object? read([int? size]) =>
      throw UnimplementedError('node:stream: pending (wave 1)');

  void unshift(List<int> chunk) =>
      throw UnimplementedError('node:stream: pending (wave 1)');

  bool push(Object? chunk, [String? encoding]) =>
      throw UnimplementedError('node:stream: pending (wave 1)');

  Readable destroy([Object? error]) =>
      throw UnimplementedError('node:stream: pending (wave 1)');

  bool get destroyed =>
      throw UnimplementedError('node:stream: pending (wave 1)');
  bool get readable =>
      throw UnimplementedError('node:stream: pending (wave 1)');
  bool get readableEnded =>
      throw UnimplementedError('node:stream: pending (wave 1)');
  int get readableLength =>
      throw UnimplementedError('node:stream: pending (wave 1)');
}

/// Node's `Writable` stream.
class Writable extends EventEmitter {
  Writable({Function? write, Function? finalCallback, Function? destroy});

  @override
  Writable on(String event, Function listener) =>
      throw UnimplementedError('node:stream: pending (wave 1)');

  @override
  Writable once(String event, Function listener) =>
      throw UnimplementedError('node:stream: pending (wave 1)');

  @override
  Writable off(String event, Function listener) =>
      throw UnimplementedError('node:stream: pending (wave 1)');

  @override
  Writable removeListener(String event, Function listener) =>
      throw UnimplementedError('node:stream: pending (wave 1)');

  bool write(Object data, [Function? callback]) =>
      throw UnimplementedError('node:stream: pending (wave 1)');

  Writable end([Object? data, Function? callback]) =>
      throw UnimplementedError('node:stream: pending (wave 1)');

  Writable destroy([Object? error]) =>
      throw UnimplementedError('node:stream: pending (wave 1)');

  bool get destroyed =>
      throw UnimplementedError('node:stream: pending (wave 1)');
  bool get writable =>
      throw UnimplementedError('node:stream: pending (wave 1)');
  bool get writableEnded =>
      throw UnimplementedError('node:stream: pending (wave 1)');
  bool get writableFinished =>
      throw UnimplementedError('node:stream: pending (wave 1)');
  int get writableLength =>
      throw UnimplementedError('node:stream: pending (wave 1)');
}

/// Node's duplex stream: a readable stream that is also writable.
class Duplex extends Readable implements Writable {
  Duplex({
    Function? read,
    Function? write,
    Function? finalCallback,
    Function? destroy,
  });

  @override
  Duplex on(String event, Function listener) =>
      throw UnimplementedError('node:stream: pending (wave 1)');

  @override
  Duplex once(String event, Function listener) =>
      throw UnimplementedError('node:stream: pending (wave 1)');

  @override
  Duplex off(String event, Function listener) =>
      throw UnimplementedError('node:stream: pending (wave 1)');

  @override
  Duplex removeListener(String event, Function listener) =>
      throw UnimplementedError('node:stream: pending (wave 1)');

  @override
  bool write(Object data, [Function? callback]) =>
      throw UnimplementedError('node:stream: pending (wave 1)');

  @override
  Duplex end([Object? data, Function? callback]) =>
      throw UnimplementedError('node:stream: pending (wave 1)');

  @override
  Duplex destroy([Object? error]) =>
      throw UnimplementedError('node:stream: pending (wave 1)');

  @override
  bool get writable =>
      throw UnimplementedError('node:stream: pending (wave 1)');
  @override
  bool get writableEnded =>
      throw UnimplementedError('node:stream: pending (wave 1)');
  @override
  bool get writableFinished =>
      throw UnimplementedError('node:stream: pending (wave 1)');
  @override
  int get writableLength =>
      throw UnimplementedError('node:stream: pending (wave 1)');
}

/// Node's transform stream, a duplex stream with a transform callback.
class Transform extends Duplex {
  Transform({
    Function? read,
    Function? write,
    Function? finalCallback,
    Function? transform,
    Function? flush,
    Function? destroy,
  });

  @override
  Transform on(String event, Function listener) =>
      throw UnimplementedError('node:stream: pending (wave 1)');

  @override
  Transform once(String event, Function listener) =>
      throw UnimplementedError('node:stream: pending (wave 1)');

  @override
  Transform off(String event, Function listener) =>
      throw UnimplementedError('node:stream: pending (wave 1)');

  @override
  Transform removeListener(String event, Function listener) =>
      throw UnimplementedError('node:stream: pending (wave 1)');

  @override
  Transform unpipe([Writable? destination]) =>
      throw UnimplementedError('node:stream: pending (wave 1)');

  @override
  Transform pause() =>
      throw UnimplementedError('node:stream: pending (wave 1)');
  @override
  Transform resume() =>
      throw UnimplementedError('node:stream: pending (wave 1)');
  @override
  Object? read([int? size]) =>
      throw UnimplementedError('node:stream: pending (wave 1)');
  @override
  void unshift(List<int> chunk) =>
      throw UnimplementedError('node:stream: pending (wave 1)');
  @override
  bool push(Object? chunk, [String? encoding]) =>
      throw UnimplementedError('node:stream: pending (wave 1)');
  @override
  bool write(Object data, [Function? callback]) =>
      throw UnimplementedError('node:stream: pending (wave 1)');
  @override
  Transform end([Object? data, Function? callback]) =>
      throw UnimplementedError('node:stream: pending (wave 1)');
  @override
  Transform destroy([Object? error]) =>
      throw UnimplementedError('node:stream: pending (wave 1)');
}

/// Node's pass-through transform stream.
class PassThrough extends Transform {
  PassThrough({
    Function? read,
    Function? write,
    Function? finalCallback,
    Function? transform,
    Function? flush,
    Function? destroy,
  });
}
