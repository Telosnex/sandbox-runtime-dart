// `node:stream`: Readable, Writable, Duplex, Transform, PassThrough,
// finished, pipeline, Readable.from/toWeb/fromWeb. No upstream counterpart;
// Node v22's lib/internal/streams/*.js is the spec, state machine included.
//
// Node's `_read`, `_write`, `_writev`, `_final`, `_destroy`, `_transform`
// and `_flush` are library-private names in Dart; subclasses override
// [Readable.readImpl], [Writable.writeImpl], [Writable.finalImpl] (with
// [Writable.hasFinalImpl]), [Readable.destroyImpl], [Transform.transformImpl]
// and [Transform.flushImpl], or pass the same-named constructor options
// (`final` is `finalCallback`). Callbacks get Node's arguments: write
// `(chunk, encoding, callback)`, transform `(chunk, encoding, callback)`,
// final/flush `(callback)`, destroy `(error, callback)`, read `(size)`.
//
// Bytes are Uint8List (Node's Buffer). process.nextTick is a microtask.
import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'errno.dart';
import 'events.dart';
import 'fetch.dart';

const int _defaultHwm = 16384;
const int _defaultObjectHwm = 16;

void _nextTick(void Function() fn) => scheduleMicrotask(fn);

NodeError _err(String code, String message) => NodeError(message, code: code);

NodeError _destroyedError(String method) => _err(
  'ERR_STREAM_DESTROYED',
  'Cannot call $method after a stream was destroyed',
);

NodeError _prematureClose() =>
    _err('ERR_STREAM_PREMATURE_CLOSE', 'Premature close');

/// Node `Buffer.from(string, encoding)` for the encodings streams accept.
Uint8List bufferFromString(String s, [String? encoding]) {
  switch ((encoding ?? 'utf8').toLowerCase()) {
    case 'utf8' || 'utf-8':
      return Uint8List.fromList(utf8.encode(s));
    case 'latin1' || 'binary' || 'ascii':
      return Uint8List.fromList([for (final c in s.codeUnits) c & 0xff]);
    case 'hex':
      final out = <int>[];
      for (var i = 0; i + 1 < s.length; i += 2) {
        final v = int.tryParse(s.substring(i, i + 2), radix: 16);
        if (v == null) break;
        out.add(v);
      }
      return Uint8List.fromList(out);
    case 'base64' || 'base64url':
      var t = s.replaceAll('-', '+').replaceAll('_', '/').replaceAll('=', '');
      t = t.padRight((t.length + 3) ~/ 4 * 4, '=');
      return base64.decode(t);
    default:
      throw _err('ERR_UNKNOWN_ENCODING', 'Unknown encoding: $encoding');
  }
}

/// Node's StringDecoder for the encodings [Readable.setEncoding] takes.
class _Decoder {
  _Decoder(String encoding) : encoding = _normalize(encoding) {
    if (this.encoding == 'utf8') {
      _sink = const Utf8Decoder(
        allowMalformed: true,
      ).startChunkedConversion(StringConversionSink.fromStringSink(_out));
    }
  }
  final String encoding;
  final StringBuffer _out = StringBuffer();
  ByteConversionSink? _sink;

  static String _normalize(String e) => switch (e.toLowerCase()) {
    'utf8' || 'utf-8' => 'utf8',
    'latin1' || 'binary' => 'latin1',
    'hex' => 'hex',
    _ => throw UnimplementedError('stream setEncoding("$e")'),
  };

  String write(Uint8List b) {
    switch (encoding) {
      case 'utf8':
        _sink!.add(b);
        final s = _out.toString();
        _out.clear();
        return s;
      case 'latin1':
        return String.fromCharCodes(b);
      default:
        return [for (final x in b) x.toRadixString(16).padLeft(2, '0')].join();
    }
  }

  String end() {
    if (encoding != 'utf8') return '';
    _sink!.close();
    final s = _out.toString();
    _out.clear();
    return s;
  }
}

int _chunkLength(Object chunk) =>
    chunk is String ? chunk.length : (chunk as List<int>).length;

// ---------------------------------------------------------------------------
// Shared state and destroy (Node destroy.js).

class _ReadableState {
  _ReadableState({
    required this.objectMode,
    required this.highWaterMark,
    required this.emitClose,
    required this.autoDestroy,
  });
  final bool objectMode;
  int highWaterMark;
  final bool emitClose, autoDestroy;
  final List<Object> buffer = [];
  int length = 0;
  final List<EventEmitter> pipes = [];
  bool? flowing;
  bool ended = false,
      endEmitted = false,
      reading = false,
      sync = true,
      needReadable = false,
      emittedReadable = false,
      readableListening = false,
      resumeScheduled = false,
      errorEmitted = false,
      destroyed = false,
      closed = false,
      closeEmitted = false,
      readingMore = false,
      dataEmitted = false,
      readable = true,
      multiAwaitDrain = false;
  bool? paused;
  Object? errored;
  EventEmitter? awaitDrainWriter;
  final Set<EventEmitter> awaitDrainWriters = {};
  _Decoder? decoder;
  String? encoding;
}

class _WritableState {
  _WritableState({
    required this.objectMode,
    required this.highWaterMark,
    required this.emitClose,
    required this.autoDestroy,
    required this.decodeStrings,
  });
  final bool objectMode;
  final int highWaterMark;
  final bool emitClose, autoDestroy, decodeStrings;
  String defaultEncoding = 'utf8';
  int length = 0, corked = 0, pendingcb = 0, writelen = 0, bufferedIndex = 0;
  bool writing = false,
      sync = true,
      bufferProcessing = false,
      needDrain = false,
      ending = false,
      ended = false,
      finished = false,
      finalCalled = false,
      prefinished = false,
      destroyed = false,
      errorEmitted = false,
      closed = false,
      closeEmitted = false,
      writable = true;
  Object? errored;
  Function? writecb;
  final List<({Object chunk, String encoding, Function? callback})> buffered =
      [];
  final List<Function> finishCallbacks = [];
}

/// The base of every Node stream here: an EventEmitter with the readable
/// and/or writable state and Node's destroy().
abstract class NodeStream extends EventEmitter {
  _ReadableState? _r;
  _WritableState? _w;
  Function? _destroyFn;

  /// Node `_destroy(err, cb)`. The default calls `cb(err)`.
  void destroyImpl(Object? error, Function callback) {
    final fn = _destroyFn;
    if (fn != null) {
      Function.apply(fn, [error, callback]);
    } else {
      Function.apply(callback, [error]);
    }
  }

  /// Node `stream.destroy([error])`.
  NodeStream destroy([Object? error, Function? callback]) {
    final r = _r, w = _w;
    if ((w?.destroyed ?? false) || (r?.destroyed ?? false)) {
      if (callback != null) applyListener(callback, const []);
      return this;
    }
    _checkError(error);
    w?.destroyed = true;
    r?.destroyed = true;
    var called = false;
    void onDestroy([Object? err]) {
      if (called) return;
      called = true;
      _checkError(err);
      w?.closed = true;
      r?.closed = true;
      if (callback != null) applyListener(callback, [err]);
      if (err != null) {
        _nextTick(() {
          _emitErrorNT(err);
          _emitCloseNT();
        });
      } else {
        _nextTick(_emitCloseNT);
      }
    }

    try {
      destroyImpl(error, onDestroy);
    } catch (e) {
      onDestroy(e);
    }
    return this;
  }

  void _checkError(Object? err) {
    if (err == null) return;
    final r = _r, w = _w;
    if (w != null && w.errored == null) w.errored = err;
    if (r != null && r.errored == null) r.errored = err;
  }

  void _emitErrorNT(Object err) {
    final r = _r, w = _w;
    if ((w?.errorEmitted ?? false) || (r?.errorEmitted ?? false)) return;
    w?.errorEmitted = true;
    r?.errorEmitted = true;
    emit('error', err);
  }

  void _emitCloseNT() {
    final r = _r, w = _w;
    w?.closeEmitted = true;
    r?.closeEmitted = true;
    if ((w?.emitClose ?? false) || (r?.emitClose ?? false)) emit('close');
  }

  /// Node's errorOrDestroy.
  void _errorOrDestroy(Object err, [bool sync = false]) {
    final r = _r, w = _w;
    if ((w?.destroyed ?? false) || (r?.destroyed ?? false)) return;
    if ((r?.autoDestroy ?? false) || (w?.autoDestroy ?? false)) {
      destroy(err);
    } else {
      _checkError(err);
      if (sync) {
        _nextTick(() => _emitErrorNT(err));
      } else {
        _emitErrorNT(err);
      }
    }
  }

  bool get destroyed => (_w?.destroyed ?? false) || (_r?.destroyed ?? false);

  /// Node `stream.closed`.
  bool get closed => (_w?.closed ?? false) || (_r?.closed ?? false);

  /// Node `stream.errored`.
  Object? get errored => _w?.errored ?? _r?.errored;
}

// ---------------------------------------------------------------------------
// Readable (Node readable.js).

/// Node's `Readable` stream.
class Readable extends NodeStream {
  Readable({
    int? highWaterMark,
    bool objectMode = false,
    String? encoding,
    bool emitClose = true,
    bool autoDestroy = true,
    Function? read,
    Function? destroy,
  }) : _readFn = read {
    _destroyFn = destroy;
    _initReadable(
      highWaterMark: highWaterMark,
      objectMode: objectMode,
      encoding: encoding,
      emitClose: emitClose,
      autoDestroy: autoDestroy,
    );
  }

  final Function? _readFn;

  void _initReadable({
    int? highWaterMark,
    bool objectMode = false,
    String? encoding,
    bool emitClose = true,
    bool autoDestroy = true,
  }) {
    final r = _r = _ReadableState(
      objectMode: objectMode,
      highWaterMark:
          highWaterMark ?? (objectMode ? _defaultObjectHwm : _defaultHwm),
      emitClose: emitClose,
      autoDestroy: autoDestroy,
    );
    if (encoding != null) {
      r.decoder = _Decoder(encoding);
      r.encoding = r.decoder!.encoding;
    }
  }

  _ReadableState get _rs => _r!;

  /// Node `Readable.from(iterable)`: an Iterable or a Dart Stream (Node's
  /// async iterable). objectMode unless [objectMode] is false.
  static Readable from(Object source, {bool objectMode = true}) {
    if (source is String || source is Uint8List) {
      final r = Readable(objectMode: objectMode, read: (int _) {});
      r.push(source);
      r.push(null);
      return r;
    }
    if (source is Iterable) {
      final it = source.iterator;
      late final Readable r;
      r = Readable(
        objectMode: objectMode,
        read: (int _) {
          while (true) {
            Object? value;
            try {
              if (!it.moveNext()) {
                r.push(null);
                return;
              }
              value = it.current;
            } catch (e) {
              r.destroy(e);
              return;
            }
            if (value == null) {
              r.destroy(
                _err(
                  'ERR_STREAM_NULL_VALUES',
                  'May not write null values to stream',
                ),
              );
              return;
            }
            if (!r.push(value)) return;
          }
        },
      );
      return r;
    }
    if (source is Stream) {
      StreamSubscription<Object?>? sub;
      late final Readable r;
      r = Readable(
        objectMode: objectMode,
        read: (int _) {
          if (sub == null) {
            sub = source.listen(
              (Object? v) {
                if (!r.push(v)) sub!.pause();
              },
              onError: (Object e) => r.destroy(e),
              onDone: () => r.push(null),
            );
          } else {
            sub!.resume();
          }
        },
        destroy: (Object? e, Function cb) {
          final s = sub;
          if (s == null) return applyListener(cb, [e]);
          s.cancel().then((_) => applyListener(cb, [e]));
        },
      );
      return r;
    }
    throw _err(
      'ERR_INVALID_ARG_TYPE',
      'The "iterable" argument must be an instance of Iterable.',
    );
  }

  /// Node `Readable.fromWeb(readableStream)`.
  static Readable fromWeb<T>(
    ReadableStream<T> readableStream, {
    bool objectMode = false,
    int? highWaterMark,
    String? encoding,
  }) {
    final reader = readableStream.getReader();
    var closed = false;
    late final Readable readable;
    readable = Readable(
      objectMode: objectMode,
      highWaterMark: highWaterMark,
      encoding: encoding,
      read: (int _) {
        reader.read().then(
          (chunk) {
            if (chunk.done) {
              // Node learns this from reader.closed.
              closed = true;
              readable.push(null);
            } else {
              final v = chunk.value;
              if (!objectMode && v is! Uint8List) {
                readable.destroy(
                  _err(
                    'ERR_INVALID_ARG_TYPE',
                    'The "chunk" argument must be of type string or an '
                        'instance of Buffer or Uint8Array.',
                  ),
                );
                return;
              }
              readable.push(v);
            }
          },
          onError: (Object error) {
            closed = true;
            readable.destroy(error);
          },
        );
      },
      destroy: (Object? error, Function callback) {
        void done([Object? _]) => applyListener(callback, [error]);
        if (!closed) {
          reader.cancel(error).then(done, onError: done);
          return;
        }
        done();
      },
    );
    return readable;
  }

  /// Node `Readable.toWeb(streamReadable)`.
  static ReadableStream<T> toWeb<T>(Readable streamReadable) {
    if (streamReadable.destroyed || !streamReadable.readable) {
      final s = ReadableStream<T>();
      s.cancel();
      return s;
    }
    final objectMode = streamReadable.readableObjectMode;
    late ReadableStreamDefaultController<T> controller;
    void onData(Object? chunk) {
      controller.enqueue(chunk as T);
      final size = controller.desiredSize;
      if (size != null && size <= 0) streamReadable.pause();
    }

    late final void Function() cleanup;
    void onFinished([Object? error]) {
      cleanup();
      if (error is NodeError && error.code == 'ERR_STREAM_PREMATURE_CLOSE') {
        error = _err('ABORT_ERR', 'The operation was aborted');
      }
      if (error != null) {
        controller.error(error);
        return;
      }
      controller.close();
    }

    streamReadable.on('data', onData);
    cleanup = finished(streamReadable, onFinished);
    assert(objectMode || !objectMode);
    return ReadableStream<T>(
      start: (c) => controller = c,
      pull: (_) => streamReadable.resume(),
      cancel: (reason) => streamReadable.destroy(reason),
    );
  }

  /// Node `_read(size)`. The default calls the `read` option, or throws
  /// ERR_METHOD_NOT_IMPLEMENTED.
  void readImpl(int size) {
    final fn = _readFn;
    if (fn == null) {
      throw _err(
        'ERR_METHOD_NOT_IMPLEMENTED',
        'The _read() method is not implemented',
      );
    }
    applyListener(fn, [size]);
  }

  // -- push / unshift ------------------------------------------------------

  bool push(Object? chunk, [String? encoding]) =>
      _readableAddChunk(chunk, encoding, false);

  bool unshift(Object? chunk, [String? encoding]) =>
      _readableAddChunk(chunk, encoding, true);

  bool _readableAddChunk(Object? chunk, String? encoding, bool addToFront) {
    final state = _rs;
    Object? err;
    if (!state.objectMode && chunk != null) {
      if (chunk is String) {
        encoding ??= 'utf8';
        if (addToFront && state.encoding != null) {
          if (state.encoding != _Decoder._normalize(encoding)) {
            chunk = state.decoder!.write(bufferFromString(chunk, encoding));
          }
        } else {
          chunk = bufferFromString(chunk, encoding);
        }
        encoding = '';
      } else if (chunk is List<int>) {
        chunk = chunk is Uint8List ? chunk : Uint8List.fromList(chunk);
        encoding = '';
      } else {
        err = _err(
          'ERR_INVALID_ARG_TYPE',
          'The "chunk" argument must be of type string or an instance of '
              'Buffer or Uint8Array.',
        );
      }
    }
    if (err != null) {
      _errorOrDestroy(err);
    } else if (chunk == null) {
      state.reading = false;
      _onEofChunk();
    } else if (state.objectMode || _chunkLength(chunk) > 0) {
      if (addToFront) {
        if (state.endEmitted) {
          _errorOrDestroy(
            _err(
              'ERR_STREAM_UNSHIFT_AFTER_END_EVENT',
              'stream.unshift() after end event',
            ),
          );
        } else if (state.destroyed || state.errored != null) {
          return false;
        } else {
          _addChunk(chunk, true);
        }
      } else if (state.ended) {
        _errorOrDestroy(
          _err('ERR_STREAM_PUSH_AFTER_EOF', 'stream.push() after EOF'),
        );
      } else if (state.destroyed || state.errored != null) {
        return false;
      } else {
        state.reading = false;
        if (state.decoder != null && encoding != null && chunk is Uint8List) {
          chunk = state.decoder!.write(chunk);
          if (state.objectMode || _chunkLength(chunk) != 0) {
            _addChunk(chunk, false);
          } else {
            _maybeReadMore();
          }
        } else {
          _addChunk(chunk, false);
        }
      }
    } else if (!addToFront) {
      state.reading = false;
      _maybeReadMore();
    }
    return !state.ended &&
        (state.length < state.highWaterMark || state.length == 0);
  }

  void _addChunk(Object chunk, bool addToFront) {
    final state = _rs;
    if (state.flowing == true &&
        state.length == 0 &&
        !state.sync &&
        listenerCount('data') > 0) {
      if (state.multiAwaitDrain) {
        state.awaitDrainWriters.clear();
      } else {
        state.awaitDrainWriter = null;
      }
      state.dataEmitted = true;
      emit('data', chunk);
    } else {
      state.length += state.objectMode ? 1 : _chunkLength(chunk);
      if (addToFront) {
        state.buffer.insert(0, chunk);
      } else {
        state.buffer.add(chunk);
      }
      if (state.needReadable) _emitReadable();
    }
    _maybeReadMore();
  }

  void _onEofChunk() {
    final state = _rs;
    if (state.ended) return;
    final decoder = state.decoder;
    if (decoder != null) {
      final rest = decoder.end();
      if (rest.isNotEmpty) {
        state.buffer.add(rest);
        state.length += state.objectMode ? 1 : rest.length;
      }
    }
    state.ended = true;
    if (state.sync) {
      _emitReadable();
    } else {
      state.needReadable = false;
      state.emittedReadable = true;
      _emitReadableNow();
    }
  }

  void _emitReadable() {
    final state = _rs;
    state.needReadable = false;
    if (!state.emittedReadable) {
      state.emittedReadable = true;
      _nextTick(_emitReadableNow);
    }
  }

  void _emitReadableNow() {
    final state = _rs;
    if (!state.destroyed &&
        state.errored == null &&
        (state.length > 0 || state.ended)) {
      emit('readable');
      state.emittedReadable = false;
    }
    state.needReadable =
        state.flowing != true &&
        !state.ended &&
        state.length <= state.highWaterMark;
    _flow();
  }

  void _maybeReadMore() {
    final state = _rs;
    if (!state.readingMore) {
      state.readingMore = true;
      _nextTick(() {
        while (!state.reading &&
            !state.ended &&
            (state.length < state.highWaterMark ||
                (state.flowing == true && state.length == 0))) {
          final len = state.length;
          read(0);
          if (len == state.length) break;
        }
        state.readingMore = false;
      });
    }
  }

  // -- read ----------------------------------------------------------------

  int _howMuchToRead(int? n) {
    final state = _rs;
    if ((n != null && n <= 0) || (state.length == 0 && state.ended)) return 0;
    if (state.objectMode) return 1;
    if (n == null) {
      if (state.flowing == true && state.length > 0) {
        return _chunkLength(state.buffer.first);
      }
      return state.length;
    }
    if (n <= state.length) return n;
    return state.ended ? state.length : 0;
  }

  /// Node `readable.read([size])`.
  Object? read([int? n]) {
    final state = _rs;
    if (n != null && n > state.highWaterMark) {
      if (n > 0x40000000) {
        throw _err(
          'ERR_OUT_OF_RANGE',
          'The value of "size" is out of range. It must be <= 1GiB. '
              'Received $n',
        );
      }
      var h = n - 1;
      h |= h >> 1;
      h |= h >> 2;
      h |= h >> 4;
      h |= h >> 8;
      h |= h >> 16;
      state.highWaterMark = h + 1;
    }
    final nOrig = n;
    if (n != 0) state.emittedReadable = false;
    if (n == 0 &&
        state.needReadable &&
        ((state.highWaterMark != 0
                ? state.length >= state.highWaterMark
                : state.length > 0) ||
            state.ended)) {
      if (state.length == 0 && state.ended) {
        _endReadable();
      } else {
        _emitReadable();
      }
      return null;
    }
    var m = _howMuchToRead(n);
    if (m == 0 && state.ended) {
      if (state.length == 0) _endReadable();
      return null;
    }
    var doRead = state.needReadable;
    if (state.length == 0 || state.length - m < state.highWaterMark) {
      doRead = true;
    }
    if (state.ended ||
        state.reading ||
        state.destroyed ||
        state.errored != null) {
      doRead = false;
    } else if (doRead) {
      state.reading = true;
      state.sync = true;
      if (state.length == 0) state.needReadable = true;
      try {
        readImpl(state.highWaterMark);
      } catch (e) {
        _errorOrDestroy(e);
      }
      state.sync = false;
      if (!state.reading) m = _howMuchToRead(nOrig);
    }
    Object? ret = m > 0 ? _fromList(m) : null;
    if (ret == null) {
      state.needReadable = state.length <= state.highWaterMark;
      m = 0;
    } else {
      state.length -= m;
      if (state.multiAwaitDrain) {
        state.awaitDrainWriters.clear();
      } else {
        state.awaitDrainWriter = null;
      }
    }
    if (state.length == 0) {
      if (!state.ended) state.needReadable = true;
      if (nOrig != m && state.ended) _endReadable();
    }
    if (ret != null && !state.errorEmitted && !state.closeEmitted) {
      state.dataEmitted = true;
      emit('data', ret);
    }
    return ret;
  }

  Object? _fromList(int n) {
    final state = _rs;
    final buf = state.buffer;
    if (buf.isEmpty) return null;
    if (state.objectMode) return buf.removeAt(0);
    if (n >= state.length) {
      Object ret;
      if (state.decoder != null) {
        ret = buf.map((c) => c as String).join();
      } else if (buf.length == 1) {
        ret = buf.first;
      } else {
        final b = BytesBuilder(copy: false);
        for (final c in buf) {
          b.add(c as Uint8List);
        }
        ret = b.takeBytes();
      }
      buf.clear();
      return ret;
    }
    if (state.decoder != null) {
      final sb = StringBuffer();
      var left = n;
      while (left > 0) {
        final s = buf.first as String;
        if (s.length <= left) {
          sb.write(s);
          left -= s.length;
          buf.removeAt(0);
        } else {
          sb.write(s.substring(0, left));
          buf[0] = s.substring(left);
          left = 0;
        }
      }
      return sb.toString();
    }
    final out = BytesBuilder(copy: false);
    var left = n;
    while (left > 0) {
      final b = buf.first as Uint8List;
      if (b.length <= left) {
        out.add(b);
        left -= b.length;
        buf.removeAt(0);
      } else {
        out.add(Uint8List.sublistView(b, 0, left));
        buf[0] = Uint8List.sublistView(b, left);
        left = 0;
      }
    }
    return out.takeBytes();
  }

  void _endReadable() {
    final state = _rs;
    if (!state.endEmitted) {
      state.ended = true;
      _nextTick(_endReadableNT);
    }
  }

  void _endReadableNT() {
    final state = _rs;
    if (state.errored == null &&
        !state.closeEmitted &&
        !state.endEmitted &&
        state.length == 0) {
      state.endEmitted = true;
      emit('end');
      final w = _w;
      if (w != null && _writableNow && this is Duplex) {
        if (!(this as Duplex).allowHalfOpen) {
          _nextTick(() {
            final d = this as Duplex;
            if (d.writable && !d.writableEnded && !d.destroyed) d.end();
          });
          return;
        }
      }
      if (state.autoDestroy) {
        final auto =
            w == null || (w.autoDestroy && (w.finished || w.writable == false));
        if (auto) destroy();
      }
    }
  }

  bool get _writableNow {
    final w = _w;
    return w != null &&
        w.writable &&
        !w.destroyed &&
        w.errored == null &&
        !w.ending &&
        !w.ended;
  }

  // -- events, flow --------------------------------------------------------

  @override
  Readable on(String event, Function listener) {
    super.on(event, listener);
    _onListener(event);
    return this;
  }

  @override
  Readable addListener(String event, Function listener) => on(event, listener);

  @override
  Readable once(String event, Function listener) {
    super.once(event, listener);
    _onListener(event);
    return this;
  }

  @override
  Readable prependListener(String event, Function listener) {
    super.prependListener(event, listener);
    _onListener(event);
    return this;
  }

  void _onListener(String ev) {
    final state = _rs;
    if (ev == 'data') {
      state.readableListening = listenerCount('readable') > 0;
      if (state.flowing != false) resume();
    } else if (ev == 'readable') {
      if (!state.endEmitted && !state.readableListening) {
        state.readableListening = state.needReadable = true;
        state.flowing = false;
        state.emittedReadable = false;
        if (state.length > 0) {
          _emitReadable();
        } else if (!state.reading) {
          _nextTick(() => read(0));
        }
      }
    }
  }

  @override
  Readable off(String event, Function listener) {
    super.off(event, listener);
    if (event == 'readable') _nextTick(_updateReadableListening);
    return this;
  }

  @override
  Readable removeListener(String event, Function listener) =>
      off(event, listener);

  @override
  Readable removeAllListeners([String? event]) {
    super.removeAllListeners(event);
    if (event == 'readable' || event == null) {
      _nextTick(_updateReadableListening);
    }
    return this;
  }

  /// A `once('readable')` listener is dropped inside [emit], which must
  /// update the flow state as Node's removeListener hook does.
  @override
  bool emit(String event, [Object? a, Object? b, Object? c, Object? d]) {
    final before = event == 'readable' ? listenerCount('readable') : 0;
    final result = super.emit(event, a, b, c, d);
    if (before > 0 && _r != null && listenerCount('readable') == 0) {
      _nextTick(_updateReadableListening);
    }
    return result;
  }

  void _updateReadableListening() {
    final state = _rs;
    state.readableListening = listenerCount('readable') > 0;
    if (state.resumeScheduled && state.paused == false) {
      state.flowing = true;
    } else if (listenerCount('data') > 0) {
      resume();
    } else if (!state.readableListening) {
      state.flowing = null;
    }
  }

  /// Node `readable.resume()`.
  Readable resume() {
    final state = _rs;
    if (state.flowing != true) {
      state.flowing = !state.readableListening;
      if (!state.resumeScheduled) {
        state.resumeScheduled = true;
        _nextTick(_resumeNow);
      }
    }
    state.paused = false;
    return this;
  }

  void _resumeNow() {
    final state = _rs;
    if (!state.reading) read(0);
    state.resumeScheduled = false;
    emit('resume');
    _flow();
    if (state.flowing == true && !state.reading) read(0);
  }

  /// Node `readable.pause()`.
  Readable pause() {
    final state = _rs;
    if (state.flowing != false) {
      state.flowing = false;
      emit('pause');
    }
    state.paused = true;
    return this;
  }

  bool isPaused() => _rs.paused == true || _rs.flowing == false;

  void _flow() {
    final state = _rs;
    while (state.flowing == true && read() != null) {}
  }

  /// Node `readable.setEncoding(encoding)`.
  Readable setEncoding(String encoding) {
    final state = _rs;
    final decoder = _Decoder(encoding);
    state.decoder = decoder;
    state.encoding = decoder.encoding;
    final sb = StringBuffer();
    for (final c in state.buffer) {
      sb.write(c is String ? c : decoder.write(c as Uint8List));
    }
    state.buffer.clear();
    final s = sb.toString();
    if (s.isNotEmpty) state.buffer.add(s);
    state.length = s.length;
    return this;
  }

  // -- pipe ----------------------------------------------------------------

  /// Node `readable.pipe(destination[, {end}])`.
  T pipe<T extends EventEmitter>(T destination, {bool end = true}) {
    final src = this;
    final dynamic dest = destination;
    final NodeStream? destStream = destination is NodeStream
        ? destination
        : null;
    final state = _rs;
    if (state.pipes.length == 1 && !state.multiAwaitDrain) {
      state.multiAwaitDrain = true;
      if (state.awaitDrainWriter != null) {
        state.awaitDrainWriters.add(state.awaitDrainWriter!);
      }
      state.awaitDrainWriter = null;
    }
    state.pipes.add(destination);
    final doEnd = end;
    Function? ondrain;
    var cleanedUp = false;
    late void Function() cleanup;
    late void Function() unpipe;
    late void Function() onclose;
    late void Function() onfinish;
    late void Function(Object?) onerror;

    void onend() => dest.end();
    void onunpipe(Object? readable, [Object? info]) {
      if (identical(readable, src) &&
          !(info is Map && info['hasUnpiped'] == true)) {
        if (info is Map) info['hasUnpiped'] = true;
        cleanup();
      }
    }

    void pauseSrc() {
      if (!cleanedUp) {
        if (state.pipes.length == 1 && identical(state.pipes[0], destination)) {
          state.awaitDrainWriter = destination;
          state.multiAwaitDrain = false;
        } else if (state.pipes.length > 1 &&
            state.pipes.contains(destination)) {
          state.awaitDrainWriters.add(destination);
        }
        src.pause();
      }
      if (ondrain == null) {
        ondrain = () {
          if (identical(state.awaitDrainWriter, dest)) {
            state.awaitDrainWriter = null;
          } else if (state.multiAwaitDrain) {
            state.awaitDrainWriters.remove(dest);
          }
          if ((state.awaitDrainWriter == null &&
                  state.awaitDrainWriters.isEmpty) &&
              src.listenerCount('data') > 0) {
            src.resume();
          }
        };
        dest.on('drain', ondrain!);
      }
    }

    void ondata(Object? chunk) {
      final ret = dest.write(chunk!);
      if (ret == false) pauseSrc();
    }

    unpipe = () => src.unpipe(destination);
    onerror = (Object? er) {
      unpipe();
      dest.removeListener('error', onerror);
      if (dest.listenerCount('error') == 0) {
        final s = destStream?._w ?? destStream?._r;
        if (s != null &&
            !(s is _WritableState ? s.errorEmitted : false) &&
            !(destStream?._r?.errorEmitted ?? false)) {
          destStream!._errorOrDestroy(er!);
        } else {
          dest.emit('error', er);
        }
      }
    };
    onclose = () {
      dest.removeListener('finish', onfinish);
      unpipe();
    };
    onfinish = () {
      dest.removeListener('close', onclose);
      unpipe();
    };
    final endFn = doEnd ? onend : unpipe;
    cleanup = () {
      dest.removeListener('close', onclose);
      dest.removeListener('finish', onfinish);
      if (ondrain != null) dest.removeListener('drain', ondrain!);
      dest.removeListener('error', onerror);
      dest.removeListener('unpipe', onunpipe);
      src.removeListener('end', onend);
      src.removeListener('end', unpipe);
      src.removeListener('data', ondata);
      cleanedUp = true;
      if (ondrain != null &&
          (state.awaitDrainWriter != null ||
              state.awaitDrainWriters.isNotEmpty) &&
          (destStream?._w?.needDrain ?? false)) {
        (ondrain as void Function())();
      }
    };

    dest.on('unpipe', onunpipe);
    src.on('data', ondata);
    dest.prependListener('error', onerror);
    dest.once('close', onclose);
    dest.once('finish', onfinish);
    dest.emit('pipe', src);
    if (dest.writableNeedDrain == true) {
      pauseSrc();
    } else if (state.flowing != true) {
      src.resume();
    }
    if (state.endEmitted) {
      _nextTick(endFn);
    } else {
      src.once('end', endFn);
    }
    return destination;
  }

  /// Node `readable.unpipe([destination])`.
  Readable unpipe([EventEmitter? dest]) {
    final state = _rs;
    if (state.pipes.isEmpty) return this;
    if (dest == null) {
      final dests = List<EventEmitter>.of(state.pipes);
      state.pipes.clear();
      pause();
      for (final d in dests) {
        d.emit('unpipe', this, {'hasUnpiped': false});
      }
      return this;
    }
    final index = state.pipes.indexOf(dest);
    if (index == -1) return this;
    state.pipes.removeAt(index);
    if (state.pipes.isEmpty) pause();
    dest.emit('unpipe', this, {'hasUnpiped': false});
    return this;
  }

  @override
  Readable destroy([Object? error, Function? callback]) {
    super.destroy(error, callback);
    return this;
  }

  /// Shim-internal (no Node counterpart): remove and return every byte
  /// waiting in the readable buffer, emitting nothing. A TLS socket taking a
  /// connection over uses it to start its handshake with them.
  Uint8List takeBufferedBytes() {
    final state = _rs;
    final b = BytesBuilder(copy: false);
    for (final c in state.buffer) {
      b.add(c is String ? bufferFromString(c, state.encoding) : c as List<int>);
    }
    state.buffer.clear();
    state.length = 0;
    return b.takeBytes();
  }

  // -- getters -------------------------------------------------------------

  /// Node `readable.readable`.
  bool get readable {
    final r = _rs;
    return r.readable && !r.destroyed && !r.errorEmitted && !r.endEmitted;
  }

  bool get readableEnded => _rs.endEmitted;
  bool? get readableFlowing => _rs.flowing;
  int get readableLength => _rs.length;
  int get readableHighWaterMark => _rs.highWaterMark;
  bool get readableObjectMode => _rs.objectMode;
  String? get readableEncoding => _rs.encoding;
  bool get readableDidRead => _rs.dataEmitted;
}

// ---------------------------------------------------------------------------
// Writable (Node writable.js).

mixin _WritableImpl on NodeStream {
  Function? _writeFn, _writevFn, _finalFn;

  void _initWritable({
    int? highWaterMark,
    bool objectMode = false,
    bool decodeStrings = true,
    String? defaultEncoding,
    bool emitClose = true,
    bool autoDestroy = true,
  }) {
    _w = _WritableState(
      objectMode: objectMode,
      highWaterMark:
          highWaterMark ?? (objectMode ? _defaultObjectHwm : _defaultHwm),
      emitClose: emitClose,
      autoDestroy: autoDestroy,
      decodeStrings: decodeStrings,
    );
    if (defaultEncoding != null) _w!.defaultEncoding = defaultEncoding;
  }

  _WritableState get _ws => _w!;

  /// Node `_write(chunk, encoding, callback)`.
  void writeImpl(Object chunk, String encoding, Function callback) {
    final fn = _writeFn;
    if (fn != null) {
      Function.apply(fn, [chunk, encoding, callback]);
    } else if (_writevFn != null) {
      writevImpl([(chunk: chunk, encoding: encoding)], callback);
    } else {
      throw _err(
        'ERR_METHOD_NOT_IMPLEMENTED',
        'The _write() method is not implemented',
      );
    }
  }

  /// Node `_writev(chunks, callback)`, when [hasWritevImpl].
  void writevImpl(
    List<({Object chunk, String encoding})> chunks,
    Function callback,
  ) {
    final fn = _writevFn;
    if (fn == null) {
      throw _err(
        'ERR_METHOD_NOT_IMPLEMENTED',
        'The _writev() method is not implemented',
      );
    }
    Function.apply(fn, [chunks, callback]);
  }

  bool get hasWritevImpl => _writevFn != null;

  /// Node `_final(callback)`, when [hasFinalImpl].
  void finalImpl(Function callback) {
    Function.apply(_finalFn!, [callback]);
  }

  bool get hasFinalImpl => _finalFn != null;

  /// Dart-only test seam for spyOn(stream, 'write' | 'end'); call-through.
  void Function(String method, List<Object?> args)? callObserver;

  /// Node `writable.write(chunk[, encoding][, callback])`.
  bool write(Object chunk, [Object? encoding, Function? callback]) {
    callObserver?.call('write', [chunk, encoding, callback]);
    final r = _write(chunk, encoding, callback);
    return r is bool ? r : false;
  }

  Object _write(Object? chunk, Object? encodingArg, Function? cb) {
    final state = _ws;
    String? encoding;
    if (encodingArg is Function) {
      cb = encodingArg;
      encoding = state.defaultEncoding;
    } else {
      encoding = (encodingArg as String?) ?? state.defaultEncoding;
      if (encoding == 'buffer') encoding = state.defaultEncoding;
    }
    if (chunk == null) {
      throw _err(
        'ERR_STREAM_NULL_VALUES',
        'May not write null values to stream',
      );
    }
    if (!state.objectMode) {
      if (chunk is String) {
        if (state.decodeStrings) {
          chunk = bufferFromString(chunk, encoding);
          encoding = 'buffer';
        }
      } else if (chunk is List<int>) {
        chunk = chunk is Uint8List ? chunk : Uint8List.fromList(chunk);
        encoding = 'buffer';
      } else {
        throw _err(
          'ERR_INVALID_ARG_TYPE',
          'The "chunk" argument must be of type string or an instance of '
              'Buffer or Uint8Array.',
        );
      }
    }
    NodeError? err;
    if (state.ending) {
      err = _err('ERR_STREAM_WRITE_AFTER_END', 'write after end');
    } else if (state.destroyed) {
      err = _destroyedError('write');
    }
    if (err != null) {
      final e = err;
      if (cb != null) _nextTick(() => applyListener(cb!, [e]));
      _errorOrDestroy(e, true);
      return e;
    }
    state.pendingcb++;
    return _writeOrBuffer(chunk, encoding, cb);
  }

  bool _writeOrBuffer(Object chunk, String encoding, Function? callback) {
    final state = _ws;
    final len = state.objectMode ? 1 : _chunkLength(chunk);
    state.length += len;
    final ret = state.length < state.highWaterMark;
    if (!ret) state.needDrain = true;
    if (state.writing || state.corked > 0 || state.errored != null) {
      state.buffered.add((
        chunk: chunk,
        encoding: encoding,
        callback: callback,
      ));
    } else {
      state.writelen = len;
      state.writecb = callback ?? _nop;
      state.writing = true;
      state.sync = true;
      writeImpl(chunk, encoding, _onwrite);
      state.sync = false;
    }
    return ret && state.errored == null && !state.destroyed;
  }

  static void _nop([Object? _]) {}

  void _doWrite(
    bool writev,
    int len,
    Object chunk,
    String encoding,
    Function cb,
  ) {
    final state = _ws;
    state.writelen = len;
    state.writecb = cb;
    state.writing = true;
    state.sync = true;
    if (state.destroyed) {
      _onwrite(_destroyedError('write'));
    } else if (writev) {
      writevImpl(chunk as List<({Object chunk, String encoding})>, _onwrite);
    } else {
      writeImpl(chunk, encoding, _onwrite);
    }
    state.sync = false;
  }

  void _onwrite([Object? er]) {
    final state = _ws;
    final sync = state.sync;
    final cb = state.writecb;
    if (cb == null) {
      _errorOrDestroy(
        _err('ERR_MULTIPLE_CALLBACK', 'Callback called multiple times'),
      );
      return;
    }
    state.writing = false;
    state.writecb = null;
    state.length -= state.writelen;
    state.writelen = 0;
    if (er != null) {
      state.errored ??= er;
      final r = _r;
      if (r != null && r.errored == null) r.errored = er;
      void onwriteError() {
        --state.pendingcb;
        applyListener(cb, [er]);
        _errorBuffer();
        _errorOrDestroy(er);
      }

      if (sync) {
        _nextTick(onwriteError);
      } else {
        onwriteError();
      }
    } else {
      if (state.buffered.length > state.bufferedIndex) _clearBuffer();
      if (sync) {
        _nextTick(() => _afterWrite(cb));
      } else {
        _afterWrite(cb);
      }
    }
  }

  void _afterWrite(Function cb) {
    final state = _ws;
    final needDrain =
        !state.ending && !destroyed && state.length == 0 && state.needDrain;
    if (needDrain) {
      state.needDrain = false;
      emit('drain');
    }
    state.pendingcb--;
    applyListener(cb, const []);
    if (state.destroyed) _errorBuffer();
    _finishMaybe(false);
  }

  void _errorBuffer() {
    final state = _ws;
    if (state.writing) return;
    for (var n = state.bufferedIndex; n < state.buffered.length; ++n) {
      final b = state.buffered[n];
      final len = state.objectMode ? 1 : _chunkLength(b.chunk);
      state.length -= len;
      final cb = b.callback;
      if (cb != null) {
        applyListener(cb, [state.errored ?? _destroyedError('write')]);
      }
    }
    for (final cb in List<Function>.of(state.finishCallbacks)) {
      applyListener(cb, [state.errored ?? _destroyedError('end')]);
    }
    state.finishCallbacks.clear();
    state.buffered.clear();
    state.bufferedIndex = 0;
  }

  void _clearBuffer() {
    final state = _ws;
    if (state.corked > 0 || state.bufferProcessing || state.destroyed) {
      return;
    }
    final buffered = state.buffered;
    final bufferedLength = buffered.length - state.bufferedIndex;
    if (bufferedLength == 0) return;
    var i = state.bufferedIndex;
    state.bufferProcessing = true;
    if (bufferedLength > 1 && hasWritevImpl) {
      state.pendingcb -= bufferedLength - 1;
      final items = buffered.sublist(i);
      void callback([Object? err]) {
        for (final it in items) {
          if (it.callback != null) applyListener(it.callback!, [err]);
        }
      }

      final chunks = [
        for (final it in items) (chunk: it.chunk, encoding: it.encoding),
      ];
      buffered.clear();
      state.bufferedIndex = 0;
      _doWrite(true, state.length, chunks, '', callback);
    } else {
      do {
        final b = buffered[i++];
        final len = state.objectMode ? 1 : _chunkLength(b.chunk);
        _doWrite(false, len, b.chunk, b.encoding, b.callback ?? _nop);
      } while (i < buffered.length && !state.writing);
      if (i == buffered.length) {
        buffered.clear();
        state.bufferedIndex = 0;
      } else {
        state.bufferedIndex = i;
      }
    }
    state.bufferProcessing = false;
  }

  /// Node `writable.cork()`.
  void cork() => _ws.corked++;

  /// Node `writable.uncork()`.
  void uncork() {
    final state = _ws;
    if (state.corked > 0) {
      state.corked--;
      if (!state.writing) _clearBuffer();
    }
  }

  /// Node `writable.setDefaultEncoding(encoding)`.
  void setDefaultEncoding(String encoding) {
    bufferFromString('', encoding);
    _ws.defaultEncoding = encoding.toLowerCase();
  }

  /// Node `writable.end([chunk][, encoding][, callback])`.
  NodeStream end([Object? chunk, Object? encoding, Function? cb]) {
    callObserver?.call('end', [chunk, encoding, cb]);
    final state = _ws;
    if (chunk is Function) {
      cb = chunk;
      chunk = null;
      encoding = null;
    } else if (encoding is Function) {
      cb = encoding;
      encoding = null;
    }
    Object? err;
    if (chunk != null) {
      final ret = _write(chunk, encoding, null);
      if (ret is NodeError) err = ret;
    }
    if (state.corked > 0) {
      state.corked = 1;
      uncork();
    }
    if (err != null) {
      // Nothing more.
    } else if (state.errored == null && !state.ending) {
      state.ending = true;
      _finishMaybe(true);
      state.ended = true;
    } else if (state.finished) {
      err = _err(
        'ERR_STREAM_ALREADY_FINISHED',
        'Cannot call end after a stream was finished',
      );
    } else if (state.destroyed) {
      err = _destroyedError('end');
    }
    if (cb != null) {
      final c = cb;
      if (err != null) {
        final e = err;
        _nextTick(() => applyListener(c, [e]));
      } else if (state.finished) {
        _nextTick(() => applyListener(c, const []));
      } else {
        state.finishCallbacks.add(c);
      }
    }
    return this;
  }

  bool _needFinish() {
    final state = _ws;
    return state.ending &&
        !state.destroyed &&
        state.length == 0 &&
        state.errored == null &&
        state.buffered.length == state.bufferedIndex &&
        !state.finished &&
        !state.writing &&
        !state.errorEmitted &&
        !state.closeEmitted;
  }

  void _callFinal() {
    final state = _ws;
    var called = false;
    void onFinish([Object? err]) {
      if (called) {
        _errorOrDestroy(
          _err('ERR_MULTIPLE_CALLBACK', 'Callback called multiple times'),
        );
        return;
      }
      called = true;
      state.pendingcb--;
      if (err != null) {
        for (final cb in List<Function>.of(state.finishCallbacks)) {
          applyListener(cb, [err]);
        }
        state.finishCallbacks.clear();
        _errorOrDestroy(err, state.sync);
      } else if (_needFinish()) {
        state.prefinished = true;
        emit('prefinish');
        state.pendingcb++;
        _nextTick(_finish);
      }
    }

    state.sync = true;
    state.pendingcb++;
    try {
      finalImpl(onFinish);
    } catch (e) {
      onFinish(e);
    }
    state.sync = false;
  }

  void _prefinish() {
    final state = _ws;
    if (!state.prefinished && !state.finalCalled) {
      if (hasFinalImpl && !state.destroyed) {
        state.finalCalled = true;
        _callFinal();
      } else {
        state.prefinished = true;
        emit('prefinish');
      }
    }
  }

  void _finishMaybe(bool sync) {
    final state = _ws;
    if (_needFinish()) {
      _prefinish();
      if (state.pendingcb == 0) {
        if (sync) {
          state.pendingcb++;
          _nextTick(() {
            if (_needFinish()) {
              _finish();
            } else {
              state.pendingcb--;
            }
          });
        } else if (_needFinish()) {
          state.pendingcb++;
          _finish();
        }
      }
    }
  }

  void _finish() {
    final state = _ws;
    state.pendingcb--;
    state.finished = true;
    final cbs = List<Function>.of(state.finishCallbacks);
    state.finishCallbacks.clear();
    for (final cb in cbs) {
      applyListener(cb, const []);
    }
    emit('finish');
    if (state.autoDestroy) {
      final r = _r;
      final auto =
          r == null || (r.autoDestroy && (r.endEmitted || r.readable == false));
      if (auto) destroy();
    }
  }

  /// Node `writable.writable`.
  bool get writable {
    final w = _ws;
    return w.writable &&
        !w.destroyed &&
        w.errored == null &&
        !w.ending &&
        !w.ended;
  }

  bool get writableEnded => _ws.ending;
  bool get writableFinished => _ws.finished;
  int get writableLength => _ws.length;
  int get writableHighWaterMark => _ws.highWaterMark;
  bool get writableObjectMode => _ws.objectMode;
  int get writableCorked => _ws.corked;
  bool get writableNeedDrain {
    final w = _w;
    if (w == null) return false;
    return !w.destroyed && !w.ending && w.needDrain;
  }
}

/// Node's `Writable` stream.
class Writable extends NodeStream with _WritableImpl {
  Writable({
    int? highWaterMark,
    bool objectMode = false,
    bool decodeStrings = true,
    String? defaultEncoding,
    bool emitClose = true,
    bool autoDestroy = true,
    Function? write,
    Function? writev,
    Function? finalCallback,
    Function? destroy,
  }) {
    _writeFn = write;
    _writevFn = writev;
    _finalFn = finalCallback;
    _destroyFn = destroy;
    _initWritable(
      highWaterMark: highWaterMark,
      objectMode: objectMode,
      decodeStrings: decodeStrings,
      defaultEncoding: defaultEncoding,
      emitClose: emitClose,
      autoDestroy: autoDestroy,
    );
  }

  @override
  Writable on(String event, Function listener) {
    super.on(event, listener);
    return this;
  }

  @override
  Writable once(String event, Function listener) {
    super.once(event, listener);
    return this;
  }

  @override
  Writable off(String event, Function listener) {
    super.off(event, listener);
    return this;
  }

  @override
  Writable removeListener(String event, Function listener) =>
      off(event, listener);

  @override
  Writable end([Object? chunk, Object? encoding, Function? cb]) {
    super.end(chunk, encoding, cb);
    return this;
  }

  @override
  Writable destroy([Object? error, Function? callback]) {
    super.destroy(error, callback);
    return this;
  }
}

/// Node's duplex stream: a readable stream that is also writable.
class Duplex extends Readable with _WritableImpl implements Writable {
  Duplex({
    int? highWaterMark,
    int? readableHighWaterMark,
    int? writableHighWaterMark,
    bool objectMode = false,
    bool readableObjectMode = false,
    bool writableObjectMode = false,
    this.allowHalfOpen = true,
    bool readable = true,
    bool writable = true,
    bool decodeStrings = true,
    super.encoding,
    String? defaultEncoding,
    bool emitClose = true,
    bool autoDestroy = true,
    super.read,
    Function? write,
    Function? writev,
    Function? finalCallback,
    super.destroy,
  }) : super(
         highWaterMark: readableHighWaterMark ?? highWaterMark,
         objectMode: objectMode || readableObjectMode,
         emitClose: emitClose,
         autoDestroy: autoDestroy,
       ) {
    _writeFn = write;
    _writevFn = writev;
    _finalFn = finalCallback;
    _initWritable(
      highWaterMark: writableHighWaterMark ?? highWaterMark,
      objectMode: objectMode || writableObjectMode,
      decodeStrings: decodeStrings,
      defaultEncoding: defaultEncoding,
      emitClose: emitClose,
      autoDestroy: autoDestroy,
    );
    if (!readable) {
      _rs
        ..readable = false
        ..ended = true
        ..endEmitted = true;
    }
    if (!writable) {
      _ws
        ..writable = false
        ..ending = true
        ..ended = true
        ..finished = true;
    }
  }

  /// Node `duplex.allowHalfOpen`: when false, the writable side ends when
  /// the readable side does.
  bool allowHalfOpen;

  @override
  Duplex on(String event, Function listener) {
    super.on(event, listener);
    return this;
  }

  @override
  Duplex addListener(String event, Function listener) => on(event, listener);

  @override
  Duplex once(String event, Function listener) {
    super.once(event, listener);
    return this;
  }

  @override
  Duplex prependListener(String event, Function listener) {
    super.prependListener(event, listener);
    return this;
  }

  @override
  Duplex off(String event, Function listener) {
    super.off(event, listener);
    return this;
  }

  @override
  Duplex removeListener(String event, Function listener) =>
      off(event, listener);

  @override
  Duplex removeAllListeners([String? event]) {
    super.removeAllListeners(event);
    return this;
  }

  @override
  Duplex end([Object? chunk, Object? encoding, Function? cb]) {
    super.end(chunk, encoding, cb);
    return this;
  }

  @override
  Duplex destroy([Object? error, Function? callback]) {
    super.destroy(error, callback);
    return this;
  }

  @override
  Duplex pause() {
    super.pause();
    return this;
  }

  @override
  Duplex resume() {
    super.resume();
    return this;
  }

  @override
  Duplex unpipe([EventEmitter? dest]) {
    super.unpipe(dest);
    return this;
  }

  @override
  Duplex setEncoding(String encoding) {
    super.setEncoding(encoding);
    return this;
  }
}

/// Node's transform stream, a duplex stream with a transform callback.
class Transform extends Duplex {
  Transform({
    super.highWaterMark,
    super.readableHighWaterMark,
    super.writableHighWaterMark,
    super.objectMode,
    super.readableObjectMode,
    super.writableObjectMode,
    super.allowHalfOpen,
    super.decodeStrings,
    super.encoding,
    super.defaultEncoding,
    super.emitClose,
    super.autoDestroy,
    super.read,
    super.write,
    super.writev,
    super.finalCallback,
    Function? transform,
    Function? flush,
    super.destroy,
  }) : _transformFn = transform,
       _flushFn = flush {
    _rs.sync = false;
    if (_finalFn != null) {
      on('prefinish', _transformFinal);
    }
  }

  final Function? _transformFn, _flushFn;
  Function? _kCallback;

  /// Node `_transform(chunk, encoding, callback)`.
  void transformImpl(Object chunk, String encoding, Function callback) {
    final fn = _transformFn;
    if (fn == null) {
      throw _err(
        'ERR_METHOD_NOT_IMPLEMENTED',
        'The _transform() method is not implemented',
      );
    }
    Function.apply(fn, [chunk, encoding, callback]);
  }

  /// Node `_flush(callback)`, when [hasFlushImpl].
  void flushImpl(Function callback) => Function.apply(_flushFn!, [callback]);

  bool get hasFlushImpl => _flushFn != null;

  // Node's `final`: the default `_final`, also run on 'prefinish' when a
  // `final` option replaced it.
  void _transformFinal([Function? cb]) {
    if (hasFlushImpl && !destroyed) {
      flushImpl(([Object? er, Object? data]) {
        if (er != null) {
          if (cb != null) {
            applyListener(cb, [er]);
          } else {
            destroy(er);
          }
          return;
        }
        if (data != null) push(data);
        push(null);
        if (cb != null) applyListener(cb, const []);
      });
    } else {
      push(null);
      if (cb != null) applyListener(cb, const []);
    }
  }

  @override
  bool get hasFinalImpl => true;

  @override
  void finalImpl(Function callback) {
    if (_finalFn != null) {
      super.finalImpl(callback);
    } else {
      _transformFinal(callback);
    }
  }

  @override
  void writeImpl(Object chunk, String encoding, Function callback) {
    if (_writeFn != null) return super.writeImpl(chunk, encoding, callback);
    final rState = _rs;
    final wState = _ws;
    final length = rState.length;
    transformImpl(chunk, encoding, ([Object? err, Object? val]) {
      if (err != null) {
        applyListener(callback, [err]);
        return;
      }
      if (val != null) push(val);
      if (rState.ended) {
        _nextTick(() => applyListener(callback, const []));
      } else if (wState.ended ||
          length == rState.length ||
          rState.length < rState.highWaterMark) {
        applyListener(callback, const []);
      } else {
        _kCallback = callback;
      }
    });
  }

  @override
  void readImpl(int size) {
    if (_readFn != null) return super.readImpl(size);
    final callback = _kCallback;
    if (callback != null) {
      _kCallback = null;
      applyListener(callback, const []);
    }
  }
}

/// Node's pass-through transform stream.
class PassThrough extends Transform {
  PassThrough({
    super.highWaterMark,
    super.objectMode,
    super.allowHalfOpen,
    super.encoding,
    super.emitClose,
    super.autoDestroy,
    super.destroy,
  });

  @override
  void transformImpl(Object chunk, String encoding, Function callback) =>
      applyListener(callback, [null, chunk]);
}

// ---------------------------------------------------------------------------
// finished / pipeline (end-of-stream.js, pipeline.js).

bool _isReadableNode(NodeStream s) =>
    s is Readable && (s._w == null || s._r!.readable != false);
bool _isWritableNode(NodeStream s) =>
    s is _WritableImpl && (s._r == null || s._w!.writable != false);

bool _isReadableFinished(NodeStream s, bool strict) {
  final r = s._r;
  if (r == null) return false;
  return r.endEmitted || (!strict && r.ended && r.length == 0);
}

bool _isWritableFinished(NodeStream s, bool strict) {
  final w = s._w;
  if (w == null) return false;
  return w.finished || (!strict && w.ended && w.length == 0);
}

bool? _isReadable(NodeStream s) {
  if (s is! Readable) return null;
  if (s.destroyed) return false;
  return _isReadableNode(s) && s.readable && !_isReadableFinished(s, true);
}

bool? _isWritable(NodeStream s) {
  if (s is! _WritableImpl) return null;
  if (s.destroyed) return false;
  final w = s;
  return _isWritableNode(s) && w.writable && !w._ws.ended;
}

bool _willEmitClose(NodeStream s) {
  final st = s._w ?? s._r;
  if (st == null) return false;
  final (auto, emitClose, closed) = st is _WritableState
      ? (st.autoDestroy, st.emitClose, st.closed)
      : ((st as _ReadableState).autoDestroy, st.emitClose, st.closed);
  return auto && emitClose && !closed;
}

/// Node `stream.finished(stream[, options], callback)`. Returns the cleanup
/// function. [callback] gets the error, or nothing.
void Function() finished(
  NodeStream stream, [
  Object? optionsOrCallback,
  Function? callbackArg,
]) {
  Map<Object?, Object?> options = const {};
  Function cb;
  if (optionsOrCallback is Function) {
    cb = optionsOrCallback;
  } else {
    options = (optionsOrCallback as Map?) ?? const {};
    cb = callbackArg!;
  }
  var called = false;
  void callback([Object? err]) {
    if (called) return;
    called = true;
    applyListener(cb, [err]);
  }

  final readable = (options['readable'] as bool?) ?? _isReadableNode(stream);
  final writable = (options['writable'] as bool?) ?? _isWritableNode(stream);
  final wState = stream._w, rState = stream._r;
  var willEmitClose =
      _willEmitClose(stream) &&
      _isReadableNode(stream) == readable &&
      _isWritableNode(stream) == writable;
  var writableFinished = _isWritableFinished(stream, false);
  var readableFinished = _isReadableFinished(stream, false);

  void onfinish() {
    writableFinished = true;
    if (stream.destroyed) willEmitClose = false;
    if (willEmitClose &&
        (!(stream is Readable && stream.readable) || readable)) {
      return;
    }
    if (!readable || readableFinished) callback();
  }

  void onend() {
    readableFinished = true;
    if (stream.destroyed) willEmitClose = false;
    if (willEmitClose &&
        (!(stream is _WritableImpl && stream.writable) || writable)) {
      return;
    }
    if (!writable || writableFinished) callback();
  }

  void onerror(Object? err) => callback(err);

  Object? erroredOf() => wState?.errored ?? rState?.errored;

  void onclose() {
    final errored = erroredOf();
    if (errored != null) return callback(errored);
    if (readable && !readableFinished && _isReadableNode(stream)) {
      if (!_isReadableFinished(stream, false)) {
        return callback(_prematureClose());
      }
    }
    if (writable && !writableFinished) {
      if (!_isWritableFinished(stream, false)) {
        return callback(_prematureClose());
      }
    }
    callback();
  }

  void onclosed() {
    final errored = erroredOf();
    if (errored != null) return callback(errored);
    callback();
  }

  stream.on('end', onend);
  stream.on('finish', onfinish);
  if (options['error'] != false) stream.on('error', onerror);
  stream.on('close', onclose);

  if (stream.closed) {
    _nextTick(onclose);
  } else if ((wState?.errorEmitted ?? false) ||
      (rState?.errorEmitted ?? false)) {
    if (!willEmitClose) _nextTick(onclosed);
  } else if (!readable &&
      (!willEmitClose || (_isReadable(stream) ?? false)) &&
      (writableFinished || _isWritable(stream) == false)) {
    _nextTick(onclosed);
  } else if (!writable &&
      (!willEmitClose || (_isWritable(stream) ?? false)) &&
      (readableFinished || _isReadable(stream) == false)) {
    _nextTick(onclosed);
  }

  return () {
    called = true;
    stream.removeListener('end', onend);
    stream.removeListener('finish', onfinish);
    stream.removeListener('error', onerror);
    stream.removeListener('close', onclose);
  };
}

/// Node `stream.pipeline(...streams, callback)`, for Node streams: pipes
/// each stream into the next, destroys all of them on an error, and calls
/// [callback] once with the first error (or nothing). Returns the last.
NodeStream pipeline(List<NodeStream> streams, Function callback) {
  if (streams.length < 2) {
    throw _err('ERR_MISSING_ARGS', 'The "streams" argument must be specified');
  }
  Object? error;
  final destroys = <void Function(Object?)>[];
  var finishCount = 0;
  var done = false;

  void finishImpl(Object? err, bool last) {
    if (err != null &&
        (error == null ||
            (error is NodeError &&
                (error as NodeError).code == 'ERR_STREAM_PREMATURE_CLOSE'))) {
      error = err;
    }
    if (error == null && !last) return;
    while (destroys.isNotEmpty) {
      destroys.removeAt(0)(error);
    }
    if (last && !done) {
      done = true;
      final e = error;
      _nextTick(() => applyListener(callback, [e]));
    }
  }

  void finish([Object? err]) => finishImpl(err, --finishCount == 0);

  for (var i = 0; i < streams.length; i++) {
    final s = streams[i];
    final reading = i < streams.length - 1;
    final writing = i > 0;
    var isFinished = false;
    s.on('close', () => isFinished = true);
    finished(s, {'readable': reading, 'writable': writing}, ([Object? e]) {
      isFinished = e == null;
    });
    destroys.add((Object? err) {
      if (isFinished) return;
      isFinished = true;
      s.destroy(err ?? _destroyedError('pipe'));
    });
    if (i > 0) {
      final src = streams[i - 1] as Readable;
      final dst = s as Writable;
      finishCount += 2;
      var ended = false;
      dst.on('close', () {
        if (!ended) finish(_prematureClose());
      });
      src.pipe(dst, end: false);
      void endFn() {
        ended = true;
        dst.end();
      }

      if (_isReadableFinished(src, true)) {
        _nextTick(endFn);
      } else {
        src.once('end', endFn);
      }
      finished(src, {'readable': true, 'writable': false}, ([Object? err]) {
        final r = src._r!;
        if (err is NodeError &&
            err.code == 'ERR_STREAM_PREMATURE_CLOSE' &&
            r.ended &&
            r.errored == null &&
            !r.errorEmitted) {
          src.once('end', endFn).once('error', finish);
        } else {
          finish(err);
        }
      });
      finished(dst, {'readable': false, 'writable': true}, finish);
    }
  }
  return streams.last;
}
