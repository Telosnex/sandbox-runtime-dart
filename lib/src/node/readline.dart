// Node's `readline.createInterface` for line-by-line reading of a stream.
// No upstream counterpart; Node is the spec.
import 'dart:convert';

import 'events.dart';

/// Node's `readline.Interface` (input only, no terminal).
class Interface extends EventEmitter {
  Interface._(this.input, this.crlfDelay) {
    input.on('data', _onData);
    input.on('end', _onEnd);
    input.on('error', _onError);
    // Node resumes the input when the interface is created.
    (input as dynamic).resume();
  }

  final EventEmitter input;
  final num crlfDelay;
  final StringBuffer _line = StringBuffer();
  late final _decoder = const Utf8Decoder(
    allowMalformed: true,
  ).startChunkedConversion(_StringSink(_onText));
  bool _sawReturn = false;
  DateTime _sawReturnAt = DateTime.fromMillisecondsSinceEpoch(0);
  bool closed = false;

  void _onData(Object? chunk) {
    if (closed) return;
    if (chunk is String) {
      _onText(chunk);
    } else {
      _decoder.add(chunk as List<int>);
    }
  }

  void _onText(String text) {
    for (var i = 0; i < text.length; i++) {
      final c = text[i];
      if (c == '\n') {
        if (_sawReturn &&
            (crlfDelay == double.infinity ||
                DateTime.now().difference(_sawReturnAt).inMilliseconds <=
                    crlfDelay)) {
          // The \n of a \r\n: the line ended at the \r.
          _sawReturn = false;
          continue;
        }
        _sawReturn = false;
        _emitLine();
      } else if (c == '\r') {
        _sawReturn = true;
        _sawReturnAt = DateTime.now();
        _emitLine();
      } else {
        _sawReturn = false;
        _line.write(c);
      }
    }
  }

  void _emitLine() {
    final line = _line.toString();
    _line.clear();
    emit('line', line);
  }

  void _onEnd([Object? _]) {
    if (closed) return;
    // A partial UTF-8 sequence at the end is dropped, as Node does.
    if (_line.isNotEmpty) _emitLine();
    close();
  }

  void _onError(Object? err) {
    emit('error', err);
  }

  /// Node's `rl.close()`: stops reading and emits 'close' once.
  void close() {
    if (closed) return;
    closed = true;
    input.off('data', _onData);
    input.off('end', _onEnd);
    input.off('error', _onError);
    try {
      (input as dynamic).pause();
    } on NoSuchMethodError {
      // An input without pause() (Node tolerates a plain emitter).
    }
    emit('close');
  }
}

class _StringSink implements Sink<String> {
  _StringSink(this._onText);
  final void Function(String) _onText;
  @override
  void add(String data) => _onText(data);
  @override
  void close() {}
}

/// Node's `readline.createInterface({ input, crlfDelay })`. `crlfDelay`
/// defaults to 100 ms, as in Node; `double.infinity` is `Infinity`.
Interface createInterface({required EventEmitter input, num crlfDelay = 100}) =>
    Interface._(input, crlfDelay < 100 ? 100 : crlfDelay);
