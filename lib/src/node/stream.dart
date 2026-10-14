// `node:stream`: stream classes and conversions. No upstream counterpart.
// Wave 1 declarations; methods are pending real stream behavior.

import 'dart:typed_data';
import 'dart:async';

import 'events.dart';
import 'fetch.dart';

/// Node's `Readable` stream.
class Readable extends EventEmitter {
  Readable({Function? read, Function? destroy}) : _readFn = read, _destroyFn = destroy;
  final Function? _readFn, _destroyFn;
  final List<Object> _buffer = [];
  final List<Writable> _pipes = [];
  bool _ended = false, _destroyed = false, _flowing = false, _paused = false, _endEmitted = false;
  static Readable from(Iterable<Object?> source) { final r=Readable(); scheduleMicrotask(() { for(final x in source) { if(x!=null) r.push(x); } r.push(null); }); return r; }

  /// Create a Node readable from a Web ReadableStream.
  static Readable fromWeb(ReadableStream<Object?> stream) {
    final r=Readable(); final reader=stream.getReader();
    Future<void>(() async { while(true) { final v=await reader.read(); if(v.done) { r.push(null); break; } r.push(v.value); } }); return r;
  }

  /// Convert a Node readable to a Web ReadableStream.
  static ReadableStream<Uint8List> toWeb(Readable stream) => ReadableStream<Uint8List>(start: (c) { stream.on('data',(Object? x) { if(x is Uint8List) c.enqueue(x); else if(x is List<int>) c.enqueue(Uint8List.fromList(x)); }); stream.on('end',c.close); stream.on('error',c.error); stream.resume(); });

  @override
  Readable on(String event, Function listener) { super.on(event,listener); if(event=='data') resume(); if(event=='readable') _readFn?.call(); return this; }

  @override
  Readable once(String event, Function listener) { super.once(event,listener); if(event=='data') resume(); return this; }

  @override
  Readable off(String event, Function listener) { super.off(event,listener); return this; }

  @override
  Readable removeListener(String event, Function listener) { super.removeListener(event,listener); return this; }

  Readable unpipe([Writable? destination]) { if(destination==null) { _pipes.clear(); } else { _pipes.remove(destination); } return this; }

  T pipe<T extends Writable>(T destination, {bool end = true}) { _pipes.add(destination); on('data',(Object? x) { if(_pipes.contains(destination) && !destination.write(x!)) { pause(); destination.once('drain',resume); } }); once('end',() { if(end) destination.end(); }); return destination; }

  Readable pause() { _paused=true; _flowing=false; return this; }

  Readable resume() { _paused=false; _flowing=true; while(_buffer.isNotEmpty && !_paused) emit('data',_buffer.removeAt(0)); if(_ended && _buffer.isEmpty) _emitEnd(); return this; }

  bool isPaused() => _paused;

  Object? read([int? size]) { if(_buffer.isEmpty) { if(!_ended) _readFn?.call(size); if(_buffer.isEmpty) return null; } return _buffer.removeAt(0); }

  void unshift(List<int> chunk) { _buffer.insert(0,Uint8List.fromList(chunk)); emit('readable'); }

  bool push(Object? chunk, [String? encoding]) { if(_destroyed || _ended) return false; if(chunk==null) { _ended=true; if(_flowing) scheduleMicrotask(_emitEnd); return false; } _buffer.add(chunk); emit('readable'); if(_flowing) scheduleMicrotask(() { if(_buffer.isNotEmpty && !_paused) emit('data',_buffer.removeAt(0)); if(_ended && _buffer.isEmpty) _emitEnd(); }); return true; }

  Readable destroy([Object? error]) { if(_destroyed) return this; _destroyed=true; _destroyFn?.call(error); if(error!=null) emit('error',error); scheduleMicrotask(() => emit('close')); return this; }

  bool get destroyed =>
      _destroyed;
  bool get readable =>
      !_ended && !_destroyed;
  bool get readableEnded =>
      _endEmitted;
  int get readableLength =>
      _buffer.fold<int>(0,(n,x)=>n+(x is List<int>?x.length:1));
  void _emitEnd() { if(!_endEmitted) { _endEmitted=true; emit('end'); } }
}

/// Node's `Writable` stream.
class Writable extends EventEmitter {
  Writable({Function? write, Function? finalCallback, Function? destroy, this.highWaterMark = 16384}) : _writeFn=write, _finalFn=finalCallback, _destroyFn=destroy;
  final Function? _writeFn, _finalFn, _destroyFn;
  final int highWaterMark;
  int _length=0; bool _destroyed=false, _ended=false, _finished=false, _writing=false;
  final List<({Object data, Function? callback})> _writes=[];

  @override
  Writable on(String event, Function listener) { super.on(event,listener); return this; }

  @override
  Writable once(String event, Function listener) { super.once(event,listener); return this; }

  @override
  Writable off(String event, Function listener) { super.off(event,listener); return this; }

  @override
  Writable removeListener(String event, Function listener) { super.removeListener(event,listener); return this; }

  bool write(Object data, [Function? callback]) { if(_ended || _destroyed) { final e=StateError('write after end'); emit('error',e); callback?.call(e); return false; } final n=data is List<int>?data.length:1; _length+=n; _writes.add((data:data,callback:callback)); scheduleMicrotask(_process); return _length < highWaterMark; }

  Writable end([Object? data, Function? callback]) { if(data!=null) write(data); if(callback!=null) once('finish',callback); if(_ended) return this; _ended=true; scheduleMicrotask(_process); return this; }

  Writable destroy([Object? error]) { if(_destroyed) return this; _destroyed=true; _destroyFn?.call(error); if(error!=null) emit('error',error); scheduleMicrotask(() => emit('close')); return this; }

  bool get destroyed =>
      _destroyed;
  bool get writable =>
      !_ended && !_destroyed;
  bool get writableEnded =>
      _ended;
  bool get writableFinished =>
      _finished;
  int get writableLength =>
      _length;
  void _process() {
    if(_writing || _destroyed) return;
    if(_writes.isNotEmpty) { final item=_writes.removeAt(0); _writing=true; final n=item.data is List<int>?(item.data as List<int>).length:1; void done([Object? err]) { _length-=n; _writing=false; if(err!=null) { emit('error',err); item.callback?.call(err); } else { item.callback?.call(); } if(_length < highWaterMark) emit('drain'); _process(); } if(_writeFn==null) { done(); } else { try { final ret=Function.apply(_writeFn!,[item.data,done]); if(ret is Future) ret.then((_)=>done(),onError:(Object e)=>done(e)); } catch(e) { done(e); } } return; }
    if(_ended && !_finished) { final f=_finalFn; if(f==null) { _finished=true; emit('finish'); emit('close'); } else { Function.apply(f,[([Object? e]) { if(e!=null) emit('error',e); _finished=true; emit('finish'); emit('close'); }]); } }
  }
}

/// Node's duplex stream: a readable stream that is also writable.
class Duplex extends Readable implements Writable {
  Duplex({
    Function? read,
    Function? write,
    Function? finalCallback,
    Function? destroy,
  }) : _dWrite=write, _dFinal=finalCallback, _dDestroy=destroy;
  final Function? _dWrite,_dFinal,_dDestroy;
  final int highWaterMark=16384;
  int _dLength=0; bool _dEnded=false,_dFinished=false,_dWriting=false;
  final List<({Object data, Function? callback})> _dQueue=[];
  @override int get _length => _dLength;
  @override set _length(int v) => _dLength=v;
  @override bool get _ended => super._ended;
  @override bool get _finished => _dFinished;
  @override set _finished(bool v) => _dFinished=v;
  @override Function? get _writeFn => _dWrite;
  @override Function? get _finalFn => _dFinal;
  @override Function? get _destroyFn => _dDestroy;
  @override bool get _writing => _dWriting;
  @override set _writing(bool v) => _dWriting=v;
  @override List<({Object data, Function? callback})> get _writes => _dQueue;
  @override void _process() {}

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
