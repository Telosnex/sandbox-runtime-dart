// Behaviour of the node:stream shim, checked against Node v22.
import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:sandbox_runtime/src/node/errno.dart';
import 'package:sandbox_runtime/src/node/stream.dart';
import 'package:test/test.dart';

Future<void> settle([int ms = 20]) =>
    Future<void>.delayed(Duration(milliseconds: ms));

String str(Object? c) => c is String ? c : utf8.decode(c! as List<int>);

void main() {
  test('Readable: data then end then close', () async {
    final log = <String>[];
    final r = Readable(read: (int _) {});
    r.on('end', () => log.add('end'));
    r.on('close', () => log.add('close'));
    r.on('data', (Object d) => log.add('data:${str(d)}'));
    r.push('a');
    r.push('b');
    r.push(null);
    await settle();
    expect(log, ['data:a', 'data:b', 'end', 'close']);
  });

  test('Writable: backpressure and finish while ending', () async {
    final log = <Object>[];
    final w = Writable(
      highWaterMark: 3,
      write: (Object c, String e, Function cb) {
        log.add('w:${str(c)}');
        Timer.run(() => cb());
      },
    );
    log.add(w.write('ab'));
    log.add(w.write('cd'));
    w.on('drain', () => log.add('drain'));
    w.on('finish', () => log.add('finish'));
    w.on('close', () => log.add('close'));
    w.end('e');
    await settle(50);
    expect(log, ['w:ab', true, false, 'w:cd', 'w:e', 'finish', 'close']);
  });

  test('Writable: drain after the buffer empties', () async {
    final log = <Object>[];
    final w = Writable(
      highWaterMark: 2,
      write: (Object c, String e, Function cb) => Timer.run(() => cb()),
    );
    w.on('drain', () => log.add('drain'));
    log.add(w.write('abc'));
    await settle();
    expect(log, [false, 'drain']);
  });

  test('Transform with flush', () async {
    final t = Transform(
      transform: (Object c, String e, Function cb) =>
          cb(null, str(c).toUpperCase()),
      flush: (Function cb) => cb(null, '!'),
    );
    final out = <String>[];
    final done = Completer<void>();
    t.on('data', (Object d) => out.add(str(d)));
    t.on('end', done.complete);
    t.write('ab');
    t.end('c');
    await done.future;
    expect(out.join(), 'ABC!');
  });

  test('write after end: callback and error', () async {
    final codes = <String>[];
    final w = Writable(write: (Object c, String e, Function cb) => cb());
    w.on('error', (Object e) => codes.add('err ${(e as NodeError).code}'));
    w.end();
    w.write('x', (Object? e) => codes.add('cb ${(e! as NodeError).code}'));
    await settle();
    expect(codes, [
      'cb ERR_STREAM_WRITE_AFTER_END',
      'err ERR_STREAM_WRITE_AFTER_END',
    ]);
  });

  test('pipeline and pipe through PassThrough', () async {
    final p = PassThrough();
    final got = <String>[];
    final sink = Writable(
      write: (Object c, String e, Function cb) {
        got.add(str(c));
        cb();
      },
    );
    final done = Completer<Object?>();
    pipeline([p, sink], ([Object? e]) => done.complete(e));
    p.end('xyz');
    expect(await done.future, isNull);
    expect(got.join(), 'xyz');
  });

  test('finished: premature close', () async {
    final r = Readable(read: (int _) {});
    final done = Completer<Object?>();
    finished(r, ([Object? e]) => done.complete(e));
    r.destroy();
    expect(
      ((await done.future)! as NodeError).code,
      'ERR_STREAM_PREMATURE_CLOSE',
    );
  });

  test('read(n) on readable', () async {
    final r = Readable(read: (int _) {});
    r.push('hello');
    r.push(null);
    final out = <Object?>[];
    final done = Completer<void>();
    r.once('readable', () {
      out
        ..add(str(r.read(2)))
        ..add(str(r.read()))
        ..add(r.read());
      done.complete();
    });
    await done.future;
    expect(out, ['he', 'llo', null]);
  });

  test('pipe backpressure through slow consumer', () async {
    final t = PassThrough();
    final received = <int>[];
    final slow = Writable(
      highWaterMark: 1024,
      write: (Object c, String e, Function cb) {
        received.addAll(c as Uint8List);
        Timer.run(() => cb());
      },
    );
    final done = Completer<void>();
    slow.on('finish', done.complete);
    t.pipe(slow);
    var saw = false;
    for (var i = 0; i < 10000; i++) {
      if (!t.write(Uint8List(10))) {
        saw = true;
        await t.onceDrain();
      }
    }
    t.end();
    await done.future;
    expect(saw, isTrue);
    expect(received.length, 100000);
  });

  test('Duplex allowHalfOpen false ends writable on end', () async {
    final log = <String>[];
    final d = Duplex(
      allowHalfOpen: false,
      read: (int _) {},
      write: (Object c, String e, Function cb) => cb(),
    );
    d.on('finish', () => log.add('finish'));
    d.on('close', () => log.add('close'));
    d.resume();
    d.push(null);
    await settle();
    expect(log, ['finish', 'close']);
  });

  test('setEncoding and unpipe', () async {
    final r = Readable(read: (int _) {})..setEncoding('utf8');
    final out = <Object>[];
    r.on('data', out.add);
    r.push(Uint8List.fromList([0xc3]));
    r.push(Uint8List.fromList([0xa9]));
    await settle();
    expect(out, ['é']);
  });

  test('Readable.from iterable', () async {
    final out = <Object>[];
    final done = Completer<void>();
    Readable.from(['a', 'b'])
      ..on('data', out.add)
      ..on('end', done.complete);
    await done.future;
    expect(out, ['a', 'b']);
  });
}

extension on Writable {
  Future<void> onceDrain() {
    final c = Completer<void>();
    once('drain', c.complete);
    return c.future;
  }
}
