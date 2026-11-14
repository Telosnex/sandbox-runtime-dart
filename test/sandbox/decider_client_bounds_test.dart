// Ported from sandbox-runtime test/sandbox/decider-client-bounds.test.ts @ 0bbebed.
// ignore_for_file: constant_identifier_names, non_constant_identifier_names, slash_for_doc_comments
import 'dart:async';
import 'dart:typed_data';

import 'package:sandbox_runtime/src/node/buffer.dart' show Buffer;
import 'package:sandbox_runtime/src/node/fetch.dart' as fetch;
import 'package:sandbox_runtime/src/node/stream.dart' as stream;
import 'package:sandbox_runtime/src/sandbox/decider_client.dart'
    show DeciderOptions, createDecider, encodeBodyFrame, encodeFrame;
import 'package:sandbox_runtime/src/sandbox/request_filter.dart'
    show RequestDecision, RequestInfo;
import 'package:test/test.dart';

import '../helpers/fake_decider.dart' show Frame, fakeDecider;

const URL_ = 'https://api.example.test/upload';
const CTX = RequestInfo(target: (host: 'api.example.test', port: 443));
const REFUSED = {
  'action': 'deny',
  'status': 503,
  'mark': 'decider_unavailable',
};

// Dart: `toMatchObject(REFUSED)`, for what a decider answers.
Matcher _toMatchObject(Map<String, Object?> expected) =>
    predicate<Object?>((got) {
      final d = got as RequestDecision;
      return (expected['action'] == null || d.action == expected['action']) &&
          (expected['status'] == null || d.status == expected['status']) &&
          (expected['mark'] == null || d.mark == expected['mark']);
    }, 'matches $expected');

fetch.Request upload(Object body) {
  return fetch.Request(
    URL_,
    method: 'POST',
    body: body is String
        ? fetch.ReadableStream<Uint8List>(
            start: (c) {
              c.enqueue(Buffer.from(body).toUint8List());
              c.close();
            },
          )
        : body as fetch.ReadableStream<Uint8List>,
    duplex: 'half',
  );
}

/** A decider that asks for every body and answers it when `release` runs. */
({Map<String, Object> d, List<Frame> bodies, void Function() release})
holdingDecider([Frame answer = const {'action': 'allow'}]) {
  final bodies = <Frame>[];
  final held = <void Function()>[];
  final d = fakeDecider([], (f) {
    if (f['t'] == 'req') return {'action': 'need_body', 'max': 40};
    bodies.add(f);
    final c = Completer<Frame>();
    held.add(() => c.complete(answer));
    return c.future;
  });
  void release() {
    final go = held.toList();
    held.clear();
    for (final f in go) {
      f();
    }
  }

  return (d: d, bodies: bodies, release: release);
}

Future<void> until(bool Function() cond) async {
  for (var i = 0; i < 400 && !cond(); i++) {
    await Future<void>.delayed(const Duration(milliseconds: 5));
  }
  expect(cond(), true);
}

void main() {
  group('body frames', () {
    test('built in place, they are the bytes encodeFrame gives', () {
      for (final size in [
        0,
        1,
        2,
        3,
        4,
        (3 << 16) - 1,
        3 << 16,
        (3 << 16) + 1,
        500001,
      ]) {
        final data = Buffer.alloc(size);
        for (var i = 0; i < size; i++) {
          data[i] = (i * 31 + size) & 0xff;
        }
        for (final cut in [false, true]) {
          final plain = encodeFrame({
            't': 'body',
            'id': 7,
            'data': data.toString('base64'),
            if (cut) 'cut': true,
          });
          expect(
            encodeBodyFrame(7, data.toUint8List(), cut),
            orderedEquals(plain),
          );
        }
      }
    });
  });

  group('the budget for bodies held for the decider', () {
    test(
      'parallel uploads past it are refused, the rest complete, and it empties',
      () async {
        final (:d, :bodies, :release) = holdingDecider();
        final s = d['streams']! as Map<String, Object>;
        final decider = createDecider(
          DeciderOptions(
            input: s['input']! as stream.Readable,
            output: s['output']! as stream.Writable,
            maxBodyBytesHeld: 100,
          ),
        );
        await decider.hello;
        final all = [
          1,
          2,
          3,
          4,
          5,
        ].map((_) => decider.filterRequest(upload('x' * 40), CTX)).toList();
        await until(() => bodies.length == 2);
        expect(decider.bodyBytesHeld(), 80);
        release();
        final got = await Future.wait(all);
        expect(got.where((g) => g.action == 'allow'), hasLength(2));
        final refused = got.where((g) => g.action == 'deny').toList();
        expect(refused, hasLength(3));
        for (final r in refused) {
          expect(r, _toMatchObject(REFUSED));
        }
        // No body of a refused request reached the decider either.
        expect(bodies, hasLength(2));
        expect(decider.bodyBytesHeld(), 0);
        final again = decider.filterRequest(upload('y' * 40), CTX);
        await until(() => bodies.length == 3);
        release();
        expect((await again).action, 'allow');
        decider.close();
      },
    );

    test(
      'is given back after a deny, a client abort, a timeout and a dead decider',
      () async {
        final (:d, :bodies, :release) = holdingDecider({
          'action': 'deny',
          'status': 403,
          'reason': 'no',
        });
        final dead = <String>[];
        final s = d['streams']! as Map<String, Object>;
        final decider = createDecider(
          DeciderOptions(
            input: s['input']! as stream.Readable,
            output: s['output']! as stream.Writable,
            maxBodyBytesHeld: 40,
            timeoutMs: 200,
            onDead: (why) => dead.add(why),
          ),
        );
        await decider.hello;

        final denied = decider.filterRequest(upload('x' * 40), CTX);
        await until(() => bodies.length == 1);
        expect(decider.bodyBytesHeld(), 40);
        release();
        expect(await denied, _toMatchObject({'action': 'deny', 'status': 403}));
        expect(dead, <String>[]);
        expect(decider.bodyBytesHeld(), 0);

        late void Function() abort;
        final aborted = decider.filterRequest(
          upload(
            fetch.ReadableStream<Uint8List>(
              start: (c) {
                c.enqueue(Uint8List(10));
                abort = () => c.error(Exception('client went away'));
              },
            ),
          ),
          CTX,
        );
        await until(() => decider.bodyBytesHeld() == 40);
        abort();
        expect(await aborted, _toMatchObject(REFUSED));
        expect(decider.bodyBytesHeld(), 0);

        // Never answered: the wait for the verdict on the body times out.
        final timedOut = decider.filterRequest(upload('x' * 40), CTX);
        await until(() => bodies.length == 2);
        expect(await timedOut, _toMatchObject(REFUSED));
        expect(decider.bodyBytesHeld(), 0);

        final pending = decider.filterRequest(upload('x' * 40), CTX);
        await until(() => bodies.length == 3);
        decider.close();
        expect(await pending, _toMatchObject(REFUSED));
        expect(decider.bodyBytesHeld(), 0);
        expect(dead, ['closed']);
      },
    );
  });

  group('a decider that stops reading', () {
    test(
      'is gone once the queue limit is passed, and every pending request is refused',
      () async {
        final d = fakeDecider([], (_) => 'hang');
        final streams = d['streams']! as Map<String, Object>;
        var stalled = false;
        final output = stream.Writable(
          write: (Object chunk, String? enc, Function done) {
            if (stalled) return;
            (streams['output']! as stream.Writable).write(chunk);
            done();
          },
        );
        final dead = <String>[];
        final decider = createDecider(
          DeciderOptions(
            input: streams['input']! as stream.Readable,
            output: output,
            maxQueuedBytes: 4000,
            timeoutMs: 60000,
            onDead: (why) => dead.add(why),
          ),
        );
        await decider.hello;
        stalled = true;
        final all = List.generate(
          200,
          (_) => decider.filterRequest(fetch.Request(URL_), CTX),
        );
        final got = await Future.any<List<RequestDecision>?>([
          Future.wait(all),
          Future<List<RequestDecision>?>.delayed(
            const Duration(milliseconds: 3000),
          ),
        ]);
        expect(dead, hasLength(1));
        expect(dead[0], matches(RegExp(r'^not reading: \d+ bytes queued$')));
        expect(got, hasLength(200));
        for (final g in got ?? <RequestDecision>[]) {
          expect(g, _toMatchObject(REFUSED));
        }
      },
    );
  });
}
