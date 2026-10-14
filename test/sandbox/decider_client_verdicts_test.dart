// Ported from sandbox-runtime test/sandbox/decider-client-verdicts.test.ts @ 24eb39e.
// ignore_for_file: constant_identifier_names, non_constant_identifier_names, slash_for_doc_comments
import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:sandbox_runtime/src/node/buffer.dart' show Buffer;
import 'package:sandbox_runtime/src/node/fetch.dart' as fetch;
import 'package:sandbox_runtime/src/node/stream.dart' as stream;
import 'package:sandbox_runtime/src/sandbox/decider_client.dart'
    show DeciderOptions, createDecider;
import 'package:sandbox_runtime/src/sandbox/request_filter.dart'
    show RequestDecision, RequestInfo;
import 'package:test/test.dart';

import '../helpers/fake_decider.dart' show Frame, fakeDecider, frameOf;

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

Buffer verdict(Object? id, Frame rest) {
  return Buffer.from(frameOf(jsonEncode({'t': 'verdict', 'id': id, ...rest})));
}

Future<void> until(bool Function() cond) async {
  for (var i = 0; i < 400 && !cond(); i++) {
    await Future<void>.delayed(const Duration(milliseconds: 5));
  }
  expect(cond(), true);
}

void main() {
  group('verdicts that arrive at an unusual time', () {
    test(
      'a deny while the body is being read is a deny, and no body is sent',
      () async {
        final d = fakeDecider(
          [],
          (f) => f['t'] == 'req' ? {'action': 'need_body', 'max': 40} : 'hang',
        );
        final s = d['streams']! as Map<String, Object>;
        final seen = d['seen']! as List<Frame>;
        final dead = <String>[];
        final decider = createDecider(
          DeciderOptions(
            input: s['input']! as stream.Readable,
            output: s['output']! as stream.Writable,
            onDead: (why) => dead.add(why),
          ),
        );
        await decider.hello;
        // A body that never ends: the read is still in flight when the deny comes.
        final body = fetch.ReadableStream<Uint8List>(
          start: (c) => c.enqueue(Uint8List(10)),
        );
        final decided = decider.filterRequest(
          fetch.Request(URL_, method: 'POST', body: body, duplex: 'half'),
          CTX,
        );
        await until(() => decider.bodyBytesHeld() == 40);
        (s['input']! as stream.Writable).write(
          verdict(seen[0]['id'], {
            'action': 'deny',
            'status': 403,
            'reason': 'no',
          }),
        );
        expect(
          await decided,
          _toMatchObject({'action': 'deny', 'status': 403}),
        );
        expect(seen.map((f) => f['t']).toList(), ['req']);
        expect(decider.bodyBytesHeld(), 0);
        expect(dead, <String>[]);
      },
    );

    test(
      'an allow for a request that already timed out changes nothing',
      () async {
        late final List<Frame> seen;
        final d = fakeDecider(
          [],
          (_) => seen.length == 1 ? 'hang' : {'action': 'allow'},
        );
        final s = d['streams']! as Map<String, Object>;
        seen = d['seen']! as List<Frame>;
        final dead = <String>[];
        final decider = createDecider(
          DeciderOptions(
            input: s['input']! as stream.Readable,
            output: s['output']! as stream.Writable,
            timeoutMs: 50,
            onDead: (why) => dead.add(why),
          ),
        );
        await decider.hello;
        final timedOut = await decider.filterRequest(fetch.Request(URL_), CTX);
        expect(timedOut, _toMatchObject(REFUSED));
        (s['input']! as stream.Writable).write(
          verdict(seen[0]['id'], {'action': 'allow'}),
        );
        // Frames are read in order, so the answer to the next request shows
        // the late allow was read and dropped: the link is alive and the
        // refusal above stands.
        final next = await decider.filterRequest(fetch.Request(URL_), CTX);
        expect(next, _toMatchObject({'action': 'allow'}));
        expect(seen, hasLength(2));
        expect(dead, <String>[]);
      },
    );

    test(
      'a frame longer than the read limit kills the link and refuses what is pending',
      () async {
        final d = fakeDecider([], (_) => 'hang');
        final s = d['streams']! as Map<String, Object>;
        final seen = d['seen']! as List<Frame>;
        final dead = <String>[];
        final decider = createDecider(
          DeciderOptions(
            input: s['input']! as stream.Readable,
            output: s['output']! as stream.Writable,
            onDead: (why) => dead.add(why),
          ),
        );
        await decider.hello;
        final pending = decider.filterRequest(fetch.Request(URL_), CTX);
        await until(() => seen.length == 1);
        final length = Buffer.alloc(4)..writeUInt32BE((1 << 20) + 1);
        (s['input']! as stream.Writable).write(length);
        expect(await pending, _toMatchObject(REFUSED));
        expect(dead, ['oversized frame']);
        expect(
          await decider.filterRequest(fetch.Request(URL_), CTX),
          _toMatchObject(REFUSED),
        );
      },
    );
  });
}
