// No upstream counterpart: review-fix regression tests for decider_client.dart.
import 'dart:async';

import 'package:sandbox_runtime/src/node/fetch.dart' as fetch;
import 'package:sandbox_runtime/src/node/stream.dart' as stream;
import 'package:sandbox_runtime/src/sandbox/decider_client.dart';
import 'package:sandbox_runtime/src/sandbox/request_filter.dart';
import 'package:test/test.dart';

import '../helpers/fake_decider.dart';

void main() {
  test('close after hello fires onDead once, no hello StateError', () async {
    final f = fakeDecider(['a.com'], (_) => {'action': 'allow'});
    final s = f['streams']! as Map<String, Object>;
    final dead = <String>[];
    final d = createDecider(
      DeciderOptions(
        input: s['input']! as stream.Readable,
        output: s['output']! as stream.Writable,
        onDead: dead.add,
      ),
    );
    await d.hello;
    d.close();
    d.close();
    await Future<void>.delayed(Duration.zero);
    expect(dead, ['closed']);
  });

  test('close after hello fails pending waiters', () async {
    final f = fakeDecider(['a.com'], (_) => 'hang');
    final s = f['streams']! as Map<String, Object>;
    final d = createDecider(
      DeciderOptions(
        input: s['input']! as stream.Readable,
        output: s['output']! as stream.Writable,
      ),
    );
    await d.hello;
    final pending = d
        .filterRequest(fetch.Request('http://a.com/'))
        .then<Object?>((r) => r, onError: (Object e) => e);
    await Future<void>.delayed(const Duration(milliseconds: 20));
    d.close();
    final r = await pending.timeout(const Duration(seconds: 1));
    if (r is RequestDecision) {
      expect(r.action, 'deny');
    } else {
      expect(r.toString(), contains('closed'));
    }
  });

  test('deeply nested frame dies cleanly', () async {
    for (final body in ['[' * 200000, '{"a":' * 200000]) {
      final input = stream.PassThrough();
      final output = stream.PassThrough();
      final dead = <String>[];
      createDecider(
        DeciderOptions(input: input, output: output, onDead: dead.add),
      );
      input.write(frameOf(body));
      await Future<void>.delayed(const Duration(milliseconds: 50));
      expect(dead, hasLength(1));
      expect(
        dead.single,
        anyOf('frame is not one JSON object', 'frame is not valid JSON'),
      );
    }
  });
}
