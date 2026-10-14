import 'dart:typed_data';
import 'dart:async';

import 'package:sandbox_runtime/src/node/fetch.dart';
import 'package:test/test.dart';

void main() {
  group('ReadableStream', () {
    test('reads enqueued chunks and then reports completion', () async {
      final stream = ReadableStream<int>(
        start: (controller) {
          controller.enqueue(1);
          controller.enqueue(2);
          controller.close();
        },
      );
      final reader = stream.getReader();
      expect(await reader.read(), (done: false, value: 1));
      expect(await reader.read(), (done: false, value: 2));
      expect(await reader.read(), (done: true, value: null));
    });

    test('pulls on demand and propagates cancellation', () async {
      var pulls = 0;
      Object? reason;
      final stream = ReadableStream<int>(
        pull: (controller) {
          pulls++;
          controller.enqueue(pulls);
        },
        cancel: (value) {
          reason = value;
        },
      );
      final reader = stream.getReader();
      expect((await reader.read()).value, 1);
      expect(pulls, 1);
      await reader.cancel('cancelled');
      expect(reason, 'cancelled');
    });

    test('errors pending reads', () async {
      final stream = ReadableStream<int>(
        start: (controller) {
          scheduleMicrotask(() => controller.error(StateError('failed')));
        },
      );
      expect(stream.getReader().read(), throwsA(isA<StateError>()));
    });
  });

  test('Request keeps the Fetch property names', () {
    final request = Request('https://example.test/', method: 'POST');
    expect(request.url, 'https://example.test/');
    expect(request.method, 'POST');
    expect(request.headers, isA<Headers>());
  });

  group('tee and Request body', () {
    ReadableStream<Uint8List> source(
      List<int> data,
      void Function(Object?) onCancel,
    ) {
      var sent = false;
      return ReadableStream<Uint8List>(
        pull: (c) {
          if (sent) return c.close();
          sent = true;
          c.enqueue(Uint8List.fromList(data));
        },
        cancel: onCancel,
      );
    }

    test('both branches see every chunk', () async {
      final [a, b] = source([1, 2], (_) {}).tee();
      expect((await a.getReader().read()).value, [1, 2]);
      final rb = b.getReader();
      expect((await rb.read()).value, [1, 2]);
      expect((await rb.read()).done, isTrue);
    });

    test('source cancelled only after both branches cancel', () async {
      Object? reason;
      var cancelled = false;
      // A source that never ends: tee pulls eagerly up to the high-water
      // mark, so one that closed would be closed before any cancel.
      final [a, b] = ReadableStream<int>(
        pull: (_) {},
        cancel: (r) {
          cancelled = true;
          reason = r;
        },
      ).tee();
      var aDone = false;
      unawaited(a.cancel('x').then((_) => aDone = true));
      await pumpEventQueue();
      expect(cancelled, isFalse);
      expect(aDone, isFalse);
      await b.cancel('y');
      expect(cancelled, isTrue);
      expect(reason, ['x', 'y']);
      expect(aDone, isTrue);
    });

    test('cancel rejects with the stored error and when locked', () async {
      final s = ReadableStream<int>(start: (c) => c.error('boom'));
      await expectLater(s.cancel(), throwsA('boom'));
      final t = ReadableStream<int>()..getReader();
      await expectLater(t.cancel(), throwsStateError);
    });

    test('bodyUsed after read or cancel', () async {
      final body = source([1], (_) {});
      final req = Request(
        'http://a/',
        method: 'POST',
        body: body,
        duplex: 'half',
      );
      expect(req.bodyUsed, isFalse);
      await body.getReader().read();
      expect(req.bodyUsed, isTrue);
      final c = source([1], (_) {});
      final req2 = Request(
        'http://a/',
        method: 'POST',
        body: c,
        duplex: 'half',
      );
      await c.cancel();
      expect(req2.bodyUsed, isTrue);
      expect(Request('http://a/').bodyUsed, isFalse);
    });

    test('Request validates like Node', () {
      expect(Request('http://A.com').url, 'http://a.com/');
      expect(Request('http://a/', method: 'post').method, 'POST');
      expect(
        () => Request('http://a/', body: source([], (_) {}), duplex: 'half'),
        throwsArgumentError,
      );
      expect(
        () => Request('http://a/', method: 'POST', body: source([], (_) {})),
        throwsArgumentError,
      );
      expect(() => Request('http://a/', method: 'TRACE'), throwsArgumentError);
      expect(() => Request('nope'), throwsA(anything));
    });
  });
}
