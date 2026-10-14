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
}
