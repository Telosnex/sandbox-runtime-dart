// Tests for unimplemented Node HTTP/socket operations to fail closed.

import 'package:sandbox_runtime/src/node/emitted_http.dart';
import 'package:test/test.dart';

void main() {
  group('emitted HTTP shim', () {
    test('header-batch handling reports the missing HTTP parser shim', () {
      expect(
        () => keepFlushedHeaderBatches(Object()),
        throwsA(
          isA<UnimplementedError>().having(
            (error) => error.message,
            'message',
            contains('raw HTTP/1.1 parser shim'),
          ),
        ),
      );
    });

    test('Latin-1 socket encoding reports the missing HTTP/socket shim', () {
      expect(
        () => writeHeadsAsLatin1(Object()),
        throwsA(
          isA<UnimplementedError>().having(
            (error) => error.message,
            'message',
            contains('HTTP/socket shim'),
          ),
        ),
      );
    });

    test('buffered body gate fails closed without IncomingMessage support', () {
      expect(
        () => gateSocketOnBufferedBody(Object(), 1024),
        throwsA(
          isA<UnimplementedError>().having(
            (error) => error.message,
            'message',
            contains('IncomingMessage.readableLength'),
          ),
        ),
      );
    });

    test('request shutdown reports the missing socket lifecycle shim', () {
      expect(
        () => endRequestAfterResponse(
          Object(),
          isMarkedEndsGracefully: (_) => false,
        ),
        throwsA(
          isA<UnimplementedError>().having(
            (error) => error.message,
            'message',
            contains('underlying socket lifecycle'),
          ),
        ),
      );
    });
  });
}
