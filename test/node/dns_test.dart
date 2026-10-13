import 'dart:async';

import 'package:sandbox_runtime/src/node/dns.dart';
import 'package:test/test.dart';

void main() {
  group('node:dns lookup', () {
    test(
      'returns all records with Node lookup result and family records',
      () async {
        final result = await _lookup('127.0.0.1', LookupAllOptions());
        expect(result.error, isNull);
        expect(result.address, isA<LookupResultAll>());
        final addresses = (result.address as LookupResultAll).addresses;
        expect(addresses, hasLength(1));
        expect(addresses.single.address, '127.0.0.1');
        expect(addresses.single.family, 4);
      },
    );

    test(
      'returns the single-address callback form when all is not requested',
      () async {
        final result = await _lookup('::1', LookupOptions(family: 'IPv6'));
        expect(result.error, isNull);
        expect(result.address, isA<LookupResultAddress>());
        expect((result.address as LookupResultAddress).address, '::1');
        expect(result.family, 6);
      },
    );

    test(
      'an IP literal is returned in its actual family despite a different family option',
      () async {
        final result = await _lookup('127.0.0.1', LookupAllOptions(family: 6));
        expect(result.error, isNull);
        expect((result.address as LookupResultAll).addresses.single.family, 4);
      },
    );

    test('reports Node error codes for invalid lookup options', () {
      expect(
        () => lookup(
          'localhost',
          LookupOptions(family: 5),
          (NodeLookupError? _, LookupResult? __, [int? family]) {},
        ),
        throwsA(
          isA<NodeLookupError>().having(
            (error) => error.code,
            'code',
            'ERR_INVALID_ARG_VALUE',
          ),
        ),
      );
      expect(
        () => lookup(
          'localhost',
          LookupOptions(order: 'unordered'),
          (NodeLookupError? _, LookupResult? __, [int? family]) {},
        ),
        throwsA(
          isA<NodeLookupError>().having(
            (error) => error.code,
            'code',
            'ERR_INVALID_ARG_VALUE',
          ),
        ),
      );
    });

    test('does not silently ignore unsupported getaddrinfo hints', () {
      expect(
        () => lookup(
          'localhost',
          LookupOptions(hints: 1),
          (NodeLookupError? _, LookupResult? __, [int? family]) {},
        ),
        throwsUnimplementedError,
      );
    });
  });
}

Future<({Object? error, LookupResult? address, int? family})> _lookup(
  String hostname,
  LookupOptions options,
) {
  final result =
      Completer<({Object? error, LookupResult? address, int? family})>();
  lookup(hostname, options, (
    NodeLookupError? error,
    LookupResult? address, [
    int? family,
  ]) {
    result.complete((error: error, address: address, family: family));
  });
  return result.future;
}
