import 'dart:convert';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:sandbox_runtime/src/node/fetch.dart';

Request mk(String s) => Request(
  'http://a/',
  method: 'POST',
  duplex: 'half',
  body: ReadableStream<Uint8List>(
    start: (c) {
      c.enqueue(Uint8List.fromList(utf8.encode(s)));
      c.close();
    },
  ),
);

void main() {
  test('text/json/arrayBuffer/bytes', () async {
    expect(await mk('hi').text(), 'hi');
    expect(await mk('{"a":1}').json(), {'a': 1});
    expect((await mk('abc').arrayBuffer()).lengthInBytes, 3);
    expect(await mk('ab').bytes(), [97, 98]);
  });
  test('bodyUsed and reuse errors', () async {
    final r = mk('x');
    expect(r.bodyUsed, isFalse);
    await r.text();
    expect(r.bodyUsed, isTrue);
    expect(r.text(), throwsA(isA<ArgumentError>()));
  });
  test('locked body and null body', () async {
    final r = mk('x');
    r.body!.getReader();
    expect(r.text(), throwsA(isA<ArgumentError>()));
    expect(await Request('http://a/').text(), '');
  });
}
