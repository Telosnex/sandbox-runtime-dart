// Ported from sandbox-runtime test/sandbox/body-substitution.test.ts @ 24eb39e.
// ignore_for_file: slash_for_doc_comments, constant_identifier_names
import 'dart:async';
import 'dart:typed_data';

import 'package:sandbox_runtime/src/node/buffer.dart';
import 'package:sandbox_runtime/src/node/crypto.dart' show randomBytes;
import 'package:sandbox_runtime/src/node/http.dart'
    show IncomingHttpHeaders, IncomingMessage;
import 'package:sandbox_runtime/src/node/stream.dart' show Writable;
import 'package:sandbox_runtime/src/sandbox/body_substitution.dart';
import 'package:test/test.dart';

SentinelBufferPair pair(String sentinel, String real) => SentinelBufferPair(
  sentinel: Buffer.from(sentinel).toUint8List(),
  realValue: Buffer.from(real).toUint8List(),
);

/** Run `chunks` through a fresh transform and collect the full output. */
Future<Uint8List> run(
  List<SentinelBufferPair> pairs,
  List<Uint8List> chunks,
) async {
  final t = createBodySubstitutionTransform(pairs);
  final out = <Uint8List>[];
  final done = Completer<void>();
  t.on('end', () => done.complete());
  t.on('error', (Object e) => done.completeError(e));
  t.on('data', (Object c) => out.add(Uint8List.fromList(c as List<int>)));
  for (final c in chunks) {
    t.write(c);
  }
  t.end();
  await done.future;
  return Buffer.concat(out).toUint8List();
}

const SENTINEL = 'fake_value_0f0f0f0f-1111-4222-8333-444455556666';
const REAL = 'ghp_realsecret_abcdef0123456789_padpadpadpadpad'; // same length

Uint8List _bytes(String s) => Buffer.from(s).toUint8List();

String _str(List<int> b) => Buffer.from(b).toString();

// Dart: `{ method, headers } as IncomingMessage` has no equivalent; a fake
// that answers only method and headers.
class _Msg implements IncomingMessage {
  _Msg(this.method, this.headers);
  @override
  final String? method;
  @override
  final Map<String, Object?> headers;
  @override
  dynamic noSuchMethod(Invocation invocation) => null;
}

void main() {
  group('createBodySubstitutionTransform', () {
    test('sentinel split across every chunk boundary offset', () async {
      final body = _bytes('{"key":"$SENTINEL","other":1}');
      final expected = _bytes('{"key":"$REAL","other":1}');
      for (var i = 0; i <= body.length; i++) {
        final out = await run(
          [pair(SENTINEL, REAL)],
          [body.sublist(0, i), body.sublist(i)],
        );
        expect(out, equals(expected));
      }
    });

    test('multiple occurrences in one body are all replaced', () async {
      final body = _bytes('$SENTINEL and $SENTINEL, plus $SENTINEL');
      final out = await run([pair(SENTINEL, REAL)], [body]);
      expect(_str(out), '$REAL and $REAL, plus $REAL');
    });

    test('sentinel at the very start and very end of the body', () async {
      final body = _bytes('$SENTINEL-middle-$SENTINEL');
      final out = await run([pair(SENTINEL, REAL)], [body]);
      expect(_str(out), '$REAL-middle-$REAL');
      // Body that IS exactly one sentinel.
      final only = await run([pair(SENTINEL, REAL)], [_bytes(SENTINEL)]);
      expect(_str(only), REAL);
    });

    test('multiple sentinels of different lengths, interleaved', () async {
      final short = pair('fake_value_short-aaaa-4bbb-8ccc-ddddeeee', 'tok-A');
      final long = pair('${SENTINEL}_extra_padding_zzz', 'much-longer-real-B');
      final body = _bytes(
        'a=${_str(short.sentinel)}&b=${_str(long.sentinel)}&c=${_str(short.sentinel)}',
      );
      // Feed byte-by-byte to force the hold-back on every boundary.
      final chunks = List.generate(body.length, (i) => body.sublist(i, i + 1));
      final out = await run([short, long], chunks);
      expect(_str(out), 'a=tok-A&b=much-longer-real-B&c=tok-A');
    });

    test(
      'binary body without sentinels passes through byte-identical',
      () async {
        final body = randomBytes(64 * 1024).toUint8List();
        final out = await run(
          [pair(SENTINEL, REAL)],
          [body.sublist(0, 100), body.sublist(100, 40000), body.sublist(40000)],
        );
        expect(out, equals(body));
      },
    );

    test('empty body produces empty output', () async {
      final out = await run([pair(SENTINEL, REAL)], []);
      expect(out.length, 0);
    });

    test('backpressure: correct output through a slow consumer', () async {
      final t = createBodySubstitutionTransform([pair(SENTINEL, REAL)]);
      final received = <Uint8List>[];
      final slow = Writable(
        highWaterMark: 1024,
        write: (Object chunk, String? _, Function cb) {
          received.add(Uint8List.fromList(chunk as List<int>));
          Timer.run(() => cb());
        },
      );
      final piece = _bytes('xx${SENTINEL}yy');
      const total = 4096;
      final done = Completer<void>();
      slow.on('finish', () => done.complete());
      slow.on('error', (Object e) => done.completeError(e));
      t.on('error', (Object e) => done.completeError(e));
      t.pipe(slow);
      var sawBackpressure = false;
      for (var i = 0; i < total; i++) {
        if (!t.write(piece)) {
          sawBackpressure = true;
          final r = Completer<void>();
          t.once('drain', () => r.complete());
          await r.future;
        }
      }
      t.end();
      await done.future;
      expect(sawBackpressure, true);
      expect(_str(Buffer.concat(received)), 'xx${REAL}yy' * total);
    });
  });

  group('allLengthMatched', () {
    test('true only when every pair has equal byte lengths', () {
      expect(allLengthMatched([pair(SENTINEL, REAL)]), true);
      expect(allLengthMatched([pair(SENTINEL, 'short')]), false);
      expect(
        allLengthMatched([pair(SENTINEL, REAL), pair('abc', 'de')]),
        false,
      );
    });
  });

  group('prepareBodySubstitution', () {
    IncomingMessage msg(String method, [IncomingHttpHeaders? headers]) =>
        _Msg(method, headers ?? {});

    test('undefined source or bodyless method → no transform', () {
      final IncomingHttpHeaders fwd = {'content-length': '10'};
      expect(prepareBodySubstitution(null, msg('POST'), fwd, 'h'), isNull);
      expect(
        prepareBodySubstitution(
          (_) => [pair(SENTINEL, REAL)],
          msg('GET'),
          fwd,
          'h',
        ),
        isNull,
      );
      expect(fwd['content-length'], '10');
    });

    test('GET that declares a body still gets the transform', () {
      // GET-with-body APIs are legal HTTP and forwarded; only a GET with no
      // declared body keeps the bare pipe.
      final IncomingHttpHeaders fwd = {'content-length': '10'};
      final t = prepareBodySubstitution(
        (_) => [pair(SENTINEL, REAL)],
        msg('GET', {'content-length': '10'}),
        fwd,
        'h',
      );
      expect(t, isNotNull);
    });

    test(
      'no injectable pairs at the host → no transform, headers untouched',
      () {
        final IncomingHttpHeaders fwd = {'content-length': '10'};
        expect(
          prepareBodySubstitution((_) => [], msg('POST'), fwd, 'h'),
          isNull,
        );
        expect(fwd['content-length'], '10');
      },
    );

    test('Content-Encoding on the request skips substitution (fail-safe)', () {
      final IncomingHttpHeaders fwd = {'content-length': '10'};
      final t = prepareBodySubstitution(
        (_) => [pair(SENTINEL, REAL)],
        msg('POST', {'content-encoding': 'gzip'}),
        fwd,
        'h',
      );
      expect(t, isNull);
      expect(fwd['content-length'], '10');
    });

    test('length-matched pairs keep Content-Length verbatim', () {
      final IncomingHttpHeaders fwd = {'content-length': '10'};
      final t = prepareBodySubstitution(
        (_) => [pair(SENTINEL, REAL)],
        msg('POST'),
        fwd,
        'h',
      );
      expect(t, isNotNull);
      expect(fwd['content-length'], '10');
    });

    test(
      'any non-length-matched pair deletes Content-Length (chunked fallback)',
      () {
        final IncomingHttpHeaders fwd = {'content-length': '10'};
        final t = prepareBodySubstitution(
          (_) => [pair(SENTINEL, REAL), pair('fake_value_odd-size', 'tiny')],
          msg('POST'),
          fwd,
          'h',
        );
        expect(t, isNotNull);
        expect(fwd['content-length'], isNull);
      },
    );
  });
}
