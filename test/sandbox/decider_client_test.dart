// Ported from sandbox-runtime test/sandbox/decider-client.test.ts @ 24eb39e.
// ignore_for_file: constant_identifier_names, non_constant_identifier_names, slash_for_doc_comments
import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:sandbox_runtime/src/node/buffer.dart' show Buffer;
import 'package:sandbox_runtime/src/node/fetch.dart' as fetch;
import 'package:sandbox_runtime/src/node/stream.dart' as stream;
import 'package:sandbox_runtime/src/sandbox/decider_client.dart'
    show
        CredentialPlacementBasic,
        DeciderOptions,
        createDecider,
        encodeFrame,
        isEgressEntry,
        reqFrameFields;
import 'package:sandbox_runtime/src/sandbox/request_filter.dart'
    show RequestDecision, RequestInfo;
import 'package:test/test.dart';

import '../helpers/fake_decider.dart' show Frame, fakeDecider, frameOf;

// Dart: `toMatchObject(expected)`, for what a decider answers.
Matcher _toMatchObject(Map<String, Object?> expected) =>
    predicate<Object?>((got) {
      final d = got as RequestDecision;
      return (expected['action'] == null || d.action == expected['action']) &&
          (expected['status'] == null || d.status == expected['status']) &&
          (expected['mark'] == null || d.mark == expected['mark']);
    }, 'matches $expected');

// Dart: `d.streams` and `d.seen` of the Map fakeDecider returns.
Map<String, Object> _streams(Map<String, Object> d) =>
    d['streams']! as Map<String, Object>;
List<Frame> _seen(Map<String, Object> d) => d['seen']! as List<Frame>;

// Dart: `{ ...d.streams, ... }` handed to createDecider.
DeciderOptions _options(
  Map<String, Object> d, {
  int? timeoutMs,
  List<CredentialPlacementBasic>? credentialPlacements,
  void Function(String why)? onDead,
}) {
  final s = _streams(d);
  return DeciderOptions(
    input: s['input']! as stream.Readable,
    output: s['output']! as stream.Writable,
    timeoutMs: timeoutMs,
    credentialPlacements: credentialPlacements,
    onDead: onDead,
  );
}

void main() {
  group('the decider link', () {
    test(
      'violations kill the link: an unknown id, a duplicate key, a credential header in setHeaders, an empty optional',
      () async {
        final cases = <(String, Uint8List Function(Frame f))>[
          (
            'unknown id',
            (f) => frameOf(
              jsonEncode({
                't': 'verdict',
                'id': (f['id'] as num) + 7,
                'action': 'deny',
                'status': 403,
              }),
            ),
          ),
          (
            'duplicate key',
            (f) => frameOf(
              '{"t":"verdict","id":${f['id']},"action":"deny","status":403,"status":404}',
            ),
          ),
          (
            'credential header set',
            (f) => frameOf(
              jsonEncode({
                't': 'verdict',
                'id': f['id'],
                'action': 'allow',
                'setHeaders': {
                  'authorization': ['Bearer x'],
                },
              }),
            ),
          ),
          (
            'empty optional',
            (f) => frameOf(
              jsonEncode({
                't': 'verdict',
                'id': f['id'],
                'action': 'allow',
                'removeHeaders': [],
              }),
            ),
          ),
          (
            'a field the protocol does not have',
            (f) => frameOf(
              jsonEncode({
                't': 'verdict',
                'id': f['id'],
                'action': 'allow',
                'extra': true,
              }),
            ),
          ),
          (
            'credential header set in another spelling',
            (f) => frameOf(
              jsonEncode({
                't': 'verdict',
                'id': f['id'],
                'action': 'allow',
                'setHeaders': {
                  'x_api_key': ['k'],
                },
              }),
            ),
          ),
          (
            'framing header removed',
            (f) => frameOf(
              jsonEncode({
                't': 'verdict',
                'id': f['id'],
                'action': 'allow',
                'removeHeaders': ['content-length'],
              }),
            ),
          ),
          (
            'credential class without a value',
            (f) => frameOf(
              jsonEncode({
                't': 'verdict',
                'id': f['id'],
                'action': 'allow',
                'cred': 'session-token',
              }),
            ),
          ),
          (
            'status as a string',
            (f) => frameOf(
              '{"t":"verdict","id":${f['id']},"action":"deny","status":"403"}',
            ),
          ),
          (
            'C1 control in a reason',
            (f) => frameOf(
              jsonEncode({
                't': 'verdict',
                'id': f['id'],
                'action': 'deny',
                'status': 403,
                'reason': 'a\u0085b',
              }),
            ),
          ),
          (
            'upper-case header name',
            (f) => frameOf(
              jsonEncode({
                't': 'verdict',
                'id': f['id'],
                'action': 'allow',
                'setHeaders': {
                  'X-A': ['1'],
                },
              }),
            ),
          ),
          (
            'credential with spaces',
            (f) => frameOf(
              jsonEncode({
                't': 'verdict',
                'id': f['id'],
                'action': 'allow',
                'cred': 'c',
                'credential': ' v ',
              }),
            ),
          ),
          (
            'null',
            (f) => frameOf(
              '{"t":"verdict","id":${f['id']},"action":"deny","status":403,"reason":null}',
            ),
          ),
        ];
        for (final (name, make) in cases) {
          final toProxy = stream.PassThrough();
          final fromProxy = stream.PassThrough();
          var hello = false;
          // Dart: the Buffer shim has no readUInt32BE or subarray; readUIntBE and sublist do the same.
          var buf = Buffer.alloc(0);
          fromProxy.on('data', (Object? c) {
            buf = Buffer.concat([buf, Buffer.wrap(c as Uint8List)]);
            while (buf.length >= 4 && buf.length >= 4 + buf.readUIntBE(0, 4)) {
              final f =
                  jsonDecode(
                        Buffer.from(
                          buf.sublist(4, 4 + buf.readUIntBE(0, 4)),
                        ).toString(),
                      )
                      as Frame;
              buf = Buffer.from(buf.sublist(4 + buf.readUIntBE(0, 4)));
              if (!hello) {
                hello = true;
                toProxy.write(
                  frameOf(
                    jsonEncode({
                      't': 'hello',
                      'proto': 1,
                      'allowedDomains': [],
                      'deniedDomains': [],
                    }),
                  ),
                );
              } else {
                toProxy.write(make(f));
              }
            }
          });
          final dead = <String>[];
          final decider = createDecider(
            DeciderOptions(
              input: toProxy,
              output: fromProxy,
              timeoutMs: 1000,
              onDead: (why) => dead.add(why),
            ),
          );
          await decider.hello;
          final v = await decider.filterRequest(
            fetch.Request('https://api.example.test/x'),
          );
          expect(
            v,
            _toMatchObject({'action': 'deny', 'status': 503}),
            reason: name,
          );
          expect(dead, hasLength(1), reason: name);
        }
      },
    );

    test(
      'an output stream that closes without an error kills the link',
      () async {
        final d = fakeDecider([], (_) => {'action': 'allow'});
        final dead = <String>[];
        final decider = createDecider(
          _options(d, onDead: (why) => dead.add(why)),
        );
        await decider.hello;
        // As Node's socket on the output descriptor ends up when the peer closes
        // its reading end: destroyed, with no error for a later write to report.
        final closed = Completer<void>();
        (_streams(d)['output']! as stream.Writable).once(
          'close',
          () => closed.complete(),
        );
        (_streams(d)['output']! as stream.Writable).destroy();
        await closed.future;
        expect(dead, equals(['decider closed the output stream']));
        expect(
          await decider.filterRequest(
            fetch.Request('https://api.example.test/x'),
            const RequestInfo(target: (host: 'api.example.test', port: 443)),
          ),
          _toMatchObject({
            'action': 'deny',
            'status': 503,
            'mark': 'decider_unavailable',
          }),
        );
        expect(_seen(d), hasLength(0));
      },
    );

    test(
      'a credential must be 1 to 8 KiB of printable ASCII without spaces, taken as is',
      () async {
        final bad = [
          '',
          'a b',
          'a\tb',
          'ab\r\nX-Evil: 1',
          'a\u0085b',
          '\u00e9',
          'x' * 8193,
        ];
        for (final credential in bad) {
          final d = fakeDecider(
            [],
            (_) => {
              'action': 'allow',
              'cred': 'session-token',
              'credential': credential,
            },
          );
          final dead = <String>[];
          final decider = createDecider(
            _options(d, onDead: (why) => dead.add(why)),
          );
          await decider.hello;
          final v = await decider.filterRequest(
            fetch.Request('https://api.example.test/x'),
            const RequestInfo(target: (host: 'api.example.test', port: 443)),
          );
          expect(
            v,
            _toMatchObject({'action': 'deny', 'status': 503}),
            reason: jsonEncode(
              credential.substring(
                0,
                credential.length < 20 ? credential.length : 20,
              ),
            ),
          );
          expect(dead, hasLength(1));
        }
        final d = fakeDecider(
          [],
          (_) => {
            'action': 'allow',
            'cred': 'session-token',
            'credential': '~' * 8192,
          },
        );
        final decider = createDecider(_options(d));
        await decider.hello;
        final v = await decider.filterRequest(
          fetch.Request('https://api.example.test/x'),
          const RequestInfo(target: (host: 'api.example.test', port: 443)),
        );
        expect(
          v.setHeaders,
          contains(('authorization', 'Bearer ${'~' * 8192}')),
        );
        decider.close();
      },
    );

    test(
      'credential placement: Bearer by default, Basic x-access-token for github on github.com',
      () async {
        for (final (host, want) in [
          ('api.github.com', 'Bearer tok'),
          (
            'github.com',
            'Basic ${Buffer.from('x-access-token:tok').toString('base64')}',
          ),
        ]) {
          final d = fakeDecider(
            [],
            (_) => {'action': 'allow', 'cred': 'github', 'credential': 'tok'},
          );
          final decider = createDecider(
            _options(
              d,
              credentialPlacements: const [
                CredentialPlacementBasic(
                  credentialClass: 'github',
                  host: 'github.com',
                  user: 'x-access-token',
                ),
              ],
            ),
          );
          await decider.hello;
          final v = await decider.filterRequest(
            fetch.Request('https://$host/x'),
            RequestInfo(target: (host: host, port: 443)),
          );
          expect(v.setHeaders, contains(('authorization', want)));
          expect(
            v.removeHeaders,
            containsAll([
              'authorization',
              'proxy-authorization',
              'cookie',
              'x-api-key',
            ]),
          );
          decider.close();
        }
      },
    );

    test(
      'the req frame carries the TLS server name when the proxy knows it',
      () async {
        final d = fakeDecider([], (_) => {'action': 'deny', 'status': 403});
        final decider = createDecider(_options(d, timeoutMs: 2000));
        await decider.hello;
        await decider.filterRequest(
          fetch.Request('https://api.example.test/x'),
          const RequestInfo(sni: 'api.example.test'),
        );
        await decider.filterRequest(
          fetch.Request('https://api.example.test/y'),
        );
        expect(_seen(d)[0], containsPair('t', 'req'));
        expect(_seen(d)[0], containsPair('sni', 'api.example.test'));
        expect(_seen(d)[1].containsKey('sni'), false);
        decider.close();
      },
    );

    test(
      "the decider's hello must be exactly proto 1 and both egress lists",
      () async {
        final hellos = <Map<String, Object?>>[
          {
            't': 'hello',
            'proto': 1,
            'allowedDomains': [],
            'deniedDomains': [],
            'extra': [],
          },
          {'t': 'hello', 'proto': 2, 'allowedDomains': [], 'deniedDomains': []},
          {'t': 'hello', 'proto': 1, 'allowedDomains': []},
          {
            't': 'hello',
            'proto': 1,
            'allowedDomains': ['Example.test'],
            'deniedDomains': [],
          },
          {
            't': 'hello',
            'proto': 1,
            'allowedDomains': ['a.test', 'a.test'],
            'deniedDomains': [],
          },
          {'t': 'verdict', 'id': 1, 'action': 'deny', 'status': 403},
        ];
        for (final h in hellos) {
          final toProxy = stream.PassThrough();
          final fromProxy = stream.PassThrough();
          fromProxy.once('data', (_) => toProxy.write(encodeFrame(h)));
          final dead = <String>[];
          final decider = createDecider(
            DeciderOptions(
              input: toProxy,
              output: fromProxy,
              onDead: (why) => dead.add(why),
            ),
          );
          await expectLater(
            decider.hello,
            throwsA(anything),
            reason: jsonEncode(h),
          );
          expect(dead, equals(['bad hello']), reason: jsonEncode(h));
        }
      },
    );
  });

  group('reqFrameFields: the decider limits, counted in UTF-8 bytes', () {
    Object at(String target, [List<String> rawHeaders = const []]) =>
        reqFrameFields(
          fetch.Request('https://api.example.test/'),
          RequestInfo(
            target: (host: 'api.example.test', port: 443),
            requestTarget: target,
            rawHeaders: ['Host', 'api.example.test', ...rawHeaders],
          ),
        );
    test(
      'a 2 MiB query is refused (the whole frame past 1 MiB); a 900 KiB one is not',
      () {
        expect(at('/x?${'q' * (2 * 1024 * 1024)}'), isA<String>());
        expect(at('/x?${'q' * (900 * 1024)}'), isA<Map<String, Object?>>());
      },
    );
    test(
      'a path of 8 KiB in bytes passes; one byte more, in two-byte characters, does not',
      () {
        expect(
          at('/${'\u00e9' * 4095}a'),
          isA<Map<String, Object?>>(),
        ); // 1 + 8190 + 1 = 8192 bytes
        expect(
          at('/${'\u00e9' * 4096}'),
          isA<String>(),
        ); // 8193 bytes, 4097 UTF-16 units
      },
    );
    test(
      'header bytes: 64 KiB of names and values, each name counted once',
      () {
        final big = '\u00e9' * 32767; // 65534 bytes, 32767 UTF-16 units
        expect(at('/', ['x-a', big]), isA<String>()); // 3 + 65534 > 65536
        expect(
          at('/', ['x', big]),
          isA<Map<String, Object?>>(),
        ); // 1 + 65534 <= 65536
        final name = 'n' * 2000;
        final many = <String>[];
        for (var i = 0; i < 40; i++) {
          many.addAll([name, 'v' * 10]);
        }
        expect(
          at('/', many),
          isA<Map<String, Object?>>(),
        ); // 2000 + 400, not 40 * 2010
      },
    );
    test('header values: at most 190, Host apart', () {
      List<String> vals(int n) => [
        for (var i = 0; i < n; i++) ...['x-v', '$i'],
      ];
      expect(at('/', vals(190)), isA<Map<String, Object?>>());
      expect(at('/', vals(191)), isA<String>());
    });
    test('control characters in a header value, C1 included, are refused', () {
      expect(at('/', ['x-a', 'a\u0085b']), isA<String>());
      expect(at('/', ['x-a', 'a\tb']), isA<Map<String, Object?>>());
    });
  });

  group('isEgressEntry: the entries of the decider hello', () {
    for (final entry in [
      'api.example.test',
      'api.example.test:443',
      '*.example.test',
      '*.example.test:8443',
      '127.0.0.1',
      '127.0.0.1:80',
      '::1',
      '[::1]:443',
      '[2001:db8::1]',
    ]) {
      test('accepts ${jsonEncode(entry)}', () {
        expect(isEgressEntry(entry), true);
      });
    }
    for (final entry in [
      '',
      '*',
      '*.test',
      'Api.example.test',
      'https://api.example.test',
      'api.example.test/x',
      'api.example.test:0',
      'api.example.test:65536',
      'api.example.test:',
      '[api.example.test]:443',
      '-a.example.test',
      'example.123',
      '1.2.3',
    ]) {
      test('refuses ${jsonEncode(entry)}', () {
        expect(isEgressEntry(entry), false);
      });
    }
  });

  group('verdicts past the protocol limits kill the link', () {
    test('setHeaders past 190 values, removeHeaders past 190 names', () async {
      List<String> tooMany(int n) => [for (var i = 0; i < n; i++) 'x-h-$i'];
      for (final (label, v, ok) in <(String, Map<String, Object?>, bool)>[
        ('190 removals', {'removeHeaders': tooMany(190)}, true),
        ('191 removals', {'removeHeaders': tooMany(191)}, false),
        (
          '190 set values',
          {
            'setHeaders': {'x-s': tooMany(190)},
          },
          true,
        ),
        (
          '191 set values',
          {
            'setHeaders': {'x-s': tooMany(191)},
          },
          false,
        ),
      ]) {
        final d = fakeDecider([], (_) => {'action': 'allow', ...v});
        final dead = <String>[];
        final decider = createDecider(
          _options(d, onDead: (why) => dead.add(why)),
        );
        await decider.hello;
        final got = await decider.filterRequest(
          fetch.Request('https://api.example.test/x'),
          const RequestInfo(target: (host: 'api.example.test', port: 443)),
        );
        expect(got.action, ok ? 'allow' : 'deny', reason: label);
        expect(dead, hasLength(ok ? 0 : 1), reason: label);
        decider.close();
      }
    });
  });

  group('need_body on a body longer than max', () {
    test(
      'one branch of a tee whose other branch is still open: cut at max and decided at once',
      () async {
        // As decideAndRespond hands it over: the request body is one branch of a
        // tee, and the other (for the upstream) is not read until the verdict.
        final source = fetch.ReadableStream<Uint8List>(
          start: (c) {
            for (var i = 0; i < 32; i++) {
              c.enqueue(Uint8List(64 << 10));
            }
          },
        );
        final [forDecider, forUpstream] = source.tee();
        forUpstream;
        final d = fakeDecider(
          [],
          (f) => f['t'] == 'req'
              ? {'action': 'need_body', 'max': 1 << 20}
              : {'action': 'allow'},
        );
        final decider = createDecider(_options(d));
        await decider.hello;
        final verdict = await decider.filterRequest(
          fetch.Request(
            'https://api.example.test/x',
            method: 'POST',
            body: forDecider,
            duplex: 'half',
          ),
          const RequestInfo(target: (host: 'api.example.test', port: 443)),
        );
        expect(verdict.action, 'allow');
        final body = _seen(d).firstWhere((f) => f['t'] == 'body');
        expect(body['cut'], true);
        expect(Buffer.from(body['data'].toString(), 'base64').length, 1 << 20);
        decider.close();
      },
      timeout: const Timeout(Duration(milliseconds: 10000)),
    );
  });

  group('each deny says where it came from (its mark)', () {
    test(
      'the decider, the proxy past the limits, and the decider unavailable',
      () async {
        final d = fakeDecider([], (_) => {'action': 'deny', 'status': 403});
        final decider = createDecider(_options(d));
        await decider.hello;
        const info = RequestInfo(target: (host: 'api.example.test', port: 443));
        expect(
          await decider.filterRequest(
            fetch.Request('https://api.example.test/x'),
            info,
          ),
          _toMatchObject({'action': 'deny', 'status': 403, 'mark': 'decider'}),
        );
        expect(
          await decider.filterRequest(
            fetch.Request('https://api.example.test/'),
            RequestInfo(
              target: info.target,
              requestTarget: '/${'a' * (9 << 10)}',
            ),
          ),
          _toMatchObject({
            'action': 'deny',
            'status': 400,
            'mark': 'bad_request',
          }),
        );
        decider.close();
        expect(
          await decider.filterRequest(
            fetch.Request('https://api.example.test/x'),
            info,
          ),
          _toMatchObject({
            'action': 'deny',
            'status': 503,
            'mark': 'decider_unavailable',
          }),
        );
      },
    );
  });
}
