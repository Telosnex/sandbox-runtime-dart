// Ported from sandbox-runtime test/sandbox/request-target-forwarding.test.ts @ 0bbebed.
// ignore_for_file: curly_braces_in_flow_control_structures
library;

// ignore_for_file: constant_identifier_names, non_constant_identifier_names, no_leading_underscores_for_local_identifiers, slash_for_doc_comments
import 'dart:async';
import 'dart:convert';
import 'dart:io' show Directory;
import 'dart:typed_data';

import 'package:sandbox_runtime/src/node/dns.dart' as dns;
import 'package:sandbox_runtime/src/node/fs.dart';
import 'package:sandbox_runtime/src/node/net.dart' as net;
import 'package:sandbox_runtime/src/node/path.dart';
import 'package:sandbox_runtime/src/node/tls.dart' as tls;
import 'package:sandbox_runtime/src/sandbox/http_proxy.dart';
import 'package:sandbox_runtime/src/sandbox/mitm_ca.dart';
import 'package:sandbox_runtime/src/sandbox/mitm_leaf.dart';
import 'package:sandbox_runtime/src/sandbox/request_filter.dart';
import 'package:sandbox_runtime/src/node/buffer.dart';
import 'package:sandbox_runtime/src/node/http.dart' as http;
import 'package:sandbox_runtime/src/node/stream.dart' as stream;
import 'package:sandbox_runtime/src/node/errno.dart';
import 'package:sandbox_runtime/src/node/console.dart' as console;
import 'package:sandbox_runtime/src/node/process.dart' as process;
import 'package:sandbox_runtime/src/sandbox/credential_sentinel.dart';
import 'package:sandbox_runtime/src/sandbox/credential_aws_pairs.dart';
import 'package:sandbox_runtime/src/sandbox/aws_sigv4.dart';
import 'package:sandbox_runtime/src/sandbox/sandbox_manager.dart';
import 'package:sandbox_runtime/src/sandbox/sandbox_config.dart';
import '../helpers/captured_warnings.dart';
import '../helpers/spawn.dart';
import 'package:test/test.dart';

// Every case here runs a proxy configured to terminate TLS, so each is
// skipped where this runtime cannot terminate it in-process.
import '../helpers/emitted_connections.dart' show SERVES_EMITTED_CONNECTIONS;

final FIXTURE_DIR = join(
  Directory.current.path, // import.meta.dir, '..'
  'test',
  'fixtures',
  'tls-terminate',
);
final CA_CERT = join(FIXTURE_DIR, 'ca.crt');
final CA_KEY = join(FIXTURE_DIR, 'ca.key');
final CA_PEM = readFileSync(CA_CERT, 'utf8') as String;

const UPSTREAM_NAME = 'upstream.test';

/** Request target as the client writes it, and as it must reach upstream. */
typedef Case = (String sent, String forwarded);

// TLS-terminated, no filterRequest: origin-form targets go out untouched.
const List<Case> TLS_UNCHANGED = [
  ('/a/../b', '/a/../b'),
  ('/a/./b/%2e%2e/c', '/a/./b/%2e%2e/c'),
  ('/a/%2E%2E/b', '/a/%2E%2E/b'),
  ('//k/x', '//k/x'),
  ('/a?', '/a?'),
  ('/a\\b', '/a\\b'),
  ('/a;p=1/b;q?x=1', '/a;p=1/b;q?x=1'),
  ('/a#frag', '/a#frag'),
];

// Plain HTTP, no filterRequest: the path and query of the parsed absolute
// URI, with a leading `//` kept.
const List<Case> PLAIN_UNCHANGED = [
  ('/a/../b', '/b'),
  ('/a/%2e%2e/b', '/b'),
  ('//k/x', '//k/x'),
  ('/a?', '/a'),
  ('/a\\b', '/a/b'),
  ('/a;p=1/b;q?x=1', '/a;p=1/b;q?x=1'),
];

// With filterRequest. Ambiguous: as spelled, and normalized.
const List<Case> AMBIGUOUS = [
  ('/a/../b', '/b'),
  ('/a/./b', '/a/b'),
  ('/a/..', '/'),
  ('/a/.', '/a/'),
  ('/a/%2e%2e/b', '/b'),
  ('/a/.%2E/b', '/b'),
  ('/a/%2e/b', '/a/b'),
  ('/a;/../b', '/b'),
  ('/a//../b', '/a/b'),
  ('//k/x', '/k/x'),
  ('///k?q=1', '/k?q=1'),
  ('/a\\b', '/a/b'),
  ('/\\k', '/k'),
  // Two kinds at once.
  ('//k/../b', '/b'),
  ('//k\\b', '/k/b'),
  ('/\\/k', '/k'),
  ('/a\\..\\b', '/b'),
  ('/a\\%2e%2e\\b', '/b'),
  ('/a\\b/../c', '/a/c'),
  // One kind, beside the escape of another.
  ('/a%5cb/../c', '/c'),
  ('//k%5cb', '/k%5cb'),
  ('/a%23/../b', '/b'),
  ('/a%23b\\c', '/a%23b/c'),
  ('//k%23', '/k%23'),
];

// A fragment is cut off before anything is read: as sent, and what is left.
const List<Case> FRAGMENT = [
  ('/p#f', '/p'),
  ('/p#', '/p'),
  ('/p#f?q', '/p'),
  ('/p?q#f', '/p?q'),
  ('/p?#f', '/p?'),
  ('/#f', '/'),
  ('/p#f#g', '/p'),
  ('/p%23a#f', '/p%23a'),
  // What would be ambiguous in the path is not, in the fragment.
  ('/p#/../x', '/p'),
  ('/p#\\x', '/p'),
];

// What is left is ambiguous as it would be without one: and normalized.
final FRAGMENT_AMBIGUOUS = [
  ('/a/../b#x', '/a/../b', '/b'),
  ('/a/%2e%2e/b#x', '/a/%2e%2e/b', '/b'),
  ('//k#x', '//k', '/k'),
  ('/a\\b#x', '/a\\b', '/a/b'),
  ('/a\\b/../c?q#x', '/a\\b/../c?q', '/a/c?q'),
];

// Not ambiguous: normalizing leaves them alone, or only escapes a character
// or drops an empty query.
final UNAMBIGUOUS = [
  '/',
  '/a/b/?x=1',
  '/a//b',
  '/a/b//',
  '/a%2Fb',
  '/a%2f..%2fb',
  '/a/..%2fb',
  '/a/%252e%252e/b',
  '/a/...',
  '/a/..b',
  '/a/.hidden',
  '/a/..;/b',
  '/a;p=1/b;q?x=1',
  '/a?x=../y&z=//&w=\\',
  '/%61%7e',
  '/a%zz',
  // The escape of `\\` or `#` is data.
  '/a%5cb',
  '/a%5c..%5cb',
  '/a/..%5cb',
  '/a%23b',
  '/a/..%23',
  '/a/%2e%2e%23',
  '/a?x=%23',
  '/a?',
  '/a??',
  '/a{b}|c^d"e<f>g`h',
  '/a?q=\'x\'&r="y"',
];

void lookup(
  String _hostname,
  dns.LookupOptions options,
  net.LookupCallback callback,
) {
  final all = options.all == true;
  if (all) {
    callback(
      null,
      const dns.LookupResultAll([
        dns.LookupAddress(address: '127.0.0.1', family: 4),
      ]),
    );
  } else {
    callback(null, const dns.LookupResultAddress('127.0.0.1'), 4);
  }
}

/** Records the request target of every request head, off the wire. */
void Function(net.NodeSocket) recordTargets(
  List<String> seen, [
  List<String>? heads,
]) {
  heads ??= [];
  return (socket) {
    var buf = '';
    socket.on('error', () {});
    socket.on('data', (Uint8List chunk) {
      buf += latin1.decode(chunk);
      for (int end; (end = buf.indexOf('\r\n\r\n')) >= 0;) {
        seen.add(buf.substring(0, buf.indexOf('\r\n')).split(' ')[1]);
        heads!.add(buf.substring(0, end));
        buf = buf.substring(end + 4);
        socket.write('HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n');
      }
    });
  };
}

typedef Reply = ({int status, String text});

/** Writes one request head and resolves with the reply, read to its end. */
Future<Reply> exchange(net.NodeSocket socket, String head) {
  final resolve = Completer<Reply>();
  var buf = '';
  socket.on('data', (Uint8List chunk) {
    buf += latin1.decode(chunk);
    if (!buf.contains('\r\n\r\n')) return;
    if (RegExp(
          r'^transfer-encoding: chunked',
          multiLine: true,
          caseSensitive: false,
        ).hasMatch(buf) &&
        !RegExp(r'\r\n0\r\n\r\n$').hasMatch(buf))
      return;
    socket.destroy();
    if (!resolve.isCompleted)
      resolve.complete((
        status: int.parse(
          RegExp(r'^HTTP/1\.1 (\d+)').firstMatch(buf)?[1] ?? '0',
        ),
        text: buf,
      ));
  });
  socket.once('error', (Object e) {
    if (!resolve.isCompleted) resolve.completeError(e);
  });
  socket.once('close', () {
    if (!resolve.isCompleted)
      resolve.completeError(NodeException('closed before a reply'));
  });
  socket.write(latin1.encode(head));
  return resolve.future;
}

// Dart: upstream's object literals, with absent optional properties null.
class _HttpOptions implements HttpProxyServerOptions {
  _HttpOptions(this.values);
  final Map<String, dynamic> values;
  @override
  bool filter(
    int port,
    String host,
    dynamic socket, [
    String? encodedCommand,
    void Function(String reason)? explain,
  ]) => true;
  @override
  dynamic noSuchMethod(Invocation i) {
    final name = i.memberName.toString().split('"')[1];
    return values[name];
  }
}

typedef Sent = ({int status, String text, String? forwarded});

void main() {
  group('request target forwarding', () {
    final ca = createMitmCA(caCertPath: CA_CERT, caKeyPath: CA_KEY);
    final tlsSeen = <String>[];
    final tlsHeads = <String>[];
    final plainSeen = <String>[];
    final hookSeen = <({String url, RequestInfo? info})>[];
    final denied = <({String method, String url, String reason})>[];
    final servers = <net.NodeServer>[];
    late int tlsPort, plainPort, noHookPort;
    /** A proxy with an allow-all hook, by its ambiguousRequestTarget. */
    final hookPort = {
      'default': 0,
      'refuse': 0,
      'asSpelled': 0,
      'normalize': 0,
    };
    late Map<String, dynamic> base;
    Future<int> listen(net.NodeServer server) async {
      servers.add(server);
      final c = Completer<void>();
      server.listen(0, '127.0.0.1', () => c.complete());
      await c.future;
      return (server.address() as net.NodeAddress).port;
    }

    setUpAll(() async {
      final leaf = mintLeafCert(ca, UPSTREAM_NAME);
      final cert = RegExp(
        r'-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----\r?\n?',
      ).firstMatch(leaf.certPem)![0]!;
      tlsPort = await listen(
        tls.createServer({
          'cert': cert,
          'key': leaf.keyPem,
        }, recordTargets(tlsSeen, tlsHeads)),
      );
      plainPort = await listen(net.createServer(recordTargets(plainSeen)));
      base = {
        'mitmCA': ca,
        'tlsTerminateUpstreamCA': CA_PEM,
        'lookupFor': (int port, [String? encodedCommand]) => lookup,
      };
      noHookPort = await listen(createHttpProxyServer(_HttpOptions(base)));
      for (final mode in ['default', 'refuse', 'asSpelled', 'normalize']) {
        hookPort[mode] = await listen(
          createHttpProxyServer(
            _HttpOptions({
              ...base,
              'ambiguousRequestTarget': mode == 'default' ? null : mode,
              'filterRequest': (request, [RequestInfo? info]) async {
                hookSeen.add((url: request.url as String, info: info));
                return const RequestDecision(action: 'allow');
              },
            }),
          ),
        );
      }
    });
    tearDownAll(() async {
      for (final s in servers) {
        final c = Completer<void>();
        s.close(() => c.complete());
        await c.future;
      }
    });

    /** A fresh TLS-terminated tunnel to the upstream. */
    Future<net.NodeSocket> tunnel(int proxyPort) async {
      final authority = '$UPSTREAM_NAME:$tlsPort';
      final r = Completer<net.NodeSocket>();
      late net.NodeSocket socket;
      socket = net.connect(
        proxyPort,
        '127.0.0.1',
        () => socket.write(
          'CONNECT $authority HTTP/1.1\r\nHost: $authority\r\n\r\n',
        ),
      );
      socket.once('error', (Object e) {
        if (!r.isCompleted) r.completeError(e);
      });
      socket.once('data', () => r.complete(socket));
      final raw = await r.future;
      final resolve = Completer<net.NodeSocket>();
      late net.NodeSocket t;
      t = tls.connect({
        'socket': raw,
        'ca': CA_PEM,
        'servername': UPSTREAM_NAME,
      }, () => resolve.complete(t));
      t.once('error', (Object e) {
        if (!resolve.isCompleted) resolve.completeError(e);
      });
      return resolve.future;
    }

    /** One request over a fresh tunnel, and the target upstream saw. */
    Future<Sent> sendTls(
      int proxyPort,
      String target, [
      Object? headers,
    ]) async {
      final authority = '$UPSTREAM_NAME:$tlsPort';
      final t = await tunnel(proxyPort);
      final before = tlsSeen.length;
      final lines = [
        'GET $target HTTP/1.1',
        'Host: $authority',
        ...?headers as List<String>?,
      ];
      final reply = await exchange(t, '${lines.join('\r\n')}\r\n\r\n');
      expect(tlsSeen.length - before, reply.status == 200 ? 1 : 0);
      return (
        status: reply.status,
        text: reply.text,
        forwarded: before < tlsSeen.length ? tlsSeen[before] : null,
      );
    }

    /** One absolute-form GET through the proxy, and the target upstream saw. */
    Future<Sent> sendPlain(
      int proxyPort,
      String target, [
      Object? scheme,
    ]) async {
      scheme ??= 'http://';
      final authority = '127.0.0.1:$plainPort';
      final before = plainSeen.length;
      final head =
          'GET $scheme$authority$target HTTP/1.1\r\nHost: $authority\r\n\r\n';
      final resolve = Completer<net.NodeSocket>();
      late net.NodeSocket s;
      s = net.connect(proxyPort, '127.0.0.1', () => resolve.complete(s));
      s.once('error', (Object e) => resolve.completeError(e));
      final socket = await resolve.future;
      final reply = await exchange(socket, head);
      expect(plainSeen.length - before, reply.status == 200 ? 1 : 0);
      return (
        status: reply.status,
        text: reply.text,
        forwarded: before < plainSeen.length ? plainSeen[before] : null,
      );
    }

    final LEGS = <(String, Future<Sent> Function(int, String, [Object?]))>[
      ('TLS-terminated', sendTls),
      ('plain HTTP', sendPlain),
    ];
    group('no hook: target forwarded unchanged', () {
      for (final (sent, forwarded) in TLS_UNCHANGED) {
        test('TLS-terminated $sent', () async {
          expect((await sendTls(noHookPort, sent)).forwarded, forwarded);
        });
      }
      for (final (sent, forwarded) in PLAIN_UNCHANGED) {
        test('plain HTTP $sent', () async {
          expect((await sendPlain(noHookPort, sent)).forwarded, forwarded);
        });
      }
    });
    for (final (leg, send) in LEGS) {
      group('with a hook, $leg', () {
        // The upstream may act on either form, and the hook has not said that it
        // judged both: neither is sent.
        for (final mode in ['default', 'refuse']) {
          group('%s'.replaceFirst('%s', mode), () {
            for (final (sent, _) in AMBIGUOUS) {
              test('$sent is refused, loudly', () async {
                final asked = hookSeen.length;
                final reply = await send(hookPort[mode]!, sent);
                expect(reply.status, 400);
                expect(
                  reply.text,
                  matches(
                    RegExp(
                      r'^x-proxy-error: ambiguous-request-target\r$',
                      multiLine: true,
                      caseSensitive: false,
                    ),
                  ),
                );
                expect(
                  reply.text,
                  contains(
                    '(network.ambiguousRequestTarget in the sandbox\'s configuration is "refuse")',
                  ),
                );
                expect(reply.forwarded, isNull);
                expect(hookSeen.length, asked);
              });
            }
          });
        }
        for (final (sent, normalized) in AMBIGUOUS) {
          test(
            'asSpelled: $sent goes out as spelled, and the hook gets both forms',
            () async {
              expect(
                (await send(hookPort['asSpelled']!, sent)).forwarded,
                sent,
              );
              expect(hookSeen.last.info?.requestTarget, sent);
              expect(hookSeen.last.info?.normalizedRequestTarget, normalized);
            },
          );
        }
        for (final (sent, normalized) in AMBIGUOUS) {
          test(
            'normalize: $sent goes out as $normalized, and the hook gets both forms',
            () async {
              final reply = await send(hookPort['normalize']!, sent);
              expect(reply.forwarded, normalized);
              expect(hookSeen.last.info?.requestTarget, sent);
              expect(hookSeen.last.info?.normalizedRequestTarget, normalized);
              expect(hookSeen.last.url.endsWith(normalized), true);
            },
          );
        }
        for (final sent in UNAMBIGUOUS) {
          test('$sent goes out byte for byte', () async {
            for (final mode in ['default', 'asSpelled']) {
              expect((await send(hookPort[mode]!, sent)).forwarded, sent);
              expect(hookSeen.last.info?.requestTarget, sent);
            }
            final reply = await send(hookPort['normalize']!, sent);
            expect(
              reply.forwarded,
              hookSeen.last.info?.normalizedRequestTarget,
            );
          });
        }
        // What a rule on request.url alone judges is the parsed URL. By default
        // nothing goes out whose spelling says anything else.
        test(
          'a prefix rule on request.url is not got around in either direction',
          () async {
            final port = await listen(
              createHttpProxyServer(
                _HttpOptions({
                  ...base,
                  'filterRequest': (request, [RequestInfo? info]) async =>
                      RequestDecision(
                        action:
                            Uri.parse(
                              request.url as String,
                            ).path.startsWith('/allowed/')
                            ? 'allow'
                            : 'deny',
                      ),
                }),
              ),
            );
            expect((await send(port, '/allowed/x')).forwarded, '/allowed/x');
            for (final target in [
              '/allowed/../secret',
              '/allowed/%2e%2e/secret',
              '/allowed\\..\\secret',
              '//secret',
              '/secret',
              // Under /secret/ to an upstream that takes the path literally.
              '/secret/../allowed/x',
              '/secret/%2E%2E/allowed/x',
              '/secret\\..\\allowed/x',
            ]) {
              final reply = await send(port, target);
              expect([400, 403], contains(reply.status));
              expect(reply.forwarded, isNull);
            }
          },
        );
        test(
          'asSpelled: a hook can refuse an ambiguous target itself, where and how it likes',
          () async {
            final port = await listen(
              createHttpProxyServer(
                _HttpOptions({
                  ...base,
                  'ambiguousRequestTarget': 'asSpelled',
                  'filterRequest': (_request, [RequestInfo? info]) async =>
                      info!.requestTargetIsAmbiguous == false
                      ? const RequestDecision(action: 'allow')
                      : const RequestDecision(action: 'deny', status: 422),
                }),
              ),
            );
            expect((await send(port, "/a{b}?q='x'")).status, 200);
            expect((await send(port, '/a/../b')).status, 422);
          },
        );
        test('a value that is none of the three refuses', () async {
          final port = await listen(
            createHttpProxyServer(
              _HttpOptions({
                ...base,
                'ambiguousRequestTarget': 'spelled',
                'filterRequest': (_request, [RequestInfo? info]) async =>
                    const RequestDecision(action: 'allow'),
              }),
            ),
          );
          expect((await send(port, '/a/../b')).status, 400);
        });
        void onDenied(
          ({String method, String url, String reason, String? encodedCommand})
          d,
        ) => denied.add((method: d.method, url: d.url, reason: d.reason));
        test(
          'requestTargetAsSpelled: what it refuses is malformed, and reported',
          () async {
            final port = await listen(
              createHttpProxyServer(
                _HttpOptions({
                  ...base,
                  'requestTargetAsSpelled': true,
                  'filterRequest': (_request, [RequestInfo? info]) async =>
                      const RequestDecision(action: 'allow'),
                  'onFilterRequestDenied': onDenied,
                }),
              ),
            );
            denied.clear();
            expect((await send(port, '/a/../b')).forwarded, '/a/../b');
            expect((await send(port, '//k')).status, 400);
            expect(denied.map((d) => d.reason).toList(), [
              'malformed request-target',
            ]);
          },
        );
        // Some clients leave it in the absolute form they send a proxy. An
        // upstream may end the path at it or take it into the path, so no mode
        // sends it, and the hook judges what is sent.
        for (final (sent, left) in FRAGMENT) {
          test('$sent goes out as $left', () async {
            for (final mode in ['default', 'asSpelled', 'normalize']) {
              final reply = await send(hookPort[mode]!, sent);
              final (:url, :info) = hookSeen.last;
              expect(
                reply.forwarded,
                mode == 'normalize' ? info?.normalizedRequestTarget : left,
              );
              expect(info?.requestTarget, left);
              expect(info?.requestTargetIsAmbiguous, false);
              expect(url, isNot(contains('#')));
            }
          });
        }
        for (final (sent, left, normalized) in FRAGMENT_AMBIGUOUS) {
          test('$sent is judged as $left', () async {
            final refused = await send(hookPort['default']!, sent);
            expect(
              refused.text,
              matches(
                RegExp(
                  r'^x-proxy-error: ambiguous-request-target\r$',
                  multiLine: true,
                  caseSensitive: false,
                ),
              ),
            );
            expect((await send(hookPort['asSpelled']!, sent)).forwarded, left);
            final info = hookSeen.last.info!;
            expect(
              (
                info.requestTarget,
                info.normalizedRequestTarget,
                info.requestTargetIsAmbiguous,
              ),
              (left, normalized, true),
            );
            expect(
              (await send(hookPort['normalize']!, sent)).forwarded,
              normalized,
            );
          });
        }
        for (final (sent, shown, reason) in [
          ('/a/../b?q=1', '/a/../b?q=1', 'ambiguous request-target'),
          ('/a/../b?q=1#x', '/a/../b?q=1', 'ambiguous request-target'),
        ]) {
          test(
            'the refusal of $sent is reported like a denial of the hook, and logged',
            () async {
              final port = await listen(
                createHttpProxyServer(
                  _HttpOptions({
                    ...base,
                    'filterRequest': (_request, [RequestInfo? info]) async =>
                        const RequestDecision(action: 'allow'),
                    'onFilterRequestDenied': onDenied,
                    'denyHeader': 'X-Deny-Reason',
                  }),
                ),
              );
              denied.clear();
              final warnings = await withCapturedWarnings(() async {
                final reply = await send(port, sent);
                expect(reply.status, 400);
                expect(
                  reply.text,
                  matches(
                    RegExp(
                      r'^x-deny-reason: bad_request\r$',
                      multiLine: true,
                      caseSensitive: false,
                    ),
                  ),
                );
              });
              expect(warnings.warnings.join('\n'), contains(reason));
              expect(denied, hasLength(1));
              expect(denied[0].method, 'GET');
              expect(
                denied[0].url.replaceFirst(RegExp(r'^https?://[^/]+'), ''),
                shown,
              );
              expect(denied[0].reason, startsWith(reason));
            },
          );
        }
      });
    }
    void onDenied(
      ({String method, String url, String reason, String? encodedCommand}) d,
    ) => denied.add((method: d.method, url: d.url, reason: d.reason));
    for (final (leg, origin) in [
      ('TLS-terminated', 'https://upstream.test:'),
      ('plain HTTP', 'http://127.0.0.1:'),
    ]) {
      test(
        'with a hook, $leg: a target of no known shape is reported too',
        () async {
          final port = await listen(
            createHttpProxyServer(
              _HttpOptions({
                ...base,
                'filterRequest': (_request, [RequestInfo? info]) async =>
                    const RequestDecision(action: 'allow'),
                'onFilterRequestDenied': onDenied,
              }),
            ),
          );
          denied.clear();
          final reply = leg == 'plain HTTP'
              ? await sendPlain(port, '/x', 'http:///')
              : await sendTls(port, 'http:///$UPSTREAM_NAME/x');
          expect(reply.status, 400);
          expect(
            reply.text,
            matches(
              RegExp(
                r'^x-proxy-error: blocked-by-sandbox-runtime\r$',
                multiLine: true,
                caseSensitive: false,
              ),
            ),
          );
          expect(denied, hasLength(1));
          expect(denied[0].url.replaceFirst(RegExp(r'\d+$'), ''), origin);
          expect(denied[0].reason, 'malformed request-target');
        },
      );
    }
    for (final mode in ['default', 'asSpelled', 'normalize']) {
      test(
        'with a hook, $mode: OPTIONS * is judged under its own host, and sent as it is',
        () async {
          final authority = '$UPSTREAM_NAME:$tlsPort';
          final asked = hookSeen.length, arrived = tlsSeen.length;
          final reply = await exchange(
            await tunnel(hookPort[mode]!),
            'OPTIONS * HTTP/1.1\r\nHost: $authority\r\n\r\n',
          );
          expect(reply.status, 200);
          expect(tlsSeen.sublist(arrived), ['*']);
          final seen = hookSeen.sublist(asked).single;
          expect(seen.url, 'https://$authority/');
          expect(seen.info!.requestTarget, '*');
        },
      );
    }
    for (final mode in ['default', 'asSpelled', 'normalize']) {
      test(
        'with a hook, $mode: a fragment right after the authority leaves the root',
        () async {
          for (final rest in ['#x', '#x/y', '#', '#@other.test/x']) {
            final reply = await sendPlain(hookPort[mode]!, rest);
            expect([rest, reply.status, reply.forwarded], [rest, 200, '/']);
          }
        },
      );
    }
    // No request handler sees these: the runtime's HTTP parser gives up on
    // them. Left to itself the tunnel would close without a word.
    group('a request the parser refuses, in a tunnel', () {
      String host() => 'Host: $UPSTREAM_NAME:$tlsPort\r\n';
      const ADVICE =
          'malformed request-target: percent-encode its bytes outside printable ASCII';
      /** Writes the chunks on a fresh tunnel; all it answers, once it closes. */
      Future<String> untilClosed(int proxyPort, List<String> chunks) async {
        final t = await tunnel(proxyPort);
        final closed = Completer<void>();
        t.once('close', () => closed.complete());
        var reply = '';
        t.on('error', () {});
        t.on('data', (Uint8List chunk) => reply += latin1.decode(chunk));
        for (final chunk in chunks) {
          t.write(latin1.encode(chunk));
          await Future<void>.delayed(const Duration(milliseconds: 50));
        }
        await closed.future;
        return reply;
      }

      Future<int> reporting([Map<String, dynamic> extra = const {}]) {
        denied.clear();
        return listen(
          createHttpProxyServer(
            _HttpOptions({
              ...base,
              'filterRequest': (request, [RequestInfo? info]) async {
                hookSeen.add((url: request.url as String, info: info));
                return const RequestDecision(action: 'allow');
              },
              'onFilterRequestDenied': onDenied,
              ...extra,
            }),
          ),
        );
      }

      for (final (sent, shown) in [
        ('/caf\xc3\xa9', '/caf%C3%A9'),
        ('/x?q=caf\xc3\xa9&k=v#f', '/x?q=caf%C3%A9&k=v#f'),
        ('/caf\xe9', '/caf%E9'),
        ('/a\tb\x00c\x7f', '/a%09b%00c%7F'),
      ]) {
        test(
          '$sent is answered 400 with what to do, and reported as $shown',
          () async {
            final port = await reporting();
            final asked = hookSeen.length, arrived = tlsSeen.length;
            final reply = await untilClosed(port, [
              'POST $sent HTTP/1.1\r\n${host()}\r\n',
            ]);
            expect(
              reply,
              'HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\nX-Proxy-Error: blocked-by-sandbox-runtime\r\nContent-Length: ${ADVICE.length + 1}\r\nConnection: close\r\n\r\n$ADVICE\n',
            );
            expect(denied, [
              (
                method: 'POST',
                url: 'https://$UPSTREAM_NAME:$tlsPort$shown',
                reason: ADVICE,
              ),
            ]);
            expect([hookSeen.length, tlsSeen.length], [asked, arrived]);
          },
        );
      }
      for (final (what, line, header) in [
        ('a space in the target', 'GET /a b HTTP/1.1\r\n', ''),
        (
          'a header name with a space',
          'GET /a HTTP/1.1\r\n',
          'Bad Name: x\r\n',
        ),
        ('a control byte in a header', 'GET /a HTTP/1.1\r\n', 'X: a\x01b\r\n'),
        ('a method it does not know', 'FROB /a HTTP/1.1\r\n', ''),
        ('two lengths', 'POST /a HTTP/1.1\r\n', 'Content-Length: 1\r\n' * 2),
        ('a head too long', 'GET /a HTTP/1.1\r\n', 'X: ${'y' * 200000}\r\n'),
      ]) {
        test('$what: 400, and only the tunnel is named', () async {
          final port = await reporting();
          final reply = await untilClosed(port, ['$line${host()}$header\r\n']);
          expect(reply, startsWith('HTTP/1.1 400 Bad Request\r\n'));
          expect(
            reply,
            matches(
              RegExp(r'\r\n\r\nmalformed request \(Parse Error: [ -~]+\)\n$'),
            ),
          );
          expect(RegExp(r'HTTP/1\.1 ').allMatches(reply), hasLength(1));
          expect(denied, hasLength(1));
          expect(
            (denied[0].method, denied[0].url),
            ('-', 'https://$UPSTREAM_NAME:$tlsPort'),
          );
          expect(
            denied[0].reason,
            startsWith('malformed request (Parse Error: '),
          );
        });
      }
      test(
        'it is answered whoever listens, and without a hook, and the tunnel ends at once',
        () async {
          for (final port in [hookPort['default']!, noHookPort]) {
            final began = DateTime.now().millisecondsSinceEpoch;
            expect(
              await untilClosed(port, [
                'GET /\xc3\xa9 HTTP/1.1\r\n${host()}\r\n',
              ]),
              endsWith('$ADVICE\n'),
            );
            expect(
              DateTime.now().millisecondsSinceEpoch - began,
              lessThan(700),
            );
          }
        },
      );
      test('a proxy that marks its refusals marks this one', () async {
        final port = await reporting({'denyHeader': 'X-Deny-Reason'});
        final reply = await untilClosed(port, [
          'GET /\xc3\xa9 HTTP/1.1\r\n${host()}\r\n',
        ]);
        expect(reply, contains('\r\nX-Deny-Reason: bad_request\r\n'));
        expect(
          reply,
          isNot(matches(RegExp('x-proxy-error', caseSensitive: false))),
        );
      });
      test('it leaves a warn-level debug line', () async {
        final result = await withCapturedWarnings(() async {
          await untilClosed(hookPort['default']!, [
            'GET /\xc3\xa9 HTTP/1.1\r\n${host()}\r\n',
          ]);
        });
        expect(result.warnings.join('\n'), contains(ADVICE));
      });
      test('after an answered request it is answered in its turn', () async {
        final port = await reporting();
        final reply = await untilClosed(port, [
          'GET /ok HTTP/1.1\r\n${host()}\r\n',
          'GET /\xc3\xa9 HTTP/1.1\r\n${host()}\r\n',
        ]);
        expect(
          RegExp(r'HTTP/1\.1 \d+').allMatches(reply).map((m) => m[0]).toList(),
          ['HTTP/1.1 200', 'HTTP/1.1 400'],
        );
        expect(denied.map((d) => d.url).toList(), [
          'https://$UPSTREAM_NAME:$tlsPort/%C3%A9',
        ]);
      });
      // The 400 would be read as the answer to the request before it.
      test('behind a request still being answered, nothing is written', () async {
        final port = await reporting();
        final reply = await untilClosed(port, [
          'GET /ok HTTP/1.1\r\n${host()}\r\nGET /\xc3\xa9 HTTP/1.1\r\n${host()}\r\n',
        ]);
        expect(reply, isNot(contains(' 400 ')));
        // The line the parser stopped in, not the packet's first.
        expect(denied.map((d) => d.url).toList(), [
          'https://$UPSTREAM_NAME:$tlsPort/%C3%A9',
        ]);
      });
      test(
        'a client that goes away in the middle of a head is no refusal',
        () async {
          final port = await reporting();
          final oldError = console.error;
          final errors = <String>[];
          console.error = ([a, b, c, d]) {
            errors.add('$a');
          };
          process.env['SRT_DEBUG'] = '1';
          try {
            final t = await tunnel(port);
            t.on('error', () {});
            t.write('GET /a HTTP/1.1\r\n${host()}X: ');
            await Future<void>.delayed(const Duration(milliseconds: 50));
            t.destroy();
            await Future<void>.delayed(const Duration(milliseconds: 100));
            // The server was told, so this is the path that reports nothing.
            expect(
              errors.join('\n'),
              contains('[tls-terminate] client connection error'),
            );
          } finally {
            process.env.remove('SRT_DEBUG');
            console.error = oldError;
          }
          expect(denied, []);
        },
      );
      test('one answer and one report, whatever follows', () async {
        final port = await reporting();
        final bad = 'GET /\xc3\xa9 HTTP/1.1\r\n${host()}\r\n';
        final reply = await untilClosed(port, [bad + bad, bad, bad]);
        expect(RegExp(r'HTTP/1\.1 ').allMatches(reply), hasLength(1));
        expect(denied, hasLength(1));
      });
    });
    test('a refused upload does not keep its tunnel', () async {
      final t = await tunnel(hookPort['default']!);
      final closed = Completer<void>();
      t.once('close', () => closed.complete());
      var reply = '';
      t.on('error', () {});
      t.on('data', (Uint8List chunk) => reply += latin1.decode(chunk));
      // A body announced and never sent: nothing else ends this connection.
      t.write(
        'PUT /a/../b HTTP/1.1\r\nHost: $UPSTREAM_NAME:$tlsPort\r\nContent-Length: 1000000\r\n\r\nstart',
      );
      await closed.future;
      expect(reply, startsWith('HTTP/1.1 400 '));
    }, timeout: const Timeout(Duration(seconds: 3)));
    group('with a hook: an absolute-form target', () {
      test(
        'in a tunnel, its path and query are read like an origin-form target',
        () async {
          final abs = 'https://$UPSTREAM_NAME:$tlsPort';
          expect(
            (await sendTls(hookPort['default']!, '$abs/a//b?x')).forwarded,
            '/a//b?x',
          );
          expect((await sendTls(hookPort['default']!, abs)).forwarded, '/');
          expect(
            (await sendTls(hookPort['default']!, '$abs?x')).forwarded,
            '/?x',
          );
          expect(
            (await sendTls(hookPort['default']!, '$abs/a/../b')).status,
            400,
          );
          expect(
            (await sendTls(hookPort['asSpelled']!, '$abs//a/../b')).forwarded,
            '//a/../b',
          );
          expect(hookSeen.last.info?.normalizedRequestTarget, '/b');
        },
      );
    });
    // The service takes the path literally: `a/../b.txt` is a key, and the
    // signature covers the path as it arrives.
    group('a request signed over its path', () {
      const REAL = (
        accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
        secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
      );
      const SIGNED = [
        ('//lead.txt', '/lead.txt'),
        ('/a/../b.txt', '/b.txt'),
        ('/a/..', '/'),
        ('/bucket/../up.txt', '/up.txt'),
      ];
      const amz = {
        'x-amz-content-sha256': UNSIGNED_PAYLOAD,
        'x-amz-date': '20260101T000000Z',
      };
      String authorizationFor(
        String target,
        ({String accessKeyId, String secretAccessKey}) creds,
      ) => signSigv4(
        Sigv4SignInput(
          method: 'GET',
          requestTarget: target,
          headers: amz,
          hostHeader: '$UPSTREAM_NAME:$tlsPort',
          signedHeaders: ['host', ...amz.keys],
          payloadHash: UNSIGNED_PAYLOAD,
          amzDate: amz['x-amz-date']!,
          scope: (date: '20260101', region: 'us-east-1', service: 's3'),
          accessKeyId: creds.accessKeyId,
          secretAccessKey: creds.secretAccessKey,
        ),
      ).authorization;
      Future<Sent> sendSigned(
        int port,
        String target,
        ({String accessKeyId, String secretAccessKey}) creds,
      ) => sendTls(port, target, [
        ...amz.entries.map((e) => '${e.key}: ${e.value}'),
        'Authorization: ${authorizationFor(target, creds)}',
      ]);
      String? receivedAuthorization() => RegExp(
        r'^authorization: (.*)$',
        caseSensitive: false,
        multiLine: true,
      ).firstMatch(tlsHeads.last)?[1];
      group('by the client', () {
        for (final (sent, _) in SIGNED) {
          test('asSpelled: $sent still verifies', () async {
            final reply = await sendSigned(hookPort['asSpelled']!, sent, REAL);
            expect(reply.forwarded, sent);
            expect(receivedAuthorization(), authorizationFor(sent, REAL));
          });
        }
        for (final (sent, _) in SIGNED) {
          test('default: $sent is refused', () async {
            expect(
              (await sendSigned(hookPort['default']!, sent, REAL)).status,
              400,
            );
          });
        }
        for (final (sent, normalized) in SIGNED) {
          test(
            'normalize: $sent arrives as $normalized, which it is not signed for',
            () async {
              final reply = await sendSigned(
                hookPort['normalize']!,
                sent,
                REAL,
              );
              expect(reply.forwarded, normalized);
              expect(
                receivedAuthorization(),
                isNot(authorizationFor(normalized, REAL)),
              );
            },
          );
        }
      });
      group('again by the proxy, for a masked credential', () {
        final sentinels = SentinelRegistry();
        final pairs = AwsPairRegistry();
        bool eq(String h, String p) => h == p;
        final FAKE = (
          accessKeyId: sentinels.register('AKID', REAL.accessKeyId, [
            UPSTREAM_NAME,
          ]),
          secretAccessKey: sentinels.register('SECRET', REAL.secretAccessKey, [
            UPSTREAM_NAME,
          ]),
        );
        pairs.register(
          AwsCredentialPair(
            accessKeyIdSentinel: FAKE.accessKeyId,
            realAccessKeyId: REAL.accessKeyId,
            realSecretAccessKey: REAL.secretAccessKey,
            injectHosts: [UPSTREAM_NAME],
          ),
        );
        Future<int> resigning(String? ambiguousRequestTarget) => listen(
          createHttpProxyServer(
            _HttpOptions({
              ...base,
              'ambiguousRequestTarget': ambiguousRequestTarget,
              'filterRequest': (_request, [RequestInfo? info]) async =>
                  const RequestDecision(action: 'allow'),
              'mutateHeaders':
                  (http.IncomingHttpHeaders headers, String host) =>
                      sentinels.substituteInHeaders(headers, host, eq),
              'planSigv4': createSigv4Planner(pairs, null, eq),
            }),
          ),
        );
        for (final (sent, _) in SIGNED) {
          test(
            'asSpelled: $sent is signed for the path the client named',
            () async {
              final reply = await sendSigned(
                await resigning('asSpelled'),
                sent,
                FAKE,
              );
              expect(reply.forwarded, sent);
              expect(receivedAuthorization(), authorizationFor(sent, REAL));
            },
          );
        }
        for (final (sent, _) in SIGNED) {
          test('default: $sent is never signed', () async {
            final reply = await sendSigned(await resigning(null), sent, FAKE);
            expect(reply.status, 400);
          });
        }
        for (final (sent, normalized) in SIGNED) {
          test(
            'normalize: $sent is signed for $normalized, the bytes forwarded',
            () async {
              final reply = await sendSigned(
                await resigning('normalize'),
                sent,
                FAKE,
              );
              expect(reply.forwarded, normalized);
              expect(
                receivedAuthorization(),
                authorizationFor(normalized, REAL),
              );
            },
          );
        }
        for (final mode in [null, 'asSpelled', 'normalize']) {
          test(
            '$mode: a fragment is in neither the path sent nor the path signed',
            () async {
              final reply = await sendSigned(
                await resigning(mode),
                '/k.txt#f',
                FAKE,
              );
              expect(reply.forwarded, '/k.txt');
              expect(receivedAuthorization(), authorizationFor('/k.txt', REAL));
            },
          );
        }
      });
    });
    // Bun's listener lets a byte outside ASCII through, decoded. (Node's
    // parser, and Bun's for a tunnel's connection, refuse the request.)
    for (final mode in ['default', 'asSpelled', 'normalize']) {
      group('with a hook, $mode: a byte outside ASCII, plain HTTP', () {
        for (final (sent, encoded) in [
          ('/caf\xc3\xa9?q=caf\xc3\xa9', '/caf%C3%A9?q=caf%C3%A9'),
          ('/\xe2\x82\xac/\xf0\x9f\x98\x80', '/%E2%82%AC/%F0%9F%98%80'),
          ('/\xc3\xa9%c3%a9', '/%C3%A9%c3%a9'),
        ]) {
          test('UTF-8 goes out percent-encoded: $sent', () async {
            expect((await sendPlain(hookPort[mode]!, sent)).forwarded, encoded);
            final info = hookSeen.last.info!;
            expect(
              (
                info.requestTarget,
                info.normalizedRequestTarget,
                info.requestTargetIsAmbiguous,
              ),
              (encoded, encoded, false),
            );
          });
        }
        // U+FFFD stands where they were: percent-encoding that would name
        // another resource.
        for (final sent in ['/caf\xe9', '/a?q=\xe9', '/a\xc3', '/a\xc0\xafb']) {
          test('bytes that are not UTF-8 are refused: $sent', () async {
            final asked = hookSeen.length;
            final reply = await sendPlain(hookPort[mode]!, sent);
            expect(reply.status, 400);
            expect(reply.text, contains('bytes that are not UTF-8'));
            expect(hookSeen.length, asked);
          });
        }
      });
    }
    test(
      'with a hook: a dot segment beside a byte outside ASCII is still ambiguous',
      () async {
        final reply = await sendPlain(hookPort['default']!, '/\xc3\xa9/../b');
        expect(
          reply.text,
          matches(
            RegExp(
              r'^x-proxy-error: ambiguous-request-target\r$',
              caseSensitive: false,
              multiLine: true,
            ),
          ),
        );
      },
    );
  }, skip: SERVES_EMITTED_CONNECTIONS ? false : 'TLS termination unavailable');
  group('readRequestTarget', () {
    for (final (raw, normalized) in AMBIGUOUS) {
      test('$raw is ambiguous', () {
        for (final r in [raw, 'http://h.test:8080$raw']) {
          final refused = readRequestTarget(r, 'GET');
          expect(
            (refused.spelled, refused.normalized, refused.ambiguous),
            (raw, normalized, true),
          );
          expect(refused.forwarded, isNull);
          expect(refused.refusal, startsWith('ambiguous request-target'));
          expect(readRequestTarget(r, 'GET', 'refuse'), refused);
          expect(readRequestTarget(r, 'GET', 'asSpelled'), (
            spelled: raw,
            normalized: normalized,
            ambiguous: true,
            forwarded: raw,
            refusal: null,
          ));
          expect(readRequestTarget(r, 'GET', 'normalize'), (
            spelled: raw,
            normalized: normalized,
            ambiguous: true,
            forwarded: normalized,
            refusal: null,
          ));
        }
      });
    }
    for (final raw in UNAMBIGUOUS) {
      test('$raw is not', () {
        final read = readRequestTarget(raw, 'GET');
        expect(
          (read.spelled, read.ambiguous, read.forwarded, read.refusal),
          (raw, false, raw, null),
        );
      });
    }
    for (final (raw, spelled) in [
      ('*', '*'),
      ('http://h.test', '/'),
      ('HTTPS://u:p@h.test?x', '/?x'),
      ('http://[::1]:80/a?', '/a?'),
      ('/caf\u00e9?q=\u20ac', '/caf%C3%A9?q=%E2%82%AC'),
      ('http://caf\u00e9.test/\u{1f600}', '/%F0%9F%98%80'),
    ]) {
      test('$raw is spelled $spelled', () {
        final read = readRequestTarget(raw, 'OPTIONS');
        expect(
          (read.spelled, read.ambiguous, read.forwarded),
          (spelled, false, spelled),
        );
      });
    }
    // Only an escape the parser ADDS is the same resource: `%2F` is not `/`.
    test('an escape is not its character', () {
      expect(readRequestTarget('/a%7Bb', 'GET').normalized, '/a%7Bb');
      expect(readRequestTarget('/a%5Cb', 'GET').ambiguous, false);
      expect(readRequestTarget('/a%5C../b', 'GET').spelled, '/a%5C../b');
    });
    test('a character that only looks like a dot or a slash is data', () {
      final read = readRequestTarget('/a/\uff0e\uff0e/b\uff0fc', 'GET');
      expect(
        (read.spelled, read.ambiguous),
        ('/a/%EF%BC%8E%EF%BC%8E/b%EF%BC%8Fc', false),
      );
    });
    const MODES = [null, 'refuse', 'asSpelled', 'normalize'];
    for (final (raw, left) in FRAGMENT) {
      test('$raw is read as $left', () {
        for (final mode in MODES) {
          for (final origin in ['', 'http://h.test']) {
            expect(
              readRequestTarget(origin + raw, 'GET', mode),
              readRequestTarget(left, 'GET', mode),
            );
          }
        }
        expect(readRequestTarget(raw, 'GET').forwarded, left);
      });
    }
    for (final (raw, left, _) in FRAGMENT_AMBIGUOUS) {
      test('$raw is read as $left', () {
        for (final mode in MODES) {
          expect(
            readRequestTarget(raw, 'GET', mode),
            readRequestTarget(left, 'GET', mode),
          );
        }
        expect(readRequestTarget(raw, 'GET').ambiguous, true);
      });
    }
    test('what the fragment holds is not read', () {
      for (final fragment in ['\ufffd', '\ud800', '\u00e9', ' ', '\n#']) {
        expect(
          readRequestTarget('/p?q#$fragment', 'GET'),
          readRequestTarget('/p?q', 'GET'),
        );
      }
    });
    for (final (raw, spelled) in [
      ('/caf\ufffd', '/caf%EF%BF%BD'),
      ('/a?q=\ufffd', '/a?q=%EF%BF%BD'),
      ('/\ud800', '/%EF%BF%BD'),
      ('/\udc00x', '/%EF%BF%BDx'),
      ('/\ufffd#x', '/%EF%BF%BD'),
    ]) {
      test('$raw is refused for what the runtime replaced', () {
        for (final mode in MODES) {
          expect(readRequestTarget(raw, 'GET', mode), (
            spelled: spelled,
            normalized: null,
            ambiguous: null,
            forwarded: null,
            refusal:
                'malformed request-target: it holds bytes that are not UTF-8, or U+FFFD',
          ));
        }
      });
    }
    for (final raw in [
      '*', '*x', 'h.test/x', 'http://[::1/x', 'ftp://h.test/x',
      // The URL parser reads another authority, or another path, than the
      // spelling has.
      'http:///h.test/x',
      'http:/h.test/x',
      'http://h.test\\x',
      'http://h.test\\@other.test/x',
      '#x',
      '*#x',
      '/a b',
      '/a\tb',
      '/a\x7f',
    ]) {
      test('$raw has no spelling to forward', () {
        for (final mode in MODES) {
          expect(readRequestTarget(raw, 'GET', mode), (
            spelled: null,
            normalized: null,
            ambiguous: null,
            forwarded: null,
            refusal: 'malformed request-target',
          ));
        }
      });
    }
    // What a client that leaves the fragment in sends for a URL with no path. The
    // URL parser ends the authority at the `#` too.
    for (final raw in [
      'http://h.test#x',
      'http://h.test#x/y',
      'http://h.test#',
      'http://h.test#@other.test/x',
    ]) {
      test('$raw is the root of its authority', () {
        expect(Uri.parse(raw).host, 'h.test');
        for (final mode in MODES) {
          expect(readRequestTarget(raw, 'GET', mode), (
            spelled: '/',
            normalized: '/',
            ambiguous: false,
            forwarded: '/',
            refusal: null,
          ));
        }
      });
    }
  });
  group('refuseUnparsedRequest', () {
    http.NodeHttpError parseError(
      String? packet,
      Object? at, [
      String code = 'HPE_INVALID_URL',
    ]) => http.NodeHttpError(
      code,
      'Parse Error: x',
      rawPacket: packet == null
          ? null
          : Uint8List.fromList(latin1.encode(packet)),
      bytesParsed: at is int ? at : null,
    );
    /** What is reported of a packet the parser stopped in at `at`. */
    String named(String? packet, [Object? at, String? code]) {
      final refused = refuseUnparsedRequest(
        parseError(packet, at, code ?? 'HPE_INVALID_URL'),
        stream.PassThrough(),
        false,
      )!;
      return '${refused.method} ${refused.target}';
    }

    test('the line the parser stopped in, with nothing raw', () {
      expect(named('GET /\xe9 HTTP/1.1\r\nHost: h\r\n\r\n', 5), 'GET /%E9');
      expect(named('M-SEARCH /\xe9 HTTP/1.0\n', 10), 'M-SEARCH /%E9');
      expect(
        named('GET /ok HTTP/1.1\r\n\r\nPUT /\x01<>\x80 HTTP/1.1\r\n', 25),
        'PUT /%01<>%80',
      );
    });
    test('at most 200 bytes of it', () {
      expect(
        named('GET /${'\xe9' * 300} HTTP/1.1\r\n', 5),
        'GET /${'%E9' * 199}',
      );
    });
    for (final (what, packet, at) in <(String, String?, Object?)>[
      ('no packet', null, 5),
      ('no offset', 'GET /\xe9 HTTP/1.1\r\n', null),
      (
        'a line that began in another packet',
        '\xe9 HTTP/1.1\r\nHost: h\r\n',
        0,
      ),
      ('a line that ends in another packet', 'GET /\xe9', 5),
      ('a line whose end is in another packet', 'GET /\xe9 HTTP/1.1', 5),
      ('a method the runtime does not know', 'FROB /\xe9 HTTP/1.1\r\n', 6),
      ('absolute form', 'GET http://o.test/\xe9 HTTP/1.1\r\n', 18),
      ('a space in the target', 'GET /\xe9 b HTTP/1.1\r\n', 5),
      ('another version', 'GET /\xe9 HTTP/2.0\r\n', 5),
      ('a request line further on', '\xe9\nGET /x HTTP/1.1\r\n', 0),
      ('a request line after the byte', '\nGET /\xe9 HTTP/1.1\r\n', 0),
      ('two lines that end like one', 'GET /\xe9\r\nX HTTP/1.1\r\n', 5),
      ('an offset that is no number', 'GET /\xe9 HTTP/1.1\r\n', '5'),
      ('a request line further back', 'GET /x HTTP/1.1\r\nX: \xe9\r\n', 20),
    ]) {
      test('$what: nothing of the packet', () {
        expect(named(packet, at), '- ');
      });
    }
    test('only where it stopped in the target', () {
      const packet = 'GET /x HTTP/1.1\r\nBad Name: y\r\n';
      expect(named(packet, 5, 'HPE_INVALID_HEADER_TOKEN'), '- ');
    });
    test("an error that is not the parser's ends the socket, unanswered", () {
      for (final code in [
        'ECONNRESET',
        'EPIPE',
        'HPE_INVALID_EOF_STATE',
        null,
        7,
      ]) {
        for (final ended in [false, true]) {
          final socket = stream.PassThrough();
          if (ended) socket.end();
          expect(
            refuseUnparsedRequest(
              code is String ? NodeError('x', code: code) : NodeException('x'),
              socket,
              true,
            ),
            isNull,
          );
          expect(socket.destroyed, true);
          expect(socket.readableLength, 0);
        }
      }
    });
    test('what fails the parser after a refusal is the same refusal', () {
      final socket = stream.PassThrough(highWaterMark: 1);
      expect(
        refuseUnparsedRequest(parseError('x', 0), socket, true),
        isNotNull,
      );
      final answer = socket.readableLength;
      final warnings = <String>[];
      final old = console.warn;
      console.warn = ([a, b, c, d]) {
        warnings.add('$a');
      };
      process.env['SRT_DEBUG'] = '1';
      try {
        for (final mayAnswer in [true, false]) {
          expect(
            refuseUnparsedRequest(parseError('x', 0), socket, mayAnswer),
            isNull,
          );
        }
        expect(warnings, []);
      } finally {
        process.env.remove('SRT_DEBUG');
        console.warn = old;
      }
      // The answer is still on its way out.
      expect(socket.destroyed, false);
      expect(socket.readableLength, answer);
    });
    test('the socket is ended at once, and goes a second later', () async {
      final socket = stream.PassThrough(autoDestroy: false);
      socket.resume();
      refuseUnparsedRequest(parseError('x', 0), socket, true);
      expect(socket.writableEnded, true);
      await Future<void>.delayed(const Duration(milliseconds: 500));
      expect(socket.destroyed, false);
      await Future<void>.delayed(const Duration(milliseconds: 700));
      expect(socket.destroyed, true);
    });
    test(
      'no write on a socket that takes none, or where it may not answer',
      () {
        final errored = stream.PassThrough();
        errored.on('error', () {});
        errored.destroy(NodeException('x'));
        for (final (socket, mayAnswer) in [
          (errored, true),
          (stream.PassThrough(), false),
        ]) {
          final before = socket.readableLength;
          expect(
            refuseUnparsedRequest(parseError('x', 0), socket, mayAnswer),
            isNotNull,
          );
          expect(socket.readableLength, before);
          expect(socket.writableEnded, false);
          expect(socket.destroyed, true);
        }
      },
    );
    test("a reset while the answer flushes is nobody's exception", () {
      final socket = stream.PassThrough();
      refuseUnparsedRequest(parseError('x', 0), socket, true);
      expect(
        () => socket.emit('error', NodeException('reset')),
        returnsNormally,
      );
    });
    test('a socket whose flush never ends is destroyed all the same', () async {
      final stuck = stream.PassThrough(highWaterMark: 1);
      stuck.cork();
      refuseUnparsedRequest(parseError('x', 0), stuck, true);
      expect(stuck.destroyed, false);
      await Future<void>.delayed(const Duration(milliseconds: 1100));
      expect(stuck.destroyed, true);
    });
  });
  group('network.ambiguousRequestTarget', () {
    final seen = <String>[];
    final upstream = net.createServer(recordTargets(seen));
    late int port;
    setUpAll(() async {
      final c = Completer<void>();
      upstream.listen(0, '127.0.0.1', () => c.complete());
      await c.future;
      port = (upstream.address() as net.NodeAddress).port;
    });
    tearDownAll(() async {
      await SandboxManager.reset();
      final c = Completer<void>();
      upstream.close(() => c.complete());
      await c.future;
    });
    for (final (ambiguousRequestTarget, status, forwarded)
        in <(String?, int, String?)>[
          (null, 400, null),
          ('refuse', 400, null),
          ('asSpelled', 200, '/a/../b?k=SECRET'),
          ('normalize', 200, '/b?k=SECRET'),
        ]) {
      test('$ambiguousRequestTarget: $status', () async {
        await SandboxManager.reset();
        await SandboxManager.initialize(
          SandboxRuntimeConfig(
            network: NetworkConfig(
              allowedDomains: ['127.0.0.1'],
              deniedDomains: [],
              filterRequest: (_request, [RequestInfo? info]) async =>
                  const RequestDecision(action: 'allow'),
              ambiguousRequestTarget: ambiguousRequestTarget,
            ),
            filesystem: FilesystemConfig(
              denyRead: [],
              allowWrite: [],
              denyWrite: [],
            ),
          ),
        );
        final auth = Buffer.from('srt:${SandboxManager.getProxyAuthToken()}');
        final resolve = Completer<net.NodeSocket>();
        late net.NodeSocket s;
        s = net.connect(
          SandboxManager.getProxyPort()!,
          '127.0.0.1',
          () => resolve.complete(s),
        );
        s.once('error', (Object e) => resolve.completeError(e));
        final socket = await resolve.future;
        final store = SandboxManager.getSandboxViolationStore();
        store.clear();
        seen.clear();
        final reply = await exchange(
          socket,
          'GET http://u:SECRET@127.0.0.1:$port/a/../b?k=SECRET#SECRET HTTP/1.1\r\nHost: 127.0.0.1:$port\r\nProxy-Authorization: Basic ${auth.toString('base64')}\r\n\r\n',
        );
        expect(reply.status, status);
        expect(seen, forwarded == null ? [] : [forwarded]);
        // The line names what was refused, not what it would resolve to.
        expect(
          store
              .getViolations()
              .map((v) => v.line.replaceFirst(RegExp(r' \(.*'), ''))
              .toList(),
          status == 400
              ? ['deny http-request GET http://127.0.0.1:$port/a/../b?…']
              : [],
        );
        expect(
          store.getViolations().map((v) => v.line).join(),
          isNot(contains('SECRET')),
        );
      });
    }
    for (final (sent, shown, reason) in [
      ('/caf\xe9', '/caf%EF%BF%BD', 'bytes that are not UTF-8, or U+FFFD'),
      ('/caf\xe9#t=SECRET', '/caf%EF%BF%BD', 'bytes that are not UTF-8'),
    ]) {
      test('$sent is recorded as $shown', () async {
        await SandboxManager.reset();
        await SandboxManager.initialize(
          SandboxRuntimeConfig(
            network: NetworkConfig(
              allowedDomains: ['127.0.0.1'],
              deniedDomains: [],
              filterRequest: (_request, [RequestInfo? info]) async =>
                  const RequestDecision(action: 'allow'),
              ambiguousRequestTarget: 'asSpelled',
            ),
            filesystem: FilesystemConfig(
              denyRead: [],
              allowWrite: [],
              denyWrite: [],
            ),
          ),
        );
        final auth = Buffer.from('srt:${SandboxManager.getProxyAuthToken()}');
        final resolve = Completer<net.NodeSocket>();
        late net.NodeSocket s;
        s = net.connect(
          SandboxManager.getProxyPort()!,
          '127.0.0.1',
          () => resolve.complete(s),
        );
        s.once('error', (Object e) => resolve.completeError(e));
        final socket = await resolve.future;
        final store = SandboxManager.getSandboxViolationStore();
        store.clear();
        final reply = await exchange(
          socket,
          'GET http://127.0.0.1:$port$sent HTTP/1.1\r\nHost: 127.0.0.1:$port\r\nProxy-Authorization: Basic ${auth.toString('base64')}\r\n\r\n',
        );
        expect(reply.status, 400);
        final lines = store.getViolations().map((v) => v.line).toList();
        expect(lines, hasLength(1));
        expect(
          lines[0],
          startsWith(
            'deny http-request GET http://127.0.0.1:$port$shown (malformed request-target: ',
          ),
        );
        expect(lines[0], contains(reason));
        expect(lines[0], isNot(contains('SECRET')));
      });
    }
    for (final (sent, shown) in [
      ('/caf\xc3\xa9?k=SECRET#SECRET', '/caf%C3%A9?…'),
      ('/caf\xc3\xa9#t=SECRET', '/caf%C3%A9#…'),
    ]) {
      test(
        'in a tunnel, $sent that the parser refuses is recorded as $shown',
        () async {
          await SandboxManager.reset();
          await SandboxManager.initialize(
            SandboxRuntimeConfig(
              network: NetworkConfig(
                allowedDomains: ['127.0.0.1'],
                deniedDomains: [],
                tlsTerminate: TlsTerminateConfig(
                  caCertPath: CA_CERT,
                  caKeyPath: CA_KEY,
                ),
              ),
              filesystem: FilesystemConfig(
                denyRead: [],
                allowWrite: [],
                denyWrite: [],
              ),
            ),
          );
          final auth = Buffer.from('srt:${SandboxManager.getProxyAuthToken()}');
          final resolve = Completer<net.NodeSocket>();
          late net.NodeSocket s;
          s = net.connect(
            SandboxManager.getProxyPort()!,
            '127.0.0.1',
            () => s.write(
              'CONNECT 127.0.0.1:$port HTTP/1.1\r\nHost: 127.0.0.1:$port\r\nProxy-Authorization: Basic ${auth.toString('base64')}\r\n\r\n',
            ),
          );
          s.once('error', (Object e) => resolve.completeError(e));
          s.once('data', () => resolve.complete(s));
          final raw = await resolve.future;
          final secure = Completer<net.NodeSocket>();
          late net.NodeSocket t;
          t = tls.connect({
            'socket': raw,
            'ca': CA_PEM,
            'checkServerIdentity': (String name, dynamic cert) => null,
          }, () => secure.complete(t));
          t.once('error', (Object e) => secure.completeError(e));
          final client = await secure.future;
          final store = SandboxManager.getSandboxViolationStore();
          store.clear();
          final reply = await exchange(
            client,
            'GET $sent HTTP/1.1\r\nHost: 127.0.0.1:$port\r\n\r\n',
          );
          expect(reply.status, 400);
          expect(store.getViolations().map((v) => v.line).toList(), [
            'deny http-request GET https://127.0.0.1:$port$shown (malformed request-target: percent-encode its bytes outside printable ASCII)',
          ]);
        },
      );
    }
    // By a client in a process of its own, busy with its upload: one that shares
    // this event loop reads the answer the moment it is there. And through the
    // manager's proxy, mux and all.
    test('in a tunnel, one with a body on its way still gets its answer', () async {
      await SandboxManager.reset();
      await SandboxManager.initialize(
        SandboxRuntimeConfig(
          network: NetworkConfig(
            allowedDomains: ['127.0.0.1'],
            deniedDomains: [],
            tlsTerminate: TlsTerminateConfig(
              caCertPath: CA_CERT,
              caKeyPath: CA_KEY,
            ),
          ),
          filesystem: FilesystemConfig(
            denyRead: [],
            allowWrite: [],
            denyWrite: [],
          ),
        ),
      );
      final store = SandboxManager.getSandboxViolationStore();
      store.clear();
      final dir = mkdtempSync(
        join(Directory.systemTemp.path, 'refused-upload-'),
      );
      try {
        writeFileSync(join(dir, 'body'), Uint8List(256 << 10));
        for (var n = 0; n < 8; n++) {
          final curl = await spawnAsync('curl', [
            '-sk',
            '-m',
            '10',
            '--noproxy',
            '',
            '-x',
            'http://srt:${SandboxManager.getProxyAuthToken()}@127.0.0.1:${SandboxManager.getProxyPort()}',
            '--data-binary',
            '@${join(dir, 'body')}',
            // As given: what curl makes of such a byte in a URL differs by
            // version.
            '--request-target', '/caf\u00e9', 'https://127.0.0.1:$port/',
          ], const RunOpts(encoding: 'utf8', timeout: 15000));
          expect(
            [curl.status, curl.stdout],
            [
              0,
              'malformed request-target: percent-encode its bytes outside printable ASCII\n',
            ],
          );
        }
        expect(store.getViolations(), hasLength(8));
      } finally {
        rmSync(dir, {'recursive': true, 'force': true});
      }
    }, timeout: const Timeout(Duration(seconds: 60)));
  });
}
