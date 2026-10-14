// Ported from sandbox-runtime test/sandbox/request-rewriting.test.ts @ 24eb39e.
// Dart: a Promise settles once; every `if (!x.isCompleted)` guard below stands for that.
// ignore_for_file: constant_identifier_names, non_constant_identifier_names, slash_for_doc_comments, prefer_interpolation_to_compose_strings, prefer_function_declarations_over_variables, curly_braces_in_flow_control_structures, library_private_types_in_public_api
import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math' as math;

import 'package:path/path.dart' as path;
import 'package:sandbox_runtime/src/node/buffer.dart'
    show Buffer, writeUInt16BE;
import 'package:sandbox_runtime/src/node/fs.dart' show readFileSync;
import 'package:sandbox_runtime/src/node/globals.dart' as globals;
import 'package:sandbox_runtime/src/node/http.dart' as http;
import 'package:sandbox_runtime/src/node/https.dart' as https;
import 'package:sandbox_runtime/src/node/net.dart' as net;
import 'package:sandbox_runtime/src/node/process.dart' as process;
import 'package:sandbox_runtime/src/node/tls.dart' as tls;
import 'package:sandbox_runtime/src/sandbox/http_proxy.dart';
import 'package:sandbox_runtime/src/sandbox/mitm_ca.dart';
import 'package:sandbox_runtime/src/sandbox/mitm_leaf.dart';
import 'package:sandbox_runtime/src/sandbox/mux_proxy.dart';
import 'package:sandbox_runtime/src/sandbox/request_filter.dart';
import 'package:sandbox_runtime/src/sandbox/sandbox_config.dart';
import 'package:sandbox_runtime/src/sandbox/sandbox_manager.dart';
import 'package:sandbox_runtime/src/sandbox/socks_proxy.dart';
import 'package:test/test.dart';

import '../helpers/emitted_connections.dart' show SERVES_EMITTED_CONNECTIONS;

final FIXTURE_DIR = path.join(
  Directory.current.path, // import.meta.dir, '..'
  'test',
  'fixtures',
  'tls-terminate',
);
final CA_CERT = path.join(FIXTURE_DIR, 'ca.crt');
final CA_KEY = path.join(FIXTURE_DIR, 'ca.key');
final CA_PEM = readFileSync(CA_CERT, 'utf8') as String;

typedef Seen = ({String url, http.IncomingHttpHeaders headers, String body});
typedef Reply = ({int status, Map<String, String> headers, String body});

// Dart: upstream's `testWithTls` cannot take a timeout, so each case passes
// skip: _tlsSkip to `test` instead (as resolved_address_guard_test does).
final Object? _tlsSkip = SERVES_EMITTED_CONNECTIONS
    ? null
    : 'TLS termination unavailable';

final List<Seen> seen = [];
late net.NodeServer httpsUpstream;
late net.NodeServer httpUpstream;
late int httpsPort;
late int httpPort;

void upstreamHandler(http.IncomingMessage req, http.ServerResponse res) {
  var body = '';
  req.on('data', (Object? c) => body += utf8.decode(c as List<int>));
  req.on('end', () {
    seen.add((url: req.url ?? '', headers: req.headers, body: body));
    res.writeHead(200, {'set-cookie': 'sid=up', 'x-kept': 'yes'});
    res.end('upstream ok');
  });
}

// Dart: the object literal upstream hands createHttpProxyServer as
// `Partial<HttpProxyServerOptions>`: only the options a case sets.
class _Extra {
  const _Extra({
    this.plaintextHeaderSet,
    this.mutateHeaders,
    this.mutateHeadersPlaintext,
    this.stripResponseHeaders,
    this.refuseOpaqueTunnels,
    this.requireHostMatch,
    this.shouldTerminateTLS,
    this.onFilterRequestDenied,
  });
  final bool? plaintextHeaderSet;
  final MutateForwardedHeaders? mutateHeaders;
  final MutateForwardedHeaders? mutateHeadersPlaintext;
  final List<String>? stripResponseHeaders;
  final bool? refuseOpaqueTunnels;
  final bool? requireHostMatch;
  final bool Function(String hostname, int port)? shouldTerminateTLS;
  final void Function(
    ({String method, String url, String reason, String? encodedCommand}),
  )?
  onFilterRequestDenied;
}

class _HttpOptions implements HttpProxyServerOptions {
  _HttpOptions({
    this.mitmCA,
    this.filterRequest,
    this.tlsTerminateUpstreamCA,
    this.extra = const _Extra(),
  }) {
    shouldTerminateTLS = extra.shouldTerminateTLS;
  }
  final _Extra extra;
  @override
  final MitmCA? mitmCA;
  @override
  final FilterRequestCallback? filterRequest;
  @override
  final dynamic tlsTerminateUpstreamCA;
  @override
  bool Function(String hostname, int port)? shouldTerminateTLS;
  @override
  bool? get plaintextHeaderSet => extra.plaintextHeaderSet;
  @override
  MutateForwardedHeaders? get mutateHeaders => extra.mutateHeaders;
  @override
  MutateForwardedHeaders? get mutateHeadersPlaintext =>
      extra.mutateHeadersPlaintext;
  @override
  List<String>? get stripResponseHeaders => extra.stripResponseHeaders;
  @override
  bool? get refuseOpaqueTunnels => extra.refuseOpaqueTunnels;
  @override
  bool? get requireHostMatch => extra.requireHostMatch;
  @override
  void Function(
    ({String method, String url, String reason, String? encodedCommand}),
  )?
  get onFilterRequestDenied => extra.onFilterRequestDenied;
  @override
  FutureOr<bool> filter(
    int port,
    String host,
    dynamic socket, [
    String? encodedCommand,
    void Function(String reason)? explain,
  ]) => true;
  @override
  dynamic noSuchMethod(Invocation invocation) => null;
}

class _SocksOptions implements SocksProxyServerOptions {
  _SocksOptions({this.refuseOpaqueTunnels, this.onTunnelRefused});
  @override
  final bool? refuseOpaqueTunnels;
  @override
  final void Function(int port, String host, String? encodedCommand)?
  onTunnelRefused;
  @override
  FutureOr<bool> filter(int port, String host, [String? encodedCommand]) =>
      true;
  @override
  dynamic noSuchMethod(Invocation invocation) => null;
}

Future<void> withProxy(
  FilterRequestCallback? filterRequest,
  _Extra extra,
  Future<void> Function(int port) fn,
) async {
  final proxy = createHttpProxyServer(
    _HttpOptions(
      mitmCA: createMitmCA(caCertPath: CA_CERT, caKeyPath: CA_KEY),
      filterRequest: filterRequest,
      tlsTerminateUpstreamCA: CA_PEM,
      extra: extra,
    ),
  );
  final listening = Completer<void>();
  proxy.listen(0, '127.0.0.1', () => listening.complete());
  await listening.future;
  try {
    await fn((proxy.address() as net.NodeAddress).port);
  } finally {
    final closed = Completer<void>();
    proxy.close(() => closed.complete());
    await closed.future;
  }
}

Reply parse(String raw) {
  final [head, ...rest] = raw.split('\r\n\r\n');
  final [statusLine, ...lines] = head.split('\r\n');
  final headers = <String, String>{};
  for (final l in lines) {
    final i = l.indexOf(':');
    if (i > 0)
      headers[l.substring(0, i).toLowerCase()] = l.substring(i + 1).trim();
  }
  var body = rest.join('\r\n\r\n');
  if (RegExp(
    'chunked',
    caseSensitive: false,
  ).hasMatch(headers['transfer-encoding'] ?? '')) {
    var out = '';
    while (body.isNotEmpty) {
      final nl = body.indexOf('\r\n');
      final n =
          int.tryParse(
            body.substring(0, nl < 0 ? body.length - 1 : nl),
            radix: 16,
          ) ??
          0;
      if (n == 0) break;
      out += body.substring(
        math.min(nl + 2, body.length),
        math.min(nl + 2 + n, body.length),
      );
      body = body.substring(math.min(nl + 2 + n + 2, body.length));
    }
    body = out;
  }
  final parts = statusLine.split(' ');
  return (
    status: parts.length > 1 ? int.tryParse(parts[1]) ?? 0 : 0,
    headers: headers,
    body: body,
  );
}

/** Raw request lines: method, target, then header lines (Host included by the caller). */
String requestText(
  String method,
  String target,
  List<String> headers, [
  String body = '',
]) {
  final lines = ['$method $target HTTP/1.1', ...headers, 'Connection: close'];
  if (body.isNotEmpty) lines.add('Content-Length: ${Buffer.byteLength(body)}');
  return lines.join('\r\n') + '\r\n\r\n' + body;
}

/** One absolute-form request to the proxy over plain HTTP. */
Future<Reply> viaPlain(
  int proxyPort,
  String path, [
  List<String> headers = const [],
  String? host,
]) {
  final completer = Completer<Reply>();
  final authority = '127.0.0.1:$httpPort';
  late final net.NodeSocket c;
  c = net.connect({'port': proxyPort, 'host': '127.0.0.1'}, () {
    c.write(
      requestText('GET', 'http://$authority$path', [
        'Host: ${host ?? authority}',
        ...headers,
      ]),
    );
  });
  var raw = '';
  c.on(
    'data',
    (Object? d) => raw += utf8.decode(d as List<int>, allowMalformed: true),
  );
  c.on('error', (Object e) {
    if (!completer.isCompleted) completer.completeError(e);
  });
  c.on('close', () {
    if (!completer.isCompleted) completer.complete(parse(raw));
  });
  return completer.future;
}

const Object _undefined = Object();

/** CONNECT through the proxy, TLS to the terminating proxy, one request inside. */
Future<Reply> viaTls(
  int proxyPort,
  String path, {
  List<String>? headers,
  Object? host = _undefined, // String | null | undefined
  String? servername,
  String? method,
  String? body,
}) {
  final completer = Completer<Reply>();
  final target = '127.0.0.1:$httpsPort';
  late final net.NodeSocket c;
  c = net.connect({'port': proxyPort, 'host': '127.0.0.1'}, () {
    c.write('CONNECT $target HTTP/1.1\r\nHost: $target\r\n\r\n');
  });
  c.on('error', (Object e) {
    if (!completer.isCompleted) completer.completeError(e);
  });
  var head = '';
  void onData(Object? d) {
    head += latin1.decode(d as List<int>);
    if (!head.contains('\r\n\r\n')) return;
    c.off('data', onData);
    if (!head.startsWith('HTTP/1.1 200')) {
      if (!completer.isCompleted) completer.complete(parse(head));
      return;
    }
    final t = tls.connect({
      'socket': c,
      'ca': CA_PEM,
      'servername': servername,
      'checkServerIdentity': (Object? a, Object? b) => null,
      'ALPNProtocols': ['http/1.1'],
    });
    var raw = '';
    t.on('secureConnect', () {
      final hostLine = host == null
          ? <String>[]
          : ['Host: ${identical(host, _undefined) ? target : host}'];
      t.write(
        requestText(method ?? 'GET', path, [
          ...hostLine,
          ...(headers ?? <String>[]),
        ], body ?? ''),
      );
    });
    t.on(
      'data',
      (Object? d) => raw += utf8.decode(d as List<int>, allowMalformed: true),
    );
    t.on('error', (Object e) {
      if (!completer.isCompleted) completer.completeError(e);
    });
    t.on('close', () {
      if (!completer.isCompleted) completer.complete(parse(raw));
    });
  }

  c.on('data', onData);
  return completer.future;
}

Seen lastSeen() => seen[seen.length - 1];

/**
 * Whether this runtime tells an https server which server name the client
 * sent (through SNICallback or the socket), probed on a loopback server.
 */
Future<bool> probeServerNameSupport() async {
  final ca = createMitmCA(caCertPath: CA_CERT, caKeyPath: CA_KEY);
  final leaf = mintLeafCert(ca, 'localhost');
  String? fromCallback;
  Object? fromSocket;
  final server = https.createServer(
    {
      'cert': leaf.certPem,
      'key': leaf.keyPem,
      'SNICallback': (String name, Function cb) {
        fromCallback = name;
        cb(null, null);
      },
    },
    (http.IncomingMessage req, http.ServerResponse res) {
      fromSocket = (req.socket as tls.TLSSocket).servername;
      res.end();
    },
  );
  final listening = Completer<void>();
  server.listen(0, '127.0.0.1', () => listening.complete());
  await listening.future;
  final port = (server.address() as net.NodeAddress).port;
  final done = Completer<void>();
  late final tls.TLSSocket t;
  t = tls.connect(
    {
      'port': port,
      'host': '127.0.0.1',
      'servername': 'localhost',
      'ca': CA_PEM,
    },
    () {
      t.write('GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n');
    },
  );
  t.on('data', () {});
  t.on('error', (_) {
    if (!done.isCompleted) done.complete();
  });
  t.on('close', () {
    if (!done.isCompleted) done.complete();
  });
  await done.future;
  final closed = Completer<void>();
  server.close(() => closed.complete());
  await closed.future;
  return fromCallback == 'localhost' || fromSocket == 'localhost';
}

Future<void> main() async {
  setUpAll(() async {
    final ca = createMitmCA(caCertPath: CA_CERT, caKeyPath: CA_KEY);
    final leaf = mintLeafCert(ca, '127.0.0.1');
    final leafOnly = RegExp(
      r'-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----\r?\n?',
    ).firstMatch(leaf.certPem)!.group(0)!;
    httpsUpstream = https.createServer({
      'cert': leafOnly,
      'key': leaf.keyPem,
    }, upstreamHandler);
    httpUpstream = http.createServer(upstreamHandler);
    final httpsListening = Completer<void>();
    httpsUpstream.listen(0, '127.0.0.1', () => httpsListening.complete());
    await httpsListening.future;
    final httpListening = Completer<void>();
    httpUpstream.listen(0, '127.0.0.1', () => httpListening.complete());
    await httpListening.future;
    httpsPort = (httpsUpstream.address() as net.NodeAddress).port;
    httpPort = (httpUpstream.address() as net.NodeAddress).port;
  });

  tearDownAll(() async {
    final httpsClosed = Completer<void>();
    httpsUpstream.close(() => httpsClosed.complete());
    await httpsClosed.future;
    final httpClosed = Completer<void>();
    httpUpstream.close(() => httpClosed.complete());
    await httpClosed.future;
  });

  final EXPOSES_SERVER_NAME = await probeServerNameSupport();
  // Dart: upstream's `test.skipIf(...)`, as the skip argument of its one use.
  final Object? testIfServerNameSkip =
      !EXPOSES_SERVER_NAME || !SERVES_EMITTED_CONNECTIONS
      ? 'server name or TLS termination unavailable'
      : null;

  group('applyHeaderEdits', () {
    test('removals fold case and the separators - _ and .', () {
      final http.IncomingHttpHeaders h = {
        'x-api-key': 'a',
        'x_api_key': 'b',
        'x.api.key': 'c',
        'X-Other': 'd',
      };
      // Dart: applyHeaderEdits takes a RequestDecision, which needs an action.
      applyHeaderEdits(
        h,
        const RequestDecision(action: 'allow', removeHeaders: ['X-Api-Key']),
      );
      expect(h, {'X-Other': 'd'});
    });
    test(
      'sets replace every spelling, keep repeated values in order, and never touch framing',
      () {
        final http.IncomingHttpHeaders h = {
          'authorization': 'client',
          'host': 'h',
          'content-length': '3',
        };
        applyHeaderEdits(
          h,
          const RequestDecision(
            action: 'allow',
            setHeaders: [
              ('Authorization', 'Bearer x'),
              ('x-multi', '1'),
              ('x-multi', '2'),
              ('host', 'evil'),
              ('content-length', '999'),
              ('x-crlf', 'a\r\nInjected: 1'),
            ],
          ),
        );
        expect(h, {
          'authorization': 'Bearer x',
          'host': 'h',
          'content-length': '3',
          'x-multi': ['1', '2'],
        });
      },
    );
  });

  group('applyHeaderEdits: framing and grouping', () {
    test('framing headers are never removed', () {
      final http.IncomingHttpHeaders h = {
        'host': 'h',
        'content-length': '3',
        'x-a': '1',
      };
      applyHeaderEdits(
        h,
        const RequestDecision(
          action: 'allow',
          removeHeaders: ['Host', 'content_length', 'x-a'],
        ),
      );
      expect(h, {'host': 'h', 'content-length': '3'});
    });
    test(
      'sets are grouped by folded name and emitted under the first spelling',
      () {
        final http.IncomingHttpHeaders h = {};
        applyHeaderEdits(
          h,
          const RequestDecision(
            action: 'allow',
            setHeaders: [('x-foo', 'a'), ('x_foo', 'b'), ('X.Foo', 'c')],
          ),
        );
        expect(h, {
          'x-foo': ['a', 'b', 'c'],
        });
      },
    );
  });

  group('an allow decision rewrites the forwarded request', () {
    // Every case runs a TLS-terminating proxy: skipped where none can run.
    // Dart: upstream's `const test = testWithTls`; see _tlsSkip.
    final FilterRequestCallback rewrite = (_, [_]) async =>
        const RequestDecision(
          action: 'allow',
          removeHeaders: ['x-api-key'],
          setHeaders: [
            ('authorization', 'Bearer from-policy'),
            ('x-added', 'yes'),
          ],
        );

    test(
      'TLS-terminated: removals and sets reach the upstream',
      () async {
        await withProxy(rewrite, const _Extra(), (port) async {
          final r = await viaTls(
            port,
            '/tls',
            headers: [
              'Authorization: Bearer client',
              'X_Api_Key: k',
              'x.api.key: k',
            ],
          );
          expect(r.status, 200);
          final h = lastSeen().headers;
          expect(h['authorization'], 'Bearer from-policy');
          expect(h['x-added'], 'yes');
          expect([
            for (final k in h.keys)
              if (k.replaceAll(RegExp(r'[_.]'), '-') == 'x-api-key') k,
          ], []);
        });
      },
      // Dart: node/tls.dart connect() throws UnimplementedError for the `socket` option.
      tags: ['pending'],
      skip: _tlsSkip,
      timeout: const Timeout(Duration(milliseconds: 15000)),
    );

    test(
      'plain HTTP: an allow with sets is refused unless plaintextHeaderSet',
      () async {
        await withProxy(rewrite, const _Extra(), (port) async {
          final before = seen.length;
          final r = await viaPlain(port, '/plain', [
            'Authorization: Bearer client',
            'X-Api-Key: k',
          ]);
          // The sets cannot be applied in cleartext, so nothing is forwarded.
          expect(r.status, 403);
          expect(seen.length, before);
        });
        await withProxy(rewrite, const _Extra(plaintextHeaderSet: true), (
          port,
        ) async {
          await viaPlain(port, '/plain', ['Authorization: Bearer client']);
          expect(lastSeen().headers['authorization'], 'Bearer from-policy');
          expect(lastSeen().headers['x-added'], 'yes');
        });
      },
      skip: _tlsSkip,
    );

    test('an allow with no edits forwards the request unchanged', () async {
      await withProxy(
        (_, [_]) async => const RequestDecision(action: 'allow'),
        const _Extra(),
        (port) async {
          await viaPlain(port, '/unchanged', ['X-Api-Key: k']);
          expect(lastSeen().headers['x-api-key'], 'k');
        },
      );
    }, skip: _tlsSkip);
  });

  group('a set strips every spelling of its name the client sent', () {
    // Every case runs a TLS-terminating proxy: skipped where none can run.
    final FilterRequestCallback setFoo = (_, [_]) async =>
        const RequestDecision(action: 'allow', setHeaders: [('x-foo', 'real')]);
    final forged = ['x_foo: forged', 'x.foo: forged', 'X-Foo: forged'];
    List<String> fooKeys(http.IncomingHttpHeaders h) => [
      for (final k in h.keys)
        if (k.replaceAll(RegExp(r'[_.]'), '-') == 'x-foo') k,
    ];

    test(
      'TLS-terminated: the upstream receives only the decision value',
      () async {
        await withProxy(setFoo, const _Extra(), (port) async {
          final r = await viaTls(port, '/foo', headers: forged);
          expect(r.status, 200);
          final h = lastSeen().headers;
          expect(fooKeys(h), ['x-foo']);
          expect(h['x-foo'], 'real');
        });
      },
      // Dart: node/tls.dart connect() throws UnimplementedError for the `socket` option.
      tags: ['pending'],
      skip: _tlsSkip,
      timeout: const Timeout(Duration(milliseconds: 15000)),
    );

    test(
      'plain HTTP with plaintextHeaderSet: the upstream receives only the decision value',
      () async {
        await withProxy(setFoo, const _Extra(plaintextHeaderSet: true), (
          port,
        ) async {
          await viaPlain(port, '/foo', forged);
          final h = lastSeen().headers;
          expect(fooKeys(h), ['x-foo']);
          expect(h['x-foo'], 'real');
        });
      },
      skip: _tlsSkip,
    );

    test(
      'plain HTTP with sets off: the request is refused, so no client spelling is forwarded',
      () async {
        await withProxy(setFoo, const _Extra(), (port) async {
          final before = seen.length;
          final r = await viaPlain(port, '/foo', forged);
          expect(r.status, 403);
          expect(seen.length, before);
        });
      },
      skip: _tlsSkip,
    );
  });

  group('edits and the credential hooks, in the same order on both paths', () {
    // Every case runs a TLS-terminating proxy: skipped where none can run.
    // A stand-in for the masked-credential substitution: swaps a sentinel
    // for the real value in any header, as the manager's hook does.
    final MutateForwardedHeaders substitute = (h, _) {
      for (final e in h.entries.toList()) {
        final v = e.value;
        if (v is String) h[e.key] = v.replaceFirst('SENTINEL', 'real-secret');
      }
    };
    final FilterRequestCallback setSentinel = (_, [_]) async =>
        const RequestDecision(
          action: 'allow',
          setHeaders: [('authorization', 'Bearer SENTINEL')],
        );

    test(
      'TLS-terminated: a value the decision sets is substituted by the credential hook',
      () async {
        await withProxy(setSentinel, _Extra(mutateHeaders: substitute), (
          port,
        ) async {
          await viaTls(port, '/cred');
          expect(lastSeen().headers['authorization'], 'Bearer real-secret');
        });
      },
      // Dart: node/tls.dart connect() throws UnimplementedError for the `socket` option.
      tags: ['pending'],
      skip: _tlsSkip,
      timeout: const Timeout(Duration(milliseconds: 15000)),
    );

    test('plain HTTP (sets and plaintext substitution on): the same', () async {
      await withProxy(
        setSentinel,
        _Extra(plaintextHeaderSet: true, mutateHeadersPlaintext: substitute),
        (port) async {
          await viaPlain(port, '/cred');
          expect(lastSeen().headers['authorization'], 'Bearer real-secret');
        },
      );
    }, skip: _tlsSkip);

    test(
      'removing a header the credential hook would fill leaves the hook free to fill it',
      () async {
        await withProxy(
          (_, [_]) async => const RequestDecision(
            action: 'allow',
            removeHeaders: ['authorization'],
          ),
          _Extra(
            mutateHeaders: (h, _) {
              h['authorization'] = 'Bearer injected-after-edits';
            },
          ),
          (port) async {
            await viaTls(
              port,
              '/cred',
              headers: ['Authorization: Bearer client'],
            );
            expect(
              lastSeen().headers['authorization'],
              'Bearer injected-after-edits',
            );
          },
        );
      },
      // Dart: node/tls.dart connect() throws UnimplementedError for the `socket` option.
      tags: ['pending'],
      skip: _tlsSkip,
      timeout: const Timeout(Duration(milliseconds: 15000)),
    );

    test(
      'a multi-value set reaches the upstream as repeated values',
      () async {
        await withProxy(
          (_, [_]) async => const RequestDecision(
            action: 'allow',
            setHeaders: [('x-multi', 'one'), ('x_multi', 'two')],
          ),
          const _Extra(),
          (port) async {
            await viaTls(port, '/multi');
            expect(lastSeen().headers['x-multi'], 'one, two');
          },
        );
      },
      // Dart: node/tls.dart connect() throws UnimplementedError for the `socket` option.
      tags: ['pending'],
      skip: _tlsSkip,
      timeout: const Timeout(Duration(milliseconds: 15000)),
    );
  });

  group('a deny decision chooses its status', () {
    // Every case runs a TLS-terminating proxy: skipped where none can run.
    test(
      'the status and reason reach the client, and nothing is dialled',
      () async {
        final before = seen.length;
        await withProxy(
          (_, [_]) async => const RequestDecision(
            action: 'deny',
            status: 451,
            reason: 'not here',
          ),
          const _Extra(),
          (port) async {
            final tls = await viaTls(port, '/denied');
            expect(tls.status, 451);
            expect(tls.body, contains('not here'));
            expect(tls.headers['x-proxy-error'], 'blocked-by-sandbox-runtime');
            final plain = await viaPlain(port, '/denied');
            expect(plain.status, 451);
          },
        );
        expect(seen.length, before);
      },
      // Dart: node/tls.dart connect() throws UnimplementedError for the `socket` option.
      tags: ['pending'],
      skip: _tlsSkip,
      timeout: const Timeout(Duration(milliseconds: 15000)),
    );

    test('a status outside 400-599, or none, answers 403', () async {
      // Dart: 450.5 is left out; RequestDecision.status is an int?.
      for (final status in <int?>[200, 302, 600, null]) {
        await withProxy(
          (_, [_]) async => RequestDecision(action: 'deny', status: status),
          const _Extra(),
          (port) async {
            expect((await viaPlain(port, '/denied')).status, 403);
          },
        );
      }
    }, skip: _tlsSkip);
  });

  group('TRACE is refused before filterRequest is asked', () {
    // Every case runs a TLS-terminating proxy: skipped where none can run.
    // Its response echoes the request, so a header the decision sets would
    // come back to the client. (TRACK is refused too, but Node's and Bun's
    // HTTP parsers answer it 400 before the proxy sees it.)
    Future<Reply> tracePlain(int port) {
      final completer = Completer<Reply>();
      final authority = '127.0.0.1:$httpPort';
      late final net.NodeSocket c;
      c = net.connect({'port': port, 'host': '127.0.0.1'}, () {
        c.write(
          requestText('TRACE', 'http://$authority/echo', ['Host: $authority']),
        );
      });
      var raw = '';
      c.on(
        'data',
        (Object? d) => raw += utf8.decode(d as List<int>, allowMalformed: true),
      );
      c.on('error', (Object e) {
        if (!completer.isCompleted) completer.completeError(e);
      });
      c.on('close', () {
        if (!completer.isCompleted) completer.complete(parse(raw));
      });
      return completer.future;
    }

    test(
      '405 on plain HTTP and inside a terminated tunnel, and nothing is dialled',
      () async {
        var asked = 0;
        final before = seen.length;
        await withProxy(
          (_, [_]) async {
            asked++;
            return const RequestDecision(
              action: 'allow',
              setHeaders: [('authorization', 'secret')],
            );
          },
          const _Extra(plaintextHeaderSet: true),
          (port) async {
            final tls = await viaTls(port, '/echo', method: 'TRACE');
            expect(tls.status, 405);
            expect(tls.body, contains('the TRACE method is not forwarded'));
            expect(tls.headers['x-proxy-error'], 'blocked-by-sandbox-runtime');
            final plain = await tracePlain(port);
            expect(plain.status, 405);
            expect(plain.body, contains('the TRACE method is not forwarded'));
          },
        );
        expect(asked, 0);
        expect(seen.length, before);
      },
      // Dart: node/tls.dart connect() throws UnimplementedError for the `socket` option.
      tags: ['pending'],
      skip: _tlsSkip,
      timeout: const Timeout(Duration(milliseconds: 15000)),
    );

    test(
      'without filterRequest, TRACE is forwarded as before',
      () async {
        final before = seen.length;
        await withProxy(null, const _Extra(), (port) async {
          final tls = await viaTls(port, '/echo', method: 'TRACE');
          expect(tls.status, 200);
          expect((await tracePlain(port)).status, 200);
        });
        expect(seen.length, before + 2);
      },
      // Dart: node/tls.dart connect() throws UnimplementedError for the `socket` option.
      tags: ['pending'],
      skip: _tlsSkip,
      timeout: const Timeout(Duration(milliseconds: 15000)),
    );
  });

  group('a malformed decision denies', () {
    // Every case runs a TLS-terminating proxy: skipped where none can run.
    // Dart: RequestDecision is typed, so a decision whose fields hold other
    // types (null here) cannot be built; those cases are skipped below.
    final malformed = <(String, RequestDecision?)>[
      ('null', null),
      ('an unknown action', const RequestDecision(action: 'maybe')),
      ('setHeaders that is not an array', null),
      ('a set entry with no value', null),
      ('a set name that is not a string', null),
      (
        'a set name that is not a token',
        const RequestDecision(action: 'allow', setHeaders: [('x foo', 'v')]),
      ),
      (
        'an empty set name',
        const RequestDecision(action: 'allow', setHeaders: [('', 'v')]),
      ),
      (
        'a set value with a control character',
        const RequestDecision(
          action: 'allow',
          setHeaders: [('x-foo', 'a\x01b')],
        ),
      ),
      (
        'a set value with a character above U+00FF',
        const RequestDecision(
          action: 'allow',
          setHeaders: [('x-foo', 'a\u2014b')],
        ),
      ),
      (
        'a set value with CR LF',
        const RequestDecision(
          action: 'allow',
          setHeaders: [('x-foo', 'a\r\nInjected: 1')],
        ),
      ),
      ('removeHeaders that is not an array', null),
      ('a removal that is not a string', null),
      ('a status that is not a number', null),
    ];
    for (final (label, decision) in malformed) {
      test(
        '$label: 403 on both paths and nothing is dialled',
        () async {
          final before = seen.length;
          final FilterRequestCallback filter = (_, [_]) async =>
              decision as RequestDecision;
          await withProxy(filter, const _Extra(plaintextHeaderSet: true), (
            port,
          ) async {
            final tls = await viaTls(port, '/malformed');
            expect(tls.status, 403);
            expect(tls.body, contains('malformed filterRequest decision'));
            final plain = await viaPlain(port, '/malformed');
            expect(plain.status, 403);
            expect(plain.body, contains('malformed filterRequest decision'));
          });
          expect(seen.length, before);
        },
        // Dart: node/tls.dart connect() throws UnimplementedError for the `socket` option.
        tags: ['pending'],
        skip: decision == null
            ? 'RequestDecision is typed; this decision cannot be built'
            : _tlsSkip,
        timeout: const Timeout(Duration(milliseconds: 15000)),
      );
    }

    test(
      'a tab inside a set value is allowed',
      () async {
        await withProxy(
          (_, [_]) async => const RequestDecision(
            action: 'allow',
            setHeaders: [('x-tab', 'a\tb')],
          ),
          const _Extra(),
          (port) async {
            expect((await viaTls(port, '/tab')).status, 200);
            expect(lastSeen().headers['x-tab'], 'a\tb');
          },
        );
      },
      // Dart: node/tls.dart connect() throws UnimplementedError for the `socket` option.
      tags: ['pending'],
      skip: _tlsSkip,
      timeout: const Timeout(Duration(milliseconds: 15000)),
    );

    test(
      'TLS-terminated: a failure after the allow answers 502 instead of hanging',
      () async {
        await withProxy(
          (_, [_]) async => const RequestDecision(action: 'allow'),
          _Extra(
            mutateHeaders: (_, _) {
              throw Exception('hook failed');
            },
          ),
          (port) async {
            final reply = await viaTls(port, '/hook-throws');
            expect(reply.status, 502);
          },
        );
      },
      // Dart: node/tls.dart connect() throws UnimplementedError for the `socket` option.
      tags: ['pending'],
      skip: _tlsSkip,
      timeout: const Timeout(Duration(milliseconds: 15000)),
    );
  });

  group(
    'the callback gets the request details it cannot recover from the Request',
    () {
      // Every case runs a TLS-terminating proxy: skipped where none can run.
      test(
        'TLS-terminated: server name, CONNECT target, request-target and raw headers',
        () async {
          RequestInfo? got;
          await withProxy(
            (_, [info]) async {
              got = info;
              return const RequestDecision(action: 'deny', status: 403);
            },
            const _Extra(),
            (port) async {
              await viaTls(
                port,
                '/a/b?x=1',
                servername: 'localhost',
                headers: ['X_Spelled: 1'],
              );
            },
          );
          // Some runtimes expose no server name to an https server at all.
          expect(got?.sni, EXPOSES_SERVER_NAME ? 'localhost' : null);
          expect(got?.target, (host: '127.0.0.1', port: httpsPort));
          expect(got?.requestTarget, '/a/b?x=1');
          // Some runtimes lower-case rawHeaders names; the spelling of the
          // separators is what matters.
          expect(
            got?.rawHeaders?.map((h) => h.toLowerCase()).toList(),
            containsAll(['x_spelled', '1']),
          );
        },
        // Dart: node/tls.dart connect() throws UnimplementedError for the `socket` option.
        tags: ['pending'],
        skip: _tlsSkip,
        timeout: const Timeout(Duration(milliseconds: 15000)),
      );

      test(
        'plain HTTP: target and the origin form of the absolute request-target',
        () async {
          RequestInfo? got;
          await withProxy(
            (_, [info]) async {
              got = info;
              return const RequestDecision(action: 'deny', status: 403);
            },
            const _Extra(),
            (port) async {
              await viaPlain(port, '/c?y=2', ['X_Spelled: 2']);
            },
          );
          expect(got?.sni, isNull);
          expect(got?.target, (host: '127.0.0.1', port: httpPort));
          expect(got?.requestTarget, '/c?y=2');
          expect(
            got?.rawHeaders?.map((h) => h.toLowerCase()).toList(),
            containsAll(['x_spelled', '2']),
          );
        },
        skip: _tlsSkip,
      );
    },
  );

  group('normalizeRequestTarget', () {
    for (final (raw, want) in [
      ('/a/b?x=1', '/a/b?x=1'),
      ('/public/%2e%2e/admin', '/admin'),
      ('//admin', '/admin'),
      ('///admin?q=1', '/admin?q=1'),
      ('//public/../admin', '/admin'),
      ('https://other.test//x/../y?z', '/y?z'),
      ('http://h.test', '/'),
    ]) {
      test('$raw becomes $want', () {
        expect(normalizeRequestTarget(raw, 'GET'), want);
        // Normalizing twice changes nothing.
        expect(normalizeRequestTarget(want, 'GET'), want);
      });
    }
    for (final (raw, method) in [
      ('@other.test/x', 'GET'),
      ('other.test/x', 'GET'),
      ('ftp://other.test/x', 'GET'),
      ('*', 'GET'),
      ('', 'GET'),
    ]) {
      test('$raw ($method) is refused', () {
        expect(normalizeRequestTarget(raw, method), isNull);
      });
    }
    test('* is accepted for OPTIONS', () {
      expect(normalizeRequestTarget('*', 'OPTIONS'), '*');
    });
  });

  group('the request-target the callback sees is the one forwarded', () {
    // Every case runs a TLS-terminating proxy: skipped where none can run.
    // Each spelling would pass a naive "/public/" prefix rule, or dodge a
    // "/admin" deny rule, if the callback saw it raw while the proxy (or the
    // runtime's HTTP client) forwarded a normalized form.
    final spellings = [
      '/public/%2e%2e/admin',
      '/public/%2E%2E/admin',
      '/public/../admin',
      '/public/./../admin?q=1',
      '/public/..%2fadmin',
      '/public/%2fadmin',
      '//admin',
      '///admin?q=1',
      '//public/../admin',
    ];
    for (final (label, send) in <(String, Future<Reply> Function(int, String))>[
      ('plain HTTP', (port, path) => viaPlain(port, path)),
      ('TLS-terminated', (port, path) => viaTls(port, path)),
    ]) {
      for (final spelling in spellings) {
        test(
          '$label: $spelling',
          () async {
            String? sinkGot;
            final before = seen.length;
            await withProxy(
              (_, [info]) async {
                sinkGot = info?.requestTarget;
                return const RequestDecision(action: 'allow');
              },
              const _Extra(),
              (port) async {
                expect((await send(port, spelling)).status, 200);
              },
            );
            expect(seen.length, before + 1);
            expect(sinkGot, lastSeen().url);
          },
          // Dart: node/tls.dart connect() throws UnimplementedError for the `socket` option.
          tags: label == 'TLS-terminated' ? ['pending'] : null,
          skip: _tlsSkip,
          timeout: const Timeout(Duration(milliseconds: 15000)),
        );
      }
      test(
        '$label: dot segments and leading slashes are normalized before the callback sees them',
        () async {
          String? sinkGot;
          await withProxy(
            (_, [info]) async {
              sinkGot = info?.requestTarget;
              return const RequestDecision(action: 'allow');
            },
            const _Extra(),
            (port) async {
              await send(port, '/public/%2e%2e/admin');
              expect(sinkGot, '/admin');
              expect(lastSeen().url, '/admin');
              await send(port, '//admin');
              expect(sinkGot, '/admin');
              expect(lastSeen().url, '/admin');
            },
          );
        },
        // Dart: node/tls.dart connect() throws UnimplementedError for the `socket` option.
        tags: label == 'TLS-terminated' ? ['pending'] : null,
        skip: _tlsSkip,
        timeout: const Timeout(Duration(milliseconds: 15000)),
      );
    }
  });

  group('a request-target of any other shape is refused with 400', () {
    // Every case runs a TLS-terminating proxy: skipped where none can run.
    test(
      'TLS-terminated: @host, a bare name, a non-http scheme and * without OPTIONS',
      () async {
        var asked = 0;
        final before = seen.length;
        await withProxy(
          (_, [_]) async {
            asked++;
            return const RequestDecision(action: 'allow');
          },
          const _Extra(),
          (port) async {
            for (final (method, target) in [
              ('GET', '@other.test/x'),
              ('GET', 'other.test/x'),
              ('GET', 'ftp://127.0.0.1/x'),
              ('GET', '*'),
            ]) {
              final reply = await viaTls(port, target, method: method);
              // A runtime's HTTP parser may refuse some of these itself and
              // close the connection without a response (status 0).
              expect([0, 400], contains(reply.status));
            }
          },
        );
        expect(asked, 0);
        expect(seen.length, before);
      },
      // Dart: node/tls.dart connect() throws UnimplementedError for the `socket` option.
      tags: ['pending'],
      skip: _tlsSkip,
      timeout: const Timeout(Duration(milliseconds: 15000)),
    );

    test('plain HTTP: a non-http absolute URI', () async {
      var asked = 0;
      await withProxy(
        (_, [_]) async {
          asked++;
          return const RequestDecision(action: 'allow');
        },
        const _Extra(),
        (port) async {
          final reply = await () {
            final completer = Completer<Reply>();
            final authority = '127.0.0.1:$httpPort';
            late final net.NodeSocket c;
            c = net.connect({'port': port, 'host': '127.0.0.1'}, () {
              c.write(
                requestText('GET', 'ftp://$authority/x', ['Host: $authority']),
              );
            });
            var raw = '';
            c.on(
              'data',
              (Object? d) =>
                  raw += utf8.decode(d as List<int>, allowMalformed: true),
            );
            c.on('error', (Object e) {
              if (!completer.isCompleted) completer.completeError(e);
            });
            c.on('close', () {
              if (!completer.isCompleted) completer.complete(parse(raw));
            });
            return completer.future;
          }();
          // Some runtimes' parsers refuse it themselves (status 0).
          expect([0, 400], contains(reply.status));
        },
      );
      expect(asked, 0);
    }, skip: _tlsSkip);
  });

  group('an allow decision can observe the upstream response', () {
    // Every case runs a TLS-terminating proxy: skipped where none can run.
    test(
      'onResponse sees the status and headers before the client does, on both paths',
      () async {
        final got = <({int status, http.IncomingHttpHeaders headers})>[];
        await withProxy(
          (_, [_]) async => RequestDecision(
            action: 'allow',
            onResponse: (status, headers) {
              got.add((status: status, headers: headers));
            },
          ),
          const _Extra(),
          (port) async {
            expect((await viaTls(port, '/observed')).status, 200);
            expect((await viaPlain(port, '/observed')).status, 200);
          },
        );
        expect(got.map((g) => g.status).toList(), [200, 200]);
        for (final g in got) {
          expect(g.headers['x-kept'], 'yes');
          expect(g.headers['set-cookie'], ['sid=up']);
          expect(g.headers['connection'], isNull);
        }
      },
      // Dart: node/tls.dart connect() throws UnimplementedError for the `socket` option.
      tags: ['pending'],
      skip: _tlsSkip,
      timeout: const Timeout(Duration(milliseconds: 15000)),
    );

    test(
      'an onResponse that throws does not disturb the response',
      () async {
        await withProxy(
          (_, [_]) async => RequestDecision(
            action: 'allow',
            onResponse: (_, _) {
              throw Exception('observer failed');
            },
          ),
          const _Extra(),
          (port) async {
            final r = await viaPlain(port, '/observed');
            expect(r.status, 200);
            expect(r.body, 'upstream ok');
            final t = await viaTls(port, '/observed');
            expect(t.status, 200);
            expect(t.body, 'upstream ok');
          },
        );
      },
      // Dart: node/tls.dart connect() throws UnimplementedError for the `socket` option.
      tags: ['pending'],
      skip: _tlsSkip,
      timeout: const Timeout(Duration(milliseconds: 15000)),
    );

    test(
      'an async onResponse that rejects is contained, on both paths',
      () async {
        final unhandled = <Object?>[];
        void onUnhandled(Object? reason) {
          unhandled.add(reason);
        }

        process.on('unhandledRejection', onUnhandled);
        try {
          var calls = 0;
          await withProxy(
            (_, [_]) async => RequestDecision(
              action: 'allow',
              onResponse: (_, _) async {
                calls++;
                throw Exception('async observer failed');
              },
            ),
            const _Extra(),
            (port) async {
              expect((await viaTls(port, '/observed')).status, 200);
              expect((await viaPlain(port, '/observed')).status, 200);
            },
          );
          final waited = Completer<void>();
          globals.setTimeout(() => waited.complete(), 50);
          await waited.future;
          expect(calls, 2);
          expect(unhandled, []);
        } finally {
          process.off('unhandledRejection', onUnhandled);
        }
      },
      // Dart: node/tls.dart connect() throws UnimplementedError for the `socket` option.
      tags: ['pending'],
      skip: _tlsSkip,
      timeout: const Timeout(Duration(milliseconds: 15000)),
    );

    test(
      'onResponse gets a copy: changing it does not change what the client receives',
      () async {
        await withProxy(
          (_, [_]) async => RequestDecision(
            action: 'allow',
            onResponse: (_, headers) {
              (headers['set-cookie'] as List).add('injected=1');
              headers['x-kept'] = 'changed';
            },
          ),
          const _Extra(),
          (port) async {
            for (final reply in [
              await viaTls(port, '/observed'),
              await viaPlain(port, '/observed'),
            ]) {
              expect(reply.headers['set-cookie'], 'sid=up');
              expect(reply.headers['x-kept'], 'yes');
            }
          },
        );
      },
      // Dart: node/tls.dart connect() throws UnimplementedError for the `socket` option.
      tags: ['pending'],
      skip: _tlsSkip,
      timeout: const Timeout(Duration(milliseconds: 15000)),
    );

    test(
      'an onResponse that is not a function denies',
      () async {
        await withProxy(
          (_, [_]) async => const RequestDecision(action: 'allow'),
          const _Extra(),
          (port) async {
            expect((await viaTls(port, '/observed')).status, 403);
            expect((await viaPlain(port, '/observed')).status, 403);
          },
        );
      },
      // Dart: node/tls.dart connect() throws UnimplementedError for the `socket` option.
      tags: ['pending'],
      skip: 'RequestDecision.onResponse is typed; "nope" cannot be built',
      timeout: const Timeout(Duration(milliseconds: 15000)),
    );
  });

  group('stripResponseHeaders', () {
    // Every case runs a TLS-terminating proxy: skipped where none can run.
    test(
      'keeps the listed response headers from the client on both paths',
      () async {
        http.IncomingHttpHeaders? observed;
        await withProxy(
          (_, [_]) async => RequestDecision(
            action: 'allow',
            onResponse: (_, h) {
              observed = h;
            },
          ),
          const _Extra(stripResponseHeaders: ['Set-Cookie']),
          (port) async {
            for (final r in [
              await viaTls(port, '/strip'),
              await viaPlain(port, '/strip'),
            ]) {
              expect(r.status, 200);
              expect(r.headers['set-cookie'], isNull);
              expect(r.headers['x-kept'], 'yes');
            }
          },
        );
        // onResponse sees the upstream's headers before stripping.
        expect(observed?['set-cookie'], ['sid=up']);
      },
      // Dart: node/tls.dart connect() throws UnimplementedError for the `socket` option.
      tags: ['pending'],
      skip: _tlsSkip,
      timeout: const Timeout(Duration(milliseconds: 15000)),
    );
  });

  /** CONNECT to the plain upstream, then speak plain HTTP inside the tunnel. */
  Future<String> plainInsideConnect(int proxyPort) {
    final completer = Completer<String>();
    final target = '127.0.0.1:$httpPort';
    late final net.NodeSocket c;
    c = net.connect({'port': proxyPort, 'host': '127.0.0.1'}, () {
      c.write('CONNECT $target HTTP/1.1\r\nHost: $target\r\n\r\n');
    });
    var raw = '';
    var sent = false;
    c.on('data', (Object? d) {
      raw += utf8.decode(d as List<int>, allowMalformed: true);
      if (!sent && raw.startsWith('HTTP/1.1 200') && raw.contains('\r\n\r\n')) {
        sent = true;
        c.write(requestText('GET', '/tunnelled', ['Host: $target']));
      }
    });
    c.on('error', (_) {
      if (!completer.isCompleted) completer.complete(raw);
    });
    c.on('close', () {
      if (!completer.isCompleted) completer.complete(raw);
    });
    return completer.future;
  }

  group('refuseOpaqueTunnels', () {
    // Every case runs a TLS-terminating proxy: skipped where none can run.
    final FilterRequestCallback allowAll = (_, [_]) async =>
        const RequestDecision(action: 'allow');

    test(
      'by default a non-TLS CONNECT is tunnelled past filterRequest',
      () async {
        var asked = 0;
        final before = seen.length;
        await withProxy(
          (_, [_]) async {
            asked++;
            return const RequestDecision(action: 'allow');
          },
          const _Extra(),
          (port) async {
            final raw = await plainInsideConnect(port);
            expect(raw, contains('upstream ok'));
          },
        );
        expect(asked, 0);
        expect(seen.length, before + 1);
      },
      skip: _tlsSkip,
    );

    test(
      'with it, a non-TLS CONNECT is closed and nothing reaches the upstream',
      () async {
        final before = seen.length;
        await withProxy(allowAll, const _Extra(refuseOpaqueTunnels: true), (
          port,
        ) async {
          final raw = await plainInsideConnect(port);
          expect(raw, isNot(contains('upstream ok')));
        });
        expect(seen.length, before);
      },
      skip: _tlsSkip,
    );

    test('with it and no mitmCA, a CONNECT is refused with 403', () async {
      final proxy = createHttpProxyServer(
        _HttpOptions(extra: const _Extra(refuseOpaqueTunnels: true)),
      );
      final listening = Completer<void>();
      proxy.listen(0, '127.0.0.1', () => listening.complete());
      await listening.future;
      final port = (proxy.address() as net.NodeAddress).port;
      final raw = await plainInsideConnect(port);
      final closed = Completer<void>();
      proxy.close(() => closed.complete());
      await closed.future;
      expect(raw, startsWith('HTTP/1.1 403'));
    }, skip: _tlsSkip);

    test(
      'with it, a CONNECT to a host shouldTerminateTLS exempts is refused with 403',
      () async {
        final refused = <String>[];
        await withProxy(
          allowAll,
          _Extra(
            refuseOpaqueTunnels: true,
            shouldTerminateTLS: (_, _) => false,
            onFilterRequestDenied: (d) => refused.add('${d.method} ${d.url}'),
          ),
          (port) async {
            expect(await plainInsideConnect(port), startsWith('HTTP/1.1 403'));
          },
        );
        expect(refused, ['CONNECT 127.0.0.1:$httpPort']);
      },
      skip: _tlsSkip,
    );
  });

  group('refuseOpaqueTunnels on the shared HTTP and SOCKS port', () {
    // Every case runs a TLS-terminating proxy: skipped where none can run.
    final FilterRequestCallback allowAll = (_, [_]) async =>
        const RequestDecision(action: 'allow');

    /** The manager's front end: one port, sniffed into HTTP or SOCKS. */
    Future<void> withMux(
      bool refuse,
      Future<void> Function(int port, List<String> refusals) fn,
    ) async {
      final refusals = <String>[];
      final httpServer = createHttpProxyServer(
        _HttpOptions(
          mitmCA: createMitmCA(caCertPath: CA_CERT, caKeyPath: CA_KEY),
          filterRequest: allowAll,
          tlsTerminateUpstreamCA: CA_PEM,
          extra: _Extra(
            refuseOpaqueTunnels: refuse,
            onFilterRequestDenied: (d) =>
                refusals.add('http ${d.method} ${d.url}'),
          ),
        ),
      );
      final socks = createSocksProxyServer(
        _SocksOptions(
          refuseOpaqueTunnels: refuse,
          onTunnelRefused: (port, host, _) => refusals.add('socks $host:$port'),
        ),
      );
      final mux = createMuxProxyServer(
        MuxProxyOptions(
          httpServer: httpServer,
          handleSocksConnection: (s) => socks.handleConnection(s),
        ),
      );
      await mux.listenHttpBackend();
      final listening = Completer<void>();
      mux.server.listen(0, '127.0.0.1', () => listening.complete());
      await listening.future;
      try {
        await fn(mux.getPort()!, refusals);
      } finally {
        await socks.close();
        await mux.close();
      }
    }

    /** Everything the proxy sends back, until it closes or 3 s pass. */
    Future<Buffer> exchange(
      int port,
      void Function(net.NodeSocket c) onConnect, [
      void Function(net.NodeSocket c, Buffer all)? onData,
    ]) {
      final completer = Completer<Buffer>();
      final chunks = <List<int>>[];
      late final net.NodeSocket c;
      c = net.connect({'port': port, 'host': '127.0.0.1'}, () => onConnect(c));
      void done() {
        c.destroy();
        if (!completer.isCompleted) completer.complete(Buffer.concat(chunks));
      }

      c.on('data', (Object? d) {
        chunks.add(d as List<int>);
        onData?.call(c, Buffer.concat(chunks));
      });
      c.on('error', (_) => done());
      c.on('close', done);
      globals.setTimeout(done, 3000).unref();
      return completer.future;
    }

    /** SOCKS5, no auth, CONNECT 127.0.0.1:httpPort, then a GET if granted. */
    Future<Buffer> socksConnect(int port) {
      var step = 0;
      return exchange(port, (c) => c.write(Buffer.from([0x05, 0x01, 0x00])), (
        c,
        all,
      ) {
        if (step == 0 && all.length >= 2) {
          step = 1;
          final p = Buffer.alloc(2);
          writeUInt16BE(p, httpPort);
          c.write(
            Buffer.concat([
              Buffer.from([0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1]),
              p,
            ]),
          );
        } else if (step == 1 && all.length >= 12 && all[3] == 0x00) {
          step = 2;
          final target = '127.0.0.1:$httpPort';
          c.write(requestText('GET', '/via-socks', ['Host: $target']));
        }
      });
    }

    test(
      'without it, SOCKS tunnels to an allowed host past filterRequest',
      () async {
        final before = seen.length;
        await withMux(false, (port, _) async {
          final reply = await socksConnect(port);
          expect(reply[3], 0x00);
          expect(reply.toString('latin1'), contains('upstream ok'));
        });
        expect(seen.length, before + 1);
      },
      skip: _tlsSkip,
    );

    test(
      'with it, SOCKS CONNECT to an allowed host is refused at the handshake',
      () async {
        final before = seen.length;
        await withMux(true, (port, refusals) async {
          final reply = await socksConnect(port);
          // Method select [5, 0], then the CONNECT reply: VER 5, REP 1.
          expect(reply.sublist(0, 4), [0x05, 0x00, 0x05, 0x01]);
          expect(reply.length, 12);
          expect(refusals, ['socks 127.0.0.1:$httpPort']);
        });
        expect(seen.length, before);
      },
      skip: _tlsSkip,
    );

    test('with it, an HTTP CONNECT carrying no TLS is still refused', () async {
      final before = seen.length;
      await withMux(true, (port, refusals) async {
        final raw = await plainInsideConnect(port);
        expect(raw, isNot(contains('upstream ok')));
        expect(refusals, ['http CONNECT 127.0.0.1:$httpPort']);
      });
      expect(seen.length, before);
    }, skip: _tlsSkip);

    test(
      'with it, a connection that starts as SOCKS and then speaks HTTP gets nowhere',
      () async {
        final before = seen.length;
        await withMux(true, (port, _) async {
          final target = '127.0.0.1:$httpPort';
          final reply = await exchange(
            port,
            (c) => c.write(
              Buffer.concat([
                Buffer.from([0x05]),
                Buffer.from(
                  'CONNECT $target HTTP/1.1\r\nHost: $target\r\n\r\n' +
                      requestText('GET', '/steered', ['Host: $target']),
                ),
              ]),
            ),
          );
          expect(reply.toString('latin1'), isNot(contains('HTTP/1.1 200')));
          expect(reply.toString('latin1'), isNot(contains('upstream ok')));
        });
        expect(seen.length, before);
      },
      skip: _tlsSkip,
    );

    test(
      'with it, a CONNECT tunnel that then speaks SOCKS gets nowhere',
      () async {
        final before = seen.length;
        await withMux(true, (port, _) async {
          final target = '127.0.0.1:$httpPort';
          var sent = false;
          final reply = await exchange(
            port,
            (c) => c.write('CONNECT $target HTTP/1.1\r\nHost: $target\r\n\r\n'),
            (c, all) {
              if (!sent && all.indexOfBytes('\r\n\r\n') >= 0) {
                sent = true;
                c.write(Buffer.from([0x05, 0x01, 0x00]));
              }
            },
          );
          expect(reply.toString('latin1'), startsWith('HTTP/1.1 200'));
          expect(reply.toString('latin1'), isNot(contains('\x05\x00')));
        });
        expect(seen.length, before);
      },
      skip: _tlsSkip,
    );
  });

  group(
    'hostMismatch: the Host and server-name shapes that name the target',
    () {
      const t = (hostname: 'api.example.test', port: 443, defaultPort: 443);
      for (final (host, sni) in <(List<String>, String?)>[
        (['api.example.test'], null),
        (['API.Example.Test'], null),
        (['api.example.test:443'], null),
        ([], null),
        (['api.example.test'], 'API.example.test'),
      ]) {
        test('accepts Host $host with server name $sni', () {
          expect(hostMismatch([...host], sni, t), isNull);
        });
      }
      test('no port names the target only on the default port', () {
        const on8443 = (
          hostname: 'h.example.test',
          port: 8443,
          defaultPort: 443,
        );
        expect(
          hostMismatch(['h.example.test'], null, on8443),
          matches(RegExp(r'Host header')),
        );
        expect(hostMismatch(['h.example.test:8443'], null, on8443), isNull);
      });
      test('an absolute-form authority must name the target too', () {
        expect(
          hostMismatch(['api.example.test'], null, t, 'api.example.test'),
          isNull,
        );
        expect(
          hostMismatch(['api.example.test'], null, t, 'api.example.test:443'),
          isNull,
        );
        expect(
          hostMismatch(['api.example.test'], null, t, 'other.example.test'),
          matches(RegExp(r'request-target authority')),
        );
        expect(
          hostMismatch(['api.example.test'], null, t, ''),
          matches(RegExp(r'request-target authority')),
        );
      });
      for (final (host, sni, why) in <(List<String>, String?, RegExp)>[
        (['other.example.test'], null, RegExp(r'Host header')),
        (['api.example.test:8443'], null, RegExp(r'Host header')),
        (['api.example.test.'], null, RegExp(r'Host header')),
        (['api.example.test:'], null, RegExp(r'Host header')),
        (['[api.example.test]'], null, RegExp(r'Host header')),
        ([''], null, RegExp(r'Host header')),
        (['api.example.test:0443'], null, RegExp(r'Host header')),
        (['a:b:c'], null, RegExp(r'Host header')),
        (
          ['api.example.test', 'api.example.test'],
          null,
          RegExp(r'more than one'),
        ),
        (['api.example.test'], 'other.example.test', RegExp(r'server name')),
        (['api.example.test'], 'api.example.test.', RegExp(r'server name')),
      ]) {
        test('refuses Host $host with server name $sni', () {
          expect(hostMismatch([...host], sni, t), matches(why));
        });
      }
      test('brackets only around an IPv6 address', () {
        const v6 = (hostname: '::1', port: 8080, defaultPort: 8080);
        expect(hostMismatch(['[::1]:8080'], null, v6), isNull);
        expect(hostMismatch(['[::1]'], null, v6), isNull);
        expect(
          hostMismatch(['[::1]:80'], null, v6),
          matches(RegExp(r'Host header')),
        );
        expect(
          hostMismatch(['::1'], null, v6),
          matches(RegExp(r'Host header')),
        );
      });
    },
  );

  group('requireHostMatch', () {
    // Every case runs a TLS-terminating proxy: skipped where none can run.
    var asked = 0;
    final FilterRequestCallback counting = (_, [_]) async {
      asked++;
      return const RequestDecision(action: 'allow');
    };

    test(
      'TLS-terminated: a Host of another host is answered 421 before filterRequest is asked',
      () async {
        asked = 0;
        final before = seen.length;
        await withProxy(counting, const _Extra(requireHostMatch: true), (
          port,
        ) async {
          expect(
            (await viaTls(port, '/m', host: 'other.example.test')).status,
            421,
          );
          expect(
            (await viaTls(
              port,
              '/m',
              host: '127.0.0.1:${httpsPort + 1}',
            )).status,
            421,
          );
          expect((await viaTls(port, '/m')).status, 200);
        });
        expect(asked, 1);
        expect(seen.length, before + 1);
      },
      // Dart: node/tls.dart connect() throws UnimplementedError for the `socket` option.
      tags: ['pending'],
      skip: _tlsSkip,
      timeout: const Timeout(Duration(milliseconds: 15000)),
    );

    test(
      'TLS-terminated: a server name of another host is answered 421',
      () async {
        asked = 0;
        await withProxy(counting, const _Extra(requireHostMatch: true), (
          port,
        ) async {
          final r = await viaTls(port, '/m', servername: 'evil.example.test');
          expect(r.status, 421);
        });
        expect(asked, 0);
      },
      // Dart: node/tls.dart connect() throws UnimplementedError for the `socket` option.
      tags: ['pending'],
      skip: testIfServerNameSkip,
      timeout: const Timeout(Duration(milliseconds: 15000)),
    );

    test(
      'TLS-terminated: an absolute-form request-target naming another host is answered 421',
      () async {
        asked = 0;
        await withProxy(counting, const _Extra(requireHostMatch: true), (
          port,
        ) async {
          final target = '127.0.0.1:$httpsPort';
          expect(
            (await viaTls(
              port,
              'https://other.example.test/m',
              host: target,
            )).status,
            421,
          );
          expect(
            (await viaTls(port, 'https://$target/m', host: target)).status,
            200,
          );
        });
        expect(asked, 1);
      },
      // Dart: node/tls.dart connect() throws UnimplementedError for the `socket` option.
      tags: ['pending'],
      skip: _tlsSkip,
      timeout: const Timeout(Duration(milliseconds: 15000)),
    );

    test(
      '421 refusals are reported like filterRequest denials',
      () async {
        final denied = <String>[];
        await withProxy(
          counting,
          _Extra(
            requireHostMatch: true,
            onFilterRequestDenied: (d) => denied.add(d.reason),
          ),
          (port) async {
            await viaTls(port, '/m', host: 'other.example.test');
            await viaPlain(port, '/m', [], 'other.example.test');
          },
        );
        expect(denied, [
          'Host header does not match the request target',
          'Host header does not match the request target',
        ]);
      },
      // Dart: node/tls.dart connect() throws UnimplementedError for the `socket` option.
      tags: ['pending'],
      skip: _tlsSkip,
      timeout: const Timeout(Duration(milliseconds: 15000)),
    );

    test(
      'plain HTTP: an IPv6 target matches only its bracketed Host',
      () async {
        final FilterRequestCallback denyAll = (_, [_]) async =>
            const RequestDecision(action: 'deny');
        await withProxy(denyAll, const _Extra(requireHostMatch: true), (
          port,
        ) async {
          Future<Reply> send(String host) {
            final completer = Completer<Reply>();
            late final net.NodeSocket c;
            c = net.connect({'port': port, 'host': '127.0.0.1'}, () {
              c.write(requestText('GET', 'http://[::1]:1/m', ['Host: $host']));
            });
            var raw = '';
            c.on(
              'data',
              (Object? d) =>
                  raw += utf8.decode(d as List<int>, allowMalformed: true),
            );
            c.on('error', (Object e) {
              if (!completer.isCompleted) completer.completeError(e);
            });
            c.on('close', () {
              if (!completer.isCompleted) completer.complete(parse(raw));
            });
            return completer.future;
          }

          expect((await send('::1')).status, 421);
          expect((await send('[::1]')).status, 421);
          // Names the target, so it reaches filterRequest, which denies.
          expect((await send('[::1]:1')).status, 403);
        });
      },
      skip: _tlsSkip,
      timeout: const Timeout(Duration(milliseconds: 15000)),
    );

    test(
      'plain HTTP: a Host of another host is answered 421; without the option it is asked',
      () async {
        asked = 0;
        await withProxy(counting, const _Extra(requireHostMatch: true), (
          port,
        ) async {
          expect(
            (await viaPlain(port, '/m', [], 'other.example.test')).status,
            421,
          );
        });
        expect(asked, 0);
        await withProxy(counting, const _Extra(), (port) async {
          expect(
            (await viaPlain(port, '/m', [], 'other.example.test')).status,
            200,
          );
        });
        expect(asked, 1);
      },
      skip: _tlsSkip,
    );
  });

  group('network config', () {
    test('accepts the rewriting options and rejects bad values', () {
      final base = {'allowedDomains': [], 'deniedDomains': []};
      final ok = NetworkConfigSchema.safeParse({
        ...base,
        'allowPlaintextHeaderSet': false,
        'stripResponseHeaders': ['set-cookie'],
        'refuseOpaqueTunnels': true,
        'requireHostMatch': true,
      });
      expect(ok.success, true);
      expect(
        NetworkConfigSchema.safeParse({
          ...base,
          'stripResponseHeaders': [''],
        }).success,
        false,
      );
      expect(
        NetworkConfigSchema.safeParse({
          ...base,
          'requireHostMatch': 'yes',
        }).success,
        false,
      );
    });
  });

  group(
    'the manager applies refuseOpaqueTunnels to the SOCKS side of its port',
    () {
      tearDownAll(() async {
        await SandboxManager.reset();
      });

      test(
        'an authenticated SOCKS CONNECT to an allowed host is refused at the handshake',
        () async {
          await SandboxManager.initialize(
            SandboxRuntimeConfig(
              network: NetworkConfig(
                allowedDomains: ['allowed.test'],
                deniedDomains: [],
                refuseOpaqueTunnels: true,
              ),
              filesystem: FilesystemConfig(
                denyRead: [],
                allowWrite: [],
                denyWrite: [],
              ),
            ),
          );
          final port = SandboxManager.getProxyPort()!;
          final token = Buffer.from(SandboxManager.getProxyAuthToken()!);
          final host = Buffer.from('allowed.test');
          final reply = await () {
            final completer = Completer<Buffer>();
            final chunks = <List<int>>[];
            late final net.NodeSocket c;
            c = net.connect({'port': port, 'host': '127.0.0.1'}, () {
              c.write(Buffer.from([0x05, 0x01, 0x02]));
              c.write(
                Buffer.concat([
                  Buffer.from([0x01, 3]),
                  Buffer.from('srt'),
                  Buffer.from([token.length]),
                  token,
                ]),
              );
              c.write(
                Buffer.concat([
                  Buffer.from([0x05, 0x01, 0x00, 0x03, host.length]),
                  host,
                  Buffer.from([0x01, 0xbb]),
                ]),
              );
            });
            void done() {
              c.destroy();
              if (!completer.isCompleted) {
                completer.complete(Buffer.concat(chunks));
              }
            }

            c.on('data', (Object? d) => chunks.add(d as List<int>));
            c.on('error', (_) => done());
            c.on('close', done);
            globals.setTimeout(done, 4000).unref();
            return completer.future;
          }();
          // Method select [5, 2], auth status [1, 0], CONNECT reply VER 5 REP 1.
          expect(reply.sublist(0, 6), [5, 2, 1, 0, 5, 1]);
        },
        timeout: const Timeout(Duration(milliseconds: 15000)),
      );
    },
  );
}
