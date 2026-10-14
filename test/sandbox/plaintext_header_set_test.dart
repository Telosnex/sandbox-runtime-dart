// Ported from sandbox-runtime test/sandbox/plaintext-header-set.test.ts @ 24eb39e.
// ignore_for_file: constant_identifier_names, non_constant_identifier_names, no_leading_underscores_for_local_identifiers, slash_for_doc_comments
import 'dart:async';

import 'package:sandbox_runtime/src/node/http.dart'
    as http
    show
        IncomingHttpHeaders,
        IncomingMessage,
        ServerResponse,
        createServer,
        request;
import 'package:sandbox_runtime/src/node/net.dart' show NodeAddress, NodeServer;
import 'package:sandbox_runtime/src/sandbox/http_proxy.dart';
import 'package:sandbox_runtime/src/sandbox/request_filter.dart';
import 'package:test/test.dart';

// Dart: the object literal upstream hands createHttpProxyServer (the
// `Partial<HttpProxyServerOptions>` spread included); every option not named
// here is absent (null).
class _HttpOptions implements HttpProxyServerOptions {
  _HttpOptions({
    this.filterRequest,
    this.onFilterRequestDenied,
    this.plaintextHeaderSet,
  });
  @override
  final FilterRequestCallback? filterRequest;
  @override
  final void Function(
    ({String method, String url, String reason, String? encodedCommand}),
  )?
  onFilterRequestDenied;
  @override
  final bool? plaintextHeaderSet;
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

// Header sets on the plain-HTTP path: an allow decision whose setHeaders
// cannot be applied (cleartext, opt-in off) must be refused, never forwarded
// without them.

final List<http.IncomingHttpHeaders> received = [];
late NodeServer upstream;
late int upstreamPort;

typedef Reply = ({int status, String body});

/** One absolute-form GET through a proxy built with the given decision. */
Future<Reply> getThroughProxy(
  RequestDecision decision, {
  void Function(
    ({String method, String url, String reason, String? encodedCommand}),
  )?
  onFilterRequestDenied,
  bool? plaintextHeaderSet,
  void Function(RequestInfo? info)? onInfo,
}) async {
  final proxy = createHttpProxyServer(
    _HttpOptions(
      filterRequest: (_req, [info]) async {
        onInfo?.call(info);
        return decision;
      },
      onFilterRequestDenied: onFilterRequestDenied,
      plaintextHeaderSet: plaintextHeaderSet,
    ),
  );
  final listening = Completer<void>();
  proxy.listen(0, '127.0.0.1', () => listening.complete());
  await listening.future;
  final proxyPort = (proxy.address() as NodeAddress).port;
  try {
    final completer = Completer<Reply>();
    final req = http.request(
      {
        'host': '127.0.0.1',
        'port': proxyPort,
        'path': 'http://127.0.0.1:$upstreamPort/resource',
        'headers': {
          'host': '127.0.0.1:$upstreamPort',
          'authorization': 'Bearer from-client',
          'x-api-key': 'client-key',
          'connection': 'close',
        },
      },
      (http.IncomingMessage res) {
        var body = '';
        res.setEncoding('utf8');
        res.on('data', (Object? chunk) => body += chunk as String);
        res.on(
          'end',
          () => completer.complete((status: res.statusCode ?? 0, body: body)),
        );
      },
    );
    req.on('error', (Object e) => completer.completeError(e));
    req.end();
    return await completer.future;
  } finally {
    final closed = Completer<void>();
    proxy.close(() => closed.complete());
    await closed.future;
  }
}

const allowWithSet = RequestDecision(
  action: 'allow',
  setHeaders: [('authorization', 'Bearer from-policy')],
);

void main() {
  setUpAll(() async {
    upstream =
        http.createServer((http.IncomingMessage req, http.ServerResponse res) {
              received.add(req.headers);
              res.end('ok');
            })
            as NodeServer;
    final listening = Completer<void>();
    upstream.listen(0, '127.0.0.1', () => listening.complete());
    await listening.future;
    upstreamPort = (upstream.address() as NodeAddress).port;
  });

  tearDownAll(() async {
    final closed = Completer<void>();
    upstream.close(() => closed.complete());
    await closed.future;
  });

  group('plain HTTP: allow decisions that set headers', () {
    test(
      'opt-in off: the request is refused and nothing reaches the upstream',
      () async {
        final before = received.length;
        final denied = <String>[];
        final reply = await getThroughProxy(
          allowWithSet,
          onFilterRequestDenied: (info) => denied.add(info.reason),
        );
        expect(reply.status, 403);
        expect(reply.body, contains('plain-HTTP'));
        expect(received.length, before);
        expect(denied, hasLength(1));
        expect(denied[0], contains('sets headers'));
      },
    );

    test('opt-in on: the upstream receives the set header', () async {
      final before = received.length;
      final reply = await getThroughProxy(
        allowWithSet,
        plaintextHeaderSet: true,
      );
      expect(reply.status, 200);
      expect(received.length, before + 1);
      expect(received.last['authorization'], 'Bearer from-policy');
    });

    test(
      'opt-in off: an allow with no sets is forwarded, removals applied',
      () async {
        final before = received.length;
        final reply = await getThroughProxy(
          const RequestDecision(action: 'allow', removeHeaders: ['x-api-key']),
        );
        expect(reply.status, 200);
        expect(received.length, before + 1);
        expect(received.last['authorization'], 'Bearer from-client');
        expect(received.last['x-api-key'], isNull);
      },
    );

    test('opt-in off: an empty setHeaders list is forwarded', () async {
      final before = received.length;
      final reply = await getThroughProxy(
        const RequestDecision(action: 'allow', setHeaders: []),
      );
      expect(reply.status, 200);
      expect(received.length, before + 1);
    });

    test("the callback is told the request arrived as 'http'", () async {
      final schemes = <String?>[];
      await getThroughProxy(
        const RequestDecision(action: 'allow'),
        onInfo: (info) => schemes.add(info?.scheme),
      );
      expect(schemes, equals(['http']));
    });
  });
}
