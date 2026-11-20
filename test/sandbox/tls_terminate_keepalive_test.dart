// Ported from sandbox-runtime test/sandbox/tls-terminate-keepalive.test.ts @ 0bbebed.
// ignore_for_file: slash_for_doc_comments, prefer_function_declarations_over_variables
library;

// ignore_for_file: non_constant_identifier_names
import 'dart:async';
import 'package:sandbox_runtime/src/sandbox/tls_terminate_proxy.dart'
    show PartialTunnelTimeouts;
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:path/path.dart' as path;
import 'package:test/test.dart';

// Every case here runs a proxy configured to terminate TLS, so each is
// skipped where this runtime cannot terminate it in-process.
import '../helpers/emitted_connections.dart' show canServeEmittedConnections;
import 'package:sandbox_runtime/src/node/https.dart' as https;
import 'package:sandbox_runtime/src/node/net.dart'
    show connect, LookupFunction, NodeAddress, NodeServer, NodeSocket;
import 'package:sandbox_runtime/src/node/dns.dart'
    show LookupAddress, LookupResultAddress, LookupResultAll;
import 'package:sandbox_runtime/src/node/stream.dart' as stream;
import 'package:sandbox_runtime/src/node/tls.dart'
    as tls_
    show connect, TLSSocket;
import 'package:sandbox_runtime/src/sandbox/http_proxy.dart';
import 'package:sandbox_runtime/src/sandbox/mitm_ca.dart';
import 'package:sandbox_runtime/src/sandbox/mitm_leaf.dart';
import 'package:sandbox_runtime/src/sandbox/body_substitution.dart'
    show GetBodySubstitutions;
import 'package:sandbox_runtime/src/sandbox/credential_aws_pairs.dart'
    show PlanSigv4;
import 'package:sandbox_runtime/src/sandbox/emitted_connection.dart'
    show ByteBudget;
import 'package:sandbox_runtime/src/sandbox/parent_proxy.dart'
    show DirectLookup, ResolvedParentProxy;
import 'package:sandbox_runtime/src/sandbox/request_filter.dart';

// Committed test-only CA — see test/fixtures/tls-terminate/README.md.
final FIXTURE_DIR = path.join(
  Directory.current.path,
  'test',
  'fixtures',
  'tls-terminate',
);
final CA_CERT = path.join(FIXTURE_DIR, 'ca.crt');
final CA_KEY = path.join(FIXTURE_DIR, 'ca.key');
final CA_PEM = File(CA_CERT).readAsStringSync();

// ignore: constant_identifier_names
const UPSTREAM_NAME = 'keepalive.localhost';

typedef Reply = ({int status, String body});

/**
 * CONNECT through the proxy and complete the TLS handshake against the
 * terminating leaf. The returned socket is one client connection.
 */
Future<tls_.TLSSocket> openTunnel(int proxyPort, String host, int port) {
  final completer = Completer<tls_.TLSSocket>();
  final resolve = completer.complete;
  final reject = completer.completeError;
  late final NodeSocket raw;
  raw = connect(proxyPort, '127.0.0.1', () {
    raw.write('CONNECT $host:$port HTTP/1.1\r\nHost: $host:$port\r\n\r\n');
  });
  raw.once('error', reject);
  raw.once('data', () {
    late final tls_.TLSSocket tls;
    tls = tls_.connect({
      'socket': raw,
      'ca': CA_PEM,
      'servername': host,
    }, () => resolve(tls));
    tls.once('error', reject);
  });
  return completer.future;
}

/**
 * One GET on an open client connection. Resolves with the parsed reply, or
 * 'closed' if the connection ended before a full reply arrived.
 */
Future<Object> get(tls_.TLSSocket tls, String path) {
  final completer = Completer<Object>();
  final resolve = completer.complete;
  var buf = '';
  late void Function(Uint8List) onData;
  late void Function() onClose;
  void finish(Object r) {
    tls.removeListener('data', onData);
    tls.removeListener('close', onClose);
    tls.removeListener('error', onClose);
    resolve(r);
  }

  onClose = () => finish('closed');
  onData = (Uint8List chunk) {
    buf += latin1.decode(chunk);
    final sep = buf.indexOf('\r\n\r\n');
    if (sep < 0) return;
    final head = buf.substring(0, sep);
    final status = int.parse(
      RegExp(r'^HTTP/1\.1 (\d+)').firstMatch(head)?.group(1) ?? '0',
    );
    final length = int.parse(
      RegExp(
            r'^content-length: (\d+)',
            caseSensitive: false,
            multiLine: true,
          ).firstMatch(head)?.group(1) ??
          '0',
    );
    final body = buf.substring(sep + 4);
    if (body.length >= length) {
      finish((status: status, body: body.substring(0, length)));
    }
  };

  tls.on('data', onData);
  tls.once('close', onClose);
  tls.once('error', onClose);
  tls.write('GET $path HTTP/1.1\r\nHost: $UPSTREAM_NAME\r\n\r\n');
  return completer.future;
}

// Dart: the object literal upstream hands createHttpProxyServer.
class _HttpProxyServerOptions implements HttpProxyServerOptions {
  _HttpProxyServerOptions({
    required this.mitmCA,
    required this.tlsTerminateUpstreamCA,
    required this.lookupFor,
  });

  @override
  FutureOr<bool> filter(
    int port,
    String host,
    stream.Duplex socket, [
    String? encodedCommand,
    void Function(String reason)? explain,
  ]) => true;

  @override
  String? Function(String host)? getMitmSocketPath;
  @override
  final MitmCA? mitmCA;
  @override
  bool Function(String hostname, int port)? shouldTerminateTLS;
  @override
  final Object? tlsTerminateUpstreamCA;
  @override
  final DirectLookup? lookupFor;
  @override
  FilterRequestCallback? get filterRequest => null;
  @override
  void Function(
    ({String method, String url, String reason, String? encodedCommand}),
  )?
  get onFilterRequestDenied => null;
  @override
  MutateForwardedHeaders? get mutateHeaders => null;
  @override
  MutateForwardedHeaders? get mutateHeadersPlaintext => null;
  @override
  GetBodySubstitutions? get getBodySubstitutions => null;
  @override
  GetBodySubstitutions? get getBodySubstitutionsPlaintext => null;
  @override
  PlanSigv4? get planSigv4 => null;
  @override
  int? get maxSigv4ResignBodyBytes => null;
  @override
  ResolvedParentProxy? get parentProxy => null;
  @override
  String? get proxyAuthToken => null;
  @override
  bool? get plaintextHeaderSet => null;
  @override
  List<String>? get stripResponseHeaders => null;
  @override
  bool? get refuseOpaqueTunnels => null;
  @override
  bool? get requireHostMatch => null;
  @override
  int? get maxHeaderSize => null;
  @override
  String? get denyHeader => null;
  @override
  bool? get requestTargetAsSpelled => null;
  @override
  String? get ambiguousRequestTarget => null;
  @override
  PartialTunnelTimeouts? get tunnelTimeouts => null;
  @override
  bool? get requireAsciiHost => null;
  @override
  bool? get foldHopByHop => null;
  @override
  int? get maxBufferedRequestBody => null;
  @override
  int? get maxTerminatedTunnels => null;
  @override
  int? get tlsHandshakeTimeoutMs => null;
  @override
  int? get maxBufferedBytes => null;
  @override
  ByteBudget? get byteBudget => null;
}

void main() {
  group(
    'tls-terminate-proxy: upstream keep-alive',
    skip: canServeEmittedConnections ? false : 'TLS termination unavailable',
    () {
      final ca = createMitmCA(caCertPath: CA_CERT, caKeyPath: CA_KEY);

      late https.Server upstream;
      late int upstreamPort;
      late NodeServer proxy;
      late int proxyPort;
      /**
     * Upstream connections that carried a request, by the id the reply body
     * reports. (The vetting probe also connects, but never sends a request.)
     */
      final upstreamSockets = <int, NodeSocket>{};
      var lookups = 0;

      final LookupFunction lookup = (hostname_, options, callback) {
        lookups++;
        final all = options.all == true;
        if (all) {
          callback(
            null,
            LookupResultAll([LookupAddress(address: '127.0.0.1', family: 4)]),
          );
        } else {
          callback(null, LookupResultAddress('127.0.0.1'), 4);
        }
      };

      setUpAll(() async {
        final upCert = mintLeafCert(ca, UPSTREAM_NAME);
        final upLeafOnly = RegExp(
          r'-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----\r?\n?',
        ).firstMatch(upCert.certPem)!.group(0)!;
        final ids = <NodeSocket, int>{};
        upstream = https.createServer(
          {'cert': upLeafOnly, 'key': upCert.keyPem},
          (https.IncomingMessage req, https.ServerResponse res) {
            if (!ids.containsKey(req.socket)) {
              ids[req.socket] = ids.length + 1;
              upstreamSockets[ids.length] = req.socket;
            }
            if (req.url == '/drop') {
              req.socket.destroy();
              return;
            }
            res.end(ids[req.socket].toString());
          },
        );
        await () {
          final r = Completer<void>();
          upstream.listen(0, '127.0.0.1', r.complete);
          return r.future;
        }();
        upstreamPort = (upstream.address()! as NodeAddress).port;

        proxy = createHttpProxyServer(
          _HttpProxyServerOptions(
            mitmCA: ca,
            tlsTerminateUpstreamCA: CA_PEM,
            lookupFor: (int port, [String? encodedCommand]) => lookup,
          ),
        );
        await () {
          final r = Completer<void>();
          proxy.listen(0, '127.0.0.1', () => r.complete());
          return r.future;
        }();
        proxyPort = (proxy.address()! as NodeAddress).port;
      });

      tearDownAll(() async {
        for (final s in upstreamSockets.values) {
          s.destroy();
        }
        await () {
          final r = Completer<void>();
          proxy.close(() => r.complete());
          return r.future;
        }();
        await () {
          final r = Completer<void>();
          upstream.close(() => r.complete());
          return r.future;
        }();
      });

      test(
        'requests on one client connection share one upstream connection, vetted once',
        () async {
          final tls = await openTunnel(proxyPort, UPSTREAM_NAME, upstreamPort);
          final first = await get(tls, '/a');
          final lookupsAfterFirst = lookups;
          final second = await get(tls, '/b');
          final third = await get(tls, '/c');
          tls.destroy();

          expect(first, isA<Reply>().having((r) => r.status, 'status', 200));
          expect(second, equals(first));
          expect(third, equals(first));
          expect(lookupsAfterFirst, greaterThan(0));
          expect(lookups, lookupsAfterFirst);
        },
      );

      test('an upstream that closed the idle connection is redialed', () async {
        final tls = await openTunnel(proxyPort, UPSTREAM_NAME, upstreamPort);
        final first = (await get(tls, '/a')) as Reply;
        expect(first.status, 200);

        upstreamSockets[int.parse(first.body)]!.destroy();
        await Future<void>.delayed(const Duration(milliseconds: 200));

        final second = (await get(tls, '/b')) as Reply;
        tls.destroy();
        expect(second.status, 200);
        expect(second.body, isNot(first.body));
      });

      test(
        'a reused upstream connection dropped mid-request closes the client connection, not 502',
        () async {
          final tls = await openTunnel(proxyPort, UPSTREAM_NAME, upstreamPort);
          expect(
            await get(tls, '/a'),
            isA<Reply>().having((r) => r.status, 'status', 200),
          );
          final dropped = await get(tls, '/drop');
          tls.destroy();
          expect(dropped, 'closed');
        },
      );
    },
  );
}
