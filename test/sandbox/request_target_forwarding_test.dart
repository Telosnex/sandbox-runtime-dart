// Ported from sandbox-runtime test/sandbox/request-target-forwarding.test.ts @ 24eb39e.
@Tags(['pending'])
library;

// ignore_for_file: constant_identifier_names, non_constant_identifier_names, no_leading_underscores_for_local_identifiers, slash_for_doc_comments
import 'dart:async';
import 'dart:convert';
import 'dart:io' show Directory;

import 'package:sandbox_runtime/src/node/dns.dart' as dns;
import 'package:sandbox_runtime/src/node/fs.dart';
import 'package:sandbox_runtime/src/node/net.dart' as net;
import 'package:sandbox_runtime/src/node/path.dart';
import 'package:sandbox_runtime/src/node/tls.dart' as tls;
import 'package:sandbox_runtime/src/sandbox/http_proxy.dart';
import 'package:sandbox_runtime/src/sandbox/mitm_ca.dart';
import 'package:sandbox_runtime/src/sandbox/mitm_leaf.dart';
import 'package:sandbox_runtime/src/sandbox/parent_proxy.dart'
    show DirectLookup;
import 'package:sandbox_runtime/src/sandbox/request_filter.dart';
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
void Function(net.NodeSocket socket) recordTargets(List<String> seen) {
  return (socket) {
    var buf = '';
    socket.on('error', (_) {});
    socket.on('data', (Object? chunk) {
      buf += latin1.decode(chunk as List<int>);
      for (int end; (end = buf.indexOf('\r\n\r\n')) >= 0;) {
        seen.add(buf.substring(0, buf.indexOf('\r\n')).split(' ')[1]);
        buf = buf.substring(end + 4);
        socket.write('HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n');
      }
    });
  };
}

/** Writes one request head and resolves with the reply's status code. */
Future<int> exchange(net.NodeSocket socket, String head) {
  final completer = Completer<int>();
  var buf = '';
  socket.on('data', (Object? chunk) {
    buf += latin1.decode(chunk as List<int>);
    if (!buf.contains('\r\n\r\n')) return;
    socket.destroy();
    completer.complete(
      int.parse(RegExp(r'^HTTP/1\.1 (\d+)').firstMatch(buf)?.group(1) ?? '0'),
    );
  });
  socket.once('error', (Object e) => completer.completeError(e));
  socket.once(
    'close',
    (_) => completer.completeError(Exception('closed before a reply')),
  );
  socket.write(head);
  return completer.future;
}

// Dart: the object literal upstream hands createHttpProxyServer; every
// option not named here is absent (null).
class _HttpOptions implements HttpProxyServerOptions {
  _HttpOptions({
    this.mitmCA,
    this.tlsTerminateUpstreamCA,
    this.lookupFor,
    this.filterRequest,
  });
  @override
  final MitmCA? mitmCA;
  @override
  final dynamic tlsTerminateUpstreamCA;
  @override
  final DirectLookup? lookupFor;
  @override
  final FilterRequestCallback? filterRequest;
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

void main() {
  // Dart: upstream's describeWithTls, spelled as group so the title audit sees it.
  group(
    'request target forwarding',
    skip: SERVES_EMITTED_CONNECTIONS ? null : 'TLS termination unavailable',
    () {
      final ca = createMitmCA(caCertPath: CA_CERT, caKeyPath: CA_KEY);
      final tlsSeen = <String>[];
      final plainSeen = <String>[];
      final hookSeen = <String?>[];
      final servers = <net.NodeServer>[];
      late int tlsPort;
      late int plainPort;
      late int noHookPort;
      late int hookPort;

      Future<int> listen(net.NodeServer server) async {
        servers.add(server);
        final listening = Completer<void>();
        server.listen(0, '127.0.0.1', () => listening.complete());
        await listening.future;
        return (server.address() as net.NodeAddress).port;
      }

      setUpAll(() async {
        final leaf = mintLeafCert(ca, UPSTREAM_NAME);
        final cert = RegExp(
          r'-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----\r?\n?',
        ).firstMatch(leaf.certPem)!.group(0)!;
        tlsPort = await listen(
          tls.createServer({
                'cert': cert,
                'key': leaf.keyPem,
              }, recordTargets(tlsSeen))
              as net.NodeServer,
        );
        plainPort = await listen(net.createServer(recordTargets(plainSeen)));
        noHookPort = await listen(
          createHttpProxyServer(
            _HttpOptions(
              mitmCA: ca,
              tlsTerminateUpstreamCA: CA_PEM,
              lookupFor: (int port, [String? encodedCommand]) => lookup,
            ),
          ),
        );
        hookPort = await listen(
          createHttpProxyServer(
            _HttpOptions(
              mitmCA: ca,
              tlsTerminateUpstreamCA: CA_PEM,
              lookupFor: (int port, [String? encodedCommand]) => lookup,
              filterRequest: (request, [info]) async {
                hookSeen.add(info?.requestTarget);
                return const RequestDecision(action: 'allow');
              },
            ),
          ),
        );
      });

      tearDownAll(() async {
        for (final s in servers) {
          final closed = Completer<void>();
          s.close(() => closed.complete());
          await closed.future;
        }
      });

      /** One GET over a fresh TLS-terminated tunnel; the target upstream saw. */
      Future<String> viaTls(int proxyPort, String target) async {
        final authority = '$UPSTREAM_NAME:$tlsPort';
        final rawCompleter = Completer<net.NodeSocket>();
        late final net.NodeSocket rawSocket;
        rawSocket = net.connect(proxyPort, '127.0.0.1', () {
          rawSocket.write(
            'CONNECT $authority HTTP/1.1\r\nHost: $authority\r\n\r\n',
          );
        });
        rawSocket.once('error', (Object e) => rawCompleter.completeError(e));
        rawSocket.once('data', (_) => rawCompleter.complete(rawSocket));
        final raw = await rawCompleter.future;
        final tlsCompleter = Completer<net.NodeSocket>();
        late final net.NodeSocket t;
        t = tls.connect({
          'socket': raw,
          'ca': CA_PEM,
          'servername': UPSTREAM_NAME,
        }, () => tlsCompleter.complete(t));
        t.once('error', (Object e) => tlsCompleter.completeError(e));
        final tlsSocket = await tlsCompleter.future;
        final before = tlsSeen.length;
        final head = 'GET $target HTTP/1.1\r\nHost: $authority\r\n\r\n';
        expect(await exchange(tlsSocket, head), 200);
        expect(tlsSeen.length, before + 1);
        return tlsSeen[before];
      }

      /** One absolute-form GET through the proxy; the target upstream saw. */
      Future<String> viaPlain(int proxyPort, String target) async {
        final authority = '127.0.0.1:$plainPort';
        final before = plainSeen.length;
        final head =
            'GET http://$authority$target HTTP/1.1\r\nHost: $authority\r\n\r\n';
        final connected = Completer<net.NodeSocket>();
        late final net.NodeSocket s;
        s = net.connect(proxyPort, '127.0.0.1', () => connected.complete(s));
        s.once('error', (Object e) => connected.completeError(e));
        final socket = await connected.future;
        expect(await exchange(socket, head), 200);
        expect(plainSeen.length, before + 1);
        return plainSeen[before];
      }

      group('no hook: target forwarded unchanged', () {
        for (final (sent, forwarded) in TLS_UNCHANGED) {
          test('TLS-terminated $sent', () async {
            expect(await viaTls(noHookPort, sent), forwarded);
          });
        }

        for (final (sent, forwarded) in PLAIN_UNCHANGED) {
          test('plain HTTP $sent', () async {
            expect(await viaPlain(noHookPort, sent), forwarded);
          });
        }
      });

      group('with a hook: the target it judges is the target forwarded', () {
        for (final (sent, _) in TLS_UNCHANGED) {
          test('TLS-terminated $sent', () async {
            final forwarded = await viaTls(hookPort, sent);
            expect(hookSeen.last, forwarded);
          });
        }

        for (final (sent, _) in PLAIN_UNCHANGED) {
          test('plain HTTP $sent', () async {
            final forwarded = await viaPlain(hookPort, sent);
            expect(hookSeen.last, forwarded);
          });
        }

        test(
          'dot segments and a leading // are resolved before the hook',
          () async {
            expect(await viaTls(hookPort, '//a/../b'), '/b');
            expect(hookSeen.last, '/b');
            expect(await viaPlain(hookPort, '//k/x'), '/k/x');
            expect(hookSeen.last, '/k/x');
          },
        );
      });
    },
  );
}
