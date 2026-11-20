// Ported from sandbox-runtime test/sandbox/tls-terminate-handshake-deadline.test.ts @ 0bbebed.
// ignore_for_file: constant_identifier_names, non_constant_identifier_names, slash_for_doc_comments
import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:sandbox_runtime/src/node/globals.dart' show setTimeout;
import 'package:sandbox_runtime/src/node/http.dart' as http;
import 'package:sandbox_runtime/src/node/https.dart' as https;
import 'package:sandbox_runtime/src/node/net.dart' as net;
import 'package:sandbox_runtime/src/node/stream.dart' as stream;
import 'package:sandbox_runtime/src/node/tls.dart' as tls_;
import 'package:sandbox_runtime/src/sandbox/http_proxy.dart';
import 'package:sandbox_runtime/src/sandbox/mitm_ca.dart';
import 'package:sandbox_runtime/src/sandbox/mitm_leaf.dart';
import 'package:test/test.dart';

import '../helpers/emitted_connections.dart' show canServeEmittedConnections;

// Dart: the named imports upstream takes from node:https, node:net and
// node:tls, as aliases.
typedef Socket = net.NodeSocket;
typedef AddressInfo = net.NodeAddress;
typedef SecureVersion = String;
final createHttpsServer = https.createServer;
final connect = net.connect;
final Duplex = stream.Duplex.new;
final tlsConnect = tls_.connect;

// Dart: the object literal upstream hands createHttpProxyServer; every
// option not named here is absent (null).
class _HttpOptions implements HttpProxyServerOptions {
  _HttpOptions({
    this.mitmCA,
    this.tlsTerminateUpstreamCA,
    this.tlsHandshakeTimeoutMs,
    this.maxTerminatedTunnels,
  });
  @override
  final MitmCA? mitmCA;
  @override
  final dynamic tlsTerminateUpstreamCA;
  @override
  final int? tlsHandshakeTimeoutMs;
  @override
  final int? maxTerminatedTunnels;
  @override
  bool Function(String hostname, int port)? shouldTerminateTLS = (_, _) => true;
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

// Long enough that a handshake on a busy machine fits well inside it.
const HANDSHAKE_MS = 1500;
const TEST_MS = 30000;
const VERSIONS = <SecureVersion>['TLSv1.2', 'TLSv1.3'];

void main() {
  final cleanup = <FutureOr<void> Function()>[];
  tearDown(() async {
    while (cleanup.isNotEmpty) {
      await cleanup.removeLast()();
    }
  });

  /**
 * A proxy that terminates TLS on one tunnel at a time, with a short
 * handshake deadline, in front of an HTTPS upstream on loopback.
 */
  Future<Served> serve() async {
    final ca = generateCa();
    final mitmCA = createMitmCA(caCertPem: ca.certPem, caKeyPem: ca.keyPem);
    final leaf = mintLeafCert(mitmCA, '127.0.0.1');
    final leafOnly = RegExp(
      r'-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----\r?\n?',
    ).firstMatch(leaf.certPem)!.group(0)!;
    final up = createHttpsServer({'cert': leafOnly, 'key': leaf.keyPem}, (
      _,
      https.ServerResponse res,
    ) {
      res.end('ok');
    });
    await () {
      final r = Completer<void>();
      up.listen(0, '127.0.0.1', () => r.complete());
      return r.future;
    }();
    final proxy = createHttpProxyServer(
      _HttpOptions(
        mitmCA: mitmCA,
        tlsTerminateUpstreamCA: ca.certPem,
        tlsHandshakeTimeoutMs: HANDSHAKE_MS,
        maxTerminatedTunnels: 1,
      ),
    );
    await () {
      final r = Completer<void>();
      proxy.listen(0, '127.0.0.1', () => r.complete());
      return r.future;
    }();
    for (final server in <http.NodeHttpServer>[up, proxy]) {
      cleanup.add(() {
        final r = Completer<void>();
        server.close(() => r.complete());
        server.closeAllConnections();
        return r.future;
      });
    }
    final target = '127.0.0.1:${(up.address()! as AddressInfo).port}';
    final port = (proxy.address()! as AddressInfo).port;

    /** The status line of the answer to a CONNECT, and the tunnel if it is 200. */
    Future<({String status, Tunnel tunnel})> connectTo() {
      final completer = Completer<({String status, Tunnel tunnel})>();
      final resolve = completer.complete;
      final reject = completer.completeError;
      late final Socket raw;
      raw = connect(port, '127.0.0.1', () {
        raw.write('CONNECT $target HTTP/1.1\r\nHost: $target\r\n\r\n');
      });
      raw.on('error', reject);
      final closedCompleter = Completer<int>();
      raw.once('close', () => closedCompleter.complete(_now()));
      final closed = closedCompleter.future;
      var head = '';
      late void Function(Object?) onData;
      onData = (Object? x) {
        head += latin1.decode(x as List<int>);
        if (!head.contains('\r\n\r\n')) return;
        raw.off('data', onData);
        raw.off('error', reject);
        raw.on('error', () {});
        final status = head.substring(0, head.indexOf('\r\n'));
        resolve((
          status: status,
          tunnel: (raw: raw, openedAt: _now(), closed: closed),
        ));
      };
      raw.on('data', onData);
      return completer.future;
    }

    Future<Tunnel> open() async {
      final (:status, :tunnel) = await connectTo();
      expect(status, contains(' 200 '));
      return tunnel;
    }

    Map<Object?, Object?> tlsOptions(SecureVersion version) => {
      'ca': ca.certPem,
      'checkServerIdentity': (Object? a, Object? b) => null,
      'ALPNProtocols': ['http/1.1'],
      'minVersion': version,
      'maxVersion': version,
    };
    return (
      target: target,
      connectTo: connectTo,
      open: open,
      tlsOptions: tlsOptions,
    );
  }

  /**
 * A real TLS client whose writes to the tunnel are gated: `partialHello`
 * lets only the first 20 bytes of its ClientHello through; `noFinished`
 * lets the whole ClientHello through and drops everything the client sends
 * once the server has spoken (so its Finished never arrives).
 */
  ({bool Function() serverSpoke, int Function() dropped}) stalledClient(
    Tunnel tunnel,
    String stall,
    Map<Object?, Object?> options,
  ) {
    final raw = tunnel.raw;
    var sent = 0;
    var dropped = 0;
    var serverSpoke = false;
    final gate = Duplex(
      read: (int _) {},
      write: (Object chunk, String encoding_, Function callback) {
        chunk as List<int>;
        final allowed = stall == 'partialHello'
            ? (20 - sent > 0 ? 20 - sent : 0)
            : serverSpoke
            ? 0
            : chunk.length;
        if (allowed > 0) {
          raw.write(Uint8List.fromList(chunk.sublist(0, allowed)));
        }
        sent += allowed < chunk.length ? allowed : chunk.length;
        dropped +=
            chunk.length - (allowed < chunk.length ? allowed : chunk.length);
        callback();
      },
    );
    raw.on('data', (Object? x) {
      serverSpoke = true;
      gate.push(x);
    });
    raw.once('close', () => gate.destroy());
    tlsConnect({'socket': gate, ...options}).on('error', (Object? _) {});
    return (serverSpoke: () => serverSpoke, dropped: () => dropped);
  }

  /** The stalled tunnel holds the only slot until the deadline destroys it. */
  Future<void> expectDestroyedAtDeadline(Served proxy, Tunnel tunnel) async {
    expect((await proxy.connectTo()).status, contains(' 503 '));
    final closedAt = await tunnel.closed;
    // Timers do not fire early; allow for the proxy arming its timer just
    // before the test saw the 200.
    expect(
      closedAt - tunnel.openedAt,
      greaterThanOrEqualTo(HANDSHAKE_MS - 100),
    );
    // The slot is free again: a new tunnel is accepted and can be used.
    final next = await proxy.open();
    next.raw.destroy();
  }

  group(
    'TLS handshake deadline',
    skip: canServeEmittedConnections ? null : 'TLS termination unavailable',
    () {
      for (final version in VERSIONS) {
        test(
          '$version: a client quiet after the handshake keeps its tunnel',
          () async {
            final proxy = await serve();
            final tunnel = await proxy.open();
            var closed = false;
            unawaited(tunnel.closed.then((_) => closed = true));
            final client = tlsConnect({
              'socket': tunnel.raw,
              ...proxy.tlsOptions(version),
            });
            client.on('error', (Object? _) {});
            await () {
              final r = Completer<void>();
              client.once('secureConnect', () => r.complete());
              return r.future;
            }();
            // Dart: tls.TLSSocket has no getProtocol().
            expect((client as dynamic).getProtocol(), version);
            await () {
              final r = Completer<void>();
              setTimeout(() => r.complete(), HANDSHAKE_MS * 3);
              return r.future;
            }();
            expect(closed, false);
            final answer = () {
              final resolve = Completer<String>();
              var text = '';
              client.on('data', (Object? x) {
                text += latin1.decode(x as List<int>);
                if (text.contains('\r\n\r\n') && !resolve.isCompleted) {
                  resolve.complete(text);
                }
              });
              client.once('close', () {
                if (!resolve.isCompleted) resolve.complete(text);
              });
              return resolve.future;
            }();
            client.write('GET / HTTP/1.1\r\nHost: ${proxy.target}\r\n\r\n');
            expect(await answer, startsWith('HTTP/1.1 200 '));
            client.destroy();
          },
          // Dart: dart:io has a minimum TLS version but no maximum, so a
          // client held to TLS 1.2 cannot be made.
          skip: version == 'TLSv1.2'
              ? 'dart:io cannot cap a client at TLS 1.2'
              : null,
          timeout: const Timeout(Duration(milliseconds: TEST_MS)),
        );

        test(
          '$version: a client that never sends its Finished is cut off, and its slot freed',
          () async {
            final proxy = await serve();
            final tunnel = await proxy.open();
            final client = stalledClient(
              tunnel,
              'noFinished',
              proxy.tlsOptions(version),
            );
            await expectDestroyedAtDeadline(proxy, tunnel);
            // The client did get the server's flight, and its reply was held back.
            expect(client.serverSpoke(), true);
            expect(client.dropped(), greaterThan(0));
          },
          // Dart: dart:io has a minimum TLS version but no maximum, so a
          // client held to TLS 1.2 cannot be made.
          skip: version == 'TLSv1.2'
              ? 'dart:io cannot cap a client at TLS 1.2'
              : null,
          timeout: const Timeout(Duration(milliseconds: TEST_MS)),
        );
      }

      test(
        'a client that sends part of a ClientHello is cut off, and its slot freed',
        () async {
          final proxy = await serve();
          final tunnel = await proxy.open();
          final client = stalledClient(
            tunnel,
            'partialHello',
            proxy.tlsOptions('TLSv1.3'),
          );
          await expectDestroyedAtDeadline(proxy, tunnel);
          expect(client.serverSpoke(), false);
        },
        timeout: const Timeout(Duration(milliseconds: TEST_MS)),
      );
    },
  );
}

// Dart: Date.now().
int _now() => DateTime.now().millisecondsSinceEpoch;

typedef Tunnel = ({Socket raw, int openedAt, Future<int> closed});

// Dart: `Awaited<ReturnType<typeof serve>>`.
typedef Served = ({
  String target,
  Future<({String status, Tunnel tunnel})> Function() connectTo,
  Future<Tunnel> Function() open,
  Map<Object?, Object?> Function(String version) tlsOptions,
});
