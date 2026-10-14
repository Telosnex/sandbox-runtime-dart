// Ported from sandbox-runtime test/sandbox/tls-terminate-runtime.test.ts @ 24eb39e.
// ignore_for_file: constant_identifier_names, non_constant_identifier_names, slash_for_doc_comments
import 'dart:async';
import 'dart:convert';

import 'package:sandbox_runtime/src/node/buffer.dart' show Buffer;
import 'package:sandbox_runtime/src/node/errno.dart' show NodeException;
import 'package:sandbox_runtime/src/node/net.dart' as net;
import 'package:sandbox_runtime/src/node/process.dart' as process;
import 'package:sandbox_runtime/src/sandbox/emitted_connection.dart';
import 'package:sandbox_runtime/src/sandbox/http_proxy.dart';
import 'package:sandbox_runtime/src/sandbox/mitm_ca.dart';
import 'package:sandbox_runtime/src/sandbox/sandbox_config.dart';
import 'package:sandbox_runtime/src/sandbox/sandbox_manager.dart';
import 'package:test/test.dart';

import '../helpers/emitted_connections.dart';

// Dart: the object literal upstream hands createHttpProxyServer; every
// option not named here is absent (null).
class _HttpOptions implements HttpProxyServerOptions {
  _HttpOptions({this.mitmCA});
  @override
  final MitmCA? mitmCA;
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

// TLS termination runs in this process and needs an http.Server that
// serves a connection handed to it (Node, Bun 1.4 and later). Where the
// runtime has none, asking for termination fails at start-up, at both
// entry points, rather than on every tunnel.

final STARTUP_ERROR = RegExp(
  r'^tlsTerminate needs Node, or Bun 1\.4 or later \(this is (Bun|Node) \S+\)$',
);

// Dart: toThrow(STARTUP_ERROR) matches the error's message.
final Matcher _throwsStartupError = throwsA(
  predicate(
    (Object? e) => e is NodeException && STARTUP_ERROR.hasMatch(e.message),
    'a startup error matching $STARTUP_ERROR',
  ),
);

void main() {
  final cleanup = <FutureOr<void> Function()>[];
  tearDown(() async {
    while (cleanup.isNotEmpty) {
      await cleanup.removeLast()();
    }
  });

  /** Answer the runtime probe with `serves` until the test ends. */
  void pretendRuntimeServes(bool serves) {
    overrideEmittedConnectionProbe(() => serves);
    cleanup.add(() => overrideEmittedConnectionProbe(null));
  }

  MitmCA testCA() {
    final ca = generateCa();
    return createMitmCA(caCertPem: ca.certPem, caKeyPem: ca.keyPem);
  }

  SandboxRuntimeConfig baseConfig([TlsTerminateConfig? tlsTerminate]) =>
      SandboxRuntimeConfig(
        network: NetworkConfig(
          allowedDomains: ['a.test'],
          deniedDomains: [],
          tlsTerminate: tlsTerminate,
        ),
        filesystem: FilesystemConfig(
          denyRead: [],
          allowWrite: [],
          denyWrite: [],
        ),
      );

  group('a runtime that cannot terminate TLS in-process fails at start-up', () {
    test(
      'createHttpProxyServer with a CA throws naming the requirement and the runtime; without one it starts',
      () {
        pretendRuntimeServes(false);
        expect(
          () => createHttpProxyServer(_HttpOptions(mitmCA: testCA())),
          _throwsStartupError,
        );
        final plain = createHttpProxyServer(_HttpOptions());
        expect(plain.listening, isFalse);
      },
    );

    test(
      'SandboxManager.initialize with tlsTerminate rejects with that error before starting anything',
      () async {
        pretendRuntimeServes(false);
        cleanup.add(() => SandboxManager.reset());
        // bun-types declares .rejects matchers as returning void, but bun returns
        // a Promise at runtime: the await is load-bearing for the assertion.
        // eslint-disable-next-line @typescript-eslint/await-thenable
        await expectLater(
          SandboxManager.initialize(baseConfig(const TlsTerminateConfig())),
          _throwsStartupError,
        );
        expect(SandboxManager.getProxyPort(), isNull);
        expect(SandboxManager.getMitmCA(), isNull);
      },
    );

    test(
      'SandboxManager.initialize without tlsTerminate is not affected',
      () async {
        pretendRuntimeServes(false);
        cleanup.add(() => SandboxManager.reset());
        await SandboxManager.initialize(baseConfig());
        expect(SandboxManager.getProxyPort(), isA<num>());
      },
      timeout: const Timeout(Duration(milliseconds: 15000)),
    );

    final runtime = process.versions['bun'] != null
        ? 'Bun ${process.versions['bun']}'
        : process.version;
    test(
      SERVES_EMITTED_CONNECTIONS
          ? 'this runtime ($runtime) serves handed-in connections: a terminating proxy starts'
          : 'this runtime ($runtime) cannot: a terminating proxy fails to start, naming it',
      () {
        start() => createHttpProxyServer(_HttpOptions(mitmCA: testCA()));
        if (SERVES_EMITTED_CONNECTIONS) {
          expect(start, returnsNormally);
        } else {
          expect(
            start,
            throwsA(
              predicate(
                (Object? e) =>
                    e is NodeException &&
                    e.message.contains('(this is $runtime)'),
              ),
            ),
          );
        }
      },
    );
  });

  /** A CONNECT to a.test:443 through the manager's proxy: the reply head and the socket. */
  Future<({String head, net.NodeSocket sock})> connectThroughManager() {
    final port = SandboxManager.getProxyPort()!;
    final auth = Buffer.from('srt:${SandboxManager.getProxyAuthToken()!}');
    final resolve = Completer<({String head, net.NodeSocket sock})>();
    late final net.NodeSocket sock;
    sock = net.connect({'port': port, 'host': '127.0.0.1'}, () {
      sock.write(
        'CONNECT a.test:443 HTTP/1.1\r\nHost: a.test:443\r\n'
        'Proxy-Authorization: Basic ${auth.toString('base64')}\r\n\r\n',
      );
    });
    sock.on('error', (Object? _) {});
    cleanup.add(() => sock.destroy());
    var head = '';
    sock.on('data', (Object? d) {
      head += latin1.decode(d as List<int>);
      if (head.contains('\r\n\r\n') && !resolve.isCompleted) {
        resolve.complete((head: head, sock: sock));
      }
    });
    return resolve.future;
  }

  group(
    "the manager's proxy takes its tunnel cap and handshake deadline from tlsTerminate",
    skip: SERVES_EMITTED_CONNECTIONS ? null : 'TLS termination unavailable',
    () {
      test(
        'maxTunnels: 1 answers a second tunnel 503; handshakeTimeoutMs closes a silent one and frees its slot',
        () async {
          cleanup.add(() => SandboxManager.reset());
          await SandboxManager.initialize(
            baseConfig(
              const TlsTerminateConfig(maxTunnels: 1, handshakeTimeoutMs: 500),
            ),
          );
          final first = await connectThroughManager();
          expect(first.head, startsWith('HTTP/1.1 200'));
          final openedAt = DateTime.now().millisecondsSinceEpoch;
          final firstClosed = Completer<int>();
          first.sock.once(
            'close',
            (Object? _) =>
                firstClosed.complete(DateTime.now().millisecondsSinceEpoch),
          );
          final second = await connectThroughManager();
          expect(second.head, startsWith('HTTP/1.1 503'));
          expect(second.head, contains('X-Proxy-Error: too-many-tunnels'));
          // The silent first tunnel is closed at the deadline, well before the
          // default 10 s.
          final closedAt = await firstClosed.future;
          expect(closedAt - openedAt, greaterThanOrEqualTo(400));
          expect(closedAt - openedAt, lessThan(5000));
          await Future<void>.delayed(const Duration(milliseconds: 50));
          final third = await connectThroughManager();
          expect(third.head, startsWith('HTTP/1.1 200'));
        },
        timeout: const Timeout(Duration(milliseconds: 20000)),
      );
    },
  );
}
