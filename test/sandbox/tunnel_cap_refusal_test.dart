// Ported from sandbox-runtime test/sandbox/tunnel-cap-refusal.test.ts @ 0bbebed.
// ignore_for_file: constant_identifier_names, non_constant_identifier_names, slash_for_doc_comments
import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:sandbox_runtime/src/node/net.dart' as net;
import 'package:sandbox_runtime/src/sandbox/http_proxy.dart';
import 'package:sandbox_runtime/src/sandbox/mitm_ca.dart';
import 'package:test/test.dart';
import '../helpers/captured_warnings.dart';
import '../helpers/emitted_connections.dart' show testWithTls;

// Of the 503 at the tunnel cap a client shows the status at most. That the
// limit is the sandbox's own is logged and passed on as a refusal is, once
// per command and burst of refusals.
const TOKEN = 'sekrit';
final cleanup = <FutureOr<void> Function()>[];
typedef Denial = ({
  String method,
  String url,
  String reason,
  String? encodedCommand,
});

class _Options implements HttpProxyServerOptions {
  _Options(this.mitmCA, this.maxTerminatedTunnels, this.onFilterRequestDenied);
  @override
  final MitmCA? mitmCA;
  @override
  final int? maxTerminatedTunnels;
  @override
  final void Function(Denial)? onFilterRequestDenied;
  @override
  String? get proxyAuthToken => TOKEN;
  @override
  bool filter(
    int port,
    String host,
    dynamic socket, [
    String? encodedCommand,
    void Function(String reason)? explain,
  ]) => true;
  @override
  dynamic noSuchMethod(Invocation invocation) => null;
}

Future<
  ({
    List<Denial> denials,
    Future<void> Function() fill,
    Future<void> Function(int) free,
    Future<List<String?>> Function([String?]) refused,
  })
>
proxyWithSlots(int maxTerminatedTunnels) async {
  final ca = generateCa();
  final denials = <Denial>[];
  final proxy = createHttpProxyServer(
    _Options(
      createMitmCA(caCertPem: ca.certPem, caKeyPem: ca.keyPem),
      maxTerminatedTunnels,
      (info) => denials.add(info),
    ),
  );
  final listening = Completer<void>();
  proxy.listen(0, '127.0.0.1', () => listening.complete());
  await listening.future;
  cleanup.add(() {
    final c = Completer<void>();
    proxy.close(() => c.complete());
    return c.future;
  });
  final port = (proxy.address() as net.NodeAddress).port;

  /** CONNECT as `command` (none: the bare user name); the status and the socket. */
  Future<({int status, net.NodeSocket sock})> open([String? command]) {
    final resolve = Completer<({int status, net.NodeSocket sock})>();
    final user = command == null ? 'srt' : 'srt.$command';
    final basic = base64.encode(utf8.encode('$user:$TOKEN'));
    late net.NodeSocket sock;
    sock = net.connect(
      port,
      '127.0.0.1',
      () => sock.write(
        'CONNECT a.test:443 HTTP/1.1\r\nHost: a.test:443\r\nProxy-Authorization: Basic $basic\r\n\r\n',
      ),
    );
    sock.on('error', () {});
    cleanup.add(() => sock.destroy());
    sock.once(
      'data',
      (Uint8List d) => resolve.complete((
        status: int.parse(latin1.decode(d).split(' ')[1]),
        sock: sock,
      )),
    );
    return resolve.future;
  }

  final held = <net.NodeSocket>[];
  return (
    denials: denials,
    /** Take slots until none is free. */
    fill: () async {
      while (held.length < maxTerminatedTunnels) {
        final (:status, :sock) = await open('holder');
        expect(status, 200);
        held.add(sock);
      }
    },
    free: (int slots) async {
      final removed = held.take(slots).toList();
      held.removeRange(0, slots);
      for (final sock in removed) {
        sock.destroy();
      }
      await Future<void>.delayed(const Duration(milliseconds: 100));
    },
    /** A CONNECT at the cap; who has been told of the cap so far. */
    refused: ([String? command]) async {
      expect((await open(command)).status, 503);
      return denials.map((d) => d.encodedCommand).toList();
    },
  );
}

void main() {
  tearDown(() async {
    while (cleanup.isNotEmpty) {
      await cleanup.removeLast()();
    }
  });
  testWithTls(
    'the first refusal of each command is logged and passed on, naming the limit and its option',
    () async {
      final p = await proxyWithSlots(2);
      await p.fill();
      final result = await withCapturedWarnings(() async {
        expect(await p.refused('A'), ['A']);
        expect(await p.refused('A'), ['A']);
        expect(await p.refused('B'), ['A', 'B']);
        expect(await p.refused(), ['A', 'B', null]);
        expect(await p.refused('B'), ['A', 'B', null]);
      });
      const reason =
          "the sandbox's limit of 2 TLS-terminated tunnels at once is reached; "
          "the limit is network.tlsTerminate.maxTunnels in the sandbox's configuration";
      expect(p.denials[0], (
        method: 'CONNECT',
        url: 'a.test:443',
        reason: reason,
        encodedCommand: 'A',
      ));
      expect(
        result.warnings,
        List.filled(
          3,
          '[SandboxDebug] [proxy] CONNECT a.test:443 refused: $reason',
        ),
      );
    },
  );
  testWithTls(
    'a burst ends once half the slots are free again, not before',
    () async {
      final p = await proxyWithSlots(4);
      await p.fill();
      expect(await p.refused('A'), ['A']);
      await p.free(1);
      await p.fill();
      expect(await p.refused('A'), ['A']);
      await p.free(2);
      await p.fill();
      expect(await p.refused('A'), ['A', 'A']);
    },
  );
  testWithTls(
    'the names kept are bounded: past a hundred they are forgotten',
    () async {
      final p = await proxyWithSlots(1);
      await p.fill();
      for (var i = 0; i < 100; i++) {
        await p.refused('c$i');
      }
      expect(await p.refused('c0'), hasLength(100));
      expect(await p.refused('one-more'), hasLength(101));
      expect(await p.refused('c0'), hasLength(102));
    },
  );
}
