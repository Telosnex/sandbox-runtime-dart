// Ported from sandbox-runtime test/sandbox/socks-unauthenticated-probe.test.ts @ 0bbebed.
// ignore_for_file: slash_for_doc_comments
import 'dart:async';
import 'dart:convert';
import 'dart:io' show Platform;
import 'dart:typed_data';

import 'package:path/path.dart' as path;
import 'package:sandbox_runtime/src/node/buffer.dart' show Buffer, readUInt32BE;
import 'package:sandbox_runtime/src/node/child_process.dart' show spawn;
import 'package:sandbox_runtime/src/node/events.dart' show once;
import 'package:sandbox_runtime/src/node/net.dart' as net;
import 'package:sandbox_runtime/src/node/process.dart' as process;
import 'package:sandbox_runtime/src/sandbox/sandbox_config.dart';
import 'package:sandbox_runtime/src/sandbox/sandbox_manager.dart';
import 'package:sandbox_runtime/src/sandbox/socks_proxy.dart';
import 'package:test/test.dart';

import '../helpers/platform.dart' show isMacOS;
import '../helpers/spawn.dart' show RunOpts, spawnAsync;

// Dart: stands for the anonymous options object `createSocksProxyServer` is given.
class _SocksOptions implements SocksProxyServerOptions {
  _SocksOptions({
    this.proxyAuthToken,
    this.probeUnauthenticated,
    this.onFilter,
  });
  final void Function()? onFilter;
  @override
  final String? proxyAuthToken;
  @override
  final Future<({String? deniedReason})> Function(int port, String host)?
  probeUnauthenticated;
  @override
  FutureOr<bool> filter(int port, String host, [String? encodedCommand]) {
    onFilter?.call();
    return true;
  }

  @override
  dynamic noSuchMethod(Invocation invocation) => null;
}

// Dart: no JS runtime hosts the test, so the helper script runs under the Dart executable.
String _helperPath() =>
    path.join(process.cwd(), 'test', 'helpers', 'socks_noauth_pipe.dart');

/**
 * A client that cannot authenticate (offers only the no-auth method, like
 * BSD `nc -X 5`) must never be tunnelled, and the refusal must be legible:
 * SSH destinations get an in-band SSH disconnect carrying the policy
 * reason; everything else gets the SOCKS "connection not allowed" reply.
 */
void main() {
  group('SOCKS unauthenticated probe', () {
    net.NodeServer? tcp;
    SocksProxyWrapper? wrapper;

    tearDown(() async {
      await wrapper?.close();
      tcp?.close();
      tcp = null;
      wrapper = null;
    });

    Future<int> startServer({
      String? deniedReason,
      void Function(int port, String host)? onProbe,
      void Function()? onFilter,
    }) async {
      wrapper = createSocksProxyServer(
        _SocksOptions(
          onFilter: onFilter,
          proxyAuthToken: 'tok-123',
          probeUnauthenticated: (port, host) async {
            onProbe?.call(port, host);
            return deniedReason != null
                ? (deniedReason: deniedReason)
                : (deniedReason: null);
          },
        ),
      );
      final w = wrapper!;
      tcp = net.createServer(
        (net.NodeSocket socket) => w.handleConnection(socket),
      );
      tcp!.listen(0, '127.0.0.1');
      await once(tcp!, 'listening');
      return (tcp!.address() as net.NodeAddress).port;
    }

    Uint8List socksConnect(String host, int port) {
      final hostBytes = utf8.encode(host);
      return Uint8List.fromList([
        ...[0x05, 0x01, 0x00, 0x03, hostBytes.length],
        ...hostBytes,
        ...[(port >> 8) & 0xff, port & 0xff],
      ]);
    }

    Future<Buffer> drive(
      int serverPort,
      ({String host, int port}) target,
    ) async {
      final sock = net.connect(serverPort, '127.0.0.1');
      await once(sock, 'connect');
      // Greeting: only the no-auth method — an unauthenticatable client.
      sock.write(Uint8List.fromList([0x05, 0x01, 0x00]));
      final chunks = <List<int>>[];
      sock.on('data', (Uint8List d) => chunks.add(d));
      // Method selection arrives, then send CONNECT.
      await Future<void>.delayed(const Duration(milliseconds: 50));
      sock.write(socksConnect(target.host, target.port));
      await once(sock, 'close');
      return Buffer.concat(chunks);
    }

    test(
      'port-22 deny: SOCKS success then SSH banner + DISCONNECT with the reason; filter never consulted',
      () async {
        final probed = <String>[];
        var filterCalls = 0;
        final port = await startServer(
          deniedReason: 'ssh to this host is blocked; use an https remote',
          onProbe: (p, h) => probed.add('$h:$p'),
          onFilter: () => filterCalls++,
        );
        final out = await drive(port, (host: 'denied.test', port: 22));

        // 05 00 (method), then 10-byte success reply, then SSH bytes.
        expect(out.sublist(0, 2), equals([0x05, 0x00]));
        expect(out.sublist(2, 4), equals([0x05, 0x00]));
        final ssh = Buffer.wrap(Uint8List.fromList(out.sublist(12)));
        final text = ssh.toString('utf8');
        expect(text.startsWith('SSH-2.0-'), isTrue);
        expect(
          text,
          contains('ssh to this host is blocked; use an https remote'),
        );
        // Well-formed plaintext DISCONNECT after the identification line.
        final pkt = ssh.sublist(ssh.indexOfBytes('\n') + 1);
        final packetLength = readUInt32BE(pkt, 0);
        expect((4 + packetLength) % 8, 0);
        expect(pkt[5], 0x01); // SSH_MSG_DISCONNECT
        expect(readUInt32BE(pkt, 6), 1); // HOST_NOT_ALLOWED_TO_CONNECT
        expect(probed, equals(['denied.test:22']));
        // The authenticated-path filter (which may prompt) is never reached.
        expect(filterCalls, 0);
      },
    );

    test(
      'port-22 non-denied: SSH disconnect says the proxy requires authentication',
      () async {
        final port = await startServer();
        final out = await drive(port, (host: 'allowed.test', port: 22));
        final text = out.toString('latin1');
        expect(text, contains('SSH-2.0-'));
        expect(text, contains('requires authentication'));
      },
    );

    test(
      'the manager: a deny entry spelled like a member of Object.prototype is refused for the generic reason',
      () async {
        // And one whose key is there with nothing behind it, as a caller that
        // builds the map from optional reasons leaves it.
        final names = [
          ...['constructor', 'valueOf', '__proto__', 'hasOwnProperty'],
          'no-reason.test',
        ];
        await SandboxManager.initialize(
          SandboxRuntimeConfig(
            network: NetworkConfig(
              allowedDomains: [],
              deniedDomains: names,
              // Dart: deniedDomainReasons is Map<String, String>, which cannot hold
              // upstream's `'no-reason.test': undefined` entry.
              deniedDomainReasons: {'other.test': 'not this one'},
            ),
            filesystem: FilesystemConfig(
              denyRead: [],
              allowWrite: [],
              denyWrite: [],
            ),
          ),
        );
        try {
          for (final host in names) {
            final out = await drive(SandboxManager.getSocksProxyPort()!, (
              host: host,
              port: 22,
            ));
            expect(
              out.toString('latin1'),
              contains('host is on the deny list'),
            );
          }
        } finally {
          await SandboxManager.reset();
        }
      },
    );

    test(
      'non-22 target: plain SOCKS refusal, no SSH bytes, no tunnel',
      () async {
        final port = await startServer(deniedReason: 'nope');
        final out = await drive(port, (host: 'denied.test', port: 443));
        expect(out.sublist(0, 2), equals([0x05, 0x00]));
        // Reply status 0x02 = connection not allowed by ruleset.
        expect(out[3], 0x02);
        expect(out.toString('latin1'), isNot(contains('SSH-2.0-')));
      },
    );

    // The ProxyCommand helper used by the ssh tests below must outlive the
    // proxy's close: the proxy sends banner + DISCONNECT and closes at once,
    // while ssh only reads the DISCONNECT after it has written its own
    // KEXINIT into the helper's stdin. A helper that exits on socket close
    // races that write; when ssh loses (a busy CI runner), it dies with
    // "Broken pipe" and never prints the reason. Reproduced here without
    // ssh: play ssh's part with a deliberately late write, and require the
    // helper to still be running when it lands (the parent-side write itself
    // reports nothing useful once the child is gone), then to exit as soon as
    // its stdin is closed — not on a fallback timer.
    test(
      'ProxyCommand helper stays alive until its stdin closes, even after the proxy hangs up',
      () async {
        final port = await startServer(deniedReason: 'late-write reason');
        final child = spawn(
          Platform.resolvedExecutable,
          [_helperPath(), '$port', 'denied.test', '22'],
          {
            'stdio': ['pipe', 'pipe', 'inherit'],
          },
        );
        int? exitCode;
        var hasExited = false;
        final exited = once(child, 'exit').then((args) {
          exitCode = args[0] as int?;
          hasExited = true;
        });
        final stdout = <List<int>>[];
        // Dart: the shim's stdout is a broadcast Stream, not an emitter.
        final firstData = child.stdout!.first;
        child.stdout!.listen((d) => stdout.add(d));
        await firstData;
        // By now the proxy has closed the socket; give the helper ample time to
        // (wrongly) exit on that.
        await Future<void>.delayed(const Duration(milliseconds: 200));
        expect(hasExited, isFalse);
        child.stdin!.write('SSH-2.0-client\r\n');
        final stdinClosedAt = DateTime.now().millisecondsSinceEpoch;
        child.stdin!.end();
        await exited;
        expect(exitCode, 0);
        expect(
          DateTime.now().millisecondsSinceEpoch - stdinClosedAt,
          lessThan(1000),
        );
        expect(
          Buffer.concat(stdout).toString('latin1'),
          contains('late-write reason'),
        );
      },
    );

    test(
      'a client offering username/password still gets the authenticated flow',
      () async {
        final port = await startServer();
        final sock = net.connect(port, '127.0.0.1');
        await once(sock, 'connect');
        sock.write(Uint8List.fromList([0x05, 0x02, 0x00, 0x02]));
        final [reply as Uint8List] = await once(sock, 'data');
        // Library selects username/password (0x02), not the probe's 0x00.
        expect(reply.sublist(0, 2), equals([0x05, 0x02]));
        sock.destroy();
      },
    );
  });

  /**
   * The end-to-end claim: real `ssh` through a no-auth SOCKS ProxyCommand
   * against a denied host prints the configured reason instead of an opaque
   * tunnel failure. The ProxyCommand is our own minimal no-auth SOCKS pipe
   * (test/helpers/socks-noauth-pipe.ts) rather than `nc -X 5`: it exercises
   * the identical wire behavior while being independent of which netcat
   * flavor the host ships (GNU/nmap variants lack -X and fail instantly).
   * macOS-gated for a real OpenSSH; the wire path itself is covered
   * cross-platform by the raw-socket tests above.
   */
  group(
    'ssh-over-nc against the real sandbox proxy',
    skip: isMacOS ? null : 'requires macOS',
    () {
      tearDown(() async {
        await SandboxManager.reset();
      });

      // Dart: execFile has no shim; spawnAsync (test/helpers/spawn.dart) runs argv-form with a timeout.
      Future<String> runSsh(int port, String host) async {
        final result = await spawnAsync('ssh', [
          '-o',
          'ProxyCommand=${Platform.resolvedExecutable} ${_helperPath()} $port %h %p',
          '-o',
          'StrictHostKeyChecking=no',
          '-o',
          'ConnectTimeout=10',
          'git@$host',
        ], const RunOpts(timeout: 15000));
        return result.stderr;
      }

      test(
        'denied host: ssh stderr carries the configured deny reason',
        () async {
          await SandboxManager.initialize(
            SandboxRuntimeConfig(
              network: NetworkConfig(
                allowedDomains: [],
                deniedDomains: ['ssh-blocked.example:22'],
                deniedDomainReasons: {
                  'ssh-blocked.example:22':
                      'ssh to this destination is blocked by sandbox policy; switch the remote to https://example.invalid/ORG/REPO.git',
                },
              ),
              filesystem: FilesystemConfig(
                denyRead: [],
                allowWrite: [],
                denyWrite: [],
              ),
            ),
          );
          final stderr = await runSsh(
            SandboxManager.getProxyPort()!,
            'ssh-blocked.example',
          );
          expect(stderr, contains('ssh to this destination is blocked'));
          expect(
            stderr,
            isNot(contains('authentication method negotiation failed')),
          );
          // Recorded (unattributed) so the violation surfaces to observers too.
          final lines = SandboxManager.getSandboxViolationStore()
              .getViolations()
              .map((v) => v.line)
              .toList();
          expect(
            lines.any((l) => l.contains('ssh-blocked.example:22')),
            isTrue,
          );
        },
      );

      test(
        'non-denied host: ssh stderr says the proxy requires authentication',
        () async {
          await SandboxManager.initialize(
            SandboxRuntimeConfig(
              network: NetworkConfig(
                allowedDomains: ['anything.example'],
                deniedDomains: [],
              ),
              filesystem: FilesystemConfig(
                denyRead: [],
                allowWrite: [],
                denyWrite: [],
              ),
            ),
          );
          final stderr = await runSsh(
            SandboxManager.getProxyPort()!,
            'anything.example',
          );
          expect(stderr, contains('requires authentication'));
        },
      );
    },
  );
}
