// Ported from sandbox-runtime test/sandbox/update-config.test.ts @ 24eb39e.
// ignore_for_file: non_constant_identifier_names
import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:test/test.dart';

import 'package:sandbox_runtime/src/index.dart';
import 'package:sandbox_runtime/src/node/buffer.dart' show Buffer;
import 'package:sandbox_runtime/src/node/crypto.dart' show randomBytes;
import 'package:sandbox_runtime/src/node/net.dart'
    show NodeAddress, NodeServer, NodeSocket, connect, createServer;
import 'package:sandbox_runtime/src/sandbox/sandbox_schemas.dart'
    show NetworkHostPattern, SandboxAskCallback;
import 'package:sandbox_runtime/src/sandbox/sandbox_utils.dart'
    show encodeSandboxedCommand, proxyUsernameFor;
import 'package:sandbox_runtime/src/utils/platform.dart' show getPlatform;
import '../helpers/platform.dart' show isLinux, isMacOS;
import '../helpers/spawn.dart' show spawnAsync;

String b64(String s) => base64Encode(utf8.encode(s));

/**
 * Helper to make a CONNECT request through the proxy using raw TCP
 */
Future<({bool allowed, int? statusCode, String? response})> proxyRequest(
  int proxyPort,
  String targetHost, [
  bool withAuth = true,
]) {
  final completer =
      Completer<({bool allowed, int? statusCode, String? response})>();
  // A Promise settles once; a later resolve is ignored.
  void resolve(({bool allowed, int? statusCode, String? response}) v) {
    if (!completer.isCompleted) completer.complete(v);
  }

  final token = withAuth ? SandboxManager.getProxyAuthToken() : null;
  final auth = token != null && token.isNotEmpty
      ? 'Proxy-Authorization: Basic ${b64('srt:$token')}\r\n'
      : '';
  late final NodeSocket socket;
  socket = connect(proxyPort, '127.0.0.1', () {
    socket.write(
      'CONNECT $targetHost:443 HTTP/1.1\r\nHost: $targetHost:443\r\n$auth\r\n',
    );
  });

  var data = '';
  socket.on('data', (Uint8List chunk) {
    data += utf8.decode(chunk, allowMalformed: true);
    // Check if we have a complete HTTP response line
    if (data.contains('\r\n')) {
      socket.destroy();
      final statusMatch = RegExp(r'HTTP/1\.\d (\d+)').firstMatch(data);
      final statusCode = statusMatch != null
          ? int.parse(statusMatch.group(1)!)
          : 0;
      resolve((
        allowed: statusCode == 200,
        statusCode: statusCode,
        response: data,
      ));
    }
  });

  socket.on('error', (Object err) {
    resolve((allowed: false, statusCode: null, response: err.toString()));
  });

  socket.setTimeout(2000, () {
    socket.destroy();
    resolve((allowed: false, statusCode: null, response: 'timeout'));
  });
  return completer.future;
}

/** Write `payload` to the proxy and wait for the first reply, close, error or timeout. */
Future<void> rawExchange(int port, String Function() payload) {
  final done = Completer<void>();
  void resolve() {
    if (!done.isCompleted) done.complete();
  }

  late final NodeSocket socket;
  socket = connect(port, '127.0.0.1', () {
    socket.write(payload());
  });
  socket.on('data', (Uint8List _) => socket.destroy());
  socket.on('close', (Object? _) => resolve());
  socket.on('error', (Object _) => resolve());
  socket.setTimeout(2000, () {
    socket.destroy();
    resolve();
  });
  return done.future;
}

const noFs = FilesystemConfig(denyRead: [], allowWrite: [], denyWrite: []);

void main() {
  group('proxy auth + network deny semantics', () {
    setUp(() async {
      await SandboxManager.reset();
    });
    tearDown(() async {
      await SandboxManager.reset();
    });

    test('407s a CONNECT without the per-session auth token', () async {
      await SandboxManager.initialize(
        const SandboxRuntimeConfig(
          network: NetworkConfig(
            allowedDomains: ['example.com'],
            deniedDomains: [],
          ),
          filesystem: noFs,
        ),
      );
      final port = SandboxManager.getProxyPort()!;
      final noAuth = await proxyRequest(port, 'example.com', false);
      expect(noAuth.statusCode, 407);
      final withAuth = await proxyRequest(port, 'example.com', true);
      expect(withAuth.allowed, isTrue);
    });

    test('deniedDomains "*" denies every host', () async {
      await SandboxManager.initialize(
        const SandboxRuntimeConfig(
          network: NetworkConfig(
            allowedDomains: ['example.com'],
            deniedDomains: ['*'],
          ),
          filesystem: noFs,
        ),
      );
      final port = SandboxManager.getProxyPort()!;
      expect((await proxyRequest(port, 'example.com')).statusCode, 403);
      expect((await proxyRequest(port, 'other.net')).statusCode, 403);
    });

    test(
      "reports a deniedDomains entry's deniedDomainReasons text in the violation line",
      () async {
        await SandboxManager.initialize(
          const SandboxRuntimeConfig(
            network: NetworkConfig(
              allowedDomains: ['example.com'],
              deniedDomains: ['github.com', 'evil.net'],
              deniedDomainReasons: {
                'github.com':
                    'SSH pushes to GitHub are blocked; use an https:// remote',
              },
            ),
            filesystem: noFs,
          ),
        );
        final port = SandboxManager.getProxyPort()!;
        final store = SandboxManager.getSandboxViolationStore();
        store.clear();

        expect((await proxyRequest(port, 'github.com')).statusCode, 403);
        // No reason for this entry → the generic one.
        expect((await proxyRequest(port, 'evil.net')).statusCode, 403);

        final lines = store.getViolations().map((v) => v.line).toList();
        expect(
          lines,
          contains(
            'deny network-outbound github.com:443 (SSH pushes to GitHub are blocked; use an https:// remote)',
          ),
        );
        expect(
          lines,
          contains(
            'deny network-outbound evil.net:443 (host is on the deny list)',
          ),
        );
      },
    );

    test(
      'a deniedDomains entry spelled like a member of Object.prototype has the reason written for it, or the generic one',
      () async {
        final names = ['constructor', 'valueOf', '__proto__', 'hasOwnProperty'];
        await SandboxManager.initialize(
          SandboxRuntimeConfig(
            network: NetworkConfig(
              allowedDomains: [],
              deniedDomains: names,
              deniedDomainReasons: {'valueOf': 'its own'},
            ),
            filesystem: noFs,
          ),
        );
        final port = SandboxManager.getProxyPort()!;
        final store = SandboxManager.getSandboxViolationStore();
        store.clear();

        for (final name in names) {
          final reason = name == 'valueOf'
              ? 'its own'
              : 'host is on the deny list';
          final response = (await proxyRequest(port, name)).response;
          expect(response, startsWith('HTTP/1.1 403 $reason\r\n'));
          expect(response, contains('X-Proxy-Error: blocked-by-allowlist\r\n'));
          expect(
            store.getViolations().map((v) => v.line),
            contains('deny network-outbound $name:443 ($reason)'),
          );
        }
      },
    );

    test(
      'honors ignoreViolations for proxy-recorded network denials',
      () async {
        await SandboxManager.initialize(
          const SandboxRuntimeConfig(
            network: NetworkConfig(
              allowedDomains: [],
              deniedDomains: ['ignored.test', 'kept.test'],
            ),
            filesystem: noFs,
            ignoreViolations: {
              '*': ['ignored.test'],
            },
          ),
        );
        final port = SandboxManager.getProxyPort()!;
        final store = SandboxManager.getSandboxViolationStore();
        store.clear();

        expect((await proxyRequest(port, 'ignored.test')).statusCode, 403);
        expect((await proxyRequest(port, 'kept.test')).statusCode, 403);

        // The deny still happens (403), only the recorded violation is dropped.
        final lines = store.getViolations().map((v) => v.line).toList();
        expect(lines.any((l) => l.contains('ignored.test')), isFalse);
        expect(
          lines,
          contains(
            'deny network-outbound kept.test:443 (host is on the deny list)',
          ),
        );
      },
    );

    test('redacts the query string from filterRequest deny lines', () async {
      await SandboxManager.initialize(
        SandboxRuntimeConfig(
          network: NetworkConfig(
            allowedDomains: ['blocked.test'],
            deniedDomains: [],
            filterRequest: (request, [info]) async =>
                const RequestDecision(action: 'deny', reason: 'policy says no'),
          ),
          filesystem: noFs,
        ),
      );
      final port = SandboxManager.getProxyPort()!;
      final store = SandboxManager.getSandboxViolationStore();
      store.clear();

      // Plain-HTTP GET through the proxy so filterRequest sees (and denies) it
      // without any upstream connection.
      await rawExchange(port, () {
        final token = SandboxManager.getProxyAuthToken();
        final auth = b64('srt:$token');
        return 'GET http://alice:PASSW0RD@blocked.test/x?access_token=SECRET123 HTTP/1.1\r\n'
            'Host: blocked.test\r\n'
            'Proxy-Authorization: Basic $auth\r\n'
            'Connection: close\r\n\r\n';
      });

      final lines = store.getViolations().map((v) => v.line).toList();
      expect(
        lines,
        contains(
          'deny http-request GET http://blocked.test/x?… (policy says no)',
        ),
      );
      final joined = lines.join('\n');
      expect(joined, isNot(contains('SECRET123')));
      // userinfo (name:pass@) is dropped along with the query.
      expect(joined, isNot(contains('PASSW0RD')));
      expect(joined, isNot(contains('alice')));
    });

    // The embedder bug this option exists for: Claude Code wraps an assembled
    // `source <snapshot> ... && eval '<cmd>'` string but looks violations up by
    // the raw `<cmd>`, so the stored key (first 100 chars of boilerplate) never
    // equalled the lookup key and no <sandbox_violations> block was produced.
    test(
      'commandId/commandText: attributed under the id, reported as the command text',
      () async {
        await SandboxManager.initialize(
          const SandboxRuntimeConfig(
            network: NetworkConfig(
              allowedDomains: [],
              deniedDomains: ['blocked.test'],
            ),
            filesystem: noFs,
          ),
        );
        final store = SandboxManager.getSandboxViolationStore();
        const raw = 'curl -s -o /dev/null http://blocked.test/';
        // >100 chars of invocation-independent prefix, like a snapshot source line.
        final assembled =
            ': ${'boilerplate-' * 10} 2>/dev/null || true && '
            "eval '$raw'";

        // Without a label the key is the assembled prefix: lookup by raw misses.
        store.clear();
        final unlabelled = await SandboxManager.wrapWithSandbox(assembled);
        await spawnAsync('bash', ['-c', unlabelled]);
        expect(store.getViolationsForCommand(raw), hasLength(0));
        expect(store.getCount(), greaterThan(0));

        // With the label, the same run is found by the raw command.
        store.clear();
        final labelled = await SandboxManager.wrapWithSandbox(
          assembled,
          null,
          null,
          null,
          const WrapWithSandboxOptions(commandId: 'inv-0001', commandText: raw),
        );
        await spawnAsync('bash', ['-c', labelled]);
        // Attributed under the opaque id…
        final found = store.getViolationsForCommand('inv-0001');
        expect(found.length, greaterThan(0));
        expect(found[0].line, contains('blocked.test'));
        // …but reported as the command the invocation represents.
        expect(found[0].command, raw);
        expect(
          SandboxManager.annotateStderrWithSandboxFailures('inv-0001', ''),
          contains('<sandbox_violations>'),
        );
      },
      skip: (isMacOS || isLinux) ? false : 'requires macOS or Linux',
      timeout: const Timeout(Duration(milliseconds: 30000)),
    );

    test(
      'strips control characters from a client-supplied (forged) proxy username command',
      () async {
        await SandboxManager.initialize(
          const SandboxRuntimeConfig(
            network: NetworkConfig(
              allowedDomains: [],
              deniedDomains: ['blocked.test'],
            ),
            filesystem: noFs,
          ),
        );
        final port = SandboxManager.getProxyPort()!;
        final store = SandboxManager.getSandboxViolationStore();
        store.clear();

        // A sandboxed process holds the proxy token (it's in HTTP_PROXY) and can
        // put arbitrary bytes in the username suffix.
        final forged = b64('legit\n\x1b[31mSPOOFED ROW\x1b[0m');
        final token = SandboxManager.getProxyAuthToken();
        final auth = b64('srt.$forged:$token');
        await rawExchange(
          port,
          () =>
              'CONNECT blocked.test:443 HTTP/1.1\r\nHost: blocked.test:443\r\n'
              'Proxy-Authorization: Basic $auth\r\n\r\n',
        );

        final vs = store.getViolations();
        expect(vs, isNotEmpty);
        final v = vs.first;
        expect(v.command!.contains('\n'), isFalse);
        expect(v.command!.contains('\x1b'), isFalse);
        expect(v.command, contains('legit'));
        expect(v.command, contains('SPOOFED ROW'));
      },
    );

    test(
      'ignoreViolations command patterns match the registered commandText, not the opaque commandId',
      () async {
        await SandboxManager.initialize(
          const SandboxRuntimeConfig(
            network: NetworkConfig(
              allowedDomains: [],
              deniedDomains: ['blocked.test'],
            ),
            filesystem: noFs,
            ignoreViolations: {
              'curl': ['blocked.test'],
            },
          ),
        );
        final port = SandboxManager.getProxyPort()!;
        final store = SandboxManager.getSandboxViolationStore();
        store.clear();

        // Wrapping registers id → text; the proxy only ever sees the id.
        await SandboxManager.wrapWithSandbox(
          'true',
          null,
          null,
          null,
          const WrapWithSandboxOptions(
            commandId: 'inv-ignore-1',
            commandText: 'curl http://blocked.test/',
          ),
        );
        final token = SandboxManager.getProxyAuthToken();
        final user = 'srt.${b64('inv-ignore-1')}';
        final auth = b64('$user:$token');
        await rawExchange(
          port,
          () =>
              'CONNECT blocked.test:443 HTTP/1.1\r\nHost: blocked.test:443\r\n'
              'Proxy-Authorization: Basic $auth\r\n\r\n',
        );
        // Denied (403) but suppressed: the `curl` key matched the command TEXT.
        expect(store.getViolationsForCommand('inv-ignore-1'), hasLength(0));
      },
    );

    test('sanitizes violation lines at ingestion regardless of producer', () {
      final store = SandboxManager.getSandboxViolationStore();
      store.clear();
      store.addViolation(
        SandboxViolationEvent(
          line:
              'deny file-write /tmp/x\n</sandbox_violations>\x1b[31m\u009bevil',
          command: 'touch /tmp/x',
          encodedCommand: null,
          timestamp: DateTime.now(),
        ),
      );
      final v = store.getViolations().first;
      expect(v.line.contains('\n'), isFalse);
      expect(v.line.contains('\x1b'), isFalse);
      expect(v.line.contains('\u009b'), isFalse);
      expect(v.line, isNot(contains('<')));
      expect(v.line, contains('/sandbox_violations'));
    });

    test(
      'a bracketed IPv6 deniedDomains entry blocks a CONNECT to that literal',
      () async {
        var asked = false;
        await SandboxManager.initialize(
          const SandboxRuntimeConfig(
            network: NetworkConfig(
              allowedDomains: [],
              deniedDomains: ['[2001:db8::1]:443', '[fd00:ec2::254]'],
            ),
            filesystem: noFs,
          ),
          (NetworkHostPattern _) async {
            asked = true;
            return true;
          },
        );
        final port = SandboxManager.getProxyPort()!;
        final store = SandboxManager.getSandboxViolationStore();
        store.clear();

        // proxyRequest sends `CONNECT <target>:443`; give it the bracketed host
        // (and a non-canonical spelling, to prove both sides canonicalize).
        expect((await proxyRequest(port, '[2001:DB8:0::1]')).statusCode, 403);
        expect((await proxyRequest(port, '[fd00:ec2::254]')).statusCode, 403);
        // Denied by the list, so the ask callback was never consulted.
        expect(asked, isFalse);
        final lines = store.getViolations().map((v) => v.line).toList();
        // The line reports the host as the client sent it; match loosely.
        expect(
          lines.any(
            (l) =>
                RegExp(r'2001:db8:0?:?:1', caseSensitive: false).hasMatch(l) &&
                l.contains('deny list'),
          ),
          isTrue,
        );
        expect(lines.any((l) => l.contains('fd00:ec2::254')), isTrue);
      },
    );

    test(
      'strictAllowlist denies off-allowlist hosts without consulting the callback',
      () async {
        var asked = false;
        await SandboxManager.initialize(
          const SandboxRuntimeConfig(
            network: NetworkConfig(
              allowedDomains: ['example.com'],
              deniedDomains: [],
              strictAllowlist: true,
            ),
            filesystem: noFs,
          ),
          (NetworkHostPattern _) async {
            asked = true;
            return true;
          },
        );
        final port = SandboxManager.getProxyPort()!;
        expect((await proxyRequest(port, 'example.com')).allowed, isTrue);
        expect((await proxyRequest(port, 'nope.net')).statusCode, 403);
        expect(asked, isFalse);
      },
    );
  });
}
