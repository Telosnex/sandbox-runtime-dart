// Ported from sandbox-runtime test/sandbox/update-config.test.ts @ 0bbebed.
// ignore_for_file: non_constant_identifier_names
import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:test/test.dart';

import 'package:sandbox_runtime/src/index.dart';
import 'package:sandbox_runtime/src/node/crypto.dart' show randomBytes;
import 'package:sandbox_runtime/src/node/console.dart' as console;
import 'package:sandbox_runtime/src/node/fetch.dart' as fetch;
import 'package:sandbox_runtime/src/node/errno.dart' show NodeException;
import 'package:sandbox_runtime/src/node/process.dart' as process;
import 'package:sandbox_runtime/src/node/net.dart'
    show NodeAddress, NodeServer, NodeSocket, connect, createServer;
import 'package:sandbox_runtime/src/sandbox/sandbox_utils.dart'
    show encodeSandboxedCommand, proxyUsernameFor;
import 'package:sandbox_runtime/src/utils/platform.dart' show getPlatform;
import '../helpers/platform.dart' show isLinux, isMacOS;
import '../helpers/spawn.dart' show RunOpts, spawnAsync;

String b64(String s) => base64Encode(utf8.encode(s));

/// Helper to make a CONNECT request through the proxy using raw TCP
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

/// Write `payload` to the proxy and wait for the first reply, close, error or timeout.
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

  /// CONNECT `target` ("host:port") through the proxy under `username`, with the
  /// session token, and report the status code of the reply.
  Future<int?> connectAs(int proxyPort, String target, String username) {
    final completer = Completer<int?>();
    void resolve(int? v) {
      if (!completer.isCompleted) completer.complete(v);
    }

    final token = SandboxManager.getProxyAuthToken();
    final auth = b64('$username:$token');
    late final NodeSocket socket;
    socket = connect(proxyPort, '127.0.0.1', () {
      socket.write(
        'CONNECT $target HTTP/1.1\r\nHost: $target\r\n'
        'Proxy-Authorization: Basic $auth\r\n\r\n',
      );
    });
    var data = '';
    socket.on('data', (Uint8List chunk) {
      data += utf8.decode(chunk, allowMalformed: true);
      if (data.contains('\r\n')) {
        socket.destroy();
        final status = RegExp(r'HTTP/1\.\d (\d+)').firstMatch(data);
        resolve(status != null ? int.parse(status.group(1)!) : null);
      }
    });
    socket.on('error', (Object _) => resolve(null));
    socket.setTimeout(2000, () {
      socket.destroy();
      resolve(null);
    });
    return completer.future;
  }

  /// The same over SOCKS5: the reply code to a CONNECT for `target` under
  /// `username` (0 is granted, 2 is refused by the rules).
  Future<int?> socksConnectAs(int proxyPort, String target, String username) {
    final completer = Completer<int?>();
    final parts = target.split(':');
    final host = parts[0];
    final port = parts[1];
    List<int> field(String text) => [
      utf8.encode(text).length,
      ...utf8.encode(text),
    ];
    late final NodeSocket socket;
    socket = connect(proxyPort, '127.0.0.1', () {
      socket.write(
        Uint8List.fromList([
          // Offer username/password only, authenticate, then CONNECT by name.
          0x05, 0x01, 0x02, 0x01,
          ...field(username),
          ...field(SandboxManager.getProxyAuthToken() ?? ''),
          0x05, 0x01, 0x00, 0x03,
          ...field(host),
          int.parse(port) >> 8, int.parse(port) & 0xff,
        ]),
      );
    });
    var reply = <int>[];
    socket.on('data', (Uint8List chunk) {
      reply = [...reply, ...chunk];
      // Method selection (2 bytes), auth status (2), then VER and REP.
      if (reply.length >= 6) socket.destroy();
    });
    socket.on('close', (Object? _) {
      if (!completer.isCompleted) {
        completer.complete(reply.length > 5 ? reply[5] : null);
      }
    });
    socket.on('error', (Object _) {});
    socket.setTimeout(2000, () => socket.destroy());
    return completer.future;
  }

  /// A listener on loopback for the proxy to dial, so an allow is observed as a
  /// 200 without leaving the machine: an IP literal has no name to resolve and
  /// nothing for the resolved-address check to refuse. It answers a request with
  /// the body `ok`.
  Future<({NodeServer server, String target})> listenOnLoopback() {
    final completer = Completer<({NodeServer server, String target})>();
    final server = createServer((NodeSocket socket) {
      socket.on('error', (Object _) {});
      socket.once(
        'data',
        () => socket.end('HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok'),
      );
    });
    server.listen(0, '127.0.0.1', () {
      final port = (server.address()! as NodeAddress).port;
      completer.complete((server: server, target: '127.0.0.1:$port'));
    });
    return completer.future;
  }

  /// An id of the kind the API asks for: 16 random bytes, 22 characters.
  String randomCommandId() => randomBytes(16).toString('base64url');

  /// The proxy username a wrap given this commandId puts in the proxy URLs.
  String usernameFor(String commandId) =>
      proxyUsernameFor(encodeSandboxedCommand(commandId));

  const noFilesystemRules = noFs;

  List<String> violationLines() => SandboxManager.getSandboxViolationStore()
      .getViolations()
      .map((v) => v.line)
      .toList();

  group('per-command network allow lists', () {
    late ({NodeServer server, String target}) loopback;
    late List<String> asked;
    Future<Object> denyAndRecord(NetworkHostPattern p) async {
      asked.add('${p.host}:${p.port}');
      return false;
    }

    Future<int> start({
      List<String> allowedDomains = const [],
      List<String> deniedDomains = const [],
      bool? strictAllowlist,
      int? httpProxyPort,
      SandboxAskCallback? callback,
    }) async {
      await SandboxManager.initialize(
        SandboxRuntimeConfig(
          network: NetworkConfig(
            allowedDomains: allowedDomains,
            deniedDomains: deniedDomains,
            strictAllowlist: strictAllowlist,
            httpProxyPort: httpProxyPort,
          ),
          filesystem: noFilesystemRules,
        ),
        callback,
      );
      SandboxManager.getSandboxViolationStore().clear();
      return SandboxManager.getProxyPort()!;
    }

    setUp(() async {
      await SandboxManager.reset();
      loopback = await listenOnLoopback();
      asked = [];
    });

    tearDown(() async {
      await SandboxManager.reset();
      loopback.server.close();
    });

    test(
      'lifts the default deny for the id the connection presents, and for no other',
      () async {
        final port = await start();
        final registered = randomCommandId();
        SandboxManager.registerCommandNetworkLists(registered, (
          allowedDomains: [loopback.target],
        ));

        expect(
          await connectAs(port, loopback.target, usernameFor(registered)),
          200,
        );
        // Any other id, and no id at all, see the configured lists alone.
        expect(
          await connectAs(
            port,
            loopback.target,
            usernameFor(randomCommandId()),
          ),
          403,
        );
        expect(await connectAs(port, loopback.target, 'srt'), 403);
        expect(violationLines(), [
          'deny network-outbound ${loopback.target} (host is not on the allow list)',
          'deny network-outbound ${loopback.target} (host is not on the allow list)',
        ]);
      },
    );

    test('applies over SOCKS5 as it does over CONNECT', () async {
      await start();
      final port = SandboxManager.getSocksProxyPort()!;
      final registered = randomCommandId();
      SandboxManager.registerCommandNetworkLists(registered, (
        allowedDomains: [loopback.target],
      ));

      expect(
        await socksConnectAs(port, loopback.target, usernameFor(registered)),
        0,
      );
      expect(
        await socksConnectAs(
          port,
          loopback.target,
          usernameFor(randomCommandId()),
        ),
        2,
      );
    });

    // The one case where the wrap, not usernameFor(), mints the username.
    test(
      'reaches a sandboxed command through the commandId its wrap was given',
      () async {
        await start();
        Future<String> curlAs(String commandId) async {
          final wrapped = await SandboxManager.wrapWithSandbox(
            // NO_PROXY in the sandbox exempts loopback; this goes to the proxy.
            "curl -s --noproxy '' --max-time 3 http://${loopback.target}/",
            null,
            null,
            null,
            WrapWithSandboxOptions(commandId: commandId),
          );
          return (await spawnAsync('bash', ['-c', wrapped])).stdout;
        }

        final registered = randomCommandId();
        SandboxManager.registerCommandNetworkLists(registered, (
          allowedDomains: [loopback.target],
        ));

        expect(await curlAs(registered), 'ok');
        expect(await curlAs(randomCommandId()), isNot('ok'));
        expect(violationLines(), [
          'deny network-outbound ${loopback.target} (host is not on the allow list)',
        ]);
      },
      skip: (isMacOS || isLinux) ? false : 'requires macOS or Linux',
      timeout: const Timeout(Duration(milliseconds: 30000)),
    );

    test(
      'is consulted before the ask callback, which still decides every host it does not list',
      () async {
        final port = await start(callback: denyAndRecord);
        final registered = randomCommandId();
        SandboxManager.registerCommandNetworkLists(registered, (
          allowedDomains: [loopback.target],
        ));

        expect(
          await connectAs(port, loopback.target, usernameFor(registered)),
          200,
        );
        expect(asked, <String>[]);

        expect(
          await connectAs(port, 'unlisted.test:443', usernameFor(registered)),
          403,
        );
        expect(await connectAs(port, loopback.target, 'srt'), 403);
        expect(asked, ['unlisted.test:443', loopback.target]);
      },
    );

    test(
      'uses the grammar of network.allowedDomains: a port suffix narrows an entry, a wildcard widens it',
      () async {
        final port = await start(callback: denyAndRecord);
        final registered = randomCommandId();
        final targetParts = loopback.target.split(':');
        final host = targetParts[0];
        final listeningPort = targetParts[1];
        // Any valid port but the listener's, which can itself be 65535.
        final anotherPort = int.parse(listeningPort) == 65535
            ? 65534
            : int.parse(listeningPort) + 1;
        SandboxManager.registerCommandNetworkLists(registered, (
          allowedDomains: ['$host:$anotherPort', '*.wild.test'],
        ));

        // Listed for another port only, so the callback is asked and denies.
        expect(
          await connectAs(port, loopback.target, usernameFor(registered)),
          403,
        );
        expect(asked, [loopback.target]);
        // The wildcard matches a subdomain (the filter allows; the dial then
        // fails, which is not a 403) and, as in the configuration, not the apex.
        expect(
          await connectAs(port, 'a.wild.test:443', usernameFor(registered)),
          isNot(403),
        );
        expect(
          await connectAs(port, 'wild.test:443', usernameFor(registered)),
          403,
        );
        expect(asked, [loopback.target, 'wild.test:443']);
      },
    );

    test('never overrides a configured deniedDomains entry', () async {
      final port = await start(
        deniedDomains: ['127.0.0.1'],
        callback: denyAndRecord,
      );
      final registered = randomCommandId();
      SandboxManager.registerCommandNetworkLists(registered, (
        allowedDomains: [loopback.target],
      ));

      expect(
        await connectAs(port, loopback.target, usernameFor(registered)),
        403,
      );
      expect(violationLines(), [
        'deny network-outbound ${loopback.target} (host is on the deny list)',
      ]);
      expect(asked, <String>[]);
    });

    test('is ignored entirely under strictAllowlist', () async {
      final port = await start(strictAllowlist: true, callback: denyAndRecord);
      final registered = randomCommandId();
      SandboxManager.registerCommandNetworkLists(registered, (
        allowedDomains: [loopback.target],
      ));

      expect(
        await connectAs(port, loopback.target, usernameFor(registered)),
        403,
      );
      expect(violationLines(), [
        'deny network-outbound ${loopback.target} (host is not on the allow list)',
      ]);
      expect(asked, <String>[]);
    });

    test(
      'never enters network.*, so the configured allow list does not grow',
      () async {
        await start(allowedDomains: ['example.com']);
        SandboxManager.registerCommandNetworkLists(randomCommandId(), (
          allowedDomains: [loopback.target, 'percommand.test'],
        ));

        expect(SandboxManager.getConfig()?.network.allowedDomains, [
          'example.com',
        ]);
        expect(SandboxManager.getNetworkRestrictionConfig().allowedHosts, [
          'example.com',
        ]);
      },
    );

    test(
      'stops applying once unregistered; unregistering an id that has no list changes nothing',
      () async {
        final port = await start();
        final registered = randomCommandId();
        SandboxManager.registerCommandNetworkLists(registered, (
          allowedDomains: [loopback.target],
        ));

        SandboxManager.unregisterCommandNetworkLists(randomCommandId());
        // Unregistering lets a non-string pass, so a cleanup path never throws.
        // Dart: the typed API cannot be handed a non-string (null, 42), so the
        // loop over those has no counterpart.
        expect(
          await connectAs(port, loopback.target, usernameFor(registered)),
          200,
        );

        SandboxManager.unregisterCommandNetworkLists(registered);
        expect(
          await connectAs(port, loopback.target, usernameFor(registered)),
          403,
        );
        // Twice is as good as once.
        SandboxManager.unregisterCommandNetworkLists(registered);
      },
    );

    test('replaces the list when an id is registered again', () async {
      final port = await start();
      final registered = randomCommandId();
      SandboxManager.registerCommandNetworkLists(registered, (
        allowedDomains: [loopback.target],
      ));
      SandboxManager.registerCommandNetworkLists(registered, (
        allowedDomains: ['elsewhere.test'],
      ));

      expect(
        await connectAs(port, loopback.target, usernameFor(registered)),
        403,
      );
    });

    test(
      'keeps the list it validated when the caller changes its array afterwards',
      () async {
        final port = await start();
        final registered = randomCommandId();
        final entries = ['elsewhere.test'];
        SandboxManager.registerCommandNetworkLists(registered, (
          allowedDomains: entries,
        ));
        entries.add(loopback.target);

        expect(
          await connectAs(port, loopback.target, usernameFor(registered)),
          403,
        );
      },
    );

    test('forgets every list on reset', () async {
      await start();
      final registered = randomCommandId();
      SandboxManager.registerCommandNetworkLists(registered, (
        allowedDomains: [loopback.target],
      ));

      await SandboxManager.reset();
      final port = await start();
      expect(
        await connectAs(port, loopback.target, usernameFor(registered)),
        403,
      );
    });

    test(
      'registers under an external network.httpProxyPort, where no list applies, and says so in the debug log',
      () async {
        final before = process.env['SRT_DEBUG'];
        process.env['SRT_DEBUG'] = '1';
        final oldWarn = console.warn;
        final oldError = console.error;
        final calls = <String>[];
        console.warn = ([Object? a, Object? b, Object? c, Object? d]) =>
            calls.add(a.toString());
        console.error = ([Object? a, Object? b, Object? c, Object? d]) {};
        List<String> warnings() => calls
            .where((message) => message.contains('registerCommandNetworkLists'))
            .toList();
        try {
          await start();
          SandboxManager.registerCommandNetworkLists(randomCommandId(), (
            allowedDomains: null,
          ));
          expect(warnings(), <String>[]);

          await SandboxManager.reset();
          await start(httpProxyPort: 8888);
          final registered = randomCommandId();
          SandboxManager.registerCommandNetworkLists(registered, (
            allowedDomains: [loopback.target],
          ));
          expect(warnings(), hasLength(1));
          expect(warnings()[0], contains('this list will never apply'));
          expect(warnings()[0], isNot(contains(registered)));
          // The library's own port still serves SOCKS and CONNECT, and reads no id.
          expect(
            await connectAs(
              SandboxManager.getSocksProxyPort()!,
              loopback.target,
              usernameFor(registered),
            ),
            403,
          );
        } finally {
          console.warn = oldWarn;
          console.error = oldError;
          if (before == null) {
            process.env.remove('SRT_DEBUG');
          } else {
            process.env['SRT_DEBUG'] = before;
          }
        }
      },
    );

    Matcher throwsMessage(Pattern pattern) => throwsA(
      isA<NodeException>().having(
        (e) => e.message,
        'message',
        matches(pattern),
      ),
    );

    test(
      'refuses an id shorter than 22 characters, and says what an id has to be',
      () {
        const lists = (allowedDomains: ['example.com']);
        for (final tooShort in ['', '1', 'inv-0001', 'a' * 21]) {
          expect(
            () => SandboxManager.registerCommandNetworkLists(tooShort, lists),
            throwsMessage(RegExp('at least 22 characters')),
          );
        }
        expect(
          () => SandboxManager.registerCommandNetworkLists('a' * 21, lists),
          throwsMessage(
            RegExp(
              'only thing that binds a proxy connection to this allow list',
            ),
          ),
        );
        expect(
          () => SandboxManager.registerCommandNetworkLists('a' * 21, lists),
          throwsMessage(
            RegExp('random .* never derived from the command text'),
          ),
        );
        // A JavaScript caller's null or number is no id either.
        // Dart: the typed API cannot be handed one, so that loop has no
        // counterpart.
        // The floor itself is accepted, and an empty or absent list is a list.
        SandboxManager.registerCommandNetworkLists('a' * 22, lists);
        SandboxManager.registerCommandNetworkLists(randomCommandId(), (
          allowedDomains: null,
        ));
        SandboxManager.registerCommandNetworkLists(randomCommandId(), (
          allowedDomains: <String>[],
        ));
        // So is no second argument at all, which a JavaScript caller can pass.
        // Dart: the typed API cannot be called without its second argument.
      },
    );

    test('does not repeat the id in the error it throws', () {
      const almost = 'secret-id-0123456789x';
      expect(almost, hasLength(21));
      var message = '';
      try {
        SandboxManager.registerCommandNetworkLists(almost, (
          allowedDomains: null,
        ));
      } on NodeException catch (error) {
        message = error.message;
      }
      expect(message, isNot(''));
      expect(message, isNot(contains(almost)));
    });

    test(
      'measures the floor on the key it stores, where an unpaired surrogate counts for nothing',
      () {
        // Each is 22 characters long, and is stored with U+FFFD in place of every
        // unpaired surrogate. U+FFFD is not counted.
        for (final hollow in [
          '\u{d800}' * 22,
          '${'a' * 21}\u{dc00}',
          '\u{fffd}' * 22,
        ]) {
          expect(hollow, hasLength(22));
          expect(
            () => SandboxManager.registerCommandNetworkLists(hollow, (
              allowedDomains: null,
            )),
            throwsMessage(
              RegExp('at least 22 characters, unpaired surrogates not counted'),
            ),
          );
        }
        // A pair is a character like any other, counted as String.length does.
        SandboxManager.registerCommandNetworkLists('\u{1f600}' * 11, (
          allowedDomains: null,
        ));
      },
    );

    // A list arriving at run time cannot carry an entry the configuration
    // would have refused, and the other way round.
    for (final (entry, valid) in <(String, bool)>[
      ('example.com', true),
      ('*.example.com', true),
      ('api.example.com:443', true),
      ('localhost', true),
      ('127.0.0.1:3000', true),
      ('[::1]', true),
      ('[2001:db8::1]:443', true),
      ('*', false),
      ('*:443', false),
      ('*.com', false),
      ('https://example.com', false),
      ('example.com/path', false),
      ('example.com:0', false),
      ('example.com:443.evil.test', false),
      ('2001:db8::1', false),
      ('nodots', false),
      ('', false),
    ]) {
      test(
        'accepts the entry ${jsonEncode(entry)} exactly when network.allowedDomains does ($valid)',
        () {
          expect(
            SandboxRuntimeConfigSchema.safeParse({
              'network': {
                'allowedDomains': [entry],
                'deniedDomains': <String>[],
              },
              'filesystem': noFilesystemRules.toJson(),
            }).success,
            valid,
          );
          void register() => SandboxManager.registerCommandNetworkLists(
            randomCommandId(),
            (allowedDomains: [entry]),
          );
          if (valid) {
            expect(register, returnsNormally);
          } else {
            expect(
              register,
              throwsMessage(RegExp('invalid allowedDomains entry')),
            );
          }
        },
      );
    }

    test(
      'refuses an entry that is not a string, and a list that is not an array',
      () {},
      // Dart: the body hands the API null, undefined, 443, an object and a bare
      // string; the typed List<String> parameter cannot be given any of them.
      skip: 'a Dart caller cannot pass a non-string entry or a non-array list',
    );

    test('registers nothing when any entry is invalid', () async {
      final port = await start();
      final registered = randomCommandId();
      expect(
        () => SandboxManager.registerCommandNetworkLists(registered, (
          allowedDomains: [loopback.target, '*.com'],
        )),
        throwsMessage(RegExp(r'invalid allowedDomains entry "\*\.com"')),
      );

      expect(
        await connectAs(port, loopback.target, usernameFor(registered)),
        403,
      );
    });

    // An id is normalised before it keys the map, and what the proxy receives
    // is decoded rather than compared as bytes, so an id can differ from the
    // registered one byte for byte and reach its list all the same.
    group('ids that differ byte for byte from the registered one', () {
      test(
        'share a list when they agree on their first 100 characters',
        () async {
          final port = await start();
          final prefix = randomBytes(75).toString('base64url');
          expect(prefix, hasLength(100));
          SandboxManager.registerCommandNetworkLists('$prefix-first', (
            allowedDomains: [loopback.target],
          ));

          // Both ids mint one username: the key is cut to 100 characters.
          expect(usernameFor('$prefix-second'), usernameFor('$prefix-first'));
          expect(
            await connectAs(
              port,
              loopback.target,
              usernameFor('$prefix-second'),
            ),
            200,
          );

          // An uncut username decodes to a longer key, which has no list.
          final uncut = b64('$prefix-first');
          expect(await connectAs(port, loopback.target, 'srt.$uncut'), 403);

          // And unregistering either id removes the one list they share.
          SandboxManager.unregisterCommandNetworkLists('$prefix-second');
          expect(
            await connectAs(
              port,
              loopback.target,
              usernameFor('$prefix-first'),
            ),
            403,
          );
        },
      );

      test(
        'reach the list through any base64 spelling of the same bytes',
        () async {
          final port = await start();
          // 22 characters that encode with padding and with both of the
          // characters the URL-safe alphabet spells differently.
          const registered = 'id?>id?>id?>id?>id?>~~';
          final minted = encodeSandboxedCommand(registered);
          expect(minted, matches(RegExp(r'[+/]')));
          expect(minted, matches(RegExp(r'=$')));
          SandboxManager.registerCommandNetworkLists(registered, (
            allowedDomains: [loopback.target],
          ));

          final unpadded = minted.replaceAll(RegExp(r'=+$'), '');
          final urlSafe = unpadded.replaceAll('+', '-').replaceAll('/', '_');
          for (final spelling in [minted, unpadded, urlSafe]) {
            expect(
              await connectAs(port, loopback.target, 'srt.$spelling'),
              200,
            );
          }
        },
      );

      test(
        'share a list when they differ only in an unpaired surrogate',
        () async {
          final port = await start();
          final stem = randomCommandId();
          // Neither half of a surrogate pair can be encoded on its own; each
          // becomes U+FFFD, so both ids normalise to one key.
          SandboxManager.registerCommandNetworkLists('$stem\u{d800}', (
            allowedDomains: [loopback.target],
          ));

          expect(
            await connectAs(
              port,
              loopback.target,
              usernameFor('$stem\u{dfff}'),
            ),
            200,
          );
          expect(
            await connectAs(
              port,
              loopback.target,
              usernameFor('$stem\u{fffd}'),
            ),
            200,
          );
          // The stem alone is a different key.
          expect(
            await connectAs(port, loopback.target, usernameFor(stem)),
            403,
          );
        },
      );

      test('do not reach it by differing in case', () async {
        final port = await start();
        final registered = '${randomCommandId()}abc';
        SandboxManager.registerCommandNetworkLists(registered, (
          allowedDomains: [loopback.target],
        ));

        expect(
          await connectAs(
            port,
            loopback.target,
            usernameFor(registered.toUpperCase()),
          ),
          403,
        );
      });
    });
  });

  group('ask callback answers', () {
    late ({NodeServer server, String target}) loopback;

    /// One CONNECT to the loopback listener, decided by `answer` alone.
    Future<({int? status, List<String> lines})> decideWith(
      Object answer,
    ) async {
      await SandboxManager.initialize(
        const SandboxRuntimeConfig(
          network: NetworkConfig(allowedDomains: [], deniedDomains: []),
          filesystem: noFilesystemRules,
        ),
        (NetworkHostPattern _) async => answer,
      );
      SandboxManager.getSandboxViolationStore().clear();
      final status = await connectAs(
        SandboxManager.getProxyPort()!,
        loopback.target,
        'srt',
      );
      return (status: status, lines: violationLines());
    }

    List<String> deniedBecause(String reason) => [
      'deny network-outbound ${loopback.target} ($reason)',
    ];

    setUp(() async {
      await SandboxManager.reset();
      loopback = await listenOnLoopback();
    });

    tearDown(() async {
      await SandboxManager.reset();
      loopback.server.close();
    });

    test('declares that it reads a denial with a reason', () {
      expect(SandboxManager.askCallbackDenyReason, isTrue);
    });

    test('allows on true', () async {
      final r = await decideWith(true);
      expect(r.status, 200);
      expect(r.lines, <String>[]);
    });

    test('denies on false, with the generic reason', () async {
      final r = await decideWith(false);
      expect(r.status, 403);
      expect(r.lines, deniedBecause('user denied'));
    });

    test(
      'denies on { allow: false, reason }, and reports that reason',
      () async {
        Future<Object> callback(NetworkHostPattern _) async => {
          'allow': false,
          'reason':
              'not listed for this command; list the host and run it again',
        };
        final r = await decideWith(await callback((host: '', port: 0)));
        expect(r.status, 403);
        expect(
          r.lines,
          deniedBecause(
            'not listed for this command; list the host and run it again',
          ),
        );
      },
    );

    for (final (name, answer) in <(String, Object)>[
      ('an empty reason', {'allow': false, 'reason': ''}),
      (
        'a reason of nothing but whitespace',
        {'allow': false, 'reason': ' \n\t '},
      ),
      ('no reason', {'allow': false}),
      ('a reason that is not a string', {'allow': false, 'reason': 42}),
    ]) {
      test('denies with the generic reason on $name', () async {
        final r = await decideWith(answer);
        expect(r.status, 403);
        expect(r.lines, deniedBecause('user denied'));
      });
    }

    // A filter that tested truthiness would allow every one of these.
    for (final (name, answer) in <(String, Object)>[
      ('the number 1', 1),
      ('a non-empty string', 'yes'),
      ('an empty object', <String, Object?>{}),
      ('an empty array', <Object?>[]),
      ('an object that says allow: true', {'allow': true}),
      ('the string "true"', 'true'),
      // A reason is reported only for an answer that says allow: false.
      (
        'an object that says allow: true and gives a reason',
        {'allow': true, 'reason': 'approved for this session'},
      ),
      (
        'an object that gives a reason and no allow',
        {'reason': 'no verdict given'},
      ),
      (
        'an object whose allow is falsy but not false',
        {'allow': 0, 'reason': 'zero is not false'},
      ),
    ]) {
      test('denies on a truthy answer that is not true: $name', () async {
        final r = await decideWith(answer);
        expect(r.status, 403);
        expect(r.lines, deniedBecause('user denied'));
      });
    }

    // Dart: the answer type is non-nullable (Future<Object>), so undefined and
    // null cannot be returned; only zero remains of the falsy answers.
    for (final (name, answer) in <(String, Object)>[('zero', 0)]) {
      test('denies on a falsy answer that is not false: $name', () async {
        final r = await decideWith(answer);
        expect(r.status, 403);
        expect(r.lines, deniedBecause('user denied'));
      });
    }

    test('cuts an over-long reason to 500 characters', () async {
      final r = await decideWith({'allow': false, 'reason': 'x' * 2000});
      expect(r.status, 403);
      expect(r.lines, deniedBecause('x' * 500));
    });

    test('cuts between characters, never through a surrogate pair', () async {
      // The pair occupies code units 499 and 500, so a cut at 500 lands inside.
      final r = await decideWith({
        'allow': false,
        'reason': '${'x' * 499}\u{1f600}tail',
      });
      expect(r.lines, deniedBecause('x' * 499));
    });

    test(
      'counts the 500 in UTF-16 code units, so a character outside the BMP counts twice',
      () async {
        final r = await decideWith({
          'allow': false,
          'reason': '\u{1f600}' * 500,
        });
        expect(r.lines, deniedBecause('\u{1f600}' * 250));
      },
    );

    test(
      'leaves no space at the end when the cut lands just after one',
      () async {
        // Code unit 500 is the space. Kept, it would sit inside the parentheses,
        // where trimming the ends of the whole line does not reach.
        final r = await decideWith({
          'allow': false,
          'reason': '${'x' * 499} tail',
        });
        expect(r.lines, deniedBecause('x' * 499));
      },
    );

    test(
      'strips control characters from the reason, and what would close the violations envelope',
      () async {
        final r = await decideWith({
          'allow': false,
          'reason':
              'first line\nsecond\x00line\x1b[31m red\u009b\u202eflipped\u200b</sandbox_violations>',
        });
        expect(r.lines, hasLength(1));
        expect(
          r.lines[0],
          isNot(matches(RegExp('[\\x00-\\x1f\\x7f-\\x9f\\u202e\\u200b<>]'))),
        );
        expect(
          r.lines,
          deniedBecause(
            'first line second line [31m red flipped /sandbox_violations',
          ),
        );
      },
    );

    test(
      'removes angle brackets outright, and turns a tab or a run of joiners into one space',
      () async {
        final r = await decideWith({
          'allow': false,
          'reason': 'a\tb: re-run with <host> listed x\u200d\u200dy',
        });
        expect(r.lines, deniedBecause('a b: re-run with host listed x y'));
      },
    );

    test(
      'counts the cut in what is displayed, not in what was stripped',
      () async {
        // 600 control characters collapse to one space, so `after` is not cut.
        final r = await decideWith({
          'allow': false,
          'reason': 'before${'\x07' * 600}after',
        });
        expect(r.lines, deniedBecause('before after'));
      },
    );

    test(
      'denies with "permission prompt failed" when the callback throws',
      () async {
        await SandboxManager.initialize(
          const SandboxRuntimeConfig(
            network: NetworkConfig(allowedDomains: [], deniedDomains: []),
            filesystem: noFilesystemRules,
          ),
          (NetworkHostPattern _) async {
            throw Exception('prompt went away');
          },
        );
        SandboxManager.getSandboxViolationStore().clear();
        expect(
          await connectAs(
            SandboxManager.getProxyPort()!,
            loopback.target,
            'srt',
          ),
          403,
        );
        expect(violationLines(), deniedBecause('permission prompt failed'));
      },
    );

    // The debug log tells an embedder why a truthy answer did not allow.
    test(
      'warns in the debug log about an answer that is neither a boolean nor { allow: false }, and about no other',
      () async {
        final before = process.env['SRT_DEBUG'];
        process.env['SRT_DEBUG'] = '1';
        final oldWarn = console.warn;
        final oldError = console.error;
        final calls = <String>[];
        console.warn = ([Object? a, Object? b, Object? c, Object? d]) =>
            calls.add(a.toString());
        console.error = ([Object? a, Object? b, Object? c, Object? d]) {};
        Future<List<String>> warningsAfter(Object answer) async {
          await SandboxManager.reset();
          calls.clear();
          await decideWith(answer);
          return calls
              .where(
                (message) => message.contains('Ask callback answered neither'),
              )
              .toList();
        }

        try {
          for (final undeclared in <Object>[
            1,
            'yes',
            <String, Object?>{},
            {'allow': true, 'reason': 'ok'},
          ]) {
            final warnings = await warningsAfter(undeclared);
            expect(warnings, hasLength(1));
            expect(warnings[0], contains('treating it as a denial'));
            expect(warnings[0], contains(loopback.target));
          }
          for (final declared in <Object>[
            true,
            false,
            {'allow': false, 'reason': 'no'},
          ]) {
            expect(await warningsAfter(declared), <String>[]);
          }
        } finally {
          console.warn = oldWarn;
          console.error = oldError;
          if (before == null) {
            process.env.remove('SRT_DEBUG');
          } else {
            process.env['SRT_DEBUG'] = before;
          }
        }
      },
    );
  });

  group('SandboxManager.updateConfig', () {
    setUp(() async {
      await SandboxManager.reset();
    });

    tearDown(() async {
      await SandboxManager.reset();
    });

    test('should handle updateConfig called before initialize', () async {
      // updateConfig before initialize - should not throw
      SandboxManager.updateConfig(
        const SandboxRuntimeConfig(
          network: NetworkConfig(
            allowedDomains: ['example.com'],
            deniedDomains: [],
          ),
          filesystem: noFs,
        ),
      );

      // Config should be set
      expect(SandboxManager.getConfig(), isNotNull);

      // But network infrastructure not ready
      expect(SandboxManager.getProxyPort(), isNull);

      // Initialize should still work and respect the pre-set config
      await SandboxManager.initialize(
        const SandboxRuntimeConfig(
          network: NetworkConfig(
            allowedDomains: ['other.com'],
            deniedDomains: [],
          ),
          filesystem: noFs,
        ),
      );

      // initialize() overwrites config
      final config = SandboxManager.getConfig();
      expect(config?.network.allowedDomains, contains('other.com'));
      expect(config?.network.allowedDomains, isNot(contains('example.com')));
    });

    test('should update network restriction config dynamically', () async {
      // Initialize with no allowed domains
      await SandboxManager.initialize(
        const SandboxRuntimeConfig(
          network: NetworkConfig(allowedDomains: [], deniedDomains: []),
          filesystem: noFs,
        ),
      );

      // Initial state: allowlist configured with zero entries. The getter must
      // preserve the empty array — consumers distinguish "no allowlist
      // configured" (undefined) from "allowlist configured, nothing allowed".
      expect(
        SandboxManager.getNetworkRestrictionConfig().allowedHosts,
        <String>[],
      );

      // Update config to allow example.com
      SandboxManager.updateConfig(
        const SandboxRuntimeConfig(
          network: NetworkConfig(
            allowedDomains: ['example.com'],
            deniedDomains: [],
          ),
          filesystem: noFs,
        ),
      );

      // Config should now reflect the update
      final config = SandboxManager.getNetworkRestrictionConfig();
      expect(config.allowedHosts, contains('example.com'));
    });

    test('should handle moving domain from allowlist to denylist', () async {
      // Initialize with example.com allowed
      await SandboxManager.initialize(
        const SandboxRuntimeConfig(
          network: NetworkConfig(
            allowedDomains: ['example.com'],
            deniedDomains: [],
          ),
          filesystem: noFs,
        ),
      );

      var config = SandboxManager.getNetworkRestrictionConfig();
      expect(config.allowedHosts, contains('example.com'));
      expect(config.deniedHosts, isNull);

      // Move to denylist
      SandboxManager.updateConfig(
        const SandboxRuntimeConfig(
          network: NetworkConfig(
            allowedDomains: [],
            deniedDomains: ['example.com'],
          ),
          filesystem: noFs,
        ),
      );

      config = SandboxManager.getNetworkRestrictionConfig();
      expect(config.allowedHosts, <String>[]);
      expect(config.deniedHosts, contains('example.com'));

      // Move back to allowlist
      SandboxManager.updateConfig(
        const SandboxRuntimeConfig(
          network: NetworkConfig(
            allowedDomains: ['example.com'],
            deniedDomains: [],
          ),
          filesystem: noFs,
        ),
      );

      config = SandboxManager.getNetworkRestrictionConfig();
      expect(config.allowedHosts, contains('example.com'));
      expect(config.deniedHosts, isNull);
    });

    test('should handle updating to empty allowlist', () async {
      // Initialize with example.com allowed
      await SandboxManager.initialize(
        const SandboxRuntimeConfig(
          network: NetworkConfig(
            allowedDomains: ['example.com'],
            deniedDomains: [],
          ),
          filesystem: noFs,
        ),
      );

      expect(
        SandboxManager.getNetworkRestrictionConfig().allowedHosts,
        contains('example.com'),
      );

      // Update to empty allowlist (should block all)
      SandboxManager.updateConfig(
        const SandboxRuntimeConfig(
          network: NetworkConfig(allowedDomains: [], deniedDomains: []),
          filesystem: noFs,
        ),
      );

      // The getter preserves the explicitly-empty allowlist so consumers can
      // tell a configured block-all apart from no restriction at all
      expect(
        SandboxManager.getNetworkRestrictionConfig().allowedHosts,
        <String>[],
      );

      // Verify the actual config still exists
      final fullConfig = SandboxManager.getConfig();
      expect(fullConfig, isNotNull);
      expect(fullConfig?.network.allowedDomains, <String>[]);
    });

    test(
      'preserves filterRequest across updateConfig (structuredClone cannot clone functions)',
      () {
        Future<RequestDecision> filterRequest(
          fetch.Request request, [
          RequestInfo? info,
        ]) async => const RequestDecision(action: 'allow');
        // Must not throw: structuredClone(fn) throws DataCloneError; the
        // function is pulled out, the rest is cloned, then the reference is
        // restored.
        SandboxManager.updateConfig(
          SandboxRuntimeConfig(
            network: NetworkConfig(
              allowedDomains: [],
              deniedDomains: [],
              filterRequest: filterRequest,
            ),
            filesystem: noFs,
          ),
        );
        expect(
          SandboxManager.getConfig()?.network.filterRequest,
          same(filterRequest),
        );
      },
    );
  });

  group('SandboxManager.updateConfig proxy filtering', () {
    tearDown(() async {
      await SandboxManager.reset();
    });

    test('should allow then block domain after config update', () async {
      // Initialize with example.com allowed
      await SandboxManager.initialize(
        const SandboxRuntimeConfig(
          network: NetworkConfig(
            allowedDomains: ['example.com'],
            deniedDomains: [],
          ),
          filesystem: noFs,
        ),
      );

      final proxyPort = SandboxManager.getProxyPort();
      expect(proxyPort, isNotNull);

      // Should be allowed initially
      final result1 = await proxyRequest(proxyPort!, 'example.com');
      expect(result1.allowed, isTrue);

      // Update to block example.com (empty allowlist)
      SandboxManager.updateConfig(
        const SandboxRuntimeConfig(
          network: NetworkConfig(allowedDomains: [], deniedDomains: []),
          filesystem: noFs,
        ),
      );

      // Should now be blocked
      final result2 = await proxyRequest(proxyPort, 'example.com');
      expect(result2.allowed, isFalse);
    });

    test('should block then allow domain after config update', () async {
      // Initialize with empty allowlist (blocks all)
      await SandboxManager.initialize(
        const SandboxRuntimeConfig(
          network: NetworkConfig(allowedDomains: [], deniedDomains: []),
          filesystem: noFs,
        ),
      );

      final proxyPort = SandboxManager.getProxyPort();
      expect(proxyPort, isNotNull);

      // Should be blocked initially
      final result1 = await proxyRequest(proxyPort!, 'example.com');
      expect(result1.allowed, isFalse);

      // Update to allow example.com
      SandboxManager.updateConfig(
        const SandboxRuntimeConfig(
          network: NetworkConfig(
            allowedDomains: ['example.com'],
            deniedDomains: [],
          ),
          filesystem: noFs,
        ),
      );

      // Should now be allowed
      final result2 = await proxyRequest(proxyPort, 'example.com');
      expect(result2.allowed, isTrue);
    });

    test('should handle moving domain between allow and deny lists', () async {
      // Initialize with example.com allowed
      await SandboxManager.initialize(
        const SandboxRuntimeConfig(
          network: NetworkConfig(
            allowedDomains: ['example.com'],
            deniedDomains: [],
          ),
          filesystem: noFs,
        ),
      );

      final proxyPort = SandboxManager.getProxyPort();
      expect(proxyPort, isNotNull);

      // Should be allowed initially
      final result1 = await proxyRequest(proxyPort!, 'example.com');
      expect(result1.allowed, isTrue);

      // Move to denylist
      SandboxManager.updateConfig(
        const SandboxRuntimeConfig(
          network: NetworkConfig(
            allowedDomains: [],
            deniedDomains: ['example.com'],
          ),
          filesystem: noFs,
        ),
      );

      // Should now be blocked
      final result2 = await proxyRequest(proxyPort, 'example.com');
      expect(result2.allowed, isFalse);

      // Move back to allowlist
      SandboxManager.updateConfig(
        const SandboxRuntimeConfig(
          network: NetworkConfig(
            allowedDomains: ['example.com'],
            deniedDomains: [],
          ),
          filesystem: noFs,
        ),
      );

      // Should be allowed again
      final result3 = await proxyRequest(proxyPort, 'example.com');
      expect(result3.allowed, isTrue);
    });

    test('should handle rapid config updates', () async {
      await SandboxManager.initialize(
        const SandboxRuntimeConfig(
          network: NetworkConfig(
            allowedDomains: ['example.com'],
            deniedDomains: [],
          ),
          filesystem: noFs,
        ),
      );

      final proxyPort = SandboxManager.getProxyPort();
      expect(proxyPort, isNotNull);

      // Rapid updates
      for (var i = 0; i < 5; i++) {
        SandboxManager.updateConfig(
          const SandboxRuntimeConfig(
            network: NetworkConfig(allowedDomains: [], deniedDomains: []),
            filesystem: noFs,
          ),
        );

        SandboxManager.updateConfig(
          const SandboxRuntimeConfig(
            network: NetworkConfig(
              allowedDomains: ['example.com'],
              deniedDomains: [],
            ),
            filesystem: noFs,
          ),
        );
      }

      // Final state should allow example.com
      final result = await proxyRequest(proxyPort!, 'example.com');
      expect(result.allowed, isTrue);
    });
  });

  /// Integration tests using wrapWithSandbox() to verify sandbox wrapper generation
  /// and actual network behavior with sandboxed curl commands.
  group('SandboxManager.updateConfig integration (wrapWithSandbox)', () {
    tearDown(() async {
      await SandboxManager.reset();
    });

    test(
      'should block then allow domain after updateConfig with sandboxed curl',
      () async {
        // Initialize with empty allowlist (blocks all)
        await SandboxManager.initialize(
          const SandboxRuntimeConfig(
            network: NetworkConfig(allowedDomains: [], deniedDomains: []),
            filesystem: noFs,
          ),
        );

        // First request should be blocked
        final cmd1 = await SandboxManager.wrapWithSandbox(
          'curl -s --max-time 3 http://example.com 2>&1',
        );
        final result1 = await spawnAsync(
          cmd1,
          const RunOpts(shell: true, encoding: 'utf8', timeout: 5000),
        );
        final output1 = (result1.stdout + result1.stderr).toLowerCase();
        // With empty allowlist, network is completely blocked (no proxy)
        expect(output1, isNot(contains('example domain')));

        // Update config to allow example.com
        SandboxManager.updateConfig(
          const SandboxRuntimeConfig(
            network: NetworkConfig(
              allowedDomains: ['example.com'],
              deniedDomains: [],
            ),
            filesystem: noFs,
          ),
        );

        // Second request should succeed
        // Note: wrapWithSandbox() generates new command with updated config
        final cmd2 = await SandboxManager.wrapWithSandbox(
          'curl -s --max-time 5 http://example.com 2>&1',
        );
        final result2 = await spawnAsync(
          cmd2,
          const RunOpts(shell: true, encoding: 'utf8', timeout: 10000),
        );

        expect(result2.status, 0);
        expect(result2.stdout, contains('Example Domain'));
      },
      skip: isLinux ? false : 'requires Linux',
      timeout: const Timeout(Duration(milliseconds: 20000)),
    );

    test(
      'should allow then block domain after updateConfig with sandboxed curl',
      () async {
        // Initialize with example.com allowed
        await SandboxManager.initialize(
          const SandboxRuntimeConfig(
            network: NetworkConfig(
              allowedDomains: ['example.com'],
              deniedDomains: [],
            ),
            filesystem: noFs,
          ),
        );

        // First request should succeed
        final cmd1 = await SandboxManager.wrapWithSandbox(
          'curl -s --max-time 5 http://example.com 2>&1',
        );
        final result1 = await spawnAsync(
          cmd1,
          const RunOpts(shell: true, encoding: 'utf8', timeout: 10000),
        );
        expect(result1.status, 0);
        expect(result1.stdout, contains('Example Domain'));

        // Update config to block all
        SandboxManager.updateConfig(
          const SandboxRuntimeConfig(
            network: NetworkConfig(allowedDomains: [], deniedDomains: []),
            filesystem: noFs,
          ),
        );

        // Second request should be blocked
        final cmd2 = await SandboxManager.wrapWithSandbox(
          'curl -s --max-time 3 http://example.com 2>&1',
        );
        final result2 = await spawnAsync(
          cmd2,
          const RunOpts(shell: true, encoding: 'utf8', timeout: 5000),
        );
        final output2 = (result2.stdout + result2.stderr).toLowerCase();
        expect(output2, isNot(contains('example domain')));
      },
      skip: isLinux ? false : 'requires Linux',
      timeout: const Timeout(Duration(milliseconds: 20000)),
    );

    test(
      'should allow network via curl after updateConfig when started with empty allowlist',
      () async {
        // Initialize with EMPTY allowlist
        await SandboxManager.initialize(
          const SandboxRuntimeConfig(
            network: NetworkConfig(allowedDomains: [], deniedDomains: []),
            filesystem: noFs,
          ),
        );

        // Update config to allow example.com
        SandboxManager.updateConfig(
          const SandboxRuntimeConfig(
            network: NetworkConfig(
              allowedDomains: ['example.com'],
              deniedDomains: [],
            ),
            filesystem: noFs,
          ),
        );

        // Full integration: sandboxed curl should work
        final cmd = await SandboxManager.wrapWithSandbox(
          'curl -s --max-time 5 http://example.com 2>&1',
        );
        final result = await spawnAsync(
          cmd,
          const RunOpts(shell: true, encoding: 'utf8', timeout: 10000),
        );

        expect(result.status, 0);
        expect(result.stdout, contains('Example Domain'));
      },
      skip: isLinux ? false : 'requires Linux',
      timeout: const Timeout(Duration(milliseconds: 20000)),
    );

    /// This test verifies the exact user scenario:
    /// 1. Start sandbox with allowedDomains: [], deniedDomains: ["example.com"]
    /// 2. Generate wrapper (should include proxy config even with empty allowlist)
    /// 3. Update config to allow example.com
    /// 4. Proxy should now allow requests (tested via raw TCP)
    ///
    /// The fix: even with empty allowlist, wrapper includes proxy config so
    /// updateConfig() can enable network access for sandboxed processes.
    test(
      'should allow network after updateConfig when started with empty allowlist and denylist',
      () async {
        // Initialize with empty allowlist, example.com in denylist (user's exact scenario)
        await SandboxManager.initialize(
          const SandboxRuntimeConfig(
            network: NetworkConfig(
              allowedDomains: [],
              deniedDomains: ['example.com'],
            ),
            filesystem: noFs,
          ),
        );

        // Wrapper should include proxy config even with empty allowlist
        final cmd = await SandboxManager.wrapWithSandbox('echo test');
        final platform = getPlatform();
        if (platform == 'macos') {
          expect(cmd, contains('HTTP_PROXY'));
        } else if (platform == 'linux') {
          expect(cmd, matches(RegExp(r'HTTP_PROXY|\.sock')));
        }

        // Proxy should be running
        final proxyPort = SandboxManager.getProxyPort();
        expect(proxyPort, isNotNull);

        // Initially, example.com should be blocked (empty allowlist = block all)
        final blockedResult = await proxyRequest(proxyPort!, 'example.com');
        expect(blockedResult.allowed, isFalse);

        // Update config to allow example.com
        SandboxManager.updateConfig(
          const SandboxRuntimeConfig(
            network: NetworkConfig(
              allowedDomains: ['example.com'],
              deniedDomains: [],
            ),
            filesystem: noFs,
          ),
        );

        // Now example.com should be allowed
        final allowedResult = await proxyRequest(proxyPort, 'example.com');
        expect(allowedResult.allowed, isTrue);
      },
    );

    /// This test verifies the core fix: sandbox wrapper should include proxy config
    /// even with empty allowlist, enabling dynamic updates.
    test(
      'should include proxy in sandbox wrapper even with empty allowlist',
      () async {
        // Initialize with EMPTY allowlist - this is the bug scenario
        await SandboxManager.initialize(
          const SandboxRuntimeConfig(
            network: NetworkConfig(allowedDomains: [], deniedDomains: []),
            filesystem: noFs,
          ),
        );

        // Get the sandbox wrapper command
        final wrapper = await SandboxManager.wrapWithSandbox('echo test');

        // The wrapper should include proxy configuration
        // On macOS: HTTP_PROXY and HTTPS_PROXY env vars
        // On Linux: socket paths
        final platform = getPlatform();
        if (platform == 'macos') {
          expect(wrapper, contains('HTTP_PROXY'));
          expect(wrapper, contains('HTTPS_PROXY'));
        } else if (platform == 'linux') {
          // Linux uses unix sockets, check for socket paths or proxy env vars
          expect(wrapper, matches(RegExp(r'HTTP_PROXY|http_proxy|\.sock')));
        }
      },
    );
  });
}
