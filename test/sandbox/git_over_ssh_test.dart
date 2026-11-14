// Ported from sandbox-runtime test/sandbox/git-over-ssh.test.ts @ 0bbebed.
// ignore_for_file: constant_identifier_names, non_constant_identifier_names, slash_for_doc_comments, library_private_types_in_public_api, prefer_is_empty
import 'dart:async';
import 'dart:convert';

import 'package:path/path.dart' show join;
import 'package:sandbox_runtime/src/node/buffer.dart' show Buffer;
import 'package:sandbox_runtime/src/node/child_process.dart'
    show ChildProcess, spawn, spawnSync;
import 'package:sandbox_runtime/src/node/console.dart' as console;
import 'package:sandbox_runtime/src/node/crypto.dart'
    show createHash, randomBytes;
import 'package:sandbox_runtime/src/node/events.dart' show once;
import 'package:sandbox_runtime/src/node/fs.dart'
    show
        existsSync,
        mkdtempSync,
        readFileSync,
        realpathSync,
        rmSync,
        writeFileSync;
import 'package:sandbox_runtime/src/node/net.dart'
    show NodeAddress, NodeServer, NodeSocket, connect, createServer;
import 'package:sandbox_runtime/src/node/os.dart' show tmpdir;
import 'package:sandbox_runtime/src/node/process.dart' as process;
import 'package:sandbox_runtime/src/sandbox/http_proxy.dart';
import 'package:sandbox_runtime/src/sandbox/sandbox_config.dart';
import 'package:sandbox_runtime/src/sandbox/sandbox_manager.dart';
import 'package:sandbox_runtime/src/sandbox/sandbox_schemas.dart';
import 'package:sandbox_runtime/src/sandbox/sandbox_utils.dart'
    show generateProxyEnvVars, sshConnectScript;
import 'package:sandbox_runtime/src/node/stream.dart' as stream;
import 'package:sandbox_runtime/src/utils/shell_quote.dart' show quote;
import 'package:sandbox_runtime/src/utils/which.dart' show whichSync;
import 'package:test/test.dart';

import '../helpers/bwrap_namespace.dart' show bwrapCanNamespaceNetwork;
import '../helpers/platform.dart' show isLinux, isMacOS, isWindows;
import '../helpers/spawn.dart' show RunOpts, RunResult, spawnAsync;

/**
 * git over ssh through the authenticating proxy, with nothing outside this
 * host: an unprivileged sshd on loopback, a scratch repository, the real
 * ssh, git and proxy.
 *
 * macOS gets its own ProxyCommand (`sshConnectScript`). Everything but its
 * `nc` is portable, so the script is driven on Linux too, with the nc found
 * there. Two things differ and are marked below: the nc of macOS leaves as
 * soon as the network side ends, netcat-openbsd only once its stdin has
 * ended as well; and the nc of macOS half-closes the socket at the end of
 * stdin, which netcat-openbsd does only under -N.
 */

final NC = existsSync('/usr/bin/nc') ? '/usr/bin/nc' : whichSync('nc');
final SSHD = existsSync('/usr/sbin/sshd')
    ? '/usr/sbin/sshd'
    : whichSync('sshd');
String absent(Map<String, Object?> tools) {
  final names = tools.keys
      .where((name) => tools[name] == null || tools[name] == false)
      .toList();
  return names.isNotEmpty ? ' [SKIPPED: no ${names.join(', ')}]' : '';
}

final NO_SCRIPT = isWindows ? ' [SKIPPED: Windows]' : absent({'nc': NC});
final NO_SSH = NO_SCRIPT.isNotEmpty
    ? NO_SCRIPT
    : absent({
        'sshd': SSHD,
        'ssh': whichSync('ssh'),
        'ssh-keygen': whichSync('ssh-keygen'),
        'git': whichSync('git'),
      });
final NO_SANDBOX = NO_SSH.isNotEmpty
    ? NO_SSH
    : (isLinux
          ? absent({
              'network namespaces': bwrapCanNamespaceNetwork(),
              'socat': whichSync('socat'),
            })
          : '');

final List<String> SHELLS = [
  '/bin/sh',
  '/bin/bash',
  '/bin/zsh',
  '/bin/dash',
  '/bin/ksh',
  '/bin/tcsh',
  '/bin/csh',
  whichSync('fish'),
].whereType<String>().where((s) => existsSync(s)).toList();

const TOKEN = '0123456789abcdef0123456789abcdef';
String basicOf(String token) =>
    Buffer.from('srt.Zm9v:$token').toString('base64');

/** Well under every test's own limit: what "promptly" means below. */
const PROMPT_MS = 15000;
const TEST_MS = 90000;

// Dart: `it(..., TEST_MS)`'s timeout argument.
const _testTimeout = Timeout(Duration(milliseconds: TEST_MS));

// Dart: the object literal upstream hands createHttpProxyServer; every
// option not named here is absent (null).
class _HttpOptions implements HttpProxyServerOptions {
  _HttpOptions({required this.filterFn, this.proxyAuthToken});
  final FutureOr<bool> Function(
    int port,
    String host,
    stream.Duplex socket,
    String? encodedCommand,
    void Function(String reason)? explain,
  )
  filterFn;
  @override
  final String? proxyAuthToken;
  @override
  FutureOr<bool> filter(
    int port,
    String host,
    stream.Duplex socket, [
    String? encodedCommand,
    void Function(String reason)? explain,
  ]) => filterFn(port, host, socket, encodedCommand, explain);
  @override
  dynamic noSuchMethod(Invocation invocation) => null;
}

Future<int> listen(NodeServer server) {
  final completer = Completer<int>();
  server.once('error', (Object? e) => completer.completeError(e!));
  server.listen(0, '127.0.0.1', () {
    completer.complete((server.address() as NodeAddress).port);
  });
  return completer.future;
}

/** A loopback port nothing listens on. */
Future<int> freePort() async {
  final server = createServer();
  final port = await listen(server);
  final closed = Completer<void>();
  server.close(() => closed.complete());
  await closed.future;
  return port;
}

/**
 * The library's HTTP proxy, requiring TOKEN; `asked` is what reached its
 * filter, which takes its time, as one that asks somebody does.
 */
Future<({int port, List<String> asked, void Function() close})> startProxy(
  int allowedPort,
) async {
  final asked = <String>[];
  final proxy = createHttpProxyServer(
    _HttpOptions(
      filterFn: (port, host, _, encodedCommand, explain) async {
        asked.add('$host:$port $encodedCommand');
        await Future<void>.delayed(const Duration(milliseconds: 200));
        explain?.call('not today');
        return host == '127.0.0.1' && port == allowedPort;
      },
      proxyAuthToken: TOKEN,
    ),
  );
  return (
    port: await listen(proxy),
    asked: asked,
    close: () {
      proxy.close();
      proxy.closeAllConnections();
    },
  );
}

/** The two variables macOS is given, whatever host this runs on. */
Map<String, String> macosVars(int proxyPort, [String token = TOKEN]) {
  // Dart: spyOn(platform, 'getPlatform') is process.setPlatformForTesting.
  process.setPlatformForTesting('darwin');
  try {
    final vars = Map<String, String>.fromEntries(
      generateProxyEnvVars(proxyPort, proxyPort, null, token, true, 'Zm9v')
          .where(
            (v) => RegExp(
              r'^(GIT_SSH_COMMAND|SRT_SSH_PROXY_COMMAND)=',
            ).hasMatch(v),
          )
          .map(
            (v) => MapEntry(
              v.substring(0, v.indexOf('=')),
              v.substring(v.indexOf('=') + 1),
            ),
          ),
    );
    return NC == '/usr/bin/nc'
        ? vars
        : {
            ...vars,
            'SRT_SSH_PROXY_COMMAND': sshConnectScript(
              proxyPort,
              basicOf(token),
              NC!,
            ),
          };
  } finally {
    process.setPlatformForTesting(null);
  }
}

// Dart: the object `hold` returns upstream, as a class.
class _Held {
  _Held({
    required this.child,
    required this.stdout,
    required this.stderr,
    required this.outEnded,
    required this.exited,
    required this.destroyStdout,
  });
  final ChildProcess child;
  final Buffer Function() stdout;
  final String Function() stderr;

  /** Resolves to the time it took stdout to end. */
  final Future<int> outEnded;
  final Future<int?> exited;

  // Dart: child.stdout is a Stream; its destroy() is cancelling the listener.
  final Future<void> Function() destroyStdout;

  /** What ssh does: once its input has ended, it closes its output and goes. */
  Future<({int ms, int? code})> leaveLikeSsh() async {
    final ms = await outEnded;
    child.stdin!.end();
    return (ms: ms, code: await exited);
  }
}

/** A running ProxyCommand, held the way ssh holds one: both pipes open. */
_Held hold(List<String> argv, Map<String, String> env) {
  final child = spawn(argv[0], argv.sublist(1), {
    'env': {...process.env, ...env},
  });
  final out = <List<int>>[];
  var err = '';
  final outEnded0 = Completer<int>();
  final started = DateTime.now().millisecondsSinceEpoch;
  final outSub = child.stdout!.listen(
    (d) => out.add(d),
    onDone: () =>
        outEnded0.complete(DateTime.now().millisecondsSinceEpoch - started),
  );
  child.stderr!.listen((d) => err += utf8.decode(d, allowMalformed: true));
  // Dart: child.stdin has no 'error' event to ignore.
  final outEnded = outEnded0.future;
  final exited = once(child, 'close').then((args) => args[0] as int?);
  return _Held(
    child: child,
    stdout: () => Buffer.concat(out),
    stderr: () => err,
    outEnded: outEnded,
    exited: exited,
    destroyStdout: () => outSub.cancel(),
  );
}

/** The script with `host` and `port` as ssh's %h and %p, past every shell. */
_Held runScript(
  String script,
  String host,
  String port, [
  List<String> sh = const ['/bin/sh'],
  Map<String, String> env = const {},
]) => hold(
  [...sh, '-c', 'eval "\$SRT_SSH_PROXY_COMMAND"', 'sh', host, port],
  {...env, 'SRT_SSH_PROXY_COMMAND': script},
);

/**
 * A shell whose `[a-z]` follows the locale, where there is one: bash does up
 * to 4.2, which is the /bin/sh of macOS, and later when asked to.
 */
const UTF8 = {'LC_ALL': 'en_US.UTF-8'};
final List<String>? COLLATING_SH = () {
  for (final entry in [
    ['/bin/sh'],
    ['/bin/bash', '--posix', '+O', 'globasciiranges'],
  ]) {
    final sh = entry[0];
    final options = entry.sublist(1);
    if (!isWindows &&
        spawnSync(
              sh,
              [...options, '-c', 'case \u00fc in [a-z]) exit 7;; esac'],
              {'env': UTF8},
            ).status ==
            7) {
      return entry;
    }
  }
  return null;
}();

Future<void> until(String what, bool Function() done) async {
  final deadline = DateTime.now().millisecondsSinceEpoch + PROMPT_MS;
  while (!done()) {
    if (DateTime.now().millisecondsSinceEpoch > deadline) {
      throw Exception('timed out waiting for $what');
    }
    await Future<void>.delayed(const Duration(milliseconds: 10));
  }
}

void main() {
  group('sshConnectScript$NO_SCRIPT', skip: NO_SCRIPT != '' ? 'unavailable' : null, () {
    final servers = <NodeServer>[];
    final sockets = <NodeSocket>[];
    final closers = <void Function()>[];

    /** A TCP server that records what it is sent, per connection. */
    Future<({int port, List<Buffer> received})> tcp(
      void Function(NodeSocket sock, Buffer all) onData,
    ) async {
      final received = <Buffer>[];
      final server = createServer({'allowHalfOpen': true}, (NodeSocket sock) {
        received.add(Buffer.alloc(0));
        final i = received.length - 1;
        sockets.add(sock);
        sock.on('error', (Object? _) {});
        sock.on('data', (Object? d) {
          received[i] = Buffer.concat([received[i], d as List<int>]);
          onData(sock, received[i]);
        });
      });
      servers.add(server);
      return (port: await listen(server), received: received);
    }

    tearDownAll(() {
      for (final s in sockets) {
        s.destroy();
      }
      for (final s in servers) {
        s.close();
      }
      for (final close in closers) {
        close();
      }
    });

    final EVERY_BYTE = Buffer.concat(
      List<Buffer>.filled(64, Buffer.from(List<int>.generate(256, (i) => i))),
    );
    const OK = 'HTTP/1.1 200 Connection Established\r\n\r\n';
    /** Answers a whole request head with `reply`, and leaves. */
    void Function(NodeSocket, Buffer) answer(String reply) =>
        (NodeSocket sock, Buffer all) {
          if (all.indexOfBytes('\r\n\r\n') >= 0 && !sock.writableEnded) {
            sock.end(reply);
          }
        };
    String headFor(String authority) =>
        'CONNECT $authority HTTP/1.1\r\nHost: $authority\r\n'
        'Proxy-Authorization: Basic ${basicOf(TOKEN)}\r\n\r\n';

    test(
      'sends one CONNECT with the credential, then every byte both ways and nothing else',
      () async {
        final head = headFor('git.example.com:22');
        final up = Buffer.concat([Buffer.from('SSH-2.0-up\r\n'), EVERY_BYTE]);
        final down = Buffer.concat([
          Buffer.from('SSH-2.0-down\r\n'),
          EVERY_BYTE,
        ]);
        var answered = false;
        final proxy = await tcp((sock, all) {
          if (!answered && all.indexOfBytes('\r\n\r\n') >= 0) {
            answered = true;
            sock.write(OK);
            sock.write(down);
          }
          if (all.length >= head.length + up.length) sock.end();
        });
        final t = runScript(
          sshConnectScript(proxy.port, basicOf(TOKEN), NC!),
          'git.example.com',
          '22',
        );
        t.child.stdin!.write(up);
        await until('the download', () => t.stdout().length >= down.length);
        t.child.stdin!.end();
        expect(await t.exited, 0);
        expect(proxy.received, hasLength(1));
        expect(
          proxy.received[0].toString('latin1'),
          head + up.toString('latin1'),
        );
        expect(t.stdout().toList(), down.toList());
        expect(t.stderr(), '');
      },
      timeout: _testTimeout,
    );

    test('brackets an IPv6 literal', () async {
      final proxy = await tcp(answer(OK));
      final t = runScript(
        sshConnectScript(proxy.port, basicOf(TOKEN), NC!),
        '2001:db8::1',
        '2222',
      );
      await until('the request', () => proxy.received.isNotEmpty);
      t.child.stdin!.end();
      expect(await t.exited, 0);
      expect(proxy.received[0].toString(), headFor('[2001:db8::1]:2222'));
    }, timeout: _testTimeout);

    test(
      'refuses a host or port that is not plainly one, before it connects',
      () async {
        final proxy = await tcp((_, _) {});
        final script = sshConnectScript(proxy.port, basicOf(TOKEN), NC!);
        final hosts = [
          '',
          'a\r\nX-Injected: 1',
          'a\nb',
          'a\rb',
          'a b',
          'a\tb',
          "a'b",
          'a"b',
          'a\$b',
          'a`b`',
          'a%b',
          'a%sb',
          'a\\b',
          'a/b',
          'a@b',
          'a;b',
          'a*',
          'a?',
          'a,b',
          'a#b',
          'a+b',
          'a=b',
          'a~b',
          'a^b',
          '[::1]',
          'a:22 HTTP/1.1',
          'b\u00fccher.example',
        ];
        for (final host in hosts) {
          final t = runScript(script, host, '22');
          expect([host, await t.leaveLikeSsh().then((r) => r.code)], [host, 1]);
          expect(t.stderr(), 'sandbox proxy: bad host\n');
          expect(t.stdout(), hasLength(0));
        }
        for (final port in [
          '',
          '22x',
          '2 2',
          '22\r\n',
          '22\nX: 1',
          '-1',
          '%s',
        ]) {
          final t = runScript(script, 'a.example', port);
          expect([port, await t.leaveLikeSsh().then((r) => r.code)], [port, 1]);
          expect(t.stderr(), 'sandbox proxy: bad port\n');
        }
        expect(proxy.received, hasLength(0));
      },
      timeout: _testTimeout,
    );

    test(
      "what a letter is does not follow the locale${absent({'shell that collates by locale': COLLATING_SH})}",
      () async {
        final proxy = await tcp((_, _) {});
        final t = runScript(
          sshConnectScript(proxy.port, basicOf(TOKEN), NC!),
          'b\u00fccher.example',
          '22',
          COLLATING_SH!,
          UTF8,
        );
        expect((await t.leaveLikeSsh()).code, 1);
        expect(t.stderr(), 'sandbox proxy: bad host\n');
        expect(proxy.received, hasLength(0));
      },
      skip: COLLATING_SH == null ? 'no shell that collates by locale' : null,
      timeout: _testTimeout,
    );

    test(
      'takes nothing but a status of 200 for a tunnel, and prints any other as it came',
      () async {
        for (final status in [
          '403 200 Connection Established',
          '2000 x',
          '200',
          '403 a%sb\\n',
        ]) {
          final proxy = await tcp(
            answer('HTTP/1.1 $status\r\n\r\nSSH-2.0-no\r\n'),
          );
          final t = runScript(
            sshConnectScript(proxy.port, basicOf(TOKEN), NC!),
            'a.example',
            '22',
          );
          final (:code, ms: _) = await t.leaveLikeSsh();
          expect(
            [code, t.stdout().toString(), t.stderr()],
            [1, '', 'sandbox proxy: a.example:22: $status\n'],
          );
        }
      },
      // Dart: upstream runs these with the bare nc, which only macOS's leaves
      // when the network side ends (see sshConnectScript); Debian and Ubuntu
      // netcat-openbsd waits for stdin, so upstream's run hangs there too.
      skip: isMacOS
          ? null
          : 'needs macOS nc (Debian/Ubuntu nc waits for stdin)',
      timeout: _testTimeout,
    );

    test(
      'a refusal ends what ssh reads promptly, while ssh still holds its end open, and says why',
      () async {
        final closedPort = await freePort();
        final proxy = await startProxy(closedPort);
        closers.add(proxy.close);
        final cases = <(String, String, String, String)>[
          (
            'not on the list',
            sshConnectScript(proxy.port, basicOf(TOKEN), NC!),
            '${closedPort - 1}',
            '403 not today',
          ),
          (
            'a wrong token',
            sshConnectScript(proxy.port, basicOf('wrong'), NC!),
            '$closedPort',
            '407 Proxy Authentication Required',
          ),
          (
            'allowed, nothing there',
            sshConnectScript(proxy.port, basicOf(TOKEN), NC!),
            '$closedPort',
            '502 Bad Gateway',
          ),
          (
            'the proxy gone',
            sshConnectScript(await freePort(), basicOf(TOKEN), NC!),
            '$closedPort',
            'no answer',
          ),
        ];
        for (final (what, script, port, why) in cases) {
          final t = runScript(script, '127.0.0.1', port);
          t.child.stdin!.write('SSH-2.0-client\r\n');
          final (:ms, :code) = await t.leaveLikeSsh();
          expect(
            [what, code, t.stderr()],
            [what, 1, 'sandbox proxy: 127.0.0.1:$port: $why\n'],
          );
          expect(t.stdout(), hasLength(0));
          expect(ms, lessThan(PROMPT_MS));
        }
        // The wrong token never reached the allow list.
        expect(proxy.asked, [
          '127.0.0.1:${closedPort - 1} Zm9v',
          '127.0.0.1:$closedPort Zm9v',
        ]);
      },
      // Dart: upstream runs these with the bare nc, which only macOS's leaves
      // when the network side ends (see sshConnectScript); Debian and Ubuntu
      // netcat-openbsd waits for stdin, so upstream's run hangs there too.
      skip: isMacOS
          ? null
          : 'needs macOS nc (Debian/Ubuntu nc waits for stdin)',
      timeout: _testTimeout,
    );

    test(
      'the end of what ssh writes reaches the far side, whose last words still arrive',
      () async {
        final far = await tcp((_, _) {});
        servers[servers.length - 1].on('connection', (Object? s) {
          final sock = s as NodeSocket;
          sock.write('hello, ');
          sock.on('end', (Object? _) => sock.end('last words'));
        });
        final proxy = await startProxy(far.port);
        closers.add(proxy.close);
        final t = runScript(
          // See the head of this file.
          sshConnectScript(
            proxy.port,
            basicOf(TOKEN),
            isMacOS ? NC! : '$NC -N',
          ),
          '127.0.0.1',
          '${far.port}',
        );
        // Not before the tunnel is up: until then the proxy takes an end of
        // input for a client that has gone, and ssh never sends one so early.
        await until('the tunnel', () => t.stdout().length > 0);
        t.child.stdin!.end('first words');
        expect(await t.exited, 0);
        expect(far.received[0].toString(), 'first words');
        expect(t.stdout().toString(), 'hello, last words');
        expect(t.stderr(), '');
      },
      timeout: _testTimeout,
    );

    // See the head of this file: netcat-openbsd stays until its stdin ends.
    test(
      'the far side leaving ends what ssh reads, while ssh still holds its end open (the nc of macOS)',
      () async {
        final far = await tcp((sock, _) => sock.end('bye'));
        final proxy = await startProxy(far.port);
        closers.add(proxy.close);
        final t = runScript(
          sshConnectScript(proxy.port, basicOf(TOKEN), NC!),
          '127.0.0.1',
          '${far.port}',
        );
        t.child.stdin!.write('hello');
        final (:ms, :code) = await t.leaveLikeSsh();
        expect(t.stdout().toString(), 'bye');
        expect([code, t.stderr()], [0, '']);
        expect(ms, lessThan(PROMPT_MS));
      },
      skip: !isMacOS ? 'macOS only' : null,
      timeout: _testTimeout,
    );

    // Through the manager's own listener, the one this script is emitted for.
    test(
      'no process of a live tunnel has the credential in its arguments, and none outlives ssh$NO_SANDBOX',
      () async {
        // A far side that never leaves: it is the listener that has to end the
        // tunnel, at the end of what nc sends.
        final far = await tcp((sock, _) => sock.write('up'));
        await SandboxManager.reset();
        await SandboxManager.initialize(
          SandboxRuntimeConfig(
            network: NetworkConfig(
              allowedDomains: ['127.0.0.1:${far.port}'],
              deniedDomains: [],
            ),
            filesystem: FilesystemConfig(
              denyRead: [],
              allowWrite: [],
              denyWrite: [],
            ),
          ),
        );
        try {
          final port = SandboxManager.getProxyPort()!;
          final token = SandboxManager.getProxyAuthToken()!;
          // See the head of this file.
          final nc = isMacOS ? NC! : '$NC -N';
          final t = runScript(
            sshConnectScript(port, basicOf(token), nc),
            '127.0.0.1',
            '${far.port}',
          );
          String ps() =>
              spawnSync(
                    'ps',
                    ['-A', '-ww', '-o', 'args'],
                    {'encoding': 'utf8'},
                  ).stdout
                  as String;
          t.child.stdin!.write('hello');
          await until('the tunnel', () => t.stdout().length > 0);
          final live = ps();
          expect(live, contains('$nc 127.0.0.1 $port'));
          expect(live, isNot(contains(token)));
          expect(live, isNot(contains(basicOf(token))));

          // ssh killed: both its ends of the pipes go at once.
          t.child.stdin!.end(); // Dart: stdin.destroy()
          await t.destroyStdout();
          await until(
            'the helpers to leave',
            () => !ps().contains(' 127.0.0.1 $port'),
          );
          await t.exited;
          expect(t.stderr(), '');
        } finally {
          await SandboxManager.reset();
        }
      },
      skip: NO_SANDBOX != '' ? 'unavailable' : null,
      timeout: _testTimeout,
    );

    /** ssh's arguments, split from GIT_SSH_COMMAND by a shell, as git has it done. */
    String proxyCommandOf(String gitSshCommand) {
      final r = spawnSync(
        '/bin/sh',
        ['-c', "ssh() { printf '%s\\n' \"\$@\"; }; $gitSshCommand"],
        {'encoding': 'utf8'},
      );
      final option = (r.stdout as String)
          .split('\n')
          .firstWhere((a) => a.startsWith('ProxyCommand='));
      return option.substring('ProxyCommand='.length);
    }

    /** What ssh hands to `$SHELL -c`. */
    String expandedBySsh(String command, String host, String port) =>
        'exec ${command.replaceAllMapped(RegExp(r'%([hp%])'), (m) {
          final c = m[1]!;
          return c == 'h'
              ? host
              : c == 'p'
              ? port
              : '%';
        })}';

    for (final shell in SHELLS) {
      test('SHELL=$shell: a host name is one word, whatever it holds', () async {
        final dir = mkdtempSync(join(tmpdir(), 'srt-ssh-word-'));
        final marker = join(dir, 'ran');
        try {
          final proxy = await tcp(answer(OK));
          final vars = macosVars(proxy.port);
          final command = proxyCommandOf(vars['GIT_SSH_COMMAND']!);
          final env = {'SRT_SSH_PROXY_COMMAND': vars['SRT_SSH_PROXY_COMMAND']!};

          final plain = hold([
            shell,
            '-c',
            expandedBySsh(command, 'a.example', '22'),
          ], env);
          await until('the request', () => proxy.received.isNotEmpty);
          plain.child.stdin!.end();
          expect([await plain.exited, plain.stderr()], [0, '']);
          expect(proxy.received.map((b) => b.toString()).toList(), [
            headFor('a.example:22'),
          ]);

          // The pair broken: the variable lost on the way here, or emptied.
          final broken = <Map<String, String>>[
            {},
            {'SRT_SSH_PROXY_COMMAND': ''},
          ];
          for (final lost in broken) {
            final t = hold([
              shell,
              '-c',
              expandedBySsh(command, 'a.example', '22'),
            ], lost);
            expect((await t.leaveLikeSsh()).code, isNot(0));
            expect(
              t.stderr(),
              matches(
                RegExp(
                  r'^[^\n]*SRT_SSH_PROXY_COMMAND: unset, but GIT_SSH_COMMAND needs it\n$',
                ),
              ),
            );
          }

          // OpenSSH 9.6 and later refuse these themselves; earlier ones hand
          // them over. (A single quote ends the word in any spelling.)
          for (final host in [
            '\$(echo >>$marker)',
            '`echo >>$marker`',
            'a;echo >>$marker',
            'a|echo >>$marker',
            'a&echo >>$marker',
            'a\necho >>$marker',
            'a b',
            'a"b',
            'a\\',
            'a!b',
            '\$HOME',
            '*',
          ]) {
            final t = hold([
              shell,
              '-c',
              expandedBySsh(command, host, '22'),
            ], env);
            expect([host, (await t.leaveLikeSsh()).code == 0], [host, false]);
          }
          expect(existsSync(marker), false);
          expect(proxy.received, hasLength(1));
        } finally {
          rmSync(dir, {'recursive': true, 'force': true});
        }
      }, timeout: _testTimeout);
    }
  });

  group(
    'git over ssh$NO_SSH',
    skip: NO_SSH != '' ? 'unavailable' : null,
    // Dart: setUpAll takes no timeout; upstream's beforeAll(…, TEST_MS).
    timeout: _testTimeout,
    () {
      const BLOB_BYTES = 24 << 20;
      var dir = '';
      ChildProcess? sshd;
      late int sshdPort;
      var sshdLog = '';
      late String blobSha256;
      late String head;
      late ({String upload, String receive}) packs;
      late String Function([int? port]) url;

      String git(List<String> args) {
        final r = spawnSync('git', args, {'encoding': 'utf8'});
        if (r.status != 0) {
          throw Exception('git ${args.join(' ')}: ${r.stderr}');
        }
        return (r.stdout as String).trim();
      }

      /** Commits `file` in the work tree, outside any sandbox. */
      String commit(String file) {
        final work = ['-C', join(dir, 'work'), '-c', 'core.compression=0'];
        git([...work, 'add', file]);
        git([
          ...work,
          ...['-c', 'user.name=t', '-c', 'user.email=t@example.com'],
          ...['commit', '-q', '-m', file],
        ]);
        return git([...work, 'rev-parse', 'HEAD']);
      }

      String sha256(String file) =>
          createHash(
                'sha256',
              ).update(readFileSync(file) as Buffer).digest('hex')
              as String;

      /** Everything a red macOS leg has to go on. */
      // Dart: `r` is a RunResult, or the record `sandboxed` returns with it.
      String explain(String what, dynamic r) {
        return '$what: status ${r.status}, signal ${r.signal}\n'
            '--- stdout\n${r.stdout}\n--- stderr\n${r.stderr}\n'
            '--- sshd\n${sshdLog.substring(sshdLog.length > 3000 ? sshdLog.length - 3000 : 0)}\n'
            '--- sandbox violations\n${SandboxManager.getSandboxViolationStore().getViolations().map((v) => v.line).join('\n')}';
      }

      Future<void> startSshd() async {
        for (var attempt = 1; ; attempt++) {
          sshdPort = await freePort();
          sshdLog = '';
          writeFileSync(
            join(dir, 'sshd_config'),
            [
              'Port $sshdPort',
              'ListenAddress 127.0.0.1',
              'HostKey $dir/host_key',
              'PidFile $dir/sshd.pid',
              'AuthorizedKeysFile $dir/authorized_keys',
              'StrictModes no',
              'UsePAM no',
              'PasswordAuthentication no',
              'LogLevel VERBOSE',
              '',
            ].join('\n'),
          );
          final child = spawn(
            SSHD!,
            ['-D', '-e', '-f', join(dir, 'sshd_config')],
            {
              'stdio': ['ignore', 'ignore', 'pipe'],
            },
          );
          child.stderr!.listen(
            (d) => sshdLog += utf8.decode(d, allowMalformed: true),
          );
          final deadline = DateTime.now().millisecondsSinceEpoch + PROMPT_MS;
          while (child.exitCode == null &&
              DateTime.now().millisecondsSinceEpoch < deadline) {
            final listening = await (() {
              final resolve = Completer<bool>();
              final probe = connect(sshdPort, '127.0.0.1');
              probe.once('error', (Object? _) => resolve.complete(false));
              probe.once('connect', () {
                probe.destroy();
                resolve.complete(true);
              });
              return resolve.future;
            })();
            if (listening) {
              sshd = child;
              return;
            }
            await Future<void>.delayed(const Duration(milliseconds: 100));
          }
          child.kill();
          if (attempt == 3) throw Exception('sshd did not start:\n$sshdLog');
        }
      }

      setUpAll(() async {
        dir = realpathSync(mkdtempSync(join(tmpdir(), 'srt-git-ssh-')));
        for (final key in ['host_key', 'id']) {
          spawnSync('ssh-keygen', [
            ...['-q', '-t', 'ed25519', '-N', '', '-f'],
            join(dir, key),
          ]);
        }
        writeFileSync(
          join(dir, 'authorized_keys'),
          readFileSync(join(dir, 'id.pub')),
        );
        await startSshd();
        writeFileSync(
          join(dir, 'known_hosts'),
          '[127.0.0.1]:$sshdPort ${readFileSync(join(dir, 'host_key.pub'), 'utf8')}',
        );
        writeFileSync(
          join(dir, 'ssh_config'),
          [
            'IdentityFile $dir/id',
            'IdentitiesOnly yes',
            'IdentityAgent none',
            'UserKnownHostsFile $dir/known_hosts',
            'GlobalKnownHostsFile /dev/null',
            'StrictHostKeyChecking yes',
            'BatchMode yes',
            // What the injected value has to switch off: a sandbox lets ssh make
            // no such socket, and ssh does not go on without it.
            'ControlMaster auto',
            'ControlPath $dir/mux-%C',
            '',
          ].join('\n'),
        );

        // Named: where `init.defaultBranch` says otherwise, the far side's HEAD
        // would name a branch that is not there, and a clone checks nothing out.
        git(['init', '-q', '--bare', '-b', 'main', join(dir, 'repo.git')]);
        git(['init', '-q', '-b', 'main', join(dir, 'work')]);
        writeFileSync(join(dir, 'work', 'blob'), randomBytes(BLOB_BYTES));
        blobSha256 = sha256(join(dir, 'work', 'blob'));
        head = commit('blob');
        git([
          ...['-C', join(dir, 'work'), 'push', '-q'],
          ...[join(dir, 'repo.git'), 'HEAD:refs/heads/main'],
        ]);
        // By path: what sshd puts on PATH need not hold the git under test.
        final execPath = git(['--exec-path']);
        packs = (
          upload: join(execPath, 'git-upload-pack'),
          receive: join(execPath, 'git-receive-pack'),
        );
        url = ([int? port]) =>
            'ssh://127.0.0.1:${port ?? sshdPort}$dir/repo.git';

        console.log(
          'git over ssh: ${(spawnSync('ssh', ['-V'], {'encoding': 'utf8'}).stderr as String).trim()}; '
          '${git(['--version'])}; sshd $SSHD; nc $NC; shells ${SHELLS.join(' ')}',
        );
      });

      tearDownAll(() {
        sshd?.kill();
        if (dir.isNotEmpty) rmSync(dir, {'recursive': true, 'force': true});
      });

      group('the macOS variables, run as git runs them', () {
        ({int port, List<String> asked, void Function() close})? proxy;

        setUpAll(() async {
          proxy = await startProxy(sshdPort);
        });
        tearDownAll(() => proxy?.close());

        // Dart: upstream's `...args` rest parameter is a list.
        Future<RunResult> run(
          String shell,
          Map<String, String> vars,
          List<String> args,
        ) => spawnAsync(
          'git',
          args,
          RunOpts(
            env: {
              ...process.env,
              ...vars,
              'GIT_SSH_COMMAND':
                  '${vars['GIT_SSH_COMMAND']} -F $dir/ssh_config',
              'SHELL': shell,
            },
            timeout: TEST_MS ~/ 2,
          ),
        );

        for (final shell in SHELLS) {
          test('SHELL=$shell: ls-remote', () async {
            proxy!.asked.clear();
            final r = await run(shell, macosVars(proxy!.port), [
              ...['ls-remote', '--upload-pack', packs.upload, url(), 'main'],
            ]);
            expect(explain(shell, r), startsWith('$shell: status 0,'));
            expect(r.stdout, '$head\trefs/heads/main\n');
            expect(r.stderr, '');
            // Attributed to the command, as every other client's requests are.
            expect(proxy!.asked, ['127.0.0.1:$sshdPort Zm9v']);
          }, timeout: _testTimeout);
        }

        test(
          'a wrong token is refused promptly, and ssh says who refused',
          () async {
            final started = DateTime.now().millisecondsSinceEpoch;
            final r = await run('/bin/sh', macosVars(proxy!.port, 'wrong'), [
              ...['ls-remote', '--upload-pack', packs.upload, url(), 'main'],
            ]);
            expect(
              DateTime.now().millisecondsSinceEpoch - started,
              lessThan(PROMPT_MS),
            );
            expect(r.status, 128);
            expect(
              r.stderr,
              contains(
                'sandbox proxy: 127.0.0.1:$sshdPort: 407 Proxy Authentication Required\n',
              ),
            );
          },
          timeout: _testTimeout,
        );

        test(
          'the script lost on the way: what is left of the pair names it',
          () async {
            final GIT_SSH_COMMAND = macosVars(proxy!.port)['GIT_SSH_COMMAND'];
            final r = await run(
              '/bin/sh',
              {'GIT_SSH_COMMAND': GIT_SSH_COMMAND!},
              [
                ...['ls-remote', '--upload-pack', packs.upload, url(), 'main'],
              ],
            );
            expect(r.status, 128);
            expect(
              r.stderr,
              contains(
                'SRT_SSH_PROXY_COMMAND: unset, but GIT_SSH_COMMAND needs it\n',
              ),
            );
          },
          timeout: _testTimeout,
        );

        test(
          'a host that ssh lets through and printf would rewrite goes nowhere',
          () async {
            proxy!.asked.clear();
            final r = await run('/bin/sh', macosVars(proxy!.port), [
              ...['ls-remote', '--upload-pack', packs.upload],
              'ssh://127.0%s.0.1:$sshdPort$dir/repo.git',
            ]);
            expect(r.status, 128);
            expect(r.stderr, contains('sandbox proxy: bad host\n'));
            expect(proxy!.asked, []);
          },
          timeout: _testTimeout,
        );
      });

      group(
        'inside the sandbox$NO_SANDBOX',
        skip: NO_SANDBOX != '' ? 'unavailable' : null,
        () {
          const DENY_REASON =
              'ssh to this port is blocked; use an https:// remote';
          const ASK_REASON = 'asked, and refused';
          late int deniedPort;

          setUpAll(() async {
            deniedPort = await freePort();
            await SandboxManager.reset();
            await SandboxManager.initialize(
              SandboxRuntimeConfig(
                // The literal with its port: a name that resolves to loopback is
                // refused, and a literal is an explicit choice.
                network: NetworkConfig(
                  allowedDomains: ['127.0.0.1:$sshdPort'],
                  deniedDomains: ['127.0.0.1:$deniedPort'],
                  deniedDomainReasons: {'127.0.0.1:$deniedPort': DENY_REASON},
                ),
                filesystem: FilesystemConfig(
                  denyRead: [],
                  allowWrite: [FilesystemPathSpelling(dir)],
                  denyWrite: [],
                ),
              ),
              // A refusal that comes late, when ssh has long sent its first bytes.
              (NetworkHostPattern _) async {
                await Future<void>.delayed(const Duration(milliseconds: 500));
                return {'allow': false, 'reason': ASK_REASON};
              },
            );
          });

          tearDownAll(() async {
            await SandboxManager.reset();
          });

          String CONFIG() => quote(['-F', join(dir, 'ssh_config')]);
          /** What the sandbox injects, plus where this test's keys are. */
          String injected() =>
              'GIT_SSH_COMMAND="\$GIT_SSH_COMMAND "${quote([CONFIG()])}';
          /**
         * The macOS variables in place of the injected ones. On Linux the proxy
         * is the sandbox's own listener on 3128.
         */
          String macos([String? token]) {
            token ??= SandboxManager.getProxyAuthToken()!;
            final vars = macosVars(
              isLinux ? 3128 : SandboxManager.getProxyPort()!,
              token,
            );
            return quote([
              'env',
              'SRT_SSH_PROXY_COMMAND=${vars['SRT_SSH_PROXY_COMMAND']}',
              'GIT_SSH_COMMAND=${vars['GIT_SSH_COMMAND']} ${CONFIG()}',
            ]);
          }

          Future<
            ({
              String stdout,
              String stderr,
              int? status,
              String? signal,
              int ms,
              String command,
            })
          >
          sandboxed(String vars, List<String> args) async {
            final command = '$vars git ${quote(args)}';
            final started = DateTime.now().millisecondsSinceEpoch;
            final r = await spawnAsync(
              await SandboxManager.wrapWithSandbox(command),
              RunOpts(timeout: TEST_MS ~/ 2),
            );
            return (
              stdout: r.stdout,
              stderr: r.stderr,
              status: r.status,
              signal: r.signal,
              ms: DateTime.now().millisecondsSinceEpoch - started,
              command: command,
            );
          }

          // On its own, so that a profile that does not let the script's nc out is
          // told from everything else that can go wrong further down.
          test('nc reaches the proxy on 127.0.0.1', () async {
            final port = isLinux ? 3128 : SandboxManager.getProxyPort()!;
            final r = await spawnAsync(
              await SandboxManager.wrapWithSandbox(
                // The sleep holds nc's stdin open, as ssh does, until the answer.
                "{ printf 'GET http://x.invalid/ HTTP/1.1\\r\\nHost: x.invalid\\r\\nConnection: close\\r\\n\\r\\n'; sleep 2; } | $NC -v 127.0.0.1 $port",
              ),
              RunOpts(timeout: TEST_MS ~/ 2),
            );
            expect(explain('nc', r), startsWith('nc: status 0,'));
            expect(r.stdout, startsWith('HTTP/1.1 407 '));
          }, timeout: _testTimeout);

          final spellings = <(String, String Function())>[
            ('as injected on ${isMacOS ? 'macOS' : 'Linux'}', injected),
            // On macOS that is the injected one already.
            if (isLinux) ('the macOS spelling, forced', macos),
          ];

          for (final (spelling, vars) in spellings) {
            final n = spellings.indexWhere((s) => s.$1 == spelling);

            test('$spelling: ls-remote', () async {
              final r = await sandboxed(vars(), [
                ...['ls-remote', '--upload-pack', packs.upload, url(), 'main'],
              ]);
              expect(explain(spelling, r), startsWith('$spelling: status 0,'));
              expect(r.stdout, '$head\trefs/heads/main\n');
            }, timeout: _testTimeout);

            test('$spelling: clones ${BLOB_BYTES >> 20} MiB intact', () async {
              final dest = join(dir, 'clone-$n');
              final r = await sandboxed(vars(), [
                ...['clone', '-q', '--upload-pack', packs.upload, url(), dest],
              ]);
              expect(explain(spelling, r), startsWith('$spelling: status 0,'));
              expect(sha256(join(dest, 'blob')), blobSha256);
            }, timeout: _testTimeout);

            test('$spelling: pushes ${BLOB_BYTES >> 20} MiB intact', () async {
              // A blob the far side does not have yet.
              final file = join(dir, 'work', 'up-$n');
              writeFileSync(file, randomBytes(BLOB_BYTES));
              commit('up-$n');
              final r = await sandboxed(vars(), [
                ...['-C', join(dir, 'work'), '-c', 'core.compression=0'],
                ...['push', '-q', '--receive-pack', packs.receive],
                ...[url(), 'HEAD:refs/heads/pushed-$n'],
              ]);
              expect(explain(spelling, r), startsWith('$spelling: status 0,'));
              final arrived = spawnSync(
                'git',
                [
                  '-C',
                  join(dir, 'repo.git'),
                  'cat-file',
                  'blob',
                  'pushed-$n:up-$n',
                ],
                {'maxBuffer': 2 * BLOB_BYTES},
              );
              expect(
                createHash(
                  'sha256',
                ).update(arrived.stdout as Buffer).digest('hex'),
                sha256(file),
              );
            }, timeout: _testTimeout);

            /**
           * How the ProxyCommand of this spelling words a 403. What socat shows
           * of one is its own matter: 1.8.0.0 nothing, 1.8.1.3 the status phrase.
           */
            Object refusal(int port, String reason) =>
                vars == injected && isLinux
                ? RegExp(
                    '( CONNECT 127\\.0\\.0\\.1:$port: $reason\n|^)Connection closed by UNKNOWN port 65535',
                    multiLine: true,
                  )
                : 'sandbox proxy: 127.0.0.1:$port: 403 $reason\n';
            void expectRefusal(String stderr, Object words) {
              if (words is String) {
                expect(stderr, contains(words));
              } else {
                expect(stderr, matches(words as RegExp));
              }
            }

            test(
              '$spelling: a destination on the deny list is refused in the words configured for it',
              () async {
                final r = await sandboxed(vars(), [
                  ...[
                    'ls-remote',
                    '--upload-pack',
                    packs.upload,
                    url(deniedPort),
                  ],
                ]);
                expect(r.status, 128);
                expect(r.ms, lessThan(PROMPT_MS));
                expectRefusal(r.stderr, refusal(deniedPort, DENY_REASON));
              },
              timeout: _testTimeout,
            );

            test(
              '$spelling: a destination on no list is refused, late, in the words of whoever was asked',
              () async {
                final other = await freePort();
                final r = await sandboxed(vars(), [
                  ...['ls-remote', '--upload-pack', packs.upload, url(other)],
                ]);
                expect(r.status, 128);
                expect(r.ms, lessThan(PROMPT_MS));
                expect(r.stdout, '');
                expectRefusal(r.stderr, refusal(other, ASK_REASON));
                if (vars == injected) {
                  // The user name that went with the token names the command.
                  expect(
                    SandboxManager.getSandboxViolationStore()
                        .getViolationsForCommand(r.command)
                        .map((v) => v.line)
                        .toList(),
                    contains(
                      'deny network-outbound 127.0.0.1:$other ($ASK_REASON)',
                    ),
                  );
                }
              },
              timeout: _testTimeout,
            );
          }

          test('the macOS spelling: a wrong token is refused promptly', () async {
            final r = await sandboxed(macos('wrong'), [
              ...['ls-remote', '--upload-pack', packs.upload, url()],
            ]);
            expect(r.status, 128);
            expect(r.ms, lessThan(PROMPT_MS));
            expect(
              r.stderr,
              contains(
                'sandbox proxy: 127.0.0.1:$sshdPort: 407 Proxy Authentication Required\n',
              ),
            );
          }, timeout: _testTimeout);

          test(
            'the macOS spelling: a host that ssh lets through and printf would rewrite goes nowhere',
            () async {
              final r = await sandboxed(macos(), [
                ...['ls-remote', '--upload-pack', packs.upload],
                'ssh://127.0%s.0.1:$sshdPort$dir/repo.git',
              ]);
              expect(r.status, 128);
              expect(r.stderr, contains('sandbox proxy: bad host\n'));
            },
            timeout: _testTimeout,
          );
        },
      );
    },
  );
}
