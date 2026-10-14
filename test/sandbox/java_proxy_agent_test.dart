// Ported from sandbox-runtime test/sandbox/java-proxy-agent.test.ts @ 24eb39e.
// ignore_for_file: non_constant_identifier_names
import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:path/path.dart' as path;
import 'package:test/test.dart';

import 'package:sandbox_runtime/src/sandbox/generate_seccomp_filter.dart'
    show getGlobalNpmPaths, getGlobalNpmPathsAsync;
import 'package:sandbox_runtime/src/sandbox/java_proxy_agent.dart'
    show
        buildJavaToolOptions,
        getJavaProxyAgentJarPathAsync,
        JAVA_PROXY_AGENT_JAR_NAME;
import 'package:sandbox_runtime/src/node/http.dart' as http;
import 'package:sandbox_runtime/src/node/net.dart' as net;
import 'package:sandbox_runtime/src/sandbox/macos_sandbox_utils.dart';

import '../helpers/platform.dart';
import '../helpers/spawn.dart';

///
/// Tests for Java proxy-agent option construction and lookup.
///
Future<void> main() async {
  group('buildJavaToolOptions', () {
    test('returns undefined when there is nothing to set', () {
      expect(buildJavaToolOptions(), isNull);
      expect(buildJavaToolOptions(flags: [], inherited: ''), isNull);
    });

    test('emits -javaagent for the jar path', () {
      expect(
        buildJavaToolOptions(agentJarPath: '/tmp/x/a.jar'),
        '-javaagent:/tmp/x/a.jar',
      );
    });

    test('double-quotes a jar path containing whitespace', () {
      // The JVM tokenizes JAVA_TOOL_OPTIONS on whitespace but honours quotes.
      expect(
        buildJavaToolOptions(agentJarPath: '/tmp/a b/a.jar'),
        '"-javaagent:/tmp/a b/a.jar"',
      );
    });

    test('preserves the inherited value and appends flags once', () {
      expect(
        buildJavaToolOptions(
          agentJarPath: '/j.jar',
          flags: ['-Dfoo=1', '-Dbar=2'],
          inherited: '-Xmx1g -Dbar=2',
        ),
        '-javaagent:/j.jar -Xmx1g -Dbar=2 -Dfoo=1',
      );
    });

    test('drops the inherited value when JAVA_TOOL_OPTIONS is denied', () {
      expect(
        buildJavaToolOptions(
          agentJarPath: '/j.jar',
          inherited: '-Dsecret=1',
          unsetEnvVars: ['JAVA_TOOL_OPTIONS'],
        ),
        '-javaagent:/j.jar',
      );
    });

    test('still emits flags alone (no agent) for the macOS IPv4 case', () {
      expect(
        buildJavaToolOptions(flags: ['-Djava.net.preferIPv4Stack=true']),
        '-Djava.net.preferIPv4Stack=true',
      );
    });
  });

  // The jar is a build artifact (vendor/java-proxy-agent/srt-proxy-agent.jar,
  // `npm run build:java-agent`, needs a JDK) and is not in git; CI builds it
  // before `bun test`. Suites that need it on disk self-skip otherwise.
  final jarPath = await getJavaProxyAgentJarPathAsync();

  group('getJavaProxyAgentJarPathAsync', () {
    test(
      'prefers an existing explicit path, and falls back past a missing one',
      () async {
        final explicit = path.join(
          Directory.current.path,
          'test',
          'fixtures',
          'java-proxy-agent',
          'ProxyProbe.java',
        );
        expect(await getJavaProxyAgentJarPathAsync(explicit), explicit);
        // A distinct missing path is its own cache key, so this runs the full
        // lookup (including the async global-npm fallback) rather than a hit.
        // Either the vendor jar (when built) or null — never the bogus path.
        expect(
          await getJavaProxyAgentJarPathAsync('/nonexistent/async-agent.jar'),
          jarPath,
        );
      },
    );

    test(
      'getGlobalNpmPathsAsync shares the sync cache and fallbacks',
      () async {
        final asyncPaths = await getGlobalNpmPathsAsync();
        expect(getGlobalNpmPaths(), same(asyncPaths));
        expect(
          asyncPaths,
          contains(
            path.join(
              '/usr',
              'lib',
              'node_modules',
              '@anthropic-ai',
              'sandbox-runtime',
            ),
          ),
        );
      },
    );

    test('finds the built jar under vendor/', () {
      expect(
        jarPath!.endsWith(
          path.join('vendor', 'java-proxy-agent', JAVA_PROXY_AGENT_JAR_NAME),
        ),
        isTrue,
      );
      expect(File(jarPath).existsSync(), isTrue);
    }, skip: jarPath == null ? 'agent jar not built' : false);
  });

  group('macOS wrapper', () {
    test('injects the agent and the IPv4 flag into JAVA_TOOL_OPTIONS', () {
      // The IPv4 flag rides along whenever a proxy port is advertised: without
      // it Java's dual-stack socket reaches the proxy as ::ffff:127.0.0.1 and
      // Seatbelt denies the connect the agent just set up.
      final wrapped = wrapCommandWithSandboxMacOS(
        MacOSSandboxParams(
          command: 'true',
          needsNetworkRestriction: true,
          httpProxyPort: 3128,
          javaAgentJarPath: '/tmp/srt-java-x/srt-proxy-agent.jar',
          readConfig: null,
          writeConfig: null,
        ),
      );
      expect(
        wrapped,
        contains(
          'JAVA_TOOL_OPTIONS=-javaagent:/tmp/srt-java-x/srt-proxy-agent.jar '
          '-Djava.net.preferIPv4Stack=true',
        ),
      );
    });

    test('keeps the IPv4 flag alone for allowLocalBinding without a proxy', () {
      final wrapped = wrapCommandWithSandboxMacOS(
        MacOSSandboxParams(
          command: 'true',
          needsNetworkRestriction: true,
          allowLocalBinding: true,
          readConfig: null,
          writeConfig: null,
        ),
      );
      expect(
        wrapped,
        contains('JAVA_TOOL_OPTIONS=-Djava.net.preferIPv4Stack=true'),
      );
    });

    test('omits JAVA_TOOL_OPTIONS when loopback is unreachable anyway', () {
      final wrapped = wrapCommandWithSandboxMacOS(
        MacOSSandboxParams(
          command: 'true',
          needsNetworkRestriction: true,
          readConfig: null,
          writeConfig: null,
        ),
      );
      expect(wrapped, isNot(contains('JAVA_TOOL_OPTIONS')));
    });
  }, skip: isMacOS ? false : 'macOS only');

  group(
    'sandboxed child',
    skip: !((isLinux || isMacOS) && jarPath != null)
        ? 'requires Linux or macOS and the built agent jar'
        : 'pending port: src/sandbox/sandbox-manager.ts',
    () {
      tearDownAll(() async {
        // await SandboxManager.reset()
      });

      test('sees JAVA_TOOL_OPTIONS pointing at a readable agent jar', () async {
        // const config: SandboxRuntimeConfig = {
        //   network: { allowedDomains: ['example.com'], deniedDomains: [] },
        //   filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
        // }
        // await SandboxManager.initialize(config)
        // const wrapped = await SandboxManager.wrapWithSandbox(
        //   // The agent flag comes first; macOS appends -Djava.net.preferIPv4Stack.
        //   'sh -c \'echo "JTO=$JAVA_TOOL_OPTIONS"; jar="${JAVA_TOOL_OPTIONS#-javaagent:}"; jar="${jar%% *}"; test -r "$jar" && echo READABLE; echo "HP=$HTTPS_PROXY"\'',
        // )
        // const result = await spawnAsync(wrapped, {
        //   shell: true,
        //   encoding: 'utf8',
        //   timeout: 15000,
        // })
        // expect(result.status).toBe(0)
        // expect(result.stdout).toContain(`JTO=-javaagent:${jarPath}`)
        // expect(result.stdout).toContain('READABLE')
        // // The credential rides in HTTPS_PROXY, never in JAVA_TOOL_OPTIONS.
        // expect(result.stdout).toMatch(/^HP=http:\/\/srt[^:]*:[0-9a-f]{32}@/m)
        // const jto = /^JTO=(.*)$/m.exec(result.stdout)![1]
        // expect(jto).not.toContain('@')
      });
    },
  );

  // ---------------------------------------------------------------------------
  // End-to-end against a real JVM (needs a JDK >= 11 for the single-file
  // source launcher). Skipped when none is available; CI installs one.

  String? findJava() {
    final candidates = [
      Platform.environment['JAVA_HOME'] != null
          ? path.join(Platform.environment['JAVA_HOME']!, 'bin', 'java')
          : '',
      'java',
    ].where((c) => c.isNotEmpty);
    for (final java in candidates) {
      final ProcessResult r;
      try {
        r = Process.runSync(java, ['-version']);
      } on ProcessException {
        continue;
      }
      if (r.exitCode != 0) continue;
      // `openjdk version "21.0.1"` / `java version "1.8.0_392"`
      final m = RegExp(
        r'version "(\d+)(?:\.(\d+))?',
      ).firstMatch('${r.stderr}${r.stdout}');
      if (m == null) continue;
      final major = m[1] == '1' ? int.parse(m[2]!) : int.parse(m[1]!);
      if (major >= 11) return java;
    }
    return null;
  }

  final java = findJava();
  final PROBE = path.join(
    Directory.current.path, // import.meta.dir, '..'
    'test',
    'fixtures',
    'java-proxy-agent',
    'ProxyProbe.java',
  );

  group(
    'agent inside a JVM',
    skip: java != null && jarPath != null
        ? false
        : 'requires a JDK >= 11 and the built agent jar '
              '(dart run tool/build_java_proxy_agent.dart)',
    () {
      Map<String, String> proxyEnv(int proxyPort) => {
        ...Platform.environment,
        'JAVA_TOOL_OPTIONS': '-javaagent:$jarPath',
        // Same shape generateProxyEnvVars emits: percent-encoded username
        // (base64 command suffix), hex token.
        'HTTPS_PROXY':
            'http://srt.YWJj%2Bx%3D%3D:deadbeef@localhost:$proxyPort',
        'HTTP_PROXY': 'http://srt.YWJj%2Bx%3D%3D:deadbeef@localhost:$proxyPort',
        'NO_PROXY':
            'localhost,127.0.0.1,::1,169.254.0.0/16,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16',
      };

      // spawnAsync, not spawnSync: the proxy tests below talk to an in-process
      // server, and spawnSync would block the loop it runs on (see helpers).
      Future<RunResult> runProbe(List<String> args, Map<String, String> env) {
        return spawnAsync(java!, [
          PROBE,
          ...args,
        ], RunOpts(env: env, timeout: 60000));
      }

      test(
        'translates the proxy env vars into system properties + Authenticator',
        () async {
          final r = await runProbe([
            'props',
            'localhost',
            '3128',
          ], proxyEnv(3128));
          expect(r.status, 0);
          expect(r.stderr, contains('Picked up JAVA_TOOL_OPTIONS'));
          expect(r.stdout, contains('https.proxyHost=localhost'));
          expect(r.stdout, contains('https.proxyPort=3128'));
          expect(r.stdout, contains('http.proxyHost=localhost'));
          expect(
            r.stdout,
            contains('jdk.http.auth.tunneling.disabledSchemes=\n'),
          );
          // Percent-decoded username, raw token; both requestor overloads answer;
          // any other endpoint gets nothing.
          expect(r.stdout, contains('auth.proxy=srt.YWJj+x==:deadbeef'));
          expect(r.stdout, contains('auth.server=srt.YWJj+x=='));
          expect(r.stdout, contains('auth.other=null'));
          // NO_PROXY → nonProxyHosts: proxy for the world, direct for loopback and
          // private ranges (172.16/12 expands to 172.16.* … 172.31.*).
          expect(
            r.stdout,
            contains(RegExp(r'http\.nonProxyHosts=.*172\.31\.\*')),
          );
          expect(
            r.stdout,
            contains(RegExp(r'select\.https=\[HTTP @ localhost.*:3128\]')),
          );
          expect(r.stdout, contains('select.localhost=[DIRECT]'));
          expect(r.stdout, contains('select.private=[DIRECT]'));
        },
      );

      test('leaves explicitly set proxy properties alone', () async {
        final env = proxyEnv(3128);
        env['JAVA_TOOL_OPTIONS'] =
            '-Dhttps.proxyHost=other -Dhttps.proxyPort=9 ${env['JAVA_TOOL_OPTIONS']}';
        final r = await runProbe(['props', 'localhost', '3128'], env);
        expect(r.status, 0);
        expect(r.stdout, contains('https.proxyHost=other'));
        expect(r.stdout, contains('https.proxyPort=9'));
      });

      test('does nothing without proxy env vars', () async {
        final env = <String, String>{
          ...Platform.environment,
          'JAVA_TOOL_OPTIONS': '-javaagent:$jarPath',
        };
        for (final k in [
          'HTTPS_PROXY',
          'https_proxy',
          'HTTP_PROXY',
          'http_proxy',
          'NO_PROXY',
          'no_proxy',
        ]) {
          env.remove(k);
        }
        final r = await runProbe(['props', 'localhost', '3128'], env);
        expect(r.status, 0);
        expect(r.stdout, contains('https.proxyHost=null'));
        expect(r.stdout, contains('auth.proxy=null'));
        expect(r.stdout, contains('select.https=[DIRECT]'));
      });

      group('against a challenging proxy', () {
        http.NodeHttpServer? proxy;
        var proxyPort = 0;
        final seen = <({String method, String url, String? auth})>[];

        Future<void> startProxy() async {
          proxy = http.createServer((
            http.IncomingMessage req,
            http.ServerResponse res,
          ) {
            seen.add((
              method: req.method!,
              url: req.url!,
              auth: req.headers['proxy-authorization'] as String?,
            ));
            if (req.headers['proxy-authorization'] == null) {
              res.writeHead(407, {'Proxy-Authenticate': 'Basic realm="srt"'});
              res.end();
              return;
            }
            res.writeHead(200, {'Content-Length': '2'});
            res.end('ok');
          });
          proxy!.on('connect', (http.IncomingMessage req, net.NodeSocket sock) {
            seen.add((
              method: 'CONNECT',
              url: req.url!,
              auth: req.headers['proxy-authorization'] as String?,
            ));
            if (req.headers['proxy-authorization'] == null) {
              sock.end(
                'HTTP/1.1 407 Proxy Authentication Required\r\n'
                'Proxy-Authenticate: Basic realm="srt"\r\n'
                'Content-Length: 0\r\n\r\n',
              );
              return;
            }
            // Accept the tunnel, then hang up: the JVM's TLS handshake fails,
            // which is fine — the assertion is on the CONNECT it sent.
            sock.end('HTTP/1.1 200 OK\r\n\r\n');
          });
          final listening = Completer<int>();
          proxy!.on('error', listening.completeError);
          proxy!.listen(
            0,
            '127.0.0.1',
            () =>
                listening.complete((proxy!.address()! as net.NodeAddress).port),
          );
          proxyPort = await listening.future;
        }

        tearDownAll(() async {
          if (proxy != null) {
            final closed = Completer<void>();
            proxy!.close(() => closed.complete());
            // The JVM may leave an unread follow-up on the 407 CONNECT socket,
            // which then never ends: close what is left.
            proxy!.closeAllConnections();
            await closed.future;
          }
        });

        final expectedAuth =
            'Basic ${base64.encode(utf8.encode('srt.YWJj+x==:deadbeef'))}';

        test(
          'answers a 407 on a plain-HTTP request with the credential',
          () async {
            await startProxy();
            seen.clear();
            final r = await runProbe([
              'connect',
              'http://example.invalid/',
            ], proxyEnv(proxyPort));
            expect(r.status, 0);
            expect(r.stdout, contains('code=200'));
            expect(seen.map((s) => s.method).toList(), ['GET', 'GET']);
            expect(seen[0].auth, isNull);
            expect(seen[1].auth, expectedAuth);
          },
        );

        test(
          'answers a 407 on CONNECT with Basic (tunneling scheme re-enabled)',
          () async {
            seen.clear();
            final r = await runProbe([
              'connect',
              'https://example.invalid/',
            ], proxyEnv(proxyPort));
            expect(r.status, 0);
            final connects = seen.where((s) => s.method == 'CONNECT').toList();
            expect(connects.length, greaterThanOrEqualTo(2));
            expect(connects[0].url, 'example.invalid:443');
            expect(connects[0].auth, isNull);
            expect(connects[1].auth, expectedAuth);
          },
        );
      });
    },
  );
}
