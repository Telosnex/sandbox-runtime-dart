// Ported from sandbox-runtime test/sandbox/java-proxy-agent.test.ts @ 24eb39e.
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
import 'package:sandbox_runtime/src/sandbox/macos_sandbox_utils.dart';

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

    if (jarPath != null) {
      test('finds the built jar under vendor/', () {
        expect(
          jarPath.endsWith(
            path.join('vendor', 'java-proxy-agent', JAVA_PROXY_AGENT_JAR_NAME),
          ),
          isTrue,
        );
        expect(File(jarPath).existsSync(), isTrue);
      });
    }
  });

  if (Platform.isMacOS) {
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

      test(
        'keeps the IPv4 flag alone for allowLocalBinding without a proxy',
        () {
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
        },
      );

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
    });
  }

  if ((Platform.isLinux || Platform.isMacOS) && jarPath != null) {
    group('sandboxed child', skip: 'pending port: sandbox-manager.ts', () {
      tearDownAll(() async {
        // Upstream calls `await SandboxManager.reset()` here.
      });
      test('sees JAVA_TOOL_OPTIONS pointing at a readable agent jar', () async {
        // Upstream body pending sandbox-manager.ts:
        // const config: SandboxRuntimeConfig = {
        // network: { allowedDomains: ['example.com'], deniedDomains: [] },
        // filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
        // }
        // await SandboxManager.initialize(config)
        // const wrapped = await SandboxManager.wrapWithSandbox(
        // 'sh -c \'echo "JTO=$JAVA_TOOL_OPTIONS"; jar="${JAVA_TOOL_OPTIONS#-javaagent:}"; jar="${jar%% *}"; test -r "$jar" && echo READABLE; echo "HP=$HTTPS_PROXY"\'',
        // )
        // const result = await spawnAsync(wrapped, {
        // shell: true,
        // encoding: 'utf8',
        // timeout: 15000,
        // })
        // expect(result.status).toBe(0)
        // expect(result.stdout).toContain(`JTO=-javaagent:${jarPath}`)
        // expect(result.stdout).toContain('READABLE')
        // expect(result.stdout).toMatch(/^HP=http:\/\/srt[^:]*:[0-9a-f]{32}@/m)
        // const jto = /^JTO=(.*)$/m.exec(result.stdout)![1]
        // expect(jto).not.toContain('@')
        //
      });
    });
  }
}
