// Ported from sandbox-runtime test/sandbox/credential-mask.test.ts @ 0bbebed.
// ignore_for_file: constant_identifier_names, non_constant_identifier_names, slash_for_doc_comments, prefer_interpolation_to_compose_strings
import 'dart:async';
import 'dart:convert';
import 'dart:io' as io;

import 'package:path/path.dart' show join;
import 'package:sandbox_runtime/src/node/buffer.dart' show Buffer;
import 'package:sandbox_runtime/src/node/child_process.dart' show spawnSync;
import 'package:sandbox_runtime/src/node/console.dart' as console;
import 'package:sandbox_runtime/src/node/fs.dart' show readFileSync;
import 'package:sandbox_runtime/src/node/http.dart' as http;
import 'package:sandbox_runtime/src/node/https.dart' as https;
import 'package:sandbox_runtime/src/node/net.dart' as net;
import 'package:sandbox_runtime/src/node/process.dart' as process;
import 'package:sandbox_runtime/src/sandbox/credential_decode.dart'
    show verifyJwt;
import 'package:sandbox_runtime/src/sandbox/credential_sentinel.dart';
import 'package:sandbox_runtime/src/sandbox/http_proxy.dart';
import 'package:sandbox_runtime/src/sandbox/macos_sandbox_utils.dart'
    show MacOSSandboxParams, wrapCommandWithSandboxMacOS;
import 'package:sandbox_runtime/src/sandbox/mitm_ca.dart';
import 'package:sandbox_runtime/src/sandbox/mitm_leaf.dart';
import 'package:sandbox_runtime/src/sandbox/request_filter.dart';
import 'package:sandbox_runtime/src/sandbox/sandbox_config.dart';
import 'package:sandbox_runtime/src/sandbox/sandbox_manager.dart';
import 'package:sandbox_runtime/src/sandbox/sandbox_schemas.dart'
    show FsWriteRestrictionConfig;
import 'package:test/test.dart';

import '../helpers/captured.dart';
import '../helpers/emitted_connections.dart'
    show SERVES_EMITTED_CONNECTIONS, testWithTls;
import '../helpers/platform.dart' show isLinux;

// Dart: the object literal upstream hands createHttpProxyServer; every
// option not named here is absent (null).
class _HttpOptions implements HttpProxyServerOptions {
  _HttpOptions({
    this.mitmCA,
    this.tlsTerminateUpstreamCA,
    this.mutateHeaders,
    this.mutateHeadersPlaintext,
  });
  @override
  final MitmCA? mitmCA;
  @override
  final dynamic tlsTerminateUpstreamCA;
  @override
  final MutateForwardedHeaders? mutateHeaders;
  @override
  final MutateForwardedHeaders? mutateHeadersPlaintext;
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

// Dart: the filesystem entry upstream writes as a bare string.
FilesystemPathEntry _p(String path) => FilesystemPathSpelling(path);

// Dart: a Promise resolved by a callback, as `new Promise<void>(r => ...)`.
Future<void> _listen(net.NodeServer server) {
  final c = Completer<void>();
  server.listen(0, '127.0.0.1', () => c.complete());
  return c.future;
}

Future<void> _close(net.NodeServer server) {
  final c = Completer<void>();
  server.close(() => c.complete());
  return c.future;
}

// Committed test-only CA — see test/fixtures/tls-terminate/README.md.
final FIXTURE_DIR = join(
  io.Directory.current.path, // import.meta.dir, '..'
  'test',
  'fixtures',
  'tls-terminate',
);
final CA_CERT = join(FIXTURE_DIR, 'ca.crt');
final CA_KEY = join(FIXTURE_DIR, 'ca.key');
final CA_PEM = readFileSync(CA_CERT, 'utf8') as String;

const REAL_TOKEN = 'ghp_realsecret_abcdef0123456789';

/** Host matcher for unit tests: exact equality. */
bool eq(String h, String p) => h == p;

/** Host matcher that always allows — for tests of the substitution itself. */
bool any(String h, String p) => true;

void main() {
  group('SentinelRegistry', () {
    test('register mints a fake_value_<uuid> sentinel', () {
      final reg = SentinelRegistry();
      final s = reg.register('GH_TOKEN', 'hunter2', ['api.github.com']);
      expect(s.startsWith(SENTINEL_PREFIX), isTrue);
      // UUID v4 is 36 chars (8-4-4-4-12 with hyphens).
      expect(s.length, SENTINEL_PREFIX.length + 36);
      expect(reg.lookupReal(s), 'hunter2');
    });

    test(
      'register pads the sentinel to the real value byte length (length-matched)',
      () {
        final reg = SentinelRegistry();
        final real = 'x' * 100;
        final s = reg.register('LONG', real, ['api.github.com']);
        expect(s.startsWith(SENTINEL_PREFIX), isTrue);
        expect(Buffer.byteLength(s), Buffer.byteLength(real));
        // Padding stays in the sentinel alphabet so the fake still survives
        // shells, JSON, and URLs unquoted.
        expect(s, matches(RegExp(r'^[a-z0-9_-]+$')));
        expect(reg.lookupReal(s), real);
      },
    );

    test(
      'register never shrinks the sentinel below the base (short real value)',
      () {
        final reg = SentinelRegistry();
        final s = reg.register('SHORT', 'tiny', ['api.github.com']);
        expect(s.length, SENTINEL_PREFIX.length + 36);
      },
    );

    test('sentinelsForHost returns byte pairs gated per credential', () {
      final reg = SentinelRegistry();
      final a = reg.register('A', 'real-a', ['a.example.com']);
      reg.register('B', 'real-b', ['b.example.com']);
      final pairs = reg.sentinelsForHost('a.example.com', eq);
      expect(pairs, hasLength(1));
      expect(utf8.decode(pairs[0].sentinel), a);
      expect(utf8.decode(pairs[0].realValue), 'real-a');
      expect(reg.sentinelsForHost('c.example.com', eq), hasLength(0));
    });

    test('sentinelsForHost reflects a re-registered real value', () {
      final reg = SentinelRegistry();
      reg.register('T', 'old-value', ['h.example.com']);
      reg.register('T', 'new-value', ['h.example.com']);
      final pairs = reg.sentinelsForHost('h.example.com', eq);
      expect(pairs, hasLength(1));
      expect(utf8.decode(pairs[0].realValue), 'new-value');
    });

    test('register is idempotent on credential name', () {
      final reg = SentinelRegistry();
      final a = reg.register('GH_TOKEN', 'hunter2', ['api.github.com']);
      final b = reg.register('GH_TOKEN', 'hunter2', ['api.github.com']);
      expect(a, b);
      expect(reg.size, 1);
    });

    test(
      're-registering a name updates value and hosts but keeps the sentinel',
      () {
        final reg = SentinelRegistry();
        final a = reg.register('T', 'old', ['old.example.com']);
        final b = reg.register('T', 'new', ['new.example.com']);
        expect(b, a);
        expect(reg.lookupReal(a), 'new');
        final http.IncomingHttpHeaders headers = {'authorization': a};
        reg.substituteInHeaders(headers, 'new.example.com', eq);
        expect(headers['authorization'], 'new');
      },
    );

    test('different names get different sentinels even for the same value', () {
      // Per-credential host gating must apply independently, so two env
      // vars carrying the same secret still need distinct sentinels.
      final reg = SentinelRegistry();
      final a = reg.register('A', 'same', ['a.example.com']);
      final b = reg.register('B', 'same', ['b.example.com']);
      expect(a, isNot(b));
      expect(reg.size, 2);
    });

    test(
      'per-extract file keys (file:<path>#<i>) yield distinct sentinels',
      () {
        // Structured file masking registers one sentinel per distinct
        // captured value under a #<i>-suffixed key. The registry must treat
        // these as independent entries so each capture swaps to its own real
        // value at the proxy.
        final reg = SentinelRegistry();
        final s0 = reg.register('file:/p#0', 'tok-a', ['h.example.com']);
        final s1 = reg.register('file:/p#1', 'tok-b', ['h.example.com']);
        expect(s0, isNot(s1));
        expect(reg.lookupReal(s0), 'tok-a');
        expect(reg.lookupReal(s1), 'tok-b');
        expect(reg.size, 2);
      },
    );

    test('clear drops every mapping', () {
      final reg = SentinelRegistry();
      final s = reg.register('T', 'x', []);
      reg.clear();
      expect(reg.size, 0);
      expect(reg.lookupReal(s), isNull);
    });

    test('substituteInHeaders replaces sentinels in any header value', () {
      final reg = SentinelRegistry();
      final s = reg.register('GH_TOKEN', REAL_TOKEN, ['api.github.com']);
      final http.IncomingHttpHeaders headers = {
        'authorization': 'Bearer $s',
        'x-api-key': s,
        'set-cookie': ['token=$s; Path=/', 'unrelated=1'],
        'user-agent': 'curl/8',
      };
      reg.substituteInHeaders(headers, 'api.github.com', any);
      expect(headers['authorization'], 'Bearer $REAL_TOKEN');
      expect(headers['x-api-key'], REAL_TOKEN);
      expect(headers['set-cookie'], [
        'token=$REAL_TOKEN; Path=/',
        'unrelated=1',
      ]);
      expect(headers['user-agent'], 'curl/8');
    });

    test('substituteInHeaders leaves headers without sentinels unchanged', () {
      final reg = SentinelRegistry();
      reg.register('GH_TOKEN', REAL_TOKEN, ['api.github.com']);
      final http.IncomingHttpHeaders headers = {
        'authorization': 'Bearer plain',
      };
      reg.substituteInHeaders(headers, 'api.github.com', any);
      expect(headers['authorization'], 'Bearer plain');
    });

    test("a sentinel only substitutes at its own credential's injectHosts", () {
      // Anti-laundering: sending GH_TOKEN's sentinel to NPM_TOKEN's host
      // must NOT swap in the GH secret.
      final reg = SentinelRegistry();
      final gh = reg.register('GH_TOKEN', 'gh-secret', ['api.github.com']);
      final npm = reg.register('NPM_TOKEN', 'npm-secret', [
        'registry.npmjs.org',
      ]);

      final http.IncomingHttpHeaders toNpm = {'authorization': 'Bearer $gh'};
      reg.substituteInHeaders(toNpm, 'registry.npmjs.org', eq);
      expect(toNpm['authorization'], 'Bearer $gh');

      final http.IncomingHttpHeaders toGh = {'authorization': 'Bearer $npm'};
      reg.substituteInHeaders(toGh, 'api.github.com', eq);
      expect(toGh['authorization'], 'Bearer $npm');

      // Each credential does swap at its own host.
      final http.IncomingHttpHeaders ghOwn = {'authorization': 'Bearer $gh'};
      reg.substituteInHeaders(ghOwn, 'api.github.com', eq);
      expect(ghOwn['authorization'], 'Bearer gh-secret');

      final http.IncomingHttpHeaders npmOwn = {'authorization': 'Bearer $npm'};
      reg.substituteInHeaders(npmOwn, 'registry.npmjs.org', eq);
      expect(npmOwn['authorization'], 'Bearer npm-secret');
    });

    test('mixed sentinels in one request: only the host-matched one swaps', () {
      final reg = SentinelRegistry();
      final gh = reg.register('GH_TOKEN', 'gh-secret', ['api.github.com']);
      final npm = reg.register('NPM_TOKEN', 'npm-secret', [
        'registry.npmjs.org',
      ]);
      final http.IncomingHttpHeaders headers = {
        'authorization': 'Bearer $gh',
        'x-npm-token': npm,
      };
      reg.substituteInHeaders(headers, 'api.github.com', eq);
      expect(headers['authorization'], 'Bearer gh-secret');
      expect(headers['x-npm-token'], npm);
    });
  });

  group('macOS env preamble for masked credentials', () {
    test('emits NAME=<sentinel> assignment and not the real value', () {
      final wrapped = wrapCommandWithSandboxMacOS(
        MacOSSandboxParams(
          command: 'true',
          needsNetworkRestriction: false,
          readConfig: null,
          writeConfig: FsWriteRestrictionConfig(
            allowOnly: ['/tmp'],
            denyWithinAllow: [],
          ),
          setEnvVars: {'GH_TOKEN': 'fake_value_test-sentinel'},
        ),
      );
      expect(wrapped, contains('GH_TOKEN=fake_value_test-sentinel'));
      expect(
        wrapped.indexOf('GH_TOKEN'),
        lessThan(wrapped.indexOf('sandbox-exec')),
      );
    });

    test('still sandboxes when masked env vars are the only restriction', () {
      final wrapped = wrapCommandWithSandboxMacOS(
        MacOSSandboxParams(
          command: 'echo hi',
          needsNetworkRestriction: false,
          readConfig: null,
          writeConfig: null,
          setEnvVars: {'GH_TOKEN': 'fake_value_x'},
        ),
      );
      expect(wrapped, isNot('echo hi'));
      expect(wrapped, contains('GH_TOKEN=fake_value_x'));
    });
  });

  /**
   * Proxy-level header injection: drive `createHttpProxyServer` directly
   * with a hand-built mutateHeaders, the same way SandboxManager wires it.
   * Reuses the tls-terminate-proxy.test.ts fixture pattern.
   */
  group('header injection through the TLS-terminating proxy', () {
    // Every case runs a TLS-terminating proxy: skipped where none can run.
    final test = testWithTls;
    final ca = createMitmCA(caCertPath: CA_CERT, caKeyPath: CA_KEY);
    final reg = SentinelRegistry();
    final sentinel = reg.register('GH_TOKEN', REAL_TOKEN, ['127.0.0.1']);

    late net.NodeServer upstream;
    late int upstreamPort;
    late net.NodeServer proxy;
    late int proxyPort;
    final lastHeaders = captured<http.IncomingHttpHeaders>();

    setUpAll(() async {
      final upCert = mintLeafCert(ca, '127.0.0.1');
      final upLeafOnly = RegExp(
        r'-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----\r?\n?',
      ).firstMatch(upCert.certPem)!.group(0)!;
      upstream = https.createServer(
        {'cert': upLeafOnly, 'key': upCert.keyPem},
        (http.IncomingMessage req, http.ServerResponse res) {
          lastHeaders.value = req.headers;
          res.writeHead(200, {'content-type': 'text/plain'});
          res.end('ok');
        },
      );
      await _listen(upstream);
      upstreamPort = (upstream.address() as net.NodeAddress).port;

      proxy = createHttpProxyServer(
        _HttpOptions(
          mitmCA: SERVES_EMITTED_CONNECTIONS ? ca : null,
          tlsTerminateUpstreamCA: CA_PEM,
          // Per-sentinel host gating lives in the registry now; the closure
          // just forwards destHost.
          mutateHeaders: (headers, destHost) =>
              reg.substituteInHeaders(headers, destHost, eq),
        ),
      );
      await _listen(proxy);
      proxyPort = (proxy.address() as net.NodeAddress).port;
    });

    tearDownAll(() async {
      await _close(proxy);
      await _close(upstream);
      await disposeMitmCA(ca);
    });

    test(
      'upstream receives the real value when the client sends the sentinel',
      () async {
        lastHeaders.clear();
        final r = await curlViaProxy(
          proxyPort,
          'https://127.0.0.1:$upstreamPort/',
          headers: ['Authorization: Bearer $sentinel'],
        );
        expect(r.exit, 0);
        expect(r.status, 200);
        expect(lastHeaders.value?['authorization'], 'Bearer $REAL_TOKEN');
        // The real value never appears in anything the client (sandbox) sees.
        expect(r.body, isNot(contains(REAL_TOKEN)));
      },
    );

    test(
      'substitution covers arbitrary header names, not a fixed list',
      () async {
        lastHeaders.clear();
        final r = await curlViaProxy(
          proxyPort,
          'https://127.0.0.1:$upstreamPort/',
          headers: ['Private-Token: $sentinel'],
        );
        expect(r.exit, 0);
        expect(lastHeaders.value?['private-token'], REAL_TOKEN);
      },
    );

    test(
      'a non-matching destination receives the sentinel unchanged',
      () async {
        // Same upstream server; mint a leaf for a second hostname that resolves
        // to 127.0.0.1 (curl --resolve) but is NOT in the injector's match set.
        final altCert = mintLeafCert(ca, 'localhost');
        final altLeaf = RegExp(
          r'-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----\r?\n?',
        ).firstMatch(altCert.certPem)!.group(0)!;
        final altUpstream = https.createServer(
          {'cert': altLeaf, 'key': altCert.keyPem},
          (http.IncomingMessage req, http.ServerResponse res) {
            lastHeaders.value = req.headers;
            res.writeHead(200);
            res.end('ok');
          },
        );
        await _listen(altUpstream);
        final altPort = (altUpstream.address() as net.NodeAddress).port;
        try {
          lastHeaders.clear();
          final r = await curlViaProxy(
            proxyPort,
            'https://localhost:$altPort/',
            headers: ['Authorization: Bearer $sentinel'],
            resolve: 'localhost:$altPort:127.0.0.1',
          );
          expect(r.exit, 0);
          expect(r.status, 200);
          // Fails closed: the upstream sees the useless fake.
          expect(lastHeaders.value?['authorization'], 'Bearer $sentinel');
          expect(
            lastHeaders.value?['authorization'],
            isNot(contains(REAL_TOKEN)),
          );
        } finally {
          await _close(altUpstream);
        }
      },
    );
  });

  group('header injection on the plain-HTTP path', () {
    final reg = SentinelRegistry();
    final sentinel = reg.register('GH_TOKEN', REAL_TOKEN, ['127.0.0.1']);
    void mutate(http.IncomingHttpHeaders headers, String destHost) =>
        reg.substituteInHeaders(headers, destHost, eq);

    late net.NodeServer upstream;
    late int upstreamPort;
    final lastHeaders = captured<http.IncomingHttpHeaders>();

    setUpAll(() async {
      upstream = http.createServer((
        http.IncomingMessage req,
        http.ServerResponse res,
      ) {
        lastHeaders.value = req.headers;
        res.writeHead(200);
        res.end('ok');
      });
      await _listen(upstream);
      upstreamPort = (upstream.address() as net.NodeAddress).port;
    });

    tearDownAll(() async {
      await _close(upstream);
    });

    test(
      'without mutateHeadersPlaintext the sentinel passes through unchanged',
      () async {
        final proxy = createHttpProxyServer(
          _HttpOptions(mutateHeaders: mutate),
        );
        await _listen(proxy);
        final port = (proxy.address() as net.NodeAddress).port;
        try {
          lastHeaders.clear();
          final r = await curlViaProxy(
            port,
            'http://127.0.0.1:$upstreamPort/',
            headers: ['Authorization: Bearer $sentinel'],
          );
          expect(r.exit, 0);
          expect(lastHeaders.value?['authorization'], 'Bearer $sentinel');
          expect(
            lastHeaders.value?['authorization'],
            isNot(contains(REAL_TOKEN)),
          );
        } finally {
          await _close(proxy);
        }
      },
    );

    test('with mutateHeadersPlaintext the real value is substituted', () async {
      final proxy = createHttpProxyServer(
        _HttpOptions(mutateHeadersPlaintext: mutate),
      );
      await _listen(proxy);
      final port = (proxy.address() as net.NodeAddress).port;
      try {
        lastHeaders.clear();
        final r = await curlViaProxy(
          port,
          'http://127.0.0.1:$upstreamPort/',
          headers: ['Authorization: Bearer $sentinel'],
        );
        expect(r.exit, 0);
        expect(lastHeaders.value?['authorization'], 'Bearer $REAL_TOKEN');
      } finally {
        await _close(proxy);
      }
    });
  });

  /**
   * SandboxManager-level masking on Linux: the sandboxed process sees the
   * sentinel in its environment; the real value never appears in the wrapped
   * command string.
   */
  group(
    'env masking on Linux (bwrap)',
    skip: isLinux ? null : 'describe.if(isLinux)',
    () {
      const MASKED_VAR = 'SRT_TEST_MASKED_TOKEN';

      SandboxRuntimeConfig baseConfig({
        NetworkConfig? network,
        CredentialsConfig? credentials,
      }) {
        return SandboxRuntimeConfig(
          network:
              network ?? NetworkConfig(allowedDomains: [], deniedDomains: []),
          filesystem: FilesystemConfig(
            denyRead: [],
            allowWrite: [_p('/tmp')],
            denyWrite: [],
          ),
          credentials: credentials,
        );
      }

      setUpAll(() async {
        process.env[MASKED_VAR] = REAL_TOKEN;
        await SandboxManager.reset();
        await SandboxManager.initialize(
          baseConfig(
            // injectHosts is unused here (this block tests env-side masking
            // only); the credential defaults to allowedDomains.
            network: NetworkConfig(
              allowedDomains: ['localhost'],
              deniedDomains: [],
            ),
            credentials: CredentialsConfig(
              envVars: [CredentialEnvVarConfig(name: MASKED_VAR, mode: 'mask')],
              allowPlaintextInject: true,
            ),
          ),
        );
      });

      tearDownAll(() async {
        await SandboxManager.reset();
        process.env.remove(MASKED_VAR);
      });

      test('bwrap argv sets the masked var to a sentinel', () async {
        final wrapped = await SandboxManager.wrapWithSandbox('true');
        expect(
          wrapped,
          matches(RegExp('--setenv $MASKED_VAR $SENTINEL_PREFIX[0-9a-f-]{36}')),
        );
      });

      test(
        'the real value never appears in the wrapped command string',
        () async {
          final wrapped = await SandboxManager.wrapWithSandbox('true');
          expect(wrapped, isNot(contains(REAL_TOKEN)));
        },
      );

      test('a masked env var that is unset on the host is skipped', () async {
        await SandboxManager.reset();
        await SandboxManager.initialize(
          baseConfig(
            network: NetworkConfig(
              allowedDomains: ['localhost'],
              deniedDomains: [],
            ),
            credentials: CredentialsConfig(
              envVars: [
                CredentialEnvVarConfig(
                  name: 'SRT_TEST_NEVER_SET',
                  mode: 'mask',
                ),
              ],
              allowPlaintextInject: true,
            ),
          ),
        );
        final wrapped = await SandboxManager.wrapWithSandbox('true');
        expect(wrapped, isNot(contains('--setenv SRT_TEST_NEVER_SET')));

        // Restore the suite-level config for the remaining tests.
        await SandboxManager.reset();
        process.env[MASKED_VAR] = REAL_TOKEN;
        await SandboxManager.initialize(
          baseConfig(
            network: NetworkConfig(
              allowedDomains: ['localhost'],
              deniedDomains: [],
            ),
            credentials: CredentialsConfig(
              envVars: [CredentialEnvVarConfig(name: MASKED_VAR, mode: 'mask')],
              allowPlaintextInject: true,
            ),
          ),
        );
      });

      test(
        'the sandboxed process sees the sentinel, not the real value',
        () async {
          final wrapped = await SandboxManager.wrapWithSandbox(
            'printenv $MASKED_VAR',
          );
          final result = spawnSync(wrapped, [], {
            'shell': true,
            'encoding': 'utf8',
            'timeout': 10000,
            'env': {...process.env, MASKED_VAR: REAL_TOKEN},
          });
          expect(result.status, 0);
          expect(
            (result.stdout as String).trim().startsWith(SENTINEL_PREFIX),
            isTrue,
          );
          expect(result.stdout, isNot(contains(REAL_TOKEN)));
        },
      );

      test('reset clears the sentinel registry', () async {
        expect(SandboxManager.getSentinelRegistry().size, greaterThan(0));
        await SandboxManager.reset();
        expect(SandboxManager.getSentinelRegistry().size, 0);
        // Re-initialize for any following tests.
        process.env[MASKED_VAR] = REAL_TOKEN;
        await SandboxManager.initialize(
          baseConfig(
            network: NetworkConfig(
              allowedDomains: ['localhost'],
              deniedDomains: [],
            ),
            credentials: CredentialsConfig(
              envVars: [CredentialEnvVarConfig(name: MASKED_VAR, mode: 'mask')],
              allowPlaintextInject: true,
            ),
          ),
        );
      });
    },
  );

  /**
   * SandboxManager-level wiring: initialize() builds the injector and wires
   * it into the proxy it starts; wrapWithSandbox() registers the sentinel.
   * Verified by talking to SandboxManager's own proxy port. The bwrap leg
   * (sandbox sees the sentinel) is covered by the previous describe; the
   * TLS leg by the createHttpProxyServer describe. Uses allowPlaintextInject
   * so the upstream doesn't need a system-trusted cert.
   */
  group(
    'end-to-end credential masking via SandboxManager',
    skip: isLinux ? null : 'describe.if(isLinux)',
    () {
      const MASKED_VAR = 'SRT_TEST_E2E_TOKEN';
      late net.NodeServer upstream;
      late int upstreamPort;
      final lastHeaders = captured<http.IncomingHttpHeaders>();

      setUpAll(() async {
        upstream = http.createServer((
          http.IncomingMessage req,
          http.ServerResponse res,
        ) {
          lastHeaders.value = req.headers;
          res.writeHead(200);
          res.end('ok');
        });
        await _listen(upstream);
        upstreamPort = (upstream.address() as net.NodeAddress).port;

        process.env[MASKED_VAR] = REAL_TOKEN;
        await SandboxManager.reset();
        await SandboxManager.initialize(
          SandboxRuntimeConfig(
            network: NetworkConfig(
              allowedDomains: ['localhost'],
              deniedDomains: [],
            ),
            filesystem: FilesystemConfig(
              denyRead: [],
              allowWrite: [_p('/tmp')],
              denyWrite: [],
            ),
            credentials: CredentialsConfig(
              envVars: [
                CredentialEnvVarConfig(
                  name: MASKED_VAR,
                  mode: 'mask',
                  injectHosts: ['localhost'],
                ),
              ],
              allowPlaintextInject: true,
            ),
          ),
        );
      });

      tearDownAll(() async {
        await SandboxManager.reset();
        process.env.remove(MASKED_VAR);
        await _close(upstream);
      });

      test(
        'the manager-started proxy substitutes sentinel→real for an injectHost',
        () async {
          // wrapWithSandbox registers the sentinel as a side effect.
          final wrapped = await SandboxManager.wrapWithSandbox(
            'printenv $MASKED_VAR',
          );
          expect(wrapped, isNot(contains(REAL_TOKEN)));
          final sentinel = SandboxManager.getSentinelRegistry()
              .entries()
              .where((e) => e.$2 == REAL_TOKEN)
              .map((e) => e.$1)
              .firstOrNull;
          expect(sentinel?.startsWith(SENTINEL_PREFIX), isTrue);

          // The sandbox itself reads the sentinel.
          final inSandbox = spawnSync(wrapped, [], {
            'shell': true,
            'encoding': 'utf8',
            'timeout': 10000,
            'env': {...process.env, MASKED_VAR: REAL_TOKEN},
          });
          expect((inSandbox.stdout as String).trim(), sentinel!);

          // A request carrying the sentinel through SandboxManager's proxy
          // reaches the upstream with the real value.
          final proxyPort = SandboxManager.getProxyPort()!;
          final authToken = SandboxManager.getProxyAuthToken()!;
          lastHeaders.clear();
          final r = await curlViaProxy(
            proxyPort,
            'http://localhost:$upstreamPort/',
            headers: ['Authorization: Bearer $sentinel'],
            proxyAuth: 'srt:$authToken',
          );
          expect(r.exit, 0);
          expect(r.status, 200);
          expect(lastHeaders.value?['authorization'], 'Bearer $REAL_TOKEN');
        },
        timeout: const Timeout(Duration(milliseconds: 20000)),
      );

      test(
        'a non-injectHost destination through the manager proxy receives the sentinel',
        () async {
          // Reconfigure with an injectHosts that does NOT cover localhost.
          await SandboxManager.reset();
          process.env[MASKED_VAR] = REAL_TOKEN;
          await SandboxManager.initialize(
            SandboxRuntimeConfig(
              network: NetworkConfig(
                allowedDomains: ['localhost', 'api.github.com'],
                deniedDomains: [],
              ),
              filesystem: FilesystemConfig(
                denyRead: [],
                allowWrite: [_p('/tmp')],
                denyWrite: [],
              ),
              credentials: CredentialsConfig(
                envVars: [
                  CredentialEnvVarConfig(
                    name: MASKED_VAR,
                    mode: 'mask',
                    injectHosts: ['api.github.com'],
                  ),
                ],
                allowPlaintextInject: true,
              ),
            ),
          );
          await SandboxManager.wrapWithSandbox('true');
          final sentinel = SandboxManager.getSentinelRegistry()
              .entries()
              .where((e) => e.$2 == REAL_TOKEN)
              .map((e) => e.$1)
              .firstOrNull;

          final proxyPort = SandboxManager.getProxyPort()!;
          final authToken = SandboxManager.getProxyAuthToken()!;
          lastHeaders.clear();
          final r = await curlViaProxy(
            proxyPort,
            'http://localhost:$upstreamPort/',
            headers: ['Authorization: Bearer $sentinel'],
            proxyAuth: 'srt:$authToken',
          );
          expect(r.exit, 0);
          expect(lastHeaders.value?['authorization'], 'Bearer $sentinel');
          expect(
            lastHeaders.value?['authorization'],
            isNot(contains(REAL_TOKEN)),
          );
        },
        timeout: const Timeout(Duration(milliseconds: 20000)),
      );
    },
  );

  /**
   * Per-credential injectHosts through SandboxManager: GH_TOKEN and NPM_TOKEN
   * each declare their own per-entry injectHosts. Each sentinel only swaps at
   * its own credential's injectHosts — sending GH_TOKEN's sentinel to
   * NPM_TOKEN's host (or vice versa) must NOT substitute, even though both
   * hosts are allowlisted.
   */
  group(
    'per-credential injectHosts via SandboxManager',
    skip: isLinux ? null : 'describe.if(isLinux)',
    () {
      const GH_VAR = 'SRT_TEST_GH_TOKEN';
      const NPM_VAR = 'SRT_TEST_NPM_TOKEN';
      const GH_REAL = 'gh-real-secret';
      const NPM_REAL = 'npm-real-secret';

      // Two upstreams behind two loopback names (a `.localhost` name resolves
      // to loopback locally, and the resolved-address guard lets it): the proxy
      // distinguishes them by the absolute-URI host on the plain-HTTP path,
      // which is what destHost gating sees.
      const GH_HOST = 'localhost';
      const NPM_HOST = 'npm.localhost';

      late net.NodeServer ghUp;
      late int ghPort;
      late net.NodeServer npmUp;
      late int npmPort;
      final ghHeaders = captured<http.IncomingHttpHeaders>();
      final npmHeaders = captured<http.IncomingHttpHeaders>();
      late String ghSentinel;
      late String npmSentinel;
      late int proxyPort;
      late String authToken;

      setUpAll(() async {
        ghUp = http.createServer((
          http.IncomingMessage req,
          http.ServerResponse res,
        ) {
          ghHeaders.value = req.headers;
          res.writeHead(200);
          res.end('ok');
        });
        npmUp = http.createServer((
          http.IncomingMessage req,
          http.ServerResponse res,
        ) {
          npmHeaders.value = req.headers;
          res.writeHead(200);
          res.end('ok');
        });
        await _listen(ghUp);
        await _listen(npmUp);
        ghPort = (ghUp.address() as net.NodeAddress).port;
        npmPort = (npmUp.address() as net.NodeAddress).port;

        process.env[GH_VAR] = GH_REAL;
        process.env[NPM_VAR] = NPM_REAL;
        await SandboxManager.reset();
        await SandboxManager.initialize(
          SandboxRuntimeConfig(
            network: NetworkConfig(
              allowedDomains: [GH_HOST, NPM_HOST],
              deniedDomains: [],
            ),
            filesystem: FilesystemConfig(
              denyRead: [],
              allowWrite: [_p('/tmp')],
              denyWrite: [],
            ),
            credentials: CredentialsConfig(
              // Each credential narrows to its own host via per-entry injectHosts.
              envVars: [
                CredentialEnvVarConfig(
                  name: GH_VAR,
                  mode: 'mask',
                  injectHosts: [GH_HOST],
                ),
                CredentialEnvVarConfig(
                  name: NPM_VAR,
                  mode: 'mask',
                  injectHosts: [NPM_HOST],
                ),
              ],
              allowPlaintextInject: true,
            ),
          ),
        );
        await SandboxManager.wrapWithSandbox('true');
        final reg = SandboxManager.getSentinelRegistry();
        ghSentinel = reg.entries().firstWhere((e) => e.$2 == GH_REAL).$1;
        npmSentinel = reg.entries().firstWhere((e) => e.$2 == NPM_REAL).$1;
        proxyPort = SandboxManager.getProxyPort()!;
        authToken = SandboxManager.getProxyAuthToken()!;
      });

      tearDownAll(() async {
        await SandboxManager.reset();
        process.env.remove(GH_VAR);
        process.env.remove(NPM_VAR);
        await _close(ghUp);
        await _close(npmUp);
      });

      test('two masked vars register two distinct sentinels', () {
        expect(ghSentinel, isNot(npmSentinel));
        expect(SandboxManager.getSentinelRegistry().size, 2);
      });

      test('GH sentinel swaps at its own per-entry injectHost', () async {
        ghHeaders.clear();
        final r = await curlViaProxy(
          proxyPort,
          'http://$GH_HOST:$ghPort/',
          headers: ['Authorization: Bearer $ghSentinel'],
          proxyAuth: 'srt:$authToken',
        );
        expect(r.exit, 0);
        expect(ghHeaders.value?['authorization'], 'Bearer $GH_REAL');
      }, timeout: const Timeout(Duration(milliseconds: 20000)));

      test('NPM sentinel swaps only at its own per-entry injectHost', () async {
        npmHeaders.clear();
        final r = await curlViaProxy(
          proxyPort,
          'http://$NPM_HOST:$npmPort/',
          headers: ['Authorization: Bearer $npmSentinel'],
          proxyAuth: 'srt:$authToken',
        );
        expect(r.exit, 0);
        expect(npmHeaders.value?['authorization'], 'Bearer $NPM_REAL');

        // Per-entry injectHosts is exclusive: NPM's sentinel sent to GH_HOST
        // (not in NPM's list) stays a fake.
        ghHeaders.clear();
        final r2 = await curlViaProxy(
          proxyPort,
          'http://$GH_HOST:$ghPort/',
          headers: ['Authorization: Bearer $npmSentinel'],
          proxyAuth: 'srt:$authToken',
        );
        expect(r2.exit, 0);
        expect(ghHeaders.value?['authorization'], 'Bearer $npmSentinel');
        expect(ghHeaders.value?['authorization'], isNot(contains(NPM_REAL)));
      }, timeout: const Timeout(Duration(milliseconds: 20000)));

      test(
        "anti-laundering: GH sentinel sent to NPM's host is not swapped",
        () async {
          npmHeaders.clear();
          final r = await curlViaProxy(
            proxyPort,
            'http://$NPM_HOST:$npmPort/',
            headers: ['Authorization: Bearer $ghSentinel'],
            proxyAuth: 'srt:$authToken',
          );
          expect(r.exit, 0);
          expect(npmHeaders.value?['authorization'], 'Bearer $ghSentinel');
          expect(npmHeaders.value?['authorization'], isNot(contains(GH_REAL)));
        },
        timeout: const Timeout(Duration(milliseconds: 20000)),
      );
    },
  );

  /**
   * No per-entry injectHosts → defaults to network.allowedDomains.
   * injectHosts is an optional narrowing; absent it, the credential is
   * injectable at *every* host the sandbox can reach. The second test
   * makes the security implication explicit.
   */
  group(
    'injectHosts defaults to allowedDomains via SandboxManager',
    skip: isLinux ? null : 'describe.if(isLinux)',
    () {
      const VAR = 'SRT_TEST_DEFAULT_TOKEN';
      const REAL = 'default-real-secret';
      const HOST_A = 'localhost';
      const HOST_B = 'host-b.localhost';

      late net.NodeServer upA;
      late int portA;
      late net.NodeServer upB;
      late int portB;
      final hdrA = captured<http.IncomingHttpHeaders>();
      final hdrB = captured<http.IncomingHttpHeaders>();

      setUpAll(() async {
        upA = http.createServer((
          http.IncomingMessage req,
          http.ServerResponse res,
        ) {
          hdrA.value = req.headers;
          res.writeHead(200);
          res.end('ok');
        });
        upB = http.createServer((
          http.IncomingMessage req,
          http.ServerResponse res,
        ) {
          hdrB.value = req.headers;
          res.writeHead(200);
          res.end('ok');
        });
        await _listen(upA);
        await _listen(upB);
        portA = (upA.address() as net.NodeAddress).port;
        portB = (upB.address() as net.NodeAddress).port;
      });

      tearDownAll(() async {
        await SandboxManager.reset();
        process.env.remove(VAR);
        await _close(upA);
        await _close(upB);
      });

      test(
        'with no injectHosts, sentinel swaps at the sole allowedDomain',
        () async {
          process.env[VAR] = REAL;
          await SandboxManager.reset();
          await SandboxManager.initialize(
            SandboxRuntimeConfig(
              network: NetworkConfig(
                allowedDomains: [HOST_A],
                deniedDomains: [],
              ),
              filesystem: FilesystemConfig(
                denyRead: [],
                allowWrite: [_p('/tmp')],
                denyWrite: [],
              ),
              credentials: CredentialsConfig(
                envVars: [CredentialEnvVarConfig(name: VAR, mode: 'mask')],
                // No per-entry injectHosts → defaults to allowedDomains.
                allowPlaintextInject: true,
              ),
            ),
          );
          await SandboxManager.wrapWithSandbox('true');
          final sentinel = SandboxManager.getSentinelRegistry()
              .entries()
              .firstWhere((e) => e.$2 == REAL)
              .$1;
          final proxyPort = SandboxManager.getProxyPort()!;
          final authToken = SandboxManager.getProxyAuthToken()!;

          hdrA.clear();
          final r = await curlViaProxy(
            proxyPort,
            'http://$HOST_A:$portA/',
            headers: ['Authorization: Bearer $sentinel'],
            proxyAuth: 'srt:$authToken',
          );
          expect(r.exit, 0);
          expect(hdrA.value?['authorization'], 'Bearer $REAL');
        },
        timeout: const Timeout(Duration(milliseconds: 20000)),
      );

      test(
        'without injectHosts, credential is injected at every allowedDomain',
        () async {
          // Security trade-off made explicit: two reachable hosts, no
          // narrowing → the real value goes to BOTH. A credential intended
          // for one host must set injectHosts to keep it from the other.
          process.env[VAR] = REAL;
          await SandboxManager.reset();
          await SandboxManager.initialize(
            SandboxRuntimeConfig(
              network: NetworkConfig(
                allowedDomains: [HOST_A, HOST_B],
                deniedDomains: [],
              ),
              filesystem: FilesystemConfig(
                denyRead: [],
                allowWrite: [_p('/tmp')],
                denyWrite: [],
              ),
              credentials: CredentialsConfig(
                envVars: [CredentialEnvVarConfig(name: VAR, mode: 'mask')],
                allowPlaintextInject: true,
              ),
            ),
          );
          await SandboxManager.wrapWithSandbox('true');
          final sentinel = SandboxManager.getSentinelRegistry()
              .entries()
              .firstWhere((e) => e.$2 == REAL)
              .$1;
          final proxyPort = SandboxManager.getProxyPort()!;
          final authToken = SandboxManager.getProxyAuthToken()!;

          hdrA.clear();
          final ra = await curlViaProxy(
            proxyPort,
            'http://$HOST_A:$portA/',
            headers: ['Authorization: Bearer $sentinel'],
            proxyAuth: 'srt:$authToken',
          );
          expect(ra.exit, 0);
          expect(hdrA.value?['authorization'], 'Bearer $REAL');

          hdrB.clear();
          final rb = await curlViaProxy(
            proxyPort,
            'http://$HOST_B:$portB/',
            headers: ['Authorization: Bearer $sentinel'],
            proxyAuth: 'srt:$authToken',
          );
          expect(rb.exit, 0);
          expect(hdrB.value?['authorization'], 'Bearer $REAL');
        },
        timeout: const Timeout(Duration(milliseconds: 20000)),
      );
    },
  );

  /**
   * Env-var masking with decode: "jwt" — the variable's whole value is a JWT
   * and the sandbox sees a JWT-shaped fake instead of the bare fake_value_
   * sentinel, so token-parsing clients keep working.
   */
  group(
    'env decode: "jwt" masking on Linux (bwrap)',
    skip: isLinux ? null : 'describe.if(isLinux)',
    () {
      const JWT_VAR = 'SRT_TEST_JWT_ENV_TOKEN';
      String b64u(String s) => Buffer.from(s, 'utf8').toString('base64url');
      final REAL_JWT =
          'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.' +
          b64u('{"sub":"env-user","iat":1516239022}') +
          '.ZW52LXJlYWwtc2ln';

      SandboxRuntimeConfig decodeConfig(String name) {
        return SandboxRuntimeConfig(
          network: NetworkConfig(
            allowedDomains: ['localhost'],
            deniedDomains: [],
          ),
          filesystem: FilesystemConfig(
            denyRead: [],
            allowWrite: [_p('/tmp')],
            denyWrite: [],
          ),
          credentials: CredentialsConfig(
            envVars: [
              CredentialEnvVarConfig(name: name, mode: 'mask', decode: 'jwt'),
            ],
            allowPlaintextInject: true,
          ),
        );
      }

      tearDownAll(() async {
        await SandboxManager.reset();
        process.env.remove(JWT_VAR);
      });

      test(
        'the sandbox sees a parseable HS256 fake JWT, never the real one',
        () async {
          process.env[JWT_VAR] = REAL_JWT;
          await SandboxManager.reset();
          await SandboxManager.initialize(decodeConfig(JWT_VAR));

          final wrapped = await SandboxManager.wrapWithSandbox(
            'printenv $JWT_VAR',
          );
          expect(wrapped, isNot(contains(REAL_JWT)));

          final result = spawnSync(wrapped, [], {
            'shell': true,
            'encoding': 'utf8',
            'timeout': 10000,
            'env': {...process.env, JWT_VAR: REAL_JWT},
          });
          expect(result.status, 0);
          final fakeJwt = (result.stdout as String).trim();
          expect(fakeJwt, isNot(REAL_JWT));
          expect(fakeJwt, isNot(contains(REAL_JWT)));

          // The fake is a structurally valid JWT: a tool that parses the token
          // from env (segment count, header, exp) keeps working.
          expect(fakeJwt.split('.'), hasLength(3));
          expect(verifyJwt(fakeJwt), isTrue);
          final header =
              jsonDecode(
                    Buffer.from(
                      fakeJwt.split('.')[0],
                      'base64url',
                    ).toString('utf8'),
                  )
                  as Map<String, Object?>;
          expect(header, {'alg': 'HS256', 'typ': 'JWT'});

          // The registry maps the fake back to the real token for the proxy.
          expect(
            SandboxManager.getSentinelRegistry().lookupReal(fakeJwt),
            REAL_JWT,
          );
        },
      );

      test(
        'a set value that is not a JWT fails open with a loud warning',
        () async {
          const NOT_JWT_VAR = 'SRT_TEST_NOT_A_JWT';
          process.env[NOT_JWT_VAR] = 'hunter2-not-a-jwt';
          // Dart: spyOn(console, 'warn') is a saved console.warn replaced by a recorder.
          final warnCalls = <Object?>[];
          final warnSpy = console.warn;
          console.warn = ([a, b, c, d]) {
            warnCalls.add(a);
          };
          try {
            await SandboxManager.reset();
            await SandboxManager.initialize(decodeConfig(NOT_JWT_VAR));
            final wrapped = await SandboxManager.wrapWithSandbox(
              'printenv $NOT_JWT_VAR',
            );

            // Nothing was masked: no sentinel is set for the var...
            expect(wrapped, isNot(contains('--setenv $NOT_JWT_VAR')));
            // ...and the variable is not unset either — the real value passes
            // through to the sandbox (fail-open).
            final result = spawnSync(wrapped, [], {
              'shell': true,
              'encoding': 'utf8',
              'timeout': 10000,
              'env': {...process.env, NOT_JWT_VAR: 'hunter2-not-a-jwt'},
            });
            expect(result.status, 0);
            expect((result.stdout as String).trim(), 'hunter2-not-a-jwt');

            // The fail-open is loud: a stderr warning names the variable.
            final msgs = warnCalls.map((c) => c as String).toList();
            final msg = msgs.where((m) => m.contains(NOT_JWT_VAR)).firstOrNull;
            expect(msg, isNotNull);
            expect(msg, contains('UNPROTECTED'));
            expect(msg, contains('did not verify'));
            expect(msg, contains('JWT'));
          } finally {
            console.warn = warnSpy;
            process.env.remove(NOT_JWT_VAR);
          }
        },
      );

      test('an unset decode var is skipped silently', () async {
        // Dart: spyOn(console, 'warn') is a saved console.warn replaced by a recorder.
        final warnCalls = <Object?>[];
        final warnSpy = console.warn;
        console.warn = ([a, b, c, d]) {
          warnCalls.add(a);
        };
        try {
          await SandboxManager.reset();
          await SandboxManager.initialize(
            decodeConfig('SRT_TEST_JWT_NEVER_SET'),
          );
          final wrapped = await SandboxManager.wrapWithSandbox('true');
          expect(wrapped, isNot(contains('--setenv SRT_TEST_JWT_NEVER_SET')));
          expect(
            warnCalls.any(
              (c) => (c as String).contains('SRT_TEST_JWT_NEVER_SET'),
            ),
            isFalse,
          );
        } finally {
          console.warn = warnSpy;
        }
      });

      test(
        'regression: without decode, a JWT-valued var gets the plain sentinel',
        () async {
          process.env[JWT_VAR] = REAL_JWT;
          await SandboxManager.reset();
          await SandboxManager.initialize(
            SandboxRuntimeConfig(
              network: NetworkConfig(
                allowedDomains: ['localhost'],
                deniedDomains: [],
              ),
              filesystem: FilesystemConfig(
                denyRead: [],
                allowWrite: [_p('/tmp')],
                denyWrite: [],
              ),
              credentials: CredentialsConfig(
                envVars: [CredentialEnvVarConfig(name: JWT_VAR, mode: 'mask')],
                allowPlaintextInject: true,
              ),
            ),
          );
          final wrapped = await SandboxManager.wrapWithSandbox('true');
          expect(
            wrapped,
            matches(RegExp('--setenv $JWT_VAR $SENTINEL_PREFIX[0-9a-f-]{36}')),
          );
          expect(wrapped, isNot(contains(REAL_JWT)));
        },
      );
    },
  );

  /**
   * End-to-end env decode masking: the env var holds a JWT; inside the
   * sandbox the tool reads a structurally valid FAKE JWT; sending it through
   * the manager proxy delivers the REAL JWT to the injectHost, while a
   * non-injectHost receives the fake.
   */
  group(
    'end-to-end env decode masking via SandboxManager',
    skip: isLinux ? null : 'describe.if(isLinux)',
    () {
      const JWT_VAR = 'SRT_TEST_E2E_JWT_TOKEN';
      const HOST_A = 'localhost';
      const HOST_B = 'host-b.localhost';

      String b64u(String s) => Buffer.from(s, 'utf8').toString('base64url');
      final REAL_JWT =
          'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.' +
          b64u('{"sub":"e2e-env-user","iat":1516239022}') +
          '.ZTJlLWVudi1zaWc';

      late net.NodeServer upstream;
      late int upstreamPort;
      final lastHeaders = captured<http.IncomingHttpHeaders>();

      setUpAll(() async {
        upstream = http.createServer((
          http.IncomingMessage req,
          http.ServerResponse res,
        ) {
          lastHeaders.value = req.headers;
          res.writeHead(200);
          res.end('ok');
        });
        await _listen(upstream);
        upstreamPort = (upstream.address() as net.NodeAddress).port;

        process.env[JWT_VAR] = REAL_JWT;
        await SandboxManager.reset();
        await SandboxManager.initialize(
          SandboxRuntimeConfig(
            network: NetworkConfig(
              allowedDomains: [HOST_A, HOST_B],
              deniedDomains: [],
            ),
            filesystem: FilesystemConfig(
              denyRead: [],
              allowWrite: [_p('/tmp')],
              denyWrite: [],
            ),
            credentials: CredentialsConfig(
              envVars: [
                CredentialEnvVarConfig(
                  name: JWT_VAR,
                  mode: 'mask',
                  decode: 'jwt',
                  injectHosts: [HOST_A],
                ),
              ],
              allowPlaintextInject: true,
            ),
          ),
        );
      });

      tearDownAll(() async {
        await SandboxManager.reset();
        process.env.remove(JWT_VAR);
        await _close(upstream);
      });

      /** Wrap printenv and run it: the fake JWT the sandbox actually sees. */
      String readFakeFromSandbox(String wrapped) {
        final result = spawnSync(wrapped, [], {
          'shell': true,
          'encoding': 'utf8',
          'timeout': 10000,
          'env': {...process.env, JWT_VAR: REAL_JWT},
        });
        expect(result.status, 0);
        return (result.stdout as String).trim();
      }

      test(
        'printenv → fake JWT; proxy delivers the real JWT to the injectHost',
        () async {
          final wrapped = await SandboxManager.wrapWithSandbox(
            'printenv $JWT_VAR',
          );
          expect(wrapped, isNot(contains(REAL_JWT)));
          final fakeJwt = readFakeFromSandbox(wrapped);
          expect(fakeJwt, isNot(REAL_JWT));
          expect(verifyJwt(fakeJwt), isTrue);

          final proxyPort = SandboxManager.getProxyPort()!;
          final authToken = SandboxManager.getProxyAuthToken()!;
          lastHeaders.clear();
          final r = await curlViaProxy(
            proxyPort,
            'http://$HOST_A:$upstreamPort/',
            headers: ['Authorization: Bearer $fakeJwt'],
            proxyAuth: 'srt:$authToken',
          );
          expect(r.exit, 0);
          expect(r.status, 200);
          expect(lastHeaders.value?['authorization'], 'Bearer $REAL_JWT');
        },
        timeout: const Timeout(Duration(milliseconds: 20000)),
      );

      test(
        'a non-injectHost destination receives the fake JWT unchanged',
        () async {
          final wrapped = await SandboxManager.wrapWithSandbox(
            'printenv $JWT_VAR',
          );
          final fakeJwt = readFakeFromSandbox(wrapped);

          final proxyPort = SandboxManager.getProxyPort()!;
          final authToken = SandboxManager.getProxyAuthToken()!;
          lastHeaders.clear();
          final r = await curlViaProxy(
            proxyPort,
            'http://$HOST_B:$upstreamPort/',
            headers: ['Authorization: Bearer $fakeJwt'],
            proxyAuth: 'srt:$authToken',
          );
          expect(r.exit, 0);
          expect(lastHeaders.value?['authorization'], 'Bearer $fakeJwt');
          expect(
            lastHeaders.value?['authorization'],
            isNot(contains(REAL_JWT)),
          );
        },
        timeout: const Timeout(Duration(milliseconds: 20000)),
      );
    },
  );

  /**
   * Env-var claim-level masking (decode: "jwt" + maskClaims): the sandbox
   * sees a rebuilt token whose named claim is a sentinel while every other
   * claim — and the header segment — is real, and the registry carries BOTH
   * mappings (whole fake token → real token, claim sentinel → real claim).
   */
  group(
    'env maskClaims masking on Linux (bwrap)',
    skip: isLinux ? null : 'describe.if(isLinux)',
    () {
      const JWT_VAR = 'SRT_TEST_JWT_ENV_CLAIMS';
      String b64u(String s) => Buffer.from(s, 'utf8').toString('base64url');
      // Header with a kid so verbatim header reuse is observable (the minted
      // whole-token fake's header has no kid).
      final REAL_HEADER = b64u('{"alg":"RS256","typ":"JWT","kid":"env-key-7"}');
      const REAL_CLAIM = 'env-real-claim-secret-0123456789';
      final REAL_PAYLOAD = <String, Object?>{
        'sub': 'env-user',
        'api_key': REAL_CLAIM,
        'aud': 'api.example.com',
        'iat': 1516239022,
      };
      final REAL_JWT =
          '$REAL_HEADER.${b64u(jsonEncode(REAL_PAYLOAD))}.ZW52LXJlYWwtc2ln';

      SandboxRuntimeConfig claimsConfig(String name, List<String> maskClaims) {
        return SandboxRuntimeConfig(
          network: NetworkConfig(
            allowedDomains: ['localhost'],
            deniedDomains: [],
          ),
          filesystem: FilesystemConfig(
            denyRead: [],
            allowWrite: [_p('/tmp')],
            denyWrite: [],
          ),
          credentials: CredentialsConfig(
            envVars: [
              CredentialEnvVarConfig(
                name: name,
                mode: 'mask',
                decode: 'jwt',
                maskClaims: maskClaims,
              ),
            ],
            allowPlaintextInject: true,
          ),
        );
      }

      /** Wrap printenv and run it: the fake JWT the sandbox actually sees. */
      String readFakeFromSandbox(String wrapped) {
        final result = spawnSync(wrapped, [], {
          'shell': true,
          'encoding': 'utf8',
          'timeout': 10000,
          'env': {...process.env, JWT_VAR: REAL_JWT},
        });
        expect(result.status, 0);
        return (result.stdout as String).trim();
      }

      Map<String, Object?> payloadOf(String token) {
        return jsonDecode(
              Buffer.from(token.split('.')[1], 'base64url').toString('utf8'),
            )
            as Map<String, Object?>;
      }

      tearDownAll(() async {
        await SandboxManager.reset();
        process.env.remove(JWT_VAR);
      });

      test(
        'named claim is a sentinel, others real, header verbatim, filler signature; both registry mappings exist',
        () async {
          process.env[JWT_VAR] = REAL_JWT;
          await SandboxManager.reset();
          await SandboxManager.initialize(claimsConfig(JWT_VAR, ['api_key']));

          final wrapped = await SandboxManager.wrapWithSandbox(
            'printenv $JWT_VAR',
          );
          expect(wrapped, isNot(contains(REAL_JWT)));
          expect(wrapped, isNot(contains(REAL_CLAIM)));
          final fakeJwt = readFakeFromSandbox(wrapped);
          expect(fakeJwt, isNot(REAL_JWT));
          expect(verifyJwt(fakeJwt), isTrue);

          // Header segment reused byte-identical; signature is the fixed filler,
          // never the real signature.
          final parts = fakeJwt.split('.');
          final h = parts[0];
          final sig = parts[2];
          expect(h, REAL_HEADER);
          expect(sig, 'c3J0LWZha2U');

          // The named claim is a sentinel; every other claim is real.
          final payload = payloadOf(fakeJwt);
          final claimSentinel = payload['api_key'] as String;
          expect(claimSentinel, startsWith(SENTINEL_PREFIX));
          expect(payload, {...REAL_PAYLOAD, 'api_key': claimSentinel});

          // Mapping (a): whole fake token → whole real token (bearer usage).
          final registry = SandboxManager.getSentinelRegistry();
          expect(registry.lookupReal(fakeJwt), REAL_JWT);
          // Mapping (b): claim sentinel → real claim value (extracted usage).
          expect(registry.lookupReal(claimSentinel), REAL_CLAIM);
          expect(registry.size, 2);
        },
      );

      test(
        'a named claim absent or non-string is skipped; the matched claim still masks',
        () async {
          process.env[JWT_VAR] = REAL_JWT;
          await SandboxManager.reset();
          await SandboxManager.initialize(
            claimsConfig(JWT_VAR, ['api_key', 'not_present', 'iat']),
          );

          final wrapped = await SandboxManager.wrapWithSandbox(
            'printenv $JWT_VAR',
          );
          final payload = payloadOf(readFakeFromSandbox(wrapped));
          expect(payload['api_key'] as String, startsWith(SENTINEL_PREFIX));
          // Absent and non-string (iat is a number) claims are skipped.
          expect(payload['not_present'], isNull);
          expect(payload['iat'], REAL_PAYLOAD['iat']);
          // Only the whole-token mapping and the one matched claim.
          expect(SandboxManager.getSentinelRegistry().size, 2);
        },
      );

      test(
        'no named claim maskable → loud warning, real value passes through (fail-open)',
        () async {
          process.env[JWT_VAR] = REAL_JWT;
          // Dart: spyOn(console, 'warn') is a saved console.warn replaced by a recorder.
          final warnCalls = <Object?>[];
          final warnSpy = console.warn;
          console.warn = ([a, b, c, d]) {
            warnCalls.add(a);
          };
          try {
            await SandboxManager.reset();
            await SandboxManager.initialize(
              claimsConfig(JWT_VAR, ['not_present']),
            );
            final wrapped = await SandboxManager.wrapWithSandbox(
              'printenv $JWT_VAR',
            );

            // Nothing was masked: no sentinel is set for the var...
            expect(wrapped, isNot(contains('--setenv $JWT_VAR')));
            // ...and the real value passes through to the sandbox (fail-open).
            expect(readFakeFromSandbox(wrapped), REAL_JWT);
            expect(SandboxManager.getSentinelRegistry().size, 0);

            // The fail-open is loud: a stderr warning names the variable.
            final msgs = warnCalls.map((c) => c as String).toList();
            final msg = msgs.where((m) => m.contains(JWT_VAR)).firstOrNull;
            expect(msg, isNotNull);
            expect(msg, contains('UNPROTECTED'));
            expect(msg, contains('maskClaims'));
          } finally {
            console.warn = warnSpy;
          }
        },
      );
    },
  );

  /**
   * End-to-end env claim-level masking: the env var holds a JWT with a
   * secret claim; inside the sandbox the tool reads a rebuilt token whose
   * named claim is a sentinel; the proxy substitutes BOTH the whole token
   * (bearer usage) and the extracted claim sentinel (claim-extraction
   * usage) on egress to the injectHost, and neither at a non-injectHost.
   */
  group(
    'end-to-end env maskClaims via SandboxManager',
    skip: isLinux ? null : 'describe.if(isLinux)',
    () {
      const JWT_VAR = 'SRT_TEST_E2E_JWT_CLAIMS';
      const HOST_A = 'localhost';
      const HOST_B = 'host-b.localhost';

      String b64u(String s) => Buffer.from(s, 'utf8').toString('base64url');
      const REAL_CLAIM = 'e2e-env-claim-secret-0123456789';
      final REAL_JWT =
          'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.' +
          b64u(
            '{"sub":"e2e-env-user","api_key":"$REAL_CLAIM","iat":1516239022}',
          ) +
          '.ZTJlLWVudi1jbGFpbXMtc2ln';

      late net.NodeServer upstream;
      late int upstreamPort;
      final lastHeaders = captured<http.IncomingHttpHeaders>();

      setUpAll(() async {
        upstream = http.createServer((
          http.IncomingMessage req,
          http.ServerResponse res,
        ) {
          lastHeaders.value = req.headers;
          res.writeHead(200);
          res.end('ok');
        });
        await _listen(upstream);
        upstreamPort = (upstream.address() as net.NodeAddress).port;

        process.env[JWT_VAR] = REAL_JWT;
        await SandboxManager.reset();
        await SandboxManager.initialize(
          SandboxRuntimeConfig(
            network: NetworkConfig(
              allowedDomains: [HOST_A, HOST_B],
              deniedDomains: [],
            ),
            filesystem: FilesystemConfig(
              denyRead: [],
              allowWrite: [_p('/tmp')],
              denyWrite: [],
            ),
            credentials: CredentialsConfig(
              envVars: [
                CredentialEnvVarConfig(
                  name: JWT_VAR,
                  mode: 'mask',
                  decode: 'jwt',
                  maskClaims: ['api_key'],
                  injectHosts: [HOST_A],
                ),
              ],
              allowPlaintextInject: true,
            ),
          ),
        );
      });

      tearDownAll(() async {
        await SandboxManager.reset();
        process.env.remove(JWT_VAR);
        await _close(upstream);
      });

      /** Wrap printenv and run it: the fake JWT the sandbox actually sees. */
      Future<String> readFakeJwt() async {
        final wrapped = await SandboxManager.wrapWithSandbox(
          'printenv $JWT_VAR',
        );
        expect(wrapped, isNot(contains(REAL_JWT)));
        final result = spawnSync(wrapped, [], {
          'shell': true,
          'encoding': 'utf8',
          'timeout': 10000,
          'env': {...process.env, JWT_VAR: REAL_JWT},
        });
        expect(result.status, 0);
        return (result.stdout as String).trim();
      }

      String claimOf(String token) {
        final payload =
            jsonDecode(
                  Buffer.from(
                    token.split('.')[1],
                    'base64url',
                  ).toString('utf8'),
                )
                as Map<String, Object?>;
        return payload['api_key'] as String;
      }

      test(
        'printenv → claim-masked fake that decodes; bearer usage delivers the whole real token',
        () async {
          final fakeJwt = await readFakeJwt();
          expect(fakeJwt, isNot(REAL_JWT));
          expect(verifyJwt(fakeJwt), isTrue);
          // Header reused verbatim; only the payload changed.
          expect(fakeJwt.split('.')[0], REAL_JWT.split('.')[0]);
          final payload =
              jsonDecode(
                    Buffer.from(
                      fakeJwt.split('.')[1],
                      'base64url',
                    ).toString('utf8'),
                  )
                  as Map<String, Object?>;
          expect(payload['api_key'] as String, startsWith(SENTINEL_PREFIX));
          expect(payload['sub'], 'e2e-env-user');
          expect(payload['iat'], 1516239022);

          // The tool sends the token verbatim → the injectHost receives the
          // whole REAL token.
          final proxyPort = SandboxManager.getProxyPort()!;
          final authToken = SandboxManager.getProxyAuthToken()!;
          lastHeaders.clear();
          final r = await curlViaProxy(
            proxyPort,
            'http://$HOST_A:$upstreamPort/',
            headers: ['Authorization: Bearer $fakeJwt'],
            proxyAuth: 'srt:$authToken',
          );
          expect(r.exit, 0);
          expect(r.status, 200);
          expect(lastHeaders.value?['authorization'], 'Bearer $REAL_JWT');
        },
        timeout: const Timeout(Duration(milliseconds: 20000)),
      );

      test(
        'extracted-claim usage: the claim sentinel alone swaps to the real claim value',
        () async {
          final sentinel = claimOf(await readFakeJwt());
          expect(sentinel, startsWith(SENTINEL_PREFIX));

          final proxyPort = SandboxManager.getProxyPort()!;
          final authToken = SandboxManager.getProxyAuthToken()!;
          lastHeaders.clear();
          final r = await curlViaProxy(
            proxyPort,
            'http://$HOST_A:$upstreamPort/',
            headers: ['Authorization: Bearer $sentinel'],
            proxyAuth: 'srt:$authToken',
          );
          expect(r.exit, 0);
          expect(lastHeaders.value?['authorization'], 'Bearer $REAL_CLAIM');
        },
        timeout: const Timeout(Duration(milliseconds: 20000)),
      );

      test(
        'a non-injectHost destination receives the fake token and sentinel unchanged',
        () async {
          final fakeJwt = await readFakeJwt();

          final proxyPort = SandboxManager.getProxyPort()!;
          final authToken = SandboxManager.getProxyAuthToken()!;
          lastHeaders.clear();
          var r = await curlViaProxy(
            proxyPort,
            'http://$HOST_B:$upstreamPort/',
            headers: ['Authorization: Bearer $fakeJwt'],
            proxyAuth: 'srt:$authToken',
          );
          expect(r.exit, 0);
          expect(lastHeaders.value?['authorization'], 'Bearer $fakeJwt');
          expect(
            lastHeaders.value?['authorization'],
            isNot(contains(REAL_CLAIM)),
          );

          lastHeaders.clear();
          r = await curlViaProxy(
            proxyPort,
            'http://$HOST_B:$upstreamPort/',
            headers: ['Authorization: Bearer ${claimOf(fakeJwt)}'],
            proxyAuth: 'srt:$authToken',
          );
          expect(r.exit, 0);
          expect(
            lastHeaders.value?['authorization'],
            'Bearer ${claimOf(fakeJwt)}',
          );
          expect(
            lastHeaders.value?['authorization'],
            isNot(contains(REAL_CLAIM)),
          );
        },
        timeout: const Timeout(Duration(milliseconds: 20000)),
      );
    },
  );
}

typedef CurlResult = ({int exit, int status, String body});

Future<CurlResult> curlViaProxy(
  int proxyPort,
  String url, {
  List<String>? headers,
  String? resolve,
  String? proxyAuth,
}) async {
  final auth = proxyAuth != null && proxyAuth.isNotEmpty ? '$proxyAuth@' : '';
  final args = [
    '-sS',
    '--proxy',
    'http://${auth}127.0.0.1:$proxyPort',
    // An empty list overrides NO_PROXY, which would send curl around
    // the proxy under test for 127.0.0.1.
    '--noproxy',
    '',
    '--max-time',
    '10',
    '-D',
    '-',
  ];
  if (url.startsWith('https://')) args.addAll(['--cacert', CA_CERT]);
  for (final h in headers ?? <String>[]) {
    args.addAll(['-H', h]);
  }
  if (resolve != null && resolve.isNotEmpty) {
    args.addAll(['--resolve', resolve]);
  }
  args.add(url);

  // Dart: dart:io's Process.start; its streams decode and end as Node's do.
  final child = await io.Process.start('curl', args);
  final outFuture = child.stdout.transform(utf8.decoder).join();
  final stderrFuture = child.stderr.transform(utf8.decoder).join();
  final out = await outFuture;
  await stderrFuture;
  final exit = await child.exitCode;

  final sep = out.lastIndexOf('\r\n\r\n');
  final headerPart = sep >= 0 ? out.substring(0, sep) : '';
  final body = sep >= 0 ? out.substring(sep + 4) : out;
  final blocks = headerPart.split(RegExp(r'\r\n\r\n'));
  final lastHdr = blocks.isNotEmpty ? blocks[blocks.length - 1] : '';
  final m = RegExp(r'HTTP/[\d.]+ (\d+)').firstMatch(lastHdr);
  final status = m != null ? int.parse(m.group(1)!) : 0;
  return (exit: exit, status: status, body: body);
}
