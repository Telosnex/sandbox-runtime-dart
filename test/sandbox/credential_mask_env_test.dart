// Ported from sandbox-runtime test/sandbox/credential-mask-env.test.ts @ 24eb39e.
// ignore_for_file: constant_identifier_names, non_constant_identifier_names, slash_for_doc_comments
import 'dart:async';

import 'package:sandbox_runtime/src/node/buffer.dart';
import 'package:sandbox_runtime/src/node/child_process.dart'
    show spawn, spawnSync;
import 'package:sandbox_runtime/src/node/console.dart' as console;
import 'package:sandbox_runtime/src/node/errno.dart' show NodeException;
import 'package:sandbox_runtime/src/node/http.dart' as http;
import 'package:sandbox_runtime/src/node/net.dart' show NodeAddress, NodeServer;
import 'package:sandbox_runtime/src/node/process.dart' as process;
import 'package:sandbox_runtime/src/sandbox/credential_mask_env.dart';
import 'package:sandbox_runtime/src/sandbox/credential_sentinel.dart';
import 'package:sandbox_runtime/src/sandbox/sandbox_config.dart';
import 'package:sandbox_runtime/src/sandbox/sandbox_manager.dart';
import 'package:test/test.dart';

import '../helpers/captured.dart';
import '../helpers/platform.dart';

/**
 * Unit tests for structured (extract) env-var masking. Platform-agnostic;
 * these touch only the sentinel registry — the host environment is passed
 * in explicitly so nothing here mutates process.env.
 */

const DB_PASSWORD = 's3cret-real-pw-0123456789';
const DB_URL = 'postgres://alice:$DB_PASSWORD@db.example.com:5432/mydb';
// Capture group 1 = the password span of a userinfo connection string.
const DB_EXTRACT = '://[^:]+:([^@]+)@';

/** Host matcher for unit tests: exact equality. */
bool eq(String h, String p) => h == p;

// Dart: `spyOn(console, 'warn').mockImplementation(() => {})` is a saved
// console.warn replaced by a recorder of its first arguments.
class _WarnSpy {
  _WarnSpy() : _saved = console.warn {
    console.warn = ([a, b, c, d]) {
      calls.add(a);
    };
  }
  final console.ConsoleMethod _saved;
  final calls = <Object?>[];
  void mockRestore() {
    console.warn = _saved;
  }
}

void main() {
  group('buildMaskedEnvVars', () {
    test('whole-value (no extract): fake value is exactly one sentinel', () {
      final reg = SentinelRegistry();
      final MaskedEnvBuildResult(
        :setEnvVars,
        :degradeToUnsetNames,
      ) = buildMaskedEnvVars(
        [CredentialEnvVarConfig(name: 'GH_TOKEN', mode: 'mask')],
        ['api.github.com'],
        reg,
        {'GH_TOKEN': 'ghp_real_secret'},
      );
      expect(degradeToUnsetNames, hasLength(0));
      final fake = setEnvVars['GH_TOKEN']!;
      expect(fake.startsWith(SENTINEL_PREFIX), isTrue);
      // The fake IS the sentinel — nothing else around it.
      expect(fake.length, SENTINEL_PREFIX.length + 36);
      expect(reg.lookupReal(fake), 'ghp_real_secret');
      expect(reg.size, 1);
    });

    test('DATABASE_URL: only the password span becomes a sentinel', () {
      final reg = SentinelRegistry();
      final MaskedEnvBuildResult(:setEnvVars) = buildMaskedEnvVars(
        [
          CredentialEnvVarConfig(
            name: 'DATABASE_URL',
            mode: 'mask',
            extract: DB_EXTRACT,
          ),
        ],
        ['db.example.com'],
        reg,
        {'DATABASE_URL': DB_URL},
      );
      final fake = setEnvVars['DATABASE_URL']!;
      // Scheme, user, host, port, and database survive byte-for-byte.
      expect(fake.startsWith('postgres://alice:'), isTrue);
      expect(fake.endsWith('@db.example.com:5432/mydb'), isTrue);
      // The password is gone; a sentinel sits in its place.
      expect(fake, isNot(contains(DB_PASSWORD)));
      final m = RegExp(r'://alice:(\S+)@').firstMatch(fake);
      expect(m![1]!.startsWith(SENTINEL_PREFIX), isTrue);
      expect(reg.lookupReal(m[1]!), DB_PASSWORD);
      expect(reg.size, 1);
    });

    test('multiple distinct captures get distinct sentinels', () {
      final reg = SentinelRegistry();
      final MaskedEnvBuildResult(:setEnvVars) = buildMaskedEnvVars(
        [
          CredentialEnvVarConfig(
            name: 'COMPOSITE',
            mode: 'mask',
            extract: '(?:secret|backup)=([^;]+)',
          ),
        ],
        ['h.example.com'],
        reg,
        {'COMPOSITE': 'id=abc;secret=tok-A;backup=tok-B'},
      );
      final fake = setEnvVars['COMPOSITE']!;
      expect(fake, contains('id=abc;'));
      expect(fake, isNot(contains('tok-A')));
      expect(fake, isNot(contains('tok-B')));
      final sentinels = RegExp(
        '$SENTINEL_PREFIX[0-9a-f-]+',
      ).allMatches(fake).map((m) => m[0]!).toList();
      expect(sentinels, hasLength(2));
      expect(sentinels[0], isNot(sentinels[1]));
      expect(reg.lookupReal(sentinels[0]), 'tok-A');
      expect(reg.lookupReal(sentinels[1]), 'tok-B');
      expect(reg.size, 2);
    });

    test('an extract sentinel only substitutes at the entry injectHosts', () {
      final reg = SentinelRegistry();
      final MaskedEnvBuildResult(:setEnvVars) = buildMaskedEnvVars(
        [
          CredentialEnvVarConfig(
            name: 'DATABASE_URL',
            mode: 'mask',
            extract: DB_EXTRACT,
            injectHosts: ['db.example.com'],
          ),
        ],
        ['db.example.com', 'evil.example.com'],
        reg,
        {'DATABASE_URL': DB_URL},
      );
      final sentinel = RegExp(
        r'://alice:(\S+)@',
      ).firstMatch(setEnvVars['DATABASE_URL']!)![1]!;

      final toDb = <String, Object?>{'authorization': 'Bearer $sentinel'};
      reg.substituteInHeaders(toDb, 'db.example.com', eq);
      expect(toDb['authorization'], 'Bearer $DB_PASSWORD');

      final toEvil = <String, Object?>{'authorization': 'Bearer $sentinel'};
      reg.substituteInHeaders(toEvil, 'evil.example.com', eq);
      expect(toEvil['authorization'], 'Bearer $sentinel');
    });

    test('absent injectHosts → defaults to allowedDomains', () {
      final reg = SentinelRegistry();
      final MaskedEnvBuildResult(:setEnvVars) = buildMaskedEnvVars(
        [
          CredentialEnvVarConfig(
            name: 'DATABASE_URL',
            mode: 'mask',
            extract: DB_EXTRACT,
          ),
        ],
        ['fallback.example.com'],
        reg,
        {'DATABASE_URL': DB_URL},
      );
      final sentinel = RegExp(
        r'://alice:(\S+)@',
      ).firstMatch(setEnvVars['DATABASE_URL']!)![1]!;
      final headers = <String, Object?>{'authorization': sentinel};
      reg.substituteInHeaders(headers, 'fallback.example.com', eq);
      expect(headers['authorization'], DB_PASSWORD);
    });

    test('a masked var that is unset in the environment is skipped', () {
      final reg = SentinelRegistry();
      final MaskedEnvBuildResult(
        :setEnvVars,
        :degradeToUnsetNames,
      ) = buildMaskedEnvVars(
        [
          CredentialEnvVarConfig(
            name: 'NEVER_SET',
            mode: 'mask',
            extract: DB_EXTRACT,
          ),
        ],
        [],
        reg,
        {},
      );
      expect(setEnvVars.keys, hasLength(0));
      expect(degradeToUnsetNames, hasLength(0));
      expect(reg.size, 0);
    });

    test('ignores deny-mode entries (the caller unsets them directly)', () {
      final reg = SentinelRegistry();
      final MaskedEnvBuildResult(
        :setEnvVars,
        :degradeToUnsetNames,
      ) = buildMaskedEnvVars(
        [CredentialEnvVarConfig(name: 'DATABASE_URL', mode: 'deny')],
        [],
        reg,
        {'DATABASE_URL': DB_URL},
      );
      expect(setEnvVars.keys, hasLength(0));
      expect(degradeToUnsetNames, hasLength(0));
      expect(reg.size, 0);
    });

    group('extract with no match (onExtractNoMatch)', () {
      const noMatch = CredentialEnvVarConfig(
        name: 'DATABASE_URL',
        mode: 'mask',
        extract: 'nope=(\\S+)',
      );
      // Dart: stands for `{ ...noMatch, onExtractNoMatch }`.
      CredentialEnvVarConfig noMatchWith(String onExtractNoMatch) =>
          CredentialEnvVarConfig(
            name: noMatch.name,
            mode: noMatch.mode,
            extract: noMatch.extract,
            onExtractNoMatch: onExtractNoMatch,
          );
      final env = {'DATABASE_URL': DB_URL};

      test('default → "warn": variable passes through, stderr warning', () {
        final warnSpy = _WarnSpy();
        final reg = SentinelRegistry();
        final MaskedEnvBuildResult(:setEnvVars, :degradeToUnsetNames) =
            buildMaskedEnvVars([noMatch], ['db.example.com'], reg, env);
        // Fail-open: no set, no unset — the entry is skipped entirely so
        // the variable is inherited with its real value.
        expect(setEnvVars.keys, hasLength(0));
        expect(degradeToUnsetNames, hasLength(0));
        expect(reg.size, 0);
        // A loud stderr warning surfaces the config error to the operator.
        expect(warnSpy.calls, hasLength(1));
        final msg = warnSpy.calls[0] as String;
        expect(msg, contains('UNPROTECTED'));
        expect(msg, contains('DATABASE_URL'));
        expect(msg, contains('nope=(\\S+)'));
        // The warning names the variable but never leaks its value.
        expect(msg, isNot(contains(DB_PASSWORD)));
        warnSpy.mockRestore();
      });

      test('explicit "warn" matches the default', () {
        final warnSpy = _WarnSpy();
        final reg = SentinelRegistry();
        final MaskedEnvBuildResult(:setEnvVars, :degradeToUnsetNames) =
            buildMaskedEnvVars([noMatchWith('warn')], [], reg, env);
        expect(setEnvVars.keys, hasLength(0));
        expect(degradeToUnsetNames, hasLength(0));
        expect(warnSpy.calls, hasLength(1));
        warnSpy.mockRestore();
      });

      test('"deny": entry degrades to unset (fail-closed)', () {
        final warnSpy = _WarnSpy();
        final reg = SentinelRegistry();
        final MaskedEnvBuildResult(
          :setEnvVars,
          :degradeToUnsetNames,
        ) = buildMaskedEnvVars(
          [noMatchWith('deny')],
          ['db.example.com'],
          reg,
          env,
        );
        expect(setEnvVars.keys, hasLength(0));
        expect(degradeToUnsetNames, ['DATABASE_URL']);
        expect(reg.size, 0);
        // No stderr warning — deny is a configured outcome, not a surprise.
        expect(warnSpy.calls, isEmpty);
        warnSpy.mockRestore();
      });

      test('"error": throws with a clear message', () {
        final reg = SentinelRegistry();
        expect(
          () => buildMaskedEnvVars([noMatchWith('error')], [], reg, env),
          throwsA(
            isA<NodeException>().having(
              (e) => e.message,
              'message',
              matches(RegExp(r'matched nothing.*onExtractNoMatch: "error"')),
            ),
          ),
        );
      });

      test(
        'onExtractNoMatch is per-entry: one "deny" does not affect a sibling "warn"',
        () {
          final warnSpy = _WarnSpy();
          final reg = SentinelRegistry();
          final MaskedEnvBuildResult(
            :setEnvVars,
            :degradeToUnsetNames,
          ) = buildMaskedEnvVars(
            [
              noMatchWith('deny'),
              CredentialEnvVarConfig(
                name: 'OTHER',
                mode: 'mask',
                extract: 'nope=(\\S+)',
              ),
            ],
            [],
            reg,
            {...env, 'OTHER': 'k=v'},
          );
          expect(setEnvVars.keys, hasLength(0));
          expect(degradeToUnsetNames, ['DATABASE_URL']);
          expect(warnSpy.calls, hasLength(1));
          expect(warnSpy.calls[0] as String, contains('OTHER'));
          warnSpy.mockRestore();
        },
      );
    });
  });

  /**
   * SandboxManager-level structured env masking on Linux: the sandboxed
   * process sees the structure-preserved fake in its environment; the real
   * credential span never appears in the wrapped command string.
   */
  group(
    'structured env masking on Linux (bwrap)',
    skip: isLinux ? null : 'Linux only',
    () {
      const VAR = 'SRT_TEST_DB_URL';

      setUpAll(() async {
        process.env[VAR] = DB_URL;
        await SandboxManager.reset();
        await SandboxManager.initialize(
          SandboxRuntimeConfig(
            network: NetworkConfig(
              allowedDomains: ['localhost'],
              deniedDomains: [],
            ),
            filesystem: FilesystemConfig(
              denyRead: [],
              allowWrite: [FilesystemPathSpelling('/tmp')],
              denyWrite: [],
            ),
            credentials: CredentialsConfig(
              envVars: [
                CredentialEnvVarConfig(
                  name: VAR,
                  mode: 'mask',
                  extract: DB_EXTRACT,
                ),
              ],
              allowPlaintextInject: true,
            ),
          ),
        );
      });

      tearDownAll(() async {
        await SandboxManager.reset();
        process.env.remove(VAR);
      });

      test(
        'printenv shows the structure-preserved fake, not the password',
        () async {
          final wrapped = await SandboxManager.wrapWithSandbox('printenv $VAR');
          expect(wrapped, isNot(contains(DB_PASSWORD)));
          final result = spawnSync(wrapped, [], {
            'shell': true,
            'encoding': 'utf8',
            'timeout': 10000,
            'env': {...process.env, VAR: DB_URL},
          });
          expect(result.status, 0);
          final seen = (result.stdout as String).trim();
          // Scheme, user, host, port, and database survive byte-for-byte.
          expect(seen.startsWith('postgres://alice:'), isTrue);
          expect(seen.endsWith('@db.example.com:5432/mydb'), isTrue);
          // The password is gone; a sentinel sits in its place.
          expect(seen, isNot(contains(DB_PASSWORD)));
          final m = RegExp(r'://alice:(\S+)@').firstMatch(seen);
          expect(m![1]!.startsWith(SENTINEL_PREFIX), isTrue);
          // The host-side registry maps that sentinel back to the password.
          expect(
            SandboxManager.getSentinelRegistry().lookupReal(m[1]!),
            DB_PASSWORD,
          );
        },
      );

      test(
        'whole-value masking (no extract) is unchanged: fake is one bare sentinel',
        () async {
          // Regression guard for the pre-extract behaviour: an entry without
          // extract must still swap the ENTIRE value for a single sentinel.
          await SandboxManager.reset();
          process.env[VAR] = DB_URL;
          await SandboxManager.initialize(
            SandboxRuntimeConfig(
              network: NetworkConfig(
                allowedDomains: ['localhost'],
                deniedDomains: [],
              ),
              filesystem: FilesystemConfig(
                denyRead: [],
                allowWrite: [FilesystemPathSpelling('/tmp')],
                denyWrite: [],
              ),
              credentials: CredentialsConfig(
                envVars: [CredentialEnvVarConfig(name: VAR, mode: 'mask')],
                allowPlaintextInject: true,
              ),
            ),
          );
          final wrapped = await SandboxManager.wrapWithSandbox('printenv $VAR');
          expect(
            wrapped,
            matches(RegExp('--setenv $VAR $SENTINEL_PREFIX[0-9a-f-]{36}')),
          );
          final result = spawnSync(wrapped, [], {
            'shell': true,
            'encoding': 'utf8',
            'timeout': 10000,
            'env': {...process.env, VAR: DB_URL},
          });
          expect(result.status, 0);
          final seen = (result.stdout as String).trim();
          expect(seen.startsWith(SENTINEL_PREFIX), isTrue);
          // DB_URL is longer than the 47-byte base sentinel, so the mint pads the
          // sentinel to the real value's byte length (length-matched sentinels
          // keep Content-Length invariant under body substitution).
          expect(seen.length, Buffer.byteLength(DB_URL));
          expect(SandboxManager.getSentinelRegistry().lookupReal(seen), DB_URL);

          // Restore the suite-level (extract) config for any following tests.
          await SandboxManager.reset();
          process.env[VAR] = DB_URL;
          await SandboxManager.initialize(
            SandboxRuntimeConfig(
              network: NetworkConfig(
                allowedDomains: ['localhost'],
                deniedDomains: [],
              ),
              filesystem: FilesystemConfig(
                denyRead: [],
                allowWrite: [FilesystemPathSpelling('/tmp')],
                denyWrite: [],
              ),
              credentials: CredentialsConfig(
                envVars: [
                  CredentialEnvVarConfig(
                    name: VAR,
                    mode: 'mask',
                    extract: DB_EXTRACT,
                  ),
                ],
                allowPlaintextInject: true,
              ),
            ),
          );
        },
      );
    },
  );

  /**
   * Linux integration: an env `extract` pattern that matches nothing follows
   * the entry's `onExtractNoMatch` — default `"warn"` passes the variable
   * through unmasked with a stderr warning; `"deny"` unsets it; `"error"`
   * rejects at wrap time.
   */
  group(
    'env extract no-match onExtractNoMatch on Linux',
    skip: isLinux ? null : 'Linux only',
    () {
      const VAR = 'SRT_TEST_NOMATCH_URL';
      const SECRET = 'nomatch-real-secret-0123456789';

      Future<void> init([String? onExtractNoMatch]) async {
        await SandboxManager.reset();
        process.env[VAR] = SECRET;
        await SandboxManager.initialize(
          SandboxRuntimeConfig(
            network: NetworkConfig(
              allowedDomains: ['localhost'],
              deniedDomains: [],
            ),
            filesystem: FilesystemConfig(
              denyRead: [],
              allowWrite: [FilesystemPathSpelling('/tmp')],
              denyWrite: [],
            ),
            credentials: CredentialsConfig(
              envVars: [
                CredentialEnvVarConfig(
                  name: VAR,
                  mode: 'mask',
                  extract: 'will_not_match_(\\S+)',
                  onExtractNoMatch: onExtractNoMatch,
                ),
              ],
              allowPlaintextInject: true,
            ),
          ),
        );
      }

      tearDownAll(() async {
        await SandboxManager.reset();
        process.env.remove(VAR);
      });

      test(
        'default ("warn"): variable passes through unmasked, stderr warning at wrap',
        () async {
          await init();
          final warnSpy = _WarnSpy();
          final wrapped = await SandboxManager.wrapWithSandbox('printenv $VAR');
          // A loud stderr warning surfaces the config error at wrap time.
          expect(warnSpy.calls, isNotEmpty);
          expect(warnSpy.calls[0] as String, contains('UNPROTECTED'));
          warnSpy.mockRestore();
          // Neither --setenv nor --unsetenv is emitted for the variable — the
          // entry is skipped entirely.
          expect(wrapped, isNot(contains('--setenv $VAR')));
          expect(wrapped, isNot(contains('--unsetenv $VAR')));
          final result = spawnSync(wrapped, [], {
            'shell': true,
            'encoding': 'utf8',
            'timeout': 10000,
            'env': {...process.env, VAR: SECRET},
          });
          // printenv succeeds and returns the real value: fail-open means the
          // variable is inherited as-is.
          expect(result.status, 0);
          expect((result.stdout as String).trim(), SECRET);
        },
      );

      test('"deny": variable unset inside the sandbox (fail-closed)', () async {
        await init('deny');
        final wrapped = await SandboxManager.wrapWithSandbox('printenv $VAR');
        // The real value never appears in the wrapped command.
        expect(wrapped, isNot(contains(SECRET)));
        expect(wrapped, contains('--unsetenv $VAR'));
        final result = spawnSync(wrapped, [], {
          'shell': true,
          'encoding': 'utf8',
          'timeout': 10000,
          'env': {...process.env, VAR: SECRET},
        });
        // printenv fails: the variable does not exist inside the sandbox.
        expect(result.status, isNot(0));
        expect(result.stdout as String, isNot(contains(SECRET)));
      });

      test('"error": wrapWithSandbox rejects', () async {
        await init('error');
        Object? thrown;
        try {
          await SandboxManager.wrapWithSandbox('printenv $VAR');
        } catch (e) {
          thrown = e;
        }
        expect(thrown, isA<Error>());
        expect(
          (thrown as NodeException).message,
          matches(RegExp(r'matched nothing.*onExtractNoMatch: "error"')),
        );
      });
    },
  );

  /**
   * End-to-end structured env masking: DATABASE_URL is masked with extract;
   * inside the sandbox a tool parses the password field out of the preserved
   * connection-string structure and sends it as a header; the manager proxy
   * swaps the sentinel to the real password at the injectHost only. Reuses
   * the e2e harness pattern from credential-mask.test.ts (plain HTTP
   * upstream + allowPlaintextInject + the manager's own proxy port).
   */
  group(
    'end-to-end structured env masking via SandboxManager',
    skip: isLinux ? null : 'Linux only',
    () {
      const VAR = 'SRT_TEST_E2E_DB_URL';
      const HOST_A = 'localhost';
      const HOST_B = 'host-b.localhost';

      late NodeServer upstream;
      late int upstreamPort;
      final lastHeaders = captured<http.IncomingHttpHeaders>();
      final lastBody = captured<String>();

      setUpAll(() async {
        upstream = http.createServer((
          http.IncomingMessage req,
          http.ServerResponse res,
        ) {
          lastHeaders.value = req.headers;
          var body = '';
          req.on(
            'data',
            (Object? c) => body += String.fromCharCodes(c as List<int>),
          );
          req.on('end', () {
            lastBody.value = body;
            res.writeHead(200);
            res.end('ok');
          });
        });
        final listening = Completer<void>();
        upstream.listen(0, '127.0.0.1', () => listening.complete());
        await listening.future;
        upstreamPort = (upstream.address() as NodeAddress).port;

        process.env[VAR] = DB_URL;
        await SandboxManager.reset();
        await SandboxManager.initialize(
          SandboxRuntimeConfig(
            network: NetworkConfig(
              allowedDomains: [HOST_A, HOST_B],
              deniedDomains: [],
            ),
            filesystem: FilesystemConfig(
              denyRead: [],
              allowWrite: [FilesystemPathSpelling('/tmp')],
              denyWrite: [],
            ),
            credentials: CredentialsConfig(
              envVars: [
                CredentialEnvVarConfig(
                  name: VAR,
                  mode: 'mask',
                  extract: DB_EXTRACT,
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
        process.env.remove(VAR);
        final closed = Completer<void>();
        upstream.close(() => closed.complete());
        await closed.future;
      });

      dynamic runInSandbox(String wrappedCommand) {
        return spawnSync(wrappedCommand, [], {
          'shell': true,
          'encoding': 'utf8',
          'timeout': 10000,
          'env': {...process.env, VAR: DB_URL},
        });
      }

      // Async spawn — spawnSync would block the event loop and the
      // in-process proxy/upstream couldn't accept the connection.
      Future<int> curlViaManagerProxy(
        String url,
        String bearer, [
        String? body,
      ]) async {
        final proxyPort = SandboxManager.getProxyPort()!;
        final authToken = SandboxManager.getProxyAuthToken()!;
        final args = [
          '-sS',
          '--max-time',
          '10',
          '--proxy',
          'http://srt:$authToken@127.0.0.1:$proxyPort',
          // An empty list overrides NO_PROXY, which would send curl around
          // the proxy under test for 127.0.0.1.
          '--noproxy',
          '',
          '-H',
          'Authorization: Bearer $bearer',
        ];
        if (body != null) args.addAll(['--data-binary', body]);
        args.add(url);
        final child = spawn('curl', args);
        child.stdout!.listen((_) {});
        child.stderr!.listen((_) {});
        final r = Completer<int>();
        child.on('close', (int? code) => r.complete(code ?? 1));
        return r.future;
      }

      test(
        'parse sentinel from the fake URL → injectHost gets the real password',
        () async {
          // bwrap leg: extract the password field from the masked connection
          // string inside the sandbox — the URL parses, and the field value is
          // the sentinel.
          final wrapped = await SandboxManager.wrapWithSandbox(
            "sh -c \"printenv $VAR | sed -E 's|.*://[^:]+:([^@]+)@.*|\\\\1|'\"",
          );
          expect(wrapped, isNot(contains(DB_PASSWORD)));
          final result = runInSandbox(wrapped);
          expect(result.status, 0);
          final sentinel = (result.stdout as String).trim();
          expect(sentinel.startsWith(SENTINEL_PREFIX), isTrue);
          expect(sentinel, isNot(contains(DB_PASSWORD)));

          // Proxy leg: the sentinel reaches HOST_A as the real password.
          lastHeaders.clear();
          final exit = await curlViaManagerProxy(
            'http://$HOST_A:$upstreamPort/',
            sentinel,
          );
          expect(exit, 0);
          expect(lastHeaders.value?['authorization'], 'Bearer $DB_PASSWORD');
        },
        timeout: const Timeout(Duration(milliseconds: 20000)),
      );

      test(
        'a sentinel in a POST body reaches the injectHost as the real password',
        () async {
          final wrapped = await SandboxManager.wrapWithSandbox(
            "sh -c \"printenv $VAR | sed -E 's|.*://[^:]+:([^@]+)@.*|\\\\1|'\"",
          );
          final sentinel = (runInSandbox(wrapped).stdout as String).trim();
          expect(sentinel.startsWith(SENTINEL_PREFIX), isTrue);

          // Body leg: the tool POSTs the credential in a JSON payload instead
          // of a header; the manager proxy substitutes in the body stream.
          lastHeaders.clear();
          lastBody.clear();
          final exit = await curlViaManagerProxy(
            'http://$HOST_A:$upstreamPort/',
            sentinel,
            '{"password":"$sentinel"}',
          );
          expect(exit, 0);
          expect(lastBody.value, '{"password":"$DB_PASSWORD"}');
          expect(lastHeaders.value?['authorization'], 'Bearer $DB_PASSWORD');
        },
        timeout: const Timeout(Duration(milliseconds: 20000)),
      );

      test(
        'a non-injectHost destination receives the sentinel unchanged',
        () async {
          final wrapped = await SandboxManager.wrapWithSandbox(
            "sh -c \"printenv $VAR | sed -E 's|.*://[^:]+:([^@]+)@.*|\\\\1|'\"",
          );
          final sentinel = (runInSandbox(wrapped).stdout as String).trim();

          // HOST_B is allowlisted but NOT in this entry's injectHosts. The
          // proxy resolves it to loopback (a `.localhost` name) and forwards
          // the sentinel as-is — fails closed.
          lastHeaders.clear();
          final exit = await curlViaManagerProxy(
            'http://$HOST_B:$upstreamPort/',
            sentinel,
          );
          expect(exit, 0);
          expect(lastHeaders.value?['authorization'], 'Bearer $sentinel');
          expect(
            lastHeaders.value?['authorization'] as String,
            isNot(contains(DB_PASSWORD)),
          );
        },
        timeout: const Timeout(Duration(milliseconds: 20000)),
      );
    },
  );
}
