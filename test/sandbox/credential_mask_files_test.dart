// Ported from sandbox-runtime test/sandbox/credential-mask-files.test.ts @ 24eb39e.
// ignore_for_file: constant_identifier_names, non_constant_identifier_names
// ignore_for_file: slash_for_doc_comments

import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:path/path.dart' show join;
import 'package:sandbox_runtime/src/node/buffer.dart';
import 'package:sandbox_runtime/src/node/child_process.dart'
    show SpawnSyncResult, spawn, spawnSync;
import 'package:sandbox_runtime/src/node/console.dart' as console;
import 'package:sandbox_runtime/src/node/errno.dart' show NodeException;
import 'package:sandbox_runtime/src/node/fs.dart'
    show
        existsSync,
        lstatSync,
        mkdirSync,
        readdirSync,
        readFileSync,
        realpathSync,
        rmSync,
        symlinkSync,
        writeFileSync;
import 'package:sandbox_runtime/src/node/http.dart' as http;
import 'package:sandbox_runtime/src/node/net.dart' show NodeAddress, NodeServer;
import 'package:sandbox_runtime/src/node/os.dart' show tmpdir;
import 'package:sandbox_runtime/src/sandbox/credential_decode.dart';
import 'package:sandbox_runtime/src/sandbox/credential_extract.dart';
import 'package:sandbox_runtime/src/sandbox/credential_mask_files.dart';
import 'package:sandbox_runtime/src/sandbox/credential_sentinel.dart';
import 'package:sandbox_runtime/src/sandbox/macos_sandbox_utils.dart';
import 'package:sandbox_runtime/src/sandbox/sandbox_config.dart';
import 'package:sandbox_runtime/src/sandbox/sandbox_schemas.dart'
    show FsWriteRestrictionConfig;
import 'package:sandbox_runtime/src/sandbox/sandbox_manager.dart';
import 'package:test/test.dart';

import '../helpers/captured.dart';
import '../helpers/platform.dart';

/**
 * Unit tests for the fake-file store and bind builder. Platform-agnostic;
 * these touch only the host filesystem and the sentinel registry.
 */

final FIXTURE_DIR = join(
  tmpdir(),
  'srt-credmask-fixture-${DateTime.now().millisecondsSinceEpoch}',
);
final TOKEN_FILE = join(FIXTURE_DIR, 'gh-token');
const TOKEN_CONTENT = 'ghp_realsecret_abcdef0123456789';
final SUBDIR = join(FIXTURE_DIR, 'aws-dir');

final HOSTS_YML = join(FIXTURE_DIR, 'hosts.yml');
const HOSTS_TOKEN = 'gho_realsecret_zyx9876543210';
const HOSTS_CONTENT =
    'github.com:\n'
    '    user: alice\n'
    '    oauth_token: $HOSTS_TOKEN\n'
    '    git_protocol: https\n';

void main() {
  setUpAll(() {
    mkdirSync(SUBDIR, {'recursive': true});
    writeFileSync(TOKEN_FILE, TOKEN_CONTENT);
    writeFileSync(HOSTS_YML, HOSTS_CONTENT);
  });

  tearDownAll(() {
    rmSync(FIXTURE_DIR, {'recursive': true, 'force': true});
  });

  group('MaskedFileStore', () {
    test('lazily creates a temp dir under os.tmpdir()', () {
      final store = MaskedFileStore();
      expect(store.dirPath, isNull);
      final fake = store.write('k', 'sentinel');
      expect(store.dirPath, isNotNull);
      expect(store.dirPath!.startsWith(tmpdir()), isTrue);
      expect(store.dirPath!, contains(MASKED_FILE_STORE_PREFIX));
      expect((readFileSync(fake, 'utf8') as String), 'sentinel');
      store.dispose();
    });

    test('write does not follow a symlink planted at the fake path', () {
      // Cross-invocation attack: if a prior sandbox run could write the
      // store dir, it could leave `ln -s <victim> 0.fake` behind and the
      // next host-side write() would clobber <victim>. write() must unlink
      // first so the sentinel lands in a fresh regular file.
      final store = MaskedFileStore();
      final fake = store.write('k', 'first');
      final victim = join(FIXTURE_DIR, 'symlink-victim');
      writeFileSync(victim, 'victim-bytes');
      rmSync(fake);
      symlinkSync(victim, fake);

      store.write('k', 'second');

      expect((readFileSync(victim, 'utf8') as String), 'victim-bytes');
      expect(lstatSync(fake).isSymbolicLink(), isFalse);
      expect((readFileSync(fake, 'utf8') as String), 'second');
      store.dispose();
    });

    test(
      'write is idempotent on key — same fake path, content overwritten',
      () {
        final store = MaskedFileStore();
        final a = store.write('file:/x', 'first');
        final b = store.write('file:/x', 'second');
        expect(b, a);
        expect((readFileSync(a, 'utf8') as String), 'second');
        expect(readdirSync(store.dirPath!), hasLength(1));
        store.dispose();
      },
    );

    test('dispose removes the temp dir and is idempotent', () {
      final store = MaskedFileStore();
      store.write('k', 'x');
      final dir = store.dirPath!;
      expect(existsSync(dir), isTrue);
      store.dispose();
      expect(existsSync(dir), isFalse);
      expect(store.dirPath, isNull);
      store.dispose(); // no-op, no throw
    });
  });

  group('extractAndSubstitute', () {
    // Deterministic sentinel callback for unit tests: <S0>, <S1>, …
    final S = (String _, int i) => '<S$i>';

    test('single match: capture replaced by sentinel, rest preserved', () {
      final content = 'github.com:\n  oauth_token: ghp_real\n  user: alice\n';
      final out = extractAndSubstitute(content, 'oauth_token:\\s*(\\S+)', S);
      expect(out, isNot(isNull));
      expect(out!.captures, ['ghp_real']);
      expect(
        out.fakeContent,
        'github.com:\n  oauth_token: <S0>\n  user: alice\n',
      );
      expect(out.fakeContent, isNot(contains('ghp_real')));
    });

    test('multiple distinct matches each get their own sentinel index', () {
      final content =
          'machine a.example.com password tok-A\n' +
          'machine b.example.com password tok-B\n';
      final out = extractAndSubstitute(content, 'password\\s+(\\S+)', S)!;
      expect(out.captures, ['tok-A', 'tok-B']);
      expect(
        out.fakeContent,
        'machine a.example.com password <S0>\n' +
            'machine b.example.com password <S1>\n',
      );
    });

    test('duplicate captures dedupe to one sentinel index', () {
      final content = 'password tok-X\npassword tok-X\npassword tok-Y\n';
      final out = extractAndSubstitute(content, 'password (\\S+)', S)!;
      expect(out.captures, ['tok-X', 'tok-Y']);
      expect(out.fakeContent, 'password <S0>\npassword <S0>\npassword <S1>\n');
    });

    test('returns null when the pattern matches nothing', () {
      expect(
        extractAndSubstitute('no creds here', 'password (\\S+)', S),
        isNull,
      );
    });

    test('throws when a match leaves group 1 undefined', () {
      // Optional group that does not participate — accepting this would
      // mask nothing for that occurrence, so the helper refuses.
      expect(
        () => extractAndSubstitute('token: \n', 'token: (\\S+)?', S),
        throwsA(anything),
      );
    });

    test(
      'only the regex-matched span is replaced; coincidental occurrences elsewhere are left intact',
      () {
        // The captured value `abc123` also appears in a comment line that the
        // regex does not match. Offset-based replacement touches only group 1
        // of each match, so the comment is preserved byte-for-byte. The old
        // value-based pass would have rewritten both.
        final content =
            'oauth_token: abc123\n' +
            '# note: the token abc123 is stored above\n';
        final out = extractAndSubstitute(content, 'oauth_token:\\s*(\\S+)', S)!;
        expect(out.captures, ['abc123']);
        expect(
          out.fakeContent,
          'oauth_token: <S0>\n' + '# note: the token abc123 is stored above\n',
        );
      },
    );

    test(
      'a capture that is a substring of another does not corrupt the longer one',
      () {
        // tok is a prefix of tok-long; offset-based replacement touches only
        // each match's own group-1 span, so neither capture corrupts the other.
        final content = 'a=tok-long b=tok';
        final out = extractAndSubstitute(content, '[ab]=(\\S+)', S)!;
        expect(out.captures, ['tok-long', 'tok']);
        expect(out.fakeContent, 'a=<S0> b=<S1>');
      },
    );

    test(
      'overlapping pattern matches are handled by the regex engine, not us',
      () {
        // matchAll with /g does not return overlapping matches, so the
        // helper sees only the engine's non-overlapping set. This test pins
        // that assumption: 'aaa' against /(aa)/g matches once at index 0.
        final out = extractAndSubstitute('aaa', '(aa)', S)!;
        expect(out.captures, ['aa']);
        expect(out.fakeContent, '<S0>a');
      },
    );

    test('empty captures are skipped, not turned into sentinels', () {
      // (\S*) can capture the empty string at end-of-line; a zero-width
      // span has nothing to mask, so the helper leaves it as-is.
      final out = extractAndSubstitute('k=v\nk=\n', 'k=(\\S*)', S)!;
      expect(out.captures, ['v']);
      expect(out.fakeContent, 'k=<S0>\nk=\n');
    });

    test('callback receives the captured value and its dedupe index', () {
      final calls = <(String, int)>[];
      extractAndSubstitute('k=A k=B k=A', 'k=(\\S+)', (String cap, int i) {
        calls.add((cap, i));
        return '_';
      });
      expect(calls, [('A', 0), ('B', 1), ('A', 0)]);
    });

    group('maskDuplicates', () {
      test(
        'a verbatim duplicate outside the match is also masked when true',
        () {
          final content =
              'oauth_token: ghp_supersecret123\n' +
              '# backup copy: ghp_supersecret123\n';
          final out = extractAndSubstitute(
            content,
            'oauth_token:\\s*(\\S+)',
            S,
            maskDuplicates: true,
          )!;
          expect(out.captures, ['ghp_supersecret123']);
          expect(out.fakeContent, 'oauth_token: <S0>\n# backup copy: <S0>\n');
          expect(out.fakeContent, isNot(contains('ghp_supersecret123')));
        },
      );

      test('explicit false keeps the offset-only behaviour', () {
        final content =
            'oauth_token: ghp_supersecret123\n' +
            '# backup copy: ghp_supersecret123\n';
        final out = extractAndSubstitute(
          content,
          'oauth_token:\\s*(\\S+)',
          S,
          maskDuplicates: false,
        )!;
        expect(
          out.fakeContent,
          'oauth_token: <S0>\n# backup copy: ghp_supersecret123\n',
        );
      });

      test(
        'inserted sentinels survive when the capture is a substring of the sentinel literal',
        () {
          // The capture `value` is a substring of the sentinel `fake_value_0`.
          // A naive post-pass split/join over the substituted output would
          // re-match inside the sentinels it just inserted and mangle them;
          // spans are computed against the original content instead.
          final content = 'secret: value\n# repeated: value\n';
          final out = extractAndSubstitute(
            content,
            'secret:\\s*(\\S+)',
            (_, _) => 'fake_value_0',
            maskDuplicates: true,
          )!;
          expect(
            out.fakeContent,
            'secret: fake_value_0\n# repeated: fake_value_0\n',
          );
        },
      );

      test(
        'a short capture also replaces coincidental substrings (documented collateral)',
        () {
          // The verbatim scan is raw substring matching — `abc` inside the
          // unrelated word `xabcy` is replaced too. This pins the documented
          // semantics: the option is for long, high-entropy secrets.
          final content = 'token: abc\nword: xabcy\n';
          final out = extractAndSubstitute(
            content,
            'token:\\s*(\\S+)',
            S,
            maskDuplicates: true,
          )!;
          expect(out.fakeContent, 'token: <S0>\nword: x<S0>y\n');
        },
      );

      test(
        'a capture that is a substring of another cannot claim part of the longer one',
        () {
          // tok is a substring of tok-long; the verbatim pass runs
          // longest-capture-first, so the duplicated tok-long in the comment
          // is claimed whole by <S0> rather than partially by <S1>.
          final content = 'a=tok-long b=tok\n# dup: tok-long and tok\n';
          final out = extractAndSubstitute(
            content,
            '[ab]=(\\S+)',
            S,
            maskDuplicates: true,
          )!;
          expect(out.captures, ['tok-long', 'tok']);
          expect(out.fakeContent, 'a=<S0> b=<S1>\n# dup: <S0> and <S1>\n');
        },
      );

      test('the duplicate pass does not re-invoke the sentinel callback', () {
        final calls = <(String, int)>[];
        extractAndSubstitute('k=A\n# A again: A\n', 'k=(\\S+)', (
          String cap,
          int i,
        ) {
          calls.add((cap, i));
          return '<S${i}>';
        }, maskDuplicates: true);
        expect(calls, [('A', 0)]);
      });

      test(
        'a declined capture (callback returns it unchanged) is not duplicate-scanned',
        () {
          // The decode-verification gate declines a candidate by returning the
          // capture itself. Its duplicates must stay unmasked, and its spans
          // must not block another capture's verbatim occurrences.
          final content = 'k=good k=bad\n# dup: good and bad\n';
          final out = extractAndSubstitute(
            content,
            'k=(\\S+)',
            (String cap, int i) => (cap == 'bad' ? cap : '<S${i}>'),
            maskDuplicates: true,
          )!;
          expect(out.fakeContent, 'k=<S0> k=bad\n# dup: <S0> and bad\n');
        },
      );
    });
  });

  group('buildMaskedFileBinds', () {
    test('registers a sentinel keyed on file path and writes it to a fake', () {
      final reg = SentinelRegistry();
      final store = MaskedFileStore();
      final MaskedFileBuildResult(:binds) = buildMaskedFileBinds(
        [CredentialFileConfig(path: TOKEN_FILE, mode: 'mask')],
        ['api.github.com'],
        reg,
        store,
      );
      expect(binds, hasLength(1));
      expect(binds[0].realPath, realpathSync(TOKEN_FILE));
      final fakeContent = (readFileSync(binds[0].fakePath, 'utf8') as String);
      expect(fakeContent.startsWith(SENTINEL_PREFIX), isTrue);
      // The fake holds the sentinel, never the real bytes.
      expect(fakeContent, isNot(contains(TOKEN_CONTENT)));
      // The registry maps that sentinel back to the real file content.
      expect(reg.lookupReal(fakeContent), TOKEN_CONTENT);
      store.dispose();
    });

    test('a file sentinel only substitutes at its own injectHosts', () {
      final reg = SentinelRegistry();
      final store = MaskedFileStore();
      final MaskedFileBuildResult(:binds) = buildMaskedFileBinds(
        [
          CredentialFileConfig(
            path: TOKEN_FILE,
            mode: 'mask',
            injectHosts: ['api.github.com'],
          ),
        ],
        ['api.github.com', 'evil.example.com'],
        reg,
        store,
      );
      final sentinel = (readFileSync(binds[0].fakePath, 'utf8') as String);
      final eq = (String h, String p) => h == p;

      final toGh = {'authorization': 'Bearer ${sentinel}'};
      reg.substituteInHeaders(toGh, 'api.github.com', eq);
      expect(toGh['authorization'], 'Bearer ${TOKEN_CONTENT}');

      final toEvil = {'authorization': 'Bearer ${sentinel}'};
      reg.substituteInHeaders(toEvil, 'evil.example.com', eq);
      expect(toEvil['authorization'], 'Bearer ${sentinel}');
      store.dispose();
    });

    test('absent injectHosts → defaults to allowedDomains', () {
      final reg = SentinelRegistry();
      final store = MaskedFileStore();
      final MaskedFileBuildResult(:binds) = buildMaskedFileBinds(
        [CredentialFileConfig(path: TOKEN_FILE, mode: 'mask')],
        ['fallback.example.com'],
        reg,
        store,
      );
      final sentinel = (readFileSync(binds[0].fakePath, 'utf8') as String);
      final eq = (String h, String p) => h == p;
      final headers = {'authorization': sentinel};
      reg.substituteInHeaders(headers, 'fallback.example.com', eq);
      expect(headers['authorization']!, TOKEN_CONTENT);
      store.dispose();
    });

    test('skips a masked file that does not exist on the host', () {
      final reg = SentinelRegistry();
      final store = MaskedFileStore();
      final MaskedFileBuildResult(
        :binds,
        :degradeToDenyPaths,
      ) = buildMaskedFileBinds(
        [
          CredentialFileConfig(
            path: join(FIXTURE_DIR, 'no-such-file'),
            mode: 'mask',
          ),
        ],
        [],
        reg,
        store,
      );
      expect(binds, hasLength(0));
      expect(degradeToDenyPaths, hasLength(0));
      expect(reg.size, 0);
      // No fake was written → store dir was never created.
      expect(store.dirPath, isNull);
      store.dispose();
    });

    test('skips a masked entry that resolves to a directory', () {
      final reg = SentinelRegistry();
      final store = MaskedFileStore();
      final MaskedFileBuildResult(:binds) = buildMaskedFileBinds(
        [CredentialFileConfig(path: SUBDIR, mode: 'mask')],
        [],
        reg,
        store,
      );
      expect(binds, hasLength(0));
      expect(reg.size, 0);
      store.dispose();
    });

    test('skips a masked file with non-UTF-8 content', () {
      // 0xFF is never valid in UTF-8. A utf8 read would silently replace it
      // with U+FFFD and the proxy would inject corrupted bytes; we skip
      // instead so the misconfiguration surfaces.
      final binFile = join(FIXTURE_DIR, 'binary-cred');
      writeFileSync(binFile, Buffer.from([0x67, 0x68, 0x70, 0x5f, 0xff, 0xfe]));
      final reg = SentinelRegistry();
      final store = MaskedFileStore();
      final MaskedFileBuildResult(
        :binds,
        :degradeToDenyPaths,
      ) = buildMaskedFileBinds(
        [CredentialFileConfig(path: binFile, mode: 'mask')],
        [],
        reg,
        store,
      );
      expect(binds, hasLength(0));
      expect(degradeToDenyPaths, hasLength(0));
      expect(reg.size, 0);
      store.dispose();
    });

    test('ignores deny-mode entries', () {
      final reg = SentinelRegistry();
      final store = MaskedFileStore();
      final MaskedFileBuildResult(:binds) = buildMaskedFileBinds(
        [CredentialFileConfig(path: TOKEN_FILE, mode: 'deny')],
        [],
        reg,
        store,
      );
      expect(binds, hasLength(0));
      store.dispose();
    });

    test('extract: fake preserves structure with sentinel substituted in', () {
      final reg = SentinelRegistry();
      final store = MaskedFileStore();
      final MaskedFileBuildResult(
        :binds,
        :degradeToDenyPaths,
      ) = buildMaskedFileBinds(
        [
          CredentialFileConfig(
            path: HOSTS_YML,
            mode: 'mask',
            extract: 'oauth_token:\\s*(\\S+)',
            injectHosts: ['api.github.com'],
          ),
        ],
        ['api.github.com'],
        reg,
        store,
      );
      expect(degradeToDenyPaths, hasLength(0));
      expect(binds, hasLength(1));
      final fake = (readFileSync(binds[0].fakePath, 'utf8') as String);
      // Structure preserved byte-for-byte except the token span.
      expect(fake, contains('github.com:\n'));
      expect(fake, contains('    user: alice\n'));
      expect(fake, contains('    git_protocol: https\n'));
      expect(fake, isNot(contains(HOSTS_TOKEN)));
      // The token was replaced by a sentinel registered for #0.
      final m = RegExp(r'oauth_token: (\S+)').firstMatch(fake);
      expect(m![1]!.startsWith(SENTINEL_PREFIX), isTrue);
      expect(reg.lookupReal(m[1]!), HOSTS_TOKEN);
      expect(reg.size, 1);
      store.dispose();
    });

    test(
      'extract with maskDuplicates: a duplicate in a comment is masked in the fake',
      () {
        final dupFile = join(FIXTURE_DIR, 'hosts-dup.yml');
        writeFileSync(
          dupFile,
          '# rotate ${HOSTS_TOKEN} before 2027\n' + HOSTS_CONTENT,
        );
        final reg = SentinelRegistry();
        final store = MaskedFileStore();
        final MaskedFileBuildResult(:binds) = buildMaskedFileBinds(
          [
            CredentialFileConfig(
              path: dupFile,
              mode: 'mask',
              extract: 'oauth_token:\\s*(\\S+)',
              maskDuplicates: true,
            ),
          ],
          ['api.github.com'],
          reg,
          store,
        );
        expect(binds, hasLength(1));
        final fake = (readFileSync(binds[0].fakePath, 'utf8') as String);
        expect(fake, isNot(contains(HOSTS_TOKEN)));
        // Both the matched span and the comment duplicate carry the same
        // sentinel, registered once.
        final sentinels = RegExp(
          '${SENTINEL_PREFIX}\\S+',
        ).allMatches(fake).map((m) => m[0]!).toList();
        expect(sentinels, hasLength(2));
        expect(sentinels.toSet().length, 1);
        expect(reg.lookupReal(sentinels[0]), HOSTS_TOKEN);
        expect(reg.size, 1);
        store.dispose();
      },
    );

    test(
      'extract without maskDuplicates leaves a comment duplicate intact',
      () {
        final dupFile = join(FIXTURE_DIR, 'hosts-dup-off.yml');
        writeFileSync(
          dupFile,
          '# rotate ${HOSTS_TOKEN} before 2027\n' + HOSTS_CONTENT,
        );
        final reg = SentinelRegistry();
        final store = MaskedFileStore();
        final MaskedFileBuildResult(:binds) = buildMaskedFileBinds(
          [
            CredentialFileConfig(
              path: dupFile,
              mode: 'mask',
              extract: 'oauth_token:\\s*(\\S+)',
            ),
          ],
          ['api.github.com'],
          reg,
          store,
        );
        expect(binds, hasLength(1));
        final fake = (readFileSync(binds[0].fakePath, 'utf8') as String);
        // Default (#326) behaviour: only the regex-matched span is replaced.
        expect(fake, contains('# rotate ${HOSTS_TOKEN} before 2027\n'));
        expect(fake, isNot(contains('oauth_token: ${HOSTS_TOKEN}')));
        store.dispose();
      },
    );

    group('extract with no match (onExtractNoMatch)', () {
      final noMatch = CredentialFileConfig(
        path: HOSTS_YML,
        mode: 'mask',
        extract: 'nope: (\\S+)',
      );

      test('default → "warn": file left unprotected, stderr warning', () {
        // Dart: spyOn(console, 'warn') is a saved console.warn replaced by a recorder.
        final warnCalls = <Object?>[];
        final warnSpy = console.warn;
        console.warn = ([a, b, c, d]) {
          warnCalls.add(a);
        };
        final reg = SentinelRegistry();
        final store = MaskedFileStore();
        final MaskedFileBuildResult(:binds, :degradeToDenyPaths) =
            buildMaskedFileBinds([noMatch], ['api.github.com'], reg, store);
        // Fail-open: no bind, no deny — the entry is skipped entirely so
        // the real file stays readable via the root mount.
        expect(binds, hasLength(0));
        expect(degradeToDenyPaths, hasLength(0));
        expect(reg.size, 0);
        expect(store.dirPath, isNull);
        // A loud stderr warning surfaces the config error to the operator.
        expect(warnCalls, hasLength(1));
        final msg = warnCalls[0] as String;
        expect(msg, contains('UNPROTECTED'));
        expect(msg, contains(HOSTS_YML));
        expect(msg, contains('nope: (\\S+)'));
        console.warn = warnSpy;
        store.dispose();
      });

      test('explicit "warn" matches the default', () {
        final warnCalls = <Object?>[];
        final warnSpy = console.warn;
        console.warn = ([a, b, c, d]) {
          warnCalls.add(a);
        };
        final reg = SentinelRegistry();
        final store = MaskedFileStore();
        final MaskedFileBuildResult(
          :binds,
          :degradeToDenyPaths,
        ) = buildMaskedFileBinds(
          [
            CredentialFileConfig(
              path: noMatch.path,
              mode: noMatch.mode,
              extract: noMatch.extract,
              onExtractNoMatch: 'warn',
            ),
          ],
          [],
          reg,
          store,
        );
        expect(binds, hasLength(0));
        expect(degradeToDenyPaths, hasLength(0));
        expect(warnCalls, hasLength(1));
        console.warn = warnSpy;
        store.dispose();
      });

      test('"deny": entry degrades to read-deny (fail-closed)', () {
        final warnCalls = <Object?>[];
        final warnSpy = console.warn;
        console.warn = ([a, b, c, d]) {
          warnCalls.add(a);
        };
        final reg = SentinelRegistry();
        final store = MaskedFileStore();
        final MaskedFileBuildResult(
          :binds,
          :degradeToDenyPaths,
        ) = buildMaskedFileBinds(
          [
            CredentialFileConfig(
              path: noMatch.path,
              mode: noMatch.mode,
              extract: noMatch.extract,
              onExtractNoMatch: 'deny',
            ),
          ],
          ['api.github.com'],
          reg,
          store,
        );
        // No bind is emitted (the real file is NOT exposed); the resolved
        // path is reported for the read-deny set.
        expect(binds, hasLength(0));
        expect(degradeToDenyPaths, [realpathSync(HOSTS_YML)]);
        expect(reg.size, 0);
        expect(store.dirPath, isNull);
        // No stderr warning — deny is a configured outcome, not a surprise.
        expect(warnCalls, isEmpty);
        console.warn = warnSpy;
        store.dispose();
      });

      test('"error": throws with a clear message', () {
        final reg = SentinelRegistry();
        final store = MaskedFileStore();
        expect(
          () => buildMaskedFileBinds(
            [
              CredentialFileConfig(
                path: noMatch.path,
                mode: noMatch.mode,
                extract: noMatch.extract,
                onExtractNoMatch: 'error',
              ),
            ],
            [],
            reg,
            store,
          ),
          throwsA(anything),
        );
        store.dispose();
      });

      test(
        'onExtractNoMatch is per-entry: one "deny" does not affect a sibling "warn"',
        () {
          final warnCalls = <Object?>[];
          final warnSpy = console.warn;
          console.warn = ([a, b, c, d]) {
            warnCalls.add(a);
          };
          final other = join(FIXTURE_DIR, 'other.yml');
          writeFileSync(other, 'k: v\n');
          final reg = SentinelRegistry();
          final store = MaskedFileStore();
          final MaskedFileBuildResult(
            :binds,
            :degradeToDenyPaths,
          ) = buildMaskedFileBinds(
            [
              CredentialFileConfig(
                path: noMatch.path,
                mode: noMatch.mode,
                extract: noMatch.extract,
                onExtractNoMatch: 'deny',
              ),
              CredentialFileConfig(
                path: other,
                mode: 'mask',
                extract: 'nope: (\\S+)',
              ),
            ],
            [],
            reg,
            store,
          );
          expect(binds, hasLength(0));
          expect(degradeToDenyPaths, [realpathSync(HOSTS_YML)]);
          expect(warnCalls, hasLength(1));
          expect(warnCalls[0] as String, contains(other));
          console.warn = warnSpy;
          store.dispose();
        },
      );
    });
  });

  group('buildMaskedFileBinds decode: "jwt"', () {
    final b64u = (String s) => Buffer.from(s, 'utf8').toString('base64url');

    // Real-shaped JWTs: HS256 header, JSON payload, garbage signature.
    final REAL_JWT =
        'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.' +
        b64u('{"sub":"1234567890","name":"John Doe","iat":1516239022}') +
        '.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
    final REAL_JWT_2 =
        'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.' +
        b64u('{"sub":"other","iat":1516239022}') +
        '.c2lnbmF0dXJl';
    // Matches the default eyJ-triple pattern but is not a JWT: the first
    // segment decodes to truncated (invalid) JSON.
    final PSEUDO_JWT = "${b64u('{"oops')}.${b64u('{}')}.c2ln";

    final DECODE_DIR = join(
      tmpdir(),
      'srt-credmask-decode-${DateTime.now().millisecondsSinceEpoch}',
    );

    setUpAll(() {
      mkdirSync(DECODE_DIR, {'recursive': true});
    });

    tearDownAll(() {
      rmSync(DECODE_DIR, {'recursive': true, 'force': true});
    });

    test(
      'default pattern: a JWT in a JSON credentials file becomes a parseable fake JWT',
      () {
        final file = join(DECODE_DIR, 'credentials.json');
        writeFileSync(file, '{"access_token":"${REAL_JWT}","note":"keep"}');
        final reg = SentinelRegistry();
        final store = MaskedFileStore();
        final MaskedFileBuildResult(:binds) = buildMaskedFileBinds(
          [CredentialFileConfig(path: file, mode: 'mask', decode: 'jwt')],
          ['api.example.com'],
          reg,
          store,
        );
        expect(binds, hasLength(1));
        final fake = (readFileSync(binds[0].fakePath, 'utf8') as String);
        expect(fake, isNot(contains(REAL_JWT)));
        // Structure preserved around the swapped span.
        expect(fake, contains('"note":"keep"'));
        final fakeToken = RegExp(
          r'"access_token":"([^"]+)"',
        ).firstMatch(fake)![1]!;

        // The fake IS a parseable JWT: three segments, JSON header/payload.
        expect(verifyJwt(fakeToken), isTrue);
        final [h, p, sig] = fakeToken.split('.');
        final header =
            jsonDecode(Buffer.from(h, 'base64url').toString('utf8'))
                as Map<String, Object?>;
        // HS256 + garbage signature, never alg:none — see mintFakeJwt.
        expect(header, {'alg': 'HS256', 'typ': 'JWT'});
        expect(sig, 'c3J0LWZha2U');
        final payload =
            jsonDecode(Buffer.from(p, 'base64url').toString('utf8'))
                as Map<String, Object?>;
        expect(payload['sub'], contains(SENTINEL_PREFIX));

        // Registry roundtrip: the full fake JWT is the sentinel key.
        expect(reg.lookupReal(fakeToken), REAL_JWT);
        store.dispose();
      },
    );

    test('a regex-matched but non-JWT candidate is left untouched', () {
      final file = join(DECODE_DIR, 'mixed');
      writeFileSync(file, 'good: ${REAL_JWT}\nblob: ${PSEUDO_JWT}\n');
      final reg = SentinelRegistry();
      final store = MaskedFileStore();
      final MaskedFileBuildResult(:binds) = buildMaskedFileBinds(
        [CredentialFileConfig(path: file, mode: 'mask', decode: 'jwt')],
        ['api.example.com'],
        reg,
        store,
      );
      expect(binds, hasLength(1));
      final fake = (readFileSync(binds[0].fakePath, 'utf8') as String);
      // The real JWT is masked; the over-matched blob is preserved as-is
      // (it is not a JWT, so there is nothing to protect).
      expect(fake, isNot(contains(REAL_JWT)));
      expect(fake, contains('blob: ${PSEUDO_JWT}\n'));
      expect(reg.size, 1);
      store.dispose();
    });

    test('all candidates failing verification → fail-open with warning', () {
      final warnCalls = <Object?>[];
      final warnSpy = console.warn;
      console.warn = ([a, b, c, d]) {
        warnCalls.add(a);
      };
      final file = join(DECODE_DIR, 'only-blob');
      writeFileSync(file, 'blob: ${PSEUDO_JWT}\n');
      final reg = SentinelRegistry();
      final store = MaskedFileStore();
      final MaskedFileBuildResult(:binds) = buildMaskedFileBinds(
        [CredentialFileConfig(path: file, mode: 'mask', decode: 'jwt')],
        ['api.example.com'],
        reg,
        store,
      );
      expect(binds, hasLength(0));
      expect(reg.size, 0);
      expect(store.dirPath, isNull);
      expect(warnCalls, hasLength(1));
      final msg = warnCalls[0] as String;
      expect(msg, contains('UNPROTECTED'));
      expect(msg, contains(file));
      expect(msg, contains('JWT'));
      console.warn = warnSpy;
      store.dispose();
    });

    test('no candidate matching at all → fail-open with warning', () {
      final warnCalls = <Object?>[];
      final warnSpy = console.warn;
      console.warn = ([a, b, c, d]) {
        warnCalls.add(a);
      };
      final file = join(DECODE_DIR, 'no-jwt');
      writeFileSync(file, 'just some plain text\n');
      final reg = SentinelRegistry();
      final store = MaskedFileStore();
      final MaskedFileBuildResult(:binds) = buildMaskedFileBinds(
        [CredentialFileConfig(path: file, mode: 'mask', decode: 'jwt')],
        ['api.example.com'],
        reg,
        store,
      );
      expect(binds, hasLength(0));
      expect(reg.size, 0);
      expect(warnCalls, hasLength(1));
      expect(warnCalls[0] as String, contains('UNPROTECTED'));
      console.warn = warnSpy;
      store.dispose();
    });

    test(
      'explicit extract wins: only its captures are candidates, verification still applies',
      () {
        final file = join(DECODE_DIR, 'tokens.yml');
        writeFileSync(
          file,
          'id_token: ${REAL_JWT}\nother_jwt: ${REAL_JWT_2}\nblob: x\n',
        );
        final reg = SentinelRegistry();
        final store = MaskedFileStore();
        final MaskedFileBuildResult(:binds) = buildMaskedFileBinds(
          [
            CredentialFileConfig(
              path: file,
              mode: 'mask',
              extract: 'id_token:\\s*(\\S+)',
              decode: 'jwt',
            ),
          ],
          ['api.example.com'],
          reg,
          store,
        );
        expect(binds, hasLength(1));
        final fake = (readFileSync(binds[0].fakePath, 'utf8') as String);
        // The author's pattern is the candidate source: the other JWT is NOT
        // masked even though the default pattern would have found it.
        expect(fake, isNot(contains('id_token: ${REAL_JWT}')));
        expect(fake, contains('other_jwt: ${REAL_JWT_2}\n'));
        final fakeToken = RegExp(r'id_token: (\S+)').firstMatch(fake)![1]!;
        expect(verifyJwt(fakeToken), isTrue);
        expect(reg.lookupReal(fakeToken), REAL_JWT);
        expect(reg.size, 1);
        store.dispose();
      },
    );

    test(
      'decode + maskDuplicates: a verified JWT duplicated in a comment is masked with the same fake',
      () {
        final file = join(DECODE_DIR, 'dup-jwt.yml');
        // The comment duplicate is outside the extract pattern's reach; the
        // pseudo-JWT candidate fails verification, so its comment duplicate
        // must stay untouched.
        writeFileSync(
          file,
          'id_token: ${REAL_JWT}\nblob: ${PSEUDO_JWT}\n' +
              '# rotate ${REAL_JWT} before 2027 (blob was ${PSEUDO_JWT})\n',
        );
        final reg = SentinelRegistry();
        final store = MaskedFileStore();
        final MaskedFileBuildResult(:binds) = buildMaskedFileBinds(
          [
            CredentialFileConfig(
              path: file,
              mode: 'mask',
              extract: '(?:id_token|blob):\\s*(\\S+)',
              decode: 'jwt',
              maskDuplicates: true,
            ),
          ],
          ['api.example.com'],
          reg,
          store,
        );
        expect(binds, hasLength(1));
        final fake = (readFileSync(binds[0].fakePath, 'utf8') as String);
        expect(fake, isNot(contains(REAL_JWT)));
        // Both occurrences carry the SAME fake JWT — the duplicate reuses the
        // verified capture's sentinel without re-verification.
        final fakeToken = RegExp(r'id_token: (\S+)').firstMatch(fake)![1]!;
        expect(verifyJwt(fakeToken), isTrue);
        expect(fake, contains('# rotate ${fakeToken} before 2027'));
        expect(reg.lookupReal(fakeToken), REAL_JWT);
        // The unverified candidate and its duplicate are left as-is.
        expect(fake, contains('blob: ${PSEUDO_JWT}\n'));
        expect(fake, contains('(blob was ${PSEUDO_JWT})'));
        expect(reg.size, 1);
        store.dispose();
      },
    );

    test(
      'explicit extract capturing a non-JWT with decode → fail-open with warning',
      () {
        final warnCalls = <Object?>[];
        final warnSpy = console.warn;
        console.warn = ([a, b, c, d]) {
          warnCalls.add(a);
        };
        final file = join(DECODE_DIR, 'not-a-jwt.yml');
        writeFileSync(file, 'id_token: opaque-session-cookie\n');
        final reg = SentinelRegistry();
        final store = MaskedFileStore();
        final MaskedFileBuildResult(:binds) = buildMaskedFileBinds(
          [
            CredentialFileConfig(
              path: file,
              mode: 'mask',
              extract: 'id_token:\\s*(\\S+)',
              decode: 'jwt',
            ),
          ],
          ['api.example.com'],
          reg,
          store,
        );
        expect(binds, hasLength(0));
        expect(reg.size, 0);
        expect(warnCalls, hasLength(1));
        console.warn = warnSpy;
        store.dispose();
      },
    );

    group('maskClaims', () {
      // A JWT whose payload carries a secret in one claim next to
      // claim-reading metadata a client legitimately needs.
      final CLAIMS_PAYLOAD = {
        'sub': 'user-1',
        'api_key': 'real-claim-secret-0123456789',
        'aud': 'api.example.com',
        'iat': 1516239022,
      };
      final CLAIMS_JWT =
          'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.' +
          b64u(jsonEncode(CLAIMS_PAYLOAD)) +
          '.Y2xhaW1zLXNpZw';

      test(
        'masks the named claim inside the token; both registry mappings exist',
        () {
          final file = join(DECODE_DIR, 'claims.json');
          writeFileSync(file, '{"id_token":"${CLAIMS_JWT}","note":"keep"}');
          final reg = SentinelRegistry();
          final store = MaskedFileStore();
          final MaskedFileBuildResult(:binds) = buildMaskedFileBinds(
            [
              CredentialFileConfig(
                path: file,
                mode: 'mask',
                decode: 'jwt',
                maskClaims: ['api_key'],
              ),
            ],
            ['api.example.com'],
            reg,
            store,
          );
          expect(binds, hasLength(1));
          final fake = (readFileSync(binds[0].fakePath, 'utf8') as String);
          expect(fake, isNot(contains(CLAIMS_JWT)));
          expect(fake, isNot(contains(CLAIMS_PAYLOAD['api_key']!)));
          expect(fake, contains('"note":"keep"'));

          final fakeToken = RegExp(
            r'"id_token":"([^"]+)"',
          ).firstMatch(fake)![1]!;
          expect(verifyJwt(fakeToken), isTrue);
          // Header segment reused verbatim; signature is the filler.
          final [h, p, sig] = fakeToken.split('.');
          expect(h, CLAIMS_JWT.split('.')[0]);
          expect(sig, 'c3J0LWZha2U');
          final payload =
              jsonDecode(Buffer.from(p, 'base64url').toString('utf8'))
                  as Map<String, Object?>;
          // The named claim is a sentinel; every other claim is real.
          final claimSentinel = payload['api_key'] as String;
          expect(claimSentinel, startsWith(SENTINEL_PREFIX));
          expect(payload, {...CLAIMS_PAYLOAD, 'api_key': claimSentinel});

          // Mapping (a): whole fake token → whole real token (bearer usage).
          expect(reg.lookupReal(fakeToken), CLAIMS_JWT);
          // Mapping (b): claim sentinel → real claim value (extracted usage).
          expect(reg.lookupReal(claimSentinel), CLAIMS_PAYLOAD['api_key']!);
          expect(reg.size, 2);
          store.dispose();
        },
      );

      test(
        'a named claim absent from the payload is skipped; matching claims still mask',
        () {
          final file = join(DECODE_DIR, 'claims-partial.json');
          writeFileSync(file, 'token: ${CLAIMS_JWT}\n');
          final reg = SentinelRegistry();
          final store = MaskedFileStore();
          final MaskedFileBuildResult(:binds) = buildMaskedFileBinds(
            [
              CredentialFileConfig(
                path: file,
                mode: 'mask',
                decode: 'jwt',
                maskClaims: ['api_key', 'not_present', 'iat'],
              ),
            ],
            ['api.example.com'],
            reg,
            store,
          );
          expect(binds, hasLength(1));
          final fake = (readFileSync(binds[0].fakePath, 'utf8') as String);
          final fakeToken = RegExp(r'token: (\S+)').firstMatch(fake)![1]!;
          final payload =
              jsonDecode(
                    Buffer.from(
                      fakeToken.split('.')[1],
                      'base64url',
                    ).toString('utf8'),
                  )
                  as Map<String, Object?>;
          expect(payload['api_key'] as String, startsWith(SENTINEL_PREFIX));
          // Absent and non-string (iat is a number) claims are skipped.
          expect(payload['not_present'], isNull);
          expect(payload['iat'], CLAIMS_PAYLOAD['iat']!);
          // Only the whole-token mapping and the one matched claim.
          expect(reg.size, 2);
          store.dispose();
        },
      );

      test(
        'no named claim matching in any verified token → onExtractNoMatch (warn)',
        () {
          final warnCalls = <Object?>[];
          final warnSpy = console.warn;
          console.warn = ([a, b, c, d]) {
            warnCalls.add(a);
          };
          final file = join(DECODE_DIR, 'claims-none.json');
          writeFileSync(file, 'token: ${CLAIMS_JWT}\n');
          final reg = SentinelRegistry();
          final store = MaskedFileStore();
          final MaskedFileBuildResult(:binds) = buildMaskedFileBinds(
            [
              CredentialFileConfig(
                path: file,
                mode: 'mask',
                decode: 'jwt',
                maskClaims: ['not_present'],
              ),
            ],
            ['api.example.com'],
            reg,
            store,
          );
          // The verified JWT has none of the named claims: nothing was
          // masked, so the entry routes through onExtractNoMatch like the
          // no-verified-candidate case.
          expect(binds, hasLength(0));
          expect(reg.size, 0);
          expect(warnCalls, hasLength(1));
          final msg = warnCalls[0] as String;
          expect(msg, contains('UNPROTECTED'));
          expect(msg, contains('maskable claims'));
          console.warn = warnSpy;
          store.dispose();
        },
      );

      test(
        'no named claim matching with onExtractNoMatch "deny" → degrades to deny',
        () {
          final file = join(DECODE_DIR, 'claims-deny.json');
          writeFileSync(file, 'token: ${CLAIMS_JWT}\n');
          final reg = SentinelRegistry();
          final store = MaskedFileStore();
          final MaskedFileBuildResult(
            :binds,
            :degradeToDenyPaths,
          ) = buildMaskedFileBinds(
            [
              CredentialFileConfig(
                path: file,
                mode: 'mask',
                decode: 'jwt',
                maskClaims: ['not_present'],
                onExtractNoMatch: 'deny',
              ),
            ],
            ['api.example.com'],
            reg,
            store,
          );
          expect(binds, hasLength(0));
          expect(degradeToDenyPaths, [realpathSync(file)]);
          store.dispose();
        },
      );

      test('two JWTs in one file: claim sentinels are per-token', () {
        final otherJwt =
            'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.' +
            b64u('{"sub":"user-2","api_key":"other-claim-secret"}') +
            '.b3RoZXItc2ln';
        final file = join(DECODE_DIR, 'claims-two.yml');
        writeFileSync(file, 'a: ${CLAIMS_JWT}\nb: ${otherJwt}\n');
        final reg = SentinelRegistry();
        final store = MaskedFileStore();
        final MaskedFileBuildResult(:binds) = buildMaskedFileBinds(
          [
            CredentialFileConfig(
              path: file,
              mode: 'mask',
              decode: 'jwt',
              maskClaims: ['api_key'],
            ),
          ],
          ['api.example.com'],
          reg,
          store,
        );
        expect(binds, hasLength(1));
        final fake = (readFileSync(binds[0].fakePath, 'utf8') as String);
        final fakeA = RegExp(r'a: (\S+)').firstMatch(fake)![1]!;
        final fakeB = RegExp(r'b: (\S+)').firstMatch(fake)![1]!;
        final claimOf = (String t) =>
            (jsonDecode(
                      Buffer.from(
                        t.split('.')[1],
                        'base64url',
                      ).toString('utf8'),
                    )
                    as Map<String, Object?>)['api_key']
                as String;
        expect(reg.lookupReal(claimOf(fakeA)), CLAIMS_PAYLOAD['api_key']!);
        expect(reg.lookupReal(claimOf(fakeB)), 'other-claim-secret');
        expect(claimOf(fakeA), isNot(claimOf(fakeB)));
        // Two whole-token mappings + two claim mappings.
        expect(reg.size, 4);
        store.dispose();
      });
    });
  });

  /**
   * Linux integration for structured (extract) masking via SandboxManager:
   * the bound fake preserves the file's structure with the credential span
   * replaced by a sentinel.
   */
  group('structured file masking on Linux (extract)', () {
    final TEST_DIR = join(
      tmpdir(),
      'srt-credmask-extract-${DateTime.now().millisecondsSinceEpoch}',
    );
    final YML_FILE = join(TEST_DIR, 'hosts.yml');
    final YML_TOKEN = 'gho_struct_real_0123456789abcdef';
    final YML_CONTENT =
        'github.com:\n' +
        '    user: alice\n' +
        '    oauth_token: ${YML_TOKEN}\n' +
        '    git_protocol: https\n';

    SpawnSyncResult runInSandbox(String wrappedCommand) {
      return spawnSync(wrappedCommand, [], {
        'shell': true,
        'encoding': 'utf8',
        'timeout': 10000,
      });
    }

    setUpAll(() async {
      mkdirSync(TEST_DIR, {'recursive': true});
      writeFileSync(YML_FILE, YML_CONTENT);
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
            files: [
              CredentialFileConfig(
                path: YML_FILE,
                mode: 'mask',
                extract: 'oauth_token:\\s*(\\S+)',
              ),
            ],
            allowPlaintextInject: true,
          ),
        ),
      );
    });

    tearDownAll(() async {
      await SandboxManager.reset();
      rmSync(TEST_DIR, {'recursive': true, 'force': true});
    });

    test(
      'cat inside the sandbox preserves YAML structure with sentinel',
      () async {
        final wrapped = await SandboxManager.wrapWithSandbox('cat ${YML_FILE}');
        expect(wrapped, isNot(contains(YML_TOKEN)));
        final result = runInSandbox(wrapped);
        expect(result.status, 0);
        final seen = (result.stdout as String);
        // Every non-credential line is byte-identical to the real file.
        expect(seen, contains('github.com:\n'));
        expect(seen, contains('    user: alice\n'));
        expect(seen, contains('    git_protocol: https\n'));
        // The credential value is gone; a sentinel sits in its place.
        expect(seen, isNot(contains(YML_TOKEN)));
        final m = RegExp(r'oauth_token: (\S+)').firstMatch(seen);
        expect(m, isNot(isNull));
        expect(m![1]!.startsWith(SENTINEL_PREFIX), isTrue);
        // Same line count and same length modulo the swapped span — the
        // rest of the file is untouched.
        expect(seen.split('\n'), hasLength(YML_CONTENT.split('\n').length));
        // The host-side registry maps that sentinel back to the real token.
        expect(
          SandboxManager.getSentinelRegistry().lookupReal(m[1]!),
          YML_TOKEN,
        );
      },
    );

    test('the masked file is read-only inside the sandbox', () async {
      final wrapped = await SandboxManager.wrapWithSandbox(
        'sh -c \'echo pwned > ${YML_FILE}\'',
      );
      final result = runInSandbox(wrapped);
      expect(result.status, isNot(0));
      expect((readFileSync(YML_FILE, 'utf8') as String), YML_CONTENT);
    });
  }, skip: (isLinux) ? false : 'requires isLinux');

  /**
   * Linux integration: an `extract` pattern that matches nothing follows
   * the entry's `onExtractNoMatch` — default `"warn"` leaves the file
   * readable as-is with a stderr warning; `"deny"` makes it unreadable.
   */
  group('extract no-match onExtractNoMatch on Linux', () {
    final TEST_DIR = join(
      tmpdir(),
      'srt-credmask-nomatch-${DateTime.now().millisecondsSinceEpoch}',
    );
    final SECRET_FILE = join(TEST_DIR, 'hosts.yml');
    final SECRET = 'gho_nomatch_real_0123456789';

    Future<void> init([String? onExtractNoMatch]) async {
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
            files: [
              CredentialFileConfig(
                path: SECRET_FILE,
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

    ;

    setUpAll(() {
      mkdirSync(TEST_DIR, {'recursive': true});
      writeFileSync(SECRET_FILE, 'oauth_token: ${SECRET}\n');
    });

    tearDownAll(() async {
      await SandboxManager.reset();
      rmSync(TEST_DIR, {'recursive': true, 'force': true});
    });

    test(
      'default ("warn"): file readable as-is, stderr warning at wrap',
      () async {
        await init();
        final warnCalls = <Object?>[];
        final warnSpy = console.warn;
        console.warn = ([a, b, c, d]) {
          warnCalls.add(a);
        };
        final wrapped = await SandboxManager.wrapWithSandbox(
          'cat ${SECRET_FILE}',
        );
        // A loud stderr warning surfaces the config error at wrap time.
        expect(warnCalls, isNotEmpty);
        expect(warnCalls[0] as String, contains('UNPROTECTED'));
        console.warn = warnSpy;
        // No fake-file bind and no /dev/null deny bind are emitted for the
        // path — the entry is skipped entirely.
        expect(
          wrapped,
          isNot(
            matches(
              RegExp('--ro-bind \\S+ ${SECRET_FILE.replaceAll('/', '\\/')}\\b'),
            ),
          ),
        );
        final result = spawnSync(wrapped, [], {
          'shell': true,
          'encoding': 'utf8',
          'timeout': 10000,
        });
        // cat succeeds and returns the real bytes: fail-open means the
        // file is left readable via the root mount.
        expect(result.status, 0);
        expect((result.stdout as String), 'oauth_token: ${SECRET}\n');
      },
    );

    test('"deny": file unreadable inside the sandbox (fail-closed)', () async {
      await init('deny');
      final wrapped = await SandboxManager.wrapWithSandbox(
        'cat ${SECRET_FILE}',
      );
      // The real credential never appears in the wrapped command.
      expect(wrapped, isNot(contains(SECRET)));
      // No --ro-bind <fake> <real> — degraded entries go via denyRead, not
      // the masked-file bind path.
      expect(
        wrapped,
        isNot(
          matches(
            RegExp(
              '--ro-bind \\S+\\.fake ${SECRET_FILE.replaceAll('/', '\\/')}',
            ),
          ),
        ),
      );
      final result = spawnSync(wrapped, [], {
        'shell': true,
        'encoding': 'utf8',
        'timeout': 10000,
      });
      // cat fails: the file is unreadable inside the sandbox, and the
      // real bytes are never exposed on stdout.
      expect(result.status, isNot(0));
      expect((result.stdout as String), isNot(contains(SECRET)));
    });

    test('"error": wrapWithSandbox rejects', () async {
      await init('error');
      Object? thrown;
      try {
        await SandboxManager.wrapWithSandbox('cat ${SECRET_FILE}');
      } catch (e) {
        thrown = e;
      }
      expect(thrown, isA<NodeException>());
      expect(
        (thrown as NodeException).message,
        matches(RegExp(r'matched nothing.*onExtractNoMatch: "error"')),
      );
    });
  }, skip: (isLinux) ? false : 'requires isLinux');

  /**
   * A degraded entry names a file the library opened, so the deny must
   * survive on a path whose own name holds glob characters. Expanded as a
   * pattern instead, `a[b/c]d` matches nothing and the deny is dropped.
   */
  group('a degraded credential path holding brackets', () {
    final TEST_DIR = join(
      realpathSync(tmpdir()),
      'srt-credmask-brackets-${DateTime.now().millisecondsSinceEpoch}',
      'a[b',
      'c]d',
    );
    final SECRET_FILE = join(TEST_DIR, 'hosts.yml');
    final SECRET = 'gho_brackets_real_0123456789';

    setUpAll(() async {
      mkdirSync(TEST_DIR, {'recursive': true});
      writeFileSync(SECRET_FILE, 'oauth_token: ${SECRET}\n');
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
            files: [
              CredentialFileConfig(
                path: SECRET_FILE,
                mode: 'mask',
                extract: 'will_not_match_(\\S+)',
                onExtractNoMatch: 'deny',
              ),
            ],
            allowPlaintextInject: true,
          ),
        ),
      );
    });

    tearDownAll(() async {
      await SandboxManager.reset();
      rmSync(TEST_DIR, {'recursive': true, 'force': true});
    });

    test('stays unreadable inside the sandbox', () async {
      final wrapped = await SandboxManager.wrapWithSandbox(
        'cat ${SECRET_FILE}',
      );
      expect(wrapped, isNot(contains(SECRET)));
      final result = spawnSync(wrapped, [], {
        'shell': true,
        'encoding': 'utf8',
        'timeout': 10000,
      });
      expect(result.status, isNot(0));
      expect((result.stdout as String), isNot(contains(SECRET)));
    });
  }, skip: (isLinux) ? false : 'requires isLinux');

  /**
   * macOS: SBPL cannot redirect a read, so a masked file degrades to a
   * (deny file-read* …) rule — same profile output as mode: "deny". The
   * fakePath is unused. Pure string assertion; runs on any platform.
   */
  group('file masking on macOS degrades to read-deny', () {
    test('profile contains (deny file-read* …) for the masked path', () {
      final wrapped = wrapCommandWithSandboxMacOS(
        MacOSSandboxParams(
          command: 'true',
          needsNetworkRestriction: false,
          readConfig: null,
          writeConfig: FsWriteRestrictionConfig(
            allowOnly: ['/tmp'],
            denyWithinAllow: [],
          ),
          maskedFileBinds: [(realPath: TOKEN_FILE, fakePath: '/unused')],
        ),
      );
      expect(wrapped, contains('deny file-read*'));
      expect(wrapped, contains(TOKEN_FILE));
      // The fake path never reaches the profile — SBPL can't bind-mount.
      expect(wrapped, isNot(contains('/unused')));
    });

    test('still sandboxes when masked files are the only restriction', () {
      final wrapped = wrapCommandWithSandboxMacOS(
        MacOSSandboxParams(
          command: 'echo hi',
          needsNetworkRestriction: false,
          readConfig: null,
          writeConfig: null,
          maskedFileBinds: [(realPath: TOKEN_FILE, fakePath: '/unused')],
        ),
      );
      expect(wrapped, isNot('echo hi'));
      expect(wrapped, contains('deny file-read*'));
    });

    test('an extract-mode masked file still degrades to (deny file-read*)', () {
      // extract changes only the fake-file CONTENT; the macOS path keys
      // off the bind list, not the content, so structured masking is
      // exactly as unsupported as whole-file masking — the file is denied.
      final reg = SentinelRegistry();
      final store = MaskedFileStore();
      final MaskedFileBuildResult(:binds) = buildMaskedFileBinds(
        [
          CredentialFileConfig(
            path: HOSTS_YML,
            mode: 'mask',
            extract: 'oauth_token:\\s*(\\S+)',
          ),
        ],
        ['api.github.com'],
        reg,
        store,
      );
      final wrapped = wrapCommandWithSandboxMacOS(
        MacOSSandboxParams(
          command: 'true',
          needsNetworkRestriction: false,
          readConfig: null,
          writeConfig: FsWriteRestrictionConfig(
            allowOnly: ['/tmp'],
            denyWithinAllow: [],
          ),
          // Dart: maskedFileBinds takes records; buildMaskedFileBinds returns MaskedFileBind.
          maskedFileBinds: [
            for (final b in binds) (realPath: b.realPath, fakePath: b.fakePath),
          ],
        ),
      );
      expect(wrapped, contains('deny file-read*'));
      expect(wrapped, contains(HOSTS_YML));
      expect(wrapped, isNot(contains(binds[0].fakePath)));
      // The real credential never reaches the profile.
      expect(wrapped, isNot(contains(HOSTS_TOKEN)));
      store.dispose();
    });
  });

  /**
   * SandboxManager-level file masking on Linux: bwrap binds the fake over
   * the real path; the sandboxed process reads the sentinel; the real bytes
   * never appear in the wrapped command string.
   */
  group('file masking on Linux (bwrap)', () {
    final TEST_DIR = join(
      tmpdir(),
      'srt-credmask-linux-${DateTime.now().millisecondsSinceEpoch}',
    );
    final SECRET_FILE = join(TEST_DIR, 'token');
    final SECRET_CONTENT = 'ghp_linux_real_secret_0123456789';
    final CONTROL_FILE = join(TEST_DIR, 'control.txt');

    SandboxRuntimeConfig baseConfig([
      PartialSandboxRuntimeConfig overrides =
          const PartialSandboxRuntimeConfig(),
    ]) {
      return SandboxRuntimeConfig(
        network:
            overrides.network ??
            NetworkConfig(allowedDomains: ['localhost'], deniedDomains: []),
        filesystem:
            overrides.filesystem ??
            FilesystemConfig(
              denyRead: [],
              allowWrite: [
                FilesystemPathSpelling(TEST_DIR),
                FilesystemPathSpelling('/tmp'),
              ],
              denyWrite: [],
            ),
        credentials:
            overrides.credentials ??
            CredentialsConfig(
              files: [CredentialFileConfig(path: SECRET_FILE, mode: 'mask')],
              allowPlaintextInject: true,
            ),
        // Dart: the spread of the other fields of `overrides` is omitted; no case sets one.
      );
    }

    SpawnSyncResult runInSandbox(String wrappedCommand) {
      return spawnSync(wrappedCommand, [], {
        'shell': true,
        'encoding': 'utf8',
        'timeout': 10000,
      });
    }

    setUpAll(() async {
      mkdirSync(TEST_DIR, {'recursive': true});
      writeFileSync(SECRET_FILE, SECRET_CONTENT);
      writeFileSync(CONTROL_FILE, 'control-ok');
      await SandboxManager.reset();
      await SandboxManager.initialize(baseConfig());
    });

    tearDownAll(() async {
      await SandboxManager.reset();
      rmSync(TEST_DIR, {'recursive': true, 'force': true});
    });

    group('bwrap argv generation', () {
      test(
        'emits --ro-bind <fake> <real> with the sentinel as fake content',
        () async {
          final wrapped = await SandboxManager.wrapWithSandbox('true');
          final m = RegExp(
            '--ro-bind (\\S+) ${SECRET_FILE.replaceAll('/', '\\/')}\\b',
          ).firstMatch(wrapped);
          expect(m, isNot(isNull));
          final fakePath = m![1]!;
          expect(fakePath, isNot('/dev/null'));
          final fakeContent = (readFileSync(fakePath, 'utf8') as String);
          expect(fakeContent.startsWith(SENTINEL_PREFIX), isTrue);
          // The registry maps that sentinel back to the real bytes.
          expect(
            SandboxManager.getSentinelRegistry().lookupReal(fakeContent),
            SECRET_CONTENT,
          );
        },
      );

      test(
        'the real file content never appears in the wrapped command',
        () async {
          final wrapped = await SandboxManager.wrapWithSandbox('true');
          expect(wrapped, isNot(contains(SECRET_CONTENT)));
        },
      );

      test(
        'a masked file that does not exist on the host emits no bind',
        () async {
          await SandboxManager.reset();
          await SandboxManager.initialize(
            baseConfig(
              PartialSandboxRuntimeConfig(
                credentials: CredentialsConfig(
                  files: [
                    CredentialFileConfig(
                      path: join(TEST_DIR, 'no-such-token'),
                      mode: 'mask',
                    ),
                  ],
                  allowPlaintextInject: true,
                ),
              ),
            ),
          );
          final wrapped = await SandboxManager.wrapWithSandbox('true');
          expect(wrapped, isNot(contains('no-such-token')));

          // Restore for the remaining tests.
          await SandboxManager.reset();
          await SandboxManager.initialize(baseConfig());
        },
      );

      test(
        'repeat wraps reuse the same fake file (no per-call leak)',
        () async {
          await SandboxManager.wrapWithSandbox('true');
          await SandboxManager.wrapWithSandbox('true');
          final dir = SandboxManager.getMaskedFileStore().dirPath!;
          expect(readdirSync(dir), hasLength(1));
        },
      );

      test(
        'emits --ro-bind <storeDir> <storeDir> after the allowWrite binds',
        () async {
          final wrapped = await SandboxManager.wrapWithSandbox('true');
          final storeDir = SandboxManager.getMaskedFileStore().dirPath!;
          // The store-dir ro-bind must overlay any allowWrite covering it,
          // so it must appear after `--bind /tmp /tmp` in argv order.
          final writeBind = wrapped.indexOf('--bind /tmp /tmp');
          final storeBind = wrapped.indexOf(
            '--ro-bind ${storeDir} ${storeDir}',
          );
          expect(writeBind, greaterThan(-1));
          expect(storeBind, greaterThan(writeBind));
        },
      );
    });

    group('integration', () {
      test(
        'cat <maskedFile> inside the sandbox returns the sentinel',
        () async {
          final wrapped = await SandboxManager.wrapWithSandbox(
            'cat ${SECRET_FILE}',
          );
          final result = runInSandbox(wrapped);
          expect(result.status, 0);
          expect((result.stdout as String).startsWith(SENTINEL_PREFIX), isTrue);
          expect((result.stdout as String), isNot(contains(SECRET_CONTENT)));
        },
      );

      test('the masked file is read-only inside the sandbox', () async {
        // Even though TEST_DIR is in allowWrite, the --ro-bind on the
        // masked path layers on top — overwriting it would expose a way
        // to swap the sentinel for something the proxy might still inject.
        final wrapped = await SandboxManager.wrapWithSandbox(
          'sh -c \'echo pwned > ${SECRET_FILE}\'',
        );
        final result = runInSandbox(wrapped);
        expect(result.status, isNot(0));
        // Real file on the host is untouched.
        expect((readFileSync(SECRET_FILE, 'utf8') as String), SECRET_CONTENT);
      });

      test('a non-masked sibling file is still readable unchanged', () async {
        final wrapped = await SandboxManager.wrapWithSandbox(
          'cat ${CONTROL_FILE}',
        );
        final result = runInSandbox(wrapped);
        expect(result.status, 0);
        expect((result.stdout as String), 'control-ok');
      });

      test(
        'the fake-file store dir is read-only inside the sandbox even under allowWrite',
        () async {
          // baseConfig() has allowWrite: ['/tmp'], which covers os.tmpdir()
          // and therefore the store dir. The store-dir ro-bind must overlay
          // it: writing the bind SOURCE from inside the sandbox must fail.
          // (The earlier "masked file is read-only" test only covers the
          // bind DEST.)
          await SandboxManager.wrapWithSandbox('true');
          final storeDir = SandboxManager.getMaskedFileStore().dirPath!;
          expect(storeDir.startsWith(tmpdir()), isTrue);

          final fake = join(storeDir, '0.fake');
          final before = (readFileSync(fake, 'utf8') as String);
          final overwrite = await SandboxManager.wrapWithSandbox(
            'sh -c \'echo pwned > ${fake}\'',
          );
          expect(runInSandbox(overwrite).status, isNot(0));
          expect((readFileSync(fake, 'utf8') as String), before);

          final plant = await SandboxManager.wrapWithSandbox(
            "ln -s /etc/passwd ${join(storeDir, 'evil')}",
          );
          expect(runInSandbox(plant).status, isNot(0));
          expect(existsSync(join(storeDir, 'evil')), isFalse);
        },
      );
    });

    test('reset() removes the fake-file temp dir', () async {
      await SandboxManager.wrapWithSandbox('true');
      final dir = SandboxManager.getMaskedFileStore().dirPath;
      expect(dir, isNotNull);
      expect(existsSync(dir!), isTrue);
      await SandboxManager.reset();
      expect(existsSync(dir), isFalse);
      expect(SandboxManager.getMaskedFileStore().dirPath, isNull);
      // Re-initialize for any following tests.
      await SandboxManager.initialize(baseConfig());
    });
  }, skip: (isLinux) ? false : 'requires isLinux');

  /**
   * End-to-end: a token *file* is masked; inside the sandbox a tool reads
   * the file and sends its content as a header. The manager-started proxy
   * substitutes sentinel→real for the file's injectHost only. Reuses the
   * pattern from credential-mask.test.ts (allowPlaintextInject, plain HTTP
   * upstream, SandboxManager's own proxy port).
   */
  group('end-to-end file masking via SandboxManager', () {
    final TEST_DIR = join(
      tmpdir(),
      'srt-credmask-e2e-${DateTime.now().millisecondsSinceEpoch}',
    );
    final SECRET_FILE = join(TEST_DIR, 'token');
    final SECRET_CONTENT = 'ghp_e2e_real_secret_0123456789';
    final HOST_A = 'localhost';
    final HOST_B = 'host-b.localhost';

    late NodeServer upstream;
    late int upstreamPort;
    final lastHeaders = captured<http.IncomingHttpHeaders>();

    setUpAll(() async {
      mkdirSync(TEST_DIR, {'recursive': true});
      writeFileSync(SECRET_FILE, SECRET_CONTENT);

      upstream = http.createServer((
        http.IncomingMessage req,
        http.ServerResponse res,
      ) {
        lastHeaders.value = req.headers;
        res.writeHead(200);
        res.end('ok');
      });
      final listening = Completer<void>();
      upstream.listen(0, '127.0.0.1', () => listening.complete());
      await listening.future;
      upstreamPort = (upstream.address() as NodeAddress).port;

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
            files: [
              CredentialFileConfig(
                path: SECRET_FILE,
                mode: 'mask',
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
      final closed = Completer<void>();
      upstream.close(() => closed.complete());
      await closed.future;
      rmSync(TEST_DIR, {'recursive': true, 'force': true});
    });

    // Async spawn — spawnSync would block the event loop and the
    // in-process proxy/upstream couldn't accept the connection.
    Future<int> curlViaManagerProxy(String url, String bearer) async {
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
      args.add(url);
      final child = spawn('curl', args);
      child.stdout!.listen((_) {});
      child.stderr!.listen((_) {});
      final r = Completer<int>();
      child.on('close', (int? code) => r.complete(code ?? 1));
      return r.future;
    }

    test(
      'cat inside the sandbox + manager proxy → injectHost gets real bytes',
      () async {
        // bwrap leg: cat inside the sandbox returns the sentinel.
        final wrapped = await SandboxManager.wrapWithSandbox(
          'cat ${SECRET_FILE}',
        );
        expect(wrapped, isNot(contains(SECRET_CONTENT)));
        final inSandbox = spawnSync(wrapped, [], {
          'shell': true,
          'encoding': 'utf8',
          'timeout': 10000,
        });
        expect(inSandbox.status, 0);
        final sentinel = (inSandbox.stdout as String);
        expect(sentinel.startsWith(SENTINEL_PREFIX), isTrue);
        expect(sentinel, isNot(contains(SECRET_CONTENT)));

        // Proxy leg: the same sentinel sent through the manager-started
        // proxy reaches HOST_A (injectHost) as the real file content.
        lastHeaders.clear();
        final exit = await curlViaManagerProxy(
          'http://${HOST_A}:${upstreamPort}/',
          sentinel,
        );
        expect(exit, 0);
        expect(lastHeaders.value?['authorization'], 'Bearer ${SECRET_CONTENT}');
      },
      timeout: const Timeout(Duration(milliseconds: 20000)),
    );

    test(
      'a non-injectHost destination receives the sentinel unchanged',
      () async {
        final wrapped = await SandboxManager.wrapWithSandbox(
          'cat ${SECRET_FILE}',
        );
        final sentinel =
            (spawnSync(wrapped, [], {
                  'shell': true,
                  'encoding': 'utf8',
                  'timeout': 10000,
                }).stdout
                as String);

        // HOST_B is allowlisted but NOT in this file's injectHosts. The
        // proxy resolves it to loopback (a `.localhost` name) and forwards
        // the sentinel as-is — fails closed.
        lastHeaders.clear();
        final exit = await curlViaManagerProxy(
          'http://${HOST_B}:${upstreamPort}/',
          sentinel,
        );
        expect(exit, 0);
        expect(lastHeaders.value?['authorization'], 'Bearer ${sentinel}');
        expect(
          lastHeaders.value?['authorization'],
          isNot(contains(SECRET_CONTENT)),
        );
      },
      timeout: const Timeout(Duration(milliseconds: 20000)),
    );
  }, skip: (isLinux) ? false : 'requires isLinux');

  /**
   * End-to-end structured (extract) masking: a multi-credential file is
   * masked with a regex; inside the sandbox a tool parses the sentinel out
   * of the preserved structure and sends it as a header; the proxy swaps
   * each sentinel to its own real captured value at the injectHost.
   */
  group('end-to-end structured file masking via SandboxManager', () {
    final TEST_DIR = join(
      tmpdir(),
      'srt-credmask-extract-e2e-${DateTime.now().millisecondsSinceEpoch}',
    );
    final HOST_A = 'localhost';
    final HOST_B = 'host-b.localhost';

    // hosts.yml-style: one credential, structure must survive.
    final YML_FILE = join(TEST_DIR, 'hosts.yml');
    final YML_TOKEN = 'gho_e2e_real_0123456789abcdef';
    final YML_CONTENT =
        'github.com:\n' +
        '    user: alice\n' +
        '    oauth_token: ${YML_TOKEN}\n' +
        '    git_protocol: https\n';

    // .netrc-style: two credentials → two sentinels, each must swap to
    // its own real value at the proxy.
    final NETRC_FILE = join(TEST_DIR, 'netrc');
    final NETRC_TOK_A = 'npm_e2e_real_aaaaaaaa';
    final NETRC_TOK_B = 'npm_e2e_real_bbbbbbbb';
    final NETRC_CONTENT =
        'machine a.example.com login alice password ${NETRC_TOK_A}\n' +
        'machine b.example.com login bob password ${NETRC_TOK_B}\n';

    late NodeServer upstream;
    late int upstreamPort;
    final lastHeaders = captured<http.IncomingHttpHeaders>();

    setUpAll(() async {
      mkdirSync(TEST_DIR, {'recursive': true});
      writeFileSync(YML_FILE, YML_CONTENT);
      writeFileSync(NETRC_FILE, NETRC_CONTENT);

      upstream = http.createServer((
        http.IncomingMessage req,
        http.ServerResponse res,
      ) {
        lastHeaders.value = req.headers;
        res.writeHead(200);
        res.end('ok');
      });
      final listening = Completer<void>();
      upstream.listen(0, '127.0.0.1', () => listening.complete());
      await listening.future;
      upstreamPort = (upstream.address() as NodeAddress).port;

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
            files: [
              CredentialFileConfig(
                path: YML_FILE,
                mode: 'mask',
                extract: 'oauth_token:\\s*(\\S+)',
                injectHosts: [HOST_A],
              ),
              CredentialFileConfig(
                path: NETRC_FILE,
                mode: 'mask',
                extract: 'password\\s+(\\S+)',
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
      final closed = Completer<void>();
      upstream.close(() => closed.complete());
      await closed.future;
      rmSync(TEST_DIR, {'recursive': true, 'force': true});
    });

    SpawnSyncResult runInSandbox(String wrappedCommand) {
      return spawnSync(wrappedCommand, [], {
        'shell': true,
        'encoding': 'utf8',
        'timeout': 10000,
      });
    }

    Future<int> curlViaManagerProxy(String url, String bearer) async {
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
      args.add(url);
      final child = spawn('curl', args);
      child.stdout!.listen((_) {});
      child.stderr!.listen((_) {});
      final r = Completer<int>();
      child.on('close', (int? code) => r.complete(code ?? 1));
      return r.future;
    }

    test(
      'hosts.yml: parse sentinel from structure → upstream gets real token',
      () async {
        // bwrap leg: extract the oauth_token field from the masked YAML
        // inside the sandbox — the file parses, and the field value is
        // the sentinel.
        final wrapped = await SandboxManager.wrapWithSandbox(
          'sh -c "grep oauth_token ${YML_FILE} | awk \'{print \\\$2}\'"',
        );
        expect(wrapped, isNot(contains(YML_TOKEN)));
        final result = runInSandbox(wrapped);
        expect(result.status, 0);
        final sentinel = (result.stdout as String).trim();
        expect(sentinel.startsWith(SENTINEL_PREFIX), isTrue);
        expect(sentinel, isNot(contains(YML_TOKEN)));

        // Proxy leg: the sentinel reaches HOST_A as the real token.
        lastHeaders.clear();
        final exit = await curlViaManagerProxy(
          'http://${HOST_A}:${upstreamPort}/',
          sentinel,
        );
        expect(exit, 0);
        expect(lastHeaders.value?['authorization'], 'Bearer ${YML_TOKEN}');
      },
      timeout: const Timeout(Duration(milliseconds: 20000)),
    );

    test(
      '.netrc: two captures → two sentinels, each swaps to its own value',
      () async {
        // bwrap leg: read both password fields inside the sandbox.
        final wrapped = await SandboxManager.wrapWithSandbox(
          'sh -c "awk \'{print \\\$NF}\' ${NETRC_FILE}"',
        );
        final result = runInSandbox(wrapped);
        expect(result.status, 0);
        final [sA, sB] = (result.stdout as String).trim().split('\n');
        expect(sA.startsWith(SENTINEL_PREFIX), isTrue);
        expect(sB.startsWith(SENTINEL_PREFIX), isTrue);
        expect(sA, isNot(sB));
        expect((result.stdout as String), isNot(contains(NETRC_TOK_A)));
        expect((result.stdout as String), isNot(contains(NETRC_TOK_B)));

        // Proxy leg: each sentinel swaps to its own real captured value.
        lastHeaders.clear();
        var exit = await curlViaManagerProxy(
          'http://${HOST_A}:${upstreamPort}/',
          sA,
        );
        expect(exit, 0);
        expect(lastHeaders.value?['authorization'], 'Bearer ${NETRC_TOK_A}');

        lastHeaders.clear();
        exit = await curlViaManagerProxy(
          'http://${HOST_A}:${upstreamPort}/',
          sB,
        );
        expect(exit, 0);
        expect(lastHeaders.value?['authorization'], 'Bearer ${NETRC_TOK_B}');
      },
      timeout: const Timeout(Duration(milliseconds: 20000)),
    );

    test(
      'an extract sentinel does not substitute at a non-injectHost',
      () async {
        final wrapped = await SandboxManager.wrapWithSandbox(
          'sh -c "grep oauth_token ${YML_FILE} | awk \'{print \\\$2}\'"',
        );
        final sentinel = (runInSandbox(wrapped).stdout as String).trim();

        lastHeaders.clear();
        final exit = await curlViaManagerProxy(
          'http://${HOST_B}:${upstreamPort}/',
          sentinel,
        );
        expect(exit, 0);
        expect(lastHeaders.value?['authorization'], 'Bearer ${sentinel}');
        expect(lastHeaders.value?['authorization'], isNot(contains(YML_TOKEN)));
      },
      timeout: const Timeout(Duration(milliseconds: 20000)),
    );
  }, skip: (isLinux) ? false : 'requires isLinux');

  /**
   * End-to-end JWT decode masking: a token file holds a JWT; inside the
   * sandbox the tool reads a structurally valid FAKE JWT (parseable header,
   * payload, exp); sending it through the manager proxy delivers the REAL
   * JWT to the injectHost, while a non-injectHost receives the fake.
   */
  group('end-to-end JWT decode masking via SandboxManager', () {
    final TEST_DIR = join(
      tmpdir(),
      'srt-credmask-jwt-e2e-${DateTime.now().millisecondsSinceEpoch}',
    );
    final JWT_FILE = join(TEST_DIR, 'id-token');
    final HOST_A = 'localhost';
    final HOST_B = 'host-b.localhost';

    final b64u = (String s) => Buffer.from(s, 'utf8').toString('base64url');
    final REAL_JWT =
        'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.' +
        b64u('{"sub":"e2e-user","iat":1516239022}') +
        '.ZTJlLXJlYWwtc2lnbmF0dXJl';

    late NodeServer upstream;
    late int upstreamPort;
    final lastHeaders = captured<http.IncomingHttpHeaders>();

    setUpAll(() async {
      mkdirSync(TEST_DIR, {'recursive': true});
      writeFileSync(JWT_FILE, '${REAL_JWT}\n');

      upstream = http.createServer((
        http.IncomingMessage req,
        http.ServerResponse res,
      ) {
        lastHeaders.value = req.headers;
        res.writeHead(200);
        res.end('ok');
      });
      final listening = Completer<void>();
      upstream.listen(0, '127.0.0.1', () => listening.complete());
      await listening.future;
      upstreamPort = (upstream.address() as NodeAddress).port;

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
            files: [
              CredentialFileConfig(
                path: JWT_FILE,
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
      final closed = Completer<void>();
      upstream.close(() => closed.complete());
      await closed.future;
      rmSync(TEST_DIR, {'recursive': true, 'force': true});
    });

    Future<int> curlViaManagerProxy(String url, String bearer) async {
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
      args.add(url);
      final child = spawn('curl', args);
      child.stdout!.listen((_) {});
      child.stderr!.listen((_) {});
      final r = Completer<int>();
      child.on('close', (int? code) => r.complete(code ?? 1));
      return r.future;
    }

    test(
      'cat → fake JWT inside; proxy delivers the real JWT to the injectHost',
      () async {
        // bwrap leg: the sandboxed read returns a structurally valid fake.
        final wrapped = await SandboxManager.wrapWithSandbox('cat ${JWT_FILE}');
        expect(wrapped, isNot(contains(REAL_JWT)));
        final result = spawnSync(wrapped, [], {
          'shell': true,
          'encoding': 'utf8',
          'timeout': 10000,
        });
        expect(result.status, 0);
        final fakeJwt = (result.stdout as String).trim();
        expect(fakeJwt, isNot(REAL_JWT));
        expect(verifyJwt(fakeJwt), isTrue);

        // Proxy leg: the fake sent as a bearer token reaches the injectHost
        // as the REAL JWT.
        lastHeaders.clear();
        final exit = await curlViaManagerProxy(
          'http://${HOST_A}:${upstreamPort}/',
          fakeJwt,
        );
        expect(exit, 0);
        expect(lastHeaders.value?['authorization'], 'Bearer ${REAL_JWT}');
      },
      timeout: const Timeout(Duration(milliseconds: 20000)),
    );

    test(
      'a non-injectHost destination receives the fake JWT unchanged',
      () async {
        final wrapped = await SandboxManager.wrapWithSandbox('cat ${JWT_FILE}');
        final fakeJwt =
            (spawnSync(wrapped, [], {
                      'shell': true,
                      'encoding': 'utf8',
                      'timeout': 10000,
                    }).stdout
                    as String)
                .trim();

        lastHeaders.clear();
        final exit = await curlViaManagerProxy(
          'http://${HOST_B}:${upstreamPort}/',
          fakeJwt,
        );
        expect(exit, 0);
        expect(lastHeaders.value?['authorization'], 'Bearer ${fakeJwt}');
        expect(lastHeaders.value?['authorization'], isNot(contains(REAL_JWT)));
      },
      timeout: const Timeout(Duration(milliseconds: 20000)),
    );
  }, skip: (isLinux) ? false : 'requires isLinux');

  /**
   * End-to-end claim-level JWT masking (`maskClaims`): the sandboxed read
   * returns a token whose named claim is a sentinel while every other claim
   * is real; the proxy substitutes BOTH the whole token (bearer usage) and
   * the extracted claim sentinel (claim-extraction usage) on egress to the
   * injectHost, and neither at a non-injectHost.
   */
  group('end-to-end maskClaims via SandboxManager', () {
    final TEST_DIR = join(
      tmpdir(),
      'srt-credmask-claims-e2e-${DateTime.now().millisecondsSinceEpoch}',
    );
    final JWT_FILE = join(TEST_DIR, 'id-token');
    final HOST_A = 'localhost';
    final HOST_B = 'host-b.localhost';

    final b64u = (String s) => Buffer.from(s, 'utf8').toString('base64url');
    final REAL_CLAIM = 'e2e-real-claim-secret-0123456789';
    final REAL_JWT =
        'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.' +
        b64u('{"sub":"e2e-user","api_key":"${REAL_CLAIM}","iat":1516239022}') +
        '.ZTJlLXJlYWwtc2lnbmF0dXJl';

    late NodeServer upstream;
    late int upstreamPort;
    final lastHeaders = captured<http.IncomingHttpHeaders>();

    setUpAll(() async {
      mkdirSync(TEST_DIR, {'recursive': true});
      writeFileSync(JWT_FILE, '${REAL_JWT}\n');

      upstream = http.createServer((
        http.IncomingMessage req,
        http.ServerResponse res,
      ) {
        lastHeaders.value = req.headers;
        res.writeHead(200);
        res.end('ok');
      });
      final listening = Completer<void>();
      upstream.listen(0, '127.0.0.1', () => listening.complete());
      await listening.future;
      upstreamPort = (upstream.address() as NodeAddress).port;

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
            files: [
              CredentialFileConfig(
                path: JWT_FILE,
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
      final closed = Completer<void>();
      upstream.close(() => closed.complete());
      await closed.future;
      rmSync(TEST_DIR, {'recursive': true, 'force': true});
    });

    Future<int> curlViaManagerProxy(String url, String bearer) async {
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
      args.add(url);
      final child = spawn('curl', args);
      child.stdout!.listen((_) {});
      child.stderr!.listen((_) {});
      final r = Completer<int>();
      child.on('close', (int? code) => r.complete(code ?? 1));
      return r.future;
    }

    /** Read the masked token from inside the sandbox. */
    Future<String> readFakeJwt() async {
      final wrapped = await SandboxManager.wrapWithSandbox('cat ${JWT_FILE}');
      expect(wrapped, isNot(contains(REAL_JWT)));
      final result = spawnSync(wrapped, [], {
        'shell': true,
        'encoding': 'utf8',
        'timeout': 10000,
      });
      expect(result.status, 0);
      return (result.stdout as String).trim();
    }

    String claimOf(String token) {
      final payload =
          jsonDecode(
                Buffer.from(token.split('.')[1], 'base64url').toString('utf8'),
              )
              as Map<String, Object?>;
      return payload['api_key'] as String;
    }

    test(
      'cat → named claim is a sentinel, other claims real; bearer usage delivers the whole real token',
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
        expect(payload['sub'], 'e2e-user');
        expect(payload['iat'], 1516239022);

        // The tool sends the token verbatim → the injectHost receives the
        // whole REAL token.
        lastHeaders.clear();
        final exit = await curlViaManagerProxy(
          'http://${HOST_A}:${upstreamPort}/',
          fakeJwt,
        );
        expect(exit, 0);
        expect(lastHeaders.value?['authorization'], 'Bearer ${REAL_JWT}');
      },
      timeout: const Timeout(Duration(milliseconds: 20000)),
    );

    test(
      'extracted-claim usage: the claim sentinel alone swaps to the real claim value',
      () async {
        final sentinel = claimOf(await readFakeJwt());
        expect(sentinel, startsWith(SENTINEL_PREFIX));

        lastHeaders.clear();
        final exit = await curlViaManagerProxy(
          'http://${HOST_A}:${upstreamPort}/',
          sentinel,
        );
        expect(exit, 0);
        expect(lastHeaders.value?['authorization'], 'Bearer ${REAL_CLAIM}');
      },
      timeout: const Timeout(Duration(milliseconds: 20000)),
    );

    test(
      'a non-injectHost destination receives the fake token and sentinel unchanged',
      () async {
        final fakeJwt = await readFakeJwt();

        lastHeaders.clear();
        var exit = await curlViaManagerProxy(
          'http://${HOST_B}:${upstreamPort}/',
          fakeJwt,
        );
        expect(exit, 0);
        expect(lastHeaders.value?['authorization'], 'Bearer ${fakeJwt}');
        expect(
          lastHeaders.value?['authorization'],
          isNot(contains(REAL_CLAIM)),
        );

        lastHeaders.clear();
        exit = await curlViaManagerProxy(
          'http://${HOST_B}:${upstreamPort}/',
          claimOf(fakeJwt),
        );
        expect(exit, 0);
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
  }, skip: (isLinux) ? false : 'requires isLinux');
}
