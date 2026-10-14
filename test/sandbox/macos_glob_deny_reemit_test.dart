// Ported from sandbox-runtime test/sandbox/macos-glob-deny-reemit.test.ts @ 24eb39e.
// ignore_for_file: constant_identifier_names
import 'dart:convert';
import 'dart:io';

import 'package:test/test.dart';

/// Profile-text tests for how the macOS read section orders denies against
/// allowWithinDeny (Seatbelt is last-match-wins). These only inspect the
/// generated SBPL, so they run on every POSIX host; the read-side enforcement
/// tests that execute the profiles under sandbox-exec live in
/// allow-read.test.ts (the write-side ones are at the bottom of this file).
///
/// Layout under test (see generateReadRules):
///   (allow file-read*)
///   (deny  file-read* `denyOnly`)
///   (allow file-read* `allowWithinDeny`)
///   (deny  file-read* `nested literal denies, every glob deny minus the
///                      allows it covers`)
///   (allow file-read* (literal "/"))          only when a deny covers "/"
///   ...
///   (deny file-write-unlink `read-denied paths inside write roots`)   last
///
/// The invariant every test here leans on: after the allowWithinDeny block,
/// the read section only adds denies. Nothing readable-today becomes
/// readable, so each assertion is about a deny landing late enough.

import 'package:sandbox_runtime/src/sandbox/macos_sandbox_utils.dart';
import 'package:sandbox_runtime/src/sandbox/sandbox_schemas.dart';

const HEADERS = <String, String>{
  'allowRead': '(allow file-read*\n',
  'denyRead': '(deny file-read*\n',
  'denyUnlink': '(deny file-write-unlink\n',
  'metadata': '(allow file-read-metadata',
  'rootReallow': '(allow file-read* (literal "/"))',
};

String readSection(String profile) {
  final start = profile.indexOf('; File read\n');
  final end = profile.indexOf('; File write');
  expect(start, greaterThanOrEqualTo(0));
  expect(end, greaterThan(start));
  return profile.substring(start, end);
}

/// Body of the trailing unlink rule, or '' when none was emitted.
String trailingUnlinkRule(String profile) {
  final marker = profile.indexOf('; File read: keep read-denied paths');
  if (marker < 0) return '';
  final rule = profile.substring(marker);
  expect(rule, contains(HEADERS['denyUnlink']!));
  return rule;
}

/// Position of the allowWithinDeny allow rule inside the read section.
int allowBlockIndex(String read) {
  final index = read.indexOf(HEADERS['allowRead']!);
  expect(index, greaterThanOrEqualTo(0));
  return index;
}

/// The slice of the read section between the allowWithinDeny allow rule and
/// the directory-metadata allow: the late deny rule plus (optionally) the
/// root re-allow. Everything that must beat the allows has to be in here —
/// later rules (move-blocking) mention the same filters for other
/// operations, so `lastIndexOf` over the whole section would mislead.
String lateBlock(String read) {
  final allowAt = allowBlockIndex(read);
  final metadataAt = read.indexOf(HEADERS['metadata']!);
  expect(metadataAt, greaterThan(allowAt));
  return read.substring(allowAt + HEADERS['allowRead']!.length, metadataAt);
}

String wrap(FsReadRestrictionConfig readConfig, [List<String>? allowWrite]) {
  return wrapCommandWithSandboxMacOS(
    MacOSSandboxParams(
      command: 'true',
      needsNetworkRestriction: false,
      readConfig: readConfig,
      writeConfig: allowWrite == null
          ? null
          : FsWriteRestrictionConfig(
              allowOnly: allowWrite,
              denyWithinAllow: [],
            ),
    ),
  );
}

// Every glob deny is rendered with the subtree tail so `x/**` (stripped
// upstream to `x`) still covers x's contents.
const ENV_GLOB = r'^/work/proj/(.*/)?\\.env(/.*)?$';
const SECRETS_GLOB = r'^/work/proj/(.*/)?secrets(/.*)?$';
const KEY_GLOB = r'^/(.*/)?[^/]*\\.key(/.*)?$';

void main() {
  if (!Platform.isWindows) {
    group('macOS read profile: glob denies vs allowRead', () {
      test('re-emits a leaf glob deny after the allow block, uncarved', () {
        final read = readSection(
          wrap(
            FsReadRestrictionConfig(
              denyOnly: ['/work/proj/**/.env'],
              allowWithinDeny: ['/work/proj'],
            ),
          ),
        );
        // Base deny layer, then re-emitted after the allow (and before the
        // directory-metadata allow — lateBlock() is bounded by both).
        final filter = '(regex "$ENV_GLOB")';
        expect(read.indexOf(filter), lessThan(allowBlockIndex(read)));
        final late = lateBlock(read);
        expect(late, contains(HEADERS['denyRead']!));
        expect(late, contains(filter));
        // Nothing about the allow dir is subtracted from it: `.env` beats the
        // directory allow it lands inside.
        expect(read, isNot(contains('require-not')));
      });

      test('renders glob denies with a subtree tail in every deny layer', () {
        final profile = wrap(
          FsReadRestrictionConfig(
            denyOnly: ['/work/proj/**/secrets', '/**/*.key'],
            allowWithinDeny: ['/work/proj'],
          ),
          ['/work/proj'],
        );
        // Base deny + re-emit + read move-blocking + trailing unlink = 4.
        expect(profile.split('(regex "$SECRETS_GLOB")').length - 1, 4);
        expect(profile.split('(regex "$KEY_GLOB")').length - 1, 4);
        // Allows keep the exact-match regex.
        final allowGlob = readSection(
          wrap(
            FsReadRestrictionConfig(
              denyOnly: ['/work'],
              allowWithinDeny: ['/work/proj*'],
            ),
          ),
        );
        expect(allowGlob, contains('(regex "^/work/proj[^/]*\$")'));
        expect(allowGlob, isNot(contains('^/work/proj[^/]*(/.*)?\$')));
      });

      test(
        'carves the allows a region-shaped glob covers out of its re-emit',
        () {
          final read = readSection(
            wrap(
              FsReadRestrictionConfig(
                denyOnly: ['/Users/me/**/*'],
                allowWithinDeny: ['/Users/me/proj', '/Users/me/other*'],
              ),
            ),
          );
          expect(
            lateBlock(read),
            contains(
              '(require-all (regex "^/Users/me/(.*/)?[^/]*(/.*)?\$")'
              ' (require-not (subpath "/Users/me/proj"))'
              ' (require-not (regex "^/Users/me/other[^/]*\$")))',
            ),
          );
        },
      );

      test(
        'carves a specific file allow out of a glob deny that covers it',
        () {
          // Shape sandbox-manager produces under tlsTerminate: the trust bundle
          // is pushed into allowWithinDeny; a user `/**/*.crt` deny covers it.
          final bundle = '/private/tmp/srt-ca-abc/trust-bundle.crt';
          final read = readSection(
            wrap(
              FsReadRestrictionConfig(
                denyOnly: ['/**/*.crt', '/work/proj/**/.env'],
                allowWithinDeny: ['/work/proj', bundle],
              ),
            ),
          );
          final late = lateBlock(read);
          final crtReemit =
              '(require-all (regex "^/(.*/)?[^/]*\\\\.crt(/.*)?\$")'
              ' (require-not (subpath "$bundle")))';
          expect(late, contains(crtReemit));
          // The `.env` glob does not cover the bundle, so it stays uncarved.
          expect(late, contains('  (regex "$ENV_GLOB")\n'));
          // Deny-only: no allow of any kind follows the re-emitted denies.
          expect(late, isNot(contains(HEADERS['rootReallow']!)));
          expect(
            read.substring(read.indexOf(crtReemit)),
            isNot(contains(HEADERS['allowRead']!)),
          );
        },
      );

      test('still re-emits a literal deny nested under a literal allow', () {
        final read = readSection(
          wrap(
            FsReadRestrictionConfig(
              denyOnly: ['/work/proj/secrets'],
              allowWithinDeny: ['/work/proj'],
            ),
          ),
        );
        const filter = '(subpath "/work/proj/secrets")';
        expect(read.indexOf(filter), lessThan(allowBlockIndex(read)));
        expect(lateBlock(read), contains(filter));
      });

      test(
        'still re-emits a literal deny nested under a literal allow of "/"',
        () {
          final read = readSection(
            wrap(
              FsReadRestrictionConfig(
                denyOnly: ['/work/proj/secrets'],
                allowWithinDeny: ['/'],
              ),
            ),
          );
          // '/' is a legal allowWithinDeny entry and re-opens every denied path,
          // so the nested deny only survives if it lands after the allow block.
          // Containment against it has to be root-aware: a `dir + '/'` prefix
          // spells '//' and matches nothing.
          const filter = '(subpath "/work/proj/secrets")';
          expect(read.indexOf(filter), lessThan(allowBlockIndex(read)));
          expect(lateBlock(read), contains(filter));
        },
      );

      test('does not re-emit a literal deny that no allow is nested in', () {
        final read = readSection(
          wrap(
            FsReadRestrictionConfig(
              denyOnly: ['/work/other'],
              allowWithinDeny: ['/work/proj'],
            ),
          ),
        );
        // Only the base (deny file-read*) rule; no late one is emitted.
        expect(read.split(HEADERS['denyRead']!).length - 1, 1);
      });

      test(
        'emits no late deny rule at all when there is nothing to re-emit',
        () {
          final read = readSection(
            wrap(FsReadRestrictionConfig(denyOnly: ['/work/other'])),
          );
          expect(read.split(HEADERS['denyRead']!).length - 1, 1);
          expect(read, isNot(contains(HEADERS['rootReallow']!)));
        },
      );
    });

    group('macOS read profile: root re-allow placement', () {
      test('lands after the re-emitted denies when denyOnly has "/"', () {
        final read = readSection(
          wrap(
            FsReadRestrictionConfig(
              denyOnly: ['/', '/work/proj/**/.env'],
              allowWithinDeny: ['/work/proj', '/usr', '/bin'],
            ),
          ),
        );
        final late = lateBlock(read);
        final rootAt = late.indexOf(HEADERS['rootReallow']!);
        expect(rootAt, greaterThan(late.indexOf('(regex "$ENV_GLOB")')));
        expect(
          late.substring(rootAt + HEADERS['rootReallow']!.length).trim(),
          isEmpty,
        );
      });

      test('is also emitted when a glob deny matches "/" itself', () {
        final read = readSection(
          wrap(
            FsReadRestrictionConfig(
              denyOnly: ['/*'],
              allowWithinDeny: ['/usr', '/bin'],
            ),
          ),
        );
        final rootAt = read.indexOf(HEADERS['rootReallow']!);
        expect(rootAt, greaterThan(0));
        // The `/*` re-emit (carved for the allows it covers) precedes it.
        const reemit =
            '(require-all (regex "^/[^/]*(/.*)?\$")'
            ' (require-not (subpath "/usr")) (require-not (subpath "/bin")))';
        expect(read.indexOf(reemit), greaterThan(0));
        expect(read.indexOf(reemit), lessThan(rootAt));
      });

      test('is not emitted for globs that cannot match "/"', () {
        final read = readSection(
          wrap(
            FsReadRestrictionConfig(
              denyOnly: ['/**/*.key'],
              allowWithinDeny: ['/work'],
            ),
          ),
        );
        expect(read, isNot(contains(HEADERS['rootReallow']!)));
      });
    });

    group('macOS profile: trailing unlink re-deny', () {
      test('is omitted when there are no write roots', () {
        final profile = wrap(
          FsReadRestrictionConfig(
            denyOnly: ['/work/proj/**/.env', '/work/proj/secrets'],
            allowWithinDeny: ['/work/proj'],
          ),
        );
        expect(trailingUnlinkRule(profile), isEmpty);
      });

      test('lands after the write section, after the unlink/create re-allow', () {
        final profile = wrap(
          FsReadRestrictionConfig(
            denyOnly: ['/work/proj/**/.env'],
            allowWithinDeny: ['/work/proj'],
          ),
          ['/work/proj'],
        );
        final rule = trailingUnlinkRule(profile);
        expect(rule, contains('(regex "$ENV_GLOB")'));
        final ruleAt = profile.indexOf(rule);
        expect(ruleAt, greaterThan(profile.indexOf('; File write')));
        expect(
          ruleAt,
          greaterThan(
            profile.indexOf('(allow file-write-unlink file-write-create\n'),
          ),
        );
        expect(ruleAt, greaterThan(profile.indexOf('(allow file-write*\n')));
        // Unlink only: creating a new file at a read-denied name stays allowed.
        expect(rule, isNot(contains('file-write-create')));
        // A glob rooted at the write root itself protects no ancestor dirs, so
        // rm of unrelated files inside the root keeps working.
        expect(rule, isNot(contains('(literal ')));
      });

      test(
        'covers a literal deny below a write root, even with no allowRead',
        () {
          final profile = wrap(
            FsReadRestrictionConfig(denyOnly: ['/work/proj/secrets']),
            ['/work/proj'],
          );
          expect(
            trailingUnlinkRule(profile),
            contains('(subpath "/work/proj/secrets")'),
          );
        },
      );

      test('skips literal denies at or above a write root', () {
        final profile = wrap(
          FsReadRestrictionConfig(
            denyOnly: ['/work', '/work/proj', '/elsewhere'],
          ),
          ['/work/proj'],
        );
        // `/work` contains the root; `/work/proj` is the root; `/elsewhere` is
        // unrelated. Move-blocking in the read section still covers all three.
        expect(trailingUnlinkRule(profile), isEmpty);
      });

      test(
        'protects ancestor dirs strictly between the entry and the write root',
        () {
          final profile = wrap(
            FsReadRestrictionConfig(
              denyOnly: ['/work/proj/a/b/secret', '/work/proj/conf/*.pem'],
            ),
            ['/work/proj'],
          );
          final rule = trailingUnlinkRule(profile);
          expect(rule, contains('(literal "/work/proj/a/b")'));
          expect(rule, contains('(literal "/work/proj/a")'));
          expect(rule, contains('(literal "/work/proj/conf")'));
          expect(rule, isNot(contains('(literal "/work/proj")')));
          expect(rule, isNot(contains('(literal "/work")')));
        },
      );

      test(
        'carves nested allows and nested write roots out of a literal entry',
        () {
          final profile = wrap(
            FsReadRestrictionConfig(
              denyOnly: ['/work/proj/secrets'],
              allowWithinDeny: ['/work/proj/secrets/pub'],
            ),
            ['/work/proj', '/work/proj/secrets/scratch'],
          );
          expect(
            trailingUnlinkRule(profile),
            contains(
              '(require-all (subpath "/work/proj/secrets")'
              ' (require-not (subpath "/work/proj/secrets/pub"))'
              ' (require-not (subpath "/work/proj/secrets/scratch")))',
            ),
          );
        },
      );

      test(
        'carves the allows and write roots a region glob covers (#171 shape)',
        () {
          final profile = wrap(
            FsReadRestrictionConfig(
              denyOnly: ['/Users/me/**/*'],
              allowWithinDeny: ['/Users/me/proj'],
            ),
            ['/Users/me/proj', '/Users/me/.cache', '/private/tmp/claude'],
          );
          final rule = trailingUnlinkRule(profile);
          // proj is both an allow and a write root — carved once. .cache is only
          // a write root but the glob covers it, so rm there keeps working. The
          // private/tmp root is outside the glob and needs no carve.
          expect(
            rule,
            contains(
              '(require-all (regex "^/Users/me/(.*/)?[^/]*(/.*)?\$")'
              ' (require-not (subpath "/Users/me/proj"))'
              ' (require-not (subpath "/Users/me/.cache")))',
            ),
          );
          expect(rule, isNot(contains('/private/tmp/claude')));
        },
      );

      test('skips globs whose region is disjoint from every write root', () {
        final profile = wrap(
          FsReadRestrictionConfig(denyOnly: ['/Users/me/.aws/*']),
          ['/work/proj'],
        );
        expect(trailingUnlinkRule(profile), isEmpty);
      });

      test('includes root-anchored globs without protecting any ancestors', () {
        final profile = wrap(FsReadRestrictionConfig(denyOnly: ['/**/*.key']), [
          '/work/proj',
        ]);
        final rule = trailingUnlinkRule(profile);
        expect(rule, contains('(regex "$KEY_GLOB")'));
        expect(rule, isNot(contains('(literal ')));
      });

      test('is conservative (emitted) when a write root is itself a glob', () {
        final profile = wrap(
          FsReadRestrictionConfig(denyOnly: ['/Users/me/.aws/*']),
          ['/scratch/*'],
        );
        final rule = trailingUnlinkRule(profile);
        expect(rule, contains(r'(regex "^/Users/me/\\.aws/[^/]*(/.*)?$")'));
        // The glob root's exact-match filter is what the read section re-allowed,
        // so it is what gets carved when the deny covers it — here it doesn't.
        expect(rule, isNot(contains('require-not')));
      });
    });

    group('macOS write profile: glob denies get the subtree tail', () {
      test(
        'renders a stripped denyWrite glob so it covers the directory contents',
        () {
          // sandbox-manager strips a trailing /** before the pattern gets here, so
          // denyWrite: ["<proj>/**/secrets/**"] arrives as "<proj>/**/secrets".
          final profile = wrapCommandWithSandboxMacOS(
            MacOSSandboxParams(
              command: 'true',
              needsNetworkRestriction: false,
              readConfig: null,
              writeConfig: FsWriteRestrictionConfig(
                allowOnly: ['/work/proj'],
                denyWithinAllow: ['/work/proj/**/secrets'],
              ),
            ),
          );
          final writeSection = profile.substring(
            profile.indexOf('; File write'),
          );
          expect(
            writeSection,
            contains(
              '(deny file-write*\n  (regex "^/work/proj/(.*/)?secrets(/.*)?\$")',
            ),
          );
          // allowWrite globs are unchanged (exact match, as before).
          final allowGlob = wrapCommandWithSandboxMacOS(
            MacOSSandboxParams(
              command: 'true',
              needsNetworkRestriction: false,
              readConfig: null,
              writeConfig: FsWriteRestrictionConfig(
                allowOnly: ['/work/out-*'],
                denyWithinAllow: [],
              ),
            ),
          );
          expect(allowGlob, contains('(regex "^/work/out-[^/]*\$")'));
          expect(allowGlob, isNot(contains('^/work/out-[^/]*(/.*)?\$')));
        },
      );
    });
  }

  if (Platform.isMacOS) {
    group('macOS write enforcement for glob denies', () {
      late Directory base;
      late Directory project;
      const original = 'ORIGINAL';
      String? originalCwd;

      setUpAll(() {
        final temp = Directory.systemTemp.resolveSymbolicLinksSync();
        base = Directory(
          '$temp/glob-deny-write-${DateTime.now().millisecondsSinceEpoch}',
        );
        project = Directory('${base.path}/project');
        Directory('${project.path}/secrets').createSync(recursive: true);
        File('${project.path}/secrets/existing').writeAsStringSync(original);
        Directory(
          '${project.path}/vendor/dep/.git/hooks',
        ).createSync(recursive: true);
        File(
          '${project.path}/vendor/dep/.git/hooks/pre-commit',
        ).writeAsStringSync(original);
        File('${project.path}/plain.txt').writeAsStringSync(original);
      });

      tearDownAll(() {
        if (originalCwd != null) Directory.current = originalCwd!;
        if (base.existsSync()) base.deleteSync(recursive: true);
      });

      setUp(() {
        originalCwd = Directory.current.path;
      });

      RunResult runWrite(
        String command, [
        List<String> denyWithinAllow = const [],
      ]) {
        final wrapped = wrapCommandWithSandboxMacOS(
          MacOSSandboxParams(
            command: command,
            needsNetworkRestriction: false,
            readConfig: null,
            writeConfig: FsWriteRestrictionConfig(
              allowOnly: [project.path],
              denyWithinAllow: denyWithinAllow,
            ),
          ),
        );
        try {
          final result = Process.runSync(
            '/bin/sh',
            ['-c', wrapped],
            stdoutEncoding: utf8,
            stderrEncoding: utf8,
          );
          return RunResult(exitCode: result.exitCode);
        } catch (error) {
          return RunResult(error: error);
        }
      }

      test(
        'a stripped **/secrets denyWrite blocks writes inside the directory',
        () {
          final existing = '${project.path}/secrets/existing';
          final fresh = '${project.path}/secrets/fresh';
          final result = runWrite(
            'echo X > $existing; echo X > $fresh; echo X > ${project.path}/plain.txt',
            ['${project.path}/**/secrets'],
          );
          expect(result.error, isNull);
          expect(File(existing).readAsStringSync(), original);
          expect(File(fresh).existsSync(), isFalse);
          // The sibling outside the deny is still writable.
          expect(File('${project.path}/plain.txt').readAsStringSync(), 'X\n');
        },
      );

      test(
        "mandatory **/.git/hooks/** still blocks a nested repo's hooks (regression guard)",
        () {
          // The mandatory patterns are anchored at process.cwd(); this pattern
          // already carried its own /** tail before the subtree change, so this
          // guards that the change keeps it working rather than fixing it.
          Directory.current = project.path;
          final hook = '${project.path}/vendor/dep/.git/hooks/pre-commit';
          final newHook = '${project.path}/vendor/dep/.git/hooks/post-checkout';
          final result = runWrite('echo X > $hook; echo X > $newHook');
          expect(result.error, isNull);
          expect(File(hook).readAsStringSync(), original);
          expect(File(newHook).existsSync(), isFalse);
        },
      );
    });
  }
}

class RunResult {
  final int? exitCode;
  final Object? error;
  RunResult({this.exitCode, this.error});
}
