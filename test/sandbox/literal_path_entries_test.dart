// Ported from sandbox-runtime test/sandbox/literal-path-entries.test.ts @ 24eb39e.
// ignore_for_file: constant_identifier_names, non_constant_identifier_names, slash_for_doc_comments
import 'dart:async';
import 'dart:convert';
import 'dart:io' show Directory, Link;

import 'package:path/path.dart' show join;
import 'package:sandbox_runtime/src/node/child_process.dart' show spawnSync;
import 'package:sandbox_runtime/src/node/fs.dart' as fs;
import 'package:sandbox_runtime/src/node/net.dart' as net;
import 'package:sandbox_runtime/src/node/os.dart' show tmpdir;
import 'package:sandbox_runtime/src/node/process.dart' as process;
import 'package:sandbox_runtime/src/node/structured_clone.dart'
    show structuredClone;
import 'package:sandbox_runtime/src/sandbox/linux_sandbox_utils.dart';
import 'package:sandbox_runtime/src/sandbox/linux_violation_monitor.dart'
    as linux_violation_monitor_module;
import 'package:sandbox_runtime/src/sandbox/linux_violation_monitor.dart'
    show LinuxViolationMonitor, LinuxViolationMonitorOptions;
import 'package:sandbox_runtime/src/sandbox/macos_sandbox_utils.dart';
import 'package:sandbox_runtime/src/sandbox/path_entries.dart';
import 'package:sandbox_runtime/src/sandbox/sandbox_config.dart';
import 'package:sandbox_runtime/src/sandbox/sandbox_manager.dart';
import 'package:sandbox_runtime/src/sandbox/sandbox_schemas.dart';
import 'package:sandbox_runtime/src/sandbox/sandbox_utils.dart';
import 'package:sandbox_runtime/src/utils/config_loader.dart';
import 'package:test/test.dart';

import '../helpers/bwrap_namespace.dart';
import '../helpers/platform.dart';

/**
 * Entries inside a directory with `*`, `?`, `[` or `]` in its name, which
 * match nothing when read as a pattern alone, and entries marked
 * `{ path, literal: true }`: see src/sandbox/path-entries.ts.
 *
 * The Linux suites run real commands under bubblewrap. The macOS suites read
 * the generated profile on any POSIX host; none runs it under sandbox-exec.
 */

/** The folder every suite works in: a name a pattern reads as a class. */
const PROJECT = '[WIP] project';

const WRAP_TIMEOUT_MS = 60000;
const RUN_TIMEOUT_MS = 15000;

String freshRoot() {
  return fs.realpathSync(fs.mkdtempSync(join(tmpdir(), 'literal-paths-')));
}

/** A path as one shell word. */
String q(String p) {
  return "'${p.replaceAll("'", r"'\''")}'";
}

String escapedForRegex(String text) {
  return text.replaceAllMapped(
    RegExp(r'[.*+?^${}()|[\]\\]'),
    (match) => '\\${match[0]}',
  );
}

/** The filter a spelling compiles to when read as a pattern. */
String patternFilter(String spelling, String kind) {
  final compile = kind == 'deny' ? denyGlobRegex : globToRegex;
  return '(regex ${jsonEncode(compile(normalizePathForSandbox(spelling)))})';
}

String subpath(String p) => '(subpath ${jsonEncode(p)})';
String literalFilter(String p) => '(literal ${jsonEncode(p)})';

List<RegExp> emittedRegexes(String profile) {
  return RegExp(r'\(regex ("(?:[^"\\]|\\.)*")\)')
      .allMatches(profile)
      .map((match) => RegExp(jsonDecode(match[1]!) as String))
      .toList();
}

List<String> emittedSubpaths(String profile) {
  return RegExp(r'\(subpath ("(?:[^"\\]|\\.)*")\)')
      .allMatches(profile)
      .map((match) => jsonDecode(match[1]!) as String)
      .toList();
}

/** The rule of `profile` that starts with `head`, up to its closing line. */
String ruleOf(String profile, String head) {
  final start = profile.indexOf(head);
  if (start < 0) return '';
  final end = profile.indexOf('(with message', start);
  // Dart: JS slice() reads an end of -1 as the length less one.
  return profile.substring(start, end < 0 ? profile.length - 1 : end);
}

String macProfile(
  FsReadRestrictionConfig? readConfig,
  FsWriteRestrictionConfig? writeConfig,
) {
  return wrapCommandWithSandboxMacOS(
    MacOSSandboxParams(
      command: 'true',
      needsNetworkRestriction: false,
      readConfig: readConfig,
      writeConfig: writeConfig,
    ),
  );
}

const noNetwork = NetworkConfig(allowedDomains: [], deniedDomains: []);

// Dart: entries are Strings or marked FilesystemPathEntry values, as in TS.
class FilesystemLists {
  const FilesystemLists({
    this.denyRead,
    this.allowRead,
    this.allowWrite,
    this.denyWrite,
  });
  final List<Object>? denyRead;
  final List<Object>? allowRead;
  final List<Object>? allowWrite;
  final List<Object>? denyWrite;
}

// Dart: a String is a spelling; a marked entry is itself.
List<FilesystemPathEntry>? _entries(List<Object>? list) => list
    ?.map(
      (e) => e is String ? FilesystemPathSpelling(e) : e as FilesystemPathEntry,
    )
    .toList();

FilesystemConfig _filesystemOf(FilesystemLists filesystem) => FilesystemConfig(
  denyRead: _entries(filesystem.denyRead) ?? [],
  allowRead: _entries(filesystem.allowRead),
  allowWrite: _entries(filesystem.allowWrite) ?? [],
  denyWrite: _entries(filesystem.denyWrite) ?? [],
);

Future<void> initialize(FilesystemLists filesystem) async {
  await SandboxManager.reset();
  await SandboxManager.initialize(
    SandboxRuntimeConfig(
      network: noNetwork,
      filesystem: _filesystemOf(filesystem),
    ),
    null,
    false,
  );
}

/**
 * Runs `payload` under the policy, behind an `echo BOOTED`, so a sandbox
 * that failed to start cannot read as a payload that was refused.
 */
Future<({String stdout, String stderr})> sandboxed(
  FilesystemLists filesystem,
  String payload, {
  required String cwd,
  FilesystemLists? perWrap,
  bool? keepMountPoints,
}) async {
  await initialize(perWrap != null ? const FilesystemLists() : filesystem);
  final wrapped = await SandboxManager.wrapWithSandbox(
    'echo BOOTED; $payload',
    null,
    perWrap != null
        ? PartialSandboxRuntimeConfig(filesystem: _filesystemOf(perWrap))
        : null,
  );
  final result = spawnSync(wrapped, [], {
    'shell': true,
    'encoding': 'utf8',
    'cwd': cwd,
    'timeout': RUN_TIMEOUT_MS,
  });
  if (keepMountPoints != true) SandboxManager.cleanupAfterCommand();
  expect(result.stdout as String, contains('BOOTED'));
  return (stdout: result.stdout as String, stderr: result.stderr as String);
}

// ============================================================================
// Deciding the reading
// ============================================================================

void main() {
  group(
    'literalReadings',
    skip: !isWindows ? false : 'Windows not supported by this port',
    () {
      late String root;
      late String project;
      final savedCwd = process.cwd();

      setUpAll(() {
        root = freshRoot();
        project = join(root, PROJECT);
        fs.mkdirSync(join(project, 'keep'), {'recursive': true});
        fs.mkdirSync(join(project, 'src'), {'recursive': true});
        fs.mkdirSync(join(project, '[ab]'), {'recursive': true});
        fs.writeFileSync(join(project, 'file'), '');
        fs.mkdirSync(join(root, 'plain', '[ab]'), {'recursive': true});
        fs.mkdirSync(join(root, 'plain', 'a'), {'recursive': true});
        fs.mkdirSync(join(root, 'plain', 'b'), {'recursive': true});
        fs.mkdirSync(join(root, 'star'), {'recursive': true});
        fs.writeFileSync(join(root, 'star', '*.env'), '');
        fs.writeFileSync(join(root, 'star', 'a.env'), '');
        for (final name in [
          'open[bracket',
          'close]bracket',
          'build*',
          'notes (draft?)',
          'curly{a,b}',
        ]) {
          fs.mkdirSync(join(root, name, 'out'), {'recursive': true});
        }
        fs.mkdirSync(join(root, 'target', 'keep'), {'recursive': true});
        Link(join(root, 'li[n]k')).createSync(join(root, 'target'));
        Link(join(root, 'dang[l]ing')).createSync(join(root, 'nowhere'));
        fs.mkdirSync(join(project, 'real'), {'recursive': true});
        Link(join(project, 'linked')).createSync(join(root, 'target'));
      });

      tearDownAll(() {
        Directory.current = savedCwd;
        fs.rmSync(root, {'recursive': true, 'force': true});
      });

      tearDown(() {
        Directory.current = savedCwd;
      });

      PathReading name(String path) => PathNameReading(path);
      PathReading beneath(String anchor, String tail) =>
          PathGlobReading(anchor: anchor, path: anchor + tail);
      Map<String, List<PathReading>> bothKinds(String spelling) => {
        'deny': literalReadings(spelling, 'deny'),
        'allow': literalReadings(spelling, 'allow'),
      };
      Map<String, List<PathReading>> forBoth(List<PathReading> readings) => {
        'deny': readings,
        'allow': readings,
      };

      test('reads a path inside the folder as the name it spells', () {
        expect(bothKinds(project), forBoth([name(project)]));
        expect(
          bothKinds(join(project, 'keep')),
          forBoth([name(join(project, 'keep'))]),
        );
      });

      test('does not ask for what follows the glob characters to exist', () {
        final notYet = join(project, 'keep', 'not-there-yet');
        expect(bothKinds(notYet), forBoth([name(notYet)]));
      });

      test(
        'reads a pattern beneath the folder as that pattern beneath its name',
        () {
          expect(
            bothKinds('$project/**/.env'),
            forBoth([beneath(project, '/**/.env')]),
          );
          expect(
            bothKinds('$project/*.pem'),
            forBoth([beneath(project, '/*.pem')]),
          );
        },
      );

      test(
        'takes the longest run of directories that exists as the anchor',
        () {
          expect(
            bothKinds('$project/src/**/.env'),
            forBoth([beneath(join(project, 'src'), '/**/.env')]),
          );
          expect(
            bothKinds('$project/absent/**/.env'),
            forBoth([beneath(project, '/absent/**/.env')]),
          );
        },
      );

      test(
        'reads a wildcard as a name only when a file has that very name',
        () {
          expect(
            bothKinds(join(root, 'star', '*.env')),
            forBoth([name(join(root, 'star', '*.env'))]),
          );
          expect(bothKinds(join(root, 'plain', '*.env')), forBoth([]));
        },
      );

      test(
        'sets a trailing /** aside for the decision and gives it back to a pattern',
        () {
          expect(bothKinds('$project/**'), forBoth([name(project)]));
          expect(
            bothKinds('$project/keep/**'),
            forBoth([name(join(project, 'keep'))]),
          );
          expect(
            bothKinds('$project/**/build/**'),
            forBoth([beneath(project, '/**/build/**')]),
          );
        },
      );

      test('keeps the /** on where brackets alone make no pattern', () {
        // As Windows reads an entry: only `*` and `?` make one a pattern, and
        // the walk reads brackets as a class all the same.
        for (final kind in ['deny', 'allow']) {
          expect(
            literalReadings(
              '$project/**',
              kind,
              isPattern: containsGlobCharsWin,
            ),
            [beneath(project, '/**')],
          );
          expect(
            literalReadings(
              '$project/keep/**',
              kind,
              isPattern: containsGlobCharsWin,
            ),
            [beneath(join(project, 'keep'), '/**')],
          );
          expect(
            literalReadings(
              '$project/keep',
              kind,
              isPattern: containsGlobCharsWin,
            ),
            [],
          );
          expect(
            literalReadings(
              '$root/plain/**',
              kind,
              isPattern: containsGlobCharsWin,
            ),
            [],
          );
        }
      });

      test(
        'strips a trailing separator from a name and keeps it in a pattern',
        () {
          expect(
            bothKinds('$project/keep/'),
            forBoth([name(join(project, 'keep'))]),
          );
          expect(bothKinds('$project/*/'), forBoth([beneath(project, '/*/')]));
        },
      );

      test('folds a parent reference in a name', () {
        expect(
          bothKinds('$project/keep/../src'),
          forBoth([name(join(project, 'src'))]),
        );
      });

      test('leaves a relative name inside a bracketed cwd alone', () {
        Directory.current = project;
        // No glob character in what the caller wrote: it is a name already.
        expect(bothKinds('./keep'), forBoth([]));
        expect(bothKinds('keep'), forBoth([]));
      });

      test(
        'reads a relative pattern inside a bracketed cwd beneath the cwd',
        () {
          Directory.current = project;
          expect(bothKinds('**/.env'), forBoth([beneath(project, '/**/.env')]));
          expect(bothKinds('./*.env'), forBoth([beneath(project, '/*.env')]));
          expect(
            bothKinds('src/**/.env'),
            forBoth([beneath(join(project, 'src'), '/**/.env')]),
          );
        },
      );

      test(
        'reads a ~ spelling beneath a home directory with brackets in its name',
        () {
          final home = join(root, PROJECT);
          // Dart: no second runtime to import path-entries in; HOME is set in this process.
          process.setEnvForTesting({...process.env, 'HOME': home});
          try {
            final result = (
              name: literalReadings('~/keep', 'deny'),
              pattern: literalReadings('~/**/.env', 'deny'),
              allow: literalReadings('~/src/*.ts', 'allow'),
            );
            expect(result.name, []);
            expect(result.pattern, [beneath(home, '/**/.env')]);
            expect(result.allow, [beneath(join(home, 'src'), '/*.ts')]);
          } finally {
            process.setEnvForTesting(null);
          }
        },
      );

      for (final dir in [
        'open[bracket',
        'close]bracket',
        'build*',
        'notes (draft?)',
      ]) {
        test('reads a path inside a directory named $dir as a name', () {
          final inside = join(root, dir, 'out');
          expect(bothKinds(inside), forBoth([name(inside)]));
        });
      }

      test('adds nothing for braces, which are no glob characters', () {
        expect(bothKinds(join(root, 'curly{a,b}', 'out')), forBoth([]));
      });

      test('adds nothing for an entry without glob characters', () {
        expect(bothKinds(join(root, 'plain', 'a')), forBoth([]));
        expect(bothKinds(join(root, 'absent')), forBoth([]));
      });

      test('adds nothing for a pattern none of which exists as a name', () {
        expect(bothKinds(join(root, 'plain', '**', '.env')), forBoth([]));
        expect(bothKinds(join(root, '[nope]', 'x')), forBoth([]));
        expect(bothKinds(join(root, 'plain', '[xy]', 'key')), forBoth([]));
      });

      test('reads [ab] as the class and as the directory of that name', () {
        // The class is the pattern reading every entry has; this adds the name.
        final inClass = join(root, 'plain', '[ab]', 'secret');
        expect(bothKinds(inClass), forBoth([name(inClass)]));
      });

      test(
        'gives one reading for each name the entry may hold, the longest first',
        () {
          expect(
            bothKinds('$project/[ab]/secret'),
            forBoth([
              name(join(project, '[ab]', 'secret')),
              beneath(project, '/[ab]/secret'),
            ]),
          );
          expect(
            bothKinds('$project/[ab]/**/.env'),
            forBoth([
              beneath(join(project, '[ab]'), '/**/.env'),
              beneath(project, '/[ab]/**/.env'),
            ]),
          );
        },
      );

      test('never turns one reading into another when a directory appears', () {
        final entry = '$project/[cd]/**/.env';
        final before = literalReadings(entry, 'deny');
        expect(before, [beneath(project, '/[cd]/**/.env')]);
        fs.mkdirSync(join(project, '[cd]'));
        try {
          final after = literalReadings(entry, 'deny');
          expect(after, [
            beneath(join(project, '[cd]'), '/**/.env'),
            ...before,
          ]);
        } finally {
          fs.rmSync(join(project, '[cd]'), {'recursive': true, 'force': true});
        }
      });

      test(
        'names the anchor in the form a profile goes by',
        skip: isMacOS ? false : 'macOS only',
        () {
          // /tmp is a link to /private/tmp, and a profile's rules go by real paths.
          final held = fs.mkdtempSync('/tmp/literal-anchor-');
          try {
            fs.mkdirSync(join(held, '[deep] p'));
            expect(literalReadings('$held/[deep] p/**/.env', 'deny'), [
              beneath('/private$held/[deep] p', '/**/.env'),
            ]);
          } finally {
            fs.rmSync(held, {'recursive': true, 'force': true});
          }
        },
      );

      test(
        'anchors a pattern at the nearest directory when a file is in the way',
        () {
          // The walk then finds the file where it looked for a directory.
          expect(literalReadings('$project/file/**/x', 'deny'), [
            beneath(project, '/file/**/x'),
          ]);
        },
      );

      group('a prefix that is a symbolic link', () {
        test('counts for a deny, which can only deny more', () {
          final inside = join(root, 'li[n]k', 'keep');
          expect(literalReadings(inside, 'deny'), [name(inside)]);
          expect(literalReadings('$root/li[n]k/**/x', 'deny'), [
            beneath(join(root, 'li[n]k'), '/**/x'),
          ]);
        });

        test(
          'does not count for an allow, which would open what it points at',
          () {
            expect(literalReadings(join(root, 'li[n]k', 'keep'), 'allow'), []);
            expect(literalReadings(join(root, 'li[n]k'), 'allow'), []);
            expect(literalReadings('$root/li[n]k/**/x', 'allow'), []);
          },
        );

        test(
          'counts for a deny when it dangles, as a name and not as a directory',
          () {
            final dangling = join(root, 'dang[l]ing');
            expect(literalReadings(dangling, 'deny'), [name(dangling)]);
            expect(literalReadings('$dangling/**/x', 'deny'), []);
            expect(literalReadings(dangling, 'allow'), []);
            expect(literalReadings('$dangling/**/x', 'allow'), []);
          },
        );

        test(
          'ends the name of an allow wherever it lies after the glob characters',
          () {
            final through = join(project, 'linked', 'keep');
            expect(literalReadings(through, 'deny'), [name(through)]);
            expect(literalReadings(through, 'allow'), []);
            expect(literalReadings(join(project, 'real', 'keep'), 'allow'), [
              name(join(project, 'real', 'keep')),
            ]);
          },
        );

        test(
          'ends the pattern of an allow when it lies before the first pattern component',
          () {
            // The walk would start at `linked`, resolved, and list what it points at.
            for (final tail in [
              '/linked/*/x',
              '/linked/*',
              '/real/../linked/**/x',
            ]) {
              expect(literalReadings(project + tail, 'allow'), []);
            }
            expect(literalReadings('$project/linked/*/x', 'deny'), [
              beneath(join(project, 'linked'), '/*/x'),
            ]);
            // Not there yet is no link, and neither is a directory.
            expect(literalReadings('$project/absent/sub/*', 'allow'), [
              beneath(project, '/absent/sub/*'),
            ]);
            expect(literalReadings('$project/real/*/x', 'allow'), [
              beneath(join(project, 'real'), '/*/x'),
            ]);
            // From the first pattern component on, the walk meets the link itself
            // and does not list it.
            expect(literalReadings('$project/*/linked/x', 'allow'), [
              beneath(project, '/*/linked/x'),
            ]);
          },
        );
      });

      test(
        'takes a path it cannot look at as present for a deny and absent for an allow',
        skip: process.getuid?.call() == 0 ? 'running as root' : false,
        () {
          final locked = join(root, 'locked');
          final inside = join(locked, '[x]', 'secret');
          fs.mkdirSync(join(locked, '[x]'), {'recursive': true});
          fs.chmodSync(locked, 0);
          try {
            expect(literalReadings(inside, 'deny'), [name(inside)]);
            expect(literalReadings(inside, 'allow'), []);
          } finally {
            fs.chmodSync(locked, 493);
          }
        },
      );

      group('a pattern beneath the folder', () {
        late String ordinary;

        setUpAll(() {
          ordinary = join(root, 'ordinary');
          for (final base in [project, ordinary]) {
            fs.mkdirSync(join(base, 'deep', 'er'), {'recursive': true});
            for (final file in [
              'a]x',
              'deep/a]x',
              'deep/er/b]x',
              'deep/.env',
            ]) {
              fs.writeFileSync(join(base, file), '');
            }
          }
        });

        List<String> found(String base, String tail, String kind) =>
            (literalReadings(base + tail, kind)
                  .expand(
                    (reading) => reading.glob
                        ? expandGlobPattern(
                            reading.path,
                            anchor: reading.anchor,
                          )
                        : <String>[],
                  )
                  .map((match) => match.substring(base.length))
                  .toList())
              ..sort();

        for (final tail in ['/**/.env', '/deep/*', '/**/er/*', '/*/*]x']) {
          test(
            'finds for $tail what the same pattern finds beneath an ordinary folder',
            () {
              final expected =
                  (expandGlobPattern(
                      ordinary + tail,
                    ).map((match) => match.substring(ordinary.length)).toList())
                    ..sort();
              expect(expected.length, greaterThan(0));
              expect(found(project, tail, 'deny'), expected);
              expect(found(project, tail, 'allow'), expected);
            },
          );
        }

        for (final (tail, expected) in [
          ('/**/[a*]x', ['/a]x', '/deep/a]x']),
          ('/[a*]x', ['/a]x']),
          ('/deep/[a*]x', ['/deep/a]x']),
        ]) {
          test(
            'matches $tail, which cannot be split, by its spelling from the anchor on',
            () {
              // A wildcard inside a bracket expression: the walk matches such a
              // pattern against whole paths, which beneath an anchor start at it.
              expect(
                (expandGlobPattern(
                    ordinary + tail,
                  ).map((match) => match.substring(ordinary.length)).toList())
                  ..sort(),
                expected,
              );
              expect(found(project, tail, 'deny'), expected);
              expect(found(project, tail, 'allow'), expected);
            },
          );
        }

        test(
          'keeps a trailing separator, with which a pattern matches nothing',
          () {
            expect(expandGlobPattern('$ordinary/*/'), []);
            expect(found(project, '/*/', 'allow'), []);
            expect(found(project, '/*/', 'deny'), []);
          },
        );
      });
    },
  );

  group('path entries as configured', () {
    test('tells spellings from marked paths', () {
      final split = splitPathEntries([
        const FilesystemPathSpelling('/a/*.env'),
        const FilesystemPathLiteral('/a/*.env'),
        const FilesystemPathSpelling('/b'),
        const FilesystemPathLiteral('~/c'),
      ]);
      expect(split.spelled, ['/a/*.env', '/b']);
      expect(split.marked, ['/a/*.env', '~/c']);
      final none = splitPathEntries(null);
      expect(none.spelled, []);
      expect(none.marked, []);
    });

    for (final (what, entry) in <(String, FilesystemPathEntry?)>[
      ('an object without the mark', null),
      ('a mark that is not true', null),
      ('a mark that is a string', null),
      ('a path that is not a string', null),
      ('an empty path', const FilesystemPathLiteral('')),
      ('null', null),
      ('a number', null),
      ('a list', null),
    ]) {
      test(
        'refuses $what rather than guess',
        skip: entry == null
            ? 'Dart: not representable as a FilesystemPathEntry'
            : false,
        () {
          // initialize() runs no schema: this is a hand-built config's only check.
          // Dart: markedLiteralPath throws ArgumentError where Node throws TypeError.
          expect(
            () => splitPathEntries([entry!]),
            throwsA(isA<ArgumentError>()),
          );
        },
      );
    }

    test(
      'tells a marked path from the same spelling, and compares by value',
      () {
        const marked = FilesystemPathLiteral('/a');
        expect(
          samePathEntries([const FilesystemPathSpelling('/a')], [marked]),
          false,
        );
        // updateConfig() clones the config, so the same entry is a new object.
        expect(
          samePathEntries(
            [const FilesystemPathSpelling('/b'), marked],
            [structuredClone(marked), const FilesystemPathSpelling('/b')],
          ),
          true,
        );
        expect(samePathEntries([marked], [marked, marked]), false);
      },
    );

    test('folds the literal lists into the lists they are more entries of', () {
      final folded = readNamesOf(
        FsReadRestrictionConfig(
          denyOnly: ['/d'],
          allowWithinDeny: ['/d/a'],
          unlistableDenyDirs: ['/u'],
          literalDenyOnly: ['/l*'],
          literalAllowWithinDeny: ['/d/l*'],
        ),
      )!;
      expect(folded.denyOnly, ['/d', '/l*']);
      expect(folded.allowWithinDeny, ['/d/a', '/d/l*']);
      expect(folded.unlistableDenyDirs, ['/u']);
      expect(folded.literalDenyOnly, isNull);
      expect(folded.literalAllowWithinDeny, isNull);
      final onlyDeny = readNamesOf(FsReadRestrictionConfig(denyOnly: ['/d']))!;
      expect(onlyDeny.denyOnly, ['/d']);
      expect(onlyDeny.allowWithinDeny, isNull);
      final onlyAllow = readNamesOf(
        FsReadRestrictionConfig(denyOnly: [], literalAllowWithinDeny: ['/a']),
      )!;
      expect(onlyAllow.denyOnly, []);
      expect(onlyAllow.allowWithinDeny, ['/a']);
      final written = writeNamesOf(
        FsWriteRestrictionConfig(
          allowOnly: ['/w'],
          denyWithinAllow: ['/w/d'],
          literalAllowOnly: ['/l*'],
          literalDenyWithinAllow: ['/w/l*'],
        ),
      )!;
      expect(written.allowOnly, ['/w', '/l*']);
      expect(written.denyWithinAllow, ['/w/d', '/w/l*']);
      expect(readNamesOf(null), isNull);
      expect(writeNamesOf(null), isNull);
    });

    test('counts a marked allow among what a write config allows', () {
      expect(writeRootsOf((allowOnly: ['/w'], literalAllowOnly: ['/l*'])), [
        '/w',
        '/l*',
      ]);
      expect(writeRootsOf((allowOnly: ['/w'], literalAllowOnly: null)), ['/w']);
    });
  });

  // ============================================================================
  // Linux: the mounts the wrapper asks for
  // ============================================================================

  /**
   * bubblewrap takes no patterns, so every path the wrapper is handed is a
   * name, and a name is resolved: a trailing separator or `/.` dropped, a
   * parent reference folded. Read as a pattern again, a name with glob
   * characters keeps its spelling, and each case below loses its mount.
   */
  group(
    'Linux wrapper: a name with glob characters, however it is spelled',
    skip: isLinux ? false : 'Linux only',
    () {
      late String root;
      late String project;
      late String sub;
      late String file;

      setUpAll(() {
        root = freshRoot();
        project = join(root, PROJECT);
        sub = join(project, 'sub');
        file = join(sub, 'file');
        fs.mkdirSync(join(sub, 'in'), {'recursive': true});
        fs.writeFileSync(file, '');
      });

      tearDownAll(() {
        fs.rmSync(root, {'recursive': true, 'force': true});
      });

      Future<String> mounts(
        FsReadRestrictionConfig? readConfig,
        FsWriteRestrictionConfig? writeConfig,
      ) => wrapCommandWithSandboxLinux(
        LinuxSandboxParams(
          command: 'true',
          needsNetworkRestriction: false,
          readConfig: readConfig,
          writeConfig: writeConfig,
        ),
      );
      String mount(String flag, String source, [String? dest]) =>
          '$flag ${q(source)} ${q(dest ?? source)}';

      for (final (how, spell) in <(String, String Function(String))>[
        ('a trailing /.', (p) => '$p/.'),
        ('a trailing separator', (p) => '$p/'),
      ]) {
        test(
          'binds an allowRead path back under its own name, spelled with $how',
          () async {
            for (final path in [sub, file]) {
              final command = await mounts(
                FsReadRestrictionConfig(
                  denyOnly: [project],
                  allowWithinDeny: [spell(path)],
                ),
                null,
              );
              expect(command, contains(mount('--ro-bind', path)));
            }
          },
        );
      }

      for (final (how, spell) in <(String, String Function(String))>[
        ('a trailing separator', (p) => '$p/'),
        ('a trailing /.', (p) => '$p/.'),
        (
          'a folder that is not there',
          (p) => p.replaceFirst('/sub', '/absent/../sub'),
        ),
      ]) {
        test('masks a denyRead file spelled with $how', () async {
          final command = await mounts(
            FsReadRestrictionConfig(denyOnly: [spell(file)]),
            null,
          );
          expect(command, contains('--ro-bind /dev/null ${q(file)}'));
        });
      }

      test('takes a denyRead that leads to the root for the root', () async {
        final allowWithinDeny = ['/usr', '/etc', '/bin', '/lib', '/lib64'];
        final up = '/..' * project.split('/').length;
        List<String> tmpfsMounts(String command) => RegExp(
          r'--tmpfs (\S+)',
        ).allMatches(command).map((match) => match[1]!).toList();
        final forRoot = tmpfsMounts(
          await mounts(
            FsReadRestrictionConfig(
              denyOnly: ['/'],
              allowWithinDeny: allowWithinDeny,
            ),
            null,
          ),
        );
        expect(forRoot.length, greaterThan(1));
        expect(
          tmpfsMounts(
            await mounts(
              FsReadRestrictionConfig(
                denyOnly: [project + up],
                allowWithinDeny: allowWithinDeny,
              ),
              null,
            ),
          ),
          forRoot,
        );
      });

      test(
        'applies a denyWrite beneath an allowOnly path spelled through a parent reference',
        () async {
          // The allow is recorded where it resolves to: left as spelled, the
          // deny beneath it would be judged outside every allowed path.
          final command = await mounts(
            null,
            FsWriteRestrictionConfig(
              allowOnly: ['$sub/in/..'],
              denyWithinAllow: [file],
            ),
          );
          expect(command, contains(mount('--bind', sub)));
          expect(command, contains(mount('--ro-bind', file)));
        },
      );

      for (final (how, spell) in <(String, String Function(String))>[
        ('a trailing separator', (p) => '$p/'),
        ('a parent reference', (p) => p.replaceFirst('/sub', '/sub/in/..')),
      ]) {
        test(
          'binds a denyWrite beneath a denied directory once, spelled with $how',
          () async {
            // The directory's own read-only bind covers it, as it does for a path
            // without glob characters.
            final command = await mounts(
              null,
              FsWriteRestrictionConfig(
                allowOnly: [root],
                denyWithinAllow: [project, spell(sub)],
              ),
            );
            expect(command, contains(mount('--ro-bind', project)));
            expect(command, isNot(contains(mount('--ro-bind', sub))));
          },
        );
      }

      test(
        'needs no placeholder beneath a denied directory spelled through a read-denied one',
        () async {
          // The directory is recorded where it resolves to. By its spelling the
          // read deny on `hidden` would seem to cover it, and the placeholder
          // kept for that reason cannot be created beneath a read-only bind.
          final hidden = join(project, 'hidden');
          fs.mkdirSync(hidden, {'recursive': true});
          final absent = join(sub, 'absent');
          final command = await mounts(
            FsReadRestrictionConfig(denyOnly: [hidden]),
            FsWriteRestrictionConfig(
              allowOnly: [root],
              denyWithinAllow: ['$hidden/../sub', absent],
            ),
          );
          expect(command, contains(mount('--ro-bind', sub)));
          expect(command, isNot(contains('--ro-bind /dev/null ${q(absent)}')));
        },
      );
    },
  );

  // ============================================================================
  // Linux: real commands under bubblewrap
  // ============================================================================

  group(
    'Linux: entries inside a folder named [WIP] project',
    skip: isLinux ? false : 'Linux only',
    () {
      // Dart: the probe runs bwrap, which only Linux has.
      final CAN_RUN = isLinux && bwrapCanNamespace();
      final savedCwd = process.cwd();
      late String root;
      late String project;

      setUp(() {
        root = freshRoot();
        project = join(root, PROJECT);
        fs.mkdirSync(join(project, 'keep'), {'recursive': true});
        fs.mkdirSync(join(project, 'real'), {'recursive': true});
        fs.mkdirSync(join(project, 'secrets', 'public'), {'recursive': true});
        fs.mkdirSync(join(project, 'sub', 'deep'), {'recursive': true});
        fs.writeFileSync(join(project, 'keep', 'file'), 'original\n');
        fs.writeFileSync(join(project, 'real', 'file'), 'original\n');
        fs.writeFileSync(join(project, 'secret.txt'), 'SECRET-FILE\n');
        fs.writeFileSync(join(project, 'secrets', 'key'), 'SECRET-DIR\n');
        fs.writeFileSync(join(project, 'secrets', 'public', 'ok'), 'PUBLIC\n');
        fs.writeFileSync(join(project, '.env'), 'ENV-TOP\n');
        fs.writeFileSync(join(project, 'sub', '.env'), 'ENV-SUB\n');
        fs.writeFileSync(join(project, 'sub', 'deep', '.env'), 'ENV-DEEP\n');
        fs.writeFileSync(join(project, 'sub', 'readme'), 'README\n');
        // Outside every allowed path, so the scan for dangerous files in the
        // working directory adds no binds of its own.
        Directory.current = root;
      });

      tearDown(() async {
        Directory.current = savedCwd;
        SandboxManager.cleanupAfterCommand();
        await SandboxManager.reset();
        fs.rmSync(root, {'recursive': true, 'force': true});
      });

      test(
        'makes the project writable when it is allowed',
        skip: CAN_RUN ? false : 'bwrap cannot namespace',
        timeout: const Timeout(Duration(milliseconds: WRAP_TIMEOUT_MS)),
        () async {
          final (:stdout, :stderr) = await sandboxed(
            FilesystemLists(allowWrite: [project]),
            'echo hi > ${q(join(project, 'new'))} && echo WROTE',
            cwd: root,
          );
          expect(stdout, contains('WROTE'));
          expect(fs.readFileSync(join(project, 'new'), 'utf8'), 'hi\n');
        },
      );

      test(
        'enforces a denyWrite inside it',
        skip: CAN_RUN ? false : 'bwrap cannot namespace',
        timeout: const Timeout(Duration(milliseconds: WRAP_TIMEOUT_MS)),
        () async {
          final kept = join(project, 'keep', 'file');
          final (:stdout, :stderr) = await sandboxed(
            FilesystemLists(
              allowWrite: [root],
              denyWrite: [join(project, 'keep')],
            ),
            'echo tampered > ${q(kept)} && echo WROTE; '
            'echo fine > ${q(join(project, 'sub', 'other'))} && echo SIBLING',
            cwd: root,
          );
          expect(stdout, isNot(contains('WROTE')));
          expect(stdout, contains('SIBLING'));
          expect(fs.readFileSync(kept, 'utf8'), 'original\n');
        },
      );

      test(
        'hides a denyRead file and a denyRead directory inside it',
        skip: CAN_RUN ? false : 'bwrap cannot namespace',
        timeout: const Timeout(Duration(milliseconds: WRAP_TIMEOUT_MS)),
        () async {
          final (:stdout, :stderr) = await sandboxed(
            FilesystemLists(
              denyRead: [join(project, 'secret.txt'), join(project, 'secrets')],
            ),
            'cat ${q(join(project, 'secret.txt'))} ${q(join(project, 'secrets', 'key'))}; '
            'cat ${q(join(project, 'sub', 'readme'))}',
            cwd: root,
          );
          expect(stdout, isNot(contains('SECRET-FILE')));
          expect(stdout, isNot(contains('SECRET-DIR')));
          expect(stdout, contains('README'));
        },
      );

      test(
        'opens an allowRead carve-out inside a denied directory',
        skip: CAN_RUN ? false : 'bwrap cannot namespace',
        timeout: const Timeout(Duration(milliseconds: WRAP_TIMEOUT_MS)),
        () async {
          final (:stdout, :stderr) = await sandboxed(
            FilesystemLists(
              denyRead: [join(project, 'secrets')],
              allowRead: [join(project, 'secrets', 'public')],
            ),
            'cat ${q(join(project, 'secrets', 'key'))} ${q(join(project, 'secrets', 'public', 'ok'))}',
            cwd: root,
          );
          expect(stdout, isNot(contains('SECRET-DIR')));
          expect(stdout, contains('PUBLIC'));
        },
      );

      test(
        'opens what an allowRead pattern beneath it matches',
        skip: CAN_RUN ? false : 'bwrap cannot namespace',
        timeout: const Timeout(Duration(milliseconds: WRAP_TIMEOUT_MS)),
        () async {
          final (:stdout, :stderr) = await sandboxed(
            FilesystemLists(
              denyRead: [join(project, 'secrets')],
              allowRead: ['$project/secrets/pub*'],
            ),
            'cat ${q(join(project, 'secrets', 'key'))} ${q(join(project, 'secrets', 'public', 'ok'))}',
            cwd: root,
          );
          expect(stdout, isNot(contains('SECRET-DIR')));
          expect(stdout, contains('PUBLIC'));
        },
      );

      for (final name in ['build*', 'notes (draft?)']) {
        test(
          'opens a carve-out inside a folder named $name, whose name a pattern matches as itself',
          skip: CAN_RUN ? false : 'bwrap cannot namespace',
          timeout: const Timeout(Duration(milliseconds: WRAP_TIMEOUT_MS)),
          () async {
            // The deny is spelled without a `/**`: with one it is the pattern as
            // well, under which every entry beneath keeps a mask of its own.
            final folder = join(root, name);
            fs.mkdirSync(join(folder, 'secrets', 'public'), {
              'recursive': true,
            });
            fs.writeFileSync(join(folder, 'secrets', 'key'), 'SECRET-DIR\n');
            fs.writeFileSync(
              join(folder, 'secrets', 'public', 'ok'),
              'PUBLIC\n',
            );
            final (:stdout, :stderr) = await sandboxed(
              FilesystemLists(
                denyRead: [join(folder, 'secrets')],
                allowRead: [join(folder, 'secrets', 'public')],
              ),
              'cat ${q(join(folder, 'secrets', 'key'))} ${q(join(folder, 'secrets', 'public', 'ok'))}',
              cwd: root,
            );
            expect(stdout, isNot(contains('SECRET-DIR')));
            expect(stdout, contains('PUBLIC'));
          },
        );
      }

      test(
        'masks .env at every depth for a recursive deny beneath it',
        skip: CAN_RUN ? false : 'bwrap cannot namespace',
        timeout: const Timeout(Duration(milliseconds: WRAP_TIMEOUT_MS)),
        () async {
          final (:stdout, :stderr) = await sandboxed(
            FilesystemLists(denyRead: ['$project/**/.env']),
            'cat ${q(join(project, '.env'))} ${q(join(project, 'sub', '.env'))} ${q(join(project, 'sub', 'deep', '.env'))}; '
            'cat ${q(join(project, 'sub', 'readme'))}',
            cwd: root,
          );
          expect(stdout, isNot(matches(RegExp(r'ENV-(TOP|SUB|DEEP)'))));
          expect(stdout, contains('README'));
        },
      );

      test(
        'masks the same for a relative recursive deny when it is the cwd',
        skip: CAN_RUN ? false : 'bwrap cannot namespace',
        timeout: const Timeout(Duration(milliseconds: WRAP_TIMEOUT_MS)),
        () async {
          Directory.current = project;
          final (:stdout, :stderr) = await sandboxed(
            FilesystemLists(denyRead: ['**/.env']),
            'cat .env sub/.env sub/deep/.env; cat sub/readme',
            cwd: project,
          );
          expect(stdout, isNot(matches(RegExp(r'ENV-(TOP|SUB|DEEP)'))));
          expect(stdout, contains('README'));
        },
      );

      test(
        'applies a deny beneath an allow that is spelled through a parent reference',
        skip: CAN_RUN ? false : 'bwrap cannot namespace',
        timeout: const Timeout(Duration(milliseconds: WRAP_TIMEOUT_MS)),
        () async {
          // The allow is recorded where it resolves to: left as spelled, the
          // deny beneath it would be judged outside every allowed path.
          final denied = join(project, 'real', 'file');
          final (:stdout, :stderr) = await sandboxed(
            FilesystemLists(
              allowWrite: ['$project/keep/../real'],
              denyWrite: [denied],
            ),
            'echo tampered > ${q(denied)} && echo WROTE; '
            'echo fine > ${q(join(project, 'real', 'other'))} && echo SIBLING',
            cwd: root,
          );
          expect(stdout, isNot(contains('WROTE')));
          expect(stdout, contains('SIBLING'));
          expect(fs.readFileSync(denied, 'utf8'), 'original\n');
        },
      );

      test(
        'keeps the entries in the write config and resolves the read ones',
        () async {
          await initialize(
            FilesystemLists(
              denyRead: [join(project, 'secret.txt'), '$project/**/.env'],
              allowRead: [join(project, 'secrets', 'public')],
              allowWrite: [project],
              denyWrite: [join(project, 'keep'), '$project/**/*.lock'],
            ),
          );
          final write = SandboxManager.getFsWriteConfig();
          expect(write.allowOnly, contains(project));
          // Write lists take no pattern on Linux, beneath this folder or any other.
          expect(write.denyWithinAllow, [join(project, 'keep')]);
          final read = SandboxManager.getFsReadConfig();
          expect(read.denyOnly, [
            join(project, 'secret.txt'),
            join(project, '.env'),
            join(project, 'sub', '.env'),
            join(project, 'sub', 'deep', '.env'),
          ]);
          expect(read.allowWithinDeny, [join(project, 'secrets', 'public')]);
        },
      );

      test(
        'still reports every write entry whose pattern is not applied',
        () async {
          // Whether an entry is also a name depends on the disk, which the
          // command can change; what is reported does not.
          await initialize(
            FilesystemLists(
              allowWrite: [
                project,
                FilesystemPathLiteral(join(root, 'marked*')),
              ],
              denyWrite: [join(project, 'keep'), '$project/**/*.lock'],
              denyRead: [
                '$project/**/.env',
                const FilesystemPathLiteral('/*/x'),
              ],
            ),
          );
          expect(SandboxManager.getLinuxGlobPatternWarnings(), [
            project,
            join(project, 'keep'),
            '$project/**/*.lock',
          ]);
        },
      );

      test(
        'takes the strings a direct caller hands the wrapper as names',
        skip: CAN_RUN ? false : 'bwrap cannot namespace',
        timeout: const Timeout(Duration(milliseconds: WRAP_TIMEOUT_MS)),
        () async {
          final kept = join(project, 'keep', 'file');
          final wrapped = await wrapCommandWithSandboxLinux(
            LinuxSandboxParams(
              command:
                  'echo BOOTED; echo tampered > ${q(kept)} && echo WROTE; '
                  'cat ${q(join(project, 'secret.txt'))}; '
                  'echo fine > ${q(join(project, 'new'))} && echo SIBLING',
              needsNetworkRestriction: false,
              readConfig: FsReadRestrictionConfig(
                denyOnly: [join(project, 'secret.txt')],
              ),
              writeConfig: FsWriteRestrictionConfig(
                allowOnly: ['$project/'],
                denyWithinAllow: [join(project, 'keep')],
              ),
            ),
          );
          final result = spawnSync(wrapped, [], {
            'shell': true,
            'encoding': 'utf8',
            'cwd': root,
            'timeout': RUN_TIMEOUT_MS,
          });
          expect(result.stdout as String, contains('BOOTED'));
          expect(result.stdout as String, isNot(contains('WROTE')));
          expect(result.stdout as String, isNot(contains('SECRET-FILE')));
          expect(result.stdout as String, contains('SIBLING'));
          expect(fs.readFileSync(kept, 'utf8'), 'original\n');
        },
      );

      for (final (tail, target) in [
        ('*/../keep', 'keep/file'),
        ('[ab]/..', 'secret.txt'),
      ]) {
        test(
          'makes nothing writable for a direct caller that spells $tail, which is not there',
          skip: CAN_RUN ? false : 'bwrap cannot namespace',
          timeout: const Timeout(Duration(milliseconds: WRAP_TIMEOUT_MS)),
          () async {
            // Nothing is named `*` or `[ab]`. Resolved as a name, the string would
            // lose that component to its parent reference and name what is there.
            final kept = join(project, target);
            final before = fs.readFileSync(kept, 'utf8');
            final wrapped = await wrapCommandWithSandboxLinux(
              LinuxSandboxParams(
                command:
                    'echo BOOTED; echo tampered > ${q(kept)} && echo WROTE; echo END',
                needsNetworkRestriction: false,
                readConfig: FsReadRestrictionConfig(denyOnly: []),
                writeConfig: FsWriteRestrictionConfig(
                  allowOnly: ['$project/$tail'],
                  denyWithinAllow: [],
                ),
              ),
            );
            final result = spawnSync(wrapped, [], {
              'shell': true,
              'encoding': 'utf8',
              'cwd': root,
              'timeout': RUN_TIMEOUT_MS,
            });
            expect(result.stdout as String, contains('BOOTED'));
            expect(result.stdout as String, isNot(contains('WROTE')));
            expect(result.stdout as String, contains('END'));
            expect(fs.readFileSync(kept, 'utf8'), before);
          },
        );
      }

      test(
        'makes a path writable that is spelled through a folder that is not there, as beneath any folder',
        skip: CAN_RUN ? false : 'bwrap cannot namespace',
        timeout: const Timeout(Duration(milliseconds: WRAP_TIMEOUT_MS)),
        () async {
          // The project's own name holds the glob characters and exists, so the
          // string is a name, and a name is resolved, parent reference and all.
          final (:stdout, :stderr) = await sandboxed(
            FilesystemLists(allowWrite: ['$project/absent/../real']),
            'echo hi > ${q(join(project, 'real', 'new'))} && echo WROTE; '
            'echo hi > ${q(join(project, 'keep', 'new'))} && echo ESCAPED',
            cwd: root,
          );
          expect(stdout, contains('WROTE'));
          expect(stdout, isNot(contains('ESCAPED')));
        },
      );
    },
  );

  /**
   * What exists is looked at on every wrap, and an earlier command may have
   * put it there: nothing it creates may switch a deny off, and a link with
   * the name an entry spells is not the path an allow takes.
   */
  group(
    'Linux: what a command can change before the next wrap',
    skip: isLinux ? false : 'Linux only',
    () {
      // Dart: the probe runs bwrap, which only Linux has.
      final CAN_RUN = isLinux && bwrapCanNamespace();
      final savedCwd = process.cwd();
      late String root;
      late String work;
      late String vault;

      setUp(() {
        root = freshRoot();
        work = join(root, 'work');
        vault = join(root, 'vault');
        fs.mkdirSync(join(work, 'proj', 'pub'), {'recursive': true});
        fs.mkdirSync(join(vault, 'pub'), {'recursive': true});
        fs.mkdirSync(join(vault, 'deep', 'pub'), {'recursive': true});
        fs.writeFileSync(join(work, 'proj', 'pub', 'ok'), 'PROJECT-PUBLIC\n');
        fs.writeFileSync(join(vault, 'pub', 'key'), 'VAULT-SECRET\n');
        fs.writeFileSync(
          join(vault, 'deep', 'pub', 'key'),
          'VAULT-DEEP-SECRET\n',
        );
        Directory.current = root;
      });

      tearDown(() async {
        Directory.current = savedCwd;
        SandboxManager.cleanupAfterCommand();
        await SandboxManager.reset();
        fs.rmSync(root, {'recursive': true, 'force': true});
      });

      String readVault() =>
          'cat ${q(join(vault, 'pub', 'key'))} ${q(join(vault, 'deep', 'pub', 'key'))} 2>/dev/null; echo END';

      for (final (entry, linkName) in [
        ('work/*/pub', '*'),
        ('work/*/**/pub', '*'),
        ('work/[ab]/pub', '[ab]'),
        ('work/?/pub', '?'),
      ]) {
        test(
          'does not open a denied directory through a link named like $entry spells it',
          skip: CAN_RUN ? false : 'bwrap cannot namespace',
          timeout: const Timeout(Duration(milliseconds: WRAP_TIMEOUT_MS)),
          () async {
            final policy = FilesystemLists(
              denyRead: [vault],
              allowRead: [join(root, entry)],
              allowWrite: [work],
            );
            // The command may write `work`, so it can plant the link itself.
            final planted = await sandboxed(
              policy,
              'ln -s ${q(vault)} ${q(join(work, linkName))} && echo PLANTED',
              cwd: root,
            );
            expect(planted.stdout, contains('PLANTED'));
            await initialize(policy);
            final allowed =
                SandboxManager.getFsReadConfig().allowWithinDeny ?? [];
            expect(allowed.where((p) => p.contains(linkName)).toList(), []);
            final (:stdout, :stderr) = await sandboxed(
              policy,
              readVault(),
              cwd: root,
            );
            expect(stdout, isNot(contains('SECRET')));
            expect(stdout, contains('END'));
          },
        );
      }

      test(
        'does not open one through a link further along the path either',
        skip: CAN_RUN ? false : 'bwrap cannot namespace',
        timeout: const Timeout(Duration(milliseconds: WRAP_TIMEOUT_MS)),
        () async {
          final policy = FilesystemLists(
            denyRead: [vault],
            allowRead: [join(work, '[ab]', 'mid', 'pub')],
            allowWrite: [work],
          );
          final planted = await sandboxed(
            policy,
            'mkdir ${q(join(work, '[ab]'))} && ln -s ${q(vault)} ${q(join(work, '[ab]', 'mid'))} && echo PLANTED',
            cwd: root,
          );
          expect(planted.stdout, contains('PLANTED'));
          final (:stdout, :stderr) = await sandboxed(
            policy,
            readVault(),
            cwd: root,
          );
          expect(stdout, isNot(contains('SECRET')));
        },
      );

      for (final (entry, dirName, linkName) in [
        ('[ab]/mid/*/pub', '[ab]', 'mid'),
        ('[ab]/mid/**/key', '[ab]', 'mid'),
        ('*/dist/*', '*', 'dist'),
      ]) {
        test(
          'does not open a denied directory through a link that a pattern spelled $entry starts beneath',
          skip: CAN_RUN ? false : 'bwrap cannot namespace',
          timeout: const Timeout(Duration(milliseconds: WRAP_TIMEOUT_MS)),
          () async {
            // The command made the directory the entry spells, and the link
            // inside it is what the pattern would be walked from.
            final policy = FilesystemLists(
              denyRead: [vault],
              allowRead: [join(work, entry)],
              allowWrite: [work],
            );
            final planted = await sandboxed(
              policy,
              'mkdir ${q(join(work, dirName))} && ln -s ${q(vault)} ${q(join(work, dirName, linkName))} && echo PLANTED',
              cwd: root,
            );
            expect(planted.stdout, contains('PLANTED'));
            await initialize(policy);
            expect(SandboxManager.getFsReadConfig().allowWithinDeny, []);
            final (:stdout, :stderr) = await sandboxed(
              policy,
              readVault(),
              cwd: root,
            );
            expect(stdout, isNot(contains('SECRET')));
            expect(stdout, contains('END'));
          },
        );
      }

      test(
        'hides a file for a read deny spelled through a link with glob characters in its name',
        skip: CAN_RUN ? false : 'bwrap cannot namespace',
        timeout: const Timeout(Duration(milliseconds: WRAP_TIMEOUT_MS)),
        () async {
          // For a deny a link of that name counts: the entry names the file,
          // by whichever of its names the command asks for it.
          final target = join(root, 'target');
          fs.mkdirSync(target);
          fs.writeFileSync(join(target, 'token'), 'THROUGH-LINK\n');
          Link(join(root, 'li[n]k')).createSync(target);
          final entry = join(root, 'li[n]k', 'token');
          final policy = FilesystemLists(denyRead: [entry]);
          await initialize(policy);
          expect(SandboxManager.getFsReadConfig().denyOnly, [entry]);
          final (:stdout, :stderr) = await sandboxed(
            policy,
            'cat ${q(entry)} ${q(join(target, 'token'))} 2>/dev/null; echo END',
            cwd: root,
          );
          expect(stdout, isNot(contains('THROUGH-LINK')));
          expect(stdout, contains('END'));
        },
      );

      test(
        'adds no name for a write allow spelled through a link with glob characters in its name',
        () async {
          Link(join(work, '[ab]')).createSync(vault);
          await initialize(
            FilesystemLists(
              allowWrite: [join(work, '[ab]', 'pub'), join(work, '[ab]')],
            ),
          );
          expect(
            SandboxManager.getFsWriteConfig().allowOnly
                .where((p) => p.startsWith(root))
                .toList(),
            [],
          );
        },
      );

      test(
        'keeps a class deny in force when a directory with the name of the class appears',
        skip: CAN_RUN ? false : 'bwrap cannot namespace',
        timeout: const Timeout(Duration(milliseconds: WRAP_TIMEOUT_MS)),
        () async {
          final bracketed = join(root, PROJECT);
          fs.mkdirSync(join(bracketed, 'a'), {'recursive': true});
          fs.writeFileSync(join(bracketed, 'a', '.env'), 'ENV-A\n');
          final policy = FilesystemLists(
            denyRead: ['$bracketed/[ab]/**/.env'],
            allowWrite: [bracketed],
          );
          final read =
              'cat ${q(join(bracketed, 'a', '.env'))} ${q(join(bracketed, '[ab]', '.env'))} 2>/dev/null; echo END';
          expect(
            (await sandboxed(policy, read, cwd: root)).stdout,
            isNot(contains('ENV-')),
          );
          final made = await sandboxed(
            policy,
            'mkdir ${q(join(bracketed, '[ab]'))} && echo ENV-LITERAL > ${q(join(bracketed, '[ab]', '.env'))} && echo MADE',
            cwd: root,
          );
          expect(made.stdout, contains('MADE'));
          expect(
            (await sandboxed(policy, read, cwd: root)).stdout,
            isNot(contains('ENV-')),
          );
        },
      );

      test(
        'keeps a write deny in force when the folder cannot be looked at',
        skip: !CAN_RUN
            ? 'bwrap cannot namespace'
            : (process.getuid?.call() == 0 ? 'running as root' : false),
        timeout: const Timeout(Duration(milliseconds: WRAP_TIMEOUT_MS)),
        () async {
          final locked = join(root, 'locked');
          final kept = join(locked, PROJECT, 'keep');
          fs.mkdirSync(kept, {'recursive': true});
          fs.writeFileSync(join(kept, 'file'), 'original\n');
          fs.chmodSync(locked, 0);
          try {
            // The command runs as the same user, so it can undo the chmod.
            final (:stdout, :stderr) = await sandboxed(
              FilesystemLists(allowWrite: [root], denyWrite: [kept]),
              'chmod 755 ${q(locked)}; echo tampered > ${q(join(kept, 'file'))} && echo WROTE; echo END',
              cwd: root,
            );
            expect(stdout, isNot(contains('WROTE')));
            expect(stdout, contains('END'));
          } finally {
            fs.chmodSync(locked, 493);
          }
          expect(fs.readFileSync(join(kept, 'file'), 'utf8'), 'original\n');
        },
      );

      test(
        'takes any write deny with glob characters for the path it spells when the folder cannot be looked at',
        skip: !CAN_RUN
            ? 'bwrap cannot namespace'
            : (process.getuid?.call() == 0 ? 'running as root' : false),
        timeout: const Timeout(Duration(milliseconds: WRAP_TIMEOUT_MS)),
        () async {
          // Whether anything in the folder has the name cannot be told, so a
          // pattern is also applied like a path that is not there: the name is
          // kept from being created, and what it would match is not denied.
          final locked = join(root, 'locked');
          final elsewhere = join(root, 'elsewhere');
          fs.mkdirSync(locked);
          fs.mkdirSync(elsewhere);
          fs.writeFileSync(join(locked, 'a.pem'), 'original\n');
          Future<({List<String> denied, String stdout})> wrapsWith(
            String name,
            String cwd,
          ) async {
            final policy = FilesystemLists(
              allowWrite: [root],
              denyWrite: [join(locked, name)],
            );
            fs.chmodSync(locked, 0);
            // Where the wrap looks for dangerous names is the process's own.
            Directory.current = cwd;
            try {
              await initialize(policy);
              final denied = SandboxManager.getFsWriteConfig().denyWithinAllow;
              final (:stdout, :stderr) = await sandboxed(
                policy,
                'chmod 755 ${q(locked)}; echo x > ${q(join(locked, name))} && echo CREATED; '
                'echo t >> ${q(join(locked, 'a.pem'))} && echo WROTE; echo END',
                cwd: cwd,
              );
              return (denied: denied, stdout: stdout);
            } finally {
              Directory.current = root;
              fs.chmodSync(locked, 493);
            }
          }

          Future<List<String>> leftBy(String name) async {
            final policy = FilesystemLists(
              allowWrite: [root],
              denyWrite: [join(locked, name)],
            );
            fs.chmodSync(locked, 0);
            try {
              await sandboxed(policy, 'echo RAN', cwd: root);
            } finally {
              fs.chmodSync(locked, 493);
            }
            final left = fs
                .readdirSync(locked, withFileTypes: true)
                .map((e) => e.name)
                .where((entry) => entry != 'a.pem')
                .toList();
            for (final entry in left) {
              fs.rmSync(join(locked, entry), {
                'recursive': true,
                'force': true,
              });
            }
            return left;
          }

          for (final name in ['absent', '*.pem']) {
            final (:denied, :stdout) = await wrapsWith(name, elsewhere);
            expect(denied, [join(locked, name)]);
            expect(stdout, isNot(contains('CREATED')));
            expect(stdout, contains('WROTE'));
            expect(stdout, contains('END'));
            expect(fs.existsSync(join(locked, name)), false);

            // Below the working directory the folder is denied whole, because
            // the scan for dangerous names could not read it either: its mode
            // cannot be given back, so what the pattern would match is safe too.
            final below = await wrapsWith(name, root);
            expect(below.denied, [join(locked, name)]);
            expect(below.stdout, isNot(contains('CREATED')));
            expect(below.stdout, isNot(contains('WROTE')));
            expect(below.stdout, contains('END'));
            expect(fs.existsSync(join(locked, name)), false);
          }
          // The folder cannot be cleaned by the host while it cannot be looked
          // at, for a name and for a pattern alike.
          final leftByName = await leftBy('absent');
          expect(
            await leftBy('*.pem'),
            leftByName
                .map((entry) => entry == 'absent' ? '*.pem' : entry)
                .toList(),
          );
        },
      );
    },
  );

  // ============================================================================
  // macOS: the generated profile
  // ============================================================================

  group(
    'macOS profile: entries inside a folder named [WIP] project',
    skip: !isWindows ? false : 'Windows not supported by this port',
    () {
      late String root;
      late String project;

      setUpAll(() {
        root = freshRoot();
        project = join(root, PROJECT);
        fs.mkdirSync(join(project, 'keep'), {'recursive': true});
        fs.mkdirSync(join(project, 'secrets', 'public'), {'recursive': true});
        fs.mkdirSync(join(project, 'sub'), {'recursive': true});
        fs.writeFileSync(join(project, 'secret.txt'), '');
        fs.writeFileSync(join(project, '.env'), '');
      });

      tearDownAll(() {
        fs.rmSync(root, {'recursive': true, 'force': true});
      });

      test('allows writes to the project by subpath', () {
        final profile = macProfile(
          null,
          FsWriteRestrictionConfig(allowOnly: [project], denyWithinAllow: []),
        );
        final allow = ruleOf(profile, '(allow file-write*');
        expect(allow, contains(subpath(project)));
        // The pattern reading is still there, as for any entry.
        expect(allow, contains(patternFilter(project, 'allow')));
      });

      test('denies a write inside it by subpath, and pins the folder', () {
        final kept = join(project, 'keep');
        final profile = macProfile(
          null,
          FsWriteRestrictionConfig(allowOnly: [root], denyWithinAllow: [kept]),
        );
        expect(ruleOf(profile, '(deny file-write*'), contains(subpath(kept)));
        final pinned = ruleOf(
          profile,
          '(deny file-write-unlink file-write-create',
        );
        expect(pinned, contains(subpath(kept)));
        expect(pinned, contains(literalFilter(project)));
        expect(profile, contains(patternFilter(kept, 'deny')));
      });

      test(
        'denies a read of a file and of a directory inside it by subpath',
        () {
          final file = join(project, 'secret.txt');
          final dir = join(project, 'secrets');
          final profile = macProfile(
            FsReadRestrictionConfig(denyOnly: [file, dir]),
            null,
          );
          final deny = ruleOf(profile, '(deny file-read*');
          expect(deny, contains(subpath(file)));
          expect(deny, contains(subpath(dir)));
          expect(deny, contains(patternFilter(file, 'deny')));
        },
      );

      test('re-allows a carve-out inside a denied directory by subpath', () {
        final dir = join(project, 'secrets');
        final open = join(dir, 'public');
        final profile = macProfile(
          FsReadRestrictionConfig(denyOnly: [dir], allowWithinDeny: [open]),
          null,
        );
        expect(ruleOf(profile, '(allow file-read*\n'), contains(subpath(open)));
        // A deny nested in an allow lands again after it; here the allow is the
        // nested one, so the deny is not repeated by name.
        final denies = profile.split('(deny file-read*\n');
        expect(denies[1], contains(subpath(dir)));
      });

      test('denies a recursive pattern beneath it with the folder escaped', () {
        final profile = macProfile(
          FsReadRestrictionConfig(denyOnly: ['$project/**/.env']),
          null,
        );
        final anchored = '^${escapedForRegex(project)}/(.*/)?\\.env(/.*)?\$';
        expect(profile, contains('(regex ${jsonEncode(anchored)})'));
        expect(profile, contains(patternFilter('$project/**/.env', 'deny')));
        final regexes = emittedRegexes(profile);
        for (final denied in [
          '.env',
          'sub/.env',
          'sub/deep/.env',
          '.env/inside',
        ]) {
          expect(regexes.any((re) => re.hasMatch(join(project, denied))), true);
        }
        expect(
          regexes.any((re) => re.hasMatch(join(project, 'sub', 'readme'))),
          false,
        );
        expect(
          ruleOf(profile, '(deny file-write-unlink file-write-create'),
          contains(literalFilter(project)),
        );
      });

      test(
        'takes the project as a write root for the rules that keep denied paths in place',
        () {
          final profile = macProfile(
            FsReadRestrictionConfig(denyOnly: [join(project, 'secrets')]),
            FsWriteRestrictionConfig(allowOnly: [project], denyWithinAllow: []),
          );
          expect(
            ruleOf(profile, '(allow file-write-unlink file-write-create'),
            contains(subpath(project)),
          );
          final tail = profile.substring(
            profile.indexOf(
              'keep read-denied paths inside write roots in place',
            ),
          );
          expect(tail, contains(subpath(join(project, 'secrets'))));
        },
      );

      test('adds no reading for a link with the name an allow spells', () {
        final work = join(root, 'work');
        fs.mkdirSync(join(root, 'vault', 'pub'), {'recursive': true});
        fs.mkdirSync(work, {'recursive': true});
        Link(join(work, '[ab]')).createSync(join(root, 'vault'));
        final entry = join(work, '[ab]', 'pub');
        final asAllow = macProfile(
          FsReadRestrictionConfig(
            denyOnly: [join(root, 'vault')],
            allowWithinDeny: [entry],
          ),
          FsWriteRestrictionConfig(allowOnly: [entry], denyWithinAllow: []),
        );
        expect(emittedSubpaths(asAllow), isNot(contains(entry)));
        expect(
          emittedSubpaths(asAllow),
          isNot(contains(join(root, 'vault', 'pub'))),
        );
        final asDeny = macProfile(
          FsReadRestrictionConfig(denyOnly: [entry]),
          null,
        );
        expect(ruleOf(asDeny, '(deny file-read*'), contains(subpath(entry)));
        final asWriteDeny = macProfile(
          null,
          FsWriteRestrictionConfig(allowOnly: [root], denyWithinAllow: [entry]),
        );
        expect(
          ruleOf(asWriteDeny, '(deny file-write*'),
          contains(subpath(entry)),
        );
      });

      test('compiles an entry as before when none of it is a name on disk', () {
        final profile = macProfile(
          FsReadRestrictionConfig(
            denyOnly: ['/srv/[ab]/secrets', '/srv/**/.env'],
          ),
          FsWriteRestrictionConfig(
            allowOnly: ['/srv/build*'],
            denyWithinAllow: ['/srv/*.lock'],
          ),
        );
        expect(
          emittedSubpaths(profile).where((p) => p.startsWith('/srv')).toList(),
          [],
        );
      });
    },
  );

  // ============================================================================
  // Both readings are both
  // ============================================================================

  group(
    'an entry that is a pattern and a name',
    skip: !isWindows ? false : 'Windows not supported by this port',
    () {
      final CAN_RUN = isLinux && bwrapCanNamespace();
      final savedCwd = process.cwd();
      late String root;
      late String entry;
      final dirs = ['[ab]', 'a', 'b', 'c'];

      setUpAll(() {
        root = freshRoot();
        entry = join(root, '[ab]', 'secret');
        for (final dir in dirs) {
          fs.mkdirSync(join(root, dir), {'recursive': true});
          fs.writeFileSync(join(root, dir, 'secret'), 'SECRET-$dir\n');
        }
        Directory.current = root;
      });

      tearDownAll(() async {
        Directory.current = savedCwd;
        await SandboxManager.reset();
        fs.rmSync(root, {'recursive': true, 'force': true});
      });

      test(
        'resolves to the class matches and to the name on Linux',
        skip: isLinux ? false : 'Linux only',
        () async {
          await initialize(FilesystemLists(denyRead: [entry]));
          expect(
            SandboxManager.getFsReadConfig().denyOnly..sort(),
            ['[ab]', 'a', 'b'].map((dir) => join(root, dir, 'secret')).toList()
              ..sort(),
          );
        },
      );

      test(
        'lists a path once that the pattern and the name both give',
        skip: isLinux ? false : 'Linux only',
        () async {
          final starred = join(root, 'c', '*');
          fs.writeFileSync(starred, '');
          try {
            await initialize(
              FilesystemLists(denyRead: [starred], allowRead: [starred]),
            );
            final read = SandboxManager.getFsReadConfig();
            final both = [join(root, 'c', '*'), join(root, 'c', 'secret')]
              ..sort();
            expect([...read.denyOnly]..sort(), both);
            expect([...(read.allowWithinDeny ?? [])]..sort(), both);
          } finally {
            fs.rmSync(starred);
          }
        },
      );

      test(
        'denies all three under bubblewrap',
        skip: CAN_RUN ? false : 'bwrap cannot namespace',
        timeout: const Timeout(Duration(milliseconds: WRAP_TIMEOUT_MS)),
        () async {
          final (:stdout, :stderr) = await sandboxed(
            FilesystemLists(denyRead: [entry]),
            dirs.map((dir) => 'cat ${q(join(root, dir, 'secret'))}').join('; '),
            cwd: root,
          );
          expect(stdout, isNot(matches(RegExp(r'SECRET-(\[ab\]|a|b)\n'))));
          expect(stdout, contains('SECRET-c'));
        },
      );

      test('covers all three in the macOS profile', () {
        final profile = macProfile(
          FsReadRestrictionConfig(denyOnly: [entry]),
          null,
        );
        final deny = ruleOf(profile, '(deny file-read*');
        final regexes = emittedRegexes(deny);
        final subpaths = emittedSubpaths(deny);
        bool covered(String p) =>
            regexes.any((re) => re.hasMatch(p)) ||
            subpaths.any((s) => p == s || p.startsWith('$s/'));
        for (final dir in ['[ab]', 'a', 'b']) {
          expect(covered(join(root, dir, 'secret')), true);
        }
        expect(covered(join(root, 'c', 'secret')), false);
      });
    },
  );

  // ============================================================================
  // Entries with no such name on disk: nothing changes
  // ============================================================================

  /**
   * Ordinary entries and patterns, under a root that does not exist: no glob
   * character of theirs can be part of a name on disk, so each has its
   * pattern reading alone, and what it resolves to is pinned byte for byte.
   */
  group(
    'entries none of which is a name with glob characters',
    skip: !isWindows ? false : 'Windows not supported by this port',
    () {
      const ROOT = '/srt-literal-path-entries';
      final lists = (
        denyRead: [
          '$ROOT/secrets',
          '$ROOT/home/.ssh/**',
          '$ROOT/proj/**/.env',
          '$ROOT/proj/*.pem',
          '$ROOT/proj/[ab]/key',
          '$ROOT/proj/file?.txt',
          '$ROOT/proj/**/build/**',
        ],
        allowRead: [
          '$ROOT/secrets/public',
          '$ROOT/proj/**/public',
          '$ROOT/home/.ssh/known_hosts',
        ],
        allowWrite: [
          '$ROOT/proj',
          '$ROOT/out/**',
          '$ROOT/build/*',
          '$ROOT/cache/[0-9]',
        ],
        denyWrite: [
          '$ROOT/proj/.git',
          '$ROOT/proj/**/node_modules',
          '$ROOT/proj/locked/**',
          '$ROOT/proj/?.lock',
        ],
      );
      final savedCwd = process.cwd();

      setUpAll(() {
        // The built-in write denies are spelled from the working directory and
        // its ancestors. From the root they are the same on every host.
        Directory.current = '/';
      });

      tearDownAll(() async {
        Directory.current = savedCwd;
        await SandboxManager.reset();
      });

      test(
        'gives the read and write config it gave before',
        skip: isLinux ? false : 'Linux only',
        () async {
          await initialize(
            FilesystemLists(
              denyRead: lists.denyRead,
              allowRead: lists.allowRead,
              allowWrite: lists.allowWrite,
              denyWrite: lists.denyWrite,
            ),
          );
          final read = SandboxManager.getFsReadConfig();
          expect(read.denyOnly, [
            '/srt-literal-path-entries/secrets',
            '/srt-literal-path-entries/home/.ssh',
          ]);
          expect(read.allowWithinDeny, [
            '/srt-literal-path-entries/secrets/public',
            '/srt-literal-path-entries/home/.ssh/known_hosts',
          ]);
          expect(read.unlistableDenyDirs, []);
          // Dart: Object.keys() has no counterpart; the fields upstream leaves unset must be null.
          expect(read.literalDenyOnly, isNull);
          expect(read.literalAllowWithinDeny, isNull);
          expect(read.credentialDenyOnly, isNull);
          expect(read.ownAllowWithinDeny, isNull);

          final write = SandboxManager.getFsWriteConfig();
          expect(write.allowOnly, [
            ...getDefaultWritePaths(),
            '/srt-literal-path-entries/proj',
            '/srt-literal-path-entries/out',
          ]);
          expect(write.denyWithinAllow, [
            '/srt-literal-path-entries/proj/.git',
            '/srt-literal-path-entries/proj/locked',
          ]);
          // Dart: `'literalAllowOnly' in write` is a null field.
          expect(write.literalAllowOnly, isNull);
          // Absent or empty: the two mean the same for this list.
          expect(write.literalDenyWithinAllow ?? [], []);

          expect(SandboxManager.getLinuxGlobPatternWarnings(), [
            '/srt-literal-path-entries/build/*',
            '/srt-literal-path-entries/cache/[0-9]',
            '/srt-literal-path-entries/proj/**/node_modules',
            '/srt-literal-path-entries/proj/?.lock',
          ]);
        },
      );

      test('gives the macOS file rules it gave before', () {
        final wrapped = macProfile(
          FsReadRestrictionConfig(
            denyOnly: lists.denyRead,
            allowWithinDeny: lists.allowRead,
          ),
          FsWriteRestrictionConfig(
            allowOnly: lists.allowWrite,
            denyWithinAllow: lists.denyWrite,
          ),
        );
        expect(fileRulesOf(wrapped), EXPECTED_MACOS_FILE_RULES);
      });
    },
  );

  // ============================================================================
  // The marker
  // ============================================================================

  group(
    'an entry marked literal',
    skip: !isWindows ? false : 'Windows not supported by this port',
    () {
      final CAN_RUN = isLinux && bwrapCanNamespace();
      final savedCwd = process.cwd();
      late String root;
      late String dir;
      late String starred;

      setUp(() {
        root = freshRoot();
        dir = join(root, 'x');
        starred = join(dir, '*.env');
        fs.mkdirSync(dir, {'recursive': true});
        fs.writeFileSync(join(dir, 'a.env'), 'ENV-A\n');
        Directory.current = root;
      });

      tearDown(() async {
        Directory.current = savedCwd;
        SandboxManager.cleanupAfterCommand();
        await SandboxManager.reset();
        fs.rmSync(root, {'recursive': true, 'force': true});
      });

      FilesystemPathEntry marked(String path) => FilesystemPathLiteral(path);

      test(
        'travels in the literal lists, as spelled, and is never expanded',
        () async {
          await initialize(
            FilesystemLists(
              denyRead: [marked(starred), marked('~/x/[y]')],
              allowRead: [marked(join(dir, 'a?'))],
              allowWrite: [marked(join(root, 'out*')), root],
              denyWrite: [marked(join(root, 'keep/**'))],
            ),
          );
          final read = SandboxManager.getFsReadConfig();
          expect(read.denyOnly, []);
          expect(read.allowWithinDeny, []);
          expect(read.literalDenyOnly, [starred, '~/x/[y]']);
          expect(read.literalAllowWithinDeny, [join(dir, 'a?')]);
          final write = SandboxManager.getFsWriteConfig();
          expect(write.allowOnly, [...getDefaultWritePaths(), root]);
          expect(write.literalAllowOnly, [join(root, 'out*')]);
          expect(write.denyWithinAllow, []);
          // A `/**` at the end of a marked path is part of the name.
          expect(write.literalDenyWithinAllow, [join(root, 'keep/**')]);
          if (isLinux) {
            expect(SandboxManager.getLinuxGlobPatternWarnings(), []);
          }
        },
      );

      test(
        'denies the file of that name and not what the pattern would match',
        skip: CAN_RUN ? false : 'bwrap cannot namespace',
        timeout: const Timeout(Duration(milliseconds: WRAP_TIMEOUT_MS)),
        () async {
          final read =
              'cat ${q(join(dir, 'a.env'))}; cat ${q(starred)} 2>/dev/null; echo END';
          final before = await sandboxed(
            FilesystemLists(denyRead: [marked(starred)]),
            read,
            cwd: root,
          );
          expect(before.stdout, contains('ENV-A'));
          fs.writeFileSync(starred, 'ENV-STAR\n');
          final after = await sandboxed(
            FilesystemLists(denyRead: [marked(starred)]),
            read,
            cwd: root,
          );
          expect(after.stdout, contains('ENV-A'));
          expect(after.stdout, isNot(contains('ENV-STAR')));
        },
      );

      test('compiles to a subpath and to no regex in the macOS profile', () {
        final profile = wrapCommandWithSandboxMacOS(
          MacOSSandboxParams(
            command: 'true',
            needsNetworkRestriction: false,
            readConfig: FsReadRestrictionConfig(
              denyOnly: [],
              literalDenyOnly: [starred],
              literalAllowWithinDeny: [join(dir, 'a?')],
            ),
            writeConfig: FsWriteRestrictionConfig(
              allowOnly: [],
              denyWithinAllow: [],
              literalAllowOnly: [join(root, 'out*')],
              literalDenyWithinAllow: [join(root, 'keep[1]')],
            ),
          ),
        );
        expect(ruleOf(profile, '(deny file-read*'), contains(subpath(starred)));
        expect(
          ruleOf(profile, '(allow file-read*\n'),
          contains(subpath(join(dir, 'a?'))),
        );
        expect(
          ruleOf(profile, '(allow file-write*'),
          contains(subpath(join(root, 'out*'))),
        );
        expect(
          ruleOf(profile, '(deny file-write*'),
          contains(subpath(join(root, 'keep[1]'))),
        );
        // No regex of the profile matches what a path would match as a pattern.
        final regexes = emittedRegexes(profile);
        for (final matched in [
          join(dir, 'a.env'),
          join(dir, 'ab'),
          join(root, 'outX'),
          join(root, 'keep1'),
        ]) {
          expect(regexes.any((re) => re.hasMatch(matched)), false);
        }
      });

      test('is a read restriction on its own in the macOS profile', () {
        final wrapped = wrapCommandWithSandboxMacOS(
          MacOSSandboxParams(
            command: 'true',
            needsNetworkRestriction: false,
            readConfig: FsReadRestrictionConfig(
              denyOnly: [],
              literalDenyOnly: [starred],
            ),
            writeConfig: null,
          ),
        );
        expect(wrapped, contains(subpath(starred)));
      });

      test(
        'is a read restriction on its own for the Linux wrapper',
        skip: CAN_RUN ? false : 'bwrap cannot namespace',
        timeout: const Timeout(Duration(milliseconds: WRAP_TIMEOUT_MS)),
        () async {
          fs.writeFileSync(starred, 'ENV-STAR\n');
          final wrapped = await wrapCommandWithSandboxLinux(
            LinuxSandboxParams(
              command: 'cat ${q(starred)} ${q(join(dir, 'a.env'))}',
              needsNetworkRestriction: false,
              readConfig: FsReadRestrictionConfig(
                denyOnly: [],
                literalDenyOnly: [starred],
              ),
              writeConfig: null,
            ),
          );
          final result = spawnSync(wrapped, [], {
            'shell': true,
            'encoding': 'utf8',
            'cwd': root,
            'timeout': RUN_TIMEOUT_MS,
          });
          expect(result.stdout as String, contains('ENV-A'));
          expect(result.stdout as String, isNot(contains('ENV-STAR')));
        },
      );

      test(
        'makes a marked path writable, and a marked path inside it read-only',
        skip: CAN_RUN ? false : 'bwrap cannot namespace',
        timeout: const Timeout(Duration(milliseconds: WRAP_TIMEOUT_MS)),
        () async {
          final out = join(root, 'out*');
          fs.mkdirSync(join(out, 'keep[1]'), {'recursive': true});
          fs.writeFileSync(join(out, 'keep[1]', 'file'), 'original\n');
          fs.mkdirSync(join(root, 'outside'));
          final (:stdout, :stderr) = await sandboxed(
            FilesystemLists(
              allowWrite: [marked(out)],
              denyWrite: [marked(join(out, 'keep[1]'))],
            ),
            'echo hi > ${q(join(out, 'new'))} && echo WROTE; '
            'echo tampered > ${q(join(out, 'keep[1]', 'file'))} && echo TAMPERED; '
            'echo hi > ${q(join(root, 'outside', 'new'))} && echo ESCAPED',
            cwd: root,
          );
          expect(stdout, contains('WROTE'));
          expect(stdout, isNot(contains('TAMPERED')));
          expect(stdout, isNot(contains('ESCAPED')));
          expect(
            fs.readFileSync(join(out, 'keep[1]', 'file'), 'utf8'),
            'original\n',
          );
        },
      );

      test(
        'denies a write to a path that is not there yet, in a folder that is not there yet',
        skip: CAN_RUN ? false : 'bwrap cannot namespace',
        timeout: const Timeout(Duration(milliseconds: WRAP_TIMEOUT_MS)),
        () async {
          // An absent deny path gets a placeholder at its first missing
          // component, which is removed from the host once the command is done.
          final folder = join(root, '[new]');
          final secret = join(folder, 'secret');
          final (:stdout, :stderr) = await sandboxed(
            FilesystemLists(allowWrite: [root], denyWrite: [marked(secret)]),
            'mkdir -p ${q(folder)} 2>/dev/null; echo x > ${q(secret)} && echo CREATED; '
            'echo fine > ${q(join(root, 'other'))} && echo SIBLING',
            cwd: root,
            keepMountPoints: true,
          );
          expect(stdout, isNot(contains('CREATED')));
          expect(stdout, contains('SIBLING'));
          expect(fs.existsSync(secret), false);
          SandboxManager.cleanupAfterCommand();
          expect(fs.existsSync(folder), false);
        },
      );

      test(
        'denies a read of a path that is not there yet from the wrap after it appears',
        skip: CAN_RUN ? false : 'bwrap cannot namespace',
        timeout: const Timeout(Duration(milliseconds: WRAP_TIMEOUT_MS)),
        () async {
          // Nothing is mounted for a read deny whose path is absent, marked or
          // not; the path is looked at again for the next command.
          final late_ = join(root, '[late]', 'secret');
          final policy = FilesystemLists(denyRead: [marked(late_)]);
          final read = 'cat ${q(late_)} 2>/dev/null; echo END';
          expect(
            (await sandboxed(policy, read, cwd: root)).stdout,
            contains('END'),
          );
          fs.mkdirSync(join(root, '[late]'));
          fs.writeFileSync(late_, 'LATE-SECRET\n');
          final (:stdout, :stderr) = await sandboxed(policy, read, cwd: root);
          expect(stdout, isNot(contains('LATE-SECRET')));
        },
      );

      test(
        'keeps the masks of a deny pattern beneath a marked allow',
        skip: CAN_RUN ? false : 'bwrap cannot namespace',
        timeout: const Timeout(Duration(milliseconds: WRAP_TIMEOUT_MS)),
        () async {
          // A match of a deny pattern that a directory match above it already
          // hides gets no mount of its own, unless a path bound back over that
          // directory lies between the two. A marked allow is one such path.
          final vault = join(root, 'tree', 'vault.key');
          final open = join(vault, 'open[1]');
          fs.mkdirSync(open, {'recursive': true});
          fs.writeFileSync(join(vault, 'top'), 'TOP\n');
          fs.writeFileSync(join(open, 'ok'), 'OPEN\n');
          fs.writeFileSync(join(open, 'inner.key'), 'INNER\n');
          final (:stdout, :stderr) = await sandboxed(
            FilesystemLists(
              denyRead: ['$root/tree/**/*.key'],
              allowRead: [marked(open)],
            ),
            'cat ${q(join(vault, 'top'))} ${q(join(open, 'inner.key'))} 2>/dev/null; '
            'cat ${q(join(open, 'ok'))}',
            cwd: root,
          );
          expect(stdout, isNot(contains('TOP')));
          expect(stdout, isNot(contains('INNER')));
          expect(stdout, contains('OPEN'));
        },
      );

      test(
        'keeps them beneath a marked write allow too',
        skip: CAN_RUN ? false : 'bwrap cannot namespace',
        timeout: const Timeout(Duration(milliseconds: WRAP_TIMEOUT_MS)),
        () async {
          final vault = join(root, 'tree', 'vault.key');
          final out = join(vault, 'out[1]');
          fs.mkdirSync(out, {'recursive': true});
          fs.writeFileSync(join(vault, 'top'), 'TOP\n');
          fs.writeFileSync(join(out, 'inner.key'), 'INNER\n');
          final (:stdout, :stderr) = await sandboxed(
            FilesystemLists(
              denyRead: ['$root/tree/**/*.key'],
              allowWrite: [marked(out)],
            ),
            'cat ${q(join(vault, 'top'))} ${q(join(out, 'inner.key'))} 2>/dev/null; '
            'echo hi > ${q(join(out, 'new'))} && echo WROTE',
            cwd: root,
          );
          expect(stdout, isNot(contains('TOP')));
          expect(stdout, isNot(contains('INNER')));
          expect(stdout, contains('WROTE'));
        },
      );

      test(
        'reaches the wrap from a per-command config',
        skip: CAN_RUN ? false : 'bwrap cannot namespace',
        timeout: const Timeout(Duration(milliseconds: WRAP_TIMEOUT_MS)),
        () async {
          fs.writeFileSync(starred, 'ENV-STAR\n');
          final (:stdout, :stderr) = await sandboxed(
            const FilesystemLists(),
            'cat ${q(join(dir, 'a.env'))}; cat ${q(starred)} 2>/dev/null; echo END',
            cwd: root,
            perWrap: FilesystemLists(denyRead: [marked(starred)]),
          );
          expect(stdout, contains('ENV-A'));
          expect(stdout, isNot(contains('ENV-STAR')));
        },
      );

      test(
        'reaches the wrap from a per-command config in each of the four lists',
        skip: CAN_RUN ? false : 'bwrap cannot namespace',
        timeout: const Timeout(Duration(milliseconds: WRAP_TIMEOUT_MS)),
        () async {
          final out = join(root, 'out*');
          final kept = join(out, 'keep[1]', 'file');
          final secrets = join(root, 'secrets?');
          final open = join(secrets, 'open[1]');
          fs.mkdirSync(join(out, 'keep[1]'), {'recursive': true});
          fs.mkdirSync(open, {'recursive': true});
          fs.writeFileSync(kept, 'original\n');
          fs.writeFileSync(join(secrets, 'key'), 'SECRET\n');
          fs.writeFileSync(join(open, 'ok'), 'OPEN\n');
          final (:stdout, :stderr) = await sandboxed(
            const FilesystemLists(),
            'echo hi > ${q(join(out, 'new'))} && echo WROTE; '
            'echo tampered > ${q(kept)} && echo TAMPERED; '
            'cat ${q(join(secrets, 'key'))} ${q(join(open, 'ok'))} 2>/dev/null; echo END',
            cwd: root,
            perWrap: FilesystemLists(
              denyRead: [marked(secrets)],
              allowRead: [marked(open)],
              allowWrite: [marked(out)],
              denyWrite: [marked(join(out, 'keep[1]'))],
            ),
          );
          expect(stdout, contains('WROTE'));
          expect(stdout, isNot(contains('TAMPERED')));
          expect(stdout, isNot(contains('SECRET')));
          expect(stdout, contains('OPEN'));
          expect(stdout, contains('END'));
          expect(fs.readFileSync(kept, 'utf8'), 'original\n');
        },
      );

      test(
        'is in the lists the violation monitor judges a write by',
        skip: isLinux ? false : 'Linux only',
        timeout: const Timeout(Duration(milliseconds: WRAP_TIMEOUT_MS)),
        () async {
          final out = join(root, 'out*');
          final kept = join(out, 'keep[1]');
          fs.mkdirSync(kept, {'recursive': true});
          LinuxViolationMonitorOptions? handedOver;
          final original =
              linux_violation_monitor_module.startLinuxSandboxViolationMonitor;
          linux_violation_monitor_module.startLinuxSandboxViolationMonitor =
              (callback, opts) {
                handedOver = opts;
                return LinuxViolationMonitor(
                  observeSocketPath: () => null,
                  ready: Future.value(),
                  stop: () {},
                );
              };
          try {
            await SandboxManager.reset();
            await SandboxManager.initialize(
              SandboxRuntimeConfig(
                network: noNetwork,
                filesystem: FilesystemConfig(
                  denyRead: [],
                  allowWrite: [marked(out)],
                  denyWrite: [marked(kept)],
                ),
              ),
              null,
              true,
            );
          } finally {
            linux_violation_monitor_module.startLinuxSandboxViolationMonitor =
                original;
          }
          expect(handedOver?.allowWritePaths, contains(out));
          expect(handedOver?.denyWritePaths, contains(kept));

          // The listener itself, with what the manager handed over: a write the
          // sandbox permits is no violation, and one it refuses is.
          final lines = <String>[];
          final monitor = linux_violation_monitor_module
              .startLinuxSandboxViolationMonitor(
                (violation) => lines.add(violation.line),
                handedOver!,
              );
          await monitor.ready;
          try {
            final done = Completer<void>();
            // Dart: the callback names `client`, so it is declared first.
            late final net.NodeSocket client;
            client = net.connect(monitor.observeSocketPath!, () {
              client.write(
                '${[join(out, 'new'), join(kept, 'file')].map((path) => jsonEncode({'syscall': 'openat', 'path': path})).join('\n')}\n',
              );
              client.end();
            });
            client.on('close', () => done.complete());
            client.on('error', (Object e) => done.completeError(e));
            await done.future;
            await Future<void>.delayed(const Duration(milliseconds: 50));
            expect(lines, ['deny openat ${join(kept, 'file')}']);
          } finally {
            monitor.stop();
          }
        },
      );

      test(
        'comes back from getConfig() and updateConfig() as it went in',
        () async {
          final filesystem = FilesystemLists(
            denyRead: [marked(starred), join(dir, 'plain')],
            allowRead: [marked(join(dir, 'a?'))],
            allowWrite: [marked(join(root, 'out*'))],
            denyWrite: [marked(join(root, 'keep[1]'))],
          );
          await initialize(filesystem);
          expect(
            SandboxManager.getConfig()?.filesystem.toJson(),
            _filesystemOf(filesystem).toJson(),
          );
          final updated = FilesystemLists(
            denyRead: [marked(join(dir, '[later]'))],
            allowRead: filesystem.allowRead,
            allowWrite: filesystem.allowWrite,
            denyWrite: filesystem.denyWrite,
          );
          SandboxManager.updateConfig(
            SandboxRuntimeConfig(
              network: noNetwork,
              filesystem: _filesystemOf(updated),
            ),
          );
          expect(
            SandboxManager.getConfig()?.filesystem.toJson(),
            _filesystemOf(updated).toJson(),
          );
          expect(SandboxManager.getFsReadConfig().literalDenyOnly, [
            join(dir, '[later]'),
          ]);
        },
      );

      test(
        'comes back from a settings file and from a control line as it went in',
        () {
          final config = <String, Object?>{
            'network': {'allowedDomains': [], 'deniedDomains': []},
            'filesystem': {
              'denyRead': [marked(starred), '/plain/*.pem'],
              'allowRead': [marked('~/a?')],
              'allowWrite': [marked('./out*')],
              'denyWrite': [marked(join(root, 'keep[1]/'))],
            },
          };
          final file = join(root, 'settings.json');
          fs.writeFileSync(file, jsonEncode(config));
          final loaded = loadConfig(file);
          expect(loaded.kind, 'ok');
          expect(
            loaded is LoadConfigResultOk
                ? loaded.config.filesystem.toJson()
                : false,
            jsonDecode(jsonEncode(config['filesystem'])),
          );
          expect(
            loadConfigFromString(jsonEncode(config))?.filesystem.toJson(),
            jsonDecode(jsonEncode(config['filesystem'])),
          );
        },
      );

      test('is refused by a settings file when the mark is not the mark', () {
        final file = join(root, 'settings.json');
        fs.writeFileSync(
          file,
          jsonEncode({
            'network': {'allowedDomains': [], 'deniedDomains': []},
            'filesystem': {
              'denyRead': [
                {'path': starred, 'literal': false},
              ],
              'allowWrite': [],
              'denyWrite': [],
            },
          }),
        );
        final loaded = loadConfig(file);
        expect(loaded.kind, 'invalid');
        expect(
          loaded is LoadConfigResultInvalid ? loaded.reason : false,
          contains(
            'filesystem.denyRead.0: Expected a path, or { "path": "<path>", "literal": true }',
          ),
        );
      });

      test(
        'is refused at the wrap when a config that skipped the schema holds half a mark',
        skip:
            'Dart: a half mark { path } is not representable as a FilesystemPathEntry',
        () async {
          // await initialize({
          //   denyRead: [{ path: starred } as unknown as FilesystemPathEntry],
          // })
          // const refusal = 'must be a path, or { path, literal: true }'
          // expect(() => SandboxManager.getFsReadConfig()).toThrow(refusal)
          // expect(() => SandboxManager.getFsWriteConfig()).toThrow(refusal)
          // await expect(SandboxManager.wrapWithSandbox('true')).rejects.toThrow(refusal)
        },
      );
    },
  );

  group(
    'default write paths under read rules with a name in them',
    skip: !isWindows ? false : 'Windows not supported by this port',
    () {
      // Dart: the body runs in this process with HOME set, not in a second runtime.
      Future<Object?> under(
        String home,
        Future<Object?> Function() body,
      ) async {
        process.setEnvForTesting({...process.env, 'HOME': home});
        try {
          return await body();
        } finally {
          process.setEnvForTesting(null);
        }
      }

      List<String> kept(List<String> paths) => paths
          .where((p) => p.endsWith('/debug') || p.endsWith('/_logs'))
          .map((p) => p.split('/').sublist(p.split('/').length - 2).join('/'))
          .toList();

      late String root;

      setUpAll(() {
        root = freshRoot();
        for (final home in ['home', '[home]']) {
          fs.mkdirSync(join(root, home, '.claude', 'debug'), {
            'recursive': true,
          });
          fs.mkdirSync(join(root, home, '.npm', '_logs'), {'recursive': true});
        }
      });

      tearDownAll(() {
        fs.rmSync(root, {'recursive': true, 'force': true});
      });

      test(
        'drops a directory a marked deny covers and keeps one a marked allow re-opens',
        () async {
          expect(
            await under(join(root, 'home'), () async {
              return {
                'denied': kept(
                  getDefaultWritePaths(
                    denyRead: [const FilesystemPathLiteral('~/.claude')],
                  ),
                ),
                'reopened': kept(
                  getDefaultWritePaths(
                    denyRead: [const FilesystemPathLiteral('~/.claude')],
                    allowRead: [const FilesystemPathLiteral('~/.claude/debug')],
                  ),
                ),
                'asPattern': kept(
                  getDefaultWritePaths(
                    denyRead: [const FilesystemPathLiteral('~/.c*')],
                  ),
                ),
              };
            }),
            {
              'denied': ['.npm/_logs'],
              'reopened': ['.npm/_logs', '.claude/debug'],
              'asPattern': ['.npm/_logs', '.claude/debug'],
            },
          );
        },
      );

      test(
        'counts a deny spelled inside a home directory with brackets in its name',
        () async {
          final home = join(root, '[home]');
          expect(
            await under(home, () async {
              FilesystemLists config(FilesystemLists filesystem) => filesystem;
              await SandboxManager.initialize(
                SandboxRuntimeConfig(
                  network: noNetwork,
                  filesystem: _filesystemOf(
                    config(FilesystemLists(denyRead: [join(home, '.claude')])),
                  ),
                ),
                null,
                false,
              );
              final denied = kept(SandboxManager.getFsWriteConfig().allowOnly);
              await SandboxManager.reset();
              await SandboxManager.initialize(
                SandboxRuntimeConfig(
                  network: noNetwork,
                  filesystem: _filesystemOf(
                    config(
                      FilesystemLists(
                        denyRead: [join(home, '.claude')],
                        allowRead: [join(home, '.claude', 'debug')],
                      ),
                    ),
                  ),
                ),
                null,
                false,
              );
              final reopened = kept(
                SandboxManager.getFsWriteConfig().allowOnly,
              );
              await SandboxManager.reset();
              return {'denied': denied, 'reopened': reopened};
            }),
            {
              'denied': ['.npm/_logs'],
              'reopened': ['.npm/_logs', '.claude/debug'],
            },
          );
        },
      );
    },
  );
}

/** The file rules of a wrapped command's profile, log tag replaced. */
String fileRulesOf(String wrapped) {
  final from = wrapped.indexOf('; File read');
  final to = wrapped.indexOf("' ", from);
  return wrapped
      .substring(from, to)
      .replaceAll(RegExp(r'CMD64_.*?_SBX'), '<tag>');
}

const EXPECTED_MACOS_FILE_RULES = r'''
; File read
(allow file-read*)
(deny file-read*
  (subpath "/srt-literal-path-entries/secrets")
  (regex "^/srt-literal-path-entries/home/\\.ssh/.*(/.*)?$")
  (regex "^/srt-literal-path-entries/proj/(.*/)?\\.env(/.*)?$")
  (regex "^/srt-literal-path-entries/proj/[^/]*\\.pem(/.*)?$")
  (regex "^/srt-literal-path-entries/proj/[ab]/key(/.*)?$")
  (regex "^/srt-literal-path-entries/proj/file[^/]\\.txt(/.*)?$")
  (regex "^/srt-literal-path-entries/proj/(.*/)?build/.*(/.*)?$")
  (with message "<tag>"))
(allow file-read*
  (subpath "/srt-literal-path-entries/secrets/public")
  (regex "^/srt-literal-path-entries/proj/(.*/)?public$")
  (subpath "/srt-literal-path-entries/home/.ssh/known_hosts")
  (with message "<tag>"))
(deny file-read*
  (require-all (regex "^/srt-literal-path-entries/home/\\.ssh/.*(/.*)?$") (require-not (subpath "/srt-literal-path-entries/home/.ssh/known_hosts")))
  (regex "^/srt-literal-path-entries/proj/(.*/)?\\.env(/.*)?$")
  (regex "^/srt-literal-path-entries/proj/[^/]*\\.pem(/.*)?$")
  (regex "^/srt-literal-path-entries/proj/[ab]/key(/.*)?$")
  (regex "^/srt-literal-path-entries/proj/file[^/]\\.txt(/.*)?$")
  (regex "^/srt-literal-path-entries/proj/(.*/)?build/.*(/.*)?$")
  (with message "<tag>"))
(allow file-read-metadata
  (vnode-type DIRECTORY))
(deny file-write-unlink file-write-create
  (subpath "/srt-literal-path-entries/secrets")
  (literal "/srt-literal-path-entries")
  (regex "^/srt-literal-path-entries/home/\\.ssh/.*(/.*)?$")
  (literal "/srt-literal-path-entries/home/.ssh")
  (literal "/srt-literal-path-entries/home")
  (regex "^/srt-literal-path-entries/proj/(.*/)?\\.env(/.*)?$")
  (literal "/srt-literal-path-entries/proj")
  (regex "^/srt-literal-path-entries/proj/[^/]*\\.pem(/.*)?$")
  (regex "^/srt-literal-path-entries/proj/[ab]/key(/.*)?$")
  (regex "^/srt-literal-path-entries/proj/file[^/]\\.txt(/.*)?$")
  (regex "^/srt-literal-path-entries/proj/(.*/)?build/.*(/.*)?$")
  (with message "<tag>"))
(allow file-write-unlink file-write-create
  (subpath "/srt-literal-path-entries/proj")
  (regex "^/srt-literal-path-entries/out/.*$")
  (regex "^/srt-literal-path-entries/build/[^/]*$")
  (regex "^/srt-literal-path-entries/cache/[0-9]$")
  (with message "<tag>"))

; File write
(allow file-write*
  (subpath "/srt-literal-path-entries/proj")
  (regex "^/srt-literal-path-entries/out/.*$")
  (regex "^/srt-literal-path-entries/build/[^/]*$")
  (regex "^/srt-literal-path-entries/cache/[0-9]$")
  (with message "<tag>"))
(deny file-write*
  (subpath "/srt-literal-path-entries/proj/.git")
  (regex "^/srt-literal-path-entries/proj/(.*/)?node_modules(/.*)?$")
  (regex "^/srt-literal-path-entries/proj/locked/.*(/.*)?$")
  (regex "^/srt-literal-path-entries/proj/[^/]\\.lock(/.*)?$")
  (subpath "/.gitconfig")
  (regex "^/(.*/)?\\.gitconfig(/.*)?$")
  (subpath "/.gitmodules")
  (regex "^/(.*/)?\\.gitmodules(/.*)?$")
  (subpath "/.bashrc")
  (regex "^/(.*/)?\\.bashrc(/.*)?$")
  (subpath "/.bash_profile")
  (regex "^/(.*/)?\\.bash_profile(/.*)?$")
  (subpath "/.zshrc")
  (regex "^/(.*/)?\\.zshrc(/.*)?$")
  (subpath "/.zprofile")
  (regex "^/(.*/)?\\.zprofile(/.*)?$")
  (subpath "/.profile")
  (regex "^/(.*/)?\\.profile(/.*)?$")
  (subpath "/.ripgreprc")
  (regex "^/(.*/)?\\.ripgreprc(/.*)?$")
  (subpath "/.mcp.json")
  (regex "^/(.*/)?\\.mcp\\.json(/.*)?$")
  (subpath "/.vscode")
  (regex "^/(.*/)?\\.vscode/.*(/.*)?$")
  (subpath "/.idea")
  (regex "^/(.*/)?\\.idea/.*(/.*)?$")
  (subpath "/.claude/commands")
  (regex "^/(.*/)?\\.claude/commands/.*(/.*)?$")
  (subpath "/.claude/agents")
  (regex "^/(.*/)?\\.claude/agents/.*(/.*)?$")
  (subpath "/.git/hooks")
  (regex "^/(.*/)?\\.git/hooks/.*(/.*)?$")
  (subpath "/.git/config")
  (regex "^/(.*/)?\\.git/config(/.*)?$")
  (with message "<tag>"))
(deny file-write-unlink file-write-create
  (subpath "/srt-literal-path-entries/proj/.git")
  (literal "/srt-literal-path-entries/proj")
  (literal "/srt-literal-path-entries")
  (regex "^/srt-literal-path-entries/proj/(.*/)?node_modules(/.*)?$")
  (regex "^/srt-literal-path-entries/proj/locked/.*(/.*)?$")
  (literal "/srt-literal-path-entries/proj/locked")
  (regex "^/srt-literal-path-entries/proj/[^/]\\.lock(/.*)?$")
  (subpath "/.gitconfig")
  (regex "^/(.*/)?\\.gitconfig(/.*)?$")
  (subpath "/.gitmodules")
  (regex "^/(.*/)?\\.gitmodules(/.*)?$")
  (subpath "/.bashrc")
  (regex "^/(.*/)?\\.bashrc(/.*)?$")
  (subpath "/.bash_profile")
  (regex "^/(.*/)?\\.bash_profile(/.*)?$")
  (subpath "/.zshrc")
  (regex "^/(.*/)?\\.zshrc(/.*)?$")
  (subpath "/.zprofile")
  (regex "^/(.*/)?\\.zprofile(/.*)?$")
  (subpath "/.profile")
  (regex "^/(.*/)?\\.profile(/.*)?$")
  (subpath "/.ripgreprc")
  (regex "^/(.*/)?\\.ripgreprc(/.*)?$")
  (subpath "/.mcp.json")
  (regex "^/(.*/)?\\.mcp\\.json(/.*)?$")
  (subpath "/.vscode")
  (regex "^/(.*/)?\\.vscode/.*(/.*)?$")
  (subpath "/.idea")
  (regex "^/(.*/)?\\.idea/.*(/.*)?$")
  (subpath "/.claude/commands")
  (literal "/.claude")
  (regex "^/(.*/)?\\.claude/commands/.*(/.*)?$")
  (subpath "/.claude/agents")
  (regex "^/(.*/)?\\.claude/agents/.*(/.*)?$")
  (subpath "/.git/hooks")
  (literal "/.git")
  (regex "^/(.*/)?\\.git/hooks/.*(/.*)?$")
  (subpath "/.git/config")
  (regex "^/(.*/)?\\.git/config(/.*)?$")
  (with message "<tag>"))

; File read: keep read-denied paths inside write roots in place
(deny file-write-unlink
  (require-all (regex "^/srt-literal-path-entries/home/\\.ssh/.*(/.*)?$") (require-not (subpath "/srt-literal-path-entries/home/.ssh/known_hosts")))
  (regex "^/srt-literal-path-entries/proj/(.*/)?\\.env(/.*)?$")
  (regex "^/srt-literal-path-entries/proj/[^/]*\\.pem(/.*)?$")
  (regex "^/srt-literal-path-entries/proj/[ab]/key(/.*)?$")
  (regex "^/srt-literal-path-entries/proj/file[^/]\\.txt(/.*)?$")
  (regex "^/srt-literal-path-entries/proj/(.*/)?build/.*(/.*)?$")
  (with message "<tag>"))''';
