// Ported from sandbox-runtime test/sandbox/read-deny-glob.test.ts @ 24eb39e.
// ignore_for_file: constant_identifier_names, non_constant_identifier_names, slash_for_doc_comments, curly_braces_in_flow_control_structures, prefer_interpolation_to_compose_strings

import 'dart:io';
import 'dart:math' as math;

import 'package:path/path.dart' show join;
import 'package:test/test.dart';

// The namespace the library binds, so a spy on it is seen by the code under
// test (see linux-ancestor-pin-errno.test.ts).
import 'package:sandbox_runtime/src/node/fs.dart' as fs;
import 'package:sandbox_runtime/src/node/fs.dart'
    show
        chmodSync,
        existsSync,
        lstatSync,
        mkdirSync,
        mkdtempSync,
        realpathSync,
        rmSync,
        writeFileSync;
import 'package:sandbox_runtime/src/node/child_process.dart' show spawnSync;
import 'package:sandbox_runtime/src/node/errno.dart' show NodeError;
import 'package:sandbox_runtime/src/node/os.dart' show tmpdir;
import 'package:sandbox_runtime/src/node/process.dart' as process;
import 'package:sandbox_runtime/src/sandbox/read_deny_glob.dart';
import 'package:sandbox_runtime/src/sandbox/sandbox_utils.dart';
import 'package:sandbox_runtime/src/sandbox/sandbox_manager.dart';
import 'package:sandbox_runtime/src/sandbox/sandbox_config.dart';
import 'package:sandbox_runtime/src/sandbox/sandbox_schemas.dart';
import 'package:sandbox_runtime/src/sandbox/linux_sandbox_utils.dart';
import '../helpers/platform.dart';
import '../helpers/bwrap_namespace.dart';
import '../helpers/bwrap_argv.dart';
import '../helpers/captured_warnings.dart';

// Node's `fs.symlinkSync`, which no shim has.
void symlinkSync(String target, String linkPath) =>
    Link(linkPath).createSync(target);

void main() {
  group(
    'expandReadDenyGlobLinux (collapse)',
    skip: !isWindows ? null : 'Windows not supported by this port',
    () {
      late String ROOT;

      setUpAll(() {
        ROOT = realpathSync(mkdtempSync(join(tmpdir(), 'deny-glob-rules-')));
        // build/ and its string-prefix sibling build-cache/, each with a nested
        // directory.
        for (final dir in ['build', 'build-cache']) {
          mkdirSync(join(ROOT, dir, 'sub'), {'recursive': true});
          writeFileSync(join(ROOT, dir, '1.out'), '');
          writeFileSync(join(ROOT, dir, 'sub', '2.out'), '');
        }
      });

      tearDownAll(() {
        rmSync(ROOT, {'recursive': true, 'force': true});
      });

      test('does not treat a string-prefix sibling as an ancestor', () {
        final mounts = expandReadDenyGlobLinux(join(ROOT, 'build*/**'), []);
        expect(mounts, [join(ROOT, 'build'), join(ROOT, 'build-cache')]);
      });

      test(
        'treats a re-exposer AT the covering directory as re-exposing everything beneath it',
        () {
          // denyRead and allowRead naming the same directory: its tmpfs is bound
          // back at once, so every match beneath needs its own mount.
          final build = join(ROOT, 'build');
          final mounts = expandReadDenyGlobLinux(join(ROOT, 'build*/**'), [
            build,
          ]);
          expect(mounts, [
            build,
            join(ROOT, 'build-cache'),
            join(build, '1.out'),
            join(build, 'sub'),
          ]);
        },
      );

      test('ignores re-exposers below the candidate or unrelated to it', () {
        final mounts = expandReadDenyGlobLinux(join(ROOT, 'build*/**'), [
          join(ROOT, 'build', 'sub', '2.out', 'deeper'),
          join(ROOT, 'buildx'),
          '/elsewhere',
        ]);
        expect(mounts, [join(ROOT, 'build'), join(ROOT, 'build-cache')]);
      });

      test(
        'denies a directory it cannot list as a whole',
        skip: process.getuid?.call() != 0 ? null : 'running as root',
        () {
          // Searchable but not listable (what a sandboxed command with write
          // access to the tree can leave for the next wrap): the matches beneath
          // it cannot be found, so the directory itself is the mount.
          final locked = join(ROOT, 'locked');
          mkdirSync(join(locked, 'build'), {'recursive': true});
          writeFileSync(join(locked, 'build', 'secret.out'), '');
          chmodSync(locked, 201); // 0o311
          try {
            final mounts = expandReadDenyGlobLinux(
              join(ROOT, '**/build/**'),
              [],
            );
            expect(mounts, contains(locked));
            expect(mounts, contains(join(ROOT, 'build')));
          } finally {
            chmodSync(locked, 493); // 0o755
            rmSync(locked, {'recursive': true, 'force': true});
          }
        },
      );

      test(
        'leaves alone an unlistable directory the pattern cannot match beneath',
        skip: process.getuid?.call() != 0 ? null : 'running as root',
        () {
          // certs/*.pem matches at one depth: certs/pgdata (a volume owned by
          // another user, say) holds no match whatever it contains, and as a
          // tmpfs it would be an empty directory whose writes go nowhere.
          final certs = join(ROOT, 'certs');
          mkdirSync(join(certs, 'pgdata'), {'recursive': true});
          writeFileSync(join(certs, 'top.pem'), '');
          chmodSync(join(certs, 'pgdata'), 0); // 0o000
          try {
            expect(expandReadDenyGlobLinux(join(certs, '*.pem'), []), [
              join(certs, 'top.pem'),
            ]);
          } finally {
            chmodSync(join(certs, 'pgdata'), 493); // 0o755
            rmSync(certs, {'recursive': true, 'force': true});
          }
        },
      );

      test(
        'warns once per mount that lands outside the pattern it came from',
        () async {
          // A matched link decides what is hidden for the whole sandbox: the
          // pattern names config/, the mount goes on a database directory nothing
          // in the configuration mentions.
          final outside = join(ROOT, 'pgdata');
          final config = join(ROOT, 'config');
          mkdirSync(join(outside, 'base'), {'recursive': true});
          mkdirSync(config, {'recursive': true});
          writeFileSync(join(config, 'app.conf'), '');
          symlinkSync(outside, join(config, 'data'));
          try {
            final (:result, :warnings) = await withCapturedWarnings(
              () async => expandReadDenyGlobLinux(join(config, '*'), []),
            );

            expect(result, contains(outside));
            final escaped = warnings
                .where((line) => line.contains(outside))
                .toList();
            expect(escaped, hasLength(1));
            expect(escaped[0], contains(join(config, '*')));
            expect(escaped[0], contains(join(config, 'data')));
            // What stays inside the pattern's own base is not worth a warning.
            expect(
              warnings
                  .where((line) => line.contains(join(config, 'app.conf')))
                  .toList(),
              [],
            );
          } finally {
            rmSync(outside, {'recursive': true, 'force': true});
            rmSync(config, {'recursive': true, 'force': true});
          }
        },
      );

      test(
        'warns when a pattern still needs more mounts than the threshold after collapsing',
        () async {
          // The expansion is never truncated — that would silently un-deny paths —
          // so a broad pattern is reported rather than cut short.
          final many = join(ROOT, 'many');
          mkdirSync(many, {'recursive': true});
          for (var i = 0; i <= 256; i++) {
            writeFileSync(join(many, '$i.key'), '');
          }
          try {
            final (:result, :warnings) = await withCapturedWarnings(
              () async => expandReadDenyGlobLinux(join(many, '*.key'), []),
            );

            expect(result, hasLength(257));
            expect(
              warnings.where((line) => line.contains('after collapsing')),
              hasLength(1),
            );

            final (warnings: quiet, result: _) = await withCapturedWarnings(
              () async => expandReadDenyGlobLinux(join(many, '1?.key'), []),
            );
            expect(
              quiet.where((line) => line.contains('after collapsing')).toList(),
              [],
            );
          } finally {
            rmSync(many, {'recursive': true, 'force': true});
          }
        },
      );
    },
  );

  group(
    'expandReadDenyGlobLinux (beneath an anchor)',
    skip: !isWindows ? null : 'Windows not supported by this port',
    () {
      late String ROOT;
      late String PROJECT;

      setUpAll(() {
        ROOT = realpathSync(mkdtempSync(join(tmpdir(), 'deny-glob-anchor-')));
        // A directory a pattern reads as a character class, and `W project`,
        // which is what that class matches.
        PROJECT = join(ROOT, '[WIP] project');
        for (final base in [PROJECT, join(ROOT, 'W project')]) {
          mkdirSync(join(base, 'pkg', 'build', 'sub'), {'recursive': true});
          writeFileSync(join(base, 'pkg', 'build', 'sub', '1.out'), '');
          writeFileSync(join(base, 'pkg', '.env'), '');
        }
        mkdirSync(join(ROOT, 'elsewhere'));
        writeFileSync(join(ROOT, 'elsewhere', '.env'), '');
        symlinkSync(join(ROOT, 'elsewhere'), join(PROJECT, 'link'));
      });

      tearDownAll(() {
        rmSync(ROOT, {'recursive': true, 'force': true});
      });

      test(
        'walks the pattern beneath the directory of that name and no other',
        () {
          expect(expandReadDenyGlobLinux('$PROJECT/**/build/**', []), [
            join(ROOT, 'W project', 'pkg', 'build'),
          ]);
          expect(
            expandReadDenyGlobLinux(
              '$PROJECT/**/build/**',
              [],
              anchor: PROJECT,
            ),
            [join(PROJECT, 'pkg', 'build')],
          );
        },
      );

      test(
        'lists a match found through a link beneath the anchor where it really lives',
        () {
          expect(
            expandReadDenyGlobLinux('$PROJECT/**/.env', [], anchor: PROJECT),
            [join(PROJECT, 'pkg', '.env'), join(ROOT, 'elsewhere', '.env')],
          );
        },
      );
    },
  );

  group(
    'expandReadDenyGlobLinux (symlinks)',
    skip: !isWindows ? null : 'Windows not supported by this port',
    () {
      late String ROOT;
      late String OUTSIDE;

      setUpAll(() {
        ROOT = realpathSync(mkdtempSync(join(tmpdir(), 'deny-glob-symlink-')));
        OUTSIDE = join(ROOT, 'outside');
        mkdirSync(OUTSIDE);
        writeFileSync(join(OUTSIDE, 'secret.txt'), '');
        writeFileSync(join(OUTSIDE, 'key.pem'), '');
        // pkg/a/build: a real file plus a directory symlink and a file symlink
        // that both point outside the tree.
        mkdirSync(join(ROOT, 'pkg', 'a', 'build'), {'recursive': true});
        writeFileSync(join(ROOT, 'pkg', 'a', 'build', '1.out'), '');
        symlinkSync(OUTSIDE, join(ROOT, 'pkg', 'a', 'build', 'link'));
        symlinkSync(
          join(OUTSIDE, 'key.pem'),
          join(ROOT, 'pkg', 'a', 'build', 'key.pem'),
        );
        // pkg/empty/build: exists but holds nothing.
        mkdirSync(join(ROOT, 'pkg', 'empty', 'build'), {'recursive': true});
        // pkg/linked/build: a symlink NAMED build, to a real build dir.
        mkdirSync(join(ROOT, 'pkg', 'linked'));
        symlinkSync(
          join(ROOT, 'pkg', 'a', 'build'),
          join(ROOT, 'pkg', 'linked', 'build'),
        );
      });

      /**
   * A fixture directory of its own for a case that plants a tree: four of
   * the tests here glob the whole of ROOT, and would otherwise see whatever
   * another case left in it.
   */
      final caseRoots = <String>[];
      String caseRoot(String name) {
        final dir = realpathSync(
          mkdtempSync(join(tmpdir(), 'deny-glob-$name-')),
        );
        caseRoots.add(dir);
        return dir;
      }

      tearDownAll(() {
        for (final dir in [ROOT, ...caseRoots]) {
          rmSync(dir, {'recursive': true, 'force': true});
        }
      });

      test('mounts a symlink beneath a collapsed directory at its target', () {
        // The denyRead loop emits the covering directory's tmpfs first, which
        // replaces the link with an empty directory inside the sandbox, so a
        // mount kept under the link spelling would land there and hide
        // nothing. The target is listed in its own right and kept instead.
        final build = join(ROOT, 'pkg', 'a', 'build');
        final mounts = expandReadDenyGlobLinux(join(ROOT, '**/build/**'), []);

        expect(mounts, contains(build));
        expect(mounts, isNot(contains(join(build, '1.out'))));
        // Directory symlink: its target is the mount, and what the listing
        // found beneath the link collapses under it.
        expect(mounts, contains(OUTSIDE));
        expect(mounts, isNot(contains(join(build, 'link'))));
        expect(mounts, isNot(contains(join(build, 'link', 'secret.txt'))));
        // File symlink: its target, already under the resolved directory.
        expect(mounts, isNot(contains(join(build, 'key.pem'))));
        expect(mounts, isNot(contains(join(OUTSIDE, 'key.pem'))));
      });

      test(
        'keeps the resolved carve-out beneath a link strictly below the covering directory',
        () {
          // pkg/a/build/link -> outside, with allowRead written against the
          // target: outside/ is denied as a whole, its carve-out and the
          // entries beneath keep their own mounts, and nothing else beneath it.
          mkdirSync(join(OUTSIDE, 'pub'));
          writeFileSync(join(OUTSIDE, 'pub', 'x.txt'), '');
          try {
            final mounts = expandReadDenyGlobLinux(
              join(ROOT, 'pkg', 'a', '**/build/**'),
              [join(OUTSIDE, 'pub')],
            );

            expect(mounts, contains(join(ROOT, 'pkg', 'a', 'build')));
            expect(mounts, contains(OUTSIDE));
            expect(mounts, contains(join(OUTSIDE, 'pub')));
            expect(mounts, contains(join(OUTSIDE, 'pub', 'x.txt')));
            expect(mounts, isNot(contains(join(OUTSIDE, 'secret.txt'))));
          } finally {
            rmSync(join(OUTSIDE, 'pub'), {'recursive': true});
          }
        },
      );

      test('gives an empty matched directory no mount', () {
        final mounts = expandReadDenyGlobLinux(join(ROOT, '**/build/**'), []);
        expect(mounts, isNot(contains(join(ROOT, 'pkg', 'empty', 'build'))));
      });

      test(
        'lists a directory symlink that is itself the covering directory where it really is',
        () {
          // pkg/linked/build -> pkg/a/build: one mount, on the target, which is
          // where the deny loop would put an entry spelled through the link.
          final linked = join(ROOT, 'pkg', 'linked', 'build');
          final mounts = expandReadDenyGlobLinux(join(ROOT, '**/build/**'), []);

          expect(mounts, contains(join(ROOT, 'pkg', 'a', 'build')));
          expect(mounts, isNot(contains(linked)));
          expect(mounts, isNot(contains(join(linked, '1.out'))));
        },
      );

      test('lists a link named like the pattern segment with its target', () {
        // proj/config/secrets -> ../vault: the target is a real directory the
        // walk also reaches by its own name, which matches nothing; the link is
        // the only spelling the pattern matches, so both names have to be
        // listed. The target is where the mount lands.
        final shal = caseRoot('shallow');
        mkdirSync(join(shal, 'proj', 'vault'), {'recursive': true});
        writeFileSync(join(shal, 'proj', 'vault', 'secret.out'), '');
        mkdirSync(join(shal, 'proj', 'config'));
        symlinkSync(
          join('..', 'vault'),
          join(shal, 'proj', 'config', 'secrets'),
        );

        final mounts = expandReadDenyGlobLinux(join(shal, '**/secrets/**'), []);

        expect(mounts, [join(shal, 'proj', 'vault')]);
      });

      test('leaves alone a directory that many links lead to', () {
        // shared/ is linked from twenty directories and holds nothing the
        // pattern matches: the only mount is the file that does match, and
        // nothing stands for a directory the expansion gave up on.
        final many = caseRoot('many-names');
        mkdirSync(join(many, 'shared', 'lib'), {'recursive': true});
        writeFileSync(join(many, 'shared', 'lib', 'index.js'), '');
        writeFileSync(join(many, '.env'), '');
        for (var i = 0; i < 20; i++) {
          mkdirSync(join(many, 'user$i'));
          symlinkSync(join('..', 'shared'), join(many, 'user$i', 'shared'));
        }

        final unlistable = <String>{};
        final mounts = expandReadDenyGlobLinux(
          join(many, '**/.env'),
          [],
          unlistableDirs: unlistable,
        );

        expect(mounts, [join(many, '.env')]);
        expect([...unlistable], []);
      });

      test(
        'denies nothing for a link out of the tree when the pattern cannot be read a name at a time',
        () {
          // `id[*].pem` cannot be followed one path component at a time, so no
          // directory is listed through a symlink, and what such a pattern would
          // match through one goes undenied: a known gap. Denying whole what every
          // link out of the tree leads to is no cure: with vendor/sdk/conf -> /usr
          // that masks /usr, and no command starts.
          final unsplit = caseRoot('unsplit');
          mkdirSync(join(unsplit, 'proj', 'vendor', 'sdk'), {
            'recursive': true,
          });
          mkdirSync(join(unsplit, 'outside'));
          writeFileSync(join(unsplit, 'outside', 'x'), '');
          symlinkSync(
            join(unsplit, 'outside'),
            join(unsplit, 'proj', 'vendor', 'sdk', 'conf'),
          );

          final unlistable = <String>{};
          final mounts = expandReadDenyGlobLinux(
            join(unsplit, 'proj', 'id[*].pem'),
            [],
            unlistableDirs: unlistable,
          );

          expect(mounts, []);
          expect([...unlistable], []);
        },
      );

      group('a directory with two names that does not list', () {
        /** The mounts of two patterns handed the same listings, with the first
     *  `failures` listings of pkg/certs failing with `code`. A link leads to
     *  it as well, by no shorter a name, so its real path is all that is
     *  ever asked. */
        ({
          String certs,
          List<List<String>> mounts,
          List<String> unlistable,
          int tries,
        })
        expandWith(String code, num failures) {
          final root = caseRoot('two-names');
          final certs = join(root, 'pkg', 'certs');
          mkdirSync(certs, {'recursive': true});
          writeFileSync(join(certs, 'id.pem'), '');
          symlinkSync(join('pkg', 'certs'), join(root, 'link-to-certs'));
          var tries = 0;
          final readdirSync = fs.readdirSync;
          fs.readdirSync = (String path, {bool withFileTypes = true}) {
            if (path == certs && ++tries <= failures) {
              throw NodeError(code, code: code);
            }
            return readdirSync(path, withFileTypes: withFileTypes);
          };
          try {
            final listings = <String, Object>{};
            final unlistable = <String>{};
            final mounts = ['*.pem', '*.key']
                .map(
                  (name) => expandReadDenyGlobLinux(
                    join(root, '**', name),
                    [],
                    unlistableDirs: unlistable,
                    listings: listings,
                  ),
                )
                .toList();
            return (
              certs: certs,
              mounts: mounts,
              unlistable: [...unlistable],
              tries: tries,
            );
          } finally {
            fs.readdirSync = readdirSync;
          }
        }

        test(
          'lets a failure kept in shared listings answer for the second name, the directory being denied whole',
          () {
            // A walk by itself tries a directory under each name that leads to it
            // (glob-expand: "does not let one name that fails to list answer for
            // the others"). Between the patterns of one configuration a failure is
            // kept, and the directory is denied whole for each of them.
            final (:certs, :mounts, :unlistable, :tries) = expandWith(
              'EMFILE',
              1,
            );

            expect(tries, 1);
            expect(mounts, [
              [certs],
              [certs],
            ]);
            expect(unlistable, [certs]);
          },
        );

        test('denies nothing for one that answers that it is not there', () {
          final (:certs, :mounts, :unlistable, :tries) = expandWith(
            'ENOENT',
            double.infinity,
          );

          expect(mounts, [[], []]);
          expect(unlistable, []);
        });

        test(
          'asks under the second name when it was not there under the first',
          () {
            final (:certs, :mounts, :unlistable, :tries) = expandWith(
              'ENOENT',
              1,
            );

            expect(mounts, [
              [join(certs, 'id.pem')],
              [],
            ]);
            expect(unlistable, []);
          },
        );
      });

      group('a link that matches and is read by its short name alone', () {
        // proj/vendor is shorter than what it leads to, so what lies in there is
        // spelled by its real path and has a short name besides. Its real path
        // failing, a link stays in the list as spelled, beneath a directory the
        // pattern denies as well: where it leads is not in there.
        const V = 'out/of/the/tree/vendor';
        const CLEAN = [
          'far.txt',
          'far2.txt',
          '$V/root',
          '$V/secrets',
          'proj',
          'store/dir',
          'store/key.txt',
          'store/sub',
        ];
        late String root;

        setUpAll(() {
          root = caseRoot('short-name-link');
          for (final dir in [
            '$V/secrets',
            '$V/alt',
            '$V/file',
            '$V/up',
            '$V/root',
            'store/dir',
            'store/sub',
            'decoy',
            'proj',
          ]) {
            mkdirSync(join(root, dir), {'recursive': true});
          }
          for (final file in [
            '$V/secrets/token.txt',
            'store/key.txt',
            'store/dir/f',
            'store/sub/g',
            'far.txt',
            'far2.txt',
            'decoy.txt',
          ]) {
            writeFileSync(join(root, file), '');
          }
          symlinkSync(join(root, V), join(root, 'proj/vendor'));
          // In a denied directory; of the directory form; behind that one.
          symlinkSync(
            join(root, 'store/key.txt'),
            join(root, V, 'secrets/key.pem'),
          );
          symlinkSync(join(root, 'store/dir'), join(root, V, 'alt/secrets'));
          symlinkSync(join(root, 'far.txt'), join(root, 'store/dir/more'));
          // Of the directory form by its name, and no directory: denies nothing.
          symlinkSync(join(root, 'decoy.txt'), join(root, V, 'file/secrets'));
          // A match that is a directory, and what lies behind it.
          symlinkSync(join(root, 'store/sub'), join(root, V, 'secrets/sub'));
          symlinkSync(join(root, 'far2.txt'), join(root, 'store/sub/more'));
          // Of the directory form, to the base and to the root: not listed through.
          symlinkSync(join(root, 'proj'), join(root, V, 'up/secrets'));
          symlinkSync('/', join(root, V, 'root/secrets'));
        });

        /// What `proj/**/secrets/**` denies while `answers` holds: by call and
        /// name, the errno it fails with or, after `=`, the path that answers.

        List<String> expandWhile(
          Map<String, String> answers, [
          String tail = '**/secrets/**',
        ]) {
          final realStat = fs.statSync;
          final realRealpath = fs.realpathSync;
          String? answerFor(String fn, String p) =>
              answers['$fn ${p.substring(math.min(root.length + 1, p.length))}'];
          fs.statSync = (String p) {
            final answer = answerFor('statSync', p);
            if (answer == null) return realStat(p);
            if (answer[0] == '=')
              return realStat(join(root, answer.substring(1)));
            throw NodeError(answer, code: answer);
          };
          fs.realpathSync = (String p) {
            final answer = answerFor('realpathSync', p);
            if (answer == null) return realRealpath(p);
            if (answer[0] == '=') {
              return realRealpath(join(root, answer.substring(1)));
            }
            throw NodeError(answer, code: answer);
          };
          try {
            return expandReadDenyGlobLinux(
              join(root, 'proj', tail),
              [],
            ).map((p) => p.substring(root.length + 1)).toList();
          } finally {
            fs.statSync = realStat;
            fs.realpathSync = realRealpath;
          }
        }

        for (final call in ['statSync', 'realpathSync'])
          for (final code in ['EACCES', 'EMFILE'])
            test('denies where it leads besides ($call, $code)', () {
              expect(expandWhile({}), CLEAN);
              for (final link in [
                'secrets/key.pem',
                'secrets/sub',
                'alt/secrets',
                'file/secrets',
                'up/secrets',
                'root/secrets',
              ]) {
                expect(
                  [
                    link,
                    expandWhile({'$call $V/$link': code}),
                  ],
                  [
                    link,
                    ([...CLEAN, '$V/$link']..sort()),
                  ],
                );
              }
              // A match with nothing of the pattern left beneath it.
              expect(
                expandWhile({
                  '$call $V/secrets/sub': code,
                }, 'vendor/secrets/s*'),
                ['proj/vendor/secrets/sub', 'store/sub'],
              );
            });

        test('denies a decoy besides, and nothing less for it', () {
          expect(
            expandWhile({
              'statSync $V/secrets/key.pem': 'EACCES',
              'statSync proj/vendor/secrets/key.pem': '=decoy.txt',
              'realpathSync proj/vendor/secrets/key.pem': '=decoy.txt',
              'statSync $V/alt/secrets': 'EACCES',
              'statSync proj/vendor/alt/secrets': '=decoy',
              'realpathSync proj/vendor/alt/secrets': '=decoy',
            }),
            [
              ...CLEAN.where(
                (p) => !['store/dir', 'store/key.txt', 'far.txt'].contains(p),
              ),
              'decoy',
              'decoy.txt',
              '$V/alt/secrets',
              '$V/secrets/key.pem',
            ]..sort(),
          );
        });

        test(
          'keeps it as spelled beneath whatever the short name says it leads to',
          () {
            expect(
              expandWhile({
                'statSync $V/secrets/key.pem': 'EACCES',
                'statSync proj/vendor/secrets/key.pem': '=$V',
                'realpathSync proj/vendor/secrets/key.pem': '=$V',
              }),
              [
                ...CLEAN.where((p) => !p.startsWith(V) && p != 'store/key.txt'),
                V,
                '$V/secrets/key.pem',
              ]..sort(),
            );
          },
        );

        test(
          'keeps one that cannot be inspected under either name as spelled',
          () {
            expect(
              expandWhile({
                'statSync $V/secrets/key.pem': 'EACCES',
                'statSync proj/vendor/secrets/key.pem': 'EACCES',
              }),
              [
                ...CLEAN.where((p) => p != 'store/key.txt'),
                '$V/secrets/key.pem',
              ]..sort(),
            );
          },
        );
      });

      test(
        'keeps a link as spelled, with where its short name leads, when no real path answers',
        skip: isLinux && process.getuid?.call() != 0
            ? null
            : 'requires Linux and a non-root user',
        () {
          // Nothing is made to fail. The working directory lies behind one that
          // cannot be searched, so what is in it answers by /proc/self/cwd alone,
          // which this runtime resolves.
          final root = caseRoot('no-real-path');
          final work = join(root, 'gate/work');
          final secrets = join(work, 'deep/er/dir/secrets');
          mkdirSync(secrets, {'recursive': true});
          writeFileSync(join(secrets, 'token.txt'), '');
          writeFileSync(join(root, 'key.txt'), '');
          symlinkSync(join(root, 'key.txt'), join(secrets, 'key.pem'));
          symlinkSync('deep/er/dir', join(work, 'l'));
          final cwd = process.cwd();
          Directory.current = work;
          chmodSync(join(root, 'gate'), 0); // 0o000
          try {
            expect(realpathSync('/proc/self/cwd'), work);
            expect(expandReadDenyGlobLinux('/proc/self/cwd/*/secrets/**', []), [
              work,
              join(secrets, 'key.pem'),
              join(root, 'key.txt'),
            ]);
          } finally {
            chmodSync(join(root, 'gate'), 493); // 0o755
            Directory.current = cwd;
          }
        },
      );

      test(
        'lists every match where it really is when the base is a symlink',
        () {
          // alias -> ROOT, sideways: normalizePathForSandbox keeps the link
          // spelling for the pattern, so every match is spelled through it. The
          // mounts go where the matches really are, and a carve-out counts the
          // same whether it is written through the alias or not.
          final alias = join(
            ROOT,
            '..',
            'alias-${math.Random().nextInt(1 << 31).toRadixString(36)}',
          );
          symlinkSync(ROOT, alias);
          try {
            final build = join('pkg', 'a', 'build');
            final carveOut = join(ROOT, build, 'public');
            mkdirSync(carveOut, {'recursive': true});
            writeFileSync(join(carveOut, 'ok.txt'), '');

            final real = expandReadDenyGlobLinux(join(alias, '**/build/**'), [
              carveOut,
            ]);
            expect(real, contains(join(ROOT, build)));
            expect(real, contains(carveOut));
            expect(real, contains(join(carveOut, 'ok.txt')));
            expect(real, isNot(contains(join(ROOT, build, '1.out'))));
            expect(real.where((m) => m.startsWith(alias + '/')).toList(), []);

            expect(
              expandReadDenyGlobLinux(join(alias, '**/build/**'), [
                join(alias, build, 'public'),
              ]),
              real,
            );
          } finally {
            Link(alias).deleteSync();
            rmSync(join(ROOT, 'pkg', 'a', 'build', 'public'), {
              'recursive': true,
            });
          }
        },
      );

      test('denies what holds a link to the root, never the root', () {
        // build/root -> /: denied where it resolves, that would be a tmpfs over
        // every top-level directory; denied at the link, a mount bwrap refuses,
        // so that no later command starts while the link exists. The directory
        // holding it is denied instead, as for an entry that cannot be
        // inspected — here build, which the pattern denies anyway.
        final rooted = caseRoot('rooted');
        mkdirSync(join(rooted, 'build'), {'recursive': true});
        writeFileSync(join(rooted, 'build', '1.out'), '');
        symlinkSync('/', join(rooted, 'build', 'root'));

        final mounts = expandReadDenyGlobLinux(join(rooted, '**/build/**'), []);

        expect(mounts, [join(rooted, 'build')]);

        // The same when the link is itself the matched directory: the mount goes
        // on the directory holding it.
        mkdirSync(join(rooted, 'img'));
        symlinkSync('/', join(rooted, 'img', 'build'));
        expect(
          expandReadDenyGlobLinux(join(rooted, 'img', '**/build/**'), []),
          [join(rooted, 'img')],
        );
      });

      test(
        'denies the target of a directory-form link the walk did not descend',
        () {
          // pkg/x/y/build -> pkg/x names a directory on its own descent chain, so
          // the walk lists nothing beneath it; it is still a match, and its target
          // is what a literal deny of the link would deny.
          final ancestry = caseRoot('ancestry');
          mkdirSync(join(ancestry, 'x', 'y'), {'recursive': true});
          writeFileSync(join(ancestry, 'x', 'src.ts'), '');
          symlinkSync(join('..'), join(ancestry, 'x', 'y', 'build'));

          final mounts = expandReadDenyGlobLinux(
            join(ancestry, '**/build/**'),
            [],
          );

          expect(mounts, contains(join(ancestry, 'x')));
        },
      );

      test('denies through a link back to the tree', () {
        // build/up -> ..: the target is the whole tree the link reaches, as a
        // literal deny of the link would have it; the walk itself stops at the
        // link.
        final esc = caseRoot('escape');
        mkdirSync(join(esc, 'build'), {'recursive': true});
        writeFileSync(join(esc, 'build', '1.out'), '');
        symlinkSync('..', join(esc, 'build', 'up'));

        final mounts = expandReadDenyGlobLinux(join(esc, '**/build/**'), []);

        expect(mounts, [esc]);
      });

      group('carve-out through a symlink (pnpm layout)', () {
        // node_modules/foo -> ../.pnpm/foo@1/node_modules/foo, the shape pnpm
        // installs; the glob matches both the link and the real tree.
        late String pnpmRoot;
        late String real;
        late String link;
        setUpAll(() {
          pnpmRoot = caseRoot('pnpm');
          real = join(pnpmRoot, '.pnpm', 'foo@1', 'node_modules', 'foo');
          link = join(pnpmRoot, 'node_modules', 'foo');
          mkdirSync(join(real, 'public'), {'recursive': true});
          writeFileSync(join(real, 'index.js'), '');
          writeFileSync(join(real, 'public', 'ok.txt'), '');
          mkdirSync(join(pnpmRoot, 'node_modules'));
          symlinkSync(
            join('..', '.pnpm', 'foo@1', 'node_modules', 'foo'),
            link,
          );
        });

        for (final spelling in ['link', 'resolved'])
          test(
            'keeps what lies beneath a carve-out written against the $spelling spelling',
            () {
              final mounts = expandReadDenyGlobLinux(
                join(pnpmRoot, '**/node_modules/foo/**'),
                [join(spelling == 'link' ? link : real, 'public')],
              );

              // The package, the carve-out and what lies beneath it, where they
              // are; index.js is hidden by the package's tmpfs.
              expect(mounts, [
                real,
                join(real, 'public'),
                join(real, 'public', 'ok.txt'),
              ]);
            },
          );

        test(
          'is not defeated by a re-exposer above the covering directory',
          () {
            // allowWrite ['.'] (the README's example) names the project root,
            // which re-exposes nothing beneath a tmpfs, so the package still
            // collapses to its two spellings.
            final mounts = expandReadDenyGlobLinux(
              join(pnpmRoot, '**/node_modules/foo/**'),
              [pnpmRoot],
            );

            expect(mounts, [real]);
          },
        );
      });

      test('keeps a match beneath a carve-out that only a second link leads to', () {
        // proj/build -> store/nm and store/nm/keep -> ../keep: y.txt is matched
        // as proj/build/keep/pub/y.txt but lives at store/keep/pub/y.txt, which
        // no spelled ancestor of the match contains. Collapsing along the
        // spelling would drop it under proj/build and lose the mask beneath the
        // carve-out.
        final chain = caseRoot('chain');
        final proj = join(chain, 'proj');
        final store = join(chain, 'store');
        mkdirSync(proj, {'recursive': true});
        mkdirSync(join(store, 'nm'), {'recursive': true});
        mkdirSync(join(store, 'keep', 'pub'), {'recursive': true});
        writeFileSync(join(store, 'keep', 'pub', 'y.txt'), '');
        writeFileSync(join(store, 'nm', 'z.out'), '');
        symlinkSync(join(store, 'nm'), join(proj, 'build'));
        symlinkSync(join('..', 'keep'), join(store, 'nm', 'keep'));

        final mounts = expandReadDenyGlobLinux(join(proj, '**/build/**'), [
          join(store, 'keep', 'pub'),
        ]);

        expect(mounts, [
          join(store, 'keep'),
          join(store, 'keep', 'pub'),
          join(store, 'keep', 'pub', 'y.txt'),
          join(store, 'nm'),
        ]);
      });

      test('drops a matched link that does not resolve', () {
        final dangling = caseRoot('dangling');
        mkdirSync(join(dangling, 'build'), {'recursive': true});
        writeFileSync(join(dangling, 'build', '1.out'), '');
        symlinkSync(join(dangling, 'gone'), join(dangling, 'build', 'lost'));

        expect(expandReadDenyGlobLinux(join(dangling, '**/build/lo*'), []), []);
      });
    },
  );

  group(
    'expandReadDenyGlobLinux (bwrap wiring through a symlink)',
    skip: isLinux ? null : 'requires Linux',
    () {
      // The pnpm layout again, driven through the real Linux wrapper: no tmpfs
      // may land on a symlink (bubblewrap 0.12 refuses to start), and the
      // carve-out must be the last word on the package's inode.
      late String ROOT;
      late String pnpmRoot;
      late String real;
      late String link;
      final savedCwd = process.cwd();
      // Dart: a skipped group's body still runs, and the probe needs bwrap.
      final hasBwrap = isLinux && bwrapCanNamespace();

      /**
     * Run a wrapped command and hold it to having started. A sandbox that
     * refuses to start prints nothing, which every assertion about what it
     * hides would otherwise read as a pass, so each command under test says
     * BOOTED first.
     */
      String runBooted(String wrapped) {
        final result = spawnSync(wrapped, [], {
          'shell': true,
          'encoding': 'utf8',
          'timeout': 15000,
        });
        expect((result.stderr ?? '') as String, isNot(contains('bwrap:')));
        expect(result.stdout as String, contains('BOOTED'));
        return result.stdout as String;
      }

      /** `ln -s` a case's second test can call again over its own fixture. */
      void ensureLink(String target, String linkPath) {
        try {
          symlinkSync(target, linkPath);
        } on FileSystemException catch (err) {
          if (err.osError?.errorCode != 17) rethrow;
        }
      }

      setUpAll(() {
        ROOT = realpathSync(mkdtempSync(join(tmpdir(), 'deny-glob-bwrap-')));
        pnpmRoot = join(ROOT, 'pnpm');
        real = join(pnpmRoot, '.pnpm', 'foo@1', 'node_modules', 'foo');
        link = join(pnpmRoot, 'node_modules', 'foo');
        mkdirSync(join(real, 'public'), {'recursive': true});
        writeFileSync(join(real, 'index.js'), 'secret');
        writeFileSync(join(real, 'public', 'ok.txt'), 'public');
        mkdirSync(join(pnpmRoot, 'node_modules'));
        symlinkSync(join('..', '.pnpm', 'foo@1', 'node_modules', 'foo'), link);
        Directory.current = ROOT;
      });

      tearDownAll(() {
        Directory.current = savedCwd;
        cleanupBwrapMountPoints(force: true);
        rmSync(ROOT, {'recursive': true, 'force': true});
      });

      Future<String> wrap(String command, String carveOut) async {
        return wrapCommandWithSandboxLinux(
          LinuxSandboxParams(
            command: command,
            needsNetworkRestriction: false,
            readConfig: FsReadRestrictionConfig(
              denyOnly: expandReadDenyGlobLinux(
                join(pnpmRoot, '**/node_modules/foo/**'),
                [carveOut],
              ),
              allowWithinDeny: [carveOut],
            ),
            writeConfig: FsWriteRestrictionConfig(
              allowOnly: [],
              denyWithinAllow: [],
            ),
          ),
        );
      }

      for (final spelling in ['link', 'target']) {
        String carveOutOf() => join(spelling == 'link' ? link : real, 'public');
        test(
          'mounts no tmpfs on a symlink and re-binds the carve-out last (allowRead in $spelling spelling)',
          () async {
            final carveOut = carveOutOf();
            final wrapped = await wrap('echo hello', carveOut);
            final ops = wrapped.split(' --').map((op) => op.trim()).toList();

            final tmpfsDests = ops
                .where((op) => op.startsWith('tmpfs '))
                .map((op) => op.substring('tmpfs '.length))
                .toList();
            expect(tmpfsDests, contains(real));
            expect(tmpfsDests, isNot(contains(link)));
            for (final dest in tmpfsDests) {
              expect(lstatSync(dest).isSymbolicLink(), false);
            }
            // One tmpfs per inode, and the carve-out's bind after the last one
            // that covers it.
            expect(tmpfsDests.where((d) => d == real).toList(), hasLength(1));
            final lastTmpfs = [
              for (final (i, op) in ops.indexed)
                if (op.startsWith('tmpfs ')) i,
            ].reduce(math.max);
            // The carve-out goes back at the name it is, read from where that
            // name resolves: both are inside the package's real location.
            final reBind = ops.lastIndexOf(
              'ro-bind ${join(real, 'public')} ${join(real, 'public')}',
            );
            expect(reBind, greaterThan(lastTmpfs));
          },
        );

        test(
          'serves the package empty but for the carve-out, in both spellings (allowRead in $spelling spelling)',
          skip: hasBwrap ? null : 'bwrap cannot create namespaces',
          () async {
            final stdout = runBooted(
              await wrap(
                [
                  'echo BOOTED',
                  'ls $link',
                  'ls $real',
                  'cat ${join(link, 'public', 'ok.txt')} | wc -c',
                  '[ -e ${join(link, 'index.js')} ] && echo INDEX_VISIBLE || echo INDEX_HIDDEN',
                ].join('; '),
                carveOutOf(),
              ),
            );
            expect(stdout.trim().split('\n'), [
              'BOOTED',
              'public',
              'public',
              '0',
              'INDEX_HIDDEN',
            ]);
          },
        );
      }

      test('honours a file carve-out written in the link spelling', () async {
        // The glob lists index.js under both spellings; only the link spelling
        // is in allowRead. Neither twin may be masked, and the carve-out is
        // bound back over the package tmpfs.
        final carveOut = join(link, 'index.js');
        final wrapped = await wrapCommandWithSandboxLinux(
          LinuxSandboxParams(
            command: 'true',
            needsNetworkRestriction: false,
            readConfig: FsReadRestrictionConfig(
              denyOnly: expandReadDenyGlobLinux(
                join(pnpmRoot, '**/node_modules/foo/**'),
                [carveOut],
              ),
              allowWithinDeny: [carveOut],
            ),
            writeConfig: FsWriteRestrictionConfig(
              allowOnly: [],
              denyWithinAllow: [],
            ),
          ),
        );

        expect(
          wrapped,
          contains(
            '--ro-bind ${join(real, 'index.js')} ${join(real, 'index.js')}',
          ),
        );
        expect(wrapped, isNot(contains('/dev/null ${join(real, 'index.js')}')));
        expect(wrapped, isNot(contains('/dev/null $carveOut')));
      });

      test(
        're-applies the tmpfs after a denyWrite bind that contains its target',
        () async {
          // denyWrite names the pnpm store, which contains the package's real
          // location but not its link spelling; the bind lands after the tmpfs
          // and would re-expose the package read-only without a re-application.
          final store = join(pnpmRoot, '.pnpm');
          final wrapped = await wrapCommandWithSandboxLinux(
            LinuxSandboxParams(
              command: 'true',
              needsNetworkRestriction: false,
              readConfig: FsReadRestrictionConfig(
                denyOnly: expandReadDenyGlobLinux(
                  join(pnpmRoot, '**/node_modules/foo/**'),
                  [],
                ),
              ),
              writeConfig: FsWriteRestrictionConfig(
                allowOnly: [pnpmRoot],
                denyWithinAllow: [store],
              ),
            ),
          );

          final storeBind = lastIndexOfMount(wrapped, [
            '--ro-bind',
            store,
            store,
          ]);
          expect(storeBind, greaterThan(-1));
          expect(
            lastIndexOfMount(wrapped, ['--tmpfs', real]),
            greaterThan(storeBind),
          );
        },
      );

      test(
        'does not re-apply a tmpfs over its carve-out when a denyWrite bind covers only the link spelling',
        () async {
          // w/d/link -> realdir (outside the write root w). denyWrite [w/d]
          // contains the link's spelling but not where the tmpfs landed
          // (realdir), so the bind re-exposes nothing; re-applying the tmpfs
          // there anyway would re-bind realdir/pub over the mask on
          // realdir/pub/secret.txt and leave the file readable.
          final caseRoot = join(ROOT, 'f4');
          final realdir = join(caseRoot, 'realdir');
          final writeRoot = join(caseRoot, 'w');
          final linkInWriteRoot = join(writeRoot, 'd', 'link');
          mkdirSync(join(realdir, 'pub'), {'recursive': true});
          writeFileSync(join(realdir, 'pub', 'secret.txt'), 'secret');
          mkdirSync(join(writeRoot, 'd'), {'recursive': true});
          symlinkSync(realdir, linkInWriteRoot);

          final wrapped = await wrapCommandWithSandboxLinux(
            LinuxSandboxParams(
              command: 'true',
              needsNetworkRestriction: false,
              readConfig: FsReadRestrictionConfig(
                denyOnly: [linkInWriteRoot, join(realdir, 'pub', 'secret.txt')],
                allowWithinDeny: [join(realdir, 'pub')],
              ),
              writeConfig: FsWriteRestrictionConfig(
                allowOnly: [writeRoot],
                denyWithinAllow: [join(writeRoot, 'd')],
              ),
              mandatoryDenySearchDepth: 1,
            ),
          );

          final mask =
              '--ro-bind /dev/null ${join(realdir, 'pub', 'secret.txt')}';
          final carveOut =
              '--ro-bind ${join(realdir, 'pub')} ${join(realdir, 'pub')}';
          expect(wrapped, contains(mask));
          // One tmpfs on the target, and the mask is the last word on the file:
          // no carve-out re-bind after it.
          expect(countMounts(wrapped, ['--tmpfs', realdir]), 1);
          expect(wrapped, contains(carveOut));
          expect(
            wrapped.lastIndexOf(mask),
            greaterThan(wrapped.lastIndexOf(carveOut)),
          );
        },
      );

      test(
        're-binds a literal carve-out written against the target of a denied link',
        () async {
          final viaLink = await wrapCommandWithSandboxLinux(
            LinuxSandboxParams(
              command: 'true',
              needsNetworkRestriction: false,
              readConfig: FsReadRestrictionConfig(
                denyOnly: [link],
                allowWithinDeny: [join(real, 'public')],
              ),
              writeConfig: FsWriteRestrictionConfig(
                allowOnly: [],
                denyWithinAllow: [],
              ),
            ),
          );
          expect(countMounts(viaLink, ['--tmpfs', real]), greaterThan(0));
          expect(
            viaLink,
            contains(
              '--ro-bind ${join(real, 'public')} ${join(real, 'public')}',
            ),
          );
        },
      );

      test(
        're-binds a carve-out written beneath the link a directory is denied by, at its target',
        () async {
          final viaLink = await wrapCommandWithSandboxLinux(
            LinuxSandboxParams(
              command: 'true',
              needsNetworkRestriction: false,
              readConfig: FsReadRestrictionConfig(
                denyOnly: [link],
                allowWithinDeny: [join(link, 'public')],
              ),
              writeConfig: FsWriteRestrictionConfig(
                allowOnly: [],
                denyWithinAllow: [],
              ),
            ),
          );
          expect(countMounts(viaLink, ['--tmpfs', real]), greaterThan(0));
          expect(
            viaLink,
            contains(
              '--ro-bind ${join(real, 'public')} ${join(real, 'public')}',
            ),
          );
        },
      );

      // denyRead [real] + allowRead [link/public]: the name `public` lives in
      // the denied directory whichever way it is reached, and the bind goes
      // where it is (bwrap refuses a symlink as a destination and, before 0.12,
      // an absolute one anywhere in it).
      Future<String> wrapCarveOutThroughOutsideLink(String command) {
        return wrapCommandWithSandboxLinux(
          LinuxSandboxParams(
            command: command,
            needsNetworkRestriction: false,
            readConfig: FsReadRestrictionConfig(
              denyOnly: [real],
              allowWithinDeny: [join(link, 'public')],
            ),
            writeConfig: FsWriteRestrictionConfig(
              allowOnly: [],
              denyWithinAllow: [],
            ),
          ),
        );
      }

      test(
        're-binds a carve-out written through a symlinked directory outside the denied one, at its target',
        () async {
          final wrapped = await wrapCarveOutThroughOutsideLink('true');
          expect(countMounts(wrapped, ['--tmpfs', real]), greaterThan(0));
          expect(
            wrapped,
            contains(
              '--ro-bind ${join(real, 'public')} ${join(real, 'public')}',
            ),
          );
        },
      );

      test(
        'serves that carve-out and nothing else of the denied directory',
        skip: hasBwrap ? null : 'bwrap cannot create namespaces',
        () async {
          final stdout = runBooted(
            await wrapCarveOutThroughOutsideLink(
              'echo BOOTED; cat ${join(link, 'public', 'ok.txt')}; cat ${join(real, 'index.js')} || echo HIDDEN',
            ),
          );
          expect(stdout, 'BOOTED\npublicHIDDEN\n');
        },
      );

      group('an allowRead that only leads into a denied directory', () {
        // What an allowRead entry resolves to never decides which deny it
        // carves out of: a sandboxed command with write access to where the
        // entry lives can point it anywhere.

        Future<String> wrapAllowReadLinkToDeniedDir(String command) {
          final home = join(ROOT, 'g1', 'home');
          final proj = join(ROOT, 'g1', 'proj');
          mkdirSync(join(home, '.ssh'), {'recursive': true});
          writeFileSync(join(home, '.ssh', 'id_rsa'), 'KEY');
          mkdirSync(proj, {'recursive': true});
          ensureLink(join(home, '.ssh'), join(proj, 'docs'));
          return wrapCommandWithSandboxLinux(
            LinuxSandboxParams(
              command: command,
              needsNetworkRestriction: false,
              readConfig: FsReadRestrictionConfig(
                denyOnly: [join(home, '.ssh')],
                allowWithinDeny: [join(proj, 'docs')],
              ),
              writeConfig: FsWriteRestrictionConfig(
                allowOnly: [proj],
                denyWithinAllow: [],
              ),
              mandatoryDenySearchDepth: 1,
            ),
          );
        }

        test(
          'does not bind a denied directory back through an allowRead symlink to it',
          () async {
            final wrapped = await wrapAllowReadLinkToDeniedDir('true');

            expect(
              countMounts(wrapped, [
                '--tmpfs',
                join(ROOT, 'g1', 'home', '.ssh'),
              ]),
              greaterThan(0),
            );
            expect(
              wrapped,
              isNot(contains('--ro-bind ${join(ROOT, 'g1', 'proj', 'docs')}')),
            );
          },
        );

        test(
          'serves nothing of that denied directory under either name',
          skip: hasBwrap ? null : 'bwrap cannot create namespaces',
          () async {
            final home = join(ROOT, 'g1', 'home');
            final proj = join(ROOT, 'g1', 'proj');
            final stdout = runBooted(
              await wrapAllowReadLinkToDeniedDir(
                'echo BOOTED; cat ${join(home, '.ssh', 'id_rsa')} ${join(proj, 'docs', 'id_rsa')} || echo HIDDEN',
              ),
            );
            expect(stdout, isNot(contains('KEY')));
            expect(stdout, contains('HIDDEN'));
          },
        );

        Future<String> wrapAllowReadLinkToDeniedFile(String command) {
          final aws = join(ROOT, 'g2', 'aws');
          final proj = join(ROOT, 'g2', 'proj');
          mkdirSync(aws, {'recursive': true});
          writeFileSync(join(aws, 'credentials'), 'CREDS');
          mkdirSync(proj, {'recursive': true});
          ensureLink(join(aws, 'credentials'), join(proj, 'cfg.json'));
          return wrapCommandWithSandboxLinux(
            LinuxSandboxParams(
              command: command,
              needsNetworkRestriction: false,
              readConfig: FsReadRestrictionConfig(
                denyOnly: [join(aws, 'credentials')],
                allowWithinDeny: [join(proj, 'cfg.json')],
              ),
              writeConfig: FsWriteRestrictionConfig(
                allowOnly: [proj],
                denyWithinAllow: [],
              ),
              mandatoryDenySearchDepth: 1,
            ),
          );
        }

        test(
          'keeps the mask on a denied file an allowRead symlink points at',
          () async {
            final wrapped = await wrapAllowReadLinkToDeniedFile('true');

            expect(
              wrapped,
              contains(
                '--ro-bind /dev/null ${join(ROOT, 'g2', 'aws', 'credentials')}',
              ),
            );
          },
        );

        test(
          'serves that file through neither name',
          skip: hasBwrap ? null : 'bwrap cannot create namespaces',
          () async {
            final aws = join(ROOT, 'g2', 'aws');
            final proj = join(ROOT, 'g2', 'proj');
            final stdout = runBooted(
              await wrapAllowReadLinkToDeniedFile(
                'echo BOOTED; cat ${join(aws, 'credentials')} ${join(proj, 'cfg.json')}; echo END',
              ),
            );
            expect(stdout, isNot(contains('CREDS')));
            expect(stdout, contains('END'));
          },
        );

        // denyRead **/.env* with allowRead **/.env.example, and
        // sub/.env.example -> ../.env planted: both patterns match the link,
        // which names the link, not .env.
        Future<String> wrapPlantedExampleLink(String command) {
          final proj = join(ROOT, 'g3', 'proj');
          mkdirSync(join(proj, 'sub'), {'recursive': true});
          writeFileSync(join(proj, '.env'), 'ENVSECRET');
          writeFileSync(join(proj, '.env.example'), 'EXAMPLE');
          ensureLink(join('..', '.env'), join(proj, 'sub', '.env.example'));
          final allowWithinDeny = expandGlobPattern(
            join(proj, '**/.env.example'),
          );
          expect(allowWithinDeny, contains(join(proj, 'sub', '.env.example')));
          return wrapCommandWithSandboxLinux(
            LinuxSandboxParams(
              command: command,
              needsNetworkRestriction: false,
              readConfig: FsReadRestrictionConfig(
                denyOnly: expandReadDenyGlobLinux(
                  join(proj, '**/.env*'),
                  allowWithinDeny,
                ),
                allowWithinDeny: allowWithinDeny,
              ),
              writeConfig: FsWriteRestrictionConfig(
                allowOnly: [proj],
                denyWithinAllow: [],
              ),
              mandatoryDenySearchDepth: 1,
            ),
          );
        }

        test(
          'does not lift a file mask for an allowRead symlink that a pattern also matches',
          () async {
            final proj = join(ROOT, 'g3', 'proj');
            final wrapped = await wrapPlantedExampleLink('true');

            expect(
              wrapped,
              contains('--ro-bind /dev/null ${join(proj, '.env')}'),
            );
            expect(
              wrapped,
              isNot(contains('/dev/null ${join(proj, '.env.example')}')),
            );
          },
        );

        test(
          'serves the example file and not what the planted link points at',
          skip: hasBwrap ? null : 'bwrap cannot create namespaces',
          () async {
            final proj = join(ROOT, 'g3', 'proj');
            final stdout = runBooted(
              await wrapPlantedExampleLink(
                'echo BOOTED; cat ${join(proj, '.env.example')}; cat ${join(proj, 'sub', '.env.example')} ${join(proj, '.env')}; echo END',
              ),
            );
            expect(stdout, contains('EXAMPLE'));
            expect(stdout, isNot(contains('ENVSECRET')));
          },
        );

        // denyRead [denied, outside/sub] + allowRead [denied/lnk], denied/lnk ->
        // ../outside: bound back at denied/lnk, `outside` would be readable
        // there whatever is denied inside it. It was never hidden by the
        // tmpfs on `denied`, so there is nothing to restore.
        const outsideTreeOrders = [
          ('the denied directory first', 0),
          ('the link spelling first', 1),
        ];
        List<String> outsideTreeDenyOnly(int order) {
          final denied = join(ROOT, 's1', 'D');
          final outside = join(ROOT, 's1', 'e');
          mkdirSync(denied, {'recursive': true});
          mkdirSync(join(outside, 'sub'), {'recursive': true});
          writeFileSync(join(outside, 'sub', 'secret'), 'secret');
          ensureLink(join('..', 'e'), join(denied, 'lnk'));
          return order == 0
              ? [denied, join(outside, 'sub')]
              : [join(denied, 'lnk', 'sub'), denied];
        }

        Future<String> wrapOutsideTree(String command, int order) {
          final denied = join(ROOT, 's1', 'D');
          return wrapCommandWithSandboxLinux(
            LinuxSandboxParams(
              command: command,
              needsNetworkRestriction: false,
              readConfig: FsReadRestrictionConfig(
                denyOnly: outsideTreeDenyOnly(order),
                allowWithinDeny: [join(denied, 'lnk')],
              ),
              writeConfig: FsWriteRestrictionConfig(
                allowOnly: [],
                denyWithinAllow: [],
              ),
            ),
          );
        }

        for (final (orderName, index) in outsideTreeOrders) {
          test(
            'does not show a tree outside the denied directory under a name inside it, with $orderName',
            () async {
              final denied = join(ROOT, 's1', 'D');
              final outside = join(ROOT, 's1', 'e');
              final wrapped = await wrapOutsideTree('true', index);

              expect(countMounts(wrapped, ['--tmpfs', denied]), greaterThan(0));
              expect(
                countMounts(wrapped, ['--tmpfs', join(outside, 'sub')]),
                greaterThan(0),
              );
              expect(
                wrapped,
                isNot(contains('--ro-bind ${join(denied, 'lnk')}')),
              );
            },
          );

          test(
            'serves nothing of that tree under either name, with $orderName',
            skip: hasBwrap ? null : 'bwrap cannot create namespaces',
            () async {
              final denied = join(ROOT, 's1', 'D');
              final outside = join(ROOT, 's1', 'e');
              final stdout = runBooted(
                await wrapOutsideTree(
                  'echo BOOTED; cat ${join(denied, 'lnk', 'sub', 'secret')} ${join(outside, 'sub', 'secret')} || echo HIDDEN',
                  index,
                ),
              );
              expect(stdout, isNot(contains('secret')));
              expect(stdout, contains('HIDDEN'));
            },
          );
        }

        // denyRead [target/private, denied] + allowRead [denied/x,
        // denied/x/lnk], denied/x/lnk -> target: denied/x is bound back from
        // the host, live link included, so `target` is reached through it as on
        // the host and target/private stays denied. A bind of denied/x/lnk
        // would land on `target` and bury that deny.
        Future<String> wrapLinkInsideCarveOut(String command) {
          final denied = join(ROOT, 's3', 'D');
          final target = join(ROOT, 's3', 't');
          mkdirSync(join(denied, 'x'), {'recursive': true});
          mkdirSync(join(target, 'private'), {'recursive': true});
          writeFileSync(join(target, 'f'), 'T');
          writeFileSync(join(target, 'private', 'key'), 'KEY');
          ensureLink(join('..', '..', 't'), join(denied, 'x', 'lnk'));
          return wrapCommandWithSandboxLinux(
            LinuxSandboxParams(
              command: command,
              needsNetworkRestriction: false,
              readConfig: FsReadRestrictionConfig(
                denyOnly: [join(target, 'private'), denied],
                allowWithinDeny: [join(denied, 'x'), join(denied, 'x', 'lnk')],
              ),
              writeConfig: FsWriteRestrictionConfig(
                allowOnly: [],
                denyWithinAllow: [],
              ),
            ),
          );
        }

        test(
          'leaves a link inside a carve-out to lead where it leads, without a mount of its own',
          () async {
            final wrapped = await wrapLinkInsideCarveOut('true');

            expect(
              wrapped,
              isNot(contains('--ro-bind ${join(ROOT, 's3', 'D', 'x', 'lnk')}')),
            );
          },
        );

        test(
          'reads through that link as on the host, and still denies what it leads into',
          skip: hasBwrap ? null : 'bwrap cannot create namespaces',
          () async {
            final denied = join(ROOT, 's3', 'D');
            final target = join(ROOT, 's3', 't');
            final stdout = runBooted(
              await wrapLinkInsideCarveOut(
                'echo BOOTED; cat ${join(denied, 'x', 'lnk', 'f')}; cat ${join(target, 'private', 'key')} ${join(denied, 'x', 'lnk', 'private', 'key')} || echo HIDDEN',
              ),
            );
            expect(stdout, 'BOOTED\nTHIDDEN\n');
          },
        );
      });

      // l1 -> a/b, a/b/l2 -> t: l1/l2/f is t/f. Mounted where it really is, it
      // is denied under every name, in either order of the two entries.
      Future<String> wrapTwoLinkSpellings(String command, bool reversed) {
        final caseRoot = join(ROOT, 's7');
        mkdirSync(join(caseRoot, 'a', 'b'), {'recursive': true});
        mkdirSync(join(caseRoot, 't'), {'recursive': true});
        writeFileSync(join(caseRoot, 't', 'f'), 'FCONTENT');
        ensureLink(join('a', 'b'), join(caseRoot, 'l1'));
        ensureLink(join('..', '..', 't'), join(caseRoot, 'a', 'b', 'l2'));
        final denied = [
          join(caseRoot, 'l1', 'l2', 'f'),
          join(caseRoot, 'a', 'b'),
        ];
        return wrapCommandWithSandboxLinux(
          LinuxSandboxParams(
            command: command,
            needsNetworkRestriction: false,
            readConfig: FsReadRestrictionConfig(
              denyOnly: reversed ? [...denied].reversed.toList() : denied,
              allowWithinDeny: [join(caseRoot, 'a', 'b', 'l2')],
            ),
            writeConfig: FsWriteRestrictionConfig(
              allowOnly: [],
              denyWithinAllow: [],
            ),
          ),
        );
      }

      for (final reversed in [false, true]) {
        final order = reversed ? 'the directory first' : 'the file first';

        test(
          'denies a path the same way whatever spelling names it, with $order',
          () async {
            final caseRoot = join(ROOT, 's7');
            final wrapped = await wrapTwoLinkSpellings('true', reversed);

            expect(
              wrapped,
              contains('--ro-bind /dev/null ${join(caseRoot, 't', 'f')}'),
            );
            expect(
              countMounts(wrapped, ['--tmpfs', join(caseRoot, 'a', 'b')]),
              greaterThan(0),
            );
          },
        );

        test(
          'serves that path through neither spelling, with $order',
          skip: hasBwrap ? null : 'bwrap cannot create namespaces',
          () async {
            final caseRoot = join(ROOT, 's7');
            final stdout = runBooted(
              await wrapTwoLinkSpellings(
                'echo BOOTED; cat ${join(caseRoot, 'l1', 'l2', 'f')} ${join(caseRoot, 't', 'f')}; echo END',
                reversed,
              ),
            );
            expect(stdout, 'BOOTED\nEND\n');
          },
        );
      }

      // x/secrets/latest -> .. (x, an allowed write root): the deny of the link
      // is a deny of x, which the write bind cancels; mounted after x/secrets
      // it would wipe that tmpfs and bind the secrets back.
      Future<String> wrapLinkBackUpToWriteRoot(String command, bool reversed) {
        final writeRoot = join(ROOT, 's5', 'x');
        mkdirSync(join(writeRoot, 'secrets'), {'recursive': true});
        writeFileSync(join(writeRoot, 'secrets', 'key'), 'KEY');
        ensureLink('..', join(writeRoot, 'secrets', 'latest'));
        final denied = [
          join(writeRoot, 'secrets'),
          join(writeRoot, 'secrets', 'latest'),
        ];
        return wrapCommandWithSandboxLinux(
          LinuxSandboxParams(
            command: command,
            needsNetworkRestriction: false,
            readConfig: FsReadRestrictionConfig(
              denyOnly: reversed ? [...denied].reversed.toList() : denied,
            ),
            writeConfig: FsWriteRestrictionConfig(
              allowOnly: [writeRoot],
              denyWithinAllow: [],
            ),
            mandatoryDenySearchDepth: 1,
          ),
        );
      }

      for (final reversed in [false, true]) {
        final order = reversed ? 'the link first' : 'the directory first';

        test(
          'mounts a directory that a link inside a denied directory leads back up to before that directory, with $order',
          () async {
            final writeRoot = join(ROOT, 's5', 'x');
            final wrapped = await wrapLinkBackUpToWriteRoot('true', reversed);

            expect(
              lastIndexOfMount(wrapped, [
                '--tmpfs',
                join(writeRoot, 'secrets'),
              ]),
              greaterThan(
                lastIndexOfMount(wrapped, ['--bind', writeRoot, writeRoot]),
              ),
            );
          },
        );

        test(
          'hides those secrets from the write root, with $order',
          skip: hasBwrap ? null : 'bwrap cannot create namespaces',
          () async {
            final writeRoot = join(ROOT, 's5', 'x');
            final stdout = runBooted(
              await wrapLinkBackUpToWriteRoot(
                'echo BOOTED; cat ${join(writeRoot, 'secrets', 'key')} || echo HIDDEN',
                reversed,
              ),
            );
            expect(stdout, 'BOOTED\nHIDDEN\n');
          },
        );
      }

      // denied/L -> ../T with denyRead [denied, denied/L/sub] and allowWrite
      // [T/sub/writable]: T/sub/writable is bound back once, where it is, under
      // the deny binds and masks that protect it. Bound a second time beneath
      // denied/L it would be writable there with none of them on top.
      Future<String> wrapWritePathUnderLink(String command) {
        final denied = join(ROOT, 's6', 'D');
        final target = join(ROOT, 's6', 'T');
        final writable = join(target, 'sub', 'w');
        mkdirSync(denied, {'recursive': true});
        mkdirSync(join(writable, '.git', 'hooks'), {'recursive': true});
        writeFileSync(join(writable, '.env'), 'ENV');
        ensureLink(join('..', 'T'), join(denied, 'L'));
        return wrapCommandWithSandboxLinux(
          LinuxSandboxParams(
            command: command,
            needsNetworkRestriction: false,
            readConfig: FsReadRestrictionConfig(
              denyOnly: [
                denied,
                join(denied, 'L', 'sub'),
                join(writable, '.env'),
              ],
              allowWithinDeny: [join(denied, 'L')],
            ),
            writeConfig: FsWriteRestrictionConfig(
              allowOnly: [writable],
              denyWithinAllow: [join(writable, '.git', 'hooks')],
            ),
            mandatoryDenySearchDepth: 1,
          ),
        );
      }

      test(
        'binds an allowed write path back only where it really is',
        () async {
          final writable = join(ROOT, 's6', 'T', 'sub', 'w');
          final wrapped = await wrapWritePathUnderLink('true');

          final binds = wrapped
              .split(' --')
              .where((op) => op.startsWith('bind $writable '))
              .map((op) => op.trim())
              .toList();
          expect(binds.length, greaterThan(0));
          expect({...binds}.toList(), ['bind $writable $writable']);
        },
      );

      test(
        'writes to that path through neither name, and reads its denied file through neither',
        skip: hasBwrap ? null : 'bwrap cannot create namespaces',
        () async {
          final denied = join(ROOT, 's6', 'D');
          final writable = join(ROOT, 's6', 'T', 'sub', 'w');
          final stdout = runBooted(
            await wrapWritePathUnderLink(
              'echo BOOTED; touch ${join(denied, 'L', 'sub', 'w', '.git', 'hooks', 'pre-commit')} ${join(writable, '.git', 'hooks', 'pre-commit')} && echo WRITTEN; cat ${join(denied, 'L', 'sub', 'w', '.env')} ${join(writable, '.env')} || echo HIDDEN',
            ),
          );
          expect(stdout, isNot(contains('WRITTEN')));
          expect(stdout, isNot(contains('ENV')));
          expect(stdout, contains('HIDDEN'));
        },
      );

      // ln -> real/secretdir and real/secretdir/out -> elsewhere/hooks:
      // denyWrite [real/secretdir/out] protects elsewhere/hooks, which the
      // tmpfs on real/secretdir does not hide.
      Future<String> wrapDenyWriteThroughDeniedDir(String command) {
        final caseRoot = join(ROOT, 's8', 'root');
        final hooks = join(caseRoot, 'elsewhere', 'hooks');
        mkdirSync(join(caseRoot, 'real', 'secretdir'), {'recursive': true});
        mkdirSync(hooks, {'recursive': true});
        ensureLink(join(caseRoot, 'real', 'secretdir'), join(caseRoot, 'ln'));
        ensureLink(hooks, join(caseRoot, 'real', 'secretdir', 'out'));
        return wrapCommandWithSandboxLinux(
          LinuxSandboxParams(
            command: command,
            needsNetworkRestriction: false,
            readConfig: FsReadRestrictionConfig(
              denyOnly: [join(caseRoot, 'ln')],
            ),
            writeConfig: FsWriteRestrictionConfig(
              allowOnly: [caseRoot],
              denyWithinAllow: [join(caseRoot, 'real', 'secretdir', 'out')],
            ),
            mandatoryDenySearchDepth: 1,
          ),
        );
      }

      test(
        'keeps a denyWrite bind whose path only passes through a read-denied directory',
        () async {
          final caseRoot = join(ROOT, 's8', 'root');
          final hooks = join(caseRoot, 'elsewhere', 'hooks');
          final wrapped = await wrapDenyWriteThroughDeniedDir('true');

          expect(
            countMounts(wrapped, [
              '--tmpfs',
              join(caseRoot, 'real', 'secretdir'),
            ]),
            greaterThan(0),
          );
          expect(wrapped, contains('--ro-bind $hooks $hooks'));
        },
      );

      test(
        'refuses the write that bind protects',
        skip: hasBwrap ? null : 'bwrap cannot create namespaces',
        () async {
          final hooks = join(ROOT, 's8', 'root', 'elsewhere', 'hooks');
          final stdout = runBooted(
            await wrapDenyWriteThroughDeniedDir(
              'echo BOOTED; touch ${join(hooks, 'x')} && echo WRITTEN || echo DENIED',
            ),
          );
          expect(stdout, 'BOOTED\nDENIED\n');
        },
      );

      test(
        're-applies one mask for a file denied through a symlinked directory',
        () async {
          // writeRoot/lnk -> real, denyRead [writeRoot/lnk/secret], denyWrite
          // [writeRoot]: the mask sits on writeRoot/real/secret alone, so the
          // bind of writeRoot re-exposes one file and one mask goes back (a
          // second on the same inode aborts bwrap before 0.5).
          final writeRoot = join(ROOT, 's10', 'W');
          mkdirSync(join(writeRoot, 'real'), {'recursive': true});
          writeFileSync(join(writeRoot, 'real', 'secret'), 'S');
          symlinkSync('real', join(writeRoot, 'lnk'));
          final wrapped = await wrapCommandWithSandboxLinux(
            LinuxSandboxParams(
              command: 'true',
              needsNetworkRestriction: false,
              readConfig: FsReadRestrictionConfig(
                denyOnly: [join(writeRoot, 'lnk', 'secret')],
              ),
              writeConfig: FsWriteRestrictionConfig(
                allowOnly: [writeRoot],
                denyWithinAllow: [writeRoot],
              ),
              mandatoryDenySearchDepth: 1,
            ),
          );
          final mask =
              '--ro-bind /dev/null ${join(writeRoot, 'real', 'secret')}';
          final afterDenyBind = wrapped.substring(
            wrapped.lastIndexOf('--ro-bind $writeRoot $writeRoot'),
          );
          expect(afterDenyBind.split(mask), hasLength(2));
          expect(
            wrapped,
            isNot(contains('/dev/null ${join(writeRoot, 'lnk', 'secret')}')),
          );
        },
      );

      // denyRead **/.env with the working directory an allowed write root and
      // mode 0311 (what a sandboxed command can leave behind): the .env files
      // beneath it cannot be enumerated, so the directory is denied whole, and
      // binding the write root back over that tmpfs would show every one of
      // them unmasked.
      String unlistableCwd() {
        final cwd = join(ROOT, 's11', 'cwd');
        mkdirSync(join(cwd, 'svc'), {'recursive': true});
        writeFileSync(join(cwd, '.env'), 'ENV1');
        writeFileSync(join(cwd, 'svc', '.env'), 'ENV2');
        chmodSync(cwd, 201); // 0o311
        return cwd;
      }

      Future<String> wrapUnlistableCwd(String command) async {
        final cwd = unlistableCwd();
        final unlistableDenyDirs = <String>{};
        final denyOnly = expandReadDenyGlobLinux(join(cwd, '**/.env'), [
          cwd,
        ], unlistableDirs: unlistableDenyDirs);
        expect(denyOnly, [cwd]);
        expect([...unlistableDenyDirs], [cwd]);
        return wrapCommandWithSandboxLinux(
          LinuxSandboxParams(
            command: command,
            needsNetworkRestriction: false,
            readConfig: FsReadRestrictionConfig(
              denyOnly: denyOnly,
              unlistableDenyDirs: [...unlistableDenyDirs],
            ),
            writeConfig: FsWriteRestrictionConfig(
              allowOnly: [cwd],
              denyWithinAllow: [],
            ),
            mandatoryDenySearchDepth: 1,
          ),
        );
      }

      test(
        'restores nothing beneath a directory the glob expansion could not list',
        skip: process.getuid?.call() != 0 ? null : 'running as root',
        () async {
          try {
            final cwd = join(ROOT, 's11', 'cwd');
            final wrapped = await wrapUnlistableCwd('true');

            expect(
              wrapped.substring(wrapped.indexOf('--tmpfs $cwd ')),
              isNot(contains('--bind $cwd $cwd')),
            );
          } finally {
            chmodSync(join(ROOT, 's11', 'cwd'), 493); // 0o755
          }
        },
      );

      test(
        'serves none of the files beneath it',
        skip: process.getuid?.call() != 0 && hasBwrap
            ? null
            : 'running as root, or bwrap cannot create namespaces',
        () async {
          try {
            final cwd = join(ROOT, 's11', 'cwd');
            final stdout = runBooted(
              await wrapUnlistableCwd(
                'echo BOOTED; cat ${join(cwd, '.env')} ${join(cwd, 'svc', '.env')} || echo HIDDEN',
              ),
            );
            expect(stdout, isNot(contains('ENV1')));
            expect(stdout, isNot(contains('ENV2')));
            expect(stdout, contains('HIDDEN'));
          } finally {
            chmodSync(join(ROOT, 's11', 'cwd'), 493); // 0o755
          }
        },
      );

      test(
        'keeps the carve-outs of a literal deny of a directory it cannot list',
        skip: process.getuid?.call() != 0 ? null : 'running as root',
        () async {
          // The same directory, denied literally: nothing was enumerated under
          // it, so nothing is missing from the deny either, and the allowed
          // write path inside it is bound back as on any other denied
          // directory. Without that bind the build writes into the tmpfs and
          // loses its output when the command exits.
          final cwd = join(ROOT, 's15', 'cwd');
          final out = join(cwd, 'out');
          mkdirSync(out, {'recursive': true});
          writeFileSync(join(cwd, '.env'), 'ENV');
          chmodSync(cwd, 201); // 0o311
          try {
            final wrapped = await wrapCommandWithSandboxLinux(
              LinuxSandboxParams(
                command: 'true',
                needsNetworkRestriction: false,
                readConfig: FsReadRestrictionConfig(denyOnly: [cwd]),
                writeConfig: FsWriteRestrictionConfig(
                  allowOnly: [out],
                  denyWithinAllow: [],
                ),
                mandatoryDenySearchDepth: 1,
              ),
            );

            final tmpfs = wrapped.lastIndexOf('--tmpfs $cwd ');
            expect(tmpfs, greaterThan(-1));
            expect(
              wrapped.indexOf('--bind $out $out ', tmpfs),
              greaterThan(tmpfs),
            );
          } finally {
            chmodSync(cwd, 493); // 0o755
          }
        },
      );

      // proj/pkg is readable but not searchable (0600): its entries can be
      // listed, so the pattern matches pkg/.env and finds pkg/build, but
      // neither can be stat'ed. Skipped as absent, both would be readable once
      // the mode is put back.
      Future<String> wrapUninspectableEntries(String command) async {
        final proj = join(ROOT, 's12', 'proj');
        final pkg = join(proj, 'pkg');
        mkdirSync(join(pkg, 'build'), {'recursive': true});
        writeFileSync(join(pkg, '.env'), 'ENV');
        writeFileSync(join(pkg, 'build', 'o'), 'OUT');
        chmodSync(pkg, 384); // 0o600
        final denyOnly = [
          ...expandReadDenyGlobLinux(join(proj, '**/build/**'), [proj]),
          ...expandReadDenyGlobLinux(join(proj, '**/.env'), [proj]),
        ];
        expect(denyOnly, contains(join(pkg, '.env')));
        return wrapCommandWithSandboxLinux(
          LinuxSandboxParams(
            command: command,
            needsNetworkRestriction: false,
            readConfig: FsReadRestrictionConfig(denyOnly: denyOnly),
            writeConfig: FsWriteRestrictionConfig(
              allowOnly: [proj],
              denyWithinAllow: [],
            ),
            mandatoryDenySearchDepth: 1,
          ),
        );
      }

      test(
        'hides the nearest directory it can inspect when an entry cannot be looked at',
        skip: process.getuid?.call() != 0 ? null : 'running as root',
        () async {
          final pkg = join(ROOT, 's12', 'proj', 'pkg');
          try {
            expect(
              countMounts(await wrapUninspectableEntries('true'), [
                '--tmpfs',
                pkg,
              ]),
              greaterThan(0),
            );
          } finally {
            chmodSync(pkg, 493); // 0o755
          }
        },
      );

      test(
        'serves neither entry once the command puts the mode back',
        skip: process.getuid?.call() != 0 && hasBwrap
            ? null
            : 'running as root, or bwrap cannot create namespaces',
        () async {
          final pkg = join(ROOT, 's12', 'proj', 'pkg');
          try {
            final stdout = runBooted(
              await wrapUninspectableEntries(
                'echo BOOTED; chmod 755 $pkg; cat ${join(pkg, '.env')} ${join(pkg, 'build', 'o')} || echo HIDDEN',
              ),
            );
            expect(stdout, isNot(contains('ENV')));
            expect(stdout, isNot(contains('OUT')));
            expect(stdout, contains('HIDDEN'));
          } finally {
            chmodSync(pkg, 493); // 0o755
          }
        },
      );

      /**
     * A matched link whose target is there but cannot be looked at: the
     * shape a sandboxed command leaves behind by making the target's
     * directory unsearchable, which it can undo from inside the next
     * sandbox. Dropped as "does not resolve", the deny would vanish for
     * exactly that command. EACCES is injected through fs spies, since a
     * root container sees no real one; the sandboxed command itself then
     * runs against the real filesystem.
     */
      Future<({String wrapped, String certs, String link})>
      wrapUninspectableLinkTarget(String command) async {
        final caseRootDir = join(ROOT, 's16');
        final certs = join(caseRootDir, 'certs');
        final secret = join(caseRootDir, 'secret');
        final link = join(certs, 'k');
        mkdirSync(certs, {'recursive': true});
        mkdirSync(secret, {'recursive': true});
        writeFileSync(join(secret, 'k'), 'KEYBYTES');
        ensureLink(join('..', 'secret', 'k'), link);

        bool unreachable(String p) =>
            p == link || p.startsWith(secret + '/') || p == secret;
        Never eacces(String p) {
          throw NodeError("EACCES: permission denied, '$p'", code: 'EACCES');
        }

        final realStat = fs.statSync;
        final realRealpath = fs.realpathSync;
        fs.statSync = (String p) => unreachable(p) ? eacces(p) : realStat(p);
        fs.realpathSync = (String p) =>
            unreachable(p) ? eacces(p) : realRealpath(p);
        try {
          final wrapped = await wrapCommandWithSandboxLinux(
            LinuxSandboxParams(
              command: command,
              needsNetworkRestriction: false,
              readConfig: FsReadRestrictionConfig(
                denyOnly: expandReadDenyGlobLinux(join(certs, '*'), []),
              ),
              writeConfig: FsWriteRestrictionConfig(
                allowOnly: [caseRootDir],
                denyWithinAllow: [],
              ),
              mandatoryDenySearchDepth: 1,
            ),
          );
          return (wrapped: wrapped, certs: certs, link: link);
        } finally {
          fs.statSync = realStat;
          fs.realpathSync = realRealpath;
        }
      }

      test(
        'hides what holds a matched link whose target cannot be looked at',
        () async {
          final (:wrapped, :certs, :link) = await wrapUninspectableLinkTarget(
            'true',
          );

          // The deny reaches the mount loop under the link's own spelling, where
          // the stand-in rule hides the nearest directory that can be inspected.
          expect(countMounts(wrapped, ['--tmpfs', certs]), greaterThan(0));
          expect(countMounts(wrapped, ['--tmpfs', link]), 0);
        },
      );

      test(
        'serves that link nothing, even once the command can look at the target again',
        skip: hasBwrap ? null : 'bwrap cannot create namespaces',
        () async {
          final (:wrapped, :certs, :link) = await wrapUninspectableLinkTarget(
            'echo BOOTED; cat ${join(ROOT, 's16', 'certs', 'k')} || echo HIDDEN; ls ${join(ROOT, 's16', 'certs')}',
          );
          final stdout = runBooted(wrapped);

          expect(stdout, isNot(contains('KEYBYTES')));
          expect(stdout, contains('HIDDEN'));
          expect(link, join(ROOT, 's16', 'certs', 'k'));
        },
      );

      // A sandboxed command with write access under the pattern's base can
      // plant a link to the root; a mount on it, or on what it resolves to,
      // would stop every later command. The directory holding it is hidden
      // instead, by the same rule as an entry that cannot be inspected.
      Future<String> wrapLinkToRoot(String command) {
        final proj = join(ROOT, 's13', 'proj');
        mkdirSync(join(proj, 'img'), {'recursive': true});
        writeFileSync(join(proj, 'img', 'note.txt'), 'NOTE');
        ensureLink('/', join(proj, 'img', 'build'));
        return wrapCommandWithSandboxLinux(
          LinuxSandboxParams(
            command: command,
            needsNetworkRestriction: false,
            readConfig: FsReadRestrictionConfig(
              denyOnly: [
                ...expandReadDenyGlobLinux(join(proj, '**/build/**'), []),
                // Named literally, the loop applies the same rule.
                join(proj, 'img', 'build'),
              ],
            ),
            writeConfig: FsWriteRestrictionConfig(
              allowOnly: [],
              denyWithinAllow: [],
            ),
            allowAllUnixSockets: true,
          ),
        );
      }

      test(
        'hides the directory holding a matched link to / instead of the root',
        () async {
          final img = join(ROOT, 's13', 'proj', 'img');
          final wrapped = await wrapLinkToRoot('true');

          expect(countMounts(wrapped, ['--tmpfs', img]), greaterThan(0));
          expect(countMounts(wrapped, ['--tmpfs', join(img, 'build')]), 0);
          // A --tmpfs / would wipe every mount before it and boot the command on
          // an empty tree, so it is never emitted, whatever a link resolves to.
          expect(countMounts(wrapped, ['--tmpfs', '/']), 0);
        },
      );

      test('keeps a link to / out of the read-deny prediction', () async {
        // The prediction says where the loop will mount a tmpfs, and every
        // covering deny directory lies under '/'. Predicted there, no deny
        // stub could be skipped anywhere on the host, and a write-denied
        // checkout would refuse to start: bubblewrap cannot create a stub's
        // mount point inside a read-only bind. A link to the root is predicted
        // at the directory holding it, where the loop mounts it.
        final work = join(ROOT, 's17', 'work');
        final proj = join(work, 'proj');
        mkdirSync(join(proj, 'img'), {'recursive': true});
        ensureLink('/', join(proj, 'img', 'build'));

        final wrapped = await wrapCommandWithSandboxLinux(
          LinuxSandboxParams(
            command: 'true',
            needsNetworkRestriction: false,
            readConfig: FsReadRestrictionConfig(
              denyOnly: [join(proj, 'img', 'build')],
            ),
            writeConfig: FsWriteRestrictionConfig(
              allowOnly: [work],
              denyWithinAllow: [proj, join(proj, '.claude', 'settings.json')],
            ),
            mandatoryDenySearchDepth: 1,
          ),
        );

        expect(
          countMounts(wrapped, ['--tmpfs', join(proj, 'img')]),
          greaterThan(0),
        );
        expect(countMounts(wrapped, ['--tmpfs', '/']), 0);
        // The absent deny path under the read-only bind of proj keeps no stub.
        expect(
          wrapped
              .split(' --')
              .where((op) => op.contains(' ${join(proj, '.claude')}'))
              .toList(),
          [],
        );
      });

      test(
        'starts, with that directory hidden',
        skip: hasBwrap ? null : 'bwrap cannot create namespaces',
        () async {
          final img = join(ROOT, 's13', 'proj', 'img');
          final stdout = runBooted(
            await wrapLinkToRoot(
              'echo BOOTED; cat ${join(img, 'note.txt')} || echo HIDDEN; ls /',
            ),
          );
          expect(stdout, isNot(contains('NOTE')));
          expect(stdout, contains('HIDDEN'));
          // The root itself is untouched: the command can still list it.
          expect(stdout, contains('usr'));
        },
      );

      // denyWrite [proj, proj/.claude/settings.json (absent)] + denyRead
      // proj/**/build/**: collapsed, the pattern is a tmpfs beneath the
      // write-denied directory. The absent deny path is uncreatable under
      // proj's read-only bind either way, and a stub for it would have bwrap
      // create a mount point inside that bind and abort.
      Future<String> wrapWriteDeniedCheckout(String command) async {
        final work = join(ROOT, 's14', 'work');
        final proj = join(work, 'proj');
        mkdirSync(join(proj, 'pkg', 'build'), {'recursive': true});
        writeFileSync(join(proj, 'pkg', 'build', '1.out'), 'OUT');
        final cwd = process.cwd();
        Directory.current = proj;
        try {
          return await wrapCommandWithSandboxLinux(
            LinuxSandboxParams(
              command: command,
              needsNetworkRestriction: false,
              readConfig: FsReadRestrictionConfig(
                denyOnly: expandReadDenyGlobLinux(join(proj, '**/build/**'), [
                  work,
                ]),
              ),
              writeConfig: FsWriteRestrictionConfig(
                allowOnly: [work],
                denyWithinAllow: [proj, join(proj, '.claude', 'settings.json')],
              ),
              mandatoryDenySearchDepth: 1,
            ),
          );
        } finally {
          Directory.current = cwd;
        }
      }

      test(
        'keeps no deny stub in a write-denied checkout with a denyRead pattern matching a directory inside it',
        () async {
          final proj = join(ROOT, 's14', 'work', 'proj');
          final wrapped = await wrapWriteDeniedCheckout('true');

          final projBind = lastIndexOfMount(wrapped, ['--ro-bind', proj, proj]);
          expect(projBind, greaterThan(-1));
          // No stub: nothing is mounted at or beneath proj/.claude.
          expect(
            wrapped
                .substring(0, wrapped.indexOf(' --dev '))
                .split(' --')
                .where((op) => op.contains(' ${join(proj, '.claude')}'))
                .toList(),
            [],
          );
          expect(
            lastIndexOfMount(wrapped, ['--tmpfs', join(proj, 'pkg', 'build')]),
            greaterThan(projBind),
          );
        },
      );

      test(
        'starts such a checkout, with the directory hidden and the absent deny path uncreatable',
        skip: hasBwrap ? null : 'bwrap cannot create namespaces',
        () async {
          final proj = join(ROOT, 's14', 'work', 'proj');
          final stdout = runBooted(
            await wrapWriteDeniedCheckout(
              'echo BOOTED; mkdir ${join(proj, '.claude')} || echo UNCREATABLE; cat ${join(proj, 'pkg', 'build', '1.out')} || echo HIDDEN',
            ),
          );
          expect(stdout, 'BOOTED\nUNCREATABLE\nHIDDEN\n');
        },
      );

      // denyRead [cfg, cfg/token], cfg/token -> ../secrets/token: the link
      // vanishes with cfg's tmpfs, but the file it named is the target, which
      // stays reachable by its own name and must be masked there.
      Future<String> wrapFileLinkBeneathDeniedDir(String command) {
        final cfg = join(ROOT, 's9', 'cfg');
        final secrets = join(ROOT, 's9', 'secrets');
        mkdirSync(cfg, {'recursive': true});
        mkdirSync(secrets, {'recursive': true});
        writeFileSync(join(secrets, 'token'), 'TOKEN');
        ensureLink(join('..', 'secrets', 'token'), join(cfg, 'token'));
        return wrapCommandWithSandboxLinux(
          LinuxSandboxParams(
            command: command,
            needsNetworkRestriction: false,
            readConfig: FsReadRestrictionConfig(
              denyOnly: [cfg, join(cfg, 'token')],
            ),
            writeConfig: FsWriteRestrictionConfig(
              allowOnly: [],
              denyWithinAllow: [],
            ),
          ),
        );
      }

      test(
        'still masks the target of a file symlink listed beneath a denied directory',
        () async {
          final secrets = join(ROOT, 's9', 'secrets');
          final wrapped = await wrapFileLinkBeneathDeniedDir('true');

          expect(
            wrapped,
            contains('--ro-bind /dev/null ${join(secrets, 'token')}'),
          );
        },
      );

      test(
        'serves that target masked under its own name',
        skip: hasBwrap ? null : 'bwrap cannot create namespaces',
        () async {
          final secrets = join(ROOT, 's9', 'secrets');
          final stdout = runBooted(
            await wrapFileLinkBeneathDeniedDir(
              'echo BOOTED; cat ${join(secrets, 'token')}; echo END',
            ),
          );
          expect(stdout, isNot(contains('TOKEN')));
          expect(stdout, contains('END'));
        },
      );

      group('a directory deny plus per-file entries beneath it', () {
        late String big;
        late List<String> keys;
        setUpAll(() {
          big = join(ROOT, 'big');
          mkdirSync(join(big, 'keep'), {'recursive': true});
          keys = [
            'a.key',
            'b.key',
            'keep/c.key',
          ].map((k) => join(big, k)).toList();
          for (final k in keys) {
            writeFileSync(k, '');
          }
        });

        test('costs one tmpfs', () async {
          final collapsed = await wrapCommandWithSandboxLinux(
            LinuxSandboxParams(
              command: 'true',
              needsNetworkRestriction: false,
              readConfig: FsReadRestrictionConfig(denyOnly: [big, ...keys]),
              writeConfig: FsWriteRestrictionConfig(
                allowOnly: [],
                denyWithinAllow: [],
              ),
            ),
          );
          expect(countMounts(collapsed, ['--tmpfs', big]), 1);
          expect(collapsed, isNot(contains('/dev/null $big/')));
        });

        test('keeps the masks beneath a carve-out', () async {
          final carved = await wrapCommandWithSandboxLinux(
            LinuxSandboxParams(
              command: 'true',
              needsNetworkRestriction: false,
              readConfig: FsReadRestrictionConfig(
                denyOnly: [big, ...keys],
                allowWithinDeny: [join(big, 'keep')],
              ),
              writeConfig: FsWriteRestrictionConfig(
                allowOnly: [],
                denyWithinAllow: [],
              ),
            ),
          );
          expect(
            carved,
            contains('--ro-bind /dev/null ${join(big, 'keep', 'c.key')}'),
          );
          expect(carved, isNot(contains('/dev/null ${join(big, 'a.key')}')));
        });
      });
    },
  );

  group('expandReadDenyGlobLinux (filesystem)', skip: isLinux ? null : 'requires Linux', () {
    late String ROOT;
    const PKGS = ['a', 'b', 'c'];

    setUpAll(() {
      ROOT = realpathSync(mkdtempSync(join(tmpdir(), 'deny-glob-collapse-')));
      // pkg/{a,b,c}/build/{1..5}.out plus a nested dir and a source file each
      for (final pkg in PKGS) {
        final build = join(ROOT, 'pkg', pkg, 'build');
        mkdirSync(join(build, 'nested'), {'recursive': true});
        for (var i = 1; i <= 5; i++) {
          writeFileSync(join(build, '$i.out'), '');
        }
        writeFileSync(join(build, 'nested', 'deep.out'), '');
        writeFileSync(join(ROOT, 'pkg', pkg, 'index.ts'), '');
      }
      // A FILE named build must not be swept up by the directory form.
      writeFileSync(join(ROOT, 'pkg', 'build'), '');
      // Something for an allowRead carve-out to re-expose.
      mkdirSync(join(ROOT, 'pkg', 'a', 'build', 'public'));
      writeFileSync(join(ROOT, 'pkg', 'a', 'build', 'public', 'ok.txt'), '');
    });

    tearDownAll(() {
      rmSync(ROOT, {'recursive': true, 'force': true});
    });

    test('collapses <root>/**/build/** to one mount per build directory', () {
      final pattern = join(ROOT, '**/build/**');
      expect(expandGlobPattern(pattern).length, greaterThanOrEqualTo(15));

      final mounts = expandReadDenyGlobLinux(pattern, []);

      expect(
        mounts,
        PKGS.map((pkg) => join(ROOT, 'pkg', pkg, 'build')).toList(),
      );
    });

    test(
      'keeps per-entry mounts under an allowRead carve-out inside a collapsed dir',
      () {
        final pattern = join(ROOT, '**/build/**');
        final carveOut = join(ROOT, 'pkg', 'a', 'build', 'public');

        final mounts = expandReadDenyGlobLinux(pattern, [carveOut]);

        for (final pkg in PKGS) {
          expect(mounts, contains(join(ROOT, 'pkg', pkg, 'build')));
        }
        expect(
          mounts,
          isNot(contains(join(ROOT, 'pkg', 'a', 'build', '1.out'))),
        );
        expect(
          mounts,
          isNot(contains(join(ROOT, 'pkg', 'b', 'build', 'nested'))),
        );
        // What the carve-out binds back keeps its own masks.
        expect(mounts, contains(carveOut));
        expect(mounts, contains(join(carveOut, 'ok.txt')));
      },
    );

    test(
      'normalizes an allowRead carve-out spelling before collapsing against it',
      () async {
        // The trailing slash is stripped before the collapse compares, so the
        // carve-out still keeps the file's own mask beneath the build tmpfs.
        final carveOut = join(ROOT, 'pkg', 'a', 'build', 'public');
        try {
          final wrapped = await SandboxManager.wrapWithSandbox(
            'echo hello',
            null,
            PartialSandboxRuntimeConfig(
              filesystem: FilesystemConfig(
                denyRead: [FilesystemPathSpelling(join(ROOT, '**/build/**'))],
                allowRead: [FilesystemPathSpelling(carveOut + '/')],
                allowWrite: [],
                denyWrite: [],
              ),
            ),
          );

          expect(
            countMounts(wrapped, ['--tmpfs', join(ROOT, 'pkg', 'a', 'build')]),
            greaterThan(0),
          );
          expect(
            wrapped,
            contains('--ro-bind /dev/null ${join(carveOut, 'ok.txt')}'),
          );
          expect(
            wrapped,
            isNot(
              contains(
                '--ro-bind /dev/null ${join(ROOT, 'pkg', 'b', 'build')}/',
              ),
            ),
          );
        } finally {
          await SandboxManager.reset();
        }
      },
    );

    test('seeds the ancestor pins from a collapsed directory', () async {
      // Every tmpfs the collapse adds is an ordinary read-deny unit, so the
      // directories between it and the allowed write root are pinned: the
      // package directory above a collapsed build/ cannot be renamed aside to
      // strip the deny off it.
      final pkgDir = join(ROOT, 'pkg', 'a');
      final build = join(pkgDir, 'build');
      final wrapped = await wrapCommandWithSandboxLinux(
        LinuxSandboxParams(
          command: 'echo hello',
          needsNetworkRestriction: false,
          readConfig: FsReadRestrictionConfig(
            denyOnly: expandReadDenyGlobLinux(join(ROOT, '**/build/**'), []),
            allowWithinDeny: [],
          ),
          writeConfig: FsWriteRestrictionConfig(
            allowOnly: [ROOT],
            denyWithinAllow: [],
          ),
        ),
      );

      final pin = '--ro-bind $pkgDir $pkgDir';
      expect(wrapped, contains(pin));
      // Beneath the write root's own bind, and so beneath the tmpfs too.
      expect(
        wrapped.indexOf(pin),
        lessThan(wrapped.indexOf('--bind $ROOT $ROOT')),
      );
      expect(countMounts(wrapped, ['--tmpfs', build]), greaterThan(0));
    });

    test(
      'refuses to rename the package directory above a collapsed build directory',
      skip: isLinux && bwrapCanNamespace()
          ? null
          : 'bwrap cannot create namespaces',
      () async {
        final pkgDir = join(ROOT, 'pkg', 'b');
        final wrapped = await wrapCommandWithSandboxLinux(
          LinuxSandboxParams(
            command:
                "sh -c 'echo BOOTED; mv $pkgDir $pkgDir-moved 2>&1; echo DONE'",
            needsNetworkRestriction: false,
            readConfig: FsReadRestrictionConfig(
              denyOnly: expandReadDenyGlobLinux(join(ROOT, '**/build/**'), []),
              allowWithinDeny: [],
            ),
            writeConfig: FsWriteRestrictionConfig(
              allowOnly: [ROOT],
              denyWithinAllow: [],
            ),
          ),
        );
        final result = spawnSync(wrapped, [], {
          'shell': true,
          'encoding': 'utf8',
          'timeout': 15000,
        });

        expect((result.stderr ?? '') as String, isNot(contains('bwrap:')));
        expect(result.stdout as String, contains('BOOTED'));
        expect(result.stdout as String, contains('DONE'));
        expect(
          result.stdout as String,
          matches(RegExp('busy', caseSensitive: false)),
        );
        expect(existsSync('$pkgDir-moved'), false);
      },
    );

    test(
      'restores a write path read-only when a write deny inside a collapsed directory is dropped',
      () async {
        // The collapsed tmpfs hides the write deny's own destination, so that
        // bind is dropped rather than re-exposing the read-denied directory
        // around it — and the allowed write path the tmpfs restored beneath that
        // destination comes back read-only, where the deny leaves it.
        final build = join(ROOT, 'pkg', 'c', 'build');
        final denied = join(build, 'nested');
        final writable = join(denied, 'out');
        mkdirSync(writable, {'recursive': true});
        final wrapped = await wrapCommandWithSandboxLinux(
          LinuxSandboxParams(
            command: 'echo hello',
            needsNetworkRestriction: false,
            readConfig: FsReadRestrictionConfig(
              denyOnly: expandReadDenyGlobLinux(join(ROOT, '**/build/**'), []),
              allowWithinDeny: [],
            ),
            writeConfig: FsWriteRestrictionConfig(
              allowOnly: [ROOT, writable],
              denyWithinAllow: [denied],
            ),
          ),
        );

        final tmpfs = wrapped.lastIndexOf('--tmpfs $build ');
        expect(tmpfs, greaterThan(-1));
        // The deny's own bind is dropped (its ancestor pin, spelled the same,
        // sits beneath the write root's bind, so only what follows the tmpfs
        // counts).
        expect(wrapped.indexOf('--ro-bind $denied $denied', tmpfs), -1);
        // The tmpfs put the write path back writable; the dropped bind puts it
        // back read-only on top, which is where the deny leaves it.
        final writableBind = wrapped.indexOf(
          '--bind $writable $writable',
          tmpfs,
        );
        final readOnlyRestore = wrapped.lastIndexOf(
          '--ro-bind $writable $writable',
        );
        expect(writableBind, greaterThan(tmpfs));
        expect(readOnlyRestore, greaterThan(writableBind));
      },
    );

    test(
      'leaves a masked file inside a collapsed directory to its mask',
      () async {
        // The dropped write-deny bind restores what the tmpfs put back beneath
        // it, but never a masked file: binding the real file read-only there
        // would land above its mask and serve the real bytes.
        final build = join(ROOT, 'pkg', 'a', 'build');
        final secret = join(build, 'cred.json');
        writeFileSync(secret, 'REAL-CREDENTIAL\n');
        final store = mkdtempSync(join(tmpdir(), 'deny-glob-store-'));
        final fake = join(store, 'cred.json.fake');
        writeFileSync(fake, 'SENTINEL\n');
        try {
          final wrapped = await wrapCommandWithSandboxLinux(
            LinuxSandboxParams(
              command: 'echo hello',
              needsNetworkRestriction: false,
              readConfig: FsReadRestrictionConfig(
                denyOnly: expandReadDenyGlobLinux(join(ROOT, '**/build/**'), [
                  secret,
                ]),
                allowWithinDeny: [],
              ),
              writeConfig: FsWriteRestrictionConfig(
                allowOnly: [ROOT, secret],
                denyWithinAllow: [build],
              ),
              maskedFileBinds: [(realPath: secret, fakePath: fake)],
              maskedFileStoreDir: store,
            ),
          );

          expect(wrapped, contains('--ro-bind $fake $secret'));
          expect(wrapped, isNot(contains('--ro-bind $secret $secret')));
          final mask = wrapped.lastIndexOf('--ro-bind $fake $secret');
          expect(wrapped.indexOf('--bind $secret $secret', mask), -1);
        } finally {
          rmSync(store, {'recursive': true, 'force': true});
          rmSync(secret, {'force': true});
        }
      },
    );

    test(
      'leaves a pattern without a trailing /** to collapse only among its own matches',
      () {
        // **/*.out matches files only: nothing to collapse under.
        final pattern = join(ROOT, '**/*.out');
        final mounts = expandReadDenyGlobLinux(pattern, []);
        expect(mounts.length, expandGlobPattern(pattern).length);
        expect(mounts.length, PKGS.length * 6);
      },
    );

    test(
      'reaches bwrap as directory tmpfs mounts, and a non-glob deny is untouched',
      () async {
        final literalFile = join(ROOT, 'pkg', 'a', 'index.ts');
        try {
          final wrapped = await SandboxManager.wrapWithSandbox(
            'echo hello',
            null,
            PartialSandboxRuntimeConfig(
              filesystem: FilesystemConfig(
                denyRead: [
                  FilesystemPathSpelling(join(ROOT, '**/build/**')),
                  FilesystemPathSpelling(literalFile),
                ],
                allowWrite: [],
                denyWrite: [],
              ),
            ),
          );

          for (final pkg in PKGS) {
            expect(
              countMounts(wrapped, [
                '--tmpfs',
                join(ROOT, 'pkg', pkg, 'build'),
              ]),
              greaterThan(0),
            );
          }
          for (final pkg in PKGS) {
            expect(
              wrapped,
              isNot(
                contains(
                  '--ro-bind /dev/null ${join(ROOT, 'pkg', pkg, 'build')}/',
                ),
              ),
            );
          }
          expect(wrapped, contains('--ro-bind /dev/null $literalFile'));
        } finally {
          await SandboxManager.reset();
        }
      },
    );

    test(
      'mounts nothing for a pattern whose base is not there, beneath a write root',
      () async {
        // Denied, a base made between the walk and the mounts, as here, would be
        // an empty tmpfs over a part of the write root, and what the command
        // writes there would be lost.
        final absent = join(ROOT, 'absent');
        Future<String> wrap(List<String> denyRead) =>
            SandboxManager.wrapWithSandbox(
              'echo hello',
              null,
              PartialSandboxRuntimeConfig(
                filesystem: FilesystemConfig(
                  denyRead: [
                    for (final p in denyRead) FilesystemPathSpelling(p),
                  ],
                  allowWrite: [FilesystemPathSpelling(ROOT)],
                  denyWrite: [],
                ),
              ),
            );
        final readdirSync = fs.readdirSync;
        void restore() => fs.readdirSync = readdirSync;
        fs.readdirSync = (String path, {bool withFileTypes = true}) {
          try {
            return readdirSync(path, withFileTypes: withFileTypes);
          } finally {
            if (path == absent) mkdirSync(absent);
          }
        };
        try {
          final wrapped = await wrap([join(absent, '**/*.out')]);
          restore();

          expect(existsSync(absent), true);
          expect(wrapped, await wrap([]));
        } finally {
          restore();
          await SandboxManager.reset();
          rmSync(absent, {'recursive': true, 'force': true});
        }
      },
    );
  });

  group(
    'expandReadDenyGlobLinux (coverage behind a directory link)',
    skip: isLinux ? null : 'requires Linux',
    () {
      // The walk descends symlinked directories and reports each match where it
      // really lives, so a deny glob covers what it matches whichever spelling
      // found it, and one mount stands for every spelling. These cases are the
      // ones a walk that does not follow links loses outright.
      late String ROOT;
      late String BASE;
      late String LNK;
      late String ABS;
      late String REALKEY;
      // Dart: a skipped group's body still runs, and the probe needs bwrap.
      final CAN_RUN = isLinux && bwrapCanNamespace();

      setUpAll(() {
        ROOT = realpathSync(mkdtempSync(join(tmpdir(), 'deny-glob-links-')));
        // A link named by the pattern's own wildcard segment.
        BASE = join(ROOT, 'base');
        mkdirSync(join(BASE, 'real', 'cfg'), {'recursive': true});
        REALKEY = join(BASE, 'real', 'cfg', 'key.txt');
        writeFileSync(REALKEY, 'KEYBYTES\n');
        LNK = join(BASE, 'lnk');
        symlinkSync(join('real', 'cfg'), LNK);
        ABS = join(BASE, 'abs');
        symlinkSync(join(BASE, 'real', 'cfg'), ABS);
        // A link whose target is outside the pattern's base directory.
        mkdirSync(join(ROOT, 'out', 'config', 'dev'), {'recursive': true});
        mkdirSync(join(ROOT, 'out', 'shared', 'prod'), {'recursive': true});
        writeFileSync(join(ROOT, 'out', 'config', 'dev', 'key'), 'DEVKEY\n');
        writeFileSync(join(ROOT, 'out', 'shared', 'prod', 'key'), 'PRODKEY\n');
        symlinkSync(
          join('..', 'shared', 'prod'),
          join(ROOT, 'out', 'config', 'prod'),
        );
        // The same, with an absolute target.
        mkdirSync(join(ROOT, 'absout', 'config'), {'recursive': true});
        mkdirSync(join(ROOT, 'absout', 'elsewhere', 'prod'), {
          'recursive': true,
        });
        writeFileSync(
          join(ROOT, 'absout', 'elsewhere', 'prod', 'key'),
          'ABS\n',
        );
        symlinkSync(
          join(ROOT, 'absout', 'elsewhere', 'prod'),
          join(ROOT, 'absout', 'config', 'prod'),
        );
        // A package linked out of node_modules, as a workspace install leaves it.
        mkdirSync(join(ROOT, 'store', 'node_modules', 'other'), {
          'recursive': true,
        });
        mkdirSync(join(ROOT, 'store', 'packages', 'pkg'), {'recursive': true});
        writeFileSync(
          join(ROOT, 'store', 'node_modules', 'other', 'index.js'),
          'OTHER\n',
        );
        writeFileSync(
          join(ROOT, 'store', 'packages', 'pkg', 'index.js'),
          'PKG\n',
        );
        symlinkSync(
          join('..', 'packages', 'pkg'),
          join(ROOT, 'store', 'node_modules', 'pkg'),
        );
        // A link to its own directory, and two links into each other.
        mkdirSync(join(ROOT, 'cycles', 'a'), {'recursive': true});
        mkdirSync(join(ROOT, 'cycles', 'b'), {'recursive': true});
        writeFileSync(join(ROOT, 'cycles', 'a', 'key.txt'), 'AKEY\n');
        writeFileSync(join(ROOT, 'cycles', 'b', 'key.txt'), 'BKEY\n');
        symlinkSync('.', join(ROOT, 'cycles', 'self'));
        symlinkSync(join('..', 'b'), join(ROOT, 'cycles', 'a', 'l1'));
        symlinkSync(join('..', 'a'), join(ROOT, 'cycles', 'b', 'l2'));
        // build/ as a link, and a build/ directory behind a link.
        mkdirSync(join(ROOT, 'builds', 'pkg1', 'build'), {'recursive': true});
        mkdirSync(join(ROOT, 'builds', 'linked'), {'recursive': true});
        mkdirSync(join(ROOT, 'builds', 'pkg2'), {'recursive': true});
        mkdirSync(join(ROOT, 'builds', 'pkg3'), {'recursive': true});
        mkdirSync(join(ROOT, 'builds', 'realpkg', 'build'), {
          'recursive': true,
        });
        writeFileSync(join(ROOT, 'builds', 'pkg1', 'build', 'f'), 'ONE\n');
        writeFileSync(join(ROOT, 'builds', 'linked', 'f'), 'LINKED\n');
        writeFileSync(
          join(ROOT, 'builds', 'realpkg', 'build', 'f'),
          'BEHIND\n',
        );
        symlinkSync(
          join('..', 'linked'),
          join(ROOT, 'builds', 'pkg2', 'build'),
        );
        symlinkSync(join('..', 'realpkg'), join(ROOT, 'builds', 'pkg3', 'lnk'));
      });

      tearDownAll(() {
        rmSync(ROOT, {'recursive': true, 'force': true});
      });

      const LINK_PATTERNS = [
        ('the wildcard segment names the link', 'l*/key.txt'),
        ('a bare star names the link', '*/key.txt'),
        ('a globstar reaches the link by name', '**/lnk/key.txt'),
        ('a globstar tail matches below the link', '**/key.txt'),
        ('the tail names the target directory', '**/cfg/key.txt'),
        ('the pattern spans depths through the link', 'l*/**/key.txt'),
        ('the link has an absolute target inside the base', 'a*/key.txt'),
      ];

      for (final (why, tail) in LINK_PATTERNS)
        test('covers the file behind a directory link when $why', () {
          expect(expandReadDenyGlobLinux(join(BASE, tail), []), [REALKEY]);
        });

      test(
        'mounts a match behind a link whose target is outside the pattern base, at its target',
        () {
          final mounts = expandReadDenyGlobLinux(
            join(ROOT, 'out', 'config', '*', 'key'),
            [],
          );

          expect(mounts, [
            join(ROOT, 'out', 'config', 'dev', 'key'),
            join(ROOT, 'out', 'shared', 'prod', 'key'),
          ]);
        },
      );

      test(
        'mounts a match behind an absolute-target link outside the base, at its target',
        () {
          final mounts = expandReadDenyGlobLinux(
            join(ROOT, 'absout', 'config', '*', 'key'),
            [],
          );

          expect(mounts, [join(ROOT, 'absout', 'elsewhere', 'prod', 'key')]);
        },
      );

      test(
        'mounts a package linked out of node_modules where the package really is',
        () {
          final mounts = expandReadDenyGlobLinux(
            join(ROOT, 'store', 'node_modules', '**', 'index.js'),
            [],
          );

          expect(mounts, [
            join(ROOT, 'store', 'node_modules', 'other', 'index.js'),
            join(ROOT, 'store', 'packages', 'pkg', 'index.js'),
          ]);
        },
      );

      test(
        'terminates on a link to its own directory and on two links into each other',
        () {
          final mounts = expandReadDenyGlobLinux(
            join(ROOT, 'cycles', '**', 'key.txt'),
            [],
          );

          expect(mounts, [
            join(ROOT, 'cycles', 'a', 'key.txt'),
            join(ROOT, 'cycles', 'b', 'key.txt'),
          ]);
        },
      );

      test(
        'collapses a linked build directory, and one behind a link, onto their targets',
        () {
          final mounts = expandReadDenyGlobLinux(
            join(ROOT, 'builds', '**', 'build', '**'),
            [],
          );

          expect(mounts, [
            join(ROOT, 'builds', 'linked'),
            join(ROOT, 'builds', 'pkg1', 'build'),
            join(ROOT, 'builds', 'realpkg', 'build'),
          ]);
        },
      );

      for (final (why, tail) in LINK_PATTERNS)
        test(
          'serves the file through neither spelling when $why',
          skip: CAN_RUN ? null : 'bwrap cannot create namespaces',
          () async {
            final wrapped = await wrapCommandWithSandboxLinux(
              LinuxSandboxParams(
                command:
                    "sh -c 'echo BOOTED; cat ${join(LNK, 'key.txt')} 2>&1; cat $REALKEY 2>&1; cat ${join(ABS, 'key.txt')} 2>&1'",
                needsNetworkRestriction: false,
                readConfig: FsReadRestrictionConfig(
                  denyOnly: expandReadDenyGlobLinux(join(BASE, tail), []),
                  allowWithinDeny: [],
                ),
                writeConfig: FsWriteRestrictionConfig(
                  allowOnly: [],
                  denyWithinAllow: [],
                ),
                allowAllUnixSockets: true,
              ),
            );
            final result = spawnSync(wrapped, [], {
              'shell': true,
              'encoding': 'utf8',
              'timeout': 15000,
            });

            expect((result.stderr ?? '') as String, isNot(contains('bwrap:')));
            expect(result.stdout as String, contains('BOOTED'));
            expect(result.stdout as String, isNot(contains('KEYBYTES')));
          },
        );
    },
  );
}
