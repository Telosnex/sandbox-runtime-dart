// Ported from sandbox-runtime test/sandbox/glob-expand.test.ts @ 24eb39e.
// ignore_for_file: slash_for_doc_comments, constant_identifier_names, non_constant_identifier_names

// <reference lib="es2021.weakref" />
import 'dart:async';
import 'dart:io';
import 'dart:math';

import 'package:path/path.dart' as path;
import 'package:path/path.dart' show basename, join;
import 'package:sandbox_runtime/src/node/abort.dart';
// The namespace of the same module production binds (sandbox-utils.ts does
// `import * as fs from 'fs'`), so a spy on it is seen by the code under test.
import 'package:sandbox_runtime/src/node/fs.dart' as fs;
import 'package:sandbox_runtime/src/node/fs.dart'
    show
        chmodSync,
        existsSync,
        mkdirSync,
        mkdtempSync,
        realpathSync,
        rmSync,
        writeFileSync;
import 'package:sandbox_runtime/src/node/errno.dart' show NodeError;
import 'package:sandbox_runtime/src/node/generators.dart';
import 'package:sandbox_runtime/src/node/globals.dart'
    show clearTimeout, setTimeout;
import 'package:sandbox_runtime/src/node/os.dart' show tmpdir;
import 'package:sandbox_runtime/src/node/process.dart' as process;
import 'package:sandbox_runtime/src/sandbox/path_entries.dart'
    show literalReadings;
import 'package:sandbox_runtime/src/sandbox/sandbox_config.dart'
    show
        FilesystemConfig,
        FilesystemPathEntry,
        FilesystemPathLiteral,
        FilesystemPathSpelling,
        CredentialFileConfig,
        CredentialsConfig,
        NetworkConfig,
        RipgrepConfig,
        SandboxRuntimeConfig;
import 'package:sandbox_runtime/src/sandbox/sandbox_manager.dart'
    show ISandboxManager, PartialSandboxRuntimeConfig, SandboxManager;
import 'package:sandbox_runtime/src/sandbox/sandbox_utils.dart'
    show
        GlobWalk,
        GlobWalkListings,
        Steps,
        denyGlobRegex,
        expandGlobPattern,
        expandTilde,
        finish,
        finishInTurns,
        globBaseDirIsRoot,
        globPatternBaseDir,
        globToRegex,
        normalizePathForSandbox,
        walkGlobPattern,
        walkGlobPatternSteps;
import 'package:sandbox_runtime/src/sandbox/windows_sandbox_utils.dart'
    show
        WindowsSandboxError,
        containsGlobCharsWin,
        expandWindowsFsPaths,
        isUncPath,
        parseWindowsSandboxError,
        stripExtendedPathPrefix;
import 'package:test/test.dart';

import '../helpers/captured_warnings.dart';
import '../helpers/platform.dart';

/**
 * Helper to get the real path of a file/dir (resolves symlinks like /var -> /private/var on macOS)
 */
String realPath(String p) {
  try {
    return realpathSync(p);
  } catch (_) {
    return p;
  }
}

// ============================================================================
// Tests for expandGlobPattern()
// ============================================================================

void main() {
  group('expandGlobPattern', () {
    // Use raw path for creation, real path for assertions
    final RAW_BASE_DIR = join(
      tmpdir(),
      'glob-expand-test-${DateTime.now().millisecondsSinceEpoch}',
    );
    final RAW_TEST_DIR = join(RAW_BASE_DIR, 'testdir');
    late String TEST_DIR;

    setUpAll(() {
      // Create test directory structure:
      // testdir/
      //   token.env
      //   secrets.env
      //   readme.txt
      //   config.json
      //   subdir/
      //     nested.env
      //     deep.txt
      //     deeper/
      //       bottom.env
      mkdirSync(join(RAW_TEST_DIR, 'subdir', 'deeper'), {'recursive': true});
      writeFileSync(join(RAW_TEST_DIR, 'token.env'), 'TOKEN=secret');
      writeFileSync(join(RAW_TEST_DIR, 'secrets.env'), 'SECRET=value');
      writeFileSync(join(RAW_TEST_DIR, 'readme.txt'), 'readme content');
      writeFileSync(join(RAW_TEST_DIR, 'config.json'), '{}');
      writeFileSync(
        join(RAW_TEST_DIR, 'subdir', 'nested.env'),
        'NESTED=secret',
      );
      writeFileSync(join(RAW_TEST_DIR, 'subdir', 'deep.txt'), 'deep content');
      writeFileSync(
        join(RAW_TEST_DIR, 'subdir', 'deeper', 'bottom.env'),
        'BOTTOM=secret',
      );

      // Resolve real path after creation (handles /var -> /private/var on macOS)
      TEST_DIR = realPath(RAW_TEST_DIR);
    });

    tearDownAll(() {
      if (existsSync(RAW_BASE_DIR)) {
        rmSync(RAW_BASE_DIR, {'recursive': true, 'force': true});
      }
    });

    test('should expand *.env to match only .env files in the directory', () {
      final pattern = join(RAW_TEST_DIR, '*.env');
      final results = expandGlobPattern(pattern);

      // Should match token.env and secrets.env but NOT nested ones
      expect(results, contains(join(TEST_DIR, 'token.env')));
      expect(results, contains(join(TEST_DIR, 'secrets.env')));
      expect(results, isNot(contains(join(TEST_DIR, 'readme.txt'))));
      expect(results, isNot(contains(join(TEST_DIR, 'config.json'))));
      expect(results, isNot(contains(join(TEST_DIR, 'subdir', 'nested.env'))));
      expect(results.length, 2);
    });

    test('should expand **/*.env to match .env files recursively', () {
      final pattern = join(RAW_TEST_DIR, '**/*.env');
      final results = expandGlobPattern(pattern);

      // Should match all .env files recursively
      expect(results, contains(join(TEST_DIR, 'token.env')));
      expect(results, contains(join(TEST_DIR, 'secrets.env')));
      expect(results, contains(join(TEST_DIR, 'subdir', 'nested.env')));
      expect(
        results,
        contains(join(TEST_DIR, 'subdir', 'deeper', 'bottom.env')),
      );
      expect(results, isNot(contains(join(TEST_DIR, 'readme.txt'))));
      expect(results.length, 4);
    });

    test('should expand ** to match all files recursively', () {
      final pattern = join(RAW_TEST_DIR, '**');
      final results = expandGlobPattern(pattern);

      // Should match all files and directories
      expect(results.length, greaterThan(0));
      expect(results, contains(join(TEST_DIR, 'token.env')));
      expect(results, contains(join(TEST_DIR, 'readme.txt')));
      expect(results, contains(join(TEST_DIR, 'subdir', 'nested.env')));
      expect(
        results,
        contains(join(TEST_DIR, 'subdir', 'deeper', 'bottom.env')),
      );
    });

    test('should return empty array for non-existent base directory', () {
      final pattern = '/nonexistent/path/*.env';
      final results = expandGlobPattern(pattern);
      expect(results, <String>[]);
    });

    test('should return empty array when no files match the pattern', () {
      final pattern = join(RAW_TEST_DIR, '*.xyz');
      final results = expandGlobPattern(pattern);
      expect(results, <String>[]);
    });

    test('should match directories as well as files', () {
      final pattern = join(RAW_TEST_DIR, '*');
      final results = expandGlobPattern(pattern);

      // Should include both files and directories (subdir)
      expect(results, contains(join(TEST_DIR, 'token.env')));
      expect(results, contains(join(TEST_DIR, 'subdir')));
      expect(results, contains(join(TEST_DIR, 'readme.txt')));
    });

    test('should handle ? wildcard', () {
      final pattern = join(RAW_TEST_DIR, '*.tx?');
      final results = expandGlobPattern(pattern);

      expect(results, contains(join(TEST_DIR, 'readme.txt')));
      expect(results, isNot(contains(join(TEST_DIR, 'token.env'))));
    });

    test('should match with partial name glob', () {
      final pattern = join(RAW_TEST_DIR, 'secret*.env');
      final results = expandGlobPattern(pattern);

      expect(results, contains(join(TEST_DIR, 'secrets.env')));
      expect(results, isNot(contains(join(TEST_DIR, 'token.env'))));
    });

    // Regression: `\` is a valid filename byte on POSIX, so the
    // shared helper must NOT rewrite it to `/` outside Windows.
    test('should preserve literal backslash in POSIX path components', () {
      final bsDir = join(RAW_TEST_DIR, 'app\\creds');
      mkdirSync(bsDir, {'recursive': true});
      writeFileSync(join(bsDir, 'key.pem'), 'k');
      final realBsDir = join(TEST_DIR, 'app\\creds');

      final results = expandGlobPattern(join(bsDir, '*.pem'));
      expect(results, contains(join(realBsDir, 'key.pem')));
      // The directory `app\creds` must not be confused with `app/creds`.
      expect(results.any((r) => r.contains('/app/creds/')), false);
    }, skip: !isWindows ? null : 'Windows not supported by this port');
  });

  group('globPatternBaseDir', () {
    // The walk consumes the base a component at a time, so one with a component
    // more or fewer than the pattern spells before its first wildcard matches
    // nothing.
    for (final (pattern, base) in <(String, String)>[
      // A root comes without its separator, whatever the host's dirname does.
      ('C:/Users*/id.pem', 'C:'),
      ('C:/*.pem', 'C:'),
      ('D:/**/*.key', 'D:'),
      ('//server/share/x*/y', '//server/share'),
      ('//server/share/*.pem', '//server/share'),
      ('C:/Users/u/certs*/id.pem', 'C:/Users/u'),
      // A doubled separator is an empty component, of the base as well. A home
      // directory that is a drive root makes one out of `~/*.pem`.
      ('C:/a//*.pem', 'C:/a/'),
      ('C:/a//x*', 'C:/a/'),
      ('C:/a///**/*.pem', 'C:/a//'),
      ('H://*.pem', 'H:/'),
      ('H://x*', 'H:/'),
      ('//server/share//*.key', '//server/share/'),
      ('/a//*.pem', '/a/'),
    ]) {
      test('starts $pattern from $base', () {
        expect(globPatternBaseDir(pattern), base);
        expect(globBaseDirIsRoot(base), false);
      });
    }
  });

  group('a pattern with a doubled separator before its first wildcard', () {
    late String root;

    setUpAll(() {
      root = realPath(mkdtempSync(join(tmpdir(), 'glob-doubled-')));
      mkdirSync(join(root, 'a', 'sub'), {'recursive': true});
      writeFileSync(join(root, 'a', 'x.pem'), '');
      writeFileSync(join(root, 'a', 'sub', 'y.pem'), '');
    });

    tearDownAll(() {
      rmSync(root, {'recursive': true, 'force': true});
    });

    for (final (tail, names) in <(String, List<String>)>[
      ('/a//*.pem', ['x.pem']),
      ('/a//x*', ['x.pem']),
      ('/a///*.pem', ['x.pem']),
      ('/a//**/*.pem', ['x.pem', 'y.pem']),
    ]) {
      test('finds what the tail $tail matches beneath an anchor', () {
        final found = expandGlobPattern(root + tail, anchor: root);
        expect(found.map((p) => basename(p)).toList()..sort(), names);
        for (final p in found) {
          expect(existsSync(p), true);
        }
      });
    }

    // Nothing collapses the separators of a Windows path before the walk.
    for (final (_how, tail) in <(String, String)>[
      ('backslashes', '\\a\\\\*.pem'),
      ('forward slashes', '/a//*.pem'),
      ('one of each', '\\a\\/*.pem'),
      ('a wildcard further into the component', '\\a\\\\x*'),
    ]) {
      test('stamps what it matches, spelled with $_how', () {
        for (final mode in ['deny', 'grant']) {
          expect(
            expandWindowsFsPaths([
              FilesystemPathSpelling(root + tail),
            ], mode: mode).map((p) => basename(p)).toList(),
            ['x.pem'],
          );
        }
      }, skip: isWindows ? null : 'Windows not supported by this port');
    }
  });

  group('a pattern whose only literal directory is a drive root', () {
    // Beneath the working directory, whose spelling holds no short (8.3) name:
    // below the first wildcard a component is matched against a listing.
    late String dir;
    late String drive;
    late List<String> components;

    setUpAll(() {
      dir = mkdtempSync(join(process.cwd(), 'glob-drive-'));
      writeFileSync(join(dir, 'id.pem'), '');
      drive = dir.substring(0, 2);
      components = dir.substring(3).split('\\');
    });

    tearDownAll(() {
      rmSync(dir, {'recursive': true, 'force': true});
    });

    for (final (_what, afterTheRoot, first)
        in <(String, String, String Function(String))>[
          ('a wildcard inside the first component', '\\', (c) => c[0] + '*'),
          ('a wildcard for the first component', '\\', (_) => '*'),
          ('forward slashes', '/', (c) => c[0] + '*'),
          // What `~\x*` comes to when the home directory is a drive root.
          ('a doubled separator after the root', '\\/', (c) => c[0] + '*'),
        ]) {
      test('walks one with $_what', () {
        expect(dir, contains(RegExp(r'^[A-Za-z]:\\[^\\]+\\')));
        final pattern =
            drive +
            afterTheRoot +
            [first(components[0]), ...components.skip(1), '*.pem'].join('\\');
        final found = expandWindowsFsPaths([
          FilesystemPathSpelling(pattern),
        ], mode: 'deny');
        expect(found.map((p) => basename(p)).toList(), ['id.pem']);
        expect(existsSync(found[0]), true);
      });
    }
  }, skip: isWindows ? null : 'Windows not supported by this port');

  group('walkGlobPattern', () {
    final RAW_BASE = join(
      tmpdir(),
      'glob-walk-test-${DateTime.now().millisecondsSinceEpoch}',
    );

    setUpAll(() {
      mkdirSync(join(RAW_BASE, 'a', 'build'), {'recursive': true});
      writeFileSync(join(RAW_BASE, 'a', 'build', '1.out'), '');
      mkdirSync(join(RAW_BASE, 'elsewhere'));
      symlinkSync(
        join(RAW_BASE, 'elsewhere'),
        join(RAW_BASE, 'a', 'build', 'link'),
      );
    });

    tearDownAll(() {
      rmSync(RAW_BASE, {'recursive': true, 'force': true});
    });

    test(
      'evaluates the directory form over the same listing and records symlinks',
      () {
        final BASE = realPath(RAW_BASE);
        final walk = walkGlobPattern(
          join(RAW_BASE, 'a', '**/build/**'),
          withDirectoryForm: true,
          followSymlinkedDirectories: true,
        );

        expect(walk.matches, contains(join(BASE, 'a', 'build', '1.out')));
        expect(walk.directoryMatches, [join(BASE, 'a', 'build')]);
        expect(walk.symlinks.toList(), [join(BASE, 'a', 'build', 'link')]);
        // Only an entry reached through a symlink has a second, real location.
        expect(walk.realOf.entries.map((e) => [e.key, e.value]).toList(), [
          [join(BASE, 'a', 'build', 'link'), join(BASE, 'elsewhere')],
        ]);
      },
    );

    test('lists no directory matches without the directory form', () {
      final walk = walkGlobPattern(join(RAW_BASE, 'a', '**/build/**'));
      expect(walk.directoryMatches, <String>[]);
    });

    test(
      'takes a symlinked directory as the match itself without the link option',
      () {
        // What the allowRead expansion and the Windows ACL stamp see: the link is
        // a match of its own, and nothing under what it points at is listed, so a
        // link planted in the tree cannot widen an allow list to another tree.
        final BASE = realPath(RAW_BASE);
        final link = join(BASE, 'a', 'build', 'link');
        writeFileSync(join(BASE, 'elsewhere', 'outside.out'), '');
        try {
          final plain = walkGlobPattern(join(RAW_BASE, 'a', '**/build/**'));
          expect(plain.matches, contains(link));
          expect(plain.matches, isNot(contains(join(link, 'outside.out'))));
          expect(plain.realOf[link], null);

          final followed = walkGlobPattern(
            join(RAW_BASE, 'a', '**/build/**'),
            followSymlinkedDirectories: true,
          );
          // What is found through the link is reported where it really is.
          expect(
            followed.matches,
            contains(join(BASE, 'elsewhere', 'outside.out')),
          );
          expect(followed.matches, isNot(contains(join(link, 'outside.out'))));
        } finally {
          rmSync(join(BASE, 'elsewhere', 'outside.out'));
        }
      },
    );

    test(
      'records a symlink whose target cannot be looked at, with no real location',
      () {
        // chmod 000 on the directory holding the target, which a sandboxed
        // command with write access there can do and undo: stat and realpath
        // both answer EACCES, which is not "nothing is there".
        final root = realPath(mkdtempSync(join(tmpdir(), 'glob-walk-eacces-')));
        final vault = join(root, 'vault');
        final link = join(root, 'certs', 'k');
        try {
          mkdirSync(join(vault, 'inner'), {'recursive': true});
          writeFileSync(join(vault, 'inner', 'k'), 'SECRET');
          mkdirSync(join(root, 'certs'));
          symlinkSync(join(vault, 'inner', 'k'), link);
          chmodSync(vault, 0x0);

          final walk = walkGlobPattern(
            join(root, 'certs', '*'),
            followSymlinkedDirectories: true,
          );

          expect(walk.matches, [link]);
          expect(walk.symlinks.contains(link), true);
          expect(walk.uninspectableLinks.contains(link), true);
          expect(walk.realOf[link], null);

          // A link that leads nowhere at all stays the other case.
          symlinkSync(join(root, 'gone'), join(root, 'certs', 'dangling'));
          final withDangling = walkGlobPattern(
            join(root, 'certs', '*'),
            followSymlinkedDirectories: true,
          );
          expect(withDangling.uninspectableLinks, {link});
          // Neither link is a directory the walk failed to list.
          expect(withDangling.unlisted, <String>[]);
        } finally {
          chmodSync(vault, 0x1ED);
          rmSync(root, {'recursive': true, 'force': true});
        }
      },
      skip: process.getuid?.call() != 0 ? null : 'running as root',
    );

    test('reports where a match beneath a symlinked base really is', () {
      // alias -> the tree, sideways: normalizePathForSandbox keeps the link
      // spelling for the pattern, so every match is spelled through it and
      // the walk reports where it really is.
      final BASE = realPath(RAW_BASE);
      final alias = path.normalize(
        join(
          RAW_BASE,
          '..',
          'alias-${Random().nextInt(1 << 31).toRadixString(36)}',
        ),
      );
      symlinkSync(BASE, alias);
      try {
        final walk = walkGlobPattern(join(alias, '**/build/**'));
        final match = join(alias, 'a', 'build', '1.out');
        expect(walk.matches, contains(match));
        expect(walk.realOf[match], join(BASE, 'a', 'build', '1.out'));
      } finally {
        rmSync(alias);
      }
    });

    test('terminates on a symlink cycle and still lists the tree', () {
      // build/up -> ..: the link leads back up the tree, and is not listed
      // through.
      final cyc = realPath(mkdtempSync(join(tmpdir(), 'glob-walk-cycle-')));
      try {
        mkdirSync(join(cyc, 'build'));
        writeFileSync(join(cyc, 'build', '1.out'), '');
        symlinkSync('..', join(cyc, 'build', 'up'));

        final walk = walkGlobPattern(
          join(cyc, '**/build/**'),
          withDirectoryForm: true,
        );

        expect(walk.matches, contains(join(cyc, 'build', '1.out')));
        expect(walk.directoryMatches, [join(cyc, 'build')]);
        expect(walk.symlinks.contains(join(cyc, 'build', 'up')), true);
        // The cycle is not re-entered: nothing appears twice.
        expect(walk.matches.toSet().length, walk.matches.length);
      } finally {
        rmSync(cyc, {'recursive': true, 'force': true});
      }
    });

    test('records a directory it cannot list and still lists its siblings', () {
      final root = realPath(mkdtempSync(join(tmpdir(), 'glob-walk-unlisted-')));
      final locked = join(root, 'pkg', 'locked');
      try {
        mkdirSync(join(locked, 'build'), {'recursive': true});
        writeFileSync(join(locked, 'build', 'secret.out'), '');
        mkdirSync(join(root, 'pkg', 'open', 'build'), {'recursive': true});
        writeFileSync(join(root, 'pkg', 'open', 'build', '1.out'), '');
        // Searchable but not listable: what a sandboxed command with write
        // access to the tree can leave behind for the next wrap.
        chmodSync(locked, 0xC9);

        final walk = walkGlobPattern(join(root, '**/build/**'));

        expect(walk.unlisted, [locked]);
        expect(walk.matches, [join(root, 'pkg', 'open', 'build', '1.out')]);
      } finally {
        chmodSync(locked, 0x1ED);
        rmSync(root, {'recursive': true, 'force': true});
      }
    }, skip: process.getuid?.call() != 0 ? null : 'running as root');

    test(
      'finds nothing, and nothing unlisted, under a base that is not there',
      () {
        final walk = walkGlobPattern(join(RAW_BASE, 'nope', '*.env'));
        expect(walk.matches, <String>[]);
        expect(walk.unlisted, <String>[]);
      },
    );

    test(
      'reports a base directory it cannot reach as unlisted, not as absent',
      () {
        // The pattern's base is there; an ancestor of it is not searchable, so
        // nothing under it can be enumerated. Read as absent, the deny would
        // vanish for as long as the mode stays that way — and a sandboxed
        // command can set it and put it back.
        final root = realPath(mkdtempSync(join(tmpdir(), 'glob-walk-base-')));
        final closed = join(root, 'closed');
        final base = join(closed, 'certs');
        try {
          mkdirSync(base, {'recursive': true});
          writeFileSync(join(base, 'id.pem'), 'KEY');
          chmodSync(closed, 0x0);

          final walk = walkGlobPattern(join(base, '*.pem'));

          expect(walk.matches, <String>[]);
          expect(walk.unlisted, [base]);
        } finally {
          chmodSync(closed, 0x1ED);
          rmSync(root, {'recursive': true, 'force': true});
        }
      },
      skip: process.getuid?.call() != 0 ? null : 'running as root',
    );

    test(
      'does not try to list a directory the pattern cannot match beneath',
      () {
        // proj/*.pem matches at one depth only: a directory beneath proj can
        // hold no match, so it is never listed and never reported as
        // unlistable, whatever its mode.
        final root = realPath(mkdtempSync(join(tmpdir(), 'glob-walk-prune-')));
        final proj = join(root, 'proj');
        try {
          mkdirSync(join(proj, 'pgdata'), {'recursive': true});
          mkdirSync(join(proj, 'deep', 'x', 'locked'), {'recursive': true});
          writeFileSync(join(proj, 'top.pem'), '');
          writeFileSync(join(proj, 'deep', 'x', 'nested.pem'), '');
          chmodSync(join(proj, 'pgdata'), 0x0);
          chmodSync(join(proj, 'deep', 'x', 'locked'), 0xC9);

          final walk = walkGlobPattern(join(proj, '*.pem'));
          expect(walk.matches, [join(proj, 'top.pem')]);
          expect(walk.unlisted, <String>[]);

          // A fixed-depth pattern descends only where its segments allow.
          final nested = walkGlobPattern(join(proj, 'de*/x/*.pem'));
          expect(nested.matches, [join(proj, 'deep', 'x', 'nested.pem')]);
          expect(nested.unlisted, <String>[]);

          // From a ** on, every directory can hold a match again.
          final spanning = walkGlobPattern(join(proj, 'deep/**/*.pem'));
          expect(spanning.matches, [join(proj, 'deep', 'x', 'nested.pem')]);
          expect(spanning.unlisted, [join(proj, 'deep', 'x', 'locked')]);
        } finally {
          chmodSync(join(proj, 'pgdata'), 0x1ED);
          chmodSync(join(proj, 'deep', 'x', 'locked'), 0x1ED);
          rmSync(root, {'recursive': true, 'force': true});
        }
      },
      skip: process.getuid?.call() != 0 ? null : 'running as root',
    );

    test('skips a pattern whose only literal directory is the root', () {
      // A wildcard in the first path component leaves '/' to start from. The
      // fixture is real and the pattern matches it, so a walk that started at
      // the root would find it: what this pins is the skip, not an empty tree.
      final root = realPath(mkdtempSync(join(tmpdir(), 'glob-walk-root-')));
      try {
        mkdirSync(join(root, 'keys'));
        writeFileSync(join(root, 'keys', 'id.pem'), 'KEY');
        final under = join(root, 'keys', '*.pem');
        expect(expandGlobPattern(under), [join(root, 'keys', 'id.pem')]);

        // Same file, named from a first-component wildcard: '/t*/…' on a Linux
        // runner, and whatever the first component of the temporary directory
        // is elsewhere.
        final [_, first, ...rest] = under.split('/');
        final fromRoot = ['', first.substring(0, 1) + '*', ...rest].join('/');
        expect(globPatternBaseDir(normalizePathForSandbox(fromRoot)), '/');
        expect(globBaseDirIsRoot('/'), true);

        final walk = walkGlobPattern(fromRoot);
        expect(walk.matches, <String>[]);
        expect(walk.unlisted, <String>[]);

        // A pattern with no literal component at all is the other half of the
        // rule: no directory to start from, not even the root. (The walk
        // resolves a relative pattern against the working directory first, so
        // this shape reaches it only from a caller that does not.)
        expect(globPatternBaseDir('*.pem'), '');
      } finally {
        rmSync(root, {'recursive': true, 'force': true});
      }
    });

    test(
      'starts no walk from the root, and starts one from a drive or a share',
      () {
        // '/' holds every filesystem the machine has mounted. A drive root and
        // the root of a UNC share are one volume each, which the entry names.
        for (final none in ['', '/']) {
          expect(globBaseDirIsRoot(none), true);
        }
        for (final dir in [
          'C:',
          'c:',
          'D:',
          '//server/share',
          '/home/u',
          'C:/Users',
          'C:/Users/u',
          '//server/share/keys',
          '/s',
        ]) {
          expect(globBaseDirIsRoot(dir), false);
        }
      },
    );

    test(
      'walks a pattern whose only literal directory is a drive root',
      () {
        // A drive stood up on this runner: a directory named `C:` in the
        // working directory, with path.dirname and path.isAbsolute answering as
        // on Windows and 'C:/' resolving to itself. The listing is the walk's.
        final root = realPath(mkdtempSync(join(tmpdir(), 'glob-walk-drive-')));
        final cwd = process.cwd();
        final realpathSync = fs.realpathSync;
        final spies = <void Function()>[
          // spyOn(path, 'dirname').mockImplementation(win32.dirname)
          // spyOn(path, 'isAbsolute').mockImplementation(win32.isAbsolute)
          () {
            fs.realpathSync = (String p) =>
                p == 'C:/' ? 'C:/' : realpathSync(p);
            return () => fs.realpathSync = realpathSync;
          }(),
        ];
        try {
          mkdirSync(join(root, 'C:', 'Users1', 'deep'), {'recursive': true});
          mkdirSync(join(root, 'C:', 'Other'));
          writeFileSync(join(root, 'C:', 'top.pem'), 'KEY');
          writeFileSync(join(root, 'C:', 'Users1', 'id.pem'), 'KEY');
          writeFileSync(join(root, 'C:', 'Users1', 'deep', 'id.pem'), 'KEY');
          writeFileSync(join(root, 'C:', 'Other', 'id.pem'), 'KEY');
          Directory.current = root;

          // A wildcard inside the first component, at its start, and a `**`.
          final middle = walkGlobPattern('C:/Users*/id.pem');
          expect(middle.matches, ['C:/Users1/id.pem']);
          expect(walkGlobPattern('C:/*.pem').matches, ['C:/top.pem']);
          expect(walkGlobPattern('C:/**/deep/*.pem').matches, [
            'C:/Users1/deep/id.pem',
          ]);
          // 'C:' on its own is the drive's current directory, not its root:
          // what the filesystem is asked about is 'C:/'. Asked about 'C:', the
          // stand-in answers with its real path instead.
          expect(middle.baseLocation, 'C:/');
          // What the ACL stamp is handed, which is nothing when the walk is.
          expect(
            expandWindowsFsPaths([
              const FilesystemPathSpelling('C:/Users*/id.pem'),
            ]),
            ['C:/Users1/id.pem'],
          );
        } finally {
          Directory.current = cwd;
          for (final spy in spies) {
            spy();
          }
          rmSync(root, {'recursive': true, 'force': true});
        }
      },
      skip: isLinux
          ? 'package:path has no spy point for dirname/isAbsolute'
          : 'requires Linux',
    );

    test('matches a name that holds a line terminator', () {
      final root = realPath(mkdtempSync(join(tmpdir(), 'glob-walk-newline-')));
      try {
        mkdirSync(join(root, 'build'));
        writeFileSync(join(root, 'build', 'a\nb.out'), '');
        expect(expandGlobPattern(join(root, '**/build/**')), [
          join(root, 'build', 'a\nb.out'),
        ]);
      } finally {
        rmSync(root, {'recursive': true, 'force': true});
      }
    });

    test(
      'follows a chain of links to its end, under names no longer than real ones',
      () {
        // d0/next -> d1, d1/next -> d2, …: the spelling of the last directory
        // crosses every link before it. A walk that carried that spelling would
        // match each entry against a longer and longer path; what is found
        // through a link is carried and reported by its real path instead.
        final root = realPath(mkdtempSync(join(tmpdir(), 'glob-walk-chain-')));
        final links = 300;
        try {
          for (var i = 0; i <= links; i++) {
            mkdirSync(join(root, 'd$i'));
            writeFileSync(join(root, 'd$i', 'id.pem'), 'KEY');
          }
          for (var i = 0; i < links; i++) {
            symlinkSync(join('..', 'd${i + 1}'), join(root, 'd$i', 'next'));
          }

          final walk = walkGlobPattern(
            join(root, 'd0', '**/*.pem'),
            followSymlinkedDirectories: true,
          );

          expect(walk.unlisted, <String>[]);
          expect(
            walk.matches..sort(),
            List.generate(links + 1, (i) => join(root, 'd$i', 'id.pem'))
              ..sort(),
          );
          final longest = join(root, 'd$links', 'next').length;
          for (final seen in walk.symlinks) {
            expect(seen.length, lessThanOrEqualTo(longest));
          }
        } finally {
          rmSync(root, {'recursive': true, 'force': true});
        }
      },
    );

    test(
      'looks at a link by a shorter name when its real path is too long to name',
      () {
        // deep is a real directory whose path is a few bytes short of PATH_MAX,
        // so deep/key.pem cannot be named by its real path at all, only through
        // base/s. The link is a match, and what it leads to has to be found.
        final root = realPath(mkdtempSync(join(tmpdir(), 'glob-walk-long-')));
        var deep = join(root, 'deep');
        while (deep.length < 4090) {
          // At least one character: a zero-length name would join to the same
          // path and the loop would never end.
          final room = 4090 - deep.length - 1;
          deep = join(deep, 'd' * max(1, min(200, room)));
        }
        final viaLink = join(root, 'base', 's', 'key.pem');
        try {
          mkdirSync(deep, {'recursive': true});
          mkdirSync(join(root, 'base'));
          writeFileSync(join(root, 'secret.txt'), 'KEY');
          symlinkSync(deep, join(root, 'base', 's'));
          symlinkSync(join(root, 'secret.txt'), viaLink);
          expect(join(deep, 'key.pem').length, greaterThan(4095));

          final walk = walkGlobPattern(
            join(root, 'base', '*/*.pem'),
            followSymlinkedDirectories: true,
          );

          expect(walk.unlisted, <String>[]);
          expect(walk.matches.map((m) => walk.realOf[m]).toList(), [
            join(root, 'secret.txt'),
          ]);
        } finally {
          rmSync(viaLink, {'force': true});
          rmSync(root, {'recursive': true, 'force': true});
        }
      },
      skip: isLinux ? null : 'requires Linux',
    );

    test(
      'lists a directory once, whatever the number of names that lead to it',
      () {
        // N packages that each link to every other. Every chain of distinct
        // packages spells the same N files differently, which is about e*N! of
        // them (N=12: 1.3 billion) for a tree a sandboxed command can plant. The
        // pattern cannot tell one of those names from another, so each directory
        // is read once and none is given up on.
        final root = realPath(mkdtempSync(join(tmpdir(), 'glob-walk-names-')));
        final names = List.generate(12, (i) => 'p$i');
        try {
          for (final name in names) {
            mkdirSync(join(root, name, 'node_modules'), {'recursive': true});
            writeFileSync(join(root, name, 'index.js'), '');
          }
          for (final from in names) {
            for (final to in names) {
              if (from != to) {
                symlinkSync(
                  join(root, to),
                  join(root, from, 'node_modules', to),
                );
              }
            }
          }
          final listed = <String>[];
          final readdirSync = fs.readdirSync;
          fs.readdirSync = (String p, {bool withFileTypes = true}) {
            listed.add(p);
            return readdirSync(p, withFileTypes: withFileTypes);
          };
          late GlobWalk walk;
          try {
            walk = walkGlobPattern(
              join(root, '**/index.js'),
              followSymlinkedDirectories: true,
            );
          } finally {
            fs.readdirSync = readdirSync;
          }

          // The root, and each package and its node_modules: once each.
          expect(
            listed..sort(),
            [
              root,
              ...names.map((name) => join(root, name)),
              ...names.map((name) => join(root, name, 'node_modules')),
            ]..sort(),
          );
          // Each file is found once, under whichever name reached it first.
          expect(
            walk.matches.map((m) => walk.realOf[m] ?? m).toList()..sort(),
            names.map((name) => join(root, name, 'index.js')).toList()..sort(),
          );
          expect(walk.unlisted, <String>[]);
        } finally {
          rmSync(root, {'recursive': true, 'force': true});
        }
      },
    );

    test(
      'lists a directory once for all the patterns handed the same listings',
      () {
        final root = realPath(mkdtempSync(join(tmpdir(), 'glob-walk-shared-')));
        try {
          mkdirSync(join(root, 'a', 'b'), {'recursive': true});
          writeFileSync(join(root, 'a', '.env'), '');
          writeFileSync(join(root, 'a', 'b', 'id.pem'), '');
          writeFileSync(join(root, 'a', 'b', 'notes.txt'), '');
          final patterns = [
            '**/.env',
            '**/*.pem',
            '**/*.key',
          ].map((p) => join(root, p)).toList();
          final alone = patterns
              .map((p) => walkGlobPattern(p).matches)
              .toList();

          final listed = <String>[];
          final readdirSync = fs.readdirSync;
          fs.readdirSync = (String p, {bool withFileTypes = true}) {
            listed.add(p);
            return readdirSync(p, withFileTypes: withFileTypes);
          };
          late List<List<String>> together;
          try {
            final GlobWalkListings listings = {};
            together = patterns
                .map((p) => walkGlobPattern(p, listings: listings).matches)
                .toList();
          } finally {
            fs.readdirSync = readdirSync;
          }

          expect(
            listed..sort(),
            [root, join(root, 'a'), join(root, 'a', 'b')]..sort(),
          );
          expect(together, alone);
          expect(
            together.expand((x) => x).toList()..sort(),
            [join(root, 'a', '.env'), join(root, 'a', 'b', 'id.pem')]..sort(),
          );
        } finally {
          rmSync(root, {'recursive': true, 'force': true});
        }
      },
    );

    test(
      'tries a directory it cannot list once for all the patterns handed the same listings',
      () {
        final root = realPath(mkdtempSync(join(tmpdir(), 'glob-walk-failed-')));
        final locked = join(root, 'locked');
        final open = join(root, 'open');
        try {
          mkdirSync(open);
          writeFileSync(join(open, 'id.pem'), '');
          mkdirSync(locked);
          chmodSync(locked, 0x0);
          final patterns = [
            '**/.env',
            '**/*.pem',
            '**/*.key',
          ].map((p) => join(root, p)).toList();
          final alone = patterns
              .map((p) => walkGlobPattern(p).unlisted)
              .toList();

          final tried = <String>[];
          final readdirSync = fs.readdirSync;
          fs.readdirSync = (String p, {bool withFileTypes = true}) {
            final dir = p;
            final askedBefore = tried.contains(dir);
            tried.add(dir);
            // Absent when the first pattern asks, and there for the others.
            if (dir == open && !askedBefore) {
              throw NodeError('gone', code: 'ENOENT');
            }
            return readdirSync(p, withFileTypes: withFileTypes);
          };
          late List<GlobWalk> together;
          try {
            final GlobWalkListings listings = {};
            together = patterns
                .map((p) => walkGlobPattern(p, listings: listings))
                .toList();
          } finally {
            fs.readdirSync = readdirSync;
          }

          expect(tried.where((dir) => dir == locked).toList(), [locked]);
          // Every pattern still has it to deny whole.
          expect(together.map((walk) => walk.unlisted).toList(), alone);
          expect(alone, patterns.map((_) => [locked]).toList());
          // An absence denies nothing, so it is nobody's answer but the asker's.
          expect(tried.where((dir) => dir == open).toList(), [open, open]);
          expect(together.map((walk) => walk.matches).toList(), [
            <String>[],
            [join(open, 'id.pem')],
            <String>[],
          ]);
        } finally {
          chmodSync(locked, 0x1ED);
          rmSync(root, {'recursive': true, 'force': true});
        }
      },
      skip: process.getuid?.call() != 0 ? null : 'running as root',
    );

    test('lists a directory again under a name the pattern tells apart', () {
      // vault is reached by its own name, which matches nothing, and through
      // config/secrets, the only spelling `**/secrets/*.pem` matches. However
      // many links lead to it, those are the two ways the pattern can carry
      // on beneath it, and both are listed.
      final root = realPath(mkdtempSync(join(tmpdir(), 'glob-walk-apart-')));
      try {
        mkdirSync(join(root, 'vault'));
        writeFileSync(join(root, 'vault', 'id.pem'), 'KEY');
        for (var i = 0; i < 20; i++) {
          mkdirSync(join(root, 'config$i'));
          symlinkSync(join('..', 'vault'), join(root, 'config$i', 'secrets'));
          symlinkSync(join('..', 'vault'), join(root, 'config$i', 'other'));
        }

        final walk = walkGlobPattern(
          join(root, '**/secrets/*.pem'),
          followSymlinkedDirectories: true,
        );

        expect(walk.unlisted, <String>[]);
        expect(walk.matches, [join(root, 'vault', 'id.pem')]);
      } finally {
        rmSync(root, {'recursive': true, 'force': true});
      }
    });

    test(
      'follows a `**` written against text through a symlinked directory',
      () {
        // globToRegex lets `**.pem` and `ce**/x.pem` span directories. Each is
        // two patterns the walk can follow a name at a time (`*.pem` or
        // `*` / `**` / `*.pem`), so what they reach through a link is found like
        // any other match: here certs leads out of the pattern's base.
        final root = realPath(mkdtempSync(join(tmpdir(), 'glob-walk-glued-')));
        try {
          mkdirSync(join(root, 'proj'));
          mkdirSync(join(root, 'outside', 'deep'), {'recursive': true});
          writeFileSync(join(root, 'outside', 'x.pem'), 'KEY');
          writeFileSync(join(root, 'outside', 'deep', 'y.pem'), 'KEY');
          writeFileSync(join(root, 'proj', 'z.pem'), 'KEY');
          symlinkSync(join('..', 'outside'), join(root, 'proj', 'certs'));

          List<String> found(String pattern) {
            final walk = walkGlobPattern(
              join(root, 'proj', pattern),
              followSymlinkedDirectories: true,
            );
            expect(walk.unlisted, <String>[]);
            return walk.matches.map((m) => walk.realOf[m] ?? m).toList()
              ..sort();
          }

          expect(found('**.pem'), [
            join(root, 'outside', 'deep', 'y.pem'),
            join(root, 'outside', 'x.pem'),
            join(root, 'proj', 'z.pem'),
          ]);
          expect(found('ce**/x.pem'), [join(root, 'outside', 'x.pem')]);
          expect(found('ce**y.pem'), [join(root, 'outside', 'deep', 'y.pem')]);
          // A run of three before a separator is a `*` and then a `**/`.
          expect(found('***/y.pem'), [join(root, 'outside', 'deep', 'y.pem')]);
          expect(found('***/x.pem'), [join(root, 'outside', 'x.pem')]);
        } finally {
          rmSync(root, {'recursive': true, 'force': true});
        }
      },
    );

    test('follows a bracket expression that can match a separator', () {
      // `[s/]` is an `s` within a name or a separator between two, and both
      // readings are followed, through a link as well.
      final root = realPath(mkdtempSync(join(tmpdir(), 'glob-walk-bracket-')));
      try {
        mkdirSync(join(root, 'proj'));
        mkdirSync(join(root, 'outside', 'cert'), {'recursive': true});
        writeFileSync(join(root, 'outside', 'cert', 'x.pem'), 'KEY');
        writeFileSync(join(root, 'outside', 'certsx.pem'), 'KEY');
        symlinkSync(join('..', 'outside'), join(root, 'proj', 'lnk'));

        List<String> found(String pattern) {
          final walk = walkGlobPattern(
            join(root, 'proj', pattern),
            followSymlinkedDirectories: true,
          );
          return walk.matches.map((m) => walk.realOf[m] ?? m).toList()..sort();
        }

        expect(found('*/cert[s/]x.pem'), [
          join(root, 'outside', 'cert', 'x.pem'),
          join(root, 'outside', 'certsx.pem'),
        ]);
        // A range holds the separator as a set does: `[+-9]` spans `/`.
        expect(found('*/cert[+-9]x.pem'), [
          join(root, 'outside', 'cert', 'x.pem'),
        ]);
        writeFileSync(join(root, 'outside', 'cert9x.pem'), 'KEY');
        expect(found('*/cert[+-9]x.pem'), [
          join(root, 'outside', 'cert', 'x.pem'),
          join(root, 'outside', 'cert9x.pem'),
        ]);
      } finally {
        rmSync(root, {'recursive': true, 'force': true});
      }
    });

    test('matches a pattern it cannot split against real paths only', () {
      // A wildcard inside a bracket expression is rewritten like any other, so
      // `?[*].pem` reads as one character, any run of `[`, `^` or `/`, then
      // `].pem`. Nothing can follow that a name at a time, and no two names
      // for a directory can be told apart, so each is listed under its own
      // name alone.
      final root = realPath(mkdtempSync(join(tmpdir(), 'glob-walk-split-')));
      try {
        mkdirSync(join(root, 'cfg'));
        writeFileSync(join(root, 'cfg', 'a].pem'), 'KEY');
        symlinkSync('cfg', join(root, 'lnk'));
        symlinkSync(join('cfg', 'a].pem'), join(root, 'b].pem'));

        final walk = walkGlobPattern(
          join(root, '**/?[*].pem'),
          followSymlinkedDirectories: true,
        );

        expect(walk.matches..sort(), [
          join(root, 'b].pem'),
          join(root, 'cfg', 'a].pem'),
        ]);
        // A link that is itself a match is still resolved, so that a deny
        // lands on what it leads to.
        expect(walk.realOf[join(root, 'b].pem')], join(root, 'cfg', 'a].pem'));
      } finally {
        rmSync(root, {'recursive': true, 'force': true});
      }
    });

    test('does not let one name that fails to list answer for the others', () {
      // A listing can fail for a reason that has nothing to do with the
      // directory (too many open files at that moment). Letting that failure
      // answer for every later name drops every match beneath the directory.
      final root = realPath(mkdtempSync(join(tmpdir(), 'glob-walk-route-')));
      try {
        mkdirSync(join(root, 'pkg', 'certs'), {'recursive': true});
        writeFileSync(join(root, 'pkg', 'certs', 'id.pem'), 'KEY');
        // No shorter than the real path, which is then all that is ever asked.
        symlinkSync(join('pkg', 'certs'), join(root, 'link-to-certs'));

        final certs = join(root, 'pkg', 'certs');
        final readdirSync = fs.readdirSync;
        final attempts = <String>[];
        num failuresLeft = 1;
        var spyCalled = false;
        fs.readdirSync = (String p, {bool withFileTypes = true}) {
          spyCalled = true;
          final at = p;
          if (at == certs) {
            attempts.add(at);
            if (failuresLeft > 0) {
              failuresLeft--;
              throw NodeError('EMFILE: too many open files', code: 'EMFILE');
            }
          }
          return readdirSync(p, withFileTypes: withFileTypes);
        };
        try {
          final retried = walkGlobPattern(
            join(root, '**/*.pem'),
            followSymlinkedDirectories: true,
          );
          // Two names lead to the directory; the second one lists it.
          expect(spyCalled, true);
          expect(attempts, hasLength(2));
          expect(retried.matches.map((m) => retried.realOf[m] ?? m).toList(), [
            join(root, 'pkg', 'certs', 'id.pem'),
          ]);
          expect(retried.unlisted, hasLength(1));

          // Failing under every name, it is tried under each and named once.
          attempts.length = 0;
          failuresLeft = double.infinity;
          final gone = walkGlobPattern(
            join(root, '**/*.pem'),
            followSymlinkedDirectories: true,
          );
          expect(attempts, hasLength(2));
          expect(gone.matches, <String>[]);
          expect(gone.unlisted, hasLength(1));
        } finally {
          fs.readdirSync = readdirSync;
        }
      } finally {
        rmSync(root, {'recursive': true, 'force': true});
      }
    });

    group('what has a name shorter than its real path', () {
      // h -> a/long/way/home is the base of the pattern, so every directory and
      // link beneath it has a short name, through h, beside its real path. The
      // real path is asked first. The short name crosses a link that a sandboxed
      // command can repoint, so what it says is added and takes nothing back.
      late String root;
      /** `~` is the real home; everything else is spelled from the root. */
      String at(String p) =>
          join(root, p.replaceFirst(RegExp(r'^~'), 'a/long/way/home'));

      setUpAll(() {
        root = realPath(mkdtempSync(join(tmpdir(), 'glob-walk-short-')));
        for (final dir in [
          '~/proj',
          '~/cfg',
          'store/in',
          'store/vendor',
          'empty',
        ]) {
          mkdirSync(at(dir), {'recursive': true});
        }
        for (final file in [
          '~/proj/.env',
          'store/in/.env',
          'store/vendor/.env',
          'store/key',
          'store/decoy',
        ]) {
          writeFileSync(at(file), '');
        }
        symlinkSync(at('~'), at('h'));
        // Leads out from beneath proj; is passed through; is itself a match.
        symlinkSync(at('store/in'), at('~/proj/out'));
        symlinkSync(at('store/vendor'), at('~/vendor'));
        symlinkSync(at('store/key'), at('~/cfg/.env'));
      });

      tearDownAll(() {
        rmSync(root, {'recursive': true, 'force': true});
      });

      /// The walk of `h/**/.env` while `answers` holds. A key is a call and the
      /// name it is made on; the value is the errno it fails with or, after `=`,
      /// the path it is answered from, the link above having been repointed.
      Map<String, List<String>> walkWhile(
        Map<String, String> answers, [
        GlobWalkListings? listings,
      ]) {
        String? answerFor(String fn, String p) {
          for (final MapEntry(key: on, value: answer) in answers.entries) {
            final [onFn, onPath] = on.split(' ');
            if (onFn == fn && at(onPath) == p) return answer;
          }
          return null;
        }

        final readdirCall = fs.readdirSync;
        final statCall = fs.statSync;
        final realpathCall = fs.realpathSync;
        final spies = <void Function()>[
          () {
            fs.readdirSync = (String p, {bool withFileTypes = true}) {
              final answer = answerFor('readdirSync', p);
              if (answer == null) {
                return readdirCall(p, withFileTypes: withFileTypes);
              }
              if (answer.startsWith('=')) {
                return readdirCall(
                  at(answer.substring(1)),
                  withFileTypes: withFileTypes,
                );
              }
              throw NodeError(answer, code: answer);
            };
            return () => fs.readdirSync = readdirCall;
          }(),
          () {
            fs.statSync = (String p) {
              final answer = answerFor('statSync', p);
              if (answer == null) return statCall(p);
              if (answer.startsWith('='))
                return statCall(at(answer.substring(1)));
              throw NodeError(answer, code: answer);
            };
            return () => fs.statSync = statCall;
          }(),
          () {
            fs.realpathSync = (String p) {
              final answer = answerFor('realpathSync', p);
              if (answer == null) return realpathCall(p);
              if (answer.startsWith('=')) {
                return realpathCall(at(answer.substring(1)));
              }
              throw NodeError(answer, code: answer);
            };
            return () => fs.realpathSync = realpathCall;
          }(),
        ];
        try {
          final walk = walkGlobPattern(
            join(at('h'), '**/.env'),
            followSymlinkedDirectories: true,
            listings: listings,
          );
          List<String> located(Iterable<String> paths) =>
              (paths.map((p) => walk.realOf[p] ?? p).toList()..sort());
          return {
            'found': located(walk.matches),
            'whole': located(walk.unlisted),
            'ownSpelling': [...walk.uninspectableLinks],
          };
        } finally {
          for (final spy in spies) {
            spy();
          }
        }
      }

      final ALL = [
        '~/proj/.env',
        'store/in/.env',
        'store/key',
        'store/vendor/.env',
      ];
      final BUT_PROJ = ['store/key', 'store/vendor/.env'];
      final LINK_AS_SPELLED = [
        ...ALL.where((p) => p != 'store/key'),
        'h/cfg/.env',
      ];

      for (final c in <Map<String, Object>>[
        {
          'when': 'everything answers',
          'answers': <String, String>{},
          'found': ALL,
        },
        {
          'when':
              'a directory is not there by its real path: the short name is asked',
          'answers': {'readdirSync ~/proj': 'ENOENT'},
          'found': ALL,
        },
        {
          'when': 'a directory is too long to name by its real path: likewise',
          'answers': {'readdirSync ~/proj': 'ENAMETOOLONG'},
          'found': ALL,
        },
        ...['EMFILE', 'ENOTDIR'].map(
          (code) => <String, Object>{
            'when':
                'a listing answers $code by the real path: denied whole, and what the short name lists is added',
            'answers': {'readdirSync ~/proj': code},
            'found': ALL,
            'whole': ['~/proj'],
          },
        ),
        {
          'when':
              'it fails and the short name leads to an empty directory by now: denied whole',
          'answers': {
            'readdirSync ~/proj': 'EACCES',
            'readdirSync h/proj': '=empty',
          },
          'found': BUT_PROJ,
          'whole': ['~/proj'],
        },
        ...[
          ['EACCES', 'ENOENT'],
          ['ENOENT', 'EACCES'],
          ['ENAMETOOLONG', 'ENOENT'],
        ].map((pair) {
          final [real, short] = pair;
          return <String, Object>{
            'when':
                'a listing answers $real by the real path and $short by the short name: denied whole',
            'answers': {
              'readdirSync ~/proj': real,
              'readdirSync h/proj': short,
            },
            'found': BUT_PROJ,
            'whole': ['~/proj'],
          };
        }),
        {
          'when':
              'a directory is not there under either name: nothing is denied',
          'answers': {
            'readdirSync ~/proj': 'ENOENT',
            'readdirSync h/proj': 'ENOENT',
          },
          'found': BUT_PROJ,
        },
        ...['statSync', 'realpathSync'].expand(
          (call) => <Map<String, Object>>[
            {
              'when':
                  '$call of a link passed through says ENOENT by the real path: followed by the short name',
              'answers': {'$call ~/vendor': 'ENOENT'},
              'found': ALL,
            },
            {
              'when':
                  '$call of a link passed through fails by the real path: followed by the short name',
              'answers': {'$call ~/vendor': 'EIO'},
              'found': ALL,
              'ownSpelling': ['h/vendor'],
            },
          ],
        ),
        ...['ENOENT', 'ENOTDIR'].map(
          (code) => <String, Object>{
            'when':
                'a link that matches answers $code, an absence, by its real path: the short name is asked',
            'answers': {'statSync ~/cfg/.env': code},
            'found': ALL,
          },
        ),
        ...[
          ['EACCES', 'ENOENT'],
          ['ENOENT', 'EACCES'],
        ].map((pair) {
          final [real, short] = pair;
          return <String, Object>{
            'when':
                'a link that matches answers $real by the real path and $short by the short name: covered as spelled',
            'answers': {
              'statSync ~/cfg/.env': real,
              'statSync h/cfg/.env': short,
            },
            'found': LINK_AS_SPELLED,
            'ownSpelling': ['h/cfg/.env'],
          };
        }),
        {
          'when':
              'a link that matches fails by the real path and leads elsewhere by the short name: covered as spelled, that place besides',
          'answers': {
            'statSync ~/cfg/.env': 'EACCES',
            'statSync h/cfg/.env': '=store/decoy',
            'realpathSync h/cfg/.env': '=store/decoy',
          },
          'found': [...LINK_AS_SPELLED, 'store/decoy'],
          'ownSpelling': ['h/cfg/.env'],
        },
        {
          'when':
              'a link that matches leads nowhere under either name: it has no location',
          'answers': {
            'statSync ~/cfg/.env': 'ENOENT',
            'statSync h/cfg/.env': 'ENOENT',
          },
          'found': LINK_AS_SPELLED,
        },
      ]) {
        final when = c['when'] as String;
        final answers = c['answers'] as Map<String, String>;
        final found = c['found'] as List<String>;
        final whole = (c['whole'] as List<String>?) ?? <String>[];
        final ownSpelling = (c['ownSpelling'] as List<String>?) ?? <String>[];
        test(when, () {
          expect(walkWhile(answers), {
            'found': found.map(at).toList()..sort(),
            'whole': whole.map(at).toList(),
            'ownSpelling': ownSpelling.map(at).toList(),
          });
        });
      }

      test(
        'hands the next pattern what the short name listed, the directory being denied whole already',
        () {
          final GlobWalkListings listings = {};
          final answers = {'readdirSync ~/proj': 'EMFILE'};
          expect(walkWhile(answers, listings)['whole'], [at('~/proj')]);
          // Handed the failure, it would not find what proj links out to.
          expect(walkWhile(answers, listings), {
            'found': ALL.map(at).toList()..sort(),
            'whole': <String>[],
            'ownSpelling': <String>[],
          });
        },
      );

      test('follows a link whose real path the runtime does not resolve', () {
        // Nothing is made to fail here: Bun's realpathSync answers ENOENT for a
        // path with a backslash in it, and takes the same link by another name.
        mkdirSync(at('proj/back\\slash'), {'recursive': true});
        symlinkSync(at('store/vendor'), at('proj/back\\slash/certs'));
        symlinkSync(at('proj/back\\slash'), at('zz'));

        final walk = walkGlobPattern(
          join(at('zz'), '**/.env'),
          followSymlinkedDirectories: true,
        );

        expect(walk.matches, [at('store/vendor/.env')]);
      });
    });

    test(
      'follows brackets that spell no set of characters a name at a time',
      () {
        // Through a link, which only a pattern that splits into names is listed
        // through; the second pair of brackets holds a separator.
        final root = realPath(mkdtempSync(join(tmpdir(), 'glob-walk-no-set-')));
        try {
          mkdirSync(join(root, 'store', '[z-a]', 'x[b-a'), {'recursive': true});
          mkdirSync(join(root, 'store', 'z'));
          mkdirSync(join(root, 'proj'));
          writeFileSync(join(root, 'store', '[z-a]', 'x[b-a', 'c]y.pem'), '');
          writeFileSync(join(root, 'store', '[z-a]', 'x[b-ac]y.pem'), '');
          writeFileSync(join(root, 'store', 'z', 'id.pem'), '');
          writeFileSync(join(root, 'store', '[z-a]', 'id.pem'), '');
          symlinkSync(join(root, 'store'), join(root, 'proj', 'link'));
          List<String> found(String tail) => walkGlobPattern(
            join(root, 'proj', tail),
            followSymlinkedDirectories: true,
          ).matches;

          expect(found('**/[z-a]/*.pem')..sort(), [
            join(root, 'store', '[z-a]', 'id.pem'),
            join(root, 'store', '[z-a]', 'x[b-ac]y.pem'),
          ]);
          expect(found('**/x[b-a/c]y.pem'), [
            join(root, 'store', '[z-a]', 'x[b-a', 'c]y.pem'),
          ]);
        } finally {
          rmSync(root, {'recursive': true, 'force': true});
        }
      },
    );
  }, skip: isWindows ? 'Windows not supported by this port' : null);

  // ============================================================================
  // Listings that give no types
  // ============================================================================

  group('a walk over listings that give no types', () {
    late String root;
    late String data;
    const QUESTIONS = ['lstatSync', 'statSync', 'realpathSync'];
    // type Failing = Partial<Record<(typeof QUESTIONS)[number], string>>

    setUpAll(() {
      root = realPath(mkdtempSync(join(tmpdir(), 'glob-walk-untyped-')));
      data = join(root, 'data');
      mkdirSync(join(data, 'x', 'deep'), {'recursive': true});
      mkdirSync(join(root, 'outside'));
      for (final dir in [data, join(data, 'x'), join(data, 'x', 'deep')]) {
        writeFileSync(join(dir, '.env'), '');
      }
      writeFileSync(join(root, 'outside', '.env'), '');
      writeFileSync(join(data, 'note.txt'), '');
      symlinkSync(join(root, 'outside'), join(data, 'x', 'link'));
      symlinkSync('round', join(data, 'x', 'round'));
    });

    tearDownAll(() {
      rmSync(root, {'recursive': true, 'force': true});
    });

    /**
     * Has `root` listed the way some file systems list: names, and no types
     * (unless `typed`). The calls in `failing` fail beneath it, with that code.
     * `asked` is every call made beneath it, as `<call> <path from root>`, but
     * for those about a pattern's own spelling.
     */
    ({List<String> asked, void Function() restore}) mounted([
      Map<String, String> failing = const {},
      bool typed = false,
    ]) {
      final asked = <String>[];
      bool beneathRoot(String call, Object? p) {
        if (!p.toString().startsWith(root + '/') ||
            p.toString().contains('*')) {
          return false;
        }
        asked.add('$call ${p.toString().substring(root.length + 1)}');
        return true;
      }

      final readdirSync = fs.readdirSync;
      final realCalls = <String, Object>{
        'lstatSync': fs.lstatSync,
        'statSync': fs.statSync,
        'realpathSync': fs.realpathSync,
      };
      final spies = <void Function()>[
        () {
          fs.readdirSync = (String p, {bool withFileTypes = true}) {
            final entries = readdirSync(p, withFileTypes: withFileTypes);
            if (!beneathRoot('readdirSync', p) || typed) return entries;
            return entries
                .map((e) => fs.Dirent(e.name, FileSystemEntityType.notFound))
                .toList();
          };
          return () => fs.readdirSync = readdirSync;
        }(),
        ...QUESTIONS.map((question) {
          final real = realCalls[question] as dynamic;
          final code = failing[question];
          dynamic spy(String p) {
            if (beneathRoot(question, p) && code != null) {
              throw NodeError(code, code: code);
            }
            return real(p);
          }

          switch (question) {
            case 'lstatSync':
              fs.lstatSync = (String p) => spy(p) as fs.Stats;
              return () => fs.lstatSync = real as fs.Stats Function(String);
            case 'statSync':
              fs.statSync = (String p) => spy(p) as fs.Stats;
              return () => fs.statSync = real as fs.Stats Function(String);
            default:
              fs.realpathSync = (String p) => spy(p) as String;
              return () => fs.realpathSync = real as String Function(String);
          }
        }),
      ];
      return (asked: asked, restore: () => spies.forEach((spy) => spy()));
    }

    /** The read-deny walk of each pattern beneath `data`, on such a mount. */
    ({List<GlobWalk> walks, List<String> asked}) walked(
      List<String> patterns, [
      Map<String, String>? failing,
      GlobWalkListings? listings,
    ]) {
      final mount = mounted(failing ?? const {});
      try {
        final walks = patterns
            .map(
              (pattern) => walkGlobPattern(
                join(data, pattern),
                withDirectoryForm: true,
                followSymlinkedDirectories: true,
                listings: listings,
              ),
            )
            .toList();
        return (walks: walks, asked: mount.asked);
      } finally {
        mount.restore();
      }
    }

    final everyEntry = [
      'data/.env',
      'data/note.txt',
      'data/x',
      'data/x/.env',
      'data/x/deep',
      'data/x/deep/.env',
      'data/x/link',
      'data/x/round',
      'outside/.env',
    ];
    List<String> lstatsIn(List<String> asked) => asked.expand<String>((call) {
      final found = RegExp(
        r'^lstatSync (.*)',
        dotAll: true,
      ).firstMatch(call)?.group(1);
      return found == null ? const <String>[] : [found];
    }).toList()..sort();

    test('asks nothing about an entry that was listed with its type', () {
      final mount = mounted({}, true);
      try {
        expect(walkGlobPattern(join(data, '**/.env')).matches, hasLength(3));
      } finally {
        mount.restore();
      }
      expect(
        mount.asked.where((call) => RegExp(r'^l?statSync ').hasMatch(call)),
        <String>[],
      );
    });

    // With lstat failing, `x` and `deep` are directories and `.env` a file by
    // stat; `link` is a link because it leads elsewhere, `round` by its ELOOP.
    for (final (how, failing) in <(String, Map<String, String>)>[
      ('by lstat', {}),
      ('by where each entry leads, when lstat fails', {'lstatSync': 'EIO'}),
    ]) {
      test('finds what it finds where types are given, $how', () {
        final typed = walkGlobPattern(
          join(data, '**/.env'),
          withDirectoryForm: true,
          followSymlinkedDirectories: true,
        );
        final (:walks, :asked) = walked(['**/.env'], failing);

        expect(walks.map(_plain).toList(), [_plain(typed)]);
        expect(typed.matches..sort(), [
          join(data, '.env'),
          join(data, 'x', '.env'),
          join(data, 'x', 'deep', '.env'),
          join(root, 'outside', '.env'),
        ]);
        expect(typed.symlinks.toList()..sort(), [
          join(data, 'x', 'link'),
          join(data, 'x', 'round'),
        ]);
        expect(typed.unlisted, <String>[]);
        expect(lstatsIn(asked), everyEntry);
      });
    }

    test(
      'leaves a directory with a backslash in its name to be denied whole when lstat fails',
      () {
        final named = join(data, 'na\\me');
        mkdirSync(named);
        try {
          final (:walks, :asked) = walked(['**/.env'], {'lstatSync': 'EIO'});

          expect(walks[0].unlisted, [named]);
        } finally {
          rmSync(named, {'recursive': true});
        }
      },
    );

    test('asks once for all the patterns handed the same listings', () {
      final patterns = ['**/.env', '**/*.txt', '**/deep/**'];
      final alone = walked(patterns);
      final together = walked(patterns, {}, {});

      expect(
        together.walks.map(_plain).toList(),
        alone.walks.map(_plain).toList(),
      );
      expect(lstatsIn(together.asked), everyEntry);
      expect(lstatsIn(alone.asked), hasLength(3 * everyEntry.length));
    });

    test(
      'matches an entry that is gone since it was listed by its name alone',
      () {
        final (:walks, :asked) = walked(
          ['**/.env', '**/x/**'],
          {'lstatSync': 'ENOENT', 'statSync': 'ENOENT'},
        );

        expect(walks.map((walk) => walk.matches).toList(), [
          [join(data, '.env')],
          <String>[],
        ]);
        for (final walk in walks) {
          expect(walk.unlisted, <String>[]);
          expect(walk.directoryMatches, <String>[]);
        }
        expect(asked, isNot(contains('readdirSync data/x')));
      },
    );

    for (final (call, code) in <(String, String)>[
      ('statSync', 'ESTALE'),
      ('realpathSync', 'EACCES'),
    ]) {
      test(
        'leaves an entry it can learn nothing about to be denied whole ($call: $code)',
        () {
          final (:walks, :asked) = walked(
            ['**/.env', '**/*.pem', '*.env'],
            {'lstatSync': 'EIO', call: code},
            {},
          );

          // Any of them may be a directory with a match beneath it.
          final entries = ['.env', 'note.txt', 'x'];
          expect(walks[0].matches, [join(data, '.env')]);
          for (final walk in walks.take(2)) {
            expect(
              walk.unlisted..sort(),
              entries.map((e) => join(data, e)).toList(),
            );
          }
          // Not for a pattern that matches nothing beneath it.
          expect(walks[2].unlisted, <String>[]);
          expect(asked, isNot(contains('readdirSync data/x')));
          expect(lstatsIn(asked), entries.map((e) => 'data/$e').toList());
        },
      );
    }

    test('says where such an entry really is beneath a symlinked base', () {
      final alias = join(root, 'alias');
      symlinkSync(data, alias);
      final mount = mounted({'lstatSync': 'EIO', 'statSync': 'ESTALE'});
      try {
        final walk = walkGlobPattern(join(alias, '**/.env'));
        expect(walk.unlisted, contains(join(alias, 'x')));
        expect(walk.realOf[join(alias, 'x')], join(data, 'x'));
      } finally {
        mount.restore();
        rmSync(alias);
      }
    });

    test('denies what it finds for a configuration', () async {
      await SandboxManager.reset();
      await SandboxManager.initialize(
        SandboxRuntimeConfig(
          network: const NetworkConfig(allowedDomains: [], deniedDomains: []),
          filesystem: FilesystemConfig(
            denyRead: [
              '**/.env',
              '**/*.pem',
              '**/*.key',
            ].map((p) => FilesystemPathSpelling(join(data, p))).toList(),
            allowWrite: [],
            denyWrite: [],
          ),
        ),
      );
      final found = [
        join(data, '.env'),
        join(data, 'x', '.env'),
        join(data, 'x', 'deep', '.env'),
        join(root, 'outside', '.env'),
      ];
      var mount = mounted();
      try {
        expect(SandboxManager.getFsReadConfig().denyOnly..sort(), found);
        // Once for the three rules together.
        final spliced = mount.asked.toList();
        mount.asked.clear();
        expect(lstatsIn(spliced), everyEntry);
        final wrapped = await SandboxManager.wrapWithSandbox('true');
        expect(lstatsIn(mount.asked), everyEntry);
        for (final file in found) {
          expect(wrapped, contains('--ro-bind /dev/null $file'));
        }

        mount.restore();
        mount = mounted({'lstatSync': 'EIO', 'statSync': 'ESTALE'});
        final unknown = [
          '.env',
          'note.txt',
          'x',
        ].map((name) => join(data, name)).toList();
        final readConfig = SandboxManager.getFsReadConfig();
        expect(readConfig.denyOnly..sort(), unknown);
        expect(readConfig.unlistableDenyDirs?..sort(), unknown);
      } finally {
        mount.restore();
        await SandboxManager.reset();
      }
    }, skip: isLinux ? null : 'requires Linux');
  }, skip: isWindows ? 'Windows not supported by this port' : null);

  // ============================================================================
  // A pattern walked beneath an anchor
  // ============================================================================

  /**
 * The glob dialect has no escape, so a directory whose own name holds `[`,
 * `*` or `?` cannot be spelled inside a pattern: `anchor` says where the name
 * ends and the pattern starts.
 */
  group('a pattern walked beneath an anchor', () {
    late String root;
    late String ordinary;
    final named = ['[WIP] project', 'build*', 'notes (draft?)'];

    setUpAll(() {
      root = realPath(mkdtempSync(join(tmpdir(), 'glob-anchor-')));
      ordinary = join(root, 'ordinary');
      // `buildX` and `W` are what `build*` and `[WIP]` match as patterns.
      for (final base in [...named, 'ordinary', 'buildX', 'W project']) {
        mkdirSync(join(root, base, 'deep', 'er'), {'recursive': true});
        for (final file in ['a]x', 'deep/a]x', 'deep/er/b]x', 'deep/.env']) {
          writeFileSync(join(root, base, file), '');
        }
      }
    });

    tearDownAll(() {
      rmSync(root, {'recursive': true, 'force': true});
    });

    List<String> beneath(String base, List<String> found) =>
        found.map((match) => match.substring(base.length)).toList()..sort();

    for (final name in named) {
      group('a directory named $name', () {
        for (final tail in [
          '/**/.env',
          '/deep/*',
          '/de*/.env',
          '/**/er/*',
          '/*/*]x',
        ]) {
          test(
            'finds for $tail what the same tail finds beneath an ordinary directory',
            () {
              final anchor = join(root, name);
              final expected = beneath(
                ordinary,
                expandGlobPattern(ordinary + tail),
              );
              expect(expected.length, greaterThan(0));
              expect(
                beneath(
                  anchor,
                  expandGlobPattern(anchor + tail, anchor: anchor),
                ),
                expected,
              );
            },
          );
        }

        for (final (tail, expected) in <(String, List<String>)>[
          ('/**/[a*]x', ['/a]x', '/deep/a]x']),
          ('/[a*]x', ['/a]x']),
          ('/deep/[a*]x', ['/deep/a]x']),
        ]) {
          test(
            'matches $tail, which cannot be split, by its spelling from the anchor on',
            () {
              // A wildcard inside a bracket expression: the walk matches such a
              // pattern against whole paths, which beneath an anchor start at it.
              final anchor = join(root, name);
              expect(
                beneath(ordinary, expandGlobPattern(ordinary + tail)),
                expected,
              );
              expect(
                beneath(
                  anchor,
                  expandGlobPattern(anchor + tail, anchor: anchor),
                ),
                expected,
              );
            },
          );
        }
      });
    }

    for (final (_what, wrong) in <(String, String Function(String))>[
      (
        'another directory of the same length',
        (a) => a.replaceFirst(RegExp(r'.$'), '_'),
      ),
      ('a longer path than the pattern', (a) => '$a/deep/.env/more'),
      ('a name cut short', (a) => a.substring(0, a.length - 1)),
      ('the root', (_) => '/'),
      ('nothing', (_) => ''),
    ]) {
      test('throws for an anchor that is $_what', () {
        // The tail is cut by length: taken as it comes, a wrong anchor would walk
        // another directory and hand back what the tail matches there.
        final anchor = join(root, '[WIP] project');
        expect(
          () => expandGlobPattern('$anchor/deep/.env', anchor: wrong(anchor)),
          throwsA(isA<ArgumentError>()),
        );
      });
    }

    test('reads no character of the anchor as pattern', () {
      // Without the anchor the same strings are patterns from end to end.
      final starred = join(root, 'build*');
      expect(expandGlobPattern('$starred/deep/.env')..sort(), [
        join(root, 'build*', 'deep', '.env'),
        join(root, 'buildX', 'deep', '.env'),
      ]);
      expect(expandGlobPattern('$starred/deep/.e*', anchor: starred), [
        join(root, 'build*', 'deep', '.env'),
      ]);
      final bracketed = join(root, '[WIP] project');
      expect(expandGlobPattern('$bracketed/deep/.e*'), [
        join(root, 'W project', 'deep', '.env'),
      ]);
      expect(expandGlobPattern('$bracketed/deep/.e*', anchor: bracketed), [
        join(bracketed, 'deep', '.env'),
      ]);
    });

    test(
      'keeps a trailing separator, with which a pattern matches nothing',
      () {
        final anchor = join(root, '[WIP] project');
        expect(expandGlobPattern('$ordinary/*/'), <String>[]);
        expect(expandGlobPattern('$anchor/*/', anchor: anchor), <String>[]);
      },
    );

    test(
      'starts at the anchor plus the directory the tail itself starts from',
      () {
        final anchor = join(root, '[WIP] project');
        expect(
          walkGlobPattern('$anchor/deep/*', anchor: anchor).baseLocation,
          join(anchor, 'deep'),
        );
        final walk = walkGlobPattern(
          '$anchor/**/er/**',
          anchor: anchor,
          withDirectoryForm: true,
        );
        expect(walk.baseLocation, anchor);
        expect(walk.directoryMatches, [join(anchor, 'deep', 'er')]);
      },
    );
  }, skip: isWindows ? 'Windows not supported by this port' : null);

  // ============================================================================
  // expandTilde — `~\` form is Windows-only
  // ============================================================================

  group('finishInTurns', () {
    /** `count` steps of about `ms` each; returns how many it took. */
    Steps<int> busy(int count, int ms, [Map<String, int>? taken]) sync* {
      taken ??= {'steps': 0};
      for (var i = 0; i < count; i++) {
        final until = Stopwatch()..start();
        while (until.elapsedMilliseconds < ms) {}
        taken['steps'] = taken['steps']! + 1;
        yield Pause();
      }
      yield Done(taken['steps']!);
      return;
    }

    test('lets the event loop have a turn while the steps go on', () async {
      final taken = <String, int>{'steps': 0};
      var stepsWhenTheTimerFired = -1;
      setTimeout(() => stepsWhenTheTimerFired = taken['steps']!, 0);
      expect(await finishInTurns(busy(30, 3, taken)), 30);
      expect(stepsWhenTheTimerFired, greaterThan(0));
      expect(stepsWhenTheTimerFired, lessThan(30));
    });

    test('takes no step for a signal already aborted', () async {
      final taken = <String, int>{'steps': 0};
      final reason = Exception('stopped');
      // Dart: no AbortSignal.abort(reason) in the shim.
      final aborted = AbortController()..abort(reason);
      expect(
        await finishInTurns(
          busy(3, 0, taken),
          aborted.signal,
        ).then<Object?>((v) => v).catchError((Object e) => e),
        reason,
      );
      expect(taken['steps'], 0);
    });

    test("stops at the next turn with the signal's reason", () async {
      final taken = <String, int>{'steps': 0};
      final controller = AbortController();
      final reason = Exception('stopped');
      setTimeout(() => controller.abort(reason), 0);
      expect(
        await finishInTurns(
          busy(30, 3, taken),
          controller.signal,
        ).then<Object?>((v) => v).catchError((Object e) => e),
        reason,
      );
      expect(taken['steps'], lessThan(30));
    });

    test(
      'hands nothing out when the signal is aborted in the last step',
      () async {
        final controller = AbortController();
        final reason = Exception('stopped');
        Steps<String> abortsAtTheEnd() sync* {
          yield Pause();
          controller.abort(reason);
          yield Done('done');
          return;
        }

        expect(
          await finishInTurns(
            abortsAtTheEnd(),
            controller.signal,
          ).then<Object?>((v) => v).catchError((Object e) => e),
          reason,
        );
      },
    );

    test('finds what the walk finds on the spot', () async {
      final root = realPath(mkdtempSync(join(tmpdir(), 'glob-walk-turns-')));
      try {
        mkdirSync(join(root, 'a', 'b'), {'recursive': true});
        writeFileSync(join(root, 'a', 'b', 'id.pem'), '');
        symlinkSync(join(root, 'a'), join(root, 'link'));
        final pattern = join(root, '**/*.pem');
        final inTurns = await finishInTurns(
          walkGlobPatternSteps(
            pattern,
            followSymlinkedDirectories: true,
            withDirectoryForm: true,
          ),
        );
        expect(
          _plain(inTurns),
          _plain(
            walkGlobPattern(
              pattern,
              followSymlinkedDirectories: true,
              withDirectoryForm: true,
            ),
          ),
        );
        expect(
          _plain(inTurns),
          _plain(
            finish(
              walkGlobPatternSteps(
                pattern,
                followSymlinkedDirectories: true,
                withDirectoryForm: true,
              ),
            ),
          ),
        );
        expect(inTurns.matches, [join(root, 'a', 'b', 'id.pem')]);
      } finally {
        rmSync(root, {'recursive': true, 'force': true});
      }
    });
  });

  group('expandTilde', () {
    test('should NOT expand `~\\` on POSIX (literal filename byte)', () {
      // `~\foo` is a legal relative filename on Linux/macOS and
      // must pass through untouched (it is later cwd-resolved).
      expect(expandTilde('~\\backup'), '~\\backup');
      // `~/` and bare `~` still expand on every platform.
      expect(expandTilde('~/x').startsWith('~'), false);
      expect(expandTilde('~').startsWith('~'), false);
    }, skip: !isWindows ? null : 'Windows not supported by this port');

    test('should expand `~\\` on Windows', () {
      expect(expandTilde('~\\x').startsWith('~'), false);
    }, skip: isWindows ? null : 'Windows not supported by this port');
  });

  // ============================================================================
  // stripExtendedPathPrefix — `\\?\` and `\\?\UNC\` shapes
  // ============================================================================

  group('stripExtendedPathPrefix', () {
    test('should strip `\\\\?\\` to a drive-letter path', () {
      expect(
        stripExtendedPathPrefix('\\\\?\\C:\\dir\\f.txt'),
        'C:\\dir\\f.txt',
      );
    });

    test('should strip `\\\\?\\UNC\\` to a `\\\\server\\share` path', () {
      expect(
        stripExtendedPathPrefix('\\\\?\\UNC\\srv\\share\\f.txt'),
        '\\\\srv\\share\\f.txt',
      );
    });

    test('should leave non-extended paths unchanged', () {
      expect(stripExtendedPathPrefix('C:\\dir\\f.txt'), 'C:\\dir\\f.txt');
      expect(
        stripExtendedPathPrefix('\\\\srv\\share\\f.txt'),
        '\\\\srv\\share\\f.txt',
      );
    });

    test('should strip `\\\\?\\UNC\\` case-insensitively', () {
      // Windows accepts the UNC marker in any casing; a case-sensitive
      // strip would leave a cwd-relative `unc\srv\…` (fail-open drop).
      expect(stripExtendedPathPrefix('\\\\?\\unc\\srv\\s\\f'), '\\\\srv\\s\\f');
      expect(stripExtendedPathPrefix('\\\\?\\Unc\\srv\\s\\f'), '\\\\srv\\s\\f');
    });
  });

  // ============================================================================
  // containsGlobCharsWin — `[`/`]` are literal on Windows
  // ============================================================================

  group('containsGlobCharsWin', () {
    test('treats [ and ] as literal filename characters', () {
      expect(containsGlobCharsWin('C:\\app\\[prod].env'), false);
    });

    test('still routes * and ? to glob expansion', () {
      expect(containsGlobCharsWin('C:\\app\\*.env'), true);
      expect(containsGlobCharsWin('C:\\app\\?.env'), true);
    });
  });

  group('expandWindowsFsPaths literal branch', () {
    test(
      'drops non-existent grant paths without throwing (single statSync)',
      () {
        // The literal branch uses one statSync({throwIfNoEntry:false})
        // rather than existsSync→statSync, so a TOCTOU ENOENT cannot
        // abort initialize().
        final missing = join(
          tmpdir(),
          'srt-no-such-${DateTime.now().millisecondsSinceEpoch}.txt',
        );
        expect(
          () => expandWindowsFsPaths([FilesystemPathSpelling(missing)]),
          returnsNormally,
        );
        expect(
          expandWindowsFsPaths([FilesystemPathSpelling(missing)]),
          <String>[],
        );
        expect(
          expandWindowsFsPaths([
            FilesystemPathSpelling(missing),
          ], mode: 'grant'),
          <String>[],
        );
      },
    );

    test('passes non-existent deny paths through for placeholder-create', () {
      // srt-win acl stamp materializes a placeholder chain and stamps
      // it, so the deny lands on the exact target path.
      final missing = join(
        tmpdir(),
        'srt-no-such-${DateTime.now().millisecondsSinceEpoch}',
        'secret.txt',
      );
      final out = expandWindowsFsPaths([
        FilesystemPathSpelling(missing),
      ], mode: 'deny');
      expect(out, hasLength(1));
      expect(out[0], contains('secret.txt'));
    });

    test(
      'still drops non-matching glob deny patterns (glob = match existing)',
      () {
        final noMatch = join(
          tmpdir(),
          'srt-no-such-${DateTime.now().millisecondsSinceEpoch}',
          '*.txt',
        );
        expect(
          expandWindowsFsPaths([FilesystemPathSpelling(noMatch)], mode: 'deny'),
          <String>[],
        );
      },
    );

    test(
      'preserves trailing separator on passed-through deny (leaf-is-dir signal)',
      () {
        // srt-win reads a trailing `/` or `\` as "materialize the
        // placeholder leaf as a directory" so a later
        // mkdirSync({recursive:true}) on the real path succeeds.
        // normalizePathForSandbox may strip it (path.resolve on
        // Windows, realpath elsewhere), so expandWindowsFsPaths
        // re-applies it from the raw input.
        final base = join(
          tmpdir(),
          'srt-no-such-${DateTime.now().millisecondsSinceEpoch}',
          'hooks',
        );
        for (final raw in [base + '/', base + '\\']) {
          final out = expandWindowsFsPaths([
            FilesystemPathSpelling(raw),
          ], mode: 'deny');
          expect(out, hasLength(1));
          expect(RegExp(r'[\\/]$').hasMatch(out[0]), true);
        }
        // No trailing separator ⇒ not re-applied.
        final out = expandWindowsFsPaths([
          FilesystemPathSpelling(base),
        ], mode: 'deny');
        expect(RegExp(r'[\\/]$').hasMatch(out[0]), false);
      },
    );
  });

  // ============================================================================
  // expandWindowsFsPaths — beneath a directory with brackets in its name
  // ============================================================================

  /**
 * `[` and `]` are characters of a name on Windows, but the walk that expands
 * a pattern reads them as a character class: beneath such a directory it
 * finds nothing on its own, and the deny or grant is lost. Pinned here on
 * every host; the spellings only Windows has are in the suite below.
 */
  group('expandWindowsFsPaths beneath a directory named [WIP] project', () {
    late String root;
    late String project;
    late List<String> envFiles;

    setUpAll(() {
      root = realPath(mkdtempSync(join(tmpdir(), 'win-literal-')));
      project = join(root, '[WIP] project');
      mkdirSync(join(project, 'keep'), {'recursive': true});
      mkdirSync(join(project, 'sub', 'deep'), {'recursive': true});
      envFiles = [
        join(project, '.env'),
        join(project, 'sub', '.env'),
        join(project, 'sub', 'deep', '.env'),
      ];
      for (final file in envFiles) {
        writeFileSync(file, '');
      }
      writeFileSync(join(project, 'sub', 'readme'), '');
    });

    tearDownAll(() {
      rmSync(root, {'recursive': true, 'force': true});
    });

    test('takes a path inside it for the path it is', () {
      final kept = join(project, 'keep');
      expect(expandWindowsFsPaths([FilesystemPathSpelling(kept)]), [kept]);
      expect(
        expandWindowsFsPaths([FilesystemPathSpelling(kept)], mode: 'deny'),
        [kept],
      );
    });

    test(
      'passes a deny for a path inside it that is not there yet, and drops the grant',
      () {
        final notYet = join(project, 'not-yet');
        expect(
          expandWindowsFsPaths([FilesystemPathSpelling(notYet)], mode: 'deny'),
          [notYet],
        );
        expect(
          expandWindowsFsPaths([FilesystemPathSpelling(notYet)], mode: 'grant'),
          <String>[],
        );
      },
    );

    for (final mode in ['deny', 'grant']) {
      test('expands a pattern beneath it ($mode)', () {
        expect(
          expandWindowsFsPaths([
            FilesystemPathSpelling('$project/**/.env'),
          ], mode: mode)..sort(),
          [...envFiles]..sort(),
        );
        expect(
          expandWindowsFsPaths([
            FilesystemPathSpelling('$project/sub/*'),
          ], mode: mode)..sort(),
          [
            join(project, 'sub', '.env'),
            join(project, 'sub', 'deep'),
            join(project, 'sub', 'readme'),
          ]..sort(),
        );
      });
    }

    for (final mode in ['deny', 'grant']) {
      test(
        'expands a /** beneath it, the one wildcard the entry has ($mode)',
        () {
          // Without `*` or `?` the rest is no pattern to Windows, and the walk
          // still reads its brackets as a class.
          expect(
            expandWindowsFsPaths([
              FilesystemPathSpelling('$project/sub/**'),
            ], mode: mode)..sort(),
            [
              join(project, 'sub', '.env'),
              join(project, 'sub', 'deep'),
              join(project, 'sub', 'deep', '.env'),
              join(project, 'sub', 'readme'),
            ]..sort(),
          );
          expect(
            expandWindowsFsPaths([
              FilesystemPathSpelling('$project/**'),
            ], mode: mode),
            hasLength(7),
          );
        },
      );
    }

    for (final mode in ['deny', 'grant']) {
      test(
        'expands a pattern with brackets that spell no set of characters ($mode)',
        () {
          // `r-i` runs backwards. At any depth, where no reading as a name reaches.
          final route = join(root, 'app', 'users', '[user-id]');
          mkdirSync(route, {'recursive': true});
          writeFileSync(join(route, 'page.tsx'), '');
          for (final pattern in ['$route/*.tsx', '$root/**/[user-id]/*.tsx']) {
            expect(
              expandWindowsFsPaths([
                FilesystemPathSpelling(pattern),
              ], mode: mode),
              [join(route, 'page.tsx')],
            );
          }
        },
      );
    }

    test('lists a path once that more than one reading finds', () {
      final out = expandWindowsFsPaths([
        FilesystemPathSpelling('$project/**/.env'),
        FilesystemPathSpelling('$project/*/.env'),
        FilesystemPathSpelling(join(project, 'sub', '.env')),
      ], mode: 'deny');
      expect(out..sort(), [...envFiles]..sort());
    });

    test('takes a marked entry for a literal, whatever it holds', () {
      final kept = join(project, 'keep');
      final FilesystemPathEntry marked = FilesystemPathLiteral(kept);
      expect(expandWindowsFsPaths([marked]), [kept]);
      final FilesystemPathEntry notYet = FilesystemPathLiteral(
        join(project, '[later]'),
      );
      expect(expandWindowsFsPaths([notYet], mode: 'deny'), [
        join(project, '[later]'),
      ]);
      expect(expandWindowsFsPaths([notYet], mode: 'grant'), <String>[]);
    });

    test('skips a marked entry with a character no Windows name can hold', () {
      // srt-win refuses `*` and `?` outright, and nothing can have the name.
      for (final path in ['$project/*.env', join(project, 'what?')]) {
        final FilesystemPathEntry marked = FilesystemPathLiteral(path);
        expect(expandWindowsFsPaths([marked], mode: 'deny'), <String>[]);
        expect(expandWindowsFsPaths([marked], mode: 'grant'), <String>[]);
      }
    });

    test('refuses an entry that is neither a path nor a marked path', () {
      // for (const entry of [
      //   { path: project },
      //   { path: project, literal: false },
      // ]) {
      //   expect(() =>
      //     expandWindowsFsPaths([entry as unknown as FilesystemPathEntry]),
      //   ).toThrow(TypeError)
      // }
    }, skip: 'FilesystemPathEntry is sealed: an invalid entry cannot be built');

    test(
      'does not expand a grant beneath a link that has the name the pattern spells',
      () {
        final work = join(root, 'work');
        mkdirSync(join(root, 'vault', 'pub'), {'recursive': true});
        mkdirSync(work, {'recursive': true});
        writeFileSync(join(root, 'vault', 'pub', 'key'), '');
        symlinkSync(join(root, 'vault'), join(work, '[ab]'));
        final pattern = '$work/[ab]/pub/*';
        expect(
          expandWindowsFsPaths([
            FilesystemPathSpelling(pattern),
          ], mode: 'grant'),
          <String>[],
        );
        expect(
          expandWindowsFsPaths([FilesystemPathSpelling(pattern)], mode: 'deny'),
          [join(work, '[ab]', 'pub', 'key')],
        );
      },
      skip: !isWindows ? null : 'Windows not supported by this port',
    );

    test(
      'does not expand a grant beneath a link that lies between such a directory and the first wildcard',
      () {
        final work = join(root, 'work-with-link-inside');
        final vault = join(root, 'vault-behind-link');
        mkdirSync(join(vault, 'deep', 'pub'), {'recursive': true});
        mkdirSync(join(work, '[ab]'), {'recursive': true});
        symlinkSync(vault, join(work, '[ab]', 'mid'));
        final pattern = '$work/[ab]/mid/*/pub';
        expect(
          expandWindowsFsPaths([
            FilesystemPathSpelling(pattern),
          ], mode: 'grant'),
          <String>[],
        );
        expect(
          expandWindowsFsPaths([FilesystemPathSpelling(pattern)], mode: 'deny'),
          [join(work, '[ab]', 'mid', 'deep', 'pub')],
        );
      },
      skip: !isWindows ? null : 'Windows not supported by this port',
    );
  });

  group(
    'expandWindowsFsPaths beneath a bracketed directory, as Windows spells paths',
    () {
      late String root;
      late String project;

      setUpAll(() {
        root = mkdtempSync(join(tmpdir(), 'win-literal-'));
        project = join(root, '[WIP] project');
        mkdirSync(join(project, 'sub', 'deep'), {'recursive': true});
        for (final dir in ['', 'sub', join('sub', 'deep')]) {
          writeFileSync(join(project, dir, '.env'), '');
        }
        writeFileSync(join(project, 'sub', 'readme'), '');
      });

      tearDownAll(() {
        rmSync(root, {'recursive': true, 'force': true});
      });

      /** Every result names an existing `.env`, and there are three of them. */
      void expectTheEnvFiles(List<String> out) {
        expect(out.map((p) => basename(p)).toList(), ['.env', '.env', '.env']);
        expect(out.map((p) => p.toLowerCase()).toSet().length, 3);
        for (final p in out) {
          expect(existsSync(p), true);
        }
      }

      test('expands a pattern spelled with a drive letter and backslashes', () {
        expect(project, contains(RegExp(r'^[A-Za-z]:\\')));
        expectTheEnvFiles(
          expandWindowsFsPaths([
            FilesystemPathSpelling('$project\\**\\.env'),
          ], mode: 'deny'),
        );
      });

      test(
        'expands one spelled with forward slashes and a lower-case drive letter',
        () {
          final spelled =
              project[0].toLowerCase() +
              project.substring(1).replaceAll('\\', '/');
          expectTheEnvFiles(
            expandWindowsFsPaths([
              FilesystemPathSpelling('$spelled/**/.env'),
            ], mode: 'deny'),
          );
          expectTheEnvFiles(
            expandWindowsFsPaths([
              FilesystemPathSpelling('$spelled/**/.env'),
            ], mode: 'grant'),
          );
        },
      );

      test(
        'expands one spelled with mixed separators and the extended-length prefix',
        () {
          expectTheEnvFiles(
            expandWindowsFsPaths([
              FilesystemPathSpelling('\\\\?\\$project/sub/..\\**/.env'),
            ], mode: 'deny'),
          );
        },
      );

      test(
        'takes a marked path spelled with backslashes, and skips one with a wildcard',
        () {
          final out = expandWindowsFsPaths([
            FilesystemPathLiteral('$project\\sub'),
            FilesystemPathLiteral('$project\\*.env'),
          ], mode: 'deny');
          expect(out.map((p) => basename(p)).toList(), ['sub']);
        },
      );

      test('gives a UNC pattern no reading that would probe the share', () {
        // Deciding on a reading looks at the disk, and looking at a UNC path
        // is a request to the host it names.
        for (final unc in [
          '\\\\srt-no-such-host\\share\\[WIP] project\\**\\.env',
          '\\\\?\\UNC\\srt-no-such-host\\share\\[WIP] project\\*.env',
          '//srt-no-such-host/share/[WIP] project/*.env',
        ]) {
          for (final kind in ['deny', 'allow']) {
            expect(
              literalReadings(unc, kind, isPattern: containsGlobCharsWin),
              <Object>[],
            );
          }
        }
      });
    },
    skip: isWindows ? null : 'Windows not supported by this port',
  );

  // ============================================================================
  // isUncPath — broker never stats `\\server\…` with real-user creds
  // ============================================================================

  group('isUncPath', () {
    test('recognises \\\\server\\share and //server/share', () {
      expect(isUncPath('\\\\srv\\share\\dir'), true);
      expect(isUncPath('//srv/share'), true);
    });

    test('recognises the extended-length \\\\?\\UNC\\… form (any casing)', () {
      expect(isUncPath('\\\\?\\UNC\\srv\\share\\dir'), true);
      expect(isUncPath('\\\\?\\unc\\srv\\share'), true);
      expect(isUncPath('//?/UNC/srv/share'), true);
      expect(isUncPath('//?/unc/srv/share'), true);
    });

    test('recognises the device-namespace \\\\.\\UNC\\… form', () {
      // `\\.\UNC\server\share\…` is a real network access — same SMB
      // round-trip as `\\server\share\…`, different spelling.
      expect(isUncPath('\\\\.\\UNC\\srv\\share\\x'), true);
      expect(isUncPath('//./UNC/srv/share'), true);
      expect(isUncPath('\\\\.\\unc\\srv\\share'), true);
    });

    test('does NOT treat drive-local extended or device paths as UNC', () {
      // `\\?\C:\…` is a drive-local extended path; `\\.\pipe\…` /
      // `\\.\C:` are local device names — none name a remote host.
      expect(isUncPath('\\\\?\\C:\\dir'), false);
      expect(isUncPath('\\\\.\\pipe\\x'), false);
      expect(isUncPath('\\\\.\\C:\\x'), false);
    });

    test('rejects local drive-letter, relative, and server-only paths', () {
      expect(isUncPath('C:\\dir'), false);
      // Relative input: toNamespacedPath resolves against the local
      // cwd → drive-local (or rooted) form → false.
      expect(isUncPath('dir\\file'), false);
      expect(isUncPath('\\single'), false);
      // Server without a share is not a valid UNC root.
      expect(isUncPath('\\\\srv'), false);
    });
  });

  group('expandWindowsFsPaths UNC pass-raw', () {
    test(
      'passes UNC literals through without stat (broker never touches SMB)',
      () {
        // A non-existent UNC host — if the broker stat'd this it would
        // hang on an SMB timeout. Pass-raw returns the literal verbatim
        // (path.win32.normalize applied); resolution failure surfaces
        // at srt-win stamp/grant time.
        final unc = '\\\\srt-no-such-host\\share\\dir';
        expect(expandWindowsFsPaths([FilesystemPathSpelling(unc)]), [unc]);
      },
    );

    test(
      'passes \\\\?\\UNC\\… literal through as \\\\server\\share (post-strip)',
      () {
        final ext = '\\\\?\\UNC\\srt-no-such-host\\share\\dir';
        expect(expandWindowsFsPaths([FilesystemPathSpelling(ext)]), [
          '\\\\srt-no-such-host\\share\\dir',
        ]);
      },
    );

    test(
      'passes a UNC deny literal raw (srt-win soft-drops, no placeholder)',
      () {
        // Composition with the deny placeholder chain: a missing UNC
        // deny target must reach srt-win raw — srt-win's is_unc_path
        // soft-drops it rather than mkdir-ing placeholders on an SMB
        // share. The broker side must not stat or placeholder-mark it.
        final unc = '\\\\srt-no-such-host\\share\\secret';
        expect(
          expandWindowsFsPaths([FilesystemPathSpelling(unc)], mode: 'deny'),
          [unc],
        );
      },
    );
  }, skip: isWindows ? null : 'Windows not supported by this port');

  // ============================================================================
  // parseWindowsSandboxError — typed error from srt-win exec stderr
  // ============================================================================

  group('parseWindowsSandboxError', () {
    test('parses mapped_drive_cwd JSON line among noise', () {
      final stderr = [
        'srt-win: launching runner as srt-sandbox (overlay=12 var(s))',
        '{"code":"mapped_drive_cwd","drive":"Z:\\\\","message":"the sandbox cannot start with a mapped/network-drive working directory (Z:\\\\ is DRIVE_REMOTE)"}',
        '',
      ].join('\n');
      final err = parseWindowsSandboxError(stderr);
      expect(err, isA<WindowsSandboxError>());
      expect(err?.code, 'mapped_drive_cwd');
      expect(err?.subcommand, 'exec');
      expect(err?.drive, 'Z:\\');
      expect(err?.message, contains('DRIVE_REMOTE'));
    });

    test('returns undefined when no typed-error line present', () {
      expect(parseWindowsSandboxError('srt-win: error: something\n'), null);
      expect(parseWindowsSandboxError(''), null);
    });
  });

  // ============================================================================
  // Tests for globToRegex() after move to sandbox-utils.ts
  // ============================================================================

  /** One character against the body of a `[…]` set, ranges included. */
  bool setContains(String set, String char) {
    for (var i = 0; i < set.length; i++) {
      if (i + 1 < set.length && set[i + 1] == '-' && i + 2 < set.length) {
        if (char.compareTo(set[i]) >= 0 && char.compareTo(set[i + 2]) <= 0) {
          return true;
        }
        i += 2;
      } else if (set[i] == char) {
        return true;
      }
    }
    return false;
  }

  /**
 * The documented glob syntax matched directly, by backtracking rather than
 * by compiling a regex: `*` and `?` stop at a separator, `**` crosses them,
 * `**\/` is zero or more directories, `[…]` is one character from the set.
 * Shares nothing with {@link globToRegex}, so the property below is two
 * implementations checking each other.
 */
  bool referenceGlobMatch(String pattern, String pathText) {
    if (pattern == '') return pathText == '';
    if (pattern.startsWith('**/')) {
      final rest = pattern.substring(3);
      if (referenceGlobMatch(rest, pathText)) return true;
      for (var i = 0; i < pathText.length; i++) {
        if (pathText[i] != '/') continue;
        if (referenceGlobMatch(rest, pathText.substring(i + 1))) return true;
      }
      return false;
    }
    if (pattern.startsWith('**')) {
      final rest = pattern.substring(2);
      for (var i = 0; i <= pathText.length; i++) {
        if (referenceGlobMatch(rest, pathText.substring(i))) return true;
      }
      return false;
    }
    final head = pattern[0];
    if (head == '*') {
      for (var i = 0; i <= pathText.length; i++) {
        if (i > 0 && pathText[i - 1] == '/') break;
        if (referenceGlobMatch(pattern.substring(1), pathText.substring(i))) {
          return true;
        }
      }
      return false;
    }
    if (head == '?') {
      return pathText.isNotEmpty &&
          pathText[0] != '/' &&
          referenceGlobMatch(pattern.substring(1), pathText.substring(1));
    }
    if (head == '[') {
      final close = pattern.indexOf(']');
      if (close > 1) {
        return pathText.isNotEmpty &&
            setContains(pattern.substring(1, close), pathText[0]) &&
            referenceGlobMatch(
              pattern.substring(close + 1),
              pathText.substring(1),
            );
      }
    }
    return pathText.isNotEmpty &&
        pathText[0] == head &&
        referenceGlobMatch(pattern.substring(1), pathText.substring(1));
  }

  group('globToRegex (shared)', () {
    test('should convert simple wildcard', () {
      final regex = globToRegex('/tmp/test/*.env');
      expect(RegExp(regex).hasMatch('/tmp/test/token.env'), true);
      expect(RegExp(regex).hasMatch('/tmp/test/secrets.env'), true);
      expect(RegExp(regex).hasMatch('/tmp/test/readme.txt'), false);
      // * should not match across /
      expect(RegExp(regex).hasMatch('/tmp/test/sub/token.env'), false);
    });

    test('should convert globstar pattern', () {
      final regex = globToRegex('/tmp/test/**/*.env');
      expect(RegExp(regex).hasMatch('/tmp/test/token.env'), true);
      expect(RegExp(regex).hasMatch('/tmp/test/sub/token.env'), true);
      expect(RegExp(regex).hasMatch('/tmp/test/sub/deep/token.env'), true);
      expect(RegExp(regex).hasMatch('/tmp/test/readme.txt'), false);
    });

    test('should convert ? wildcard', () {
      final regex = globToRegex('/tmp/test/file?.txt');
      expect(RegExp(regex).hasMatch('/tmp/test/file1.txt'), true);
      expect(RegExp(regex).hasMatch('/tmp/test/fileA.txt'), true);
      expect(RegExp(regex).hasMatch('/tmp/test/file12.txt'), false);
      // ? should not match /
      expect(RegExp(regex).hasMatch('/tmp/test/file/.txt'), false);
    });

    test('should handle ** without trailing slash', () {
      final regex = globToRegex('/tmp/test/**');
      expect(RegExp(regex).hasMatch('/tmp/test/anything'), true);
      expect(RegExp(regex).hasMatch('/tmp/test/sub/deep/file.txt'), true);
    });

    test('should match one character from a bracket set', () {
      final digits = globToRegex('/tmp/test/file[0-9].txt');
      expect(RegExp(digits).hasMatch('/tmp/test/file3.txt'), true);
      expect(RegExp(digits).hasMatch('/tmp/test/fileA.txt'), false);
      expect(RegExp(digits).hasMatch('/tmp/test/file12.txt'), false);
      expect(RegExp(digits).hasMatch('/tmp/test/file.txt'), false);

      final letters = globToRegex('/tmp/test/[a-z]bc.txt');
      expect(RegExp(letters).hasMatch('/tmp/test/abc.txt'), true);
      expect(RegExp(letters).hasMatch('/tmp/test/Abc.txt'), false);
      expect(RegExp(letters).hasMatch('/tmp/test/1bc.txt'), false);
    });

    test('never negates a bracket set: ^ and ! are members of it', () {
      // Both spellings used for negation elsewhere (regex `^`, gitignore `!`)
      // land in the set as ordinary characters, so such a pattern matches
      // fewer names than its author meant, not more.
      final caret = globToRegex('/tmp/test/file[^0-9].txt');
      expect(RegExp(caret).hasMatch('/tmp/test/file^.txt'), true);
      expect(RegExp(caret).hasMatch('/tmp/test/file3.txt'), true);
      expect(RegExp(caret).hasMatch('/tmp/test/fileA.txt'), false);

      final bang = globToRegex('/tmp/test/file[!0-9].txt');
      expect(RegExp(bang).hasMatch('/tmp/test/file!.txt'), true);
      expect(RegExp(bang).hasMatch('/tmp/test/file3.txt'), true);
      expect(RegExp(bang).hasMatch('/tmp/test/fileA.txt'), false);
    });

    test('treats a bracket that opens no set as a literal character', () {
      final unclosed = globToRegex('/tmp/test/file[abc.txt');
      expect(RegExp(unclosed).hasMatch('/tmp/test/file[abc.txt'), true);
      expect(RegExp(unclosed).hasMatch('/tmp/test/filea.txt'), false);

      final stray = globToRegex('/tmp/test/file]a.txt');
      expect(RegExp(stray).hasMatch('/tmp/test/file]a.txt'), true);
      expect(RegExp(stray).hasMatch('/tmp/test/filea.txt'), false);
    });

    for (final name in [
      '[z-a]',
      '[user-id]',
      'backup[2024-01-15]',
      '[[z-a]',
      '[z-a]]',
      '[a-.]',
      'a[b[c',
    ]) {
      test('reads brackets that spell no set as the text they are: $name', () {
        final regex = RegExp(globToRegex('/tmp/$name/x'));
        expect(regex.hasMatch('/tmp/$name/x'), true);
        for (final char in name.split('')) {
          expect(regex.hasMatch('/tmp/$char/x'), false);
        }
      });
    }

    test('keeps the rest of such a pattern a pattern', () {
      final regex = RegExp(globToRegex('/tmp/**/[user-id]/file[0-9]?.*'));
      expect(regex.hasMatch('/tmp/[user-id]/file3x.env'), true);
      expect(regex.hasMatch('/tmp/a/b/[user-id]/file3x.env'), true);
      expect(regex.hasMatch('/tmp/[user-id]/file[0-9]x.env'), false);
      expect(regex.hasMatch('/tmp/u/file3x.env'), false);

      final within = RegExp(globToRegex('/tmp/[z-a*.]'));
      expect(within.hasMatch('/tmp/[z-a and more.]'), true);
      expect(within.hasMatch('/tmp/[z-a/more.]'), false);
      expect(within.hasMatch('/tmp/[z-a and more!]'), false);
    });

    test('says under SRT_DEBUG which brackets it reads as text', () async {
      final (result: _, :warnings) = await withCapturedWarnings(
        () => Future.value(globToRegex('/tmp/[ab]/[user-id]/*')),
      );
      expect(warnings, hasLength(1));
      expect(warnings[0], contains('The brackets in [user-id] spell no set'));
      expect(warnings[0], endsWith(': /tmp/[ab]/[user-id]/*'));
    });

    test('gives a regular expression whatever it is given', () {
      // fc.array(fc.constantFrom(...'[[]]--**??//\\^!().az', '__GLOBSTAR__'), { maxLength: 10 })
      final random = Random(20261010);
      final choices = [...'[[]]--**??//\\^!().az'.split(''), '__GLOBSTAR__'];
      for (var run = 0; run < 5000; run++) {
        final pattern = List.generate(
          random.nextInt(11),
          (_) => choices[random.nextInt(choices.length)],
        ).join('');
        RegExp(globToRegex(pattern), caseSensitive: false, dotAll: true);
        RegExp(denyGlobRegex(pattern));
      }
    });

    test(
      'matches the path a generated pattern spells, and not one a set would',
      () {
        // A segment, a name it matches, and for brackets that spell no set a name
        // they would match as one.
        final segment = <(String, String, String?)>[
          ('a', 'a', null),
          ('*', 'xy', null),
          ('?', 'x', null),
          ('**', 'p/q', null),
          ('[ab]c', 'bc', null),
          ('[z-a]', '[z-a]', 'z'),
          ('[user-id]', '[user-id]', 'u'),
          ('v[9-0]*', 'v[9-0].1', 'v9.1'),
          ('[ab][b-a]', 'a[b-a]', 'ab'),
        ];
        final random = Random(20261010);
        for (var run = 0; run < 500; run++) {
          final parts = List.generate(
            1 + random.nextInt(5),
            (_) => segment[random.nextInt(segment.length)],
          );
          final regex = RegExp(
            globToRegex('/' + parts.map((p) => p.$1).join('/')),
          );
          final names = parts.map((p) => p.$2).toList();
          expect(regex.hasMatch('/' + names.join('/')), true);
          for (final (i, (_, _, asSet)) in parts.indexed) {
            if (asSet == null) continue;
            final other = [
              for (final (j, name) in names.indexed) j == i ? asSet : name,
            ];
            expect(regex.hasMatch('/' + other.join('/')), false);
          }
        }
      },
    );

    test('keeps a component spelled like a globstar placeholder literal', () {
      // Dart: it.failing, which passes when its body fails.
      expect(() {
        // globToRegex parks `**` under __GLOBSTAR__ / __GLOBSTAR_SLASH__ while
        // it rewrites `*` and `?`, then restores them by name, so a directory
        // actually called __GLOBSTAR__ comes back as a wildcard.
        final parked = globToRegex('/tmp/__GLOBSTAR__/x');
        expect(RegExp(parked).hasMatch('/tmp/__GLOBSTAR__/x'), true);
        expect(RegExp(parked).hasMatch('/tmp/anything/x'), false);

        final parkedSlash = globToRegex('/tmp/__GLOBSTAR_SLASH__x');
        expect(RegExp(parkedSlash).hasMatch('/tmp/__GLOBSTAR_SLASH__x'), true);
      }, throwsA(isA<TestFailure>()));
    });

    test(
      'agrees with a reference matcher over generated patterns and paths',
      () {
        // Segments are drawn from the documented syntax only; the corners the
        // cases above pin (an unclosed bracket, a stray `]`, a negated set, a
        // literal placeholder) are left out so a disagreement here means the
        // documented syntax itself diverged.
        final segment = [
          'a',
          'bc',
          'a*',
          '*b',
          '*',
          '?',
          'a?c',
          '[ab]',
          '[0-9]',
          '[a-c]c',
          '**',
        ];
        final pathPart = ['a', 'b', 'c', 'bc', 'a1', 'abc', '0', 'ab'];
        final random = Random(20261010);
        for (var run = 0; run < 200; run++) {
          final p =
              '/' +
              List.generate(
                1 + random.nextInt(4),
                (_) => segment[random.nextInt(segment.length)],
              ).join('/');
          final f =
              '/' +
              List.generate(
                1 + random.nextInt(4),
                (_) => pathPart[random.nextInt(pathPart.length)],
              ).join('/');
          expect(
            RegExp(globToRegex(p)).hasMatch(f),
            referenceGlobMatch(p, f),
            reason: 'run $run, pattern $p, path $f',
          );
        }
      },
    );
  });

  // ============================================================================
  // Tests for getFsReadConfig with glob expansion on Linux
  // ============================================================================

  group('getFsReadConfig with glob patterns on Linux', () {
    final RAW_BASE_DIR = join(
      tmpdir(),
      'fsread-glob-test-${DateTime.now().millisecondsSinceEpoch}',
    );
    final RAW_TEST_DIR = join(RAW_BASE_DIR, 'testdir');

    setUpAll(() {
      mkdirSync(RAW_TEST_DIR, {'recursive': true});
      writeFileSync(join(RAW_TEST_DIR, 'secret.env'), 'SECRET=value');
      writeFileSync(join(RAW_TEST_DIR, 'token.env'), 'TOKEN=value');
      writeFileSync(join(RAW_TEST_DIR, 'readme.txt'), 'readme');
    });

    tearDownAll(() {
      if (existsSync(RAW_BASE_DIR)) {
        rmSync(RAW_BASE_DIR, {'recursive': true, 'force': true});
      }
    });

    test(
      'should expand glob denyRead patterns to concrete paths on Linux',
      () async {
        await SandboxManager.reset();
        await SandboxManager.initialize(
          _config(
            denyRead: [join(RAW_TEST_DIR, '*.env')],
            allowWrite: ['/tmp'],
          ),
        );

        final readConfig = SandboxManager.getFsReadConfig();
        final realTestDir = realPath(RAW_TEST_DIR);

        // Should contain the expanded concrete paths, not the glob pattern
        expect(readConfig.denyOnly, contains(join(realTestDir, 'secret.env')));
        expect(readConfig.denyOnly, contains(join(realTestDir, 'token.env')));
        // Should NOT contain the original glob pattern
        final hasGlob = readConfig.denyOnly.any((String p) => p.contains('*'));
        expect(hasGlob, false);
        // Should NOT contain non-matching files
        expect(
          readConfig.denyOnly,
          isNot(contains(join(realTestDir, 'readme.txt'))),
        );

        await SandboxManager.reset();
      },
    );

    test(
      'lists a directory once for all the denyRead patterns of a configuration',
      () async {
        await SandboxManager.reset();
        await SandboxManager.initialize(
          _config(
            denyRead: [
              '*.env',
              '*.txt',
              '*.pem',
            ].map((p) => join(RAW_TEST_DIR, p)).toList(),
            allowWrite: ['/tmp'],
          ),
        );

        final realTestDir = realPath(RAW_TEST_DIR);
        Future<int> timesListedBy(Object? Function() call) async {
          var times = 0;
          final readdirSync = fs.readdirSync;
          fs.readdirSync = (String p, {bool withFileTypes = true}) {
            if (p == realTestDir) times++;
            return readdirSync(p, withFileTypes: withFileTypes);
          };
          try {
            await call();
          } finally {
            fs.readdirSync = readdirSync;
          }
          return times;
        }

        try {
          expect(
            await timesListedBy(() => SandboxManager.getFsReadConfig()),
            1,
          );
          expect(
            await timesListedBy(() => SandboxManager.wrapWithSandbox('true')),
            1,
          );
        } finally {
          await SandboxManager.reset();
        }
      },
    );

    test('gives each path once, however many patterns came to it', () async {
      final root = realPath(mkdtempSync(join(tmpdir(), 'glob-walk-once-')));
      final locked = join(root, 'locked');
      mkdirSync(locked);
      chmodSync(locked, 0x0);
      writeFileSync(join(root, 'id.pem'), '');

      await SandboxManager.reset();
      await SandboxManager.initialize(
        _config(
          // All three could not list `locked`, and two match the file.
          denyRead: [
            '**/*.pem',
            '**/id.*',
            '**/.env',
          ].map((p) => join(root, p)).toList(),
        ),
      );
      try {
        expect(SandboxManager.getFsReadConfig().denyOnly, [
          join(root, 'id.pem'),
          locked,
        ]);
      } finally {
        await SandboxManager.reset();
        chmodSync(locked, 0x1ED);
        rmSync(root, {'recursive': true, 'force': true});
      }
    }, skip: process.getuid?.call() != 0 ? null : 'running as root');

    for (final list in ['denyRead', 'allowRead']) {
      test(
        'gives up a wrap whose signal is aborted while a $list pattern is walked',
        () async {
          final root = realPath(
            mkdtempSync(join(tmpdir(), 'glob-walk-abort-')),
          );
          final dirs = List.generate(12, (i) => join(root, 'd$i'));
          for (final dir in dirs) {
            mkdirSync(dir);
          }

          await SandboxManager.reset();
          await SandboxManager.initialize(
            _config(
              denyRead: list == 'denyRead' ? [join(root, '**/*.pem')] : [root],
              allowRead: list == 'allowRead' ? [join(root, '**/*.pem')] : [],
            ),
          );

          // Each listing takes longer than a turn, and the third one aborts.
          final controller = AbortController();
          final reason = Exception('stopped');
          var listed = 0;
          final readdirSync = fs.readdirSync;
          fs.readdirSync = (String p, {bool withFileTypes = true}) {
            if (p.startsWith(root)) {
              if (++listed == 3) controller.abort(reason);
              final until = Stopwatch()..start();
              while (until.elapsedMilliseconds < 15) {}
            }
            return readdirSync(p, withFileTypes: withFileTypes);
          };
          try {
            expect(
              await SandboxManager.wrapWithSandbox(
                'true',
                null,
                null,
                controller.signal,
              ).then<Object?>((v) => v).catchError((Object e) => e),
              reason,
            );
            expect(listed, 3);
          } finally {
            fs.readdirSync = readdirSync;
            await SandboxManager.reset();
            rmSync(root, {'recursive': true, 'force': true});
          }
        },
      );
    }

    test('wraps by one configuration when that is replaced in a turn', () async {
      final root = realPath(mkdtempSync(join(tmpdir(), 'glob-walk-replaced-')));
      for (var i = 0; i < 6; i++) {
        mkdirSync(join(root, 'tree', 'd$i'), {'recursive': true});
      }
      mkdirSync(join(root, '.git'));
      for (final name in ['first', 'second', '.git/config']) {
        writeFileSync(join(root, name), '');
      }
      // They differ in what the wrap reads before its first turn and after its
      // last: put together, the first's write list and the second's
      // allowGitConfig would leave .git/config writable, which neither does.
      final allowRead = [join(root, 'tree', '**/*.pem')];
      final first = _config(
        denyRead: [join(root, 'first')],
        allowRead: allowRead,
        allowWrite: [root],
      );
      final second = _config(
        denyRead: [join(root, 'second')],
        allowRead: allowRead,
        allowGitConfig: true,
      );

      final cwd = process.cwd();
      Directory.current = root;
      await SandboxManager.reset();
      await SandboxManager.initialize(first);

      // Each listing takes longer than a turn; the configuration is replaced
      // while the allowRead pattern, the first to be walked, is under way.
      var listed = 0;
      final readdirSync = fs.readdirSync;
      fs.readdirSync = (String p, {bool withFileTypes = true}) {
        if (p.startsWith(root)) {
          if (++listed == 2) SandboxManager.updateConfig(second);
          final until = Stopwatch()..start();
          while (until.elapsedMilliseconds < 15) {}
        }
        return readdirSync(p, withFileTypes: withFileTypes);
      };
      try {
        final disturbed = await SandboxManager.wrapWithSandbox('true');
        fs.readdirSync = readdirSync;

        expect(listed, greaterThan(2));
        expect(disturbed, await SandboxManager.wrapWithSandbox('true'));
        expect(disturbed, contains(join(root, 'second')));
        expect(disturbed, isNot(contains(join(root, 'first'))));
      } finally {
        fs.readdirSync = readdirSync;
        Directory.current = cwd;
        await SandboxManager.reset();
        rmSync(root, {'recursive': true, 'force': true});
      }
    });

    for (final (what, before, after) in <(String, List<String>, List<String>)>[
      (
        'the rule that matches it was installed',
        ['**/.env'],
        ['**/.env', '**/*.pem'],
      ),
      ('the same rules were installed again', ['**/*.pem'], ['**/*.pem']),
    ]) {
      // The third listing is in the middle of the walk, the seventh is its
      // last, after which only the check at the end of the wrap can tell.
      for (final at in [3, 7]) {
        test(
          'denies a file written during the wrap, before $what (in listing $at)',
          () async {
            final root = realPath(
              mkdtempSync(join(tmpdir(), 'glob-walk-fresh-')),
            );
            for (var i = 0; i < 6; i++) {
              mkdirSync(join(root, 'd$i'));
            }
            SandboxRuntimeConfig configured(List<String> patterns) => _config(
              denyRead: patterns.map((pattern) => join(root, pattern)).toList(),
            );

            await SandboxManager.reset();
            await SandboxManager.initialize(configured(before));

            // Each listing takes longer than a turn. In listing `at`, with `root`
            // long listed, the host writes a file there and then installs rules.
            final listed = <String>[];
            final readdirSync = fs.readdirSync;
            fs.readdirSync = (String p, {bool withFileTypes = true}) {
              if (p.startsWith(root)) {
                listed.add(p);
                if (listed.length == at) {
                  writeFileSync(join(root, 'key.pem'), '');
                  SandboxManager.updateConfig(configured(after));
                }
                final until = Stopwatch()..start();
                while (until.elapsedMilliseconds < 15) {}
              }
              return readdirSync(p, withFileTypes: withFileTypes);
            };
            try {
              final disturbed = await SandboxManager.wrapWithSandbox('true');
              fs.readdirSync = readdirSync;

              expect(listed[0], root);
              expect(disturbed, contains(join(root, 'key.pem')));
              expect(disturbed, await SandboxManager.wrapWithSandbox('true'));
              // The first attempt is left at once; the second lists all seven.
              expect(listed.length, at + 7);
            } finally {
              fs.readdirSync = readdirSync;
              await SandboxManager.reset();
              rmSync(root, {'recursive': true, 'force': true});
            }
          },
        );
      }
    }

    // As above: the third listing is in the middle of the walk, the seventh is
    // its last.
    for (final at in [3, 7]) {
      test(
        'wraps from one working directory when the host changes it in a turn (in listing $at)',
        () async {
          final root = realPath(
            mkdtempSync(join(tmpdir(), 'glob-walk-chdir-')),
          );
          for (var i = 0; i < 6; i++) {
            mkdirSync(join(root, 'tree', 'd$i'), {'recursive': true});
          }
          mkdirSync(join(root, 'from'));
          mkdirSync(join(root, 'to'));
          final cwd = process.cwd();
          Directory.current = join(root, 'from');

          await SandboxManager.reset();
          await SandboxManager.initialize(
            _config(
              denyRead: [join(root, 'tree', '**/*.pem')],
              allowWrite: ['.'],
            ),
          );

          final listed = <String>[];
          final readdirSync = fs.readdirSync;
          fs.readdirSync = (String p, {bool withFileTypes = true}) {
            if (p.startsWith(join(root, 'tree'))) {
              listed.add(p);
              if (listed.length == at) {
                Directory.current = join(root, 'to');
              }
              final until = Stopwatch()..start();
              while (until.elapsedMilliseconds < 15) {}
            }
            return readdirSync(p, withFileTypes: withFileTypes);
          };
          try {
            final disturbed = await SandboxManager.wrapWithSandbox('true');
            fs.readdirSync = readdirSync;

            expect(disturbed, await SandboxManager.wrapWithSandbox('true'));
            expect(disturbed, contains(join(root, 'to')));
            expect(disturbed, isNot(contains(join(root, 'from'))));
            expect(listed.length, at + 7);
          } finally {
            fs.readdirSync = readdirSync;
            Directory.current = cwd;
            await SandboxManager.reset();
            rmSync(root, {'recursive': true, 'force': true});
          }
        },
      );
    }

    test(
      'wraps from one working directory when the host changes it while the mandatory denies are looked for',
      () async {
        final root = realPath(
          mkdtempSync(join(tmpdir(), 'glob-walk-scan-cd-')),
        );
        mkdirSync(join(root, 'from'));
        mkdirSync(join(root, 'to'));
        // Stands in for ripgrep: says that it ran, finds nothing, and takes long
        // enough for the host to move meanwhile.
        final scans = join(root, 'scans');
        final slowScan = join(root, 'slow-scan');
        writeFileSync(slowScan, '#!/bin/sh\necho ran >> $scans\nsleep 0.4\n', {
          'mode': 0x1ED,
        });
        final cwd = process.cwd();
        Directory.current = join(root, 'from');

        await SandboxManager.reset();
        await SandboxManager.initialize(
          _config(
            denyRead: [],
            allowWrite: ['.'],
            ripgrep: RipgrepConfig(command: slowScan),
          ),
        );
        final moving = setTimeout(
          () => Directory.current = join(root, 'to'),
          150,
        );
        try {
          final disturbed = await SandboxManager.wrapWithSandbox('true');

          expect(fs.readFileSync(scans, 'utf8'), 'ran\nran\n');
          expect(disturbed, await SandboxManager.wrapWithSandbox('true'));
          expect(disturbed, contains(join(root, 'to')));
          expect(disturbed, isNot(contains(join(root, 'from'))));
        } finally {
          clearTimeout(moving);
          Directory.current = cwd;
          await SandboxManager.reset();
          rmSync(root, {'recursive': true, 'force': true});
        }
      },
    );

    test(
      'starts over for a configuration object that is installed a second time',
      () async {
        final DIRECTORIES = 24;
        final root = realPath(mkdtempSync(join(tmpdir(), 'glob-walk-again-')));
        for (var i = 0; i < DIRECTORIES; i++) {
          mkdirSync(join(root, 'd$i'));
        }
        // initialize() keeps this very object, so it is the same one afterwards.
        final same = _config(denyRead: [join(root, '**/*.pem')]);

        await SandboxManager.reset();
        await SandboxManager.initialize(same);

        // In the third listing, with `root` long listed, the host writes a file
        // there, and then resets and initializes in the turns that follow.
        final listed = <String>[];
        int? listedWhenInstalled;
        Future<void>? installed;
        final readdirSync = fs.readdirSync;
        fs.readdirSync = (String p, {bool withFileTypes = true}) {
          if (p.startsWith(root)) {
            listed.add(p);
            if (listed.length == 3) {
              writeFileSync(join(root, 'key.pem'), '');
              installed = SandboxManager.reset().then((_) {
                final initialized = SandboxManager.initialize(same);
                listedWhenInstalled = listed.length;
                return initialized;
              });
            }
            final until = Stopwatch()..start();
            while (until.elapsedMilliseconds < 15) {}
          }
          return readdirSync(p, withFileTypes: withFileTypes);
        };
        try {
          final disturbed = await SandboxManager.wrapWithSandbox('true');
          fs.readdirSync = readdirSync;

          // While the first attempt was still walking, or this shows nothing.
          expect(listedWhenInstalled, lessThan(1 + DIRECTORIES));
          expect(disturbed, contains(join(root, 'key.pem')));
        } finally {
          fs.readdirSync = readdirSync;
          await installed;
          await SandboxManager.reset();
          rmSync(root, {'recursive': true, 'force': true});
        }
      },
    );

    test('walks without a turn once a wrap has started over twice', () async {
      final root = realPath(mkdtempSync(join(tmpdir(), 'glob-walk-churn-')));
      for (var n = 0; n < 8; n++) {
        mkdirSync(join(root, 't$n', 'd'), {'recursive': true});
        writeFileSync(join(root, 't$n', 'd', 'id.pem'), '');
      }
      // Each configuration's pattern has a base no other one lists.
      SandboxRuntimeConfig configured(int n) =>
          _config(denyRead: [join(root, 't$n', '**/*.pem')]);

      await SandboxManager.reset();
      await SandboxManager.initialize(configured(0));

      // Each listing takes longer than a turn and leaves a new configuration
      // for the next turn to bring. The first attempt is left after it has
      // listed t0 and the second after t1; the third walks t2 without a turn,
      // so the configurations its listings leave come too late.
      var replaced = 0;
      final listed = <String>[];
      final readdirSync = fs.readdirSync;
      fs.readdirSync = (String p, {bool withFileTypes = true}) {
        if (p.startsWith(root)) {
          listed.add(p.substring(root.length + 1));
          Timer(
            Duration.zero,
            () => SandboxManager.updateConfig(configured(++replaced)),
          );
          final until = Stopwatch()..start();
          while (until.elapsedMilliseconds < 15) {}
        }
        return readdirSync(p, withFileTypes: withFileTypes);
      };
      try {
        final wrapped = await SandboxManager.wrapWithSandbox('true');
        fs.readdirSync = readdirSync;

        expect(listed, ['t0', 't1', 't2', 't2/d']);
        expect(wrapped, contains(join(root, 't2', 'd', 'id.pem')));
      } finally {
        fs.readdirSync = readdirSync;
        await Future<void>.delayed(Duration.zero);
        await SandboxManager.reset();
        rmSync(root, {'recursive': true, 'force': true});
      }
    });

    test(
      'gives up a wrap whose signal is aborted while the mandatory denies are looked for',
      () async {
        final root = realPath(mkdtempSync(join(tmpdir(), 'glob-walk-scan-')));
        // Stands in for ripgrep, and outlasts the abort.
        final slowScan = join(root, 'slow-scan');
        writeFileSync(slowScan, '#!/bin/sh\nsleep 5\n', {'mode': 0x1ED});

        await SandboxManager.reset();
        await SandboxManager.initialize(
          _config(
            denyRead: [],
            allowWrite: [root],
            ripgrep: RipgrepConfig(command: slowScan),
          ),
        );
        final controller = AbortController();
        final reason = Exception('stopped');
        setTimeout(() => controller.abort(reason), 200);
        try {
          expect(
            await SandboxManager.wrapWithSandbox(
              'true',
              null,
              null,
              controller.signal,
            ).then<Object?>((v) => v).catchError((Object e) => e),
            reason,
          );
        } finally {
          await SandboxManager.reset();
          rmSync(root, {'recursive': true, 'force': true});
        }
      },
    );

    test('should pass non-glob paths through unchanged on Linux', () async {
      await SandboxManager.reset();
      await SandboxManager.initialize(
        _config(
          denyRead: [join(RAW_TEST_DIR, 'secret.env')],
          allowWrite: ['/tmp'],
        ),
      );

      final readConfig = SandboxManager.getFsReadConfig();

      // Literal path should pass through (after normalization)
      expect(readConfig.denyOnly.length, 1);
      expect(readConfig.denyOnly[0], contains('secret.env'));

      await SandboxManager.reset();
    });

    test(
      'should handle trailing /** by stripping suffix (existing behavior)',
      () async {
        final realTestDir = realPath(RAW_TEST_DIR);

        await SandboxManager.reset();
        await SandboxManager.initialize(
          _config(denyRead: [RAW_TEST_DIR + '/**'], allowWrite: ['/tmp']),
        );

        final readConfig = SandboxManager.getFsReadConfig();

        // /** suffix is stripped, leaving the directory path
        // This is the existing behavior - bubblewrap uses tmpfs over the directory
        expect(readConfig.denyOnly.length, 1);
        expect(readConfig.denyOnly[0], realTestDir);

        await SandboxManager.reset();
      },
    );
  }, skip: isLinux ? null : 'requires Linux');

  // ============================================================================
  // Tests for wraps asked for while another one walks, on Linux
  // ============================================================================

  group('wrapWithSandbox while another wrap walks', () {
    final cwd = process.cwd();
    late String root;
    /** The tree each listing was in: `a`, `b` or `c`, three listings each. */
    late String listed;
    /** Runs in each listing, with how many there have been and what it found. */
    late void Function(int nth, Object entries) inListing;
    late void Function() readdirSpy;

    SandboxRuntimeConfig configured(
      List<String> denyRead,
      List<String> allowWrite,
    ) => _config(
      denyRead: denyRead.map((pattern) => join(root, pattern)).toList(),
      allowWrite: allowWrite,
    );
    /** A wrap that walks `tree`, whatever is configured. */
    Future<String> wrapWalking(String tree, [AbortSignal? signal]) =>
        SandboxManager.wrapWithSandbox(
          'true',
          null,
          PartialSandboxRuntimeConfig(
            filesystem: configured(['$tree/**/*.pem'], []).filesystem,
          ),
          signal,
        );

    setUp(() async {
      root = realPath(mkdtempSync(join(tmpdir(), 'glob-walk-line-')));
      for (final tree in ['a', 'b', 'c']) {
        mkdirSync(join(root, tree, 'from'), {'recursive': true});
        mkdirSync(join(root, tree, 'to'));
      }
      listed = '';
      inListing = (_, _) {};
      // Each listing takes longer than a turn.
      final readdirSync = fs.readdirSync;
      fs.readdirSync = (String p, {bool withFileTypes = true}) {
        final entries = readdirSync(p, withFileTypes: withFileTypes);
        if (p.startsWith(root)) {
          listed += p[root.length + 1];
          inListing(listed.length, entries);
          final until = Stopwatch()..start();
          while (until.elapsedMilliseconds < 15) {}
        }
        return entries;
      };
      readdirSpy = () => fs.readdirSync = readdirSync;
      Directory.current = join(root, 'c', 'from');
      await SandboxManager.reset();
      await SandboxManager.initialize(configured(['b/**/.env'], ['.', root]));
    });

    tearDown(() async {
      readdirSpy();
      Directory.current = cwd;
      await SandboxManager.reset();
      rmSync(root, {'recursive': true, 'force': true});
    });

    test(
      'walks for one wrap at a time, in the order they were asked for',
      () async {
        await Future.wait(['a', 'b', 'c'].map((tree) => wrapWalking(tree)));
        expect(listed, 'aaabbbccc');
      },
    );

    // Aborted before it is asked for, and while it waits.
    for (final at in [0, 2]) {
      test(
        'gives up an aborted wrap before its place comes, and goes on to the next (aborted after $at listings)',
        () async {
          final controller = AbortController();
          final reason = Exception('stopped');
          inListing = (nth, _) {
            if (nth == at) controller.abort(reason);
          };
          inListing(0, <Object>[]);
          var listedWhenGivenUp = '';
          final results = await Future.wait<Object?>([
            wrapWalking('a'),
            wrapWalking(
              'b',
              controller.signal,
            ).then<Object?>((v) => v).catchError((Object e) {
              listedWhenGivenUp = listed;
              return e;
            }),
            wrapWalking('c'),
          ]);
          final givenUp = results[1];
          expect(givenUp, reason);
          expect(listedWhenGivenUp.length, lessThan(3));
          expect(listed, 'aaaccc');
        },
      );
    }

    test(
      'goes on to the next when the wrap that walks is aborted, and when it throws',
      () async {
        final controller = AbortController();
        inListing = (nth, _) {
          if (nth == 2) controller.abort(Exception('stopped'));
        };
        Future<String> status(Future<Object?> f) =>
            f.then((_) => 'fulfilled', onError: (_) => 'rejected');
        final outcomes = await Future.wait([
          status(wrapWalking('a', controller.signal)),
          // Neither a path nor a marked one.
          // SandboxManager.wrapWithSandbox('true', undefined, {
          //   filesystem: { denyRead: [{} as never], allowWrite: [], denyWrite: [] },
          // }),
          status(wrapWalking('b')),
        ]);
        expect(outcomes, ['rejected', 'rejected', 'fulfilled']);
        expect(listed, 'aabbb');
      },
      skip: 'FilesystemPathEntry is sealed: an invalid entry cannot be built',
    );

    // What the host does in the second listing of `a`, with a wrap by the
    // configuration waiting. That one has read nothing yet, so it walks `b` once;
    // the wrap that was walking starts over, behind it.
    for (final (_what, disturb, holds, lacks)
        in <(String, void Function(), String, String)>[
          (
            'the configuration installed',
            () {
              writeFileSync(join(root, 'b', 'key.pem'), '');
              SandboxManager.updateConfig(
                configured(['b/**/.env', 'b/**/*.pem'], []),
              );
            },
            'b/key.pem',
            'c/from',
          ),
          (
            'the working directory the host moved to',
            () => Directory.current = join(root, 'c', 'to'),
            'c/to',
            'c/from',
          ),
        ]) {
      test('goes by $_what while it waited', () async {
        inListing = (nth, _) {
          if (nth == 2) disturb();
        };
        final results = await Future.wait<String>([
          wrapWalking('a'),
          SandboxManager.wrapWithSandbox('true'),
        ]);
        final waited = results[1];
        expect(listed, 'aabbbaaa');
        expect(waited, contains(join(root, holds)));
        expect(waited, isNot(contains(join(root, lacks))));
        expect(waited, await SandboxManager.wrapWithSandbox('true'));
      });
    }

    test('keeps the order through a reset()', () async {
      Future<void>? reset;
      inListing = (nth, _) {
        if (nth == 2) reset = SandboxManager.reset();
      };
      // Either may find the network bridge gone, as any wrap during a reset().
      await Future.wait<Object?>([
        wrapWalking('a').then<Object?>((v) => v, onError: (_) => null),
        wrapWalking('b').then<Object?>((v) => v, onError: (_) => null),
      ]);
      await reset;
      expect(listed, 'aaabbb');
    });

    test(
      'has walked, and let go of what it listed, before the mandatory denies are looked for',
      () async {
        // Stands in for ripgrep: says that it runs, and goes on until told.
        final scans = join(root, 'scans');
        final enough = join(root, 'enough');
        final slowScan = join(root, 'slow-scan');
        writeFileSync(
          slowScan,
          '#!/bin/sh\necho ran >> $scans\nfor i in \$(seq 300); do [ -e $enough ] && exit; sleep 0.01; done\n',
          {'mode': 0x1ED},
        );
        writeFileSync(scans, '');
        SandboxManager.updateConfig(
          _config(
            denyRead: [],
            ripgrep: RipgrepConfig(command: slowScan),
          ),
        );
        // final listings: WeakRef<object>[] = []
        // inListing = (_, entries) => listings.push(new WeakRef(entries))

        var wrapped = 0;
        final wrapping = Future.wait(
          ['a', 'b'].map((tree) => wrapWalking(tree).then((_) => wrapped++)),
        );
        try {
          while (fs.readFileSync(scans, 'utf8') != 'ran\nran\n') {
            await Future<void>.delayed(const Duration(milliseconds: 5));
          }
          // The second has walked while the first was scanning.
          expect(wrapped, 0);
          // readdirSpy.mockClear() // It keeps what each call returned.
          // Bun.gc(true)
          // Not none: a collector that reads the stack can take a stale word for a
          // reference. Held by the wraps, it would be all six.
          // expect(listings.filter(l => l.deref() !== undefined).length).toBeLessThan(
          //   6,
          // )
        } finally {
          writeFileSync(enough, '');
          await wrapping;
        }
      },
      skip: 'Dart has no WeakRef or forced collection (Bun.gc)',
    );
  }, skip: isLinux ? null : 'requires Linux');

  // ============================================================================
  // Tests for getLinuxGlobPatternWarnings
  // ============================================================================

  group('getLinuxGlobPatternWarnings after fix', () {
    test(
      'should NOT warn about denyRead globs on Linux (they are now expanded)',
      () async {
        await SandboxManager.reset();
        await SandboxManager.initialize(
          _config(denyRead: ['/tmp/test/*.env'], allowWrite: ['/tmp']),
        );

        final warnings = SandboxManager.getLinuxGlobPatternWarnings();

        // denyRead globs should no longer produce warnings since they are expanded
        expect(warnings, isNot(contains('/tmp/test/*.env')));
        expect(warnings.length, 0);

        await SandboxManager.reset();
      },
    );

    test(
      'should still warn about allowWrite and denyWrite globs on Linux',
      () async {
        await SandboxManager.reset();
        await SandboxManager.initialize(
          _config(
            denyRead: [],
            allowWrite: ['/tmp/test/*.log'],
            denyWrite: ['/tmp/test/secret_*'],
          ),
        );

        final warnings = SandboxManager.getLinuxGlobPatternWarnings();

        // allowWrite and denyWrite globs should still produce warnings
        expect(warnings, contains('/tmp/test/*.log'));
        expect(warnings, contains('/tmp/test/secret_*'));

        await SandboxManager.reset();
      },
    );

    test(
      'warns about a read pattern with no literal directory to start from',
      () async {
        // Expanded, such a pattern would have to start listing at '/', so it is
        // skipped and the entry it came from is silently unenforced. That is the
        // one read glob shape a user has to be told about.
        await SandboxManager.reset();
        await SandboxManager.initialize(
          _config(
            denyRead: ['/**/*.pem', '/opt*/keys/**', '/tmp/test/*.env'],
            allowRead: ['/et*/ssl'],
            allowWrite: ['/tmp'],
          ),
        );

        final warnings = SandboxManager.getLinuxGlobPatternWarnings();

        expect(
          warnings..sort(),
          ['/**/*.pem', '/et*/ssl', '/opt*/keys/**']..sort(),
        );

        await SandboxManager.reset();
      },
    );

    Future<ISandboxManager> initialized(
      FilesystemConfig filesystem, [
      CredentialsConfig? credentials,
    ]) async {
      await SandboxManager.reset();
      await SandboxManager.initialize(
        SandboxRuntimeConfig(
          network: const NetworkConfig(allowedDomains: [], deniedDomains: []),
          filesystem: filesystem,
          credentials: credentials,
        ),
      );
      return SandboxManager;
    }

    test(
      'warns about such a pattern as the path of a credential file deny',
      () async {
        // It joins the read denies and is skipped like one of them.
        final SandboxManager = await initialized(
          FilesystemConfig(
            denyRead: _entries(['/**/.netrc']),
            allowWrite: _entries(['/tmp/test/*.log']),
            denyWrite: [],
          ),
          const CredentialsConfig(
            files: [
              CredentialFileConfig(path: '/**/.netrc', mode: 'deny'),
              CredentialFileConfig(path: '/*/token', mode: 'deny'),
              CredentialFileConfig(path: '/tmp/test/*.key', mode: 'deny'),
              // Always the name of one file.
              CredentialFileConfig(path: '/*/masked', mode: 'mask'),
            ],
          ),
        );

        expect(SandboxManager.getLinuxGlobPatternWarnings(), [
          '/tmp/test/*.log',
          '/**/.netrc',
          '/*/token',
        ]);

        await SandboxManager.reset();
      },
    );

    for (final list in ['denyRead', 'allowRead']) {
      test('tells such a pattern from every other $list entry', () async {
        final skipped = ['/**/.ssh/**', '/*/x', '/*', '/*/**', '/ho*/x'];
        final applied = <FilesystemPathEntry>[
          const FilesystemPathSpelling(
            '**/.ssh/**',
          ), // starts at the working directory
          const FilesystemPathSpelling('~/**/.env'),
          const FilesystemPathSpelling('/home/**/x'),
          const FilesystemPathSpelling('/home/x'),
          const FilesystemPathSpelling(
            '/**',
          ), // `/`, once the trailing `/**` is dropped
          const FilesystemPathLiteral('/**/.ssh/**'),
        ];
        final entries = [...applied, ..._entries(skipped)];
        final SandboxManager = await initialized(
          FilesystemConfig(
            denyRead: list == 'denyRead' ? entries : [],
            allowRead: list == 'allowRead' ? entries : null,
            allowWrite: [],
            denyWrite: [],
          ),
        );

        expect(SandboxManager.getLinuxGlobPatternWarnings(), skipped);

        await SandboxManager.reset();
      });
    }
  }, skip: isLinux ? null : 'requires Linux');

  // ============================================================================
  // Integration test: denyRead with glob patterns on Linux via sandbox
  // ============================================================================

  group('denyRead with glob patterns - Linux integration', () {
    final RAW_BASE_DIR = join(
      tmpdir(),
      'glob-deny-integ-${DateTime.now().millisecondsSinceEpoch}',
    );
    final RAW_TEST_DIR = join(RAW_BASE_DIR, 'testdir');
    late String TEST_DIR;

    setUpAll(() {
      mkdirSync(RAW_TEST_DIR, {'recursive': true});
      writeFileSync(join(RAW_TEST_DIR, 'secret.env'), 'SECRET_DATA');
      writeFileSync(join(RAW_TEST_DIR, 'token.env'), 'TOKEN_DATA');
      writeFileSync(join(RAW_TEST_DIR, 'readme.txt'), 'PUBLIC_DATA');
      TEST_DIR = realPath(RAW_TEST_DIR);
    });

    tearDownAll(() {
      if (existsSync(RAW_BASE_DIR)) {
        rmSync(RAW_BASE_DIR, {'recursive': true, 'force': true});
      }
    });

    test(
      'should block reading files matching *.env glob pattern via sandbox',
      () async {
        await SandboxManager.reset();
        await SandboxManager.initialize(
          _config(
            denyRead: [join(RAW_TEST_DIR, '*.env')],
            allowWrite: ['/tmp'],
          ),
        );

        // Try reading a .env file - should fail
        final command = await SandboxManager.wrapWithSandbox(
          'cat ${join(TEST_DIR, 'secret.env')}',
        );

        final result = Process.runSync('/bin/sh', ['-c', command]);

        // The file should be blocked (bound to /dev/null, so empty output or error)
        expect(result.stdout, isNot(contains('SECRET_DATA')));

        await SandboxManager.reset();
      },
    );

    test(
      'should allow reading files NOT matching glob pattern via sandbox',
      () async {
        await SandboxManager.reset();
        await SandboxManager.initialize(
          _config(
            denyRead: [join(RAW_TEST_DIR, '*.env')],
            allowWrite: ['/tmp'],
          ),
        );

        // Try reading a .txt file - should succeed
        final command = await SandboxManager.wrapWithSandbox(
          'cat ${join(TEST_DIR, 'readme.txt')}',
        );

        final result = Process.runSync('/bin/sh', ['-c', command]);

        expect(result.exitCode, 0);
        expect(result.stdout, contains('PUBLIC_DATA'));

        await SandboxManager.reset();
      },
    );

    test('should block reading with literal path (regression test)', () async {
      await SandboxManager.reset();
      await SandboxManager.initialize(
        _config(
          denyRead: [join(RAW_TEST_DIR, 'secret.env')],
          allowWrite: ['/tmp'],
        ),
      );

      final command = await SandboxManager.wrapWithSandbox(
        'cat ${join(TEST_DIR, 'secret.env')}',
      );

      final result = Process.runSync('/bin/sh', ['-c', command]);

      // Should be blocked
      expect(result.stdout, isNot(contains('SECRET_DATA')));

      await SandboxManager.reset();
    });

    test('should block reading with ** recursive glob via sandbox', () async {
      // Create a nested file
      mkdirSync(join(RAW_TEST_DIR, 'nested'), {'recursive': true});
      writeFileSync(join(RAW_TEST_DIR, 'nested', 'deep.env'), 'DEEP_SECRET');
      final nestedPath = realPath(join(RAW_TEST_DIR, 'nested', 'deep.env'));

      await SandboxManager.reset();
      await SandboxManager.initialize(
        _config(
          denyRead: [join(RAW_TEST_DIR, '**/*.env')],
          allowWrite: ['/tmp'],
        ),
      );

      // Try reading nested .env file
      final command = await SandboxManager.wrapWithSandbox('cat $nestedPath');

      final result = Process.runSync('/bin/sh', ['-c', command]);

      expect(result.stdout, isNot(contains('DEEP_SECRET')));

      await SandboxManager.reset();
    });
  }, skip: isLinux ? null : 'requires Linux');

  // ============================================================================
  // Tests for wrapWithSandbox with glob denyRead via customConfig
  // ============================================================================

  group('wrapWithSandbox with glob denyRead customConfig', () {
    final RAW_BASE_DIR = join(
      tmpdir(),
      'wrap-sandbox-glob-test-${DateTime.now().millisecondsSinceEpoch}',
    );
    final RAW_TEST_DIR = join(RAW_BASE_DIR, 'testdir');
    late String TEST_DIR;

    setUpAll(() {
      mkdirSync(RAW_TEST_DIR, {'recursive': true});
      writeFileSync(join(RAW_TEST_DIR, 'secret.env'), 'CUSTOM_SECRET');
      writeFileSync(join(RAW_TEST_DIR, 'readme.txt'), 'CUSTOM_PUBLIC');
      TEST_DIR = realPath(RAW_TEST_DIR);
    });

    tearDownAll(() {
      if (existsSync(RAW_BASE_DIR)) {
        rmSync(RAW_BASE_DIR, {'recursive': true, 'force': true});
      }
    });

    test('should expand glob denyRead in customConfig on Linux', () async {
      await SandboxManager.reset();
      await SandboxManager.initialize(
        _config(denyRead: [], allowWrite: ['/tmp']),
      );

      // Use customConfig with glob denyRead
      final command = await SandboxManager.wrapWithSandbox(
        'cat ${join(TEST_DIR, 'secret.env')}',
        null,
        PartialSandboxRuntimeConfig(
          filesystem: _config(
            denyRead: [join(RAW_TEST_DIR, '*.env')],
            allowWrite: ['/tmp'],
          ).filesystem,
        ),
      );

      final result = Process.runSync('/bin/sh', ['-c', command]);

      // Should be blocked
      expect(result.stdout, isNot(contains('CUSTOM_SECRET')));

      await SandboxManager.reset();
    });
  }, skip: isLinux ? null : 'requires Linux');
}

// Dart: GlobWalk has no ==, so toEqual on one compares these fields.
Object _plain(GlobWalk w) => [
  w.baseLocation,
  w.matches,
  w.directoryMatches,
  w.symlinks.toList()..sort(),
  w.uninspectableLinks.toList()..sort(),
  w.unlisted,
  (w.realOf.entries.map((e) => '${e.key}\u0000${e.value}').toList()..sort()),
];

// Dart: the config literals upstream writes inline, with string entries.
List<FilesystemPathEntry> _entries(Iterable<String> paths) => [
  for (final p in paths) FilesystemPathSpelling(p),
];

SandboxRuntimeConfig _config({
  required List<String> denyRead,
  List<String>? allowRead,
  List<String> allowWrite = const [],
  List<String> denyWrite = const [],
  bool? allowGitConfig,
  RipgrepConfig? ripgrep,
}) => SandboxRuntimeConfig(
  network: const NetworkConfig(allowedDomains: [], deniedDomains: []),
  filesystem: FilesystemConfig(
    denyRead: _entries(denyRead),
    allowRead: allowRead == null ? null : _entries(allowRead),
    allowWrite: _entries(allowWrite),
    denyWrite: _entries(denyWrite),
    allowGitConfig: allowGitConfig,
  ),
  ripgrep: ripgrep,
);

// Dart: no fs.symlinkSync in the shim.
void symlinkSync(String target, String path) => Link(path).createSync(target);
