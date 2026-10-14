// Ported from sandbox-runtime test/sandbox/deny-order-independence.test.ts @ 24eb39e.
// ignore_for_file: constant_identifier_names, non_constant_identifier_names, slash_for_doc_comments
import 'package:path/path.dart' show join;
import 'package:sandbox_runtime/src/node/fs.dart'
    show
        chmodSync,
        mkdirSync,
        mkdtempSync,
        realpathSync,
        rmSync,
        symlinkSync,
        writeFileSync;
import 'package:sandbox_runtime/src/node/os.dart' show tmpdir;
import 'package:sandbox_runtime/src/node/process.dart' as process;
import 'package:sandbox_runtime/src/sandbox/linux_sandbox_utils.dart'
    show
        LinuxSandboxParams,
        cleanupBwrapMountPoints,
        wrapCommandWithSandboxLinux;
import 'package:sandbox_runtime/src/sandbox/sandbox_schemas.dart'
    show FsReadRestrictionConfig, FsWriteRestrictionConfig;
import 'package:test/test.dart';

import '../helpers/bwrap_argv.dart' show mountsOf;
import '../helpers/platform.dart' show isLinux;

/** The empty directory mounted over an absent deny path's first missing
 * component is made fresh per wrap, so its name says nothing about the plan. */
final EMPTY_MOUNT_SOURCE = RegExp(r'\S*claude-empty-[A-Za-z0-9]+');

/** A profile's mounts as a multiset, for the reason mountsOf gives. */
List<String> mountMultiset(String command) {
  return mountsOf(command)
      .map(
        (mount) => mount.replaceAll(EMPTY_MOUNT_SOURCE, '<empty mount source>'),
      )
      .toList()
    ..sort();
}

/**
 * A deny set protects the same paths whichever order the caller wrote it
 * down in, so a profile's mounts must be the same for a denyWithinAllow list
 * and for its reverse.
 *
 * The deny loop deduplicates entries on the path they resolve to, and skips
 * an existing deny path that a denied directory above it already re-binds
 * read-only. Were that skip to ask whether the entry IN HAND is reached
 * through a symlink, a destination named both directly and through a
 * symlink would be bound or not according to which spelling came first.
 * Nothing is writable either way: the covering directory's read-only bind
 * holds the whole subtree.
 */
void main() {
  group('Deny order independence', skip: isLinux ? null : 'not Linux', () {
    late String BASE;
    final savedCwd = process.cwd();

    setUp(() {
      // realpathSync so the deny paths the wrapper resolves are spelled the way
      // the fixture spells them, even where tmpdir is itself a symlink.
      BASE = realpathSync(mkdtempSync(join(tmpdir(), 'deny-order-')));
    });

    tearDown(() {
      process.chdir(savedCwd);
      cleanupBwrapMountPoints(force: true);
      rmSync(BASE, {'recursive': true, 'force': true});
    });

    /** The mounts one configuration produces with its deny list as given and
     * reversed. The tree is rebuilt before each pass: a wrap leaves mount
     * points on the host for absent deny paths, which the next must not see. */
    Future<({List<String> forward, List<String> reversed})> bothOrders(
      void Function() tree,
      List<String> allowOnly,
      List<String> denyWithinAllow,
    ) async {
      Future<List<String>> pass(List<String> denies) async {
        rmSync(BASE, {'recursive': true, 'force': true});
        mkdirSync(BASE, {'recursive': true});
        tree();
        // Outside the allowed area, so the mandatory-deny scan adds no binds
        // of its own to reason about.
        process.chdir(BASE);
        final mounts = mountMultiset(
          await wrapCommandWithSandboxLinux(
            LinuxSandboxParams(
              command: 'true',
              needsNetworkRestriction: false,
              writeConfig: FsWriteRestrictionConfig(
                allowOnly: allowOnly,
                denyWithinAllow: denies,
              ),
            ),
          ),
        );
        process.chdir(savedCwd);
        cleanupBwrapMountPoints(force: true);
        return mounts;
      }

      return (
        forward: await pass(denyWithinAllow),
        reversed: await pass([...denyWithinAllow].reversed.toList()),
      );
    }

    test(
      'binds a file named both directly and through a symlink, either order',
      () async {
        final AREA = join(BASE, 'area');
        final FILE = join(AREA, 'settings.json');
        final LINK = join(AREA, 'link');
        final (:forward, :reversed) = await bothOrders(
          () {
            mkdirSync(AREA, {'recursive': true});
            writeFileSync(FILE, '{}\n');
            symlinkSync(FILE, LINK);
          },
          [AREA],
          // The deny on AREA is what covers FILE. Without it neither spelling is
          // skipped and both orders agree for free.
          [AREA, FILE, LINK],
        );
        expect(reversed, forward);
        // Both orders give the answer the deny set gives when only the symlinked
        // spelling is listed: the destination keeps its own bind.
        expect(forward, contains('--ro-bind $FILE $FILE'));
        expect(forward, contains('--ro-bind $AREA $AREA'));
      },
    );

    test(
      'binds a directory named through a chain that leaves the allowed area, either order',
      () async {
        final AREA = join(BASE, 'area');
        final HOOKS = join(AREA, 'repo', '.git', 'hooks');
        final OUTSIDE = join(BASE, 'outside');
        final (:forward, :reversed) = await bothOrders(
          () {
            mkdirSync(HOOKS, {'recursive': true});
            mkdirSync(OUTSIDE, {'recursive': true});
            // area/away -> outside, outside/to-hooks -> area/repo/.git/hooks: the
            // chain leaves the allowed area and comes back into it.
            symlinkSync(HOOKS, join(OUTSIDE, 'to-hooks'));
            symlinkSync(OUTSIDE, join(AREA, 'away'));
          },
          [AREA],
          [AREA, HOOKS, join(AREA, 'away', 'to-hooks')],
        );
        expect(reversed, forward);
        expect(forward, contains('--ro-bind $HOOKS $HOOKS'));
        expect(forward, contains('--ro-bind $AREA $AREA'));
      },
    );

    test(
      'leaves a deny set with no covering directory alone, either order',
      () async {
        final AREA = join(BASE, 'area');
        final FILE = join(AREA, 'settings.json');
        final LINK = join(AREA, 'link');
        final (:forward, :reversed) = await bothOrders(
          () {
            mkdirSync(AREA, {'recursive': true});
            writeFileSync(FILE, '{}\n');
            symlinkSync(FILE, LINK);
          },
          [AREA],
          [FILE, LINK],
        );
        expect(reversed, forward);
        expect(forward, contains('--ro-bind $FILE $FILE'));
      },
    );
  });

  /**
   * The same property over random trees, whose shapes are the ones the deny
   * loop branches on (see buildTree), with a random allow list, deny list and
   * read-deny list, and the working directory inside the tree.
   *
   * Bounded and seeded, so a failing tree replays: this range holds trees that
   * tell the two orders apart when the skip asks the entry in hand.
   */
  group(
    'Deny order independence over random trees',
    skip: isLinux ? null : 'not Linux',
    () {
      const FIRST_SEED = 800;
      const SEEDS = 120;

      late String ROOT;
      final savedCwd = process.cwd();

      setUp(() {
        ROOT = realpathSync(mkdtempSync(join(tmpdir(), 'deny-order-trees-')));
      });

      tearDown(() {
        process.chdir(savedCwd);
        cleanupBwrapMountPoints(force: true);
        rmSync(ROOT, {'recursive': true, 'force': true});
      });

      /** mulberry32, so a tree is a function of its seed alone. */
      double Function() rng(int seed) {
        // Dart: no Math.imul; the low 32 bits of the product, unsigned.
        int imul(int x, int y) => (x * y) & 0xffffffff;
        var a = seed & 0xffffffff;
        return () {
          a = (a + 0x6d2b79f5) & 0xffffffff;
          var t = imul(a ^ (a >> 15), 1 | a);
          t = ((t + imul(t ^ (t >> 7), 61 | t)) & 0xffffffff) ^ t;
          return ((t ^ (t >> 14)) & 0xffffffff) / 4294967296;
        };
      }

      const NAMES = [
        '.git',
        'hooks',
        'config',
        'config.worktree',
        'commondir',
        'modules',
        'worktrees',
        'src',
        'sub',
        'deep',
        'a',
        'b',
        '.env',
        '.bashrc',
        '.gitconfig',
        'link',
        'dangling',
        'loop',
        'stale',
        'file.txt',
      ];

      /** Rebuild ROOT from scratch for `seed`. A mkdir, write or symlink that
       * loses its name to something already there just leaves that entry out. */
      ({
        List<String> dirs,
        List<String> files,
        List<String> links,
        List<String> absent,
      })
      buildTree(int seed) {
        final r = rng(seed);
        T pick<T>(List<T> xs) => xs[(r() * xs.length).floor()];
        rmSync(ROOT, {'recursive': true, 'force': true});
        mkdirSync(ROOT, {'recursive': true});
        final dirs = <String>[ROOT];
        final files = <String>[];
        final links = <String>[];
        final absent = <String>[];

        final dirCount = 3 + (r() * 8).floor();
        for (var i = 0; i < dirCount; i++) {
          final dir = join(pick(dirs), pick(NAMES));
          try {
            mkdirSync(dir, {'recursive': true});
            dirs.add(dir);
          } catch (_) {
            // a file already sits there
          }
        }
        final fileCount = 3 + (r() * 8).floor();
        for (var i = 0; i < fileCount; i++) {
          final file = join(pick(dirs), pick(NAMES));
          try {
            writeFileSync(file, 'x');
            files.add(file);
          } catch (_) {
            // a directory already sits there
          }
        }

        // A git directory, sometimes with a commondir, sometimes named by a
        // worktree pointer file, sometimes with its hooks behind a link.
        final gitDir = join(pick(dirs), '.git');
        try {
          mkdirSync(join(gitDir, 'hooks'), {'recursive': true});
          writeFileSync(join(gitDir, 'config'), '[core]\n');
          writeFileSync(join(gitDir, 'HEAD'), 'ref: refs/heads/main\n');
          dirs.addAll([gitDir, join(gitDir, 'hooks')]);
          if (r() < 0.4) {
            writeFileSync(join(gitDir, 'commondir'), '../..\n');
            files.add(join(gitDir, 'commondir'));
          }
          if (r() < 0.4) {
            final pointerDir = join(ROOT, 'wt');
            mkdirSync(pointerDir, {'recursive': true});
            writeFileSync(join(pointerDir, '.git'), 'gitdir: $gitDir\n');
            dirs.add(pointerDir);
            files.add(join(pointerDir, '.git'));
          }
          if (r() < 0.4) {
            final real = join(ROOT, 'realhooks');
            mkdirSync(real, {'recursive': true});
            rmSync(join(gitDir, 'hooks'), {'recursive': true, 'force': true});
            symlinkSync(real, join(gitDir, 'hooks'));
            links.add(join(gitDir, 'hooks'));
            dirs.add(real);
          }
        } catch (_) {
          // something is already there
        }

        // Symlinks: to a directory, to a file, dangling, and a self cycle.
        final linkCount = 1 + (r() * 5).floor();
        for (var i = 0; i < linkCount; i++) {
          final link = join(pick(dirs), 'l$i');
          final kind = r();
          try {
            if (kind < 0.35) {
              symlinkSync(pick(dirs), link);
            } else if (kind < 0.6 && files.isNotEmpty) {
              symlinkSync(pick(files), link);
            } else if (kind < 0.85) {
              symlinkSync(join(ROOT, 'nowhere'), link);
            } else {
              symlinkSync(link, link);
            }
            links.add(link);
          } catch (_) {
            // name taken
          }
        }

        // Mount points an earlier sandbox would have left behind.
        final staleCount = (r() * 3).floor();
        for (var i = 0; i < staleCount; i++) {
          final stale = join(pick(dirs), '.stale$i');
          try {
            writeFileSync(stale, '');
            chmodSync(stale, 292);
            files.add(stale);
          } catch (_) {
            // name taken
          }
        }

        // Paths that do not exist: a leaf, and a leaf under an absent parent.
        for (var i = 0; i < 3; i++) {
          absent.add(join(pick(dirs), 'absent$i'));
          absent.add(join(pick(dirs), 'gone$i', 'leaf'));
        }
        return (dirs: dirs, files: files, links: links, absent: absent);
      }

      /** The configuration for `seed`, drawn from what its tree holds. */
      ({
        List<String> allowOnly,
        List<String> denyWithinAllow,
        FsReadRestrictionConfig? readConfig,
        bool allowGitConfig,
        bool allowAllUnixSockets,
      })
      configFor(
        int seed,
        ({
          List<String> dirs,
          List<String> files,
          List<String> links,
          List<String> absent,
        })
        tree,
      ) {
        final r = rng(seed ^ 0x5bf03635);
        T pick<T>(List<T> xs) => xs[(r() * xs.length).floor()];
        List<T> some<T>(List<T> xs, int count) {
          final out = <T>[];
          for (var i = 0; i < count && xs.isNotEmpty; i++) {
            out.add(pick(xs));
          }
          return out;
        }

        final all = [
          ...tree.dirs,
          ...tree.files,
          ...tree.links,
          ...tree.absent,
        ];
        final allowOnly = r() < 0.15
            ? [ROOT]
            : some(tree.dirs, 1 + (r() * 2).floor());
        final globs = ['/*.txt', '/**/*.env', '/[ab].*', '/?.txt', '/**/hooks'];
        final denyOnly = some(
          all,
          (r() * 3).floor(),
        ).map((p) => r() < 0.3 ? p + pick(globs) : p).toList();
        return (
          allowOnly: allowOnly,
          denyWithinAllow: some(
            all,
            (r() * 6).floor(),
          ).map((p) => r() < 0.15 ? '$p/' : p).toList(),
          readConfig: r() < 0.4
              ? null
              : FsReadRestrictionConfig(
                  denyOnly: denyOnly,
                  allowWithinDeny: some(tree.dirs, (r() * 2).floor()),
                ),
          allowGitConfig: r() < 0.25,
          allowAllUnixSockets: r() < 0.5,
        );
      }

      test('produces the same mounts for a deny list and its reverse', () async {
        /** Rebuilds the tree before each pass, as bothOrders does. Undefined for
           * a tree whose deny list has nothing to reorder. */
        Future<List<String>?> pass(int seed, bool reverse) async {
          final config = configFor(seed, buildTree(seed));
          if (config.denyWithinAllow.length < 2) return null;
          process.chdir(ROOT);
          final mounts = mountMultiset(
            await wrapCommandWithSandboxLinux(
              LinuxSandboxParams(
                command: 'true',
                needsNetworkRestriction: false,
                readConfig: config.readConfig,
                writeConfig: FsWriteRestrictionConfig(
                  allowOnly: config.allowOnly,
                  denyWithinAllow: reverse
                      ? [...config.denyWithinAllow].reversed.toList()
                      : config.denyWithinAllow,
                ),
                allowGitConfig: config.allowGitConfig,
                allowAllUnixSockets: config.allowAllUnixSockets,
              ),
            ),
          );
          process.chdir(savedCwd);
          cleanupBwrapMountPoints(force: true);
          return mounts;
        }

        final disagreed = <int>[];
        var compared = 0;
        for (var i = 0; i < SEEDS; i++) {
          final seed = FIRST_SEED + i;
          final forward = await pass(seed, false);
          if (forward == null) continue;
          final reversed = await pass(seed, true);
          if (reversed == null) continue;
          compared++;
          if (forward.join('\n') != reversed.join('\n')) disagreed.add(seed);
        }
        expect(disagreed, <int>[]);
        // A generator that stopped producing trees with two deny entries would
        // pass for free.
        expect(compared, greaterThan(SEEDS / 2));
      }, timeout: const Timeout(Duration(milliseconds: 300000)));
    },
  );
}
