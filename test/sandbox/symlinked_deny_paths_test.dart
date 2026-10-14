// Ported from sandbox-runtime test/sandbox/symlinked-deny-paths.test.ts @ 24eb39e.
// ignore_for_file: non_constant_identifier_names, slash_for_doc_comments
import 'dart:io';

import 'package:path/path.dart' as p;
import 'package:test/test.dart';

import 'package:sandbox_runtime/src/node/child_process.dart'
    show SpawnSyncResult, spawnSync;
import 'package:sandbox_runtime/src/node/fs.dart' as fs;
import 'package:sandbox_runtime/src/sandbox/linux_sandbox_utils.dart';
import 'package:sandbox_runtime/src/sandbox/sandbox_schemas.dart';

import '../helpers/bwrap_argv.dart';
import '../helpers/bwrap_namespace.dart';
import '../helpers/platform.dart';

String join(String a, [String? b, String? c, String? d]) =>
    p.joinAll([a, ?b, ?c, ?d]);

bool existsSync(String path) =>
    FileSystemEntity.typeSync(path) != FileSystemEntityType.notFound;

/**
 * The root's symlinks into /usr (/bin, /lib, /sbin on a usr-merged system),
 * listed here rather than inside a test: a `describe.if` body runs on every
 * platform, and a root symlink may dangle (macOS runners have one). An empty
 * list means the host is not usr-merged, and the case below has nothing to
 * tell apart.
 */
final USR_MERGED_ROOT_LINKS = fs
    .readdirSync('/', withFileTypes: true)
    .where((entry) => entry.isSymbolicLink())
    .expand((entry) {
      try {
        return [fs.realpathSync('/${entry.name}')];
      } catch (_) {
        return <String>[];
      }
    })
    .where((target) => target.startsWith('/usr/'))
    .toList();

void main() {
  /**
   * Regression tests for symlinked deny paths (resolve-before-mask).
   *
   * In the common dotfiles setup, .claude (or the parent of .mcp.json) is a
   * symlink to a real directory. Deny paths crossing such a symlink used to be
   * masked with `--ro-bind /dev/null <symlink>`, which bwrap rejects at
   * startup ("Is a directory" for relative link targets, ENOENT for absolute
   * ones) — so every sandboxed command failed. Deny paths must instead be
   * canonicalized through symlinks and the deny applied to the resolved
   * target, which is the inode writes through the symlink actually reach.
   */
  group('Symlinked deny paths (resolve-before-mask)', () {
    // realpathSync so exact-string assertions hold even when tmpdir itself
    // contains symlinks.
    late String BASE;
    late String AREA; // allowed write area
    late String PROJ; // project dir containing the symlinks
    late String DOTFILES; // real directory the symlinks point into

    final hasBwrap = isLinux ? bwrapCanNamespace() : false;

    setUp(() {
      BASE = Directory.systemTemp
          .createTempSync('symlinked-deny-')
          .resolveSymbolicLinksSync();
      AREA = join(BASE, 'area');
      PROJ = join(AREA, 'proj');
      DOTFILES = join(AREA, 'dotfiles');
      Directory(
        join(DOTFILES, 'claude', 'commands'),
      ).createSync(recursive: true);
      Directory(join(DOTFILES, 'claude', 'agents')).createSync(recursive: true);
      Directory(PROJ).createSync(recursive: true);
    });

    tearDown(() {
      cleanupBwrapMountPoints(force: true);
      final directory = Directory(BASE);
      if (directory.existsSync()) directory.deleteSync(recursive: true);
    });

    Future<String> wrap(
      List<String> denyPaths, [
      List<String> readDenyPaths = const [],
    ]) async {
      return wrapCommandWithSandboxLinux(
        LinuxSandboxParams(
          command: 'echo hello',
          needsNetworkRestriction: false,
          readConfig: FsReadRestrictionConfig(denyOnly: readDenyPaths),
          writeConfig: FsWriteRestrictionConfig(
            allowOnly: [AREA],
            denyWithinAllow: denyPaths,
          ),
        ),
      );
    }

    test(
      'denies the resolved target for a .claude directory symlink with a relative target',
      () async {
        final claudeLink = join(PROJ, '.claude');
        Link(claudeLink).createSync(join('..', 'dotfiles', 'claude'));

        final result = await wrap([join(PROJ, '.claude', 'commands')]);
        final resolved = join(DOTFILES, 'claude', 'commands');

        // No /dev/null bind onto the raw symlink path (bwrap aborts on those).
        expect(result, isNot(contains('--ro-bind /dev/null $claudeLink')));
        // The resolved target is write-denied instead.
        expect(result, contains('--ro-bind $resolved $resolved'));
      },
    );

    test(
      'denies the resolved target for a .claude directory symlink with an absolute target',
      () async {
        final claudeLink = join(PROJ, '.claude');
        Link(claudeLink).createSync(join(DOTFILES, 'claude'));

        final result = await wrap([join(PROJ, '.claude', 'commands')]);
        final resolved = join(DOTFILES, 'claude', 'commands');

        expect(result, isNot(contains('--ro-bind /dev/null $claudeLink')));
        expect(result, contains('--ro-bind $resolved $resolved'));
      },
    );

    test(
      'blocks creation of .mcp.json at the resolved location when its parent is a symlink',
      () async {
        // proj2 is a symlink to a real directory; .mcp.json does not exist yet.
        final realProj = join(AREA, 'real-proj');
        Directory(realProj).createSync();
        final projLink = join(AREA, 'proj2');
        Link(projLink).createSync(realProj);

        final result = await wrap([join(projLink, '.mcp.json')]);

        // The creation-blocking mask must land at the resolved parent, not the
        // raw symlinked path.
        expect(
          result,
          isNot(contains('/dev/null ${join(projLink, '.mcp.json')}')),
        );
        expect(
          result,
          contains('--ro-bind /dev/null ${join(realProj, '.mcp.json')}'),
        );
      },
    );

    test(
      'follows a dangling symlink so the deny lands where a write would create the file',
      () async {
        // .mcp.json -> <AREA>/nowhere.json (target does not exist). A write
        // through the link would create the target, so that is what gets masked.
        final danglingLink = join(PROJ, '.mcp.json');
        final linkTarget = join(AREA, 'nowhere.json');
        Link(danglingLink).createSync(linkTarget);

        final result = await wrap([danglingLink]);

        expect(result, isNot(contains('/dev/null $danglingLink')));
        expect(result, contains('--ro-bind /dev/null $linkTarget'));
      },
    );

    test(
      'fails closed on a symlink cycle rather than dropping the deny',
      () async {
        // An unresolvable deny path must not silently disappear: masking the
        // symlink makes bwrap refuse to start, rather than sandboxing the
        // command with the path unprotected.
        final a = join(PROJ, 'cycle-a');
        final b = join(PROJ, 'cycle-b');
        Link(b).createSync(a);
        Link(a).createSync(b);

        final result = await wrap([join(a, '.mcp.json')]);

        expect(result, contains('--ro-bind /dev/null $a'));
      },
    );

    test(
      'emits the symlink mask only once for several denies sharing a cyclic ancestor',
      () async {
        // Two --ro-bind /dev/null onto the same dest make bwrap's ensure_file()
        // fall through to creat() on a read-only mount.
        final claudeLink = join(PROJ, '.claude');
        final other = join(PROJ, '.claude-x');
        Link(claudeLink).createSync(other);
        Link(other).createSync(claudeLink);

        final result = await wrap([
          join(claudeLink, 'commands'),
          join(claudeLink, 'agents'),
        ]);

        final masks =
            result.split('--ro-bind /dev/null $claudeLink').length - 1;
        expect(masks, 1);
      },
    );

    test(
      'does not re-expose a read-denied directory reached through a symlink',
      () async {
        // denyRead names the symlinked dir; its tmpfs lands on the link's
        // target (bwrap refuses a symlink as a mount destination), while the
        // denyWrite dest is canonicalized. If the two were compared by the raw
        // spelling the denyWrite --ro-bind would land on top of the tmpfs and
        // re-expose the real, read-denied contents.
        final claudeLink = join(PROJ, '.claude');
        Link(claudeLink).createSync(join('..', 'dotfiles', 'claude'));

        final result = await wrap([join(claudeLink, 'commands')], [claudeLink]);
        final resolved = join(DOTFILES, 'claude', 'commands');

        expect(
          countMounts(result, ['--tmpfs', join(DOTFILES, 'claude')]),
          greaterThan(0),
        );
        expect(countMounts(result, ['--tmpfs', claudeLink]), 0);
        expect(result, isNot(contains('--ro-bind $resolved $resolved')));
      },
    );

    test(
      "does not deny the root's symlinks in their own right under a denyRead of /",
      () async {
        // A '/' deny stands for the root's children, minus the ones an allowRead
        // entry covers: /usr and /etc are named, and /bin, /lib and /sbin are
        // links into /usr, so all five are skipped. Denied as entries of their
        // own the links would be mounted where they lead and empty the very
        // directories that allowRead names.
        // allowAllUnixSockets keeps the apply-seccomp helper out of the command:
        // where it has been built it lives in the checkout, which the '/' deny
        // hides, and the shell would fail to exec it (allow-read.test.ts does the
        // same for its '/' denies).
        final wrapped = await wrapCommandWithSandboxLinux(
          LinuxSandboxParams(
            command: 'echo STARTED',
            needsNetworkRestriction: false,
            readConfig: FsReadRestrictionConfig(
              denyOnly: ['/'],
              allowWithinDeny: ['/usr', '/etc'],
            ),
            writeConfig: FsWriteRestrictionConfig(
              allowOnly: [],
              denyWithinAllow: [],
            ),
            allowAllUnixSockets: true,
          ),
        );

        expect(countMounts(wrapped, ['--tmpfs', '/usr']), 0);
        expect(countMounts(wrapped, ['--tmpfs', '/etc']), 0);
        for (final target in USR_MERGED_ROOT_LINKS) {
          expect(countMounts(wrapped, ['--tmpfs', target]), 0);
        }
        if (hasBwrap) {
          final run = spawnSync(wrapped, [], {
            'shell': true,
            'encoding': 'utf8',
            'timeout': 10000,
          });
          // The whole outcome, so a failure says why the sandbox did not start.
          expect(
            {'status': run.status, 'stdout': run.stdout, 'stderr': run.stderr},
            {'status': 0, 'stdout': 'STARTED\n', 'stderr': ''},
          );
        }
      },
      skip: USR_MERGED_ROOT_LINKS.isEmpty ? 'not usr-merged' : false,
      // Dart: fs.readdirSync('/', withFileTypes: false) throws UnimplementedError (linux_sandbox_utils.dart:2284)
      tags: ['pending'],
    );

    test(
      'resolves the mandatory .claude deny paths when cwd/.claude is a symlink',
      () async {
        final claudeLink = join(PROJ, '.claude');
        Link(claudeLink).createSync(join('..', 'dotfiles', 'claude'));

        final originalCwd = Directory.current;
        Directory.current = PROJ;
        try {
          // No explicit denyWithinAllow: the mandatory deny paths (cwd-relative
          // .claude/commands, .claude/agents, .mcp.json, ...) trigger the bug.
          final result = await wrap([]);

          expect(result, isNot(contains('--ro-bind /dev/null $claudeLink')));
          for (final sub in ['commands', 'agents']) {
            final resolved = join(DOTFILES, 'claude', sub);
            expect(result, contains('--ro-bind $resolved $resolved'));
          }
        } finally {
          Directory.current = originalCwd;
        }
      },
    );

    test(
      'e2e: sandbox starts with a symlinked .claude and still denies writes through it',
      () async {
        final claudeLink = join(PROJ, '.claude');
        Link(claudeLink).createSync(join('..', 'dotfiles', 'claude'));

        Future<SpawnSyncResult> run(String command) async {
          final wrapped = await wrapCommandWithSandboxLinux(
            LinuxSandboxParams(
              command: command,
              needsNetworkRestriction: false,
              readConfig: FsReadRestrictionConfig(denyOnly: []),
              writeConfig: FsWriteRestrictionConfig(
                allowOnly: [AREA],
                denyWithinAllow: [
                  join(PROJ, '.claude', 'commands'),
                  join(PROJ, '.claude', 'agents'),
                ],
              ),
            ),
          );
          return spawnSync(wrapped, [], {
            'shell': true,
            'encoding': 'utf8',
            'timeout': 10000,
            'cwd': PROJ,
          });
        }

        // Before the fix bwrap aborted at startup for every command.
        final ok = await run('echo e2e-ok');
        expect(ok.stderr, isNot(contains("Can't create file")));
        expect(ok.status, 0);
        expect(ok.stdout, contains('e2e-ok'));

        // Writes through the symlinked path hit the denied resolved target.
        final denied = await run(
          "sh -c 'echo evil > ${join(claudeLink, 'commands', 'evil.md')}'",
        );
        expect(denied.status, isNot(0));
        expect(
          existsSync(join(DOTFILES, 'claude', 'commands', 'evil.md')),
          false,
        );

        // The rest of the allowed area stays writable.
        final allowed = await run("sh -c 'echo ok > ${join(PROJ, 'ok.txt')}'");
        expect(allowed.status, 0);
        expect(existsSync(join(PROJ, 'ok.txt')), true);
      },
      skip: hasBwrap ? false : 'bwrap cannot namespace here',
      // Dart: on the VM apply-seccomp fails to write /proc/self/setgroups in a nested userns (environment)
      tags: ['pending'],
    );

    test(
      'e2e: a cyclic .claude stops the sandbox instead of leaving the path writable',
      () async {
        final claudeLink = join(PROJ, '.claude');
        final other = join(PROJ, '.claude-x');
        Link(claudeLink).createSync(other);
        Link(other).createSync(claudeLink);

        final wrapped = await wrapCommandWithSandboxLinux(
          LinuxSandboxParams(
            command:
                'rm -f .claude && mkdir -p .claude/commands && echo planted > ${join(PROJ, '.claude', 'commands', 'planted.md')}',
            needsNetworkRestriction: false,
            readConfig: FsReadRestrictionConfig(denyOnly: []),
            writeConfig: FsWriteRestrictionConfig(
              allowOnly: [AREA],
              denyWithinAllow: [join(PROJ, '.claude', 'commands')],
            ),
          ),
        );
        final result = spawnSync(wrapped, [], {
          'shell': true,
          'encoding': 'utf8',
          'timeout': 10000,
          'cwd': PROJ,
        });

        expect(result.status, isNot(0));
        expect(
          existsSync(join(PROJ, '.claude', 'commands', 'planted.md')),
          false,
        );
      },
      skip: hasBwrap ? false : 'bwrap cannot namespace here',
    );
  }, skip: isLinux ? false : 'not Linux');
}
