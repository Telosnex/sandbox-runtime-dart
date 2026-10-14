// Ported from sandbox-runtime test/sandbox/linux-ancestor-pin-errno.test.ts @ 24eb39e.
import 'dart:io';

import 'package:path/path.dart' as p;
import 'package:test/test.dart';

import 'package:sandbox_runtime/src/node/errno.dart' show NodeError;
import 'package:sandbox_runtime/src/node/fs.dart' as fs;
import 'package:sandbox_runtime/src/sandbox/linux_sandbox_utils.dart';
import 'package:sandbox_runtime/src/sandbox/sandbox_schemas.dart';
import 'package:sandbox_runtime/src/utils/which.dart' as which;

import '../helpers/platform.dart';

String join(String a, [String? b, String? c, String? d, String? e]) =>
    p.joinAll([a, ?b, ?c, ?d, ?e]);

void main() {
  // What is emitted for paths that are missing or cannot be inspected: a missing
  // directory gets no pin, and one that exists but cannot be stat'ed is
  // protected anyway. EACCES is injected through an fs spy (a root container
  // sees no real one). Nothing here executes bwrap.
  group('Linux sandbox — pins and read denies on paths that cannot be inspected', () {
    final created = <String>[];
    final spies = <void Function()>[];
    tearDown(() {
      for (final restore in spies.toList().reversed) {
        restore();
      }
      spies.clear();
      cleanupBwrapMountPoints(force: true);
      for (final dir in created.toList()) {
        final directory = Directory(dir);
        if (directory.existsSync()) directory.deleteSync(recursive: true);
      }
      created.clear();
    });

    String makeTree() {
      // proj/a/b/.git/config: pins expected for a, a/b, a/b/.git
      final proj = Directory.systemTemp
          .createTempSync('pin-errno-')
          .resolveSymbolicLinksSync();
      created.add(proj);
      Directory(join(proj, 'a', 'b', '.git')).createSync(recursive: true);
      File(
        join(proj, 'a', 'b', '.git', 'config'),
      ).writeAsStringSync('[core]\n');
      return proj;
    }

    Future<String> wrap(
      String proj, {
      FsReadRestrictionConfig? readConfig,
      List<({String realPath, String fakePath})>? maskedFileBinds,
    }) async {
      return wrapCommandWithSandboxLinux(
        LinuxSandboxParams(
          command: 'true',
          needsNetworkRestriction: false,
          allowAllUnixSockets: true,
          writeConfig: FsWriteRestrictionConfig(
            allowOnly: [proj],
            denyWithinAllow: [join(proj, 'a', 'b', '.git', 'config')],
          ),
          readConfig: readConfig,
          maskedFileBinds: maskedFileBinds,
        ),
      );
    }

    /// Make statSync(p) throw EACCES where matches(p); returns the hit count.
    int Function() failStatWhere(bool Function(String p) matches) {
      final realStat = fs.statSync;
      var hits = 0;
      spies.add(() => fs.statSync = realStat);
      fs.statSync = (String p) {
        if (matches(p)) {
          hits++;
          throw NodeError('EACCES: permission denied', code: 'EACCES');
        }
        return realStat(p);
      };
      return () => hits;
    }

    test(
      'still pins a directory that exists but cannot be inspected',
      () async {
        final proj = makeTree();
        final uninspectable = join(proj, 'a', 'b');
        final statHits = failStatWhere((p) => p == uninspectable);

        final wrapped = await wrap(proj);

        expect(statHits(), greaterThan(0));
        for (final dir in [
          join(proj, 'a'),
          uninspectable,
          join(proj, 'a', 'b', '.git'),
        ]) {
          expect(wrapped, contains('--ro-bind $dir $dir'));
        }
      },
    );

    test(
      'hides the deepest inspectable directory above a denyRead path that cannot be inspected',
      () async {
        // chmod 000 on cfg/secrets by an earlier command: the key cannot be
        // stat'ed, but the next command can chmod it back and read it.
        final proj = makeTree();
        final secrets = join(proj, 'cfg', 'secrets');
        Directory(join(secrets, 'pub')).createSync(recursive: true);
        File(join(secrets, 'key')).writeAsStringSync('K');
        final statHits = failStatWhere((p) => p.startsWith('$secrets/'));

        final wrapped = await wrap(
          proj,
          readConfig: FsReadRestrictionConfig(
            denyOnly: [join(secrets, 'key')],
            allowWithinDeny: [join(secrets, 'pub')],
          ),
        );

        expect(statHits(), greaterThan(0));
        expect(wrapped, contains('--tmpfs $secrets '));
        // Nothing beneath the stand-in can be vouched for, so nothing returns.
        expect(wrapped, isNot(contains(join(secrets, 'pub'))));
        expect(wrapped, isNot(contains(join(secrets, 'key'))));
        final cfg = join(proj, 'cfg');
        expect(wrapped, contains('--ro-bind $cfg $cfg'));
      },
    );

    test(
      'leaves out the pin of a missing directory and pins the existing one above it',
      () async {
        // A credential mask is emitted whether or not its file exists, so its
        // ancestors are the one walk that can cross a missing directory.
        final proj = makeTree();
        final missing = join(proj, 'a', 'missing');
        final fakePath = join(proj, 'fake-token');
        File(fakePath).writeAsStringSync('FAKE\n');

        final wrapped = await wrap(
          proj,
          maskedFileBinds: [
            (realPath: join(missing, 'token'), fakePath: fakePath),
          ],
        );

        expect(wrapped, isNot(contains('--ro-bind $missing $missing')));
        final above = join(proj, 'a');
        expect(wrapped, contains('--ro-bind $above $above'));
      },
    );

    test(
      'pins the ancestors of a FIFO denyRead entry (every non-directory is masked)',
      () async {
        final proj = makeTree();
        Directory(join(proj, 'secrets')).createSync();
        final fifoPath = join(proj, 'secrets', 'pipe.fifo');
        expect(Process.runSync('mkfifo', [fifoPath]).exitCode, 0);

        final wrapped = await wrap(
          proj,
          readConfig: FsReadRestrictionConfig(
            denyOnly: [fifoPath],
            allowWithinDeny: [],
          ),
        );

        final maskedDir = join(proj, 'secrets');
        expect(wrapped, contains('--ro-bind $maskedDir $maskedDir'));
        expect(wrapped, contains('--ro-bind /dev/null $fifoPath'));
      },
      skip: which.whichSync('mkfifo') != null ? false : 'mkfifo not found',
    );

    test('pins nothing for a denyRead file that does not exist', () async {
      // secrets exists, so only the missing file decides: an unmasked entry
      // must not pin its parent.
      final proj = makeTree();
      final parent = join(proj, 'secrets');
      Directory(parent).createSync();

      final wrapped = await wrap(
        proj,
        readConfig: FsReadRestrictionConfig(
          denyOnly: [join(parent, 'gone')],
          allowWithinDeny: [],
        ),
      );

      expect(wrapped, isNot(contains('--ro-bind $parent $parent')));
    });

    test(
      'mounts nothing for a denyRead path uninspectable all the way up to "/"',
      () async {
        // A dead network mount answers every ancestor with ENOTCONN/ESTALE/EIO,
        // so the stand-in walk reaches '/', where stat succeeds. '/' as the
        // stand-in means --tmpfs /, which wipes every mount before it and the
        // second pivot promotes: the command boots on an empty tree.
        final proj = makeTree();
        final statHits = failStatWhere(
          (p) => p == '/mnt' || p.startsWith('/mnt/'),
        );

        final wrapped = await wrap(
          proj,
          readConfig: FsReadRestrictionConfig(
            denyOnly: ['/mnt/share/secrets'],
            allowWithinDeny: [],
          ),
        );

        expect(statHits(), greaterThan(0));
        final argv = wrapped.split(RegExp(r'\s+'));
        expect(
          argv.asMap().entries.any(
            (e) =>
                e.value == '--tmpfs' &&
                e.key + 1 < argv.length &&
                argv[e.key + 1] == '/',
          ),
          false,
        );
      },
    );
  }, skip: isLinux ? false : 'not Linux');
}
