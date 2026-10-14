// Ported from sandbox-runtime test/sandbox/deny-path-made-meanwhile.test.ts @ 24eb39e.
// ignore_for_file: constant_identifier_names, non_constant_identifier_names, slash_for_doc_comments
import 'package:path/path.dart' show join;
import 'package:sandbox_runtime/src/node/fs.dart' as fs;
import 'package:sandbox_runtime/src/node/fs.dart'
    show chmodSync, mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync;
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

import '../helpers/bwrap_argv.dart' show countMounts;
import '../helpers/platform.dart' show isLinux;

/**
 * An absent deny path is blocked by a mount point bubblewrap makes on the
 * host. Two processes wrapping in one project deny the same absent paths, so
 * one's bubblewrap can make that file between two looks of the other's wrap.
 */
void main() {
  group(
    'A deny path made while the wrap is looking',
    skip: isLinux ? null : 'not Linux',
    () {
      late String base;
      late String area;
      final savedCwd = process.cwd();

      setUp(() {
        cleanupBwrapMountPoints(force: true);
        base = realpathSync(mkdtempSync(join(tmpdir(), 'deny-meanwhile-')));
        area = join(base, 'area');
        mkdirSync(area);
        process.chdir(area);
      });

      tearDown(() {
        process.chdir(savedCwd);
        cleanupBwrapMountPoints(force: true);
        rmSync(base, {'recursive': true, 'force': true});
      });

      Future<String> wrap(String deny) => wrapCommandWithSandboxLinux(
        LinuxSandboxParams(
          command: 'true',
          needsNetworkRestriction: false,
          readConfig: FsReadRestrictionConfig(denyOnly: []),
          writeConfig: FsWriteRestrictionConfig(
            allowOnly: [area],
            denyWithinAllow: [deny],
          ),
        ),
      );

      test(
        'still binds over a path that was absent when asked and is a file a moment later',
        () async {
          final denied = join(area, 'denied.lock');
          final exists = fs.existsSync;
          var made = false;
          // What another sandbox's bubblewrap does: an empty read-only file.
          fs.existsSync = (String p) {
            final was = exists(p);
            if (p == denied && !made) {
              made = true;
              writeFileSync(denied, '');
              chmodSync(denied, 292);
            }
            return was;
          };
          late String wrapped;
          try {
            wrapped = await wrap(denied);
          } finally {
            fs.existsSync = exists;
          }

          expect(made, isTrue);
          expect(countMounts(wrapped, ['--ro-bind', '/dev/null', denied]), 1);
        },
      );

      test(
        'still leaves alone a path beneath a file, which can never be created',
        () async {
          writeFileSync(join(area, '.git'), 'gitdir: elsewhere\n');
          final denied = join(area, '.git', 'hooks');

          final wrapped = await wrap(denied);

          expect(wrapped, isNot(contains(denied)));
        },
      );
    },
  );
}
