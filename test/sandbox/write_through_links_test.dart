// Ported from sandbox-runtime test/sandbox/write-through-links.test.ts @ 24eb39e.
// ignore_for_file: constant_identifier_names, non_constant_identifier_names, slash_for_doc_comments

import 'package:path/path.dart' show join;
import 'package:sandbox_runtime/src/node/child_process.dart' show spawnSync;
import 'package:sandbox_runtime/src/node/fs.dart'
    show
        existsSync,
        mkdirSync,
        mkdtempSync,
        readFileSync,
        realpathSync,
        rmSync,
        symlinkSync,
        writeFileSync;
import 'package:sandbox_runtime/src/node/os.dart' show tmpdir;
import 'package:sandbox_runtime/src/sandbox/linux_sandbox_utils.dart'
    show LinuxSandboxParams, wrapCommandWithSandboxLinux;
import 'package:sandbox_runtime/src/sandbox/macos_sandbox_utils.dart'
    show MacOSSandboxParams, wrapCommandWithSandboxMacOS;
import 'package:sandbox_runtime/src/sandbox/sandbox_schemas.dart'
    show FsReadRestrictionConfig, FsWriteRestrictionConfig;
import 'package:test/test.dart';

import '../helpers/bwrap_namespace.dart' show bwrapCanNamespace;
import '../helpers/platform.dart' show isLinux, isMacOS;

// Dart: the `linkSync` shim does not exist; a hard link is made with `ln`.
void linkSync(String existingPath, String newPath) {
  final result = spawnSync('ln', [existingPath, newPath]);
  if (result.status != 0) throw StateError('link failed: $newPath');
}

/**
 * A write is judged by where it lands, not by the name it was asked for by:
 * every symbolic link on the way is followed first. So a link inside a write
 * root that leads out of it gives a command nothing, whoever made the link
 * and whenever, and a link outside every write root that leads into one is a
 * way in like any other name. On Linux that is the mount table's doing (the
 * file system is bound read-only and the write roots writable over it); on
 * macOS it is Seatbelt's, which compares the path the kernel resolved.
 *
 * Every link here is made on the host before the command is wrapped, and
 * every target a write is refused at exists, holds `original`, and must
 * still hold it afterwards.
 */
void main() {
  group(
    'A write through a link is judged by where it lands',
    skip: ((isLinux && bwrapCanNamespace()) || isMacOS)
        ? null
        : 'requires Linux with bwrap namespaces, or macOS',
    () {
      late String BASE;
      late String ROOT; // the one write root
      late String OUTSIDE; // beside it, under no write root

      setUp(() {
        // Where the temp dir really is: macOS names it through a link.
        BASE = realpathSync(
          mkdtempSync(join(tmpdir(), 'write-through-links-')),
        );
        ROOT = join(BASE, 'root');
        OUTSIDE = join(BASE, 'outside');
        mkdirSync(join(ROOT, 'inner'), {'recursive': true});
        mkdirSync(join(OUTSIDE, 'dir'), {'recursive': true});
        writeFileSync(join(ROOT, 'inner', 'file'), 'original');
        writeFileSync(join(OUTSIDE, 'file'), 'original');
        writeFileSync(join(OUTSIDE, 'dir', 'file'), 'original');
      });

      tearDown(() {
        rmSync(BASE, {'recursive': true, 'force': true});
      });

      /** What `command` said and how it ended, run with ROOT as its one write
       *  root and nothing denied within it. */
      Future<({int? status, String said})> run(String command) async {
        final readConfig = FsReadRestrictionConfig(denyOnly: []);
        final writeConfig = FsWriteRestrictionConfig(
          allowOnly: [ROOT],
          denyWithinAllow: [],
        );
        final wrapped = isLinux
            ? await wrapCommandWithSandboxLinux(
                LinuxSandboxParams(
                  command: command,
                  needsNetworkRestriction: false,
                  readConfig: readConfig,
                  writeConfig: writeConfig,
                ),
              )
            : wrapCommandWithSandboxMacOS(
                MacOSSandboxParams(
                  command: command,
                  needsNetworkRestriction: false,
                  readConfig: readConfig,
                  writeConfig: writeConfig,
                ),
              );
        final result = spawnSync(wrapped, [], {
          'shell': true,
          'encoding': 'utf8',
          'timeout': 30000,
          // Under no write root, so nothing of the working directory's is
          // protected or made.
          'cwd': OUTSIDE,
        });
        return (
          status: result.status,
          said: '${result.stdout ?? ''}${result.stderr ?? ''}',
        );
      }

      /** A command that tries `attempt` and says how it went, after showing
       *  that the sandbox itself started. */
      String trying(String attempt) =>
          'echo started; if ( $attempt ) 2>/dev/null; then echo WROTE; else echo refused; fi';

      test(
        'refuses a write through a link in the write root to a file outside it',
        () async {
          final link = join(ROOT, 'link-to-file');
          symlinkSync(join(OUTSIDE, 'file'), link);

          final said = (await run(trying('echo changed > $link'))).said;

          expect(said, contains('started'));
          expect(said, contains('refused'));
          expect(readFileSync(join(OUTSIDE, 'file'), 'utf8'), 'original');
        },
      );

      test(
        'refuses a write and a create beneath a link in the write root to a directory outside it',
        () async {
          final link = join(ROOT, 'link-to-dir');
          symlinkSync(join(OUTSIDE, 'dir'), link);

          final written = await run(trying('echo changed > $link/file'));
          expect(written.said, contains('started'));
          expect(written.said, contains('refused'));
          expect(
            readFileSync(join(OUTSIDE, 'dir', 'file'), 'utf8'),
            'original',
          );

          final created = await run(trying('echo new > $link/new'));
          expect(created.said, contains('started'));
          expect(created.said, contains('refused'));
          expect(existsSync(join(OUTSIDE, 'dir', 'new')), false);
        },
      );

      test(
        'refuses a rename onto a file outside the write root, through a linked directory',
        () async {
          final link = join(ROOT, 'link-to-dir');
          symlinkSync(join(OUTSIDE, 'dir'), link);

          final said = (await run(
            trying('echo changed > $ROOT/made && mv $ROOT/made $link/file'),
          )).said;

          expect(said, contains('started'));
          expect(said, contains('refused'));
          expect(
            readFileSync(join(OUTSIDE, 'dir', 'file'), 'utf8'),
            'original',
          );
        },
      );

      test(
        'refuses a create through a link in the write root to a name outside it that is not there',
        () async {
          final link = join(ROOT, 'dangling');
          symlinkSync(join(OUTSIDE, 'not-there'), link);

          final said = (await run(trying('echo new > $link'))).said;

          expect(said, contains('started'));
          expect(said, contains('refused'));
          expect(existsSync(join(OUTSIDE, 'not-there')), false);
        },
      );

      test('refuses the same through a link the command makes itself', () async {
        final link = join(ROOT, 'made-inside');

        final said = (await run(
          'ln -s ${join(OUTSIDE, 'file')} $link && ${trying('echo changed > $link')}',
        )).said;

        expect(said, contains('started'));
        expect(said, contains('refused'));
        expect(readFileSync(join(OUTSIDE, 'file'), 'utf8'), 'original');
      });

      test(
        'allows a write through a link in the write root that stays in it',
        () async {
          final link = join(ROOT, 'link-inside');
          symlinkSync(join(ROOT, 'inner', 'file'), link);

          final said = (await run(trying('echo changed > $link'))).said;

          expect(said, contains('WROTE'));
          expect(
            readFileSync(join(ROOT, 'inner', 'file'), 'utf8'),
            'changed\n',
          );
        },
      );

      test(
        'allows a write through a link outside every write root that leads into one',
        () async {
          final link = join(OUTSIDE, 'link-into-root');
          symlinkSync(join(ROOT, 'inner', 'file'), link);

          final said = (await run(trying('echo changed > $link'))).said;

          expect(said, contains('WROTE'));
          expect(
            readFileSync(join(ROOT, 'inner', 'file'), 'utf8'),
            'changed\n',
          );
        },
      );

      // A hard link is not a link that is followed: it is a second name for
      // the file itself. On Linux the name inside the write root is as good as
      // any, and the file is written through it although its other name is
      // outside. macOS is left out on purpose: which of a file's names Seatbelt
      // is handed is the system's choice, and nothing here depends on it.
      test(
        'allows a write through a second name in the write root for a file that also has one outside it',
        skip: isLinux ? null : 'Linux only',
        () async {
          final name = join(ROOT, 'second-name');
          linkSync(join(OUTSIDE, 'file'), name);

          final said = (await run(trying('echo changed > $name'))).said;

          expect(said, contains('WROTE'));
          expect(readFileSync(join(OUTSIDE, 'file'), 'utf8'), 'changed\n');
        },
      );

      // Such a name has to be there already. The write root is a mount of its
      // own inside the sandbox, and link(2) does not cross mounts.
      test(
        'does not let the command give a file outside the write root a second name in it',
        skip: isLinux ? null : 'Linux only',
        () async {
          final name = join(ROOT, 'second-name');

          final said = (await run(
            trying(
              'ln ${join(OUTSIDE, 'file')} $name',
            ).replaceFirst('WROTE', 'LINKED'),
          )).said;

          expect(said, contains('started'));
          expect(said, contains('refused'));
          expect(existsSync(name), false);
        },
      );
    },
  );
}
