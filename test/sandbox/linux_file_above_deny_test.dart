// Ported from sandbox-runtime test/sandbox/linux-file-above-deny.test.ts @ 0bbebed.
// ignore_for_file: constant_identifier_names, non_constant_identifier_names, slash_for_doc_comments, prefer_adjacent_string_concatenation
import 'package:test/test.dart';
import 'package:sandbox_runtime/src/node/child_process.dart';
import 'package:sandbox_runtime/src/node/fs.dart';
import 'package:sandbox_runtime/src/node/os.dart';
import 'package:sandbox_runtime/src/node/path.dart';
import 'package:sandbox_runtime/src/node/process.dart' as process;
import 'package:sandbox_runtime/src/sandbox/linux_sandbox_utils.dart';
import 'package:sandbox_runtime/src/sandbox/sandbox_schemas.dart';
import '../helpers/platform.dart';
import '../helpers/bwrap_argv.dart';
import '../helpers/bwrap_namespace.dart';

/**
 * Nothing can be created below a file, for as long as the file is there. So a
 * file above a write deny is kept there, in a directory the command may write.
 */
void main() {
  group('A file above a write deny', () {
    const POINTER = 'gitdir: elsewhere\n';
    late String base;
    late String area;
    final savedCwd = process.cwd();

    setUp(() {
      cleanupBwrapMountPoints(force: true);
      base = realpathSync(mkdtempSync(join(tmpdir(), 'file-above-deny-')));
      area = join(base, 'area');
      mkdirSync(area);
      process.chdir(area);
    });

    tearDown(() {
      process.chdir(savedCwd);
      cleanupBwrapMountPoints(force: true);
      rmSync(base, {'recursive': true, 'force': true});
    });

    Future<String> wrap([
      String command = 'true',
      List<String> denyWithinAllow = const [],
      List<String>? allowOnly,
    ]) => wrapCommandWithSandboxLinux(
      LinuxSandboxParams(
        command: command,
        needsNetworkRestriction: false,
        readConfig: FsReadRestrictionConfig(denyOnly: []),
        writeConfig: FsWriteRestrictionConfig(
          allowOnly: allowOnly ?? [area],
          denyWithinAllow: denyWithinAllow,
        ),
      ),
    );
    int held(String wrapped, String file) =>
        countMounts(wrapped, ['--ro-bind', file, file]);

    group('in the plan', () {
      test(
        'a .git that is a file is bound onto itself, once, and nothing below it',
        () async {
          writeFileSync(join(area, '.git'), POINTER);
          final wrapped = await wrap();
          expect(held(wrapped, join(area, '.git')), 1);
          expect(wrapped, isNot(contains(join(area, '.git', 'hooks'))));
          expect(wrapped, isNot(contains(join(area, '.git', 'config'))));
        },
      );

      // git rewrites and removes it: a checkout that recurses into submodules.
      test('one below the working directory is left to git', () async {
        mkdirSync(join(area, 'sub'));
        writeFileSync(join(area, 'sub', '.git'), POINTER);
        expect(await wrap(), isNot(contains(join(area, 'sub'))));
      });

      test('a .git that is a directory is denied as before', () async {
        mkdirSync(join(area, '.git', 'hooks'), {'recursive': true});
        writeFileSync(join(area, '.git', 'config'), '');
        final wrapped = await wrap();
        expect(held(wrapped, join(area, '.git', 'hooks')), 1);
        expect(held(wrapped, join(area, '.git', 'config')), 1);
      });

      test('no .git at all: nothing is laid there', () async {
        final wrapped = await wrap();
        expect(lastMountAt(wrapped, join(area, '.git')), isNull);
        expect(wrapped, isNot(contains('${join(area, '.git')}/')));
      });

      // Read without the scan too, which would find the file as well.
      for (final (what, denied) in <(String, List<String>)>[
        ('a file', ['.git']),
        ('a directory', ['.git/hooks', '.git/config']),
        ('not there', []),
      ]) {
        test('what follows from the cwd alone, .git being %s', () {
          if (what == 'a file') writeFileSync(join(area, '.git'), POINTER);
          if (what == 'a directory') mkdirSync(join(area, '.git'));
          expect(
            linuxGetCwdMandatoryDenyPaths()
                .where(
                  (p) =>
                      RegExp(r'/\.git(/|$)').hasMatch(p.substring(area.length)),
                )
                .toList(),
            denied.map((name) => join(area, name)).toList(),
          );
        });
      }

      test('two denies below one file: one bind', () async {
        writeFileSync(join(area, 'f'), 'mine');
        final wrapped = await wrap('true', [
          join(area, 'f', 'x'),
          join(area, 'f', 'y', 'z'),
        ]);
        expect(held(wrapped, join(area, 'f')), 1);
      });

      test('a file that is denied itself too: one bind', () async {
        writeFileSync(join(area, 'f'), 'mine');
        for (final denies in [
          [join(area, 'f'), join(area, 'f', 'x')],
          [join(area, 'f', 'x'), join(area, 'f')],
        ]) {
          expect(held(await wrap('true', denies), join(area, 'f')), 1);
        }
      });

      test('where the command may not write, nothing is laid', () async {
        writeFileSync(join(base, 'f'), 'mine');
        expect(
          await wrap('true', [join(base, 'f', 'x')]),
          isNot(contains(join(base, 'f'))),
        );
      });

      test(
        'where it may write the file and not its directory, the file is not held',
        () async {
          final f = join(base, 'f');
          writeFileSync(f, 'mine');
          final wrapped = await wrap('true', [join(f, 'x')], [f]);
          expect(held(wrapped, f), 0);
          expect(lastMountAt(wrapped, f), '--bind $f $f');
        },
      );
    });

    group('in the sandbox', () {
      Future<String> run(
        String command, [
        List<String> denies = const [],
        List<String>? allowOnly,
      ]) async {
        final r = spawnSync(await wrap(command, denies, allowOnly), [], {
          'shell': true,
          'encoding': 'utf8',
          'timeout': 20000,
        });
        cleanupBwrapMountPoints();
        expect(r.stderr, isNot(contains('bwrap:')));
        return (r.stdout as String).trim();
      }

      // Each way of putting something else at the name, and what it is after.
      String REPLACE(String name) =>
          'mv $name aside 2>/dev/null; echo mv=\$?; rm -rf $name 2>/dev/null; echo rm=\$?; ' +
          'mkdir -p $name/hooks 2>/dev/null; echo mkdir=\$?; echo x > $name 2>/dev/null; echo write=\$?';
      const REFUSED = 'mv=1\nrm=1\nmkdir=1\nwrite=1';

      test('a .git that is a file stays one', () async {
        writeFileSync(join(area, '.git'), POINTER);
        expect(await run(REPLACE('.git')), REFUSED);
        expect(readFileSync(join(area, '.git'), 'utf8'), POINTER);
      });
      test('a command beside it runs, and writes what it may', () async {
        writeFileSync(join(area, '.git'), POINTER);
        expect(
          await run('cat .git; echo mine > new; cat new'),
          '${POINTER}mine',
        );
      });
      test('a configured deny below a file: the file stays', () async {
        writeFileSync(join(area, 'f'), 'mine');
        expect(await run(REPLACE('f'), [join(area, 'f', 'x')]), REFUSED);
        expect(readFileSync(join(area, 'f'), 'utf8'), 'mine');
      });
      test(
        'a file that alone may be written is written, and stays one',
        () async {
          final f = join(base, 'f');
          writeFileSync(f, 'mine');
          expect(
            await run(
              'echo more >> $f; echo append=\$?; cd $base; ${REPLACE('f')}',
              [join(f, 'x')],
              [f],
            ),
            'append=0\nmv=1\nrm=1\nmkdir=1\nwrite=0',
          );
          expect(readFileSync(f, 'utf8'), 'x\n');
        },
      );
      test(
        'a protected name that leads through a file: the file stays',
        () async {
          writeFileSync(join(area, 'f'), 'mine');
          symlinkSync('f/x', join(area, '.bashrc'));
          expect(await run(REPLACE('f')), REFUSED);
          expect(readFileSync(join(area, 'f'), 'utf8'), 'mine');
        },
      );
      // An empty one looks like a mount point bubblewrap has made.
      for (final (name, content, denies) in <(String, String, List<String>)>[
        ('.git', POINTER, []),
        ('f', 'mine', ['f/x']),
        ('f', '', ['f/x']),
      ]) {
        test(
          "%s holding %p is the caller's own afterwards: there, as it was, and writable",
          () async {
            writeFileSync(join(area, name), content, {'mode': 420});
            await run('true', denies.map((d) => join(area, d)).toList());
            cleanupBwrapMountPoints(force: true);
            expect(readFileSync(join(area, name), 'utf8'), content);
            expect(lstatSync(join(area, name)).mode & 511, 420);
            writeFileSync(join(area, name), 'changed');
          },
        );
      }
    }, skip: isLinux && bwrapCanNamespace() ? false : 'bwrap cannot namespace here');
  }, skip: isLinux ? false : 'not Linux');
}
