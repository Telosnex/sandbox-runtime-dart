// Ported from sandbox-runtime test/sandbox/write-deny-way-cut-short.property.test.ts @ 0bbebed.
// ignore_for_file: slash_for_doc_comments, constant_identifier_names, non_constant_identifier_names
import 'dart:io' as io;
import 'dart:math';
import 'package:path/path.dart' show join;
import 'package:test/test.dart';
import 'package:sandbox_runtime/src/node/child_process.dart' show spawnSync;
import 'package:sandbox_runtime/src/node/fs.dart' as fs;
import 'package:sandbox_runtime/src/node/os.dart' show tmpdir;
import 'package:sandbox_runtime/src/sandbox/sandbox_config.dart';
import 'package:sandbox_runtime/src/sandbox/sandbox_manager.dart';
import '../helpers/bwrap_namespace.dart' show bwrapCanNamespace;
import '../helpers/platform.dart' show isLinux;

/**
 * Trees of directories and links in a write root, with a write deny on a link
 * that leads nowhere yet. A command in the real sandbox then makes every name
 * that is not there, as a directory, a link or a file, and tries the denied
 * name after each round. It replaces nothing that is there.
 */
void main() {
  group(
    'property: a write deny on a link that leads nowhere yet',
    () {
      final savedCwd = io.Directory.current.path;
      const NAMES = ['a', 'b', 'c'];
      List<String> beneath(List<String> places) => places
          .expand((place) => NAMES.map((name) => '$place/$name'))
          .toList();
      /** Every path of up to three names, a directory before what it holds. */
      final PLACES = [...NAMES, ...beneath(NAMES), ...beneath(beneath(NAMES))];
      final random = Random(20261015);
      String target() => List.generate(
        1 + random.nextInt(4),
        (_) => [...NAMES, '..', '..'][random.nextInt(5)],
      ).join('/');
      const MAKES = {
        'directory': r'mkdir "$place"',
        // Its parent is another than that of the name it is made at.
        'link': r'ln -s "$PWD/far/away" "$place"',
        'file': r': > "$place"',
      };
      String make() => MAKES.values.elementAt(random.nextInt(MAKES.length));
      tearDownAll(() async {
        io.Directory.current = savedCwd;
        await SandboxManager.reset();
      });
      test('holds whatever the command makes', () async {
        var started = 0;
        var completed = 0;
        while (completed < 25) {
          final denied = target();
          final entries = List.generate(
            random.nextInt(9),
            (_) => (
              PLACES[random.nextInt(PLACES.length)],
              random.nextBool() ? null : target(),
            ),
          );
          final mixed = List.generate(PLACES.length, (_) => make());
          var precondition = true;
          for (final makes in [
            PLACES.map((_) => MAKES['directory']!).toList(),
            PLACES.map((_) => MAKES['link']!).toList(),
            mixed,
          ]) {
            final root = fs.realpathSync(
              fs.mkdtempSync(join(tmpdir(), 'cut-')),
            );
            try {
              final work = join(root, 'outer', 'work');
              fs.mkdirSync(work, {'recursive': true});
              for (final (place, leadsTo) in entries) {
                try {
                  if (leadsTo == null) {
                    fs.mkdirSync(join(work, place));
                  } else {
                    fs.symlinkSync(leadsTo, join(work, place));
                  }
                } catch (_) {
                  // Taken, or nothing holds it: the tree goes without.
                }
              }
              fs.symlinkSync(denied, join(work, 'name'));
              if (fs.existsSync(join(work, 'name'))) {
                precondition = false;
                break;
              }
              io.Directory.current = root;
              await SandboxManager.reset();
              await SandboxManager.initialize(
                SandboxRuntimeConfig(
                  network: NetworkConfig(allowedDomains: [], deniedDomains: []),
                  filesystem: FilesystemConfig(
                    denyRead: [],
                    allowWrite: [FilesystemPathSpelling(work)],
                    denyWrite: [FilesystemPathSpelling(join(work, 'name'))],
                  ),
                ),
                null,
                false,
              );
              final wrapped = await SandboxManager.wrapWithSandbox(
                [
                  "echo STARTED; cd '$work'; mkdir -p far/away",
                  'for round in 1 2 3; do',
                  ...PLACES.indexed.map(
                    (e) =>
                        'place=${e.$2}; [ -e \$place ] || [ -L \$place ] || ${makes[e.$1]}',
                  ),
                  '( echo written >> name ) && echo WRITTEN',
                  'done 2>/dev/null',
                ].join('\n'),
              );
              final result = spawnSync(wrapped, [], {
                'shell': true,
                'encoding': 'utf8',
                'timeout': 20000,
              });
              final stdout = result.stdout as String;
              SandboxManager.cleanupAfterCommand();
              // A sandbox that does not start writes nothing either.
              if (stdout != '') started++;
              expect(
                [stdout, fs.existsSync(join(work, 'name'))],
                [stdout == '' ? '' : 'STARTED\n', false],
              );
            } finally {
              io.Directory.current = savedCwd;
              fs.rmSync(root, {'recursive': true, 'force': true});
            }
          }
          // Every look at a smaller tree is three more sandboxes.
          if (precondition) completed++;
        }
        expect(started, greaterThan(0));
      }, timeout: const Timeout(Duration(milliseconds: 300000)));
    },
    skip: isLinux && bwrapCanNamespace()
        ? false
        : 'requires Linux and bwrap namespaces',
  );
}
