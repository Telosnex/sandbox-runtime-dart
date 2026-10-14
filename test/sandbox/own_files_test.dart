// Ported from sandbox-runtime test/sandbox/own-files.test.ts @ 24eb39e.
// ignore_for_file: constant_identifier_names, non_constant_identifier_names, slash_for_doc_comments
import 'dart:convert';
import 'dart:io' show Platform, Directory;

import 'package:path/path.dart' as path;
import 'package:sandbox_runtime/src/node/child_process.dart' show spawnSync;
import 'package:sandbox_runtime/src/node/fs.dart' as fs;
import 'package:sandbox_runtime/src/node/os.dart' show tmpdir;
import 'package:sandbox_runtime/src/sandbox/own_files.dart'
    show ownInstallWarning;
import 'package:sandbox_runtime/src/sandbox/sandbox_config.dart'
    show FilesystemPathEntry, FilesystemPathLiteral, FilesystemPathSpelling;
import 'package:test/test.dart';

import '../helpers/platform.dart' show isWindows;

typedef _Layout = ({String root, String link});

/** A copy of the library a sandboxed command may write is warned about, not
 *  denied: src/sandbox/own-files.ts says why. */
void main() {
  group(
    'The library installed under a write path',
    skip: isWindows ? 'Windows not supported by this port' : null,
    () {
      late String dir;
      late String project;

      setUp(() {
        dir = fs.realpathSync(
          fs.mkdtempSync(path.join(tmpdir(), 'own-files-')),
        );
        project = path.join(dir, 'project');
      });

      tearDown(() {
        fs.rmSync(dir, {'recursive': true, 'force': true});
      });

      /** A package at `root`; returns a module inside it. */
      String makePackage(String root) {
        fs.mkdirSync(path.join(root, 'dist'), {'recursive': true});
        fs.writeFileSync(path.join(root, 'package.json'), '{}');
        return path.join(root, 'dist', 'own-files.js');
      }

      /** npm: `<project>/node_modules/<name>`. */
      _Layout npmLayout(String name) {
        final root = path.join(project, 'node_modules', name);
        fs.mkdirSync(root, {'recursive': true});
        return (root: root, link: root);
      }

      /** pnpm: `node_modules/.pnpm/<id>/node_modules/<name>`, behind a link. */
      _Layout pnpmLayout(String name) {
        final store = path.join(
          project,
          'node_modules',
          '.pnpm',
          'x@1',
          'node_modules',
        );
        final [root, link] = [
          store,
          path.join(project, 'node_modules'),
        ].map((holder) => path.join(holder, name)).toList();
        fs.mkdirSync(root, {'recursive': true});
        fs.mkdirSync(path.dirname(link), {'recursive': true});
        fs.symlinkSync(root, link);
        return (root: root, link: link);
      }

      group('whether to warn', () {
        // Dart: a function's `.name` does not exist, so the names are given.
        for (final layout in <(String, _Layout Function(String))>[
          ('npmLayout', npmLayout),
          ('pnpmLayout', pnpmLayout),
        ]) {
          test('warns with the project writable: ${layout.$1}', () {
            final (:root, :link) = layout.$2('@scope/lib');
            final moduleFile = makePackage(root);
            expect(ownInstallWarning([project], moduleFile), contains(root));
            // As the loader spells it under --preserve-symlinks.
            expect(
              ownInstallWarning([project], moduleFile.replaceFirst(root, link)),
              contains(link),
            );
          });
        }

        test('goes by where a path really is, on both sides', () {
          final moduleFile = makePackage(npmLayout('lib').root);
          final link = path.join(dir, 'link');
          fs.symlinkSync(project, link);
          expect(ownInstallWarning([link], moduleFile), isNotNull);
          expect(
            ownInstallWarning([
              project,
            ], moduleFile.replaceFirst(project, link)),
            isNotNull,
          );
        });

        test('does not warn where no write path covers the copy', () {
          final moduleFile = makePackage(npmLayout('lib').root);
          // Nothing, a directory beside it, a name that merely starts the same.
          for (final allowed in <List<String>>[
            [],
            [path.join(project, 'src')],
            [path.join(dir, 'pro')],
          ]) {
            expect(ownInstallWarning(allowed, moduleFile), isNull);
          }
          // An install outside the project, as a global one is.
          final global = makePackage(
            path.join(dir, 'lib', 'node_modules', 'lib'),
          );
          expect(ownInstallWarning([project], global), isNull);
          expect(ownInstallWarning([path.join(dir, 'lib')], global), isNotNull);
        });

        test(
          'does not warn for a checkout, which is the project being worked on',
          () {
            expect(ownInstallWarning([dir], makePackage(project)), isNull);
            // Nor for this repository: no other test sees the warning.
            expect(ownInstallWarning(['/']), isNull);
          },
        );

        test('does not warn where there is no package on disk', () {
          // Compiled into an application: the module has a location, not a file.
          expect(
            ownInstallWarning(['/'], '/\$bunfs/root/node_modules/x/dist/m.js'),
            isNull,
          );
        });
      });

      /** The library's source placed in a project as a package manager would
       *  place it, and loaded from there. */
      group('loaded from a project', () {
        final REPO = path.join(
          Directory.current.path, // import.meta.dir, '..', '..'
        );
        final MANIFEST = path.join(REPO, 'package.json');
        const NAME = '@anthropic-ai/sandbox-runtime';

        /** The source placed by `layout`, its dependencies beside it. */
        _Layout install(_Layout Function(String) layout) {
          final (:root, :link) = layout(NAME);
          spawnSync('cp', ['-R', path.join(REPO, 'src'), MANIFEST, root]);
          fs.symlinkSync(path.join(REPO, 'vendor'), path.join(root, 'vendor'));
          final manifest =
              jsonDecode(fs.readFileSync(MANIFEST, 'utf8') as String)
                  as Map<String, Object?>;
          for (final name in (manifest['dependencies']! as Map).keys) {
            final beside = path.join(
              root.substring(0, root.length - NAME.length),
              name as String,
            );
            fs.mkdirSync(path.dirname(beside), {'recursive': true});
            fs.symlinkSync(
              fs.realpathSync(path.join(REPO, 'node_modules', name)),
              beside,
            );
          }
          return (root: root, link: link);
        }

        /**
         * Runs `body` in the project and returns the JSON it prints. It has `s`,
         * the manager of the copy at `link`; `filesystem`, a policy with
         * `allowWrite`; and `warnings()`, the dependency check's under a policy.
         */
        ({Object? printed, String stderr}) run(
          String link,
          FilesystemPathEntry allowWrite,
          String body,
        ) {
          final child = spawnSync(
            Platform.resolvedExecutable,
            [
              '-e',
              '''const { SandboxManager: s } = await import(${jsonEncode(path.join(link, 'src', 'index.ts'))})
           const filesystem = { denyRead: [], allowWrite: [${jsonEncode(allowWrite)}], denyWrite: [] }
           const warnings = filesystem => {
             s.updateConfig({ network: { allowedDomains: [], deniedDomains: [] }, filesystem })
             return s.checkDependencies().warnings
           }
           $body''',
            ],
            {
              'cwd': project,
              'encoding': 'utf8',
              'env': {...Platform.environment, 'SRT_DEBUG': '1'},
              'timeout': 60000,
            },
          );
          if (child.status != 0) throw Exception(child.stderr);
          return (
            printed: jsonDecode(child.stdout as String),
            stderr: child.stderr as String,
          );
        }

        FilesystemPathEntry spelled(String p) => FilesystemPathSpelling(p);
        FilesystemPathEntry marked(String p) => FilesystemPathLiteral(p);

        for (final (layoutName, layout, entryName, entry)
            in <
              (
                String,
                _Layout Function(String),
                String,
                FilesystemPathEntry Function(String),
              )
            >[
              ('npmLayout', npmLayout, 'spelled', spelled),
              ('pnpmLayout', pnpmLayout, 'spelled', spelled),
              ('npmLayout', npmLayout, 'marked', marked),
            ]) {
          test(
            'is reported by the dependency check and logged once: $layoutName, write path $entryName',
            () {
              final (:root, :link) = install(layout);
              final (:printed, :stderr) = run(
                link,
                entry(project),
                '''await s.wrapWithSandbox('true', undefined, { filesystem })
           await s.wrapWithSandbox('true', undefined, { filesystem })
           console.log(JSON.stringify([
             warnings(filesystem),
             warnings({ ...filesystem, disabled: true }),
           ]))''',
              );

              bool about(String text) => text.contains('$root,');
              final [enabled, disabled] = (printed! as List)
                  .map((e) => (e as List).cast<String>())
                  .toList();
              expect(enabled.where(about), hasLength(1));
              // No path is outside the write paths when every path may be written.
              expect(disabled.where(about).toList(), <String>[]);
              expect(stderr.split('\n').where(about), hasLength(1));
            },
            timeout: const Timeout(Duration(milliseconds: 120000)),
            // Dart: needs upstream's TypeScript package (package.json, src/index.ts) run by bun; no Dart equivalent.
            tags: ['pending'],
          );
        }

        test(
          'leaves a malformed entry to whoever enforces the config',
          () {
            final (:root, :link) = install(npmLayout);
            final (:printed, stderr: _) = run(
              link,
              FilesystemPathSpelling(project),
              '''console.log(JSON.stringify([
           warnings({ ...filesystem, denyRead: [{ path: '/x' }] }),
           [await s.wrapWithSandbox('true').catch(e => e.message)],
         ]))''',
            );
            final [warnings, [wrap]] = (printed! as List)
                .map((e) => (e as List).cast<String>())
                .toList();
            expect(
              (warnings as List)
                  .cast<String>()
                  .where((w) => w.contains(root))
                  .toList(),
              <String>[],
            );
            expect(
              wrap,
              contains('must be a path, or { path, literal: true }'),
            );
          },
          timeout: const Timeout(Duration(milliseconds: 120000)),
          // Dart: needs upstream's TypeScript package (package.json, src/index.ts) run by bun; no Dart equivalent.
          tags: ['pending'],
        );

        test(
          'says nothing where the working directory is gone',
          () {
            final (:root, :link) = install(npmLayout);
            final gone = path.join(dir, 'gone');
            fs.mkdirSync(gone);
            final (:printed, stderr: _) = run(
              link,
              FilesystemPathSpelling(project),
              '''process.chdir(${jsonEncode(gone)})
         require('node:fs').rmdirSync(${jsonEncode(gone)})
         console.log(JSON.stringify(warnings({ ...filesystem, allowWrite: ['.'] })))''',
            );
            expect(
              (printed! as List)
                  .cast<String>()
                  .where((w) => w.contains(root))
                  .toList(),
              <String>[],
            );
          },
          timeout: const Timeout(Duration(milliseconds: 120000)),
          // Dart: needs upstream's TypeScript package (package.json, src/index.ts) run by bun; no Dart equivalent.
          tags: ['pending'],
        );

        test(
          'fails neither call site, whatever goes wrong in it',
          () {
            final (:root, :link) = install(npmLayout);
            fs.writeFileSync(
              path.join(root, 'src', 'sandbox', 'own-files.ts'),
              "export function ownInstallWarning() { throw new Error('thrown') }",
            );
            final (:printed, stderr: _) = run(
              link,
              FilesystemPathSpelling(project),
              '''const wrapped = await s.wrapWithSandbox('true', undefined, { filesystem })
         console.log(JSON.stringify([typeof wrapped, typeof warnings(filesystem)]))''',
            );
            expect(printed, ['string', 'object']);
          },
          timeout: const Timeout(Duration(milliseconds: 120000)),
          // Dart: needs upstream's TypeScript package (package.json, src/index.ts) run by bun; no Dart equivalent.
          tags: ['pending'],
        );
      });
    },
  );
}
