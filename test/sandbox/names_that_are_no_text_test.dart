// Ported from sandbox-runtime test/sandbox/names-that-are-no-text.test.ts @ 0bbebed.
// ignore_for_file: non_constant_identifier_names
// ignore_for_file: slash_for_doc_comments, constant_identifier_names
import 'dart:convert';
import 'dart:io' as io;
import 'package:path/path.dart' show join;
import 'package:test/test.dart';
import 'package:sandbox_runtime/src/node/fs.dart' as fs;
import 'package:sandbox_runtime/src/node/os.dart' show tmpdir;
import 'package:sandbox_runtime/src/sandbox/own_files.dart'
    show ownInstallWarning;
import 'package:sandbox_runtime/src/sandbox/sandbox_config.dart';
import 'package:sandbox_runtime/src/sandbox/sandbox_manager.dart';
import '../helpers/captured_warnings.dart';
import '../helpers/platform.dart' show isLinux;

typedef Lists = Map<String, List<String>>;

/** What leads there, from which working directory, with `R` for the root. */
final _ROWS = <(String, String, Lists, String?)>[
  (
    'the working directory',
    'link',
    {
      'allowWrite': ['.'],
    },
    null,
  ),
  (
    'a write root',
    'plain',
    {
      'allowWrite': ['R/link'],
    },
    null,
  ),
  (
    'a write root beneath it',
    'plain',
    {
      'allowWrite': ['R/link/sub'],
    },
    null,
  ),
  (
    'denyRead',
    'plain',
    {
      'denyRead': ['R/link/file'],
    },
    null,
  ),
  (
    'a denyRead pattern from it',
    'plain',
    {
      'denyRead': ['R/link/**/file'],
    },
    null,
  ),
  (
    'a denyRead pattern that comes to it',
    'plain',
    {
      'denyRead': ['R/**/file'],
    },
    null,
  ),
  (
    'allowRead',
    'plain',
    {
      'denyRead': ['R'],
      'allowRead': ['R/link/file'],
    },
    null,
  ),
  (
    'an allowRead pattern',
    'plain',
    {
      'denyRead': ['R'],
      'allowRead': ['R/*/file'],
    },
    null,
  ),
  (
    'denyWrite',
    'plain',
    {
      'allowWrite': ['R'],
      'denyWrite': ['R/link/file'],
    },
    null,
  ),
  (
    'a denyWrite pattern',
    'plain',
    {
      'allowWrite': ['R'],
      'denyWrite': ['R/**/file'],
    },
    null,
  ),
  (
    'a built-in deny, a link to a directory',
    'directory',
    {
      'allowWrite': ['.'],
    },
    null,
  ),
  (
    'a built-in deny, a link to a file',
    'file',
    {
      'allowWrite': ['.'],
    },
    null,
  ),
  (
    'a built-in deny, a link to nothing yet',
    'not-there',
    {
      'allowWrite': ['.'],
    },
    null,
  ),
  (
    'a built-in deny beneath the working directory',
    '.',
    {
      'allowWrite': ['.'],
    },
    null,
  ),
  ('a credentials deny', 'plain', {}, 'deny'),
  ('a credentials mask', 'plain', {}, 'mask'),
];

/**
 * A name can hold bytes that are no text, and a link can lead to one. No
 * string spells where that is, which is for the mounts of one command to deal
 * with: setting the sandbox up, and asking it what it holds, go on as ever.
 *
 * macOS lets no such name be made.
 */
void main() {
  group('a configuration that leads to a name that is no text', () {
    final savedCwd = io.Directory.current.path;
    late String root;
    List<int> bytes(String before, [String after = '']) => [
      ...utf8.encode(before),
      0xff,
      ...utf8.encode(after),
    ];

    setUp(() {
      root = fs.realpathSync(fs.mkdtempSync(join(tmpdir(), 'no-text-')));
      fs.mkdirSync(bytes('$root/n', '/sub'), {'recursive': true});
      fs.symlinkSync(bytes('n'), join(root, 'link'));
      fs.writeFileSync(join(root, 'link/file'), '');
      fs.writeFileSync(join(root, 'link/.bashrc'), '');
      fs.mkdirSync(join(root, 'plain'));
      for (final (project, name, target) in [
        ('directory', '.vscode', bytes('../n')),
        ('file', '.bashrc', bytes('../n', '/file')),
        ('not-there', '.mcp.json', bytes('../n', '/not-there')),
      ]) {
        fs.mkdirSync(join(root, project));
        fs.symlinkSync(target, join(root, project, name));
      }
    });
    tearDown(() async {
      io.Directory.current = savedCwd;
      await SandboxManager.reset();
      fs.rmSync(root, {'recursive': true, 'force': true});
    });

    SandboxRuntimeConfig configOf(Lists lists, [String? mode]) {
      List<FilesystemPathEntry> entries(String key) => (lists[key] ?? [])
          .map(
            (entry) =>
                FilesystemPathSpelling(entry.replaceFirst(RegExp(r'^R'), root)),
          )
          .toList();
      return SandboxRuntimeConfig(
        network: NetworkConfig(
          allowedDomains: ['localhost'],
          deniedDomains: [],
        ),
        filesystem: FilesystemConfig(
          denyRead: entries('denyRead'),
          allowRead: lists.containsKey('allowRead')
              ? entries('allowRead')
              : null,
          allowWrite: entries('allowWrite'),
          denyWrite: entries('denyWrite'),
        ),
        credentials: mode == null
            ? null
            : CredentialsConfig(
                files: [
                  CredentialFileConfig(
                    path: join(root, 'link/file'),
                    mode: mode,
                  ),
                ],
                allowPlaintextInject: true,
              ),
      );
    }

    for (final (what, cwd, lists, mode) in _ROWS) {
      test('is set up, changed and asked about: $what', () async {
        io.Directory.current = join(root, cwd);
        final config = configOf(lists, mode);
        await SandboxManager.initialize(config, null, false);
        SandboxManager.updateConfig(configOf({}));
        SandboxManager.updateConfig(config);
        expect(SandboxManager.getFsReadConfig(), isA<Object>());
        expect(SandboxManager.getFsWriteConfig(), isA<Object>());
        expect(SandboxManager.checkDependencies().errors, []);
      });
    }
    test('is judged for whether it lets the library itself be written', () {
      fs.mkdirSync(join(root, 'link/node_modules/library'), {
        'recursive': true,
      });
      fs.writeFileSync(
        join(root, 'link/node_modules/library/package.json'),
        '{}',
      );
      expect(
        ownInstallWarning([
          join(root, 'link'),
        ], join(root, 'link/node_modules/library/index.js')),
        isA<String>(),
      );
    });
    test('says why a read deny is mounted on its spelling', () async {
      await SandboxManager.initialize(
        configOf({
          'denyRead': ['R/link/file'],
        }),
        null,
        false,
      );
      final captured = await withCapturedWarnings(
        () => SandboxManager.wrapWithSandbox('true'),
      );
      SandboxManager.cleanupAfterCommand();
      expect(
        captured.warnings.where((said) => said.contains('cannot be told')),
        [matches(RegExp('$root/link/file .*EILSEQ'))],
      );
    });
  }, skip: isLinux ? false : 'requires Linux');
}
