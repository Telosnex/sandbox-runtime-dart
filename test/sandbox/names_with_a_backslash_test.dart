// Ported from sandbox-runtime test/sandbox/names-with-a-backslash.test.ts @ 0bbebed.
// ignore_for_file: constant_identifier_names, non_constant_identifier_names, slash_for_doc_comments
import 'dart:convert' show jsonEncode;

import 'package:path/path.dart' show basename, dirname, join;
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
import 'package:sandbox_runtime/src/node/process.dart' as process;
import 'package:sandbox_runtime/src/sandbox/macos_sandbox_utils.dart'
    show MacOSSandboxParams, wrapCommandWithSandboxMacOS;
import 'package:sandbox_runtime/src/sandbox/sandbox_config.dart';
import 'package:sandbox_runtime/src/sandbox/sandbox_manager.dart';
import 'package:sandbox_runtime/src/sandbox/sandbox_schemas.dart'
    show FsReadRestrictionConfig;
import 'package:sandbox_runtime/src/sandbox/sandbox_utils.dart'
    show normalizePathForSandbox, pathSpellings;
import 'package:test/test.dart';

import '../helpers/bwrap_namespace.dart' show bwrapCanNamespaceNetwork;
import '../helpers/platform.dart' show isLinux, isMacOS, isWindows;

/**
 * Off Windows a backslash is a character of a file name like any other:
 * `a\b` is one name, and `a/b` is another file. A rule that names the one
 * applies to it, however it is spelled, and leaves the other alone.
 */

const APPENDED = 'appended';
// Dart: the probe spawns a process, so it runs only on Linux.
final canRun = isMacOS || (isLinux && bwrapCanNamespaceNetwork());

late String root;
final savedCwd = process.cwd();

// Dart: `Omit<Partial<SandboxRuntimeConfig>, 'filesystem'> & { filesystem?:
// Partial<...> }` as a class; only the fields these cases set are present.
class Policy {
  const Policy({this.network, this.credentials, this.filesystem});
  final NetworkConfig? network;
  final CredentialsConfig? credentials;
  final PolicyFilesystem? filesystem;
}

class PolicyFilesystem {
  const PolicyFilesystem({
    this.denyRead,
    this.allowRead,
    this.allowWrite,
    this.denyWrite,
  });
  final List<String>? denyRead;
  final List<String>? allowRead;
  final List<String>? allowWrite;
  final List<String>? denyWrite;
}

List<FilesystemPathEntry>? _entries(List<String>? list) =>
    list?.map<FilesystemPathEntry>(FilesystemPathSpelling.new).toList();

/**
 * Which of `files`, given from `root`, a command in the sandbox can read, or
 * append to. Each is made first, holding its own name, unless `absent`. The
 * command runs behind an `echo BOOTED`, so a sandbox that failed to start
 * cannot read as a command that was refused.
 */
Future<List<String>> reach(
  Policy policy,
  String does,
  List<String> files, [
  bool absent = false,
]) async {
  for (final file in files) {
    mkdirSync(dirname(join(root, file)), {'recursive': true});
    if (!absent) writeFileSync(join(root, file), '<$file>');
  }
  await SandboxManager.initialize(
    SandboxRuntimeConfig(
      network:
          policy.network ??
          const NetworkConfig(allowedDomains: [], deniedDomains: []),
      credentials: policy.credentials,
      filesystem: FilesystemConfig(
        denyRead: _entries(policy.filesystem?.denyRead) ?? [],
        allowRead: _entries(policy.filesystem?.allowRead),
        allowWrite: _entries(policy.filesystem?.allowWrite) ?? [],
        denyWrite: _entries(policy.filesystem?.denyWrite) ?? [],
      ),
    ),
    null,
    false,
  );
  final wrapped = await SandboxManager.wrapWithSandbox(
    ['echo BOOTED']
        .followedBy(
          files.map(
            (file) => does == 'read'
                ? "cat '${join(root, file)}'"
                : "echo $APPENDED >> '${join(root, file)}'",
          ),
        )
        .join('; '),
  );
  final stdout =
      spawnSync(wrapped, [], {
            'shell': true,
            'encoding': 'utf8',
            'timeout': 15000,
          }).stdout
          as String;
  SandboxManager.cleanupAfterCommand();
  expect(stdout, contains('BOOTED'));
  return files
      .where(
        (file) => does == 'read'
            ? stdout.contains('<$file>')
            : existsSync(join(root, file)) &&
                  (readFileSync(join(root, file), 'utf8') as String).contains(
                    APPENDED,
                  ),
      )
      .toList();
}

Policy credential(String path, String mode) => Policy(
  network: const NetworkConfig(
    allowedDomains: ['localhost'],
    deniedDomains: [],
  ),
  credentials: CredentialsConfig(
    files: [CredentialFileConfig(path: path, mode: mode)],
    allowPlaintextInject: true,
  ),
);

/** Each kind of rule as the policy that holds it for `entry`, what a command
 *  then tries, and whether the rule leaves it `entry` or everything else. */
final List<(String, Policy Function(String), String, String)> RULES = [
  (
    'denyRead',
    (e) => Policy(filesystem: PolicyFilesystem(denyRead: [e])),
    'read',
    'the rest',
  ),
  (
    'a denyRead pattern',
    (e) => Policy(
      filesystem: PolicyFilesystem(
        denyRead: ['${dirname(e)}/**/${basename(e)}'],
      ),
    ),
    'read',
    'the rest',
  ),
  ('a credentials deny', (e) => credential(e, 'deny'), 'read', 'the rest'),
  ('a credentials mask', (e) => credential(e, 'mask'), 'read', 'the rest'),
  (
    'allowRead',
    (e) => Policy(
      filesystem: PolicyFilesystem(
        denyRead: [join(root, 'tree')],
        allowRead: [e],
      ),
    ),
    'read',
    'it',
  ),
  (
    'an allowRead pattern',
    (e) => Policy(
      filesystem: PolicyFilesystem(
        denyRead: [join(root, 'tree')],
        allowRead: [e.replaceFirst('\\', '*')],
      ),
    ),
    'read',
    'it',
  ),
  (
    'denyWrite',
    (e) => Policy(
      filesystem: PolicyFilesystem(allowWrite: [root], denyWrite: [e]),
    ),
    'append',
    'the rest',
  ),
  (
    'allowWrite',
    (e) => Policy(filesystem: PolicyFilesystem(allowWrite: [e])),
    'append',
    'it',
  ),
];

void main() {
  setUp(() {
    root = realpathSync(mkdtempSync(join(tmpdir(), 'backslash-')));
  });

  tearDown(() async {
    process.chdir(savedCwd);
    await SandboxManager.reset();
    rmSync(root, {'recursive': true, 'force': true});
  });

  group(
    'a rule on a name that holds a backslash',
    skip: canRun ? null : 'requires macOS or Linux with bwrap',
    () {
      for (final (rule, policy, does, leaves) in RULES) {
        for (final name in ['a\\b', 'c\\d/file']) {
          for (final through in ['tree', 'link']) {
            // Of the write rules only a deny for bubblewrap is followed through a
            // link, whatever the name.
            if (does == 'append' &&
                through == 'link' &&
                !(isLinux && rule == 'denyWrite')) {
              continue;
            }
            for (final other in [name.replaceFirst('\\', '/'), 'plain']) {
              test(
                '$rule of $through/$name, beside tree/$other, leaves $leaves within reach',
                () async {
                  symlinkSync('tree', join(root, 'link'));
                  final files = ['tree/$name', 'tree/$other'];

                  expect(
                    await reach(policy(join(root, through, name)), does, files),
                    [files[leaves == 'it' ? 0 : 1]],
                  );
                },
                timeout: const Timeout(Duration(milliseconds: 60000)),
              );
            }
          }
        }
      }

      for (final other in ['c/d/file', 'plain']) {
        test(
          'denyWrite of tree/c\\d/file, which is not there, beside tree/$other, leaves the rest within reach',
          () async {
            expect(
              await reach(
                Policy(
                  filesystem: PolicyFilesystem(
                    allowWrite: [root],
                    denyWrite: [join(root, 'tree/c\\d/file')],
                  ),
                ),
                'append',
                ['tree/c\\d/file', 'tree/$other'],
                true,
              ),
              ['tree/$other'],
            );
          },
          timeout: const Timeout(Duration(milliseconds: 60000)),
        );
      }

      test(
        'keeps the shell start-up file of a working directory with such a name read-only',
        () async {
          mkdirSync(join(root, 'pro\\ject'));
          process.chdir(join(root, 'pro\\ject'));

          expect(
            await reach(
              Policy(filesystem: PolicyFilesystem(allowWrite: [root])),
              'append',
              ['pro\\ject/.bashrc', 'pro\\ject/plain', 'pro/ject/.bashrc'],
            ),
            ['pro\\ject/plain', 'pro/ject/.bashrc'],
          );
        },
        timeout: const Timeout(Duration(milliseconds: 60000)),
      );

      test(
        'keeps a shell start-up file in a directory with such a name, beneath the working directory, read-only',
        () async {
          process.chdir(root);

          expect(
            await reach(
              Policy(filesystem: PolicyFilesystem(allowWrite: [root])),
              'append',
              ['c\\d/.bashrc', 'c\\d/plain', 'c/d/.bashrc'],
            ),
            ['c\\d/plain'],
          );
        },
        timeout: const Timeout(Duration(milliseconds: 60000)),
      );

      // Only bubblewrap is handed what a pattern finds; Seatbelt matches paths.
      test(
        'denies what a denyRead pattern reaches through a link in a directory with such a name',
        skip: isLinux ? null : 'Linux only',
        () async {
          mkdirSync(join(root, 'tree/c\\d'), {'recursive': true});
          symlinkSync(join(root, 'elsewhere'), join(root, 'tree/c\\d/link'));

          expect(
            await reach(
              Policy(
                filesystem: PolicyFilesystem(
                  denyRead: [join(root, 'tree/**/file')],
                ),
              ),
              'read',
              ['elsewhere/file', 'elsewhere/plain'],
            ),
            ['elsewhere/plain'],
          );
        },
        timeout: const Timeout(Duration(milliseconds: 60000)),
      );
    },
  );

  group(
    'a name that holds a backslash, behind a link',
    skip: !isWindows ? null : 'Windows not supported by this port',
    () {
      setUp(() {
        mkdirSync(join(root, 'tree/a/b'), {'recursive': true});
        mkdirSync(join(root, 'tree/a\\b'));
        symlinkSync('tree', join(root, 'link'));
      });

      test('is spelled as written and as it really is', () {
        expect(pathSpellings(join(root, 'link/a\\b')), [
          join(root, 'link/a\\b'),
          join(root, 'tree/a\\b'),
        ]);
      });

      for (final tail in ['', '/**/file']) {
        test(
          'is normalized with a parent reference before it folded ($tail)',
          () {
            expect(
              normalizePathForSandbox('$root/tree/a/../a\\b$tail'),
              '$root/tree/a\\b$tail',
            );
          },
        );
      }

      test('is denied in a Seatbelt profile where it really is', () {
        final profile = wrapCommandWithSandboxMacOS(
          MacOSSandboxParams(
            command: 'true',
            needsNetworkRestriction: false,
            readConfig: FsReadRestrictionConfig(
              denyOnly: [join(root, 'link/a\\b')],
            ),
            writeConfig: null,
          ),
        );

        expect(
          profile,
          contains('(subpath ${jsonEncode(join(root, 'tree/a\\b'))})'),
        );
        expect(profile, isNot(contains(join(root, 'tree/a/b'))));
      });
    },
  );
}
