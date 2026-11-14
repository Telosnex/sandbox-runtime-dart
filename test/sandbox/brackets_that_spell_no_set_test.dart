// Ported from sandbox-runtime test/sandbox/brackets-that-spell-no-set.test.ts @ 0bbebed.
// ignore_for_file: slash_for_doc_comments
// ignore_for_file: non_constant_identifier_names
import 'dart:convert';
import 'dart:io';

import 'package:path/path.dart' show dirname, join;
import 'package:test/test.dart';

import 'package:sandbox_runtime/src/node/child_process.dart' show spawnSync;
import 'package:sandbox_runtime/src/node/fs.dart' as fs;
import 'package:sandbox_runtime/src/node/os.dart' show tmpdir;
import 'package:sandbox_runtime/src/node/process.dart' as process;
import 'package:sandbox_runtime/src/sandbox/macos_sandbox_utils.dart'
    show MacOSSandboxParams, wrapCommandWithSandboxMacOS;
import 'package:sandbox_runtime/src/sandbox/sandbox_config.dart';
import 'package:sandbox_runtime/src/sandbox/sandbox_manager.dart';
import 'package:sandbox_runtime/src/sandbox/sandbox_schemas.dart'
    show FsReadRestrictionConfig, FsWriteRestrictionConfig;
import '../helpers/bwrap_namespace.dart' show bwrapCanNamespace;
import '../helpers/platform.dart' show isLinux, isMacOS, isWindows;

/**
 * An entry with brackets that spell no set of characters, because a range in
 * them runs backwards (`[user-id]`: `r-i`). A route folder is named so. The
 * brackets are the text they are, in every list and on every platform, and
 * the rest of the entry is the pattern it was.
 *
 * So are brackets with nothing in them and a bracket without its partner. A
 * wildcard in a set is a member of it.
 */

final ROOT = join(
  isWindows ? tmpdir() : fs.realpathSync(tmpdir()),
  'brackets-no-set-${DateTime.now().millisecondsSinceEpoch}',
);
final TREE = join(ROOT, 'tree');

/** The files a command tries, each under the letter it answers with. */
final FILES = {
  'S': '[user-id]/secret',
  'E': '[user-id]/a.env',
  'D': 'deep/[user-id]/a.env',
  // What a set of the letters between the brackets would match.
  'U': 'u/a.env',
  'P': 'plain',
  'L': 'list[].ts',
  'C': 'x]y',
  'O': 'o[p[q1',
  'W': 'a*c',
  // What a wildcard there would match.
  'B': 'abc',
};
final ALL = FILES.keys.join();
String without(String letters) =>
    ALL.split('').where((letter) => !letters.contains(letter)).join();

/** An entry beneath TREE, the files it covers, and the regular expression it is. */
final ENTRIES = <(String, String, String)>[
  ('[z-a]', '', '\\[z-a\\]'),
  ('[user-id]', 'SE', '\\[user-id\\]'),
  ('[user-id]/secret', 'S', '\\[user-id\\]/secret'),
  ('**/[user-id]/*.env', 'ED', '(.*/)?\\[user-id\\]/[^/]*\\.env'),
  // After a `**/`, so that none is also read as the name of the file.
  ('**/list[].ts', 'L', r'(.*/)?list\[\]\.ts'),
  ('**/x]y', 'C', r'(.*/)?x\]y'),
  ('**/o[p[q*', 'O', r'(.*/)?o\[p\[q[^/]*'),
  ('**/a[*]c', 'W', '(.*/)?a[*]c'),
];

typedef Policy = PartialSandboxRuntimeConfig;
const nothingListed = FilesystemConfig(
  denyRead: [],
  allowWrite: [],
  denyWrite: [],
);

/** A list: the policy with `entry` in it, and what is left of ALL to a command
 *  that reads, or writes, when the entry covers `covered`. */
final LISTS =
    <
      String,
      ({
        Policy Function(String entry) policy,
        bool? writes,
        String Function(String covered) left,
      })
    >{
      'denyRead': (
        policy: (entry) => PartialSandboxRuntimeConfig(
          filesystem: FilesystemConfig(
            denyRead: [FilesystemPathSpelling(entry)],
            allowWrite: [],
            denyWrite: [],
          ),
        ),
        writes: null,
        left: without,
      ),
      'credential deny': (
        policy: (entry) => PartialSandboxRuntimeConfig(
          filesystem: nothingListed,
          credentials: CredentialsConfig(
            files: [CredentialFileConfig(path: entry, mode: 'deny')],
          ),
        ),
        writes: null,
        left: without,
      ),
      'allowRead': (
        policy: (entry) => PartialSandboxRuntimeConfig(
          filesystem: FilesystemConfig(
            denyRead: [FilesystemPathSpelling(TREE)],
            allowRead: [FilesystemPathSpelling(entry)],
            allowWrite: [],
            denyWrite: [],
          ),
        ),
        writes: null,
        left: (covered) => covered,
      ),
      'denyWrite': (
        policy: (entry) => PartialSandboxRuntimeConfig(
          filesystem: FilesystemConfig(
            denyRead: [],
            allowWrite: [FilesystemPathSpelling(TREE)],
            denyWrite: [FilesystemPathSpelling(entry)],
          ),
        ),
        writes: true,
        left: without,
      ),
      'allowWrite': (
        policy: (entry) => PartialSandboxRuntimeConfig(
          filesystem: FilesystemConfig(
            denyRead: [],
            allowWrite: [FilesystemPathSpelling(entry)],
            denyWrite: [],
          ),
        ),
        writes: true,
        left: (covered) => covered,
      ),
    };

String stdoutOf(String wrapped) =>
    spawnSync(wrapped, [], {
          'shell': true,
          'encoding': 'utf8',
          'timeout': 20000,
        }).stdout
        as String;

final CASES = [
  for (final MapEntry(key: list, value: how) in LISTS.entries)
    for (final (entry, covered, source) in ENTRIES)
      (
        list: list,
        entry: entry,
        covered: covered,
        source: source,
        policy: how.policy,
        writes: how.writes,
        left: how.left,
      ),
];

void main() {
  group(
    'brackets that spell no set of characters',
    skip: !isWindows ? false : 'Windows not supported by this port',
    () {
      setUpAll(() {
        for (final file in FILES.values) {
          fs.mkdirSync(dirname(join(TREE, file)), {'recursive': true});
          fs.writeFileSync(join(TREE, file), 'content');
        }
      });

      tearDownAll(() {
        fs.rmSync(ROOT, {'recursive': true, 'force': true});
      });

      group(
        'what a command reads and writes',
        skip: (isLinux && bwrapCanNamespace()) || isMacOS
            ? false
            : 'requires bwrap namespaces on Linux, or macOS',
        () {
          setUpAll(() async {
            await SandboxManager.reset();
            await SandboxManager.initialize(
              SandboxRuntimeConfig(
                network: NetworkConfig(allowedDomains: [], deniedDomains: []),
                filesystem: nothingListed,
              ),
            );
          });

          tearDownAll(() async {
            await SandboxManager.reset();
          });

          for (final c in CASES) {
            test('${c.list} ${c.entry}', () async {
              final entry = c.entry;
              final covered = c.covered;
              final policy = c.policy;
              final writes = c.writes;
              final left = c.left;
              final attempts = FILES.entries.map((e) {
                final letter = e.key;
                final file = e.value;
                final path = "'${join(TREE, file)}'";
                // Opened to append and left as it is.
                final attempt = writes == true
                    ? ': >> $path'
                    : 'cat $path > /dev/null';
                return '( $attempt ) 2> /dev/null && printf $letter';
              }).toList();
              final wrapped = await SandboxManager.wrapWithSandbox(
                // 'ran' tells a command that was refused all from one that never ran.
                "echo ran; ${attempts.join('; ')}",
                null,
                policy(join(TREE, entry)),
              );
              // Linux takes no pattern in a write list, whatever it holds.
              final applies =
                  !(isLinux && writes == true && entry.contains('*'));
              expect(stdoutOf(wrapped), 'ran\n${left(applies ? covered : '')}');
            }, timeout: Timeout(Duration(milliseconds: 60000)));
          }

          test(
            'an ordinary relative pattern, from inside such a folder',
            () async {
              final cwd = process.cwd();
              Directory.current = join(TREE, '[user-id]');
              try {
                final wrapped = await SandboxManager.wrapWithSandbox(
                  'echo ran; cat a.env secret',
                  null,
                  PartialSandboxRuntimeConfig(
                    filesystem: FilesystemConfig(
                      denyRead: [FilesystemPathSpelling('*.env')],
                      allowWrite: [],
                      denyWrite: [],
                    ),
                  ),
                );
                expect(stdoutOf(wrapped), 'ran\ncontent');
              } finally {
                Directory.current = cwd;
              }
            },
            timeout: Timeout(Duration(milliseconds: 60000)),
          );

          test('reports the lists of the session', () async {
            await SandboxManager.reset();
            await SandboxManager.initialize(
              SandboxRuntimeConfig(
                network: NetworkConfig(allowedDomains: [], deniedDomains: []),
                filesystem: FilesystemConfig(
                  denyRead: [
                    FilesystemPathSpelling(join(TREE, '**/[user-id]/*.env')),
                    FilesystemPathSpelling(join(TREE, '[z-a]')),
                  ],
                  allowRead: [
                    FilesystemPathSpelling(join(TREE, '[user-id]/secret')),
                  ],
                  allowWrite: [],
                  denyWrite: [],
                ),
              ),
            );
            final read = SandboxManager.getFsReadConfig();
            final denyOnly = read.denyOnly;
            final allowWithinDeny = read.allowWithinDeny;
            denyOnly.sort();
            expect(denyOnly, [
              join(TREE, FILES['E']!),
              join(TREE, FILES['D']!),
            ]);
            expect(allowWithinDeny, [join(TREE, FILES['S']!)]);
          }, skip: isLinux ? false : 'requires Linux');
        },
      );

      // Read on any POSIX host. The builder compiles some of them itself, and
      // Seatbelt is handed them all.
      for (final c in CASES) {
        test('macOS profile, ${c.list} ${c.entry}: every regex compiles', () {
          final list = c.list;
          final source = c.source;
          final policy = c.policy;
          final p = policy(join(TREE, c.entry));
          final filesystem = p.filesystem!;
          final credentials = p.credentials;
          final credentialDenyOnly = credentials?.files
              ?.map((file) => file.path)
              .toList();
          final profile = wrapCommandWithSandboxMacOS(
            MacOSSandboxParams(
              command: 'true',
              needsNetworkRestriction: false,
              readConfig: FsReadRestrictionConfig(
                denyOnly: [
                  for (final e in filesystem.denyRead)
                    (e as FilesystemPathSpelling).path,
                  ...(credentialDenyOnly ?? []),
                ],
                credentialDenyOnly: credentialDenyOnly,
                allowWithinDeny: filesystem.allowRead
                    ?.map((e) => (e as FilesystemPathSpelling).path)
                    .toList(),
              ),
              writeConfig: FsWriteRestrictionConfig(
                allowOnly: [
                  for (final e in filesystem.allowWrite)
                    (e as FilesystemPathSpelling).path,
                ],
                denyWithinAllow: [
                  for (final e in filesystem.denyWrite)
                    (e as FilesystemPathSpelling).path,
                ],
              ),
            ),
          );
          final regexes = RegExp(r'\(regex ("(?:[^"\\]|\\.)*")\)')
              .allMatches(profile)
              .map((match) => jsonDecode(match[1]!) as String)
              .toList();
          for (final regex in regexes) {
            expect(() => RegExp(regex), returnsNormally);
          }
          expect(
            regexes.map((regex) => regex.split('/tree/').elementAtOrNull(1)),
            contains(source + (list.startsWith('allow') ? r'$' : r'(/.*)?$')),
          );
        });
      }
    },
  );
}
