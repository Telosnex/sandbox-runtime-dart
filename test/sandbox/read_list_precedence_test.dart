// Ported from sandbox-runtime test/sandbox/read-list-precedence.test.ts @ 0bbebed.
// ignore_for_file: constant_identifier_names, non_constant_identifier_names, slash_for_doc_comments, prefer_adjacent_string_concatenation, prefer_interpolation_to_compose_strings
import 'dart:convert';

import 'package:path/path.dart' show dirname, join;
import 'package:sandbox_runtime/src/node/child_process.dart' show spawnSync;
import 'package:sandbox_runtime/src/node/fs.dart'
    show
        mkdirSync,
        readFileSync,
        realpathSync,
        rmSync,
        symlinkSync,
        writeFileSync;
import 'package:sandbox_runtime/src/node/os.dart' show homedir, tmpdir;
import 'package:sandbox_runtime/src/sandbox/credential_mask_files.dart'
    show MaskedFileBind;
import 'package:sandbox_runtime/src/sandbox/macos_sandbox_utils.dart'
    show MacOSSandboxParams, wrapCommandWithSandboxMacOS;
import 'package:sandbox_runtime/src/sandbox/sandbox_config.dart';
import 'package:sandbox_runtime/src/sandbox/sandbox_manager.dart'
    show PartialSandboxRuntimeConfig, SandboxManager;
import 'package:sandbox_runtime/src/sandbox/sandbox_schemas.dart'
    show FsReadRestrictionConfig, FsWriteRestrictionConfig;
import 'package:sandbox_runtime/src/sandbox/sandbox_utils.dart'
    show isAtOrUnder;
import 'package:test/test.dart';

import '../helpers/bwrap_argv.dart'
    show countMounts, indexOfMount, lastIndexOfMount, lastMountAt;
import '../helpers/captured_warnings.dart' show withCapturedWarnings;
import '../helpers/platform.dart' show isLinux, isMacOS, isWindows;

/**
 * How the lists that decide what a command reads rank against each other:
 * `filesystem.denyRead`, `filesystem.allowRead`, `filesystem.allowWrite` and
 * `credentials.files`.
 */

const CONTENT = 'file-content';
final ROOT = join(
  isWindows ? tmpdir() : realpathSync(tmpdir()),
  'read-list-precedence-' + DateTime.now().millisecondsSinceEpoch.toString(),
);
final VAULT = join(ROOT, 'vault');
final V1 = join(VAULT, 'v1');
final TOKEN = join(V1, 'token');
final SIBLING = join(V1, 'sibling');
final BRACKETS = join(VAULT, '[v1.2]');
final BRACKETS_TOKEN = join(BRACKETS, 'token');
final DIR = join(VAULT, 'dir');
final DEEP = join(DIR, 'deep');
final DEEP_TOKEN = join(DEEP, 'token');
final SUB = join(VAULT, 'sub');
final NETRC = join(SUB, '.netrc');
final TOKEN_LINK = join(VAULT, 'link-to-token');
final DIR_LINK = join(VAULT, 'link-to-dir');
final BRACKETS_LINK = join(VAULT, 'link-to-brackets');
final VAULT_LINK = join(ROOT, 'link-to-vault');
final LINKED_DIR = join(VAULT_LINK, 'dir');
final ROOT_LINK = join(ROOT, 'link-to-root');
final NULL_LINK = join(ROOT, 'link-to-null');
final DEV_LINK = join(ROOT, 'link-to-dev');
final JAR = join(ROOT, 'agent', 'agent.jar');

const CREDENTIAL =
    <String, ({String mode, String? extract, String? onExtractNoMatch})>{
      'credential deny': (mode: 'deny', extract: null, onExtractNoMatch: null),
      'credential mask': (mode: 'mask', extract: null, onExtractNoMatch: null),
      'credential mask with no match': (
        mode: 'mask',
        extract: 'absent-(text)',
        onExtractNoMatch: 'deny',
      ),
    };
typedef Kind = String; // 'denyRead' | keyof typeof CREDENTIAL
final KINDS = <Kind>['denyRead', ...CREDENTIAL.keys];

// Dart: upstream's object type; allowRead entries are String or FilesystemPathEntry.
class Lists {
  Lists({this.denyRead, this.allowRead, this.allowWrite});
  final List<String>? denyRead;
  final List<Object>? allowRead;
  final List<String>? allowWrite;

  // Dart: JSON.stringify(lists), which jsonEncode calls.
  Map<String, Object?> toJson() => {
    if (denyRead != null) 'denyRead': denyRead,
    if (allowRead != null)
      'allowRead': [
        for (final e in allowRead!) e is FilesystemPathEntry ? e.toJson() : e,
      ],
    if (allowWrite != null) 'allowWrite': allowWrite,
  };
}

FilesystemPathEntry _entry(Object e) =>
    e is FilesystemPathEntry ? e : FilesystemPathSpelling(e as String);

/** `entry` listed in one of KINDS, beside the other lists. */
// Dart: Pick<SandboxRuntimeConfig, 'filesystem' | 'credentials'> as a record.
({FilesystemConfig filesystem, CredentialsConfig credentials}) configOf(
  Kind kind,
  String entry,
  Lists lists,
) {
  return (
    filesystem: FilesystemConfig(
      denyRead: [
        for (final p in [
          ...(lists.denyRead ?? <String>[]),
          if (kind == 'denyRead') entry,
        ])
          FilesystemPathSpelling(p),
      ],
      allowRead: [for (final e in lists.allowRead ?? <Object>[]) _entry(e)],
      allowWrite: [
        for (final p in lists.allowWrite ?? <String>[])
          FilesystemPathSpelling(p),
      ],
      denyWrite: [],
    ),
    credentials: CredentialsConfig(
      files: kind == 'denyRead'
          ? []
          : [
              CredentialFileConfig(
                path: entry,
                mode: CREDENTIAL[kind]!.mode,
                extract: CREDENTIAL[kind]!.extract,
                onExtractNoMatch: CREDENTIAL[kind]!.onExtractNoMatch,
              ),
            ],
    ),
  );
}

// Dart: the Partial config wrapWithSandbox takes for a `configOf` result.
PartialSandboxRuntimeConfig _partial(
  ({FilesystemConfig filesystem, CredentialsConfig credentials}) c,
) => PartialSandboxRuntimeConfig(
  filesystem: c.filesystem,
  credentials: c.credentials,
);

// Dart: `{ ...configOf(...) }` handed to initialize().
SandboxRuntimeConfig _full(
  ({FilesystemConfig filesystem, CredentialsConfig credentials}) c,
) => SandboxRuntimeConfig(
  network: network,
  filesystem: c.filesystem,
  credentials: c.credentials,
);

const network = NetworkConfig(allowedDomains: [], deniedDomains: []);
const nothingListed = FilesystemConfig(
  denyRead: [],
  allowWrite: [],
  denyWrite: [],
);
String short(String text) => text.split(ROOT + '/').join('');
String stdoutOf(String wrapped) =>
    spawnSync(wrapped, [], {
          'shell': true,
          'encoding': 'utf8',
          'timeout': 10000,
        }).stdout
        as String;

void main() {
  group(
    'precedence between the read lists',
    skip: !isWindows ? null : 'Windows not supported by this port',
    () {
      setUpAll(() {
        for (final file in [
          TOKEN,
          SIBLING,
          BRACKETS_TOKEN,
          DEEP_TOKEN,
          NETRC,
          JAR,
        ]) {
          mkdirSync(dirname(file), {'recursive': true});
          writeFileSync(file, CONTENT);
        }
        symlinkSync(TOKEN, TOKEN_LINK);
        symlinkSync(DIR, DIR_LINK);
        symlinkSync(BRACKETS, BRACKETS_LINK);
        symlinkSync(VAULT, VAULT_LINK);
        symlinkSync('/', ROOT_LINK);
        symlinkSync('/dev/null', NULL_LINK);
        symlinkSync('/dev', DEV_LINK);
      });

      tearDownAll(() async {
        await SandboxManager.reset();
        rmSync(ROOT, {'recursive': true, 'force': true});
      });

      group(
        'what a command reads',
        skip: isLinux || isMacOS ? null : 'requires Linux or macOS',
        () {
          setUpAll(() async {
            await SandboxManager.reset();
            await SandboxManager.initialize(
              SandboxRuntimeConfig(network: network, filesystem: nothingListed),
            );
          });

          // The entry, the other lists, the file read, and its state with the entry
          // in each of KINDS: R readable, U unreadable, M masked, - not asked.
          // A write path is bound, and so readable, on Linux alone.
          final W = isLinux ? 'R' : 'U';
          final rows = <(String, Lists, String, String)>[
            (TOKEN, Lists(), TOKEN, 'UUMU'),
            (TOKEN, Lists(), SIBLING, 'RRRR'),
            (TOKEN, Lists(allowRead: [TOKEN]), TOKEN, 'RUMU'),
            (TOKEN, Lists(allowRead: [V1]), TOKEN, 'UUMU'),
            (TOKEN, Lists(allowRead: [join(V1, '*')]), TOKEN, 'RUMU'),
            (
              TOKEN,
              Lists(allowRead: [FilesystemPathLiteral(TOKEN)]),
              TOKEN,
              'RUMU',
            ),
            (TOKEN, Lists(allowWrite: [TOKEN]), TOKEN, 'UUMU'),
            (TOKEN, Lists(allowWrite: [V1]), TOKEN, 'UUMU'),
            (TOKEN, Lists(denyRead: [VAULT]), TOKEN, 'UUMU'),
            (
              TOKEN,
              Lists(denyRead: [VAULT], allowRead: [TOKEN]),
              TOKEN,
              'RUMU',
            ),
            (TOKEN, Lists(denyRead: [VAULT], allowRead: [V1]), TOKEN, 'UUMU'),
            (TOKEN, Lists(denyRead: [VAULT], allowRead: [V1]), SIBLING, 'RRRR'),
            (
              TOKEN,
              Lists(denyRead: [VAULT], allowRead: [join(V1, '*')]),
              TOKEN,
              'RUMU',
            ),
            (
              TOKEN,
              Lists(denyRead: [VAULT], allowRead: [TOKEN_LINK, TOKEN]),
              TOKEN_LINK,
              '-UUU',
            ),
            (
              BRACKETS_TOKEN,
              Lists(denyRead: [VAULT], allowRead: [join(BRACKETS, '*')]),
              BRACKETS_TOKEN,
              'RUMU',
            ),
            (TOKEN, Lists(allowRead: [TOKEN_LINK]), TOKEN, 'UUMU'),
            (TOKEN_LINK, Lists(), TOKEN, 'UUMU'),
            (
              TOKEN_LINK,
              Lists(denyRead: [VAULT], allowRead: [TOKEN]),
              TOKEN,
              'RUMU',
            ),
            (join(VAULT_LINK, 'v1', 'token'), Lists(), TOKEN, 'UUMU'),
            (join(VAULT_LINK, 'v1', 'token'), Lists(), SIBLING, 'RRRR'),
            (DIR, Lists(), DEEP_TOKEN, 'UU--'),
            (DIR, Lists(allowRead: [DIR]), DEEP_TOKEN, 'RU--'),
            (DIR, Lists(allowRead: [DEEP]), DEEP_TOKEN, 'RU--'),
            (DIR, Lists(allowRead: [DEEP_TOKEN]), DEEP_TOKEN, 'RU--'),
            (
              DIR,
              Lists(allowRead: [join(DIR_LINK, 'deep')]),
              DEEP_TOKEN,
              'RU--',
            ),
            (
              DIR,
              Lists(allowRead: [join(DIR_LINK, 'deep', '*')]),
              DEEP_TOKEN,
              'RU--',
            ),
            (DIR, Lists(allowRead: [DIR_LINK]), DEEP_TOKEN, 'UU--'),
            (DIR, Lists(allowWrite: [DIR]), DEEP_TOKEN, '${W}U--'),
            (DIR, Lists(allowWrite: [DEEP]), DEEP_TOKEN, '${W}U--'),
            (DIR, Lists(allowWrite: [VAULT]), DEEP_TOKEN, 'UU--'),
            (
              DIR,
              Lists(allowWrite: [DIR_LINK]),
              join(DIR_LINK, 'deep/token'),
              'UU--',
            ),
            (
              DIR,
              Lists(denyRead: [VAULT], allowRead: [DIR_LINK]),
              join(DIR_LINK, 'deep/token'),
              'UU--',
            ),
            (
              DIR,
              Lists(denyRead: [VAULT], allowRead: [VAULT]),
              DEEP_TOKEN,
              'UU--',
            ),
            (
              DIR,
              Lists(denyRead: [VAULT], allowRead: [DEEP]),
              DEEP_TOKEN,
              'RU--',
            ),
            (
              DIR,
              Lists(denyRead: [VAULT], allowWrite: [DEEP]),
              DEEP_TOKEN,
              '${W}U--',
            ),
            (DIR_LINK, Lists(), DEEP_TOKEN, 'UU--'),
            (DIR_LINK, Lists(allowRead: [DEEP]), DEEP_TOKEN, 'RU--'),
            (
              LINKED_DIR,
              Lists(allowRead: [join(LINKED_DIR, 'deep')]),
              DEEP_TOKEN,
              'RU--',
            ),
            (
              join(LINKED_DIR, 'deep'),
              Lists(denyRead: [VAULT_LINK], allowRead: [LINKED_DIR]),
              DEEP_TOKEN,
              'UU--',
            ),
            (join(VAULT, '**', '.netrc'), Lists(), NETRC, 'UU--'),
            (
              join(VAULT, '**', '.netrc'),
              Lists(allowRead: [NETRC]),
              NETRC,
              'RU--',
            ),
            (
              join(VAULT, '**', '.netrc'),
              Lists(allowRead: [SUB]),
              NETRC,
              'UU--',
            ),
            (
              join(VAULT, '**', '.netrc'),
              Lists(allowWrite: [NETRC]),
              NETRC,
              'UU--',
            ),
            (join(VAULT_LINK, '**', '.netrc'), Lists(), NETRC, 'UU--'),
          ];

          for (final (entry, lists, file, states) in rows) {
            KINDS.asMap().forEach((i, kind) {
              final state = states[i];
              if (state == '-') return;
              final name = '$kind $entry ${jsonEncode(lists)}: $file $state';
              test(short(name), () async {
                final wrapped = await SandboxManager.wrapWithSandbox(
                  // 'ran' tells a command that read nothing from one that never ran.
                  "echo ran; cat '$file'",
                  null,
                  _partial(configOf(kind, entry, lists)),
                );
                final stdout = stdoutOf(wrapped);
                if (state == 'R') {
                  expect(stdout, 'ran\n$CONTENT');
                } else if (state == 'M' && isLinux) {
                  expect(stdout, matches(RegExp(r'^ran\nfake_value_')));
                } else {
                  expect(stdout, 'ran\n');
                }
              });
            });
          }

          // Linux: an older bubblewrap refuses the mount this makes on /dev/null.
          for (final (kind, entry) in <(Kind, String)>[
            ('denyRead', NULL_LINK),
            ('credential deny', NULL_LINK),
            ('credential mask', NULL_LINK),
            ('denyRead', DEV_LINK),
            ('denyRead', join(DEV_LINK, '*')),
          ]) {
            test(
              '$kind on a link to a device leaves the device: $entry',
              () async {
                final wrapped = await SandboxManager.wrapWithSandbox(
                  'echo ran; cat /dev/null && echo read; cat < /dev/null && echo opened',
                  null,
                  _partial(configOf(kind, entry, Lists())),
                );
                expect(stdoutOf(wrapped), 'ran\nread\nopened\n');
              },
              skip: isMacOS ? null : 'macOS only',
            );
          }

          test(
            'the lists of the session rank as those of one command',
            () async {
              for (final (kind, stdout) in <(Kind, String)>[
                ('denyRead', 'ran\n$CONTENT'),
                ('credential deny', 'ran\n'),
              ]) {
                await SandboxManager.reset();
                await SandboxManager.initialize(
                  _full(configOf(kind, TOKEN, Lists(allowRead: [TOKEN]))),
                );
                expect(
                  stdoutOf(
                    await SandboxManager.wrapWithSandbox(
                      "echo ran; cat '$TOKEN'",
                    ),
                  ),
                  stdout,
                );
              }
            },
          );
        },
      );

      group(
        'what a command moves',
        skip: isLinux || isMacOS ? null : 'requires Linux or macOS',
        () {
          final BOX = join(ROOT, 'box');
          final OUT = join(ROOT, 'out');

          setUpAll(() async {
            await SandboxManager.reset();
            await SandboxManager.initialize(
              SandboxRuntimeConfig(network: network, filesystem: nothingListed),
            );
          });

          setUp(() {
            for (final dir in [BOX, OUT]) {
              rmSync(dir, {'recursive': true, 'force': true});
            }
            mkdirSync(join(BOX, 'dir'), {'recursive': true});
            mkdirSync(OUT);
            for (final file in ['dir/token', 'token', 'plain', '.netrc']) {
              writeFileSync(join(BOX, file), CONTENT);
            }
          });

          // In BOX: the entry, the write path, what is moved out. Then what is read
          // of it, and whether it is there.
          for (final (kind, entry, allowWrite, moved, read, arrives)
              in <(Kind, String, String, String, String, bool)>[
                ('credential deny', 'token', '', 'plain', '', true),
                ('credential deny', 'token', '', 'token', '', false),
                ('credential deny', 'token', 'token', 'token', '', false),
                ('credential mask', 'token', 'token', 'token', '', false),
                ('credential deny', 'dir', 'dir', 'dir/token', '', false),
                ('credential deny', 'dir', 'dir', 'dir', 'token', false),
                ('credential deny', 'dir', '', '', 'dir/token', false),
                ('credential deny', '**/.netrc', '.netrc', '.netrc', '', false),
              ]) {
            test(
              '$kind on ${jsonEncode(entry)}, allowWrite on ${jsonEncode(allowWrite)}: ${jsonEncode(moved)} moved out, ${jsonEncode(read)} read: $arrives',
              () async {
                final to = join(OUT, 'moved');
                final stdout = stdoutOf(
                  await SandboxManager.wrapWithSandbox(
                    "echo ran; mv '${join(BOX, moved)}' '$to'; cat '${join(to, read)}'",
                    null,
                    _partial(
                      configOf(
                        kind,
                        join(BOX, entry),
                        Lists(allowWrite: [join(BOX, allowWrite), OUT]),
                      ),
                    ),
                  ),
                );
                expect(stdout.startsWith('ran\n'), true);
                expect(stdout.contains(CONTENT), arrives);
              },
            );
          }
        },
      );

      group(
        "the library's own files",
        skip: isLinux || isMacOS ? null : 'requires Linux or macOS',
        () {
          setUpAll(() async {
            await SandboxManager.reset();
            await SandboxManager.initialize(
              SandboxRuntimeConfig(
                network: NetworkConfig(
                  allowedDomains: network.allowedDomains,
                  deniedDomains: network.deniedDomains,
                  tlsTerminate: const TlsTerminateConfig(),
                ),
                filesystem: nothingListed,
                javaAgentJarPath: JAR,
              ),
            );
          });

          Future<String> reading(String command, Kind kind, String entry) =>
              SandboxManager.wrapWithSandbox(
                command,
                null,
                _partial(configOf(kind, entry, Lists())),
              ).then(stdoutOf);

          for (final kind in ['denyRead', 'credential deny']) {
            test(
              '$kind on their folders: they are readable, what lies beside them is not',
              () async {
                final ca = SandboxManager.getMitmCA()!;
                final trustBundlePath = ca.trustBundlePath;
                final certPath = ca.certPath;
                final keyPath = ca.keyPath;
                for (final own in [trustBundlePath, certPath, JAR]) {
                  expect(
                    await reading("head -c 10 '$own'", kind, dirname(own)),
                    (readFileSync(own, 'utf8') as String).substring(0, 10),
                  );
                }
                expect(dirname(keyPath), dirname(certPath));
                expect(
                  await reading(
                    "echo ran; cat '$keyPath'",
                    kind,
                    dirname(certPath),
                  ),
                  'ran\n',
                );
              },
            );

            test(
              '$kind on a pattern that matches it: the trust bundle is readable',
              () async {
                final trustBundlePath =
                    SandboxManager.getMitmCA()!.trustBundlePath;
                expect(
                  await reading(
                    'head -c 10 "\$SSL_CERT_FILE"',
                    kind,
                    join(dirname(trustBundlePath), '*.crt'),
                  ),
                  '-----BEGIN',
                );
              },
            );
          }

          test('the debug log names none of them', () async {
            final trustBundlePath = SandboxManager.getMitmCA()!.trustBundlePath;
            final (:warnings, result: _) = await withCapturedWarnings(
              () =>
                  reading('true', 'credential deny', dirname(trustBundlePath)),
            );
            expect(
              warnings.where((w) => w.contains('not bound back')),
              <String>[],
            );
          }, skip: isLinux ? null : 'Linux only');
        },
      );

      group(
        'the configs the manager reports',
        skip: isLinux || isMacOS ? null : 'requires Linux or macOS',
        () {
          final logs = join(homedir(), '.npm', '_logs');

          for (final (kind, allowRead, listed) in <(Kind, List<String>, bool)>[
            ('denyRead', [], false),
            ('denyRead', ['~/.npm/_logs'], true),
            ('denyRead', ['~/.npm'], true),
            ('credential deny', [], false),
            ('credential deny', ['~/.npm/_logs'], false),
            ('credential deny', ['~/.npm'], false),
          ]) {
            test(
              '$kind ~/.npm, allowRead ${jsonEncode(allowRead)}: ~/.npm/_logs a default write path: $listed',
              () async {
                await SandboxManager.reset();
                await SandboxManager.initialize(
                  _full(configOf(kind, '~/.npm', Lists(allowRead: allowRead))),
                );
                final allowOnly = SandboxManager.getFsWriteConfig().allowOnly;
                expect(allowOnly.contains(logs), listed);
              },
            );
          }

          test('lists what a credential pattern expands to', () async {
            await SandboxManager.reset();
            await SandboxManager.initialize(
              _full(
                configOf(
                  'credential deny',
                  join(VAULT, '**', '.netrc'),
                  Lists(denyRead: [V1]),
                ),
              ),
            );
            final read = SandboxManager.getFsReadConfig();
            expect(read.denyOnly, [V1, NETRC]);
            expect(read.credentialDenyOnly, [NETRC]);
          }, skip: isLinux ? null : 'Linux only');
        },
      );

      group('bubblewrap mounts', skip: isLinux ? null : 'Linux only', () {
        setUpAll(() async {
          await SandboxManager.reset();
          await SandboxManager.initialize(
            SandboxRuntimeConfig(network: network, filesystem: nothingListed),
          );
        });

        Future<String> wrap(Kind kind, String entry, Lists lists) =>
            SandboxManager.wrapWithSandbox(
              'true',
              null,
              _partial(configOf(kind, entry, lists)),
            );

        test(
          'a file deny is mounted after the folder above it is bound back',
          () async {
            for (final kind in ['denyRead', 'credential deny']) {
              final wrapped = await wrap(
                kind,
                TOKEN,
                Lists(denyRead: [VAULT], allowRead: [V1]),
              );
              final boundBack = indexOfMount(wrapped, ['--ro-bind', V1, V1]);
              expect(boundBack, greaterThan(-1));
              expect(
                indexOfMount(wrapped, ['--ro-bind', '/dev/null', TOKEN]),
                greaterThan(boundBack),
              );
            }
          },
        );

        test(
          'an allowRead on a denied file decides its last mount by the kind of deny',
          () async {
            final lists = Lists(allowRead: [TOKEN]);
            expect(
              lastMountAt(await wrap('denyRead', TOKEN, lists), TOKEN),
              isNull,
            );
            expect(
              lastMountAt(await wrap('credential deny', TOKEN, lists), TOKEN),
              '--ro-bind /dev/null $TOKEN',
            );
          },
        );

        test(
          'a denied folder binds an allowRead file back by the kind of deny on the file',
          () async {
            final lists = Lists(denyRead: [VAULT], allowRead: [TOKEN]);
            for (final (kind, binds) in <(Kind, int)>[
              ('denyRead', 1),
              ('credential deny', 0),
            ]) {
              final wrapped = await wrap(kind, TOKEN, lists);
              expect(countMounts(wrapped, ['--tmpfs', VAULT]), 1);
              expect(countMounts(wrapped, ['--ro-bind', TOKEN, TOKEN]), binds);
            }
          },
        );

        Future<int> boundBack(Kind kind, String entry, Lists lists) async =>
            countMounts(await wrap(kind, entry, lists), [
              '--ro-bind',
              DEEP,
              DEEP,
            ]);

        // However the directory and the path beneath it are spelled, and whether
        // or not a denied folder lies around them.
        for (final entry in [DIR, DIR_LINK]) {
          for (final deep in [DEEP, join(DIR_LINK, 'deep')]) {
            for (final denyRead in <List<String>>[
              [],
              [VAULT],
            ]) {
              final where = short(
                '$entry, $deep, denyRead [${denyRead.join(',')}]',
              );

              test('read paths beneath a denied directory: $where', () async {
                final lists = Lists(denyRead: denyRead, allowRead: [deep]);
                expect(await boundBack('denyRead', entry, lists), 1);
                expect(await boundBack('credential deny', entry, lists), 0);
              });
            }
          }

          test(
            'write paths beneath a denied directory: ${short(entry)}',
            () async {
              for (final denyRead in <List<String>>[
                [],
                [VAULT],
              ]) {
                final lists = Lists(denyRead: denyRead, allowWrite: [DEEP]);
                final tmpfs = denyRead.isEmpty ? DIR : denyRead[0];
                final plain = await wrap('denyRead', entry, lists);
                expect(
                  lastIndexOfMount(plain, ['--bind', DEEP, DEEP]),
                  greaterThan(indexOfMount(plain, ['--tmpfs', tmpfs])),
                );
                final credential = await wrap('credential deny', entry, lists);
                expect(countMounts(credential, ['--bind', DEEP, DEEP]), 1);
                expect(
                  indexOfMount(credential, ['--bind', DEEP, DEEP]),
                  lessThan(indexOfMount(credential, ['--tmpfs', tmpfs])),
                );
              }
            },
          );
        }

        for (final lists in <Lists>[
          Lists(allowRead: [DEEP]),
          Lists(allowWrite: [DEEP]),
          Lists(allowRead: [DEEP, V1], allowWrite: [DEEP, V1]),
        ]) {
          test(
            'the debug log names once a path at or beneath a credential deny: ${jsonEncode(lists)}',
            () async {
              for (final (kind, lines) in <(Kind, List<String>)>[
                ('denyRead', []),
                (
                  'credential deny',
                  [
                    '[SandboxDebug] [Sandbox Linux] $DEEP is at or beneath the credential deny $DIR: not bound back',
                  ],
                ),
              ]) {
                final (:warnings, result: _) = await withCapturedWarnings(
                  () => wrap(kind, DIR_LINK, lists),
                );
                expect(warnings.where((w) => w.contains('not bound back')), [
                  ...lines,
                ]);
              }
            },
          );
        }

        test('an entry on the root takes its exceptions by its kind', () async {
          final top = await wrap('denyRead', '/', Lists(allowRead: ['/usr']));
          expect(countMounts(top, ['--tmpfs', '/usr']), 0);
          final inner = await wrap(
            'denyRead',
            '/',
            Lists(allowRead: ['/usr/bin']),
          );
          expect(countMounts(inner, ['--tmpfs', '/usr']), 1);
          expect(countMounts(inner, ['--ro-bind', '/usr/bin', '/usr/bin']), 1);

          for (final allowRead in [
            ['/usr'],
            ['/usr/bin'],
          ]) {
            final wrapped = await wrap(
              'credential deny',
              '/',
              Lists(allowRead: allowRead),
            );
            expect(countMounts(wrapped, ['--tmpfs', '/usr']), 1);
            expect(
              countMounts(wrapped, ['--ro-bind', allowRead[0], allowRead[0]]),
              0,
            );
          }
        });
      });

      // Profile text only, so it runs on every POSIX host.
      group('Seatbelt profile', () {
        String profileOf(
          FsReadRestrictionConfig readConfig, {
          List<String>? allowWrite,
          String? masked,
        }) => wrapCommandWithSandboxMacOS(
          MacOSSandboxParams(
            command: 'true',
            needsNetworkRestriction: false,
            readConfig: readConfig,
            writeConfig: allowWrite == null
                ? null
                : FsWriteRestrictionConfig(
                    allowOnly: allowWrite,
                    denyWithinAllow: [],
                  ),
            maskedFileBinds: masked != null
                ? [MaskedFileBind(realPath: masked, fakePath: '/fakes/0')]
                : [],
          ),
        );

        /** The file-read* denies that come after the allowRead rule. */
        String lateDenies(String profile) {
          final allowAt = profile.indexOf('(allow file-read*\n');
          expect(allowAt, greaterThan(-1));
          return profile.substring(
            allowAt,
            profile.indexOf('(allow file-read-metadata'),
          );
        }

        /** Whether a filter of the first file-read* rule of `action` matches. */
        bool Function(String profile, String file) firstRule(String action) =>
            (String profile, String file) {
              final at = profile.indexOf('($action file-read*\n');
              return profile
                  .substring(at, profile.indexOf('(with message', at))
                  .split('\n')
                  .any((line) {
                    final m = RegExp(
                      r'^ {2}\((subpath|regex) (".*")\)$',
                    ).firstMatch(line);
                    final kind = m?.group(1);
                    final text = m?.group(2);
                    if (text == null) return false;
                    final value = jsonDecode(text) as String;
                    return kind == 'regex'
                        ? RegExp(value).hasMatch(file)
                        : isAtOrUnder(file, value);
                  });
            };
        final denies = firstRule('deny');
        final allows = firstRule('allow');

        /** The trailing file-write-unlink deny rule, or '' when there is none. */
        String unlinkDenies(
          FsReadRestrictionConfig readConfig,
          List<String> allowWrite, [
          String? masked,
        ]) {
          final profile = profileOf(
            readConfig,
            allowWrite: allowWrite,
            masked: masked,
          );
          final at = profile.indexOf('; File read: keep read-denied');
          return at < 0 ? '' : profile.substring(at);
        }

        FsReadRestrictionConfig asCredential(FsReadRestrictionConfig config) =>
            FsReadRestrictionConfig(
              denyOnly: config.denyOnly,
              allowWithinDeny: config.allowWithinDeny,
              literalDenyOnly: config.literalDenyOnly,
              literalAllowWithinDeny: config.literalAllowWithinDeny,
              credentialDenyOnly: config.denyOnly,
              ownAllowWithinDeny: config.ownAllowWithinDeny,
              unlistableDenyDirs: config.unlistableDenyDirs,
            );

        for (final allow in [
          '/vault/v1/token',
          '/vault/v1/*',
          '/vault/v1/token/part',
        ]) {
          test(
            'a literal deny beside an allow on $allow comes after it by its kind',
            () {
              final config = FsReadRestrictionConfig(
                denyOnly: ['/vault/v1/token'],
                allowWithinDeny: [allow],
              );
              const filter =
                  '(deny file-read*\n  (subpath "/vault/v1/token")\n';
              expect(lateDenies(profileOf(config)), isNot(contains(filter)));
              expect(
                lateDenies(profileOf(asCredential(config))),
                contains(filter),
              );
            },
          );
        }

        test(
          'a credential deny on a name with brackets comes after the allows as that name',
          () {
            expect(
              lateDenies(
                profileOf(
                  asCredential(
                    FsReadRestrictionConfig(
                      denyOnly: [BRACKETS_TOKEN],
                      allowWithinDeny: [join(BRACKETS, '*')],
                    ),
                  ),
                ),
              ),
              contains('  (subpath "$BRACKETS_TOKEN")\n'),
            );
          },
        );

        test(
          'a pattern deny has an allow it covers subtracted by its kind',
          () {
            final config = FsReadRestrictionConfig(
              denyOnly: ['/vault/**/.netrc'],
              allowWithinDeny: ['/vault/sub/.netrc'],
            );
            const carved = '(require-not (subpath "/vault/sub/.netrc"))';
            expect(lateDenies(profileOf(config)), contains(carved));
            final late = lateDenies(profileOf(asCredential(config)));
            expect(
              late,
              contains(
                r'  (regex "^/vault/(.*/)?\\.netrc(/.*)?$")'
                '\n',
              ),
            );
            expect(late, isNot(contains(carved)));
          },
        );

        test('a masked file is denied after the allows', () {
          expect(
            lateDenies(
              profileOf(
                FsReadRestrictionConfig(
                  denyOnly: [],
                  allowWithinDeny: ['/vault/v1/token'],
                ),
                masked: '/vault/v1/token',
              ),
            ),
            contains('(deny file-read*\n  (subpath "/vault/v1/token")\n'),
          );
        });

        test("the library's own files are subtracted from a credential deny", () {
          const bundle = '/tmp-x/srt-ca-1/trust-bundle.crt';
          final late = lateDenies(
            profileOf(
              asCredential(
                FsReadRestrictionConfig(
                  denyOnly: ['/tmp-x', '/tmp-x/**/*.crt', '/elsewhere'],
                  allowWithinDeny: ['/tmp-x/other', bundle],
                  ownAllowWithinDeny: [bundle],
                ),
              ),
            ),
          );
          const minusBundle = ' (require-not (subpath "$bundle")))\n';
          expect(
            late,
            contains('  (require-all (subpath "/tmp-x")$minusBundle'),
          );
          expect(
            late,
            contains(
              '  (require-all (regex "^/tmp-x/(.*/)?[^/]*\\\\.crt(/.*)?\$")$minusBundle',
            ),
          );
          expect(late, contains('  (subpath "/elsewhere")\n'));
          expect(
            late,
            isNot(contains('(require-not (subpath "/tmp-x/other"))')),
          );
        });

        test('a deny is emitted under both spellings of its path', () {
          for (final as_
              in <FsReadRestrictionConfig Function(FsReadRestrictionConfig)>[
                (c) => c,
                asCredential,
              ]) {
            final profile = profileOf(
              as_(
                FsReadRestrictionConfig(
                  denyOnly: [
                    TOKEN_LINK,
                    join(VAULT_LINK, 'dir'),
                    join(VAULT_LINK, '**', '.netrc'),
                    join(BRACKETS_LINK, '*'),
                    ROOT_LINK,
                  ],
                ),
              ),
            );
            for (final file in [
              TOKEN_LINK,
              TOKEN,
              DEEP_TOKEN,
              NETRC,
              BRACKETS_TOKEN,
            ]) {
              expect(denies(profile, file), true);
            }
            expect(denies(profile, SIBLING), false);
          }
        });

        for (final entry in [
          NULL_LINK,
          DEV_LINK,
          join(DEV_LINK, '*'),
          join(DEV_LINK, 'null'),
        ]) {
          test(
            'a deny on a link to a device is one on the link alone: $entry',
            () {
              for (final as_
                  in <
                    FsReadRestrictionConfig Function(FsReadRestrictionConfig)
                  >[(c) => c, asCredential]) {
                final config = as_(FsReadRestrictionConfig(denyOnly: [entry]));
                expect(denies(profileOf(config), '/dev/null'), false);
                expect(
                  denies(profileOf(config), join(DEV_LINK, 'null')),
                  entry != NULL_LINK,
                );
                expect(unlinkDenies(config, [ROOT]), isNot(contains('"/dev')));
              }
              expect(
                denies(
                  profileOf(FsReadRestrictionConfig(denyOnly: [NULL_LINK])),
                  NULL_LINK,
                ),
                true,
              );
            },
          );
        }

        test('a masked link to a device is denied as the link alone', () {
          final profile = profileOf(
            FsReadRestrictionConfig(denyOnly: []),
            masked: NULL_LINK,
          );
          expect(denies(profile, NULL_LINK), true);
          expect(denies(profile, '/dev/null'), false);
        });

        test('a masked file is denied under both spellings of its path', () {
          final profile = profileOf(
            FsReadRestrictionConfig(denyOnly: []),
            masked: TOKEN_LINK,
          );
          expect(denies(profile, TOKEN_LINK), true);
          expect(denies(profile, TOKEN), true);
        });

        for (final (allow, file, matches_) in <(String, String, bool)>[
          (join(LINKED_DIR, 'deep'), join(LINKED_DIR, 'deep', 'token'), true),
          (join(LINKED_DIR, 'deep'), DEEP_TOKEN, true),
          (join(LINKED_DIR, 'deep', '*'), DEEP_TOKEN, true),
          (join(DIR_LINK, '*'), DEEP, true),
          (join(BRACKETS_LINK, '*'), BRACKETS_TOKEN, true),
          (DIR_LINK, DEEP_TOKEN, false),
          (TOKEN_LINK, TOKEN, false),
          (join(ROOT_LINK, '*'), ROOT, false),
        ]) {
          test(
            'an allow is emitted under both spellings of its name: $allow, $file: $matches_',
            () {
              final profile = profileOf(
                FsReadRestrictionConfig(
                  denyOnly: [VAULT],
                  allowWithinDeny: [allow],
                ),
              );
              expect(allows(profile, file), matches_);
            },
          );
        }

        test(
          'both spellings of an allow count against the denies around it',
          () {
            final nested = FsReadRestrictionConfig(
              denyOnly: [DEEP],
              allowWithinDeny: [LINKED_DIR],
            );
            expect(
              lateDenies(profileOf(nested)),
              contains('  (subpath "$DEEP")\n'),
            );

            String minus(String allow) => '(require-not (subpath "$allow"))';
            final covered = FsReadRestrictionConfig(
              denyOnly: [join(VAULT, '**', 'token')],
              allowWithinDeny: [join(LINKED_DIR, 'deep', 'token')],
            );
            expect(lateDenies(profileOf(covered)), contains(minus(DEEP_TOKEN)));
            expect(unlinkDenies(covered, [VAULT]), contains(minus(DEEP_TOKEN)));
            expect(
              unlinkDenies(
                FsReadRestrictionConfig(
                  denyOnly: [DIR],
                  allowWithinDeny: [join(LINKED_DIR, 'deep')],
                ),
                [VAULT],
              ),
              contains(minus(DEEP)),
            );

            final own = join(VAULT_LINK, 'v1', 'sibling');
            expect(
              lateDenies(
                profileOf(
                  asCredential(
                    FsReadRestrictionConfig(
                      denyOnly: [VAULT],
                      allowWithinDeny: [own],
                      ownAllowWithinDeny: [own],
                    ),
                  ),
                ),
              ),
              contains(
                '  (require-all (subpath "$VAULT") ${minus(SIBLING)})\n',
              ),
            );
          },
        );

        for (final (deny, filter, inside) in <(String, String, String)>[
          ('/work/dir', '(subpath "/work/dir")', '/work/dir/token'),
          (
            '/work/**/.netrc',
            r'(regex "^/work/(.*/)?\\.netrc(/.*)?$")',
            '/work/sub/.netrc',
          ),
        ]) {
          test(
            'what a deny on $deny covers in a write root is kept in place, with exceptions by its kind',
            () {
              for (final lists
                  in <
                    ({List<String> allowWithinDeny, List<String> allowWrite})
                  >[
                    (allowWithinDeny: [inside], allowWrite: ['/work']),
                    (allowWithinDeny: [], allowWrite: ['/work', inside]),
                  ]) {
                final config = FsReadRestrictionConfig(
                  denyOnly: [deny],
                  allowWithinDeny: lists.allowWithinDeny,
                );
                final plain = unlinkDenies(config, lists.allowWrite);
                expect(
                  plain,
                  contains(
                    '  (require-all $filter (require-not (subpath "$inside")))\n',
                  ),
                );
                expect(plain, isNot(contains('(literal "/work")')));
                final credential = unlinkDenies(
                  asCredential(config),
                  lists.allowWrite,
                );
                expect(credential, contains('  $filter\n'));
                expect(credential, contains('  (literal "/work")\n'));
                expect(credential, isNot(contains('require-not')));
              }
            },
          );
        }

        test(
          'a deny at or above a write root is kept in place by its kind',
          () {
            for (final allowWrite in ['/vault/dir', '/vault/dir/cache']) {
              final config = FsReadRestrictionConfig(denyOnly: ['/vault/dir']);
              expect(unlinkDenies(config, [allowWrite]), '');
              expect(
                unlinkDenies(asCredential(config), [allowWrite]),
                contains('  (subpath "/vault/dir")\n'),
              );
            }
            expect(
              unlinkDenies(FsReadRestrictionConfig(denyOnly: []), [
                '/vault/token',
              ], '/vault/token'),
              contains('  (subpath "/vault/token")\n'),
            );
          },
        );
      });
    },
  );
}
