// Ported from sandbox-runtime test/sandbox/rules-through-links-on-every-runtime.test.ts @ 0bbebed.
// ignore_for_file: curly_braces_in_flow_control_structures
// ignore_for_file: slash_for_doc_comments, constant_identifier_names, non_constant_identifier_names
import 'dart:convert';
import 'dart:io' as io;
import 'package:path/path.dart' show dirname, join;
import 'package:test/test.dart';
import 'package:sandbox_runtime/src/node/child_process.dart' show spawnSync;
import 'package:sandbox_runtime/src/node/errno.dart' show NodeError;
import 'package:sandbox_runtime/src/node/fs.dart' as fs;
import 'package:sandbox_runtime/src/node/os.dart' show tmpdir;
import 'package:sandbox_runtime/src/node/process.dart' as process;
import '../helpers/bwrap_namespace.dart' show bwrapCanNamespaceNetwork;
import '../helpers/platform.dart' show isLinux, isMacOS;

/**
 * A rule spelled through a link applies where the kernel leads, on every
 * runtime: these rows run the built CLI, in Node and in this one.
 *
 * In a link's target `..` is the parent of where the way has led, which
 * behind another link is not the directory the link lies in. And a target can
 * hold bytes that are no text, which no rule and no mount can spell.
 */
final _CLI_PATH = join(io.Directory.current.path, 'bin', 'srt.dart');
// Dart is the port's runtime, under both upstream runtime labels.
final _RUNTIMES = [
  (
    'node',
    [
      io.Platform.resolvedExecutable,
      '--packages=${join(io.Directory.current.path, '.dart_tool', 'package_config.json')}',
    ],
  ),
  (
    'bun',
    [
      io.Platform.resolvedExecutable,
      '--packages=${join(io.Directory.current.path, '.dart_tool', 'package_config.json')}',
    ],
  ),
];
const _APPENDED = 'appended';
final _canRun = isMacOS || (isLinux && bwrapCanNamespaceNetwork());
late String _root;

/**
 * Which of `files`, given from `root`, a command run by the CLI can read, or
 * append to, by its own account: a placeholder is gone when it has ended. The CLI is ended hard past its time, and the command runs behind
 * an `echo BOOTED`, so neither can read as a command that was refused: a
 * sandbox that is to refuse to start is said not to `boot`. What the command
 * does `first`, it does in `root`.
 */
List<String> _reach(
  List<String> argv,
  Map<String, Object?> policy,
  String does,
  List<String> files, [
  Object boots = true,
  String first = 'true',
]) {
  final settings = join(_root, 'settings.json');
  fs.writeFileSync(
    settings,
    jsonEncode({
      'network': {'allowedDomains': [], 'deniedDomains': []},
      'filesystem': {'denyRead': [], 'allowWrite': [], 'denyWrite': []},
      ...policy,
    }),
  );
  final command = [
    'echo BOOTED',
    '( $first ) 2>/dev/null',
    ...files.map(
      (file) => does == 'read'
          ? "cat '$_root/$file'"
          : "( echo $_APPENDED >> '$_root/$file' ) && echo '<$file>'",
    ),
  ].join('; ');
  final result = spawnSync(
    argv[0],
    [...argv.skip(1), _CLI_PATH, '-s', settings, '-c', command],
    {
      'encoding': 'utf8',
      'timeout': 20000,
      'killSignal': 'SIGKILL',
      'cwd': _root,
    },
  );
  final stdout = result.stdout as String;
  expect(result.error, isNull);
  if (boots != 'or not')
    expect(stdout.contains('BOOTED'), boots, reason: result.stderr as String);
  return files.where((file) => stdout.contains('<$file>')).toList();
}

Map<String, Object?> _denyRead(List<String> entries) => {
  'filesystem': {'denyRead': entries, 'allowWrite': [], 'denyWrite': []},
};
Map<String, Object?> _denyWrite(String entry) => {
  'filesystem': {
    'denyRead': [],
    'allowWrite': [_root],
    'denyWrite': [entry],
  },
};

void main() {
  setUp(() {
    _root = fs.realpathSync(fs.mkdtempSync(join(tmpdir(), 'links-up-')));
    for (final file in [
      'here/file',
      'elsewhere/file',
      'elsewhere/in/other',
      'elsewhere/down/in/file',
    ]) {
      fs.mkdirSync(dirname(join(_root, file)), {'recursive': true});
      fs.writeFileSync(join(_root, file), '<$file>');
    }
    fs.symlinkSync('../elsewhere/in', join(_root, 'here/link'));
    fs.symlinkSync('link/../file', join(_root, 'here/up'));
    fs.symlinkSync('link/../down/in', join(_root, 'here/down'));
  });
  tearDown(() {
    fs.rmSync(_root, {'recursive': true, 'force': true});
  });

  for (final (runtime, argv) in _RUNTIMES) {
    group(
      'a rule through a link whose target goes up from behind a link, in $runtime',
      () {
        final files = ['elsewhere/file', 'elsewhere/down/in/file', 'here/file'];
        List<String> but(String file) =>
            files.where((other) => other != file).toList();
        test('denyRead of a file refuses the file the kernel finds there', () {
          expect(
            _reach(argv, _denyRead([join(_root, 'here/up')]), 'read', files),
            but('elsewhere/file'),
          );
        }, timeout: const Timeout(Duration(seconds: 60)));
        test('a credentials deny refuses the file the kernel finds there', () {
          final credentials = {
            'files': [
              {'path': join(_root, 'here/up'), 'mode': 'deny'},
            ],
          };
          expect(
            _reach(argv, {'credentials': credentials}, 'read', files),
            but('elsewhere/file'),
          );
        }, timeout: const Timeout(Duration(seconds: 60)));
        test(
          'denyRead of a directory hides the directory the kernel finds there',
          () {
            expect(
              _reach(
                argv,
                _denyRead([join(_root, 'here/down')]),
                'read',
                files,
              ),
              but('elsewhere/down/in/file'),
            );
          },
          timeout: const Timeout(Duration(seconds: 60)),
        );
        test(
          'a command that goes up from behind a link is held where the kernel leads',
          () {
            _reach(argv, _denyWrite(join(_root, 'elsewhere/down')), 'append', [
              'here/link/../down/in/file',
              'here/link/../file',
            ]);
            expect(
              fs.readFileSync(join(_root, 'elsewhere/down/in/file'), 'utf8'),
              '<elsewhere/down/in/file>',
            );
            expect(
              fs.readFileSync(join(_root, 'elsewhere/file'), 'utf8'),
              contains(_APPENDED),
            );
          },
          timeout: const Timeout(Duration(seconds: 60)),
        );
        // Only bubblewrap is handed what a pattern finds, and only its write
        // denies are followed through a link.
        test(
          'a denyRead pattern refuses what it reaches through the link',
          () {
            expect(
              _reach(
                argv,
                _denyRead([join(_root, 'here/**/file')]),
                'read',
                files,
              ),
              ['elsewhere/file'],
            );
          },
          skip: isLinux ? null : 'requires Linux',
          timeout: const Timeout(Duration(seconds: 60)),
        );
        for (final (entry, kept) in [
          ('here/up', 'elsewhere/file'),
          ('here/down/file', 'elsewhere/down/in/file'),
        ]) {
          test(
            'denyWrite of $entry keeps $kept as it is',
            () {
              expect(
                _reach(argv, _denyWrite(join(_root, entry)), 'append', files),
                but(kept),
              );
            },
            skip: isLinux ? null : 'requires Linux',
            timeout: const Timeout(Duration(seconds: 60)),
          );
        }
        for (final (what, target) in [
          ('up', 'link/../made'),
          ('up and down again', 'link/../down/made'),
        ]) {
          test(
            'denyWrite of a link that leads $what to what is not there keeps it from being made',
            () {
              fs.symlinkSync(target, join(_root, 'here/new'));
              expect(
                _reach(argv, _denyWrite(join(_root, 'here/new')), 'append', [
                  'here/new',
                  ...files,
                ]),
                files,
              );
            },
            skip: isLinux ? null : 'requires Linux',
            timeout: const Timeout(Duration(seconds: 60)),
          );
        }
      },
      skip: _canRun ? false : 'requires macOS or Linux bwrap network namespace',
    );
  }

  // macOS lets no such name be made.
  for (final (runtime, argv) in _RUNTIMES) {
    group('a rule through a link to a name that is no text, in $runtime', () {
      final files = ['here/to-bytes/file', 'bytes-\uFFFD/file'];
      setUp(() {
        final bytes = [...utf8.encode('bytes-'), 0xff];
        fs.mkdirSync([...utf8.encode('$_root/'), ...bytes]);
        fs.mkdirSync(join(_root, 'bytes-\uFFFD'));
        fs.symlinkSync([
          ...utf8.encode('../'),
          ...bytes,
        ], join(_root, 'here/to-bytes'));
        for (final file in files) {
          fs.writeFileSync(join(_root, file), '<$file>');
        }
      });
      test(
        'denyRead keeps the file the kernel finds there from being read',
        () {
          final policy = {
            'filesystem': {
              'denyRead': [join(_root, files[0])],
              'allowWrite': [_root],
              'denyWrite': [],
            },
          };
          // Whether a mount can be put on the spelling is bubblewrap's to say:
          // 0.12 cannot, and then nothing runs.
          expect(
            _reach(argv, policy, 'read', files, 'or not'),
            isNot(contains(files[0])),
          );
        },
        timeout: const Timeout(Duration(seconds: 60)),
      );
      test(
        'denyWrite of a link to what is not there yet keeps it from being made',
        () {
          fs.symlinkSync([
            ...utf8.encode('../elsewhere/'),
            0xff,
          ], join(_root, 'here/new'));
          // Whether a mount can be put on the link itself is bubblewrap's to say.
          expect(
            _reach(argv, _denyWrite(join(_root, 'here/new')), 'append', [
              'here/new',
            ], 'or not'),
            [],
          );
        },
        timeout: const Timeout(Duration(seconds: 60)),
      );
      for (final name in ['file', 'not-there']) {
        test(
          'denyWrite of $name there lets nothing run that could write it',
          () {
            final file = 'here/to-bytes/$name';
            expect(
              _reach(argv, _denyWrite(join(_root, file)), 'append', [
                file,
              ], false),
              [],
            );
          },
          timeout: const Timeout(Duration(seconds: 60)),
        );
      }
    }, skip: isLinux && _canRun ? false : 'requires Linux bwrap network namespace');
  }

  /**
   * A way can be cut short at a name that is not there: a directory a target
   * lacks, a link on the way that is missing or dangles in its turn. Whoever
   * makes that name decides where the way goes on, so it is what is held.
   */
  for (final (runtime, argv) in _RUNTIMES) {
    group('a write deny on a link whose way is cut short, in $runtime', () {
      const bytes = r'''"$(printf 'n\377')"''';
      for (final (what, links, first)
          in <(String, Map<String, String>, String)>[
            (
              'the directories a dangling hop lacks',
              {'hop': 'lacking/in', 'name': 'hop/../made'},
              'mkdir -p lacking/in',
            ),
            (
              'a hop that is not there, as a link',
              {'name': 'hop/../made'},
              'ln -s elsewhere/in hop',
            ),
            (
              'a hop that is not there, as a directory',
              {'name': 'hop/../made'},
              'mkdir hop',
            ),
            (
              'what a dangling hop leads to, as a link',
              {'hop': 'lacking', 'name': 'hop/../made'},
              'ln -s elsewhere/in lacking',
            ),
            (
              'what the second of two dangling hops lacks',
              {'hop': 'second/x', 'second': 'lacking/y', 'name': 'hop/made'},
              'mkdir -p lacking/y/x',
            ),
            (
              'what the third of three dangling hops lacks',
              {
                'hop': 'second/x',
                'second': 'third/y',
                'third': 'lacking/z',
                'name': 'hop/../made',
              },
              'mkdir -p lacking/z/y/x',
            ),
            (
              'a name that a built-in deny holds as a directory',
              {'name': '.claude/../made'},
              'true',
            ),
          ]) {
        test('holds when the command makes $what', () {
          for (final link in links.entries) {
            fs.symlinkSync(link.value, join(_root, link.key));
          }
          expect(
            _reach(
              argv,
              _denyWrite(join(_root, 'name')),
              'append',
              ['name', 'here/file'],
              true,
              first,
            ),
            ['here/file'],
          );
        }, timeout: const Timeout(Duration(seconds: 60)));
      }
      test('holds where a hop leads out of the write root', () {
        fs.symlinkSync('../../lacking/in', join(_root, 'here/hop'));
        fs.symlinkSync('hop/made', join(_root, 'here/name'));
        final policy = {
          'filesystem': {
            'denyRead': [],
            'allowWrite': [join(_root, 'here')],
            'denyWrite': [join(_root, 'here/name')],
          },
        };
        expect(
          _reach(
            argv,
            policy,
            'append',
            ['here/name', 'here/file'],
            true,
            'mkdir -p lacking/in',
          ),
          ['here/file'],
        );
      }, timeout: const Timeout(Duration(seconds: 60)));
      test(
        'lets nothing run that could write it where a hop leads to a name that is no text',
        () {
          fs.symlinkSync([
            ...utf8.encode('n'),
            0xff,
            ...utf8.encode('/in'),
          ], join(_root, 'hop'));
          fs.symlinkSync('hop/../made', join(_root, 'name'));
          expect(
            _reach(
              argv,
              _denyWrite(join(_root, 'name')),
              'append',
              ['name'],
              false,
              'mkdir -p $bytes/in',
            ),
            [],
          );
        },
        timeout: const Timeout(Duration(seconds: 60)),
      );
      // root searches a directory of any mode.
      test(
        'holds a directory that is shut at the wrap, mode and all',
        () {
          fs.mkdirSync(join(_root, 'shut/in'), {'recursive': true});
          fs.symlinkSync('shut/in/made', join(_root, 'name'));
          fs.chmodSync(join(_root, 'shut'), 0);
          try {
            expect(
              _reach(
                argv,
                _denyWrite(join(_root, 'name')),
                'append',
                ['name', 'shut/in/made', 'here/file'],
                true,
                'chmod 755 shut || { mv shut aside && mkdir -p shut/in; }',
              ),
              ['here/file'],
            );
          } finally {
            fs.chmodSync(join(_root, 'shut'), 493);
          }
        },
        skip: process.getuid?.call() != 0
            ? null
            : 'root searches a directory of any mode.',
        timeout: const Timeout(Duration(seconds: 60)),
      );
      final anothers = ['/etc/ssl/private', '/var/lib/private', '/root'].where((
        dir,
      ) {
        try {
          fs.accessSync(dir, fs.constants.X_OK);
          return false;
        } catch (error) {
          return error is NodeError && error.code == 'EACCES';
        }
      }).firstOrNull;
      for (final name in ['.mcp.json', '.vscode', 'name']) {
        test(
          'starts where $name is a link into a directory another user keeps shut',
          () {
            fs.symlinkSync('$anothers/in/made', join(_root, name));
            expect(
              _reach(argv, _denyWrite(join(_root, 'name')), 'append', [
                name,
                'here/file',
              ]),
              ['here/file'],
            );
          },
          skip: anothers != null ? null : 'no inaccessible directory',
          timeout: const Timeout(Duration(seconds: 60)),
        );
      }
      test(
        'starts where such a directory lies in a write path, too',
        () {
          fs.symlinkSync('$anothers/in/made', join(_root, 'name'));
          final filesystem = {
            'denyRead': [],
            'allowWrite': ['/'],
            'denyWrite': [join(_root, 'name')],
          };
          expect(
            _reach(
              argv,
              {'filesystem': filesystem},
              'append',
              ['name', 'here/file'],
            ),
            ['here/file'],
          );
        },
        skip: anothers != null ? null : 'no inaccessible directory',
        timeout: const Timeout(Duration(seconds: 60)),
      );
      test(
        'leaves the rest of the project to a command where a built-in deny is a link to what is not built yet',
        () {
          fs.symlinkSync('build/vscode', join(_root, '.vscode'));
          expect(
            _reach(
              argv,
              _denyWrite(join(_root, 'not-there')),
              'append',
              [
                '.vscode/settings.json',
                'build/vscode/settings.json',
                'here/file',
              ],
              true,
              'mkdir -p build/vscode',
            ),
            ['here/file'],
          );
        },
        timeout: const Timeout(Duration(seconds: 60)),
      );
    }, skip: isLinux && _canRun ? false : 'requires Linux bwrap network namespace');
  }
}
