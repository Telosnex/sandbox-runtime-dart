// Ported from sandbox-runtime test/sandbox/default-write-paths.test.ts @ 0bbebed.
// ignore_for_file: constant_identifier_names, non_constant_identifier_names, slash_for_doc_comments
import 'dart:convert';
import 'dart:io' as io;

import 'package:path/path.dart' show join;
import 'package:sandbox_runtime/src/node/child_process.dart'
    show SpawnSyncResult, spawnSync;
import 'package:sandbox_runtime/src/node/fs.dart' as fs;
import 'package:sandbox_runtime/src/node/os.dart' show homedir, tmpdir;
import 'package:sandbox_runtime/src/sandbox/sandbox_config.dart'
    show
        CredentialFileConfig,
        CredentialsConfig,
        FilesystemConfig,
        FilesystemPathEntry,
        FilesystemPathSpelling,
        NetworkConfig,
        SandboxRuntimeConfig;
import 'package:sandbox_runtime/src/sandbox/sandbox_manager.dart';
import 'package:sandbox_runtime/src/sandbox/sandbox_utils.dart'
    show getDefaultWritePaths, isAtOrUnder;
import 'package:test/test.dart';

import '../helpers/platform.dart' show isLinux, isMacOS, isWindows;

// Dart: the tests run from the package root; upstream's join(import.meta.dir, '../..').
final REPO_ROOT = io.Directory.current.path;
const NPM_LOGS = '.npm/_logs';
const CLAUDE_DEBUG = '.claude/debug';
const SANDBOX_OWN = [
  '/dev/stdout',
  '/dev/stderr',
  '/dev/null',
  '/dev/tty',
  '/dev/dtracehelper',
  '/dev/autofs_nowait',
  '/tmp/claude',
  '/private/tmp/claude',
];

// Dart: the config takes path entries, not bare strings.
List<FilesystemPathEntry> _entries(List<String> paths) => [
  for (final p in paths) FilesystemPathSpelling(p),
];

// Dart: the runtime that stands in for upstream's `node`, `bun` and
// process.execPath, which run TypeScript/JavaScript.
final String _execPath = io.Platform.resolvedExecutable;

// Dart: upstream hands `-e script` to the runtime; a Dart program cannot, so
// the script is written to a file and run with this package's package config.
SpawnSyncResult _spawnScript(
  String runtime,
  String script,
  Map<String, Object?> options,
) {
  final scriptDir = fs.mkdtempSync(join(tmpdir(), 'srt-script-'));
  final scriptFile = join(scriptDir, 'script.dart');
  fs.writeFileSync(scriptFile, script);
  try {
    return spawnSync(runtime, [
      '--packages=${join(REPO_ROOT, '.dart_tool', 'package_config.json')}',
      scriptFile,
    ], options);
  } finally {
    fs.rmSync(scriptDir, {'recursive': true, 'force': true});
  }
}

/**
 * Runs `script` (an ES module body) under bun with HOME set to `fakeHome`
 * and returns the JSON it prints last. os.homedir() does not follow a HOME
 * changed at runtime, so these cases need a process of their own.
 */
Object? runWithHome(String fakeHome, String script) {
  final result = _spawnScript(_execPath, script, {
    'cwd': REPO_ROOT,
    'env': {...io.Platform.environment, 'HOME': fakeHome},
    'encoding': 'utf8',
    'timeout': 60000,
  });
  if (result.status != 0) {
    throw Exception('exit ${result.status}: ${result.stderr}');
  }
  final lines = (result.stdout as String).trim().split('\n');
  return jsonDecode(lines.isEmpty ? '' : lines.last);
}

void main() {
  /**
   * The two home directories among the default write paths are conveniences
   * the caller never asked for; one that a read-deny covers must not be bound
   * back over that deny. What the sandbox itself needs is never dropped.
   */
  group(
    'getDefaultWritePaths',
    skip: !isWindows ? null : 'describe.if(!isWindows)',
    () {
      final home = homedir();
      final npmLogs = join(home, NPM_LOGS);
      final claudeDebug = join(home, CLAUDE_DEBUG);

      test('is the whole list when given no read rules', () {
        expect(getDefaultWritePaths(), [...SANDBOX_OWN, npmLogs, claudeDebug]);
        expect(
          getDefaultWritePaths(denyRead: _entries([])),
          getDefaultWritePaths(),
        );
      });

      for (final deny in [home, '~/', '~/**', join(home, '**'), '/', '/**']) {
        test(
          'drops both home conveniences, and nothing else, under denyRead $deny',
          () {
            expect(
              getDefaultWritePaths(denyRead: _entries([deny])),
              SANDBOX_OWN,
            );
          },
        );
      }

      for (final deny in ['/tmp', '/private/tmp', '/dev']) {
        test('drops nothing under denyRead $deny', () {
          expect(
            getDefaultWritePaths(denyRead: _entries([deny])),
            getDefaultWritePaths(),
          );
        });
      }

      test('leaves nothing under a read-denied home', () {
        expect(
          getDefaultWritePaths(
            denyRead: _entries(['~']),
          ).where((p) => isAtOrUnder(p, home)).toList(),
          [],
        );
      });

      test('drops only the convenience a deny names', () {
        expect(getDefaultWritePaths(denyRead: _entries([npmLogs])), [
          ...SANDBOX_OWN,
          claudeDebug,
        ]);
      });

      for (final deny in [
        join(home, '.n*'),
        join(home, '.np?'),
        '~/.n*',
        '~/**/_logs',
      ]) {
        test('drops a convenience a glob deny reaches: $deny', () {
          // These go through the string-level denyGlobRegex, the one a caller's
          // configured spelling belongs in: every character in it is pattern.
          expect(getDefaultWritePaths(denyRead: _entries([deny])), [
            ...SANDBOX_OWN,
            claudeDebug,
          ]);
        });
      }

      test('keeps a convenience beside, not beneath, what is read-denied', () {
        expect(
          getDefaultWritePaths(
            denyRead: _entries([
              join(home, '.npmrc'),
              join(home, '.np'),
              join(home, '**/*.log'),
            ]),
          ),
          getDefaultWritePaths(),
        );
      });

      test(
        'compares an entry whose brackets are no valid class as a literal',
        () {
          expect(
            getDefaultWritePaths(
              denyRead: _entries([join(home, 'backup[2024-01-15]')]),
            ),
            getDefaultWritePaths(),
          );
        },
      );

      test('takes a pattern too large to compile as one that covers', () {
        expect(
          getDefaultWritePaths(denyRead: _entries(['/x/${'a' * (1 << 20)}*'])),
          SANDBOX_OWN,
        );
      });

      // The engines differ in when they find a pattern too large.
      for (final (name, runtime) in [('node', _execPath), ('bun', _execPath)]) {
        test('getFsWriteConfig() answers for such a pattern, in $name', () {
          final result = _spawnScript(
            runtime,
            r"""
import 'dart:convert';
import 'dart:io';
import 'package:sandbox_runtime/src/sandbox/sandbox_config.dart';
import 'package:sandbox_runtime/src/sandbox/sandbox_manager.dart';

Future<void> main() async {
  await SandboxManager.initialize(
    SandboxRuntimeConfig(
      network: NetworkConfig(allowedDomains: [], deniedDomains: []),
      filesystem: FilesystemConfig(
        denyRead: [FilesystemPathSpelling('/x/' + 'a' * (1 << 20) + '*')],
        allowWrite: [],
        denyWrite: [],
      ),
    ),
  );
  final allowOnly = SandboxManager.getFsWriteConfig().allowOnly;
  await SandboxManager.reset();
  stdout.write(jsonEncode(allowOnly));
  await stdout.flush();
  exit(0);
}
""",
            {'cwd': REPO_ROOT, 'encoding': 'utf8', 'timeout': 30000},
          );
          final stdout = result.stdout as String?;
          expect(
            [
              result.stderr,
              jsonDecode(stdout == null || stdout.isEmpty ? 'null' : stdout),
            ],
            ['', SANDBOX_OWN],
          );
        }, timeout: const Timeout(Duration(milliseconds: 60000)));
      }

      for (final c in [
        (
          name: 'an allowRead above the directory, beneath the deny',
          denyRead: ['~'],
          allowRead: ['~/.claude'],
          kept: [claudeDebug],
        ),
        (
          name: 'an allowRead of the directory itself',
          denyRead: ['~/.npm'],
          allowRead: ['~/.npm/_logs/**'],
          kept: [npmLogs, claudeDebug],
        ),
        (
          name: 'no allowRead above the deny',
          denyRead: ['~/.claude'],
          allowRead: ['~'],
          kept: [npmLogs],
        ),
        (
          name: 'no glob allowRead',
          denyRead: ['~'],
          allowRead: ['~/.c*'],
          kept: <String>[],
        ),
      ]) {
        test('counts ${c.name} as re-opening it', () {
          expect(
            getDefaultWritePaths(
              denyRead: _entries(c.denyRead),
              allowRead: _entries(c.allowRead),
            ),
            [...SANDBOX_OWN, ...c.kept],
          );
        });
      }
    },
  );

  group(
    'default write paths under another HOME',
    skip: isLinux || isMacOS ? null : 'describe.if(isLinux || isMacOS)',
    () {
      late String fakeHome;

      setUpAll(() {
        // On macOS tmpdir() is under /var, which normalizes to /private/var.
        fakeHome = fs.mkdtempSync(join(tmpdir(), 'srt-home-'));
        fs.mkdirSync(join(fakeHome, '.npm'));
        fs.mkdirSync(join(fakeHome, CLAUDE_DEBUG), {'recursive': true});
      });

      tearDownAll(() {
        fs.rmSync(fakeHome, {'recursive': true, 'force': true});
      });

      test('drops a convenience directory that does not exist yet', () {
        final paths = runWithHome(fakeHome, r"""
import 'dart:convert';
import 'package:sandbox_runtime/src/sandbox/sandbox_config.dart';
import 'package:sandbox_runtime/src/sandbox/sandbox_utils.dart';

void main() {
  print(jsonEncode(getDefaultWritePaths(denyRead: [FilesystemPathSpelling('~/.npm')])));
}
""");
        expect(paths, [...SANDBOX_OWN, join(fakeHome, CLAUDE_DEBUG)]);
      });

      /** Whether the wrapped command makes `dir` writable. */
      bool grantsWrite(String wrapped, String dir) {
        if (isLinux) return wrapped.contains('--bind $dir $dir');
        final rule = wrapped.substring(wrapped.indexOf('(allow file-write*'));
        return rule.substring(0, rule.indexOf('(with message')).contains(dir);
      }

      test('reaches getFsWriteConfig() and the wrapped command', () {
        fs.mkdirSync(join(fakeHome, NPM_LOGS), {'recursive': true});
        final out =
            runWithHome(fakeHome, r"""
import 'dart:convert';
import 'dart:io';
import 'package:sandbox_runtime/src/sandbox/sandbox_config.dart';
import 'package:sandbox_runtime/src/sandbox/sandbox_manager.dart';

Future<void> main() async {
  final filesystem = FilesystemConfig(
    denyRead: [FilesystemPathSpelling('~/.npm')],
    allowWrite: [],
    denyWrite: [],
  );
  await SandboxManager.initialize(
    SandboxRuntimeConfig(
      network: NetworkConfig(allowedDomains: [], deniedDomains: []),
      filesystem: filesystem,
      credentials: CredentialsConfig(
        files: [CredentialFileConfig(path: '~/.claude', mode: 'deny')],
      ),
    ),
  );
  final out = {
    'allowOnly': SandboxManager.getFsWriteConfig().allowOnly,
    'wrapped': await SandboxManager.wrapWithSandbox('true'),
    'reopened': await SandboxManager.wrapWithSandbox(
      'true',
      null,
      PartialSandboxRuntimeConfig(
        filesystem: FilesystemConfig(
          denyRead: filesystem.denyRead,
          allowWrite: filesystem.allowWrite,
          denyWrite: filesystem.denyWrite,
          allowRead: [FilesystemPathSpelling('~/.npm/_logs')],
        ),
      ),
    ),
  };
  await SandboxManager.reset();
  stdout.write(jsonEncode(out) + '\n');
  await stdout.flush();
  exit(0);
}
""")
                as Map<String, Object?>;
        final allowOnly = out['allowOnly'] as List;
        final wrapped = out['wrapped'] as String;
        final reopened = out['reopened'] as String;

        // A filesystem deny and a credential file deny each drop theirs.
        expect(allowOnly, SANDBOX_OWN);
        expect(grantsWrite(wrapped, join(fakeHome, NPM_LOGS)), isFalse);
        expect(grantsWrite(wrapped, join(fakeHome, CLAUDE_DEBUG)), isFalse);
        // A per-call allowRead of the directory keeps its write allow.
        expect(grantsWrite(reopened, join(fakeHome, NPM_LOGS)), isTrue);
      });

      test(
        'is covered by a denyWrite entry above it',
        skip: isLinux ? null : 'it.if(isLinux)',
        () {
          fs.mkdirSync(join(fakeHome, NPM_LOGS), {'recursive': true});
          final wrapped =
              runWithHome(fakeHome, r"""
import 'dart:convert';
import 'package:sandbox_runtime/src/sandbox/sandbox_config.dart';
import 'package:sandbox_runtime/src/sandbox/sandbox_manager.dart';

Future<void> main() async {
  print(jsonEncode(await SandboxManager.wrapWithSandbox(
    'true',
    null,
    PartialSandboxRuntimeConfig(
      filesystem: FilesystemConfig(
        denyRead: [],
        allowWrite: [],
        denyWrite: [FilesystemPathSpelling('~/.npm')],
      ),
    ),
  )));
}
""")
                  as String;

          final npm = join(fakeHome, '.npm');
          expect(grantsWrite(wrapped, join(fakeHome, NPM_LOGS)), isTrue);
          expect(
            wrapped.indexOf('--ro-bind $npm $npm'),
            greaterThan(wrapped.indexOf('--bind $npm/_logs $npm/_logs')),
          );
          expect(wrapped, isNot(contains('--ro-bind $fakeHome/.claude')));
        },
      );
    },
  );

  group(
    'getFsWriteConfig() stays a plain getter',
    skip: isLinux ? null : 'describe.if(isLinux)',
    () {
      late String dir;

      setUpAll(() {
        dir = fs.mkdtempSync(join(tmpdir(), 'srt-write-getter-'));
        fs.writeFileSync(join(dir, 'a.env'), 'A=1');
        fs.writeFileSync(join(dir, 'backup[2024-01-15].env'), 'B=2');
        fs.writeFileSync(join(dir, 'hosts.yml'), 'k: v\n');
      });

      tearDownAll(() async {
        await SandboxManager.reset();
        fs.rmSync(dir, {'recursive': true, 'force': true});
      });

      test(
        'is untouched by what a denyRead glob expands to, or by a credential mask',
        () async {
          await SandboxManager.reset();
          await SandboxManager.initialize(
            SandboxRuntimeConfig(
              network: NetworkConfig(allowedDomains: [], deniedDomains: []),
              filesystem: FilesystemConfig(
                denyRead: [FilesystemPathSpelling(join(dir, '**/*.env'))],
                allowWrite: [],
                denyWrite: [],
              ),
              credentials: CredentialsConfig(
                files: [
                  CredentialFileConfig(
                    path: join(dir, 'hosts.yml'),
                    mode: 'mask',
                    extract: 'nope: (\\S+)',
                    onExtractNoMatch: 'error',
                  ),
                ],
              ),
            ),
          );

          expect(
            SandboxManager.getFsWriteConfig().allowOnly,
            getDefaultWritePaths(),
          );
        },
      );

      test(
        'wraps when a denyRead glob matches a file name with brackets',
        () async {
          await SandboxManager.reset();
          await SandboxManager.initialize(
            SandboxRuntimeConfig(
              network: NetworkConfig(allowedDomains: [], deniedDomains: []),
              filesystem: FilesystemConfig(
                denyRead: [FilesystemPathSpelling(join(dir, '**/*.env'))],
                allowWrite: [],
                denyWrite: [],
              ),
            ),
          );

          expect(
            await SandboxManager.wrapWithSandbox('true'),
            contains(join(dir, 'backup[2024-01-15].env')),
          );
        },
      );
    },
  );
  /**
   * The getter is asked once a path, from permission checks, so what its read
   * rules compile to is kept. Only that: what it asks of the configuration and
   * of the disk it asks every time.
   */
  group('getFsWriteConfig() is asked once a path', () {
    late String base;
    setUpAll(() {
      base = fs.mkdtempSync(join(tmpdir(), 'srt-home-'));
    });
    tearDownAll(() async {
      await SandboxManager.reset();
      fs.rmSync(base, {'recursive': true, 'force': true});
    });
    /** Runs `body`, which fills `out`, under a new HOME named `name`. */
    Object? run(String name, String body) {
      final home = join(base, name);
      fs.mkdirSync(join(home, NPM_LOGS), {'recursive': true});
      return runWithHome(home, '''
import 'dart:convert';
import 'dart:io';
import 'package:sandbox_runtime/src/node/fs.dart' as fs;
import 'package:sandbox_runtime/src/sandbox/sandbox_config.dart';
import 'package:sandbox_runtime/src/sandbox/sandbox_manager.dart';
Future<void> main() async {
  final home = Platform.environment['HOME']!;
  final logs = home + '/$NPM_LOGS';
  bool logsWritable() => SandboxManager.getFsWriteConfig().allowOnly.contains(logs);
  Future<SandboxRuntimeConfig> start(Map<String, List<String>> filesystem) async {
    final config = SandboxRuntimeConfig(
      network: NetworkConfig(allowedDomains: [], deniedDomains: []),
      filesystem: FilesystemConfig(
        denyRead: (filesystem['denyRead'] ?? []).map(FilesystemPathSpelling.new).toList(),
        allowRead: filesystem['allowRead']?.map(FilesystemPathSpelling.new).toList(),
        allowWrite: (filesystem['allowWrite'] ?? []).map(FilesystemPathSpelling.new).toList(),
        denyWrite: (filesystem['denyWrite'] ?? []).map(FilesystemPathSpelling.new).toList(),
      ),
    );
    await SandboxManager.initialize(config);
    return config;
  }
  final out = [];
  $body
  await SandboxManager.reset();
  stdout.write(jsonEncode(out) + '\\n');
  await stdout.flush();
  exit(0);
}
''');
    }

    test('follows a configuration that is changed in place', () {
      expect(
        run('in-place', '''
        final config = await start({'denyRead': []});
        out.add(logsWritable());
        config.filesystem.denyRead.add(FilesystemPathSpelling('~/.np[m]'));
        out.add(logsWritable());
      '''),
        [true, false],
      );
    });
    // In a home whose name holds brackets the allowRead is a name only for as
    // long as nothing on its way is a link.
    test('follows what is on disk', () {
      expect(
        run('[h]ome', '''
        await start({'denyRead': [home + '/.npm'], 'allowRead': [logs]});
        out.add(logsWritable());
        fs.rmSync(logs, {'recursive': true});
        fs.symlinkSync(home, logs);
        out.add(logsWritable());
      '''),
        [true, false],
      );
    });
    test('reads more pattern text than it keeps', () {
      expect(
        run('much', '''
        final much = List.generate(300, (i) => '/x' + i.toString() + '/' + 'a' * 4000 + '*');
        await start({'denyRead': much});
        out.addAll([logsWritable(), logsWritable()]);
        await SandboxManager.reset();
        await start({'denyRead': [...much, '~/.np[m]', ...much.map((p) => p + 'b')]});
        out.addAll([logsWritable(), logsWritable()]);
      '''),
        [true, true, false, false],
      );
    });
    // Dart: upstream asks for 60 calls under 1,500 ms. Here that is about
    // 750 ms for `[` on a fast machine, and slow macOS CI runners took 2 s.
    // Compiling every time takes about 1,400 ms on the fast machine, so no
    // fixed limit tells the two apart on every machine. The calls are timed
    // against the same calls for 24 patterns of plain text of the same length,
    // in the same process. Measured on macOS and Linux:
    //   `[`      1.9-2.0 times plain; compiled every time, 3.4-3.5
    //   `[z-a]`  1.4-1.5 times plain; compiled every time, 2.2-2.3
    // The fastest of three rounds is kept for each.
    Future<int> sixtyCalls(String Function(int i) pattern) async {
      await SandboxManager.reset();
      await SandboxManager.initialize(
        SandboxRuntimeConfig(
          network: NetworkConfig(allowedDomains: [], deniedDomains: []),
          filesystem: FilesystemConfig(
            denyRead: List.generate(
              24,
              (i) => FilesystemPathSpelling(pattern(i)),
            ),
            allowWrite: [],
            denyWrite: [],
          ),
        ),
      );
      final began = Stopwatch()..start();
      for (var i = 0; i < 60; i++) {
        SandboxManager.getFsWriteConfig();
      }
      return began.elapsedMilliseconds;
    }

    for (final (unit, limit) in [('[', 2.6), ('[z-a]', 1.8)]) {
      test('does not compile 96 KB of $unit for every path', () async {
        var units = 1 << 62;
        var plain = 1 << 62;
        for (var round = 0; round < 3; round++) {
          final u = await sixtyCalls(
            (i) => '/x$i/${unit * (4000 ~/ unit.length)}',
          );
          final p = await sixtyCalls((i) => '/x$i/${'a' * 3999}*');
          if (u < units) units = u;
          if (p < plain) plain = p;
        }
        // Some 3 ms each. Compiled each time, 40 ms and more.
        expect(
          units / plain,
          lessThan(limit),
          reason: '$unit took $units ms, plain text $plain ms',
        );
      });
    }
  }, skip: isLinux || isMacOS ? false : 'requires Linux or macOS');
}
