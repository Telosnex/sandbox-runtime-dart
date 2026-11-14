// Ported from sandbox-runtime test/cli.test.ts @ 0bbebed.
import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:path/path.dart' show join;
import 'package:test/test.dart';

import 'package:sandbox_runtime/src/node/child_process.dart'
    show spawn, spawnSync;
import 'package:sandbox_runtime/src/node/fs.dart'
    show mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync;
import 'package:sandbox_runtime/src/node/os.dart' show tmpdir;
import 'package:sandbox_runtime/src/node/process.dart' as process;
import 'helpers/platform.dart' show isLinux;

/**
 * Get the path to the CLI entry point
 */
String getCliPath() {
  return join(process.cwd(), 'bin', 'srt.dart');
}

/**
 * Run the CLI with given arguments and return the result
 */
({String stdout, String stderr, int? status}) runCli(
  List<String> args, {
  String? input,
  bool? debug,
  String? home,
}) {
  final env = <String, String>{
    ...process.env,
    // Default to a non-existent config to get default behavior; `home`
    // points the default settings path at a directory the test set up.
    'HOME': home ?? '/tmp/cli-test-nonexistent',
    // Enable SRT_DEBUG if debug option is set
    ...(debug == true ? {'SRT_DEBUG': 'true'} : {}),
  };
  // npm exports npm_package_version to its lifecycle scripts, so it is set
  // whenever the suite runs under `npm test`. The CLI under test is a `srt`
  // binary a user installed, which has no such variable.
  env.remove('npm_package_version');
  // Dart: `bun run src/cli.ts` is the Dart VM running bin/srt.dart.
  final result = spawnSync(
    Platform.resolvedExecutable,
    [
      '--packages=${join(process.cwd(), '.dart_tool', 'package_config.json')}',
      getCliPath(),
      ...args,
    ],
    {'encoding': 'utf-8', 'input': input, 'env': env},
  );
  return (
    stdout: result.stdout as String,
    stderr: result.stderr as String,
    status: result.status,
  );
}

void main() {
  group('CLI', () {
    group('--version', () {
      test('reports the version in the package manifest', () {
        // Dart: the manifest is pubspec.yaml, not package.json.
        final manifest = (
          version: RegExp(r'^version:\s*(\S+)', multiLine: true).firstMatch(
            readFileSync(join(process.cwd(), 'pubspec.yaml'), 'utf-8')
                as String,
          )![1]!,
        );
        final result = runCli(['--version']);
        expect(result.stdout.trim(), manifest.version);
        expect(result.status, 0);
      });
    });

    group('-c flag (command string mode)', () {
      test('executes simple command with -c flag', () {
        final result = runCli(['-c', 'echo hello']);
        expect(result.stdout.trim(), 'hello');
        expect(result.status, 0);
      });

      test('passes command string directly without escaping', () {
        final result = runCli(['-c', 'echo "hello world"']);
        expect(result.stdout.trim(), 'hello world');
        expect(result.status, 0);
      });

      test('handles JSON arguments correctly', () {
        // This is the main use case - JSON with quotes and special chars
        final result = runCli(['-c', 'echo \'{"key": "value"}\'']);
        expect(result.stdout.trim(), '{"key": "value"}');
        expect(result.status, 0);
      });

      test('handles complex JSON with nested objects', () {
        final json = '{"servers":{"name":"test","type":"sdk"}}';
        final result = runCli(['-c', "echo '$json'"]);
        expect(result.stdout.trim(), json);
        expect(result.status, 0);
      });

      test('handles shell expansion in -c mode', () {
        final result = runCli(['-c', 'echo \$HOME']);
        // $HOME should be expanded by the shell
        expect(result.stdout.trim(), isNot(r'$HOME'));
        expect(result.status, 0);
      });

      test('handles pipes in -c mode', () {
        final result = runCli(['-c', 'echo "hello world" | wc -w']);
        expect(result.stdout.trim(), '2');
        expect(result.status, 0);
      });

      test('handles command substitution in -c mode', () {
        final result = runCli(['-c', 'echo "count: \$(echo 1 2 3 | wc -w)"']);
        expect(result.stdout.trim(), contains('3'));
        expect(result.status, 0);
      });
    });

    group('default mode (positional arguments)', () {
      test('executes simple command with positional args', () {
        final result = runCli(['echo', 'hello']);
        expect(result.stdout.trim(), 'hello');
        expect(result.status, 0);
      });

      test('joins multiple positional arguments with spaces', () {
        final result = runCli(['echo', 'hello', 'world']);
        expect(result.stdout.trim(), 'hello world');
        expect(result.status, 0);
      });

      test('handles arguments with flags', () {
        final result = runCli(['echo', '-n', 'no newline']);
        // -n flag to echo suppresses newline
        expect(result.stdout, 'no newline');
        expect(result.status, 0);
      });

      test('preserves argument boundaries when args contain spaces', () {
        // Regression for #157: positional args are later run via `bash -c`,
        // so they must be shell-quoted. printf '%s\n' emits one line per
        // arg, which exposes whether "hello world" arrived as one token
        // (correct) or was re-split into "hello" and "world".
        final result = runCli(['printf', '%s\n', 'hello world', 'a b']);
        expect(result.stdout, 'hello world\na b\n');
        expect(result.status, 0);
      });

      test('preserves shell metacharacters in positional args', () {
        // Positional mode is argv-style; metacharacters in an arg are data,
        // not shell syntax (use -c for shell semantics).
        final result = runCli(['printf', '%s', r'$HOME;|&']);
        expect(result.stdout, r'$HOME;|&');
        expect(result.status, 0);
      });
    });

    group('error handling', () {
      test('shows error when no command specified', () {
        final result = runCli([]);
        expect(result.stderr, contains('No command specified'));
        expect(result.status, 1);
      });

      test('shows error when only options provided without command', () {
        final result = runCli(['-d']);
        expect(result.stderr, contains('No command specified'));
        expect(result.status, 1);
      });
    });

    group('--settings error handling', () {
      // The CLI must fail closed when an explicitly requested settings file
      // cannot be used: silently falling back to the default config would run
      // the command without the restrictions the caller asked for (e.g. the
      // credentials deny rules).
      test(
        'refuses to run when an explicit --settings file does not exist',
        () {
          final result = runCli([
            '--settings',
            '/nonexistent/srt-settings.json',
            'echo',
            'should-not-run',
          ]);
          expect(result.status, 1);
          expect(result.stderr, contains('does not exist'));
          expect(result.stderr, contains('--settings asked for'));
          expect(result.stdout, isNot(contains('should-not-run')));
        },
      );

      test(
        'refuses to run when an explicit --settings file fails validation',
        () {
          final dir = mkdtempSync(join(tmpdir(), 'srt-cli-settings-'));
          final settingsPath = join(dir, 'invalid.json');
          // Valid JSON, but missing required network/filesystem fields
          writeFileSync(settingsPath, jsonEncode({'network': {}}));
          try {
            final result = runCli([
              '--settings',
              settingsPath,
              'echo',
              'should-not-run',
            ]);
            expect(result.status, 1);
            expect(result.stderr, contains('does not hold a valid config'));
            expect(result.stdout, isNot(contains('should-not-run')));
          } finally {
            rmSync(dir, {'recursive': true, 'force': true});
          }
        },
      );
    });

    group('default settings file error handling', () {
      // Same rule for the default ~/.srt-settings.json: it is optional, but
      // one that is there and does not load must not fall through to the
      // built-in defaults, which are a different config rather than a weaker
      // one — falling back would drop every rule the file did hold.
      void withHome(void Function(String home) run) {
        final home = mkdtempSync(join(tmpdir(), 'srt-cli-home-'));
        try {
          run(home);
        } finally {
          rmSync(home, {'recursive': true, 'force': true});
        }
      }

      test(
        'refuses to run when the default settings file fails validation',
        () {
          withHome((home) {
            // Valid JSON, but missing required network/filesystem fields
            writeFileSync(
              join(home, '.srt-settings.json'),
              jsonEncode({'network': {}}),
            );
            final result = runCli(['echo', 'should-not-run'], home: home);
            expect(result.status, 1);
            expect(result.stderr, contains('does not hold a valid config'));
            // Names the key that failed, so the file can be fixed from the
            // message alone.
            expect(result.stderr, contains('filesystem'));
            expect(result.stdout, isNot(contains('should-not-run')));
          });
        },
      );

      test('refuses to run when the default settings file is empty', () {
        withHome((home) {
          // A file truncated to nothing: falling back to the defaults here
          // would drop rules that were in force before the truncation.
          writeFileSync(join(home, '.srt-settings.json'), '');
          final result = runCli(['echo', 'should-not-run'], home: home);
          expect(result.status, 1);
          expect(result.stderr, contains('is empty'));
          expect(result.stdout, isNot(contains('should-not-run')));
        });
      });

      test(
        'refuses to run when the default settings file is whitespace only',
        () {
          withHome((home) {
            writeFileSync(join(home, '.srt-settings.json'), '   \n\t  ');
            final result = runCli(['echo', 'should-not-run'], home: home);
            expect(result.status, 1);
            expect(result.stderr, contains('is empty'));
            expect(result.stdout, isNot(contains('should-not-run')));
          });
        },
      );

      test('refuses to run when the default settings path cannot be read', () {
        withHome((home) {
          // A directory where the file should be: readFileSync fails with
          // EISDIR, which is not "no settings file" and must not be treated
          // as one.
          mkdirSync(join(home, '.srt-settings.json'));
          final result = runCli(['echo', 'should-not-run'], home: home);
          expect(result.status, 1);
          expect(result.stderr, contains('could not be read'));
          expect(result.stderr, contains('EISDIR'));
          expect(result.stdout, isNot(contains('should-not-run')));
        });
      });

      test(
        'runs with the built-in defaults when there is no settings file',
        () {
          withHome((home) {
            final result = runCli(['echo', 'no-settings-file'], home: home);
            expect(result.status, 0);
            expect(result.stdout, contains('no-settings-file'));
          });
        },
      );
    });

    group('debug output', () {
      test('SRT_DEBUG enables debug output for positional args', () {
        final result = runCli(['echo', 'test'], debug: true);
        // Debug mode should show additional logging to stderr
        expect(result.stderr, contains('[SandboxDebug]'));
        expect(result.stderr, contains('Original command'));
        expect(result.status, 0);
      });

      test('SRT_DEBUG enables debug output for -c mode', () {
        final result = runCli(['-c', 'echo test'], debug: true);
        expect(result.stderr, contains('[SandboxDebug]'));
        expect(result.stderr, contains('Command string mode'));
        expect(result.status, 0);
      });

      test('no debug output without SRT_DEBUG', () {
        final result = runCli(['echo', 'test'], debug: false);
        expect(result.stderr, isNot(contains('[SandboxDebug]')));
        expect(result.status, 0);
      });

      test('--debug flag enables debug output (without SRT_DEBUG env)', () {
        // Regression for #174: the flag must set the same env var the logger
        // reads. Exercise the flag alone — runCli's {debug:true} option sets
        // SRT_DEBUG directly, which would mask the bug.
        final result = runCli(['--debug', 'echo', 'test']);
        expect(result.stderr, contains('[SandboxDebug]'));
        expect(result.status, 0);
      });
    });

    group(
      'an interrupt before the command has started',
      skip: isLinux ? false : 'requires Linux',
      () {
        for (final (when_, lastLine) in [
          // The library's handlers are in place, and there is more to wait for.
          ('the sandbox is being initialized', 'Starting HTTP bridge'),
          // The last thing the CLI says before it wraps the command.
          ('the command is being wrapped', 'Original command'),
        ]) {
          test('stops the run while $when_, and the command is not run', () async {
            // Enough directories for the walk of the pattern to outlast the signal.
            final root = mkdtempSync(join(tmpdir(), 'cli-interrupt-'));
            try {
              for (var i = 0; i < 200; i++) {
                for (var j = 0; j < 100; j++) {
                  mkdirSync(join(root, 'tree', 'd$i', 'e$j'), {
                    'recursive': true,
                  });
                }
              }
              final settings = join(root, 'settings.json');
              writeFileSync(
                settings,
                jsonEncode({
                  'network': {'allowedDomains': [], 'deniedDomains': []},
                  'filesystem': {
                    'denyRead': [join(root, 'tree', '**/*.pem')],
                    'allowWrite': [],
                    'denyWrite': [],
                  },
                }),
              );
              final child = spawn(
                Platform.resolvedExecutable,
                [
                  '--packages=${join(process.cwd(), '.dart_tool', 'package_config.json')}',
                  getCliPath(),
                  '-s',
                  settings,
                  'echo',
                  'RAN',
                ],
                {
                  'env': {...process.env, 'SRT_DEBUG': 'true'},
                },
              );
              var stdout = '';
              var stderr = '';
              var signalled = false;
              // Dart: stdout and stderr are Streams, not emitters.
              child.stdout!.listen((chunk) => stdout += utf8.decode(chunk));
              child.stderr!.listen((chunk) {
                stderr += utf8.decode(chunk);
                if (!signalled && stderr.contains(lastLine)) {
                  signalled = true;
                  child.kill('SIGINT');
                }
              });
              final exited = Completer<Object?>();
              child.on('exit', exited.complete);
              final status = await exited.future;

              expect(signalled, isTrue);
              expect(stderr, contains('interrupted by SIGINT'));
              expect(stdout, isNot(contains('RAN')));
              expect(status, 1);
            } finally {
              rmSync(root, {'recursive': true, 'force': true});
            }
          }, timeout: Timeout(Duration(milliseconds: 60000)));
        }
      },
    );
  });
}
