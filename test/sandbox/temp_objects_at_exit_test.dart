// Ported from sandbox-runtime test/sandbox/temp-objects-at-exit.test.ts @ 0bbebed.
// ignore_for_file: constant_identifier_names, non_constant_identifier_names

import 'dart:convert';
import 'dart:io';

import 'package:path/path.dart' as path;
import 'package:test/test.dart';

import '../helpers/platform.dart';

// Committed test-only CA — see test/fixtures/tls-terminate/README.md.
final FIXTURE_DIR = path.join(
  Directory.current.path,
  'test',
  'fixtures',
  'tls-terminate',
);
const TIMEOUT_MS = 60000;

// Dart: the child runs a Dart script (there is no `node -e`); it wraps the
// library's SandboxManager so the upstream `start`/`ending` snippets keep
// their shape, taking the configuration as a map.
const _PRELUDE = r'''
import 'dart:convert';
import 'dart:io';

import 'package:sandbox_runtime/src/node/process.dart' as process;
import 'package:sandbox_runtime/src/sandbox/sandbox_config.dart';
import 'package:sandbox_runtime/src/sandbox/sandbox_manager.dart' as real;

class _Manager {
  Future<void> initialize(
    Map<String, Object?> config, [
    Object? ask,
    bool? enableLogMonitor,
  ]) async {
    final parsed = SandboxRuntimeConfigSchema.safeParse(config);
    if (!parsed.success) throw StateError('${parsed.error!.issues}');
    await real.SandboxManager.initialize(parsed.data!, null, enableLogMonitor);
  }

  Future<String> wrapWithSandbox(String command) =>
      real.SandboxManager.wrapWithSandbox(command);

  Future<void> reset() => real.SandboxManager.reset();
}

final SandboxManager = _Manager();
''';

/// reset() is asynchronous and a process 'exit' handler is not waited for, so
/// a host that ends with process.exit() gets no further than reset()'s first
/// await. What the library put in the temp directory must be gone all the same.
void main() {
  group(
    'temp objects when the process ends',
    skip: (isLinux || isMacOS) ? false : 'requires Linux or macOS',
    () {
      late String BASE;
      late String TMP; // the child's temp directory, and nobody else's

      setUp(() {
        BASE = Directory.systemTemp.createTempSync('srt-exit-').path;
        TMP = path.join(BASE, 't');
        Directory(TMP).createSync();
        File(path.join(BASE, 'token')).writeAsStringSync('dummy\n');
        // A bridge that never removes its own socket. Whether the real one does
        // is a matter of timing, which would leave the outcome to chance.
        File(path.join(BASE, 'socat')).writeAsStringSync(
          '#!/bin/sh\nexec socat "\$1,unlink-close=0" "\$2"\n',
        );
        Process.runSync('chmod', ['755', path.join(BASE, 'socat')]);
      });

      tearDown(() {
        final base = Directory(BASE);
        if (base.existsSync()) base.deleteSync(recursive: true);
      });

      List<String> readdirSync(String dir) => [
        for (final e in Directory(dir).listSync(followLinks: false))
          path.basename(e.path),
      ];

      /// The library's objects among `names`, by kind: `srt-ca-Ab12Cd` is an `srt-ca`.
      List<String> kinds(List<String> names) => [
        for (final name in names)
          ...switch (RegExp(r'^(srt|claude)-[a-z]+').firstMatch(name)) {
            final m? => [m[0]!],
            null => <String>[],
          },
      ]..sort();

      const START = '''await SandboxManager.initialize(config);
      await SandboxManager.wrapWithSandbox('true');''';

      /// Runs a process that initializes with `tlsTerminate` and wraps a command
      /// (or runs another `start`), and then runs `ending`. Returns what the
      /// library has in its temp directory just before `ending`, and once the
      /// process is gone.
      ({List<String> before, List<String> after}) endWith(
        String ending, [
        Map<String, String> tlsTerminate = const {},
        String start = START,
      ]) {
        final script =
            '''
$_PRELUDE
Future<void> main() async {
      final config = <String, Object?>{
        'network': {
          'allowedDomains': ['example.com'],
          'deniedDomains': [],
          'tlsTerminate': ${jsonEncode(tlsTerminate)},
        },
        'filesystem': {'denyRead': [], 'allowWrite': [], 'denyWrite': []},
        'credentials': {
          'files': [{'path': ${jsonEncode(path.join(BASE, 'token'))}, 'mode': 'mask'}],
        },
        'socatPath': ${jsonEncode(path.join(BASE, 'socat'))},
      };
      $start
      print(jsonEncode(Directory(${jsonEncode(TMP)}).listSync().map((e) => e.uri.pathSegments.where((s) => s.isNotEmpty).last).toList()));
      $ending
}''';
        final scriptPath = path.join(BASE, 'child.dart');
        File(scriptPath).writeAsStringSync(script);
        final result = Process.runSync(
          Platform.resolvedExecutable,
          [
            '--packages=${path.join(Directory.current.path, '.dart_tool', 'package_config.json')}',
            scriptPath,
          ],
          workingDirectory: BASE,
          environment: {
            ...Platform.environment,
            'TMPDIR': TMP,
            'SRT_DEBUG': '',
          },
          stdoutEncoding: utf8,
          stderrEncoding: utf8,
        );
        expect(result.stderr, '');
        expect(result.exitCode, 0);
        return (
          before: kinds(
            (jsonDecode((result.stdout as String).trim().split('\n').last)
                    as List)
                .cast<String>(),
          ),
          after: kinds(readdirSync(TMP)),
        );
      }

      // The bridge's socket, the trust bundle, the masked credential file, the
      // proxy's socket.
      final ALWAYS = [
        if (isLinux) 'claude-http',
        'srt-ca',
        'srt-credmask',
        'srt-mux',
      ];

      for (final (why0, ending) in [
        ('without reset()', 'process.exit(0);'),
        ('with reset() under way', 'SandboxManager.reset(); process.exit(0);'),
        ('after reset()', 'await SandboxManager.reset(); process.exit(0);'),
      ]) {
        test('are all gone when it exits $why0', () {
          final (:before, :after) = endWith(ending);

          // The second `srt-ca` holds the generated CA and its private key.
          expect(before, [...ALWAYS, 'srt-ca']..sort());
          expect(after, <String>[]);
        }, timeout: const Timeout(Duration(milliseconds: TIMEOUT_MS)));
      }

      /// An initialize() that is rejected after it has made its CA.
      String rejected(String args) =>
          'await SandboxManager.initialize($args).then<void>((_) => process.exit(3), onError: (Object _) {});';
      final NO_BWRAP = rejected(
        "{...config, 'bwrapPath': '/nonexistent/bwrap'}",
      );

      // Both fail before anything is registered to run at 'exit'.
      for (final (why, start) in [
        ('a dependency is missing', NO_BWRAP),
        (
          'the violation monitor cannot start',
          rejected(
            "{...config, 'filesystem': {...(config['filesystem'] as Map<String, Object?>), 'denyWrite': [{'path': '/x'}]}}, null, true",
          ),
        ),
      ]) {
        test(
          'are gone as soon as initialize() fails because $why',
          () {
            final result = endWith('process.exit(0);', {}, start);
            expect(result.before, <String>[]);
            expect(result.after, <String>[]);
          },
          skip: !isLinux,
          timeout: const Timeout(Duration(milliseconds: TIMEOUT_MS)),
        );
      }

      for (final (why0, start, expectedBefore)
          in <(String, String, List<String>)>[
            ('', START, [...ALWAYS, 'srt-ca']..sort()),
            if (isLinux) (' after a failed initialize()', NO_BWRAP, ['srt-ca']),
          ]) {
        test(
          'do not include a CA pair the configuration names, whatever it is called$why0',
          () {
            final theirs = path.join(TMP, 'srt-ca-theirs');
            Directory(theirs).createSync();
            for (final file in ['ca.crt', 'ca.key']) {
              File(
                path.join(FIXTURE_DIR, file),
              ).copySync(path.join(theirs, file));
            }

            final (:before, :after) = endWith('process.exit(0);', {
              'caCertPath': path.join(theirs, 'ca.crt'),
              'caKeyPath': path.join(theirs, 'ca.key'),
            }, start);

            expect(before, expectedBefore);
            expect(after, ['srt-ca']);
            expect(readdirSync(theirs)..sort(), ['ca.crt', 'ca.key']);
          },
          timeout: const Timeout(Duration(milliseconds: TIMEOUT_MS)),
        );
      }
    },
  );
}
