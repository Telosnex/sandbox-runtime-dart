// Ported from sandbox-runtime test/sandbox/path-canonicalization.test.ts @ 24eb39e.
// ignore_for_file: non_constant_identifier_names
import 'dart:convert';
import 'dart:io';

import 'package:path/path.dart' as path;
import 'package:test/test.dart';

import 'package:sandbox_runtime/src/sandbox/macos_sandbox_utils.dart';
import 'package:sandbox_runtime/src/sandbox/sandbox_schemas.dart';
import 'package:sandbox_runtime/src/sandbox/sandbox_utils.dart'
    show normalizePathForSandbox;

///
/// Interior non-canonical spellings.
///
/// realpath canonicalises a path that exists, so '/a//b' and '/a/./b' only
/// reach the backends verbatim when their target is absent — which for a deny
/// is the case the deny is for (a credential file that appears later). Seatbelt
/// then compares the kernel's canonical path, so such a filter matches nothing,
/// silently. '..' is left to realpath: folding it lexically can aim the rule
/// past a symlink at a file the kernel would never reach.
///

/// An absent path under a real directory, so no realpath can rescue a spelling
/// under it and its own spelling is fixed. `scratch` is the working directory
/// the child processes below run in.
late String _ABSENT;
late String _absentRoot;
late String _scratch;

///
/// normalizePathForSandbox in a child with $HOME set to `home`: $HOME is read
/// once at start-up, so it cannot be changed in this process. The environment
/// is scrubbed so the parent's SRT_DEBUG does not put sandbox debug output on
/// the child's stderr.
///
Map<String, Object?> _normalizeWithHome(String home, List<String> patterns) {
  final script = File(path.join(_scratch, 'normalize-with-home.dart'));
  script.writeAsStringSync("""
import 'dart:convert';
import 'dart:io';
import 'package:sandbox_runtime/src/node/os.dart' as os;
import 'package:sandbox_runtime/src/sandbox/sandbox_utils.dart' as m;
void main() {
  // Pending port: src/sandbox/linux-sandbox-utils.ts. Upstream runs
  // wrapCommandWithSandboxLinux here on Linux and tests its argv for
  // ' --bind / / '; until then the caller skips that check on Linux.
  const argv = '';
  stdout.writeln(jsonEncode({
    'homedir': os.homedir(),
    'results': ${jsonEncode(patterns)}.map((p) => m.normalizePathForSandbox(p)).toList(),
    'tildeBindsRoot': RegExp(r' --bind \\/ \\/ ').hasMatch(argv),
  }));
}
""");
  final child = Process.runSync(
    Platform.resolvedExecutable,
    [
      '--packages=${path.join(Directory.current.path, '.dart_tool', 'package_config.json')}',
      script.path,
    ],
    stdoutEncoding: utf8,
    stderrEncoding: utf8,
    environment: {'PATH': Platform.environment['PATH'] ?? '', 'HOME': home},
    includeParentEnvironment: false,
    // Its own directory: the Linux wrap scans the working directory and may
    // leave mount-point stubs there, which this process would not clean up.
    workingDirectory: _scratch,
  );
  expect(child.exitCode, 0, reason: '${child.stderr}');
  expect(child.stderr, '');
  return jsonDecode(child.stdout as String) as Map<String, Object?>;
}

String _captureWarning(String pattern) {
  final script = File(path.join(_scratch, 'capture-sandbox-warning.dart'));
  script.writeAsStringSync('''
import 'package:sandbox_runtime/src/sandbox/sandbox_utils.dart'
    show normalizePathForSandbox;
void main(List<String> args) => normalizePathForSandbox(args.single);
''');
  final result = Process.runSync(
    Platform.resolvedExecutable,
    [
      '--packages=${path.join(Directory.current.path, '.dart_tool', 'package_config.json')}',
      script.path,
      pattern,
    ],
    workingDirectory: _scratch,
    environment: {...Platform.environment, 'SRT_DEBUG': '1'},
    stdoutEncoding: utf8,
    stderrEncoding: utf8,
  );
  expect(result.exitCode, 0, reason: '${result.stdout}\n${result.stderr}');
  expect(result.stdout, '');
  return result.stderr as String;
}

void main() {
  setUpAll(() {
    _absentRoot = Directory.systemTemp
        .createTempSync('srt-absent-')
        .resolveSymbolicLinksSync();
    _ABSENT = path.join(_absentRoot, 'no-such-dir');
    _scratch = Directory.systemTemp
        .createTempSync('srt-scratch-')
        .resolveSymbolicLinksSync();
  });

  tearDownAll(() {
    Directory(_absentRoot).deleteSync(recursive: true);
    Directory(_scratch).deleteSync(recursive: true);
  });

  group(
    'normalizePathForSandbox interior spellings',
    skip: Platform.isWindows ? 'not POSIX' : false,
    () {
      test('collapses slash runs, "." components and the trailing run', () {
        expect(normalizePathForSandbox('$_ABSENT//x'), '$_ABSENT/x');
        expect(normalizePathForSandbox('$_ABSENT///x'), '$_ABSENT/x');
        expect(normalizePathForSandbox('$_ABSENT/./x'), '$_ABSENT/x');
        expect(normalizePathForSandbox('$_ABSENT/././x'), '$_ABSENT/x');
        expect(normalizePathForSandbox('$_ABSENT/x/.'), '$_ABSENT/x');
        expect(normalizePathForSandbox('$_ABSENT/.//x//'), '$_ABSENT/x');
        // A leading '//' is collapsed with the rest: POSIX allows an
        // implementation to treat it specially, neither backend does.
        expect(normalizePathForSandbox('/$_ABSENT/x'), '$_ABSENT/x');
        // Nothing collapses to the empty string.
        expect(normalizePathForSandbox('//'), '/');
        expect(normalizePathForSandbox('/.'), '/');
      });

      test('leaves a dot-file segment alone', () {
        // The '/.' drop is gated on a following '/', so a name that merely starts
        // with a dot, and '...', survive.
        expect(
          normalizePathForSandbox('$_ABSENT/.ssh/id_rsa'),
          '$_ABSENT/.ssh/id_rsa',
        );
        expect(normalizePathForSandbox('$_ABSENT/.../b'), '$_ABSENT/.../b');
        expect(normalizePathForSandbox('$_ABSENT/.*/x'), '$_ABSENT/.*/x');
      });

      test('keeps a ".." component in an absent path verbatim', () {
        expect(
          normalizePathForSandbox('$_ABSENT/sub/../x'),
          '$_ABSENT/sub/../x',
        );
        // Including in a glob spelling, which returns before the realpath below.
        expect(
          normalizePathForSandbox('$_ABSENT/sub/../*.pem'),
          '$_ABSENT/sub/../*.pem',
        );
      });

      test('says so when a glob spelling keeps an unfoldable ".."', () {
        // The glob branch returns before the realpath below, so this line is the
        // only notice that the compiled rule may match nothing. It names the
        // spelling that reaches the backend, not the one the caller passed.
        final logged = _captureWarning('$_ABSENT//sub/../*.pem');
        expect(logged, contains('$_ABSENT/sub/../*.pem'));
        expect(logged, isNot(contains('$_ABSENT//')));
      });

      test('collapses the interior of a glob spelling too', () {
        expect(normalizePathForSandbox('$_ABSENT//x/*'), '$_ABSENT/x/*');
        expect(
          normalizePathForSandbox('$_ABSENT/./x/*.pem'),
          '$_ABSENT/x/*.pem',
        );
        expect(normalizePathForSandbox('$_ABSENT//**/x'), '$_ABSENT/**/x');
        expect(normalizePathForSandbox('//**/x'), '/**/x');
      });

      test('keeps what is semantic in a glob spelling', () {
        // A slash after a glob segment compiles to a different regex, and a '**'
        // segment is left as it is.
        expect(normalizePathForSandbox('$_ABSENT/x/*/'), '$_ABSENT/x/*/');
        expect(
          normalizePathForSandbox('$_ABSENT/**/*.pem'),
          '$_ABSENT/**/*.pem',
        );
      });

      test('canonicalises a home directory spelled with a trailing slash', () {
        // `ENV HOME=/root/` in a Dockerfile is enough to reintroduce the slash:
        // the strip runs before expansion, so '~/x' would otherwise reach the
        // backends as '/root//x'.
        final created = Directory.systemTemp.createTempSync('srt-home-');
        try {
          final home = created.resolveSymbolicLinksSync();
          final result = _normalizeWithHome('$home/', [
            '~',
            '~/x',
            '~/x/*.key',
          ]);
          expect(result['results'], [home, '$home/x', '$home/x/*.key']);
        } finally {
          created.deleteSync(recursive: true);
        }
      }, timeout: const Timeout(Duration(seconds: 30)));

      test(
        'does not expand a tilde into the filesystem root under an empty HOME',
        () {
          // An empty $HOME makes homedir(), and so expandTilde('~'), empty; '' must
          // not fall through to '/' here or at the Linux backend's own trailing-run
          // strip, either of which turns `allowWrite: ['~']` into a whole-filesystem
          // write grant. Only a runtime whose homedir() honours an empty $HOME
          // reaches that at all: node does, bun falls back to the passwd entry.
          final result = _normalizeWithHome('', ['~']);
          final results = result['results']! as List<Object?>;
          expect(results[0], isNot('/'));
          expect(results[0], result['homedir']);
          expect(result['tildeBindsRoot'], false);
        },
        timeout: const Timeout(Duration(seconds: 30)),
        skip: Platform.isLinux
            ? 'pending port: src/sandbox/linux-sandbox-utils.ts'
            : false,
      );
    },
  );

  group(
    'macOS profile: interior spellings',
    skip: Platform.isWindows ? 'not POSIX' : false,
    () {
      test('emits the canonical subpath for an absent slash-run deny', () {
        final profile = wrapCommandWithSandboxMacOS(
          MacOSSandboxParams(
            command: 'true',
            needsNetworkRestriction: false,
            readConfig: FsReadRestrictionConfig(
              denyOnly: ['$_ABSENT/a//b'],
              allowWithinDeny: [],
            ),
            writeConfig: null,
          ),
        );
        expect(profile, contains('(subpath "$_ABSENT/a/b")'));
        expect(profile, isNot(contains('$_ABSENT/a//b')));
      });

      test(
        'compiles a deny glob spelled with a slash run like the clean one',
        () {
          String profileFor(String deny) => wrapCommandWithSandboxMacOS(
            MacOSSandboxParams(
              command: 'true',
              needsNetworkRestriction: false,
              readConfig: FsReadRestrictionConfig(
                denyOnly: [deny],
                allowWithinDeny: [],
              ),
              writeConfig: null,
            ),
          );

          final spelled = profileFor('$_ABSENT/a//*.pem');
          expect(spelled, profileFor('$_ABSENT/a/*.pem'));
          expect(spelled, isNot(contains('$_ABSENT/a//')));
        },
      );
    },
  );
}
