// Ported from sandbox-runtime test/sandbox/macos-literal-deny-brackets.test.ts @ 24eb39e.
import 'dart:convert';
import 'dart:io';

import 'package:test/test.dart';

import '../../lib/src/sandbox/macos_sandbox_utils.dart';
import '../../lib/src/sandbox/sandbox_schemas.dart';
import '../../lib/src/sandbox/sandbox_utils.dart';

/// A path the library computed is a name on disk, not a pattern: the
/// mandatory write denies are joined onto the cwd, a caller's relative
/// spelling is resolved against it, and a cwd may contain `[`, `*` or `?`.
/// Compiled as a glob, `a[b/c]d` turns into a one-character class and the
/// filter stops matching the directory it was built from, so the deny
/// covers nothing. The `**\\/.git/hooks/**` pattern does not make up for
/// it: it covers what is inside the directory, never the directory vnode,
/// which is what `mv` and `ln -s` operate on.
///
/// The profile tests only inspect generated SBPL and run on every POSIX
/// host; the enforcement tests run the profile under sandbox-exec.

/// `<root>/a[b/c]d` — brackets a glob would read as one character class.
const BRACKET_SEGMENTS = ['a[b', 'c]d'];

typedef BracketTree = ({String root, String work, String hooks});

BracketTree bracketTree(String prefix) {
  final root = joinPath(
    Directory.systemTemp.resolveSymbolicLinksSync(),
    '$prefix-${DateTime.now().microsecondsSinceEpoch}',
  );
  final work = _joinAll(root, BRACKET_SEGMENTS);
  final hooks = joinPath(work, '.git', 'hooks');
  Directory(hooks).createSync(recursive: true);
  return (root: root, work: work, hooks: hooks);
}

///
/// The filter `literalPath` compiles to when its `[`, `*` or `?` are read
/// as glob syntax — spelled the way the generator spells it, with the
/// regex metacharacters that are not glob syntax escaped. `tail` is
/// `(/.*)?$` for a deny (which extends over the subtree) and `$` for an
/// allow. This is the text these rules must NOT contain.
///
String sniffedFilter(String literalPath, String tail) {
  final escaped = literalPath.replaceAllMapped(
    RegExp(r'[.^$+{}()|\\]'),
    (match) => '\\${match[0]}',
  );
  return '(regex ${jsonEncode('^$escaped$tail')})';
}

/// Every `(regex "…")` filter the profile emits.
List<String> emittedRegexes(String profile) => RegExp(r'\(regex ("[^"]*")\)')
    .allMatches(profile)
    .map((match) => jsonDecode(match.group(1)!) as String)
    .toList();

String wrap(BracketTree tree, String command) => wrapCommandWithSandboxMacOS(
  MacOSSandboxParams(
    command: command,
    needsNetworkRestriction: false,
    readConfig: null,
    writeConfig: FsWriteRestrictionConfig(
      allowOnly: [tree.root],
      denyWithinAllow: [],
    ),
  ),
);

String joinPath(String base, String one, [String? two, String? three]) {
  var result = '$base${Platform.pathSeparator}$one';
  if (two != null) result += '${Platform.pathSeparator}$two';
  if (three != null) result += '${Platform.pathSeparator}$three';
  return result;
}

String _joinAll(String base, List<String> segments) => segments.fold(
  base,
  (current, segment) => '$current${Platform.pathSeparator}$segment',
);

String _shellQuote(String value) => "'${value.replaceAll("'", "'\\''")}'";

ProcessResult _runShell(String command) =>
    Process.runSync('/bin/sh', ['-c', command]);

bool get _isMacOS => Platform.isMacOS;
bool get _isWindows => Platform.isWindows;

void main() {
  group('macOS profile: mandatory denies under a bracketed cwd', () {
    late BracketTree tree;
    late Directory originalCwd;

    setUpAll(() {
      originalCwd = Directory.current;
      tree = bracketTree('bracket-deny-profile');
      Directory.current = tree.work;
    });
    tearDownAll(() {
      Directory.current = originalCwd.path;
      Directory(tree.root).deleteSync(recursive: true);
    });

    test('denies the git hooks directory by subpath, not by regex', () {
      final profile = wrap(tree, 'true');
      expect(profile, contains('(subpath ${jsonEncode(tree.hooks)})'));
      expect(profile, isNot(contains(sniffedFilter(tree.hooks, r'(/.*)?$'))));
    }, skip: _isWindows ? 'not POSIX' : false);

    test('keeps the cwd literal in the subtree patterns', () {
      final profile = wrap(tree, 'true');
      // `**\\/.git/hooks/**` is anchored at the cwd, so only the tail is a
      // pattern; the cwd itself is escaped into the regex.
      final anchor = tree.work.replaceAllMapped(
        RegExp(r'[.*+?^${}()|[\]\\]'),
        (match) => '\\${match[0]}',
      );
      final expected = '^$anchor/(.*/)?\\.git/hooks/.*(/.*)?\$';
      expect(profile, contains('(regex ${jsonEncode(expected)})'));
    }, skip: _isWindows ? 'not POSIX' : false);

    test('denies every cwd-joined dangerous path by subpath', () {
      final profile = wrap(tree, 'true');
      for (final name in ['.gitconfig', '.zshrc', '.vscode', '.git/config']) {
        expect(
          profile,
          contains('(subpath ${jsonEncode(joinPath(tree.work, name))})'),
        );
      }
    }, skip: _isWindows ? 'not POSIX' : false);

    test('still compiles a bracket pattern the caller wrote as a regex', () {
      final profile = wrapCommandWithSandboxMacOS(
        MacOSSandboxParams(
          command: 'true',
          needsNetworkRestriction: false,
          readConfig: FsReadRestrictionConfig(denyOnly: ['/srv/[ab]/secrets']),
          writeConfig: null,
        ),
      );
      expect(profile, contains('(regex "^/srv/[ab]/secrets(/.*)?\$")'));
      expect(profile, isNot(contains('(subpath "/srv/[ab]/secrets")')));
    }, skip: _isWindows ? 'not POSIX' : false);
  }, skip: _isWindows ? 'not POSIX' : false);

  ///
  /// A caller's relative or `~` spelling is resolved against a directory the
  /// library picked, which splices that directory's own name into the path.
  /// Read back as glob syntax, the caller's own deny stops matching the file
  /// it named and its write root stops covering the project.
  ///
  group('macOS profile: caller spellings resolved under a bracketed cwd', () {
    late BracketTree tree;
    late String secrets;
    late Directory originalCwd;
    setUpAll(() {
      originalCwd = Directory.current;
      tree = bracketTree('bracket-relative-profile');
      secrets = joinPath(tree.work, 'secrets');
      Directory(secrets).createSync(recursive: true);
      Directory.current = tree.work;
    });
    tearDownAll(() {
      Directory.current = originalCwd.path;
      Directory(tree.root).deleteSync(recursive: true);
    });

    String wrapRelative() => wrapCommandWithSandboxMacOS(
      MacOSSandboxParams(
        command: 'true',
        needsNetworkRestriction: false,
        readConfig: FsReadRestrictionConfig(
          denyOnly: ['./secrets'],
          allowWithinDeny: [],
        ),
        writeConfig: FsWriteRestrictionConfig(
          allowOnly: ['.'],
          denyWithinAllow: ['secrets'],
        ),
      ),
    );

    test('denies a relative read-deny by subpath', () {
      final profile = wrapRelative();
      expect(profile, contains('(subpath ${jsonEncode(secrets)})'));
      expect(profile, isNot(contains(sniffedFilter(secrets, r'(/.*)?$'))));
    }, skip: _isWindows ? 'not POSIX' : false);

    test('denies a relative write-deny by subpath', () {
      final profile = wrapRelative();
      final writeSection = profile.substring(profile.indexOf('; File write'));
      expect(writeSection, contains('(subpath ${jsonEncode(secrets)})'));
      expect(writeSection, isNot(contains(sniffedFilter(secrets, r'(/.*)?$'))));
    }, skip: _isWindows ? 'not POSIX' : false);

    test('makes the working directory itself the write root', () {
      final profile = wrapRelative();
      expect(profile, contains('(subpath ${jsonEncode(tree.work)})'));
      expect(profile, isNot(contains(sniffedFilter(tree.work, r'$'))));
    }, skip: _isWindows ? 'not POSIX' : false);
  }, skip: _isWindows ? 'not POSIX' : false);

  ///
  /// A `*` in the cwd goes the other way: compiled as a glob it matches
  /// sibling directories the deny was never meant to reach.
  ///
  group('macOS profile: a cwd whose name contains a star', () {
    late String root;
    late String work;
    late Directory originalCwd;
    setUpAll(() {
      originalCwd = Directory.current;
      root = joinPath(
        Directory.systemTemp.resolveSymbolicLinksSync(),
        'star-deny-profile-${DateTime.now().microsecondsSinceEpoch}',
      );
      work = joinPath(root, 's*t');
      Directory(work).createSync(recursive: true);
      Directory(joinPath(root, 'sZZt')).createSync(recursive: true);
      Directory.current = work;
    });
    tearDownAll(() {
      Directory.current = originalCwd.path;
      Directory(root).deleteSync(recursive: true);
    });

    test('denies the cwd-joined path by subpath and spares the sibling', () {
      final profile = wrapCommandWithSandboxMacOS(
        MacOSSandboxParams(
          command: 'true',
          needsNetworkRestriction: false,
          readConfig: null,
          writeConfig: FsWriteRestrictionConfig(
            allowOnly: [root],
            denyWithinAllow: [],
          ),
        ),
      );
      expect(
        profile,
        contains('(subpath ${jsonEncode(joinPath(work, '.zshrc'))})'),
      );
      final sibling = joinPath(root, 'sZZt/.zshrc');
      for (final regex in emittedRegexes(profile)) {
        expect(RegExp(regex).hasMatch(sibling), isFalse);
      }
    }, skip: _isWindows ? 'not POSIX' : false);
  }, skip: _isWindows ? 'not POSIX' : false);

  ///
  /// A masked credential file is a file the library opened, on both routes:
  /// the bind list, and the degrade-to-deny list an entry lands on when its
  /// extract pattern stops matching under `onExtractNoMatch: "deny"`.
  ///
  group(
    'macOS profile: a masked credential file under a bracketed directory',
    () {
      late BracketTree tree;
      late String credential;

      setUpAll(() {
        tree = bracketTree('bracket-credential-profile');
        credential = joinPath(tree.work, 'hosts.yml');
        File(
          credential,
        ).writeAsStringSync('oauth_token: gho_notarealtoken_0123456789\n');
      });
      tearDownAll(() {
        Directory(tree.root).deleteSync(recursive: true);
      });

      String wrapMasked({
        List<({String realPath, String fakePath})>? maskedFileBinds,
        List<String>? degradeToDenyPaths,
      }) => wrapCommandWithSandboxMacOS(
        MacOSSandboxParams(
          command: 'true',
          needsNetworkRestriction: false,
          readConfig: null,
          writeConfig: FsWriteRestrictionConfig(
            allowOnly: [tree.root],
            denyWithinAllow: [],
          ),
          maskedFileBinds: maskedFileBinds,
          degradeToDenyPaths: degradeToDenyPaths,
        ),
      );

      test('denies a masked path by subpath', () {
        // Pending the credential-mask-files.ts port, the upstream body is:
        // const store = new MaskedFileStore()
        // const { binds } = buildMaskedFileBinds(
        // [{ path: credential, mode: 'mask' }],
        // [],
        // new SentinelRegistry(),
        // store,
        // )
        // expect(binds).toHaveLength(1)
        // const profile = wrapMasked({ maskedFileBinds: binds })
        // expect(profile).toContain(`(subpath ${JSON.stringify(credential)})`)
        // expect(profile).not.toContain(sniffedFilter(credential, '(/.*)?$'))
        // store.dispose()
        //
      }, skip: 'pending port: credential-mask-files.ts');
      test('denies a path that degraded to deny by subpath', () {
        // Pending the credential-mask-files.ts port, the upstream body is:
        // const store = new MaskedFileStore()
        // const { binds, degradeToDenyPaths } = buildMaskedFileBinds(
        // [
        // {
        // path: credential,
        // mode: 'mask',
        // extract: 'will_not_match_(\\S+)',
        // onExtractNoMatch: 'deny',
        // },
        // ],
        // [],
        // new SentinelRegistry(),
        // store,
        // )
        // expect(binds).toHaveLength(0)
        // expect(degradeToDenyPaths).toEqual([credential])
        // const profile = wrapMasked({ degradeToDenyPaths })
        // expect(profile).toContain(`(subpath ${JSON.stringify(credential)})`)
        // expect(profile).not.toContain(sniffedFilter(credential, '(/.*)?$'))
        // store.dispose()
        //
      }, skip: 'pending port: credential-mask-files.ts');
    },
    skip: _isWindows ? 'not POSIX' : false,
  );

  group('macOS sandbox: a bracketed cwd keeps its git hooks directory', () {
    late BracketTree tree;
    late Directory originalCwd;
    setUpAll(() {
      originalCwd = Directory.current;
      tree = bracketTree('bracket-deny-exec');
      File(joinPath(tree.hooks, 'pre-commit')).writeAsStringSync('#!/bin/sh\n');
      Directory.current = tree.work;
    });
    tearDownAll(() {
      Directory.current = originalCwd.path;
      Directory(tree.root).deleteSync(recursive: true);
    });

    ProcessResult run(String command) => _runShell(wrap(tree, command));

    test('allows writes elsewhere under the write root (sanity check)', () {
      final result = run(
        'echo ok > ${_shellQuote(joinPath(tree.work, 'file'))}',
      );
      expect(result.exitCode, 0);
    }, skip: _isMacOS ? false : 'macOS sandbox-exec required');

    test('refuses to move the hooks directory out of the way', () {
      final moved = joinPath(tree.work, '.git/hooks-moved');
      final result = run('mv ${_shellQuote(tree.hooks)} ${_shellQuote(moved)}');
      expect(result.exitCode, isNot(0));
      expect(
        (result.stderr as String).toLowerCase(),
        contains('operation not permitted'),
      );
    }, skip: _isMacOS ? false : 'macOS sandbox-exec required');
  }, skip: _isMacOS ? false : 'macOS sandbox-exec required');

  ///
  /// A caller's relative or `~` spelling is resolved against a directory the
  /// library picked, which splices that directory's own name into the path.
  /// Read back as glob syntax, the caller's own deny stops matching the file
  /// it named and its write root stops covering the project.
  ///
  group('macOS sandbox: a bracketed working directory as the write root', () {
    late BracketTree tree;
    late Directory originalCwd;
    setUpAll(() {
      originalCwd = Directory.current;
      tree = bracketTree('bracket-relative-exec');
      Directory(joinPath(tree.work, 'secrets')).createSync(recursive: true);
      Directory.current = tree.work;
    });
    tearDownAll(() {
      Directory.current = originalCwd.path;
      Directory(tree.root).deleteSync(recursive: true);
    });

    int? run(String command, List<String> allowOnly) => _runShell(
      wrapCommandWithSandboxMacOS(
        MacOSSandboxParams(
          command: command,
          needsNetworkRestriction: false,
          readConfig: null,
          writeConfig: FsWriteRestrictionConfig(
            allowOnly: allowOnly,
            denyWithinAllow: ['secrets'],
          ),
        ),
      ),
    ).exitCode;

    test('writes into the project directory the caller allowed', () {
      expect(
        run('echo ok > ${_shellQuote(joinPath(tree.work, 'file'))}', ['.']),
        0,
      );
    }, skip: _isMacOS ? false : 'macOS sandbox-exec required');

    test('refuses to write inside the directory the caller denied', () {
      // Write root without brackets, so the deny is the only thing that
      // can refuse this write.
      final key = joinPath(tree.work, 'secrets/key');
      expect(run('echo x > ${_shellQuote(key)}', [tree.root]), isNot(0));
    }, skip: _isMacOS ? false : 'macOS sandbox-exec required');
  }, skip: _isMacOS ? false : 'macOS sandbox-exec required');

  ///
  /// The deny-glob compiler exists twice on purpose: a string-taking one in
  /// `sandbox-utils.ts`, where a caller's configured spelling is all pattern,
  /// and the entry-taking wrapper here, which splices an anchor back in as an
  /// escaped literal. Taking the string one everywhere drops the anchor from
  /// every macOS deny regex and puts the bracket bypass back, so both halves
  /// are pinned: the anchor survives, and the wrapper stays in step with the
  /// helper it delegates to.
  ///
  group('macOS deny regexes: anchor and shared compiler', () {
    late BracketTree tree;
    late Directory originalCwd;
    setUpAll(() {
      originalCwd = Directory.current;
      tree = bracketTree('bracket-deny-anchor');
      Directory.current = tree.work;
    });
    tearDownAll(() {
      Directory.current = originalCwd.path;
      Directory(tree.root).deleteSync(recursive: true);
    });

    test('escapes the cwd brackets in every regex the profile emits', () {
      final regexes = emittedRegexes(wrap(tree, 'true'));
      expect(regexes.length, greaterThan(0));
      for (final regex in regexes) {
        // The cwd reaches a regex only as an escaped literal: unescaped, its
        // `a[b/c]d` is a one-character class and the rule matches nothing it
        // was built from. Escaped, the segments read `a\\[b` and `c\\]d`.
        expect(regex, isNot(contains('${BRACKET_SEGMENTS[0]}/')));
        expect(regex, isNot(contains(BRACKET_SEGMENTS[1])));
      }
    }, skip: _isWindows ? 'not POSIX' : false);

    test('anchors the mandatory subtree patterns at the cwd', () {
      final anchor = tree.work.replaceAllMapped(
        RegExp(r'[.*+?^${}()|[\]\\]'),
        (match) => '\\${match[0]}',
      );
      final regexes = emittedRegexes(wrap(tree, 'true'));
      final anchored = regexes
          .where((regex) => regex.startsWith('^$anchor/'))
          .toList();
      expect(anchored.length, greaterThan(0));
      // `**\\/.git/hooks/**` covers a nested repository's hooks under the real
      // working directory, and nothing under the two directories the bracket
      // class would have matched instead.
      final nested = joinPath(tree.work, 'vendor/lib/.git/hooks/pre-commit');
      expect(anchored.any((regex) => RegExp(regex).hasMatch(nested)), isTrue);
      for (final decoy in ['abd', 'acd']) {
        final sibling = joinPath(tree.root, '$decoy/lib/.git/hooks/pre-commit');
        for (final regex in regexes) {
          expect(RegExp(regex).hasMatch(sibling), isFalse);
        }
      }
    }, skip: _isWindows ? 'not POSIX' : false);

    test('compiles a caller glob through the shared string helper', () {
      final spelling = joinPath(tree.root, 'logs/*.pem');
      final profile = wrapCommandWithSandboxMacOS(
        MacOSSandboxParams(
          command: 'true',
          needsNetworkRestriction: false,
          readConfig: FsReadRestrictionConfig(denyOnly: [spelling]),
          writeConfig: null,
        ),
      );
      expect(
        emittedRegexes(profile),
        contains(denyGlobRegex(normalizePathForSandbox(spelling))),
      );
    }, skip: _isWindows ? 'not POSIX' : false);
  }, skip: _isWindows ? 'not POSIX' : false);
}
