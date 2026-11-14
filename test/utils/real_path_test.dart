// Ported from sandbox-runtime test/utils/real-path.test.ts @ 0bbebed.
// ignore_for_file: curly_braces_in_flow_control_structures, non_constant_identifier_names
// ignore_for_file: slash_for_doc_comments
// ignore_for_file: no_leading_underscores_for_local_identifiers
// ignore_for_file: constant_identifier_names

import 'dart:convert';
import 'dart:io';
import 'dart:math';

import 'package:path/path.dart' as path;
import 'package:test/test.dart';

import 'package:sandbox_runtime/src/node/child_process.dart' as child_process;
import 'package:sandbox_runtime/src/node/errno.dart';
import '../helpers/platform.dart' show isLinux, isMacOS;
import 'package:sandbox_runtime/src/node/fs.dart' as fs;
import 'package:sandbox_runtime/src/node/process.dart' as process;
import 'package:sandbox_runtime/src/utils/real_path.dart';

/** What a call gives: its value, or the code of what it throws. */
String _answer(String Function() call) {
  try {
    return call();
  } catch (error) {
    if (error is NodeError) return error.code;
    if (error is FileSystemException) {
      final errno = error.osError?.errorCode;
      if (errno != null) return codeForErrno(errno);
    }
    return 'UNKNOWN';
  }
}

/** The file the kernel finds at `p`, or the code it refuses with. */
String _fileAt(String p) => _answer(() => fs.statIdentitySync(p));

/**
 * For each of `paths`, in Node: what realPathOf gives, what the C library
 * gives for the name folded in text and, if asked for, Node's own answer. The
 * child is ended hard: a call that does not return hears no signal.
 */
List<List<Object?>> _inNode(List<String> paths, [bool askNode = false]) {
  final result = child_process.spawnSync(
    'node',
    [
      '--max-old-space-size=256',
      '--experimental-strip-types',
      '--no-warnings',
      '--input-type=module',
      '-e',
      r'''
    import fs from 'node:fs'
    import path from 'node:path'
    const { realPathOf } = await import(process.argv[1])
    const answer = call => { try { return call() } catch (error) { return error.code } }
    const { paths, askNode } = JSON.parse(fs.readFileSync(0, 'utf8'))
    console.log(JSON.stringify(paths.map(p => [
      answer(() => realPathOf(p)),
      answer(() => fs.realpathSync.native(path.resolve(p))),
      askNode && answer(() => fs.realpathSync(p))])))''',
      _upstreamRealPath,
    ],
    {
      'input': jsonEncode({'paths': paths, 'askNode': askNode}),
      'encoding': 'utf8',
      'timeout': 20000,
      'killSignal': 'SIGKILL',
    },
  );
  expect([result.error, result.stderr], [null, '']);
  return (jsonDecode(result.stdout as String) as List)
      .map((r) => (r as List).cast<Object?>())
      .toList();
}

final _upstreamRealPath = path.join(
  Platform.environment['SRT_UPSTREAM'] ??
      path.join(Directory.current.path, '../sandbox-runtime'),
  'src/utils/real-path.ts',
);

void main() {
  group('realPathOf', () {
    late String root;
    final savedCwd = Directory.current.path;
    /** As written: `join` would fold what `p` holds. */
    String _at(String p) => '$root/$p';

    setUpAll(() {
      root = Directory.systemTemp
          .createTempSync('real-path-')
          .resolveSymbolicLinksSync();
      for (final dir in [
        r'a\b/in',
        'a/b/in',
        'a/up-and-in/in',
        r'alone\',
        'plain/in',
        r'shut\/in',
      ]) {
        Directory(_at(dir)).createSync(recursive: true);
      }
      for (final file in [
        r'a\b/file',
        'a/b/file',
        'a/file',
        r'alone\/file',
        'plain/file',
        'file',
      ]) {
        File(_at(file)).createSync(recursive: true);
      }
      for (final (link, target) in [
        ('to-it', r'a\b'),
        ('to-it-from-the-root', _at(r'a\b')),
        (r'a\b/out', '../plain'),
        (r'a\b/up-behind-a-link', 'out/../file'),
        (r'a\b/slashes', './/in/.//'),
        (r'a\b/nowhere', 'not-there'),
        (r'a\b/round', 'round'),
        (r'a\b/up-from-a-file', 'file/..'),
        (r'a\b/in-a-file', 'file/.'),
        (r'a\b/file-as-a-directory', 'file/'),
        (r'a\b/up-from-shut', r'../shut\/..'),
        (r'a\b/1', 'file'),
        ('plain/out', '../a/b'),
        ('plain/up-behind-a-link', 'out/../file'),
        ('plain/up-and-in', 'out/../up-and-in/in'),
      ]) {
        Link(_at(link)).createSync(target);
      }
      for (var i = 2; i <= 41; i++) {
        Link(_at('a\\b/$i')).createSync('${i - 1}');
      }
      Process.runSync('chmod', ['600', _at(r'shut\')]);
    });

    tearDown(() => Directory.current = savedCwd);

    tearDownAll(() {
      Process.runSync('chmod', ['700', _at(r'shut\')]);
      Directory(root).deleteSync(recursive: true);
    });

    final IS = <(String, String)>[
      // The name itself, with another file where slashes would lead or none.
      (r'a\b', r'a\b'),
      (r'a\b/file', r'a\b/file'),
      (r'alone\', r'alone\'),
      ('a/b/file', 'a/b/file'),
      // Links to it, from it and in it.
      ('to-it/file', r'a\b/file'),
      ('to-it-from-the-root/in', r'a\b/in'),
      (r'a\b/out/file', 'plain/file'),
      (r'a\b/40', r'a\b/file'),
      // In a link's target `..` is the parent of where the way has led.
      (r'a\b/up-behind-a-link', 'file'),
      (r'a\b/slashes', r'a\b/in'),
      ('plain/up-behind-a-link', 'a/file'),
      ('plain/up-and-in', 'a/up-and-in/in'),
      // In the name given they are folded in text.
      (r'a\b/out/../file', r'a\b/file'),
      (r'a\b/file/../in', r'a\b/in'),
      (r'a\b/not-there/..', r'a\b'),
      (r'a\b/./in//', r'a\b/in'),
      (r'a\b/..', ''),
      (r'a\b/file/', r'a\b/file'),
      ('plain/out/../file', 'plain/file'),
      ('plain/file/../in', 'plain/in'),
      ('plain/not-there/..', 'plain'),
      ('plain/./in//', 'plain/in'),
      ('plain/file/', 'plain/file'),
    ];
    for (final (given, real) in IS) {
      test('$given is $real', () {
        expect(realPathOf(_at(given)), _resolve(_at(real)));
      });
    }

    final FAILS = <(String, String)>[
      (r'a\b/not-there', 'ENOENT'),
      (r'not\there', 'ENOENT'),
      (r'a\b/nowhere', 'ENOENT'),
      (r'a\b/nowhere/in', 'ENOENT'),
      (r'a\b/file/in', 'ENOTDIR'),
      (r'a\b/up-from-a-file', 'ENOTDIR'),
      (r'a\b/in-a-file', 'ENOTDIR'),
      (r'a\b/file-as-a-directory', 'ENOTDIR'),
      (r'a\b/round', 'ELOOP'),
      (r'a\b/round/in', 'ELOOP'),
      (r'a\b/41', 'ELOOP'),
      ('a\\b/${'n' * 256}', 'ENAMETOOLONG'),
      ('plain/not-there', 'ENOENT'),
      ('plain/file/in', 'ENOTDIR'),
      ('plain/${'n' * 256}', 'ENAMETOOLONG'),
    ];
    for (final (given, code) in FAILS) {
      test('$given fails with $code', () {
        expect(_answer(() => realPathOf(_at(given))), code);
      });
    }

    test('gives all of that in Node too', () {
      expect(
        _inNode(
          [...IS, ...FAILS].map((r) => _at(r.$1)).toList(),
        ).map((r) => r[0]),
        [...IS.map((r) => _resolve(_at(r.$2))), ...FAILS.map((r) => r.$2)],
      );
    }, timeout: const Timeout(Duration(seconds: 30)));
    // macOS lets no such name be made.
    test(
      'refuses a way through a name that is no text, and takes U+FFFD in a name for itself, in Node too',
      () {
        final bytes = [...utf8.encode('../bytes-'), 0xff];
        fs.mkdirSync([...utf8.encode(_at('plain/')), ...bytes]);
        fs.mkdirSync(_at('bytes-\uFFFD'));
        final rows = <(String, String)>[];
        for (final dir in ['plain', r'a\b']) {
          fs.symlinkSync(bytes, _at('$dir/to-bytes'));
          fs.symlinkSync('../bytes-\uFFFD', _at('$dir/to-text'));
          rows.addAll([
            (_at('$dir/to-bytes'), 'EILSEQ'),
            (_at('$dir/to-text'), _at('bytes-\uFFFD')),
          ]);
        }
        final expected = rows.map((r) => r.$2).toList();
        expect(rows.map((r) => _answer(() => realPathOf(r.$1))), expected);
        expect(
          _inNode(rows.map((r) => r.$1).toList()).map((r) => r[0]),
          expected,
        );
      },
      skip: isLinux ? false : 'requires Linux',
      timeout: const Timeout(Duration(seconds: 30)),
    );

    // root searches a directory of any mode.
    final uid = Process.runSync('id', ['-u']);
    final isRoot = uid.exitCode == 0 && uid.stdout.toString().trim() == '0';
    for (final given in [r'shut\/in', r'a\b/up-from-shut']) {
      test(
        '$given fails with EACCES',
        () => expect(_answer(() => realPathOf(_at(given))), 'EACCES'),
        skip: isRoot ? 'root searches a directory of any mode.' : false,
      );
    }

    test('says which path had too many links', () {
      expect(
        () => realPathOf(_at(r'a\b/round')),
        throwsA(
          isA<NodeError>()
              .having((error) => error.syscall, 'syscall', 'realpath')
              .having((error) => error.path, 'path', _at(r'a\b/round')),
        ),
      );
    });

    final relativePaths = <(String, String, String)>[
      (r'a\b', 'file', r'a\b/file'),
      (r'a\b', '.', r'a\b'),
      (r'a\b', '..', ''),
      (r'a\b/in', '../out/file', 'plain/file'),
      (r'alone\', '.', r'alone\'),
      (r'alone\', 'file', r'alone\/file'),
      ('plain', r'../a\b/file', r'a\b/file'),
      ('plain', 'file', 'plain/file'),
    ];
    for (final (cwd, given, real) in relativePaths) {
      test('in $cwd, $given is $real', () {
        Directory.current = _at(cwd);
        expect(realPathOf(given), _resolve(_at(real)));
      });
    }

    for (final (to, real, rest) in <(String, String, List<String>)>[
      ('plain/file', 'plain/file', []),
      (r'a\b/out/file', 'plain/file', []),
      ('plain/not-there/in', 'plain', ['not-there', 'in']),
      ('plain/file/in/deep', 'plain/file', ['in', 'deep']),
      (r'a\b/nowhere/in', r'a\b', ['not-there', 'in']),
      ('plain/out/not-there/../x', 'a/b', ['not-there', '..', 'x']),
    ]) {
      test('the way to $to leads as far as $real and leaves $rest', () {
        final way = wayTo(_at(to));
        expect([way.real, way.rest], [_at(real), rest]);
      });
    }
    // root searches a directory of any mode.
    for (final (to, rest) in <(String, List<String>)>[
      (r'shut\/in/deep', ['in', 'deep']),
      (r'a\b/up-from-shut/x', ['..', 'x']),
    ]) {
      test(
        'the way to $to stops at the directory that is shut and leaves $rest',
        () {
          final way = wayTo(_at(to));
          expect([way.real, way.rest], [_at(r'shut\'), rest]);
          expect((way.notThere as NodeError).code, 'EACCES');
        },
        skip: isRoot ? 'root searches a directory of any mode.' : false,
      );
    }
    for (final (to, code) in [
      (r'a\b/round', 'ELOOP'),
      (r'a\b/up-from-a-file', 'ENOTDIR'),
    ]) {
      test('the way to $to fails with $code', () {
        expect(_answer(() => wayTo(_at(to)).real), code);
      });
    }

    test('is the root for the root', () {
      Link(_at(r'a\b/root')).createSync('/');
      expect(realPathOf(_at(r'a\b/root')), '/');
      expect(realPathOf(_at(r'a\b/root/..')), _at(r'a\b'));
      expect(realPathOf(_at(r'a\b/root/../..')), root);
    });

    group('what it asks', () {
      const _CALLS = [
        'realpathSync',
        'realpathSync.native',
        'lstatSync',
        'readlinkSync',
      ];
      List<String> _asked(String given) {
        final callsMade = <String>[];
        final previous = fs.fsCallObserver;
        fs.fsCallObserver = (call) {
          if (_CALLS.contains(call.split(' ').first))
            callsMade.add(call.replaceFirst('realpathSync.native', 'native'));
        };
        try {
          realPathOf(given);
        } finally {
          fs.fsCallObserver = previous;
        }
        return callsMade;
      }

      for (final given in ['plain/file', 'to-it/file', 'plain/../plain//in/']) {
        test(
          'asks once about $given, which holds no backslash, folded in text',
          () => expect(_asked(_at(given)), ['native ${_resolve(_at(given))}']),
        );
      }

      test('asks about each component once where the name holds one', () {
        final above = <String>[];
        for (var index = 1; index < root.length; index++) {
          if (root[index] == '/') {
            above.add('lstatSync ${root.substring(0, index)}');
          }
        }
        above.add('lstatSync $root');
        expect(_asked(_at(r'a\b/out/file')), [
          'lstatSync /.',
          ...above,
          'lstatSync ${_at(r'a\b')}',
          'lstatSync ${_at(r'a\b/out')}',
          'readlinkSync ${_at(r'a\b/out')}',
          'lstatSync ${_at(r'a\b')}/.',
          'lstatSync ${_at('plain')}',
          'lstatSync ${_at('plain/file')}',
        ]);
      });

      test(
        'hands every name to realpathSync on Windows, where a backslash separates',
        () {
          process.setPlatformForTesting('win32');
          try {
            expect(_asked(_at('to-it//')), ['realpathSync ${_at('to-it//')}']);
            expect(
              _answer(() => _asked(_at(r'a\b')).join()),
              isNot(contains('lstatSync')),
            );
          } finally {
            process.setPlatformForTesting(null);
          }
        },
      );
    });
  }, skip: process.platform == 'win32' ? 'POSIX backslash-name behavior.' : false);

  // How a volume that folds case, and a volume mounted into another, are spelled
  // is the system's to say: logged, and held to naming the same file.
  group('realPathOf on macOS', () {
    test('names the file it was asked about, in Node too', () {
      final root = fs.mkdtempSync(
        path.join(Directory.systemTemp.path, 'Real-Path-'),
      );
      try {
        fs.writeFileSync(path.join(root, 'File'), '');
        final paths = [
          root,
          path.join(root, 'File'),
          path.join(root, 'file'),
          path.join(root.toLowerCase(), 'FILE'),
          path.join('/System/Volumes/Data', fs.realpathSync(root), 'File'),
        ].where(fs.existsSync).toList();
        final answers = _inNode(paths);
        for (final (i, p) in paths.indexed) {
          final here = realPathOf(p);
          final there = answers[i][0] as String;
          print('$p: $here${there == here ? '' : '; in Node $there'}');
          expect(
            [p, _fileAt(here), _fileAt(there)],
            [p, _fileAt(p), _fileAt(p)],
          );
        }
      } finally {
        fs.rmSync(root, {'recursive': true, 'force': true});
      }
    }, timeout: const Timeout(Duration(seconds: 30)));
  }, skip: isMacOS ? false : 'requires macOS');

  /**
   * Trees of directories, files and links whose names hold backslashes, beside
   * what the same names lead to with slashes. No file has two names but by a
   * link, so its real path is the one path to it that crosses none.
   */
  group('property: realPathOf', () {
    const _NAMES = ['a', 'b', r'a\b', r'b\', r'\a', r'..\a'];
    List<String> _segments(Random random, int maxLength) => List.generate(
      random.nextInt(maxLength + 1),
      (_) => [
        ..._NAMES,
        ..._NAMES,
        '..',
        '..',
        '.',
        '',
      ][random.nextInt(2 * _NAMES.length + 4)],
    );
    String _pick(List<String> from, int n) => from[n % from.length];
    List<String> _linksOnTheWayTo(String p) {
      final links = <String>[];
      for (var index = 1; index <= p.length; index++) {
        if (index == p.length || p[index] == '/') {
          final prefix = p.substring(0, index);
          if (Link(prefix).existsSync()) links.add(prefix);
        }
      }
      return links;
    }

    test(
      'leads where the kernel leads and crosses no link, in Node too, and is what the C library gives',
      () async {
        final random = Random(0x24eb39e);
        for (var run = 0; run < 60; run++) {
          final prefix = random.nextBool() ? 'real-path-' : r'real\path-';
          final root = Directory.systemTemp
              .createTempSync(prefix)
              .resolveSymbolicLinksSync();
          try {
            final directories = <String>[root];
            final made = <String>[root];
            /** Where an entry goes, by the index of an earlier one, its name, and what
             *  it is: a link leads to an earlier entry or along `way`, from the root
             *  of the tree or from where it lies. */
            final entries = List.generate(8 + random.nextInt(17), (_) {
              final way = _segments(random, 4);
              return (
                inside: random.nextInt(100),
                name: _NAMES[random.nextInt(_NAMES.length)],
                kind: [
                  'directory',
                  'directory',
                  'file',
                  'link',
                  'link',
                ][random.nextInt(5)],
                to: random.nextBool() ? random.nextInt(100) : null,
                way: way,
                fromRoot: random.nextBool(),
              );
            });
            var upBehindAName = false;
            for (final entry in entries) {
              final p = path.join(_pick(directories, entry.inside), entry.name);
              if (FileSystemEntity.typeSync(p, followLinks: false) !=
                      FileSystemEntityType.notFound ||
                  made.contains(p)) {
                continue;
              }
              if (entry.kind == 'directory') {
                Directory(p).createSync();
                directories.add(p);
              } else if (entry.kind == 'file') {
                File(p).createSync();
              } else {
                final String led;
                if (entry.to == null) {
                  led = entry.way.join('/');
                } else {
                  led = _pick(made, entry.to!);
                }
                final target = entry.to == null
                    ? (entry.fromRoot ? '$root/' : '') + led
                    : entry.fromRoot
                    ? led
                    : path.relative(led, from: path.dirname(p));
                if (target.isEmpty) continue;
                Link(p).createSync(target);
                upBehindAName =
                    upBehindAName ||
                    (entry.to == null &&
                        entry.way.asMap().entries.any(
                          (part) =>
                              part.value == '..' &&
                              entry.way
                                  .take(part.key)
                                  .any(
                                    (segment) =>
                                        segment.isNotEmpty &&
                                        segment != '.' &&
                                        segment != '..',
                                  ),
                        ));
              }
              made.add(p);
            }
            final questions = List.generate(
              30,
              (_) => (random.nextInt(100), _segments(random, 3)),
            );
            final paths = questions
                .map(
                  (question) =>
                      '${_pick(made, question.$1)}/${question.$2.join('/')}',
                )
                .toList();
            // Node folds a link's target in text, so where one goes up from
            // behind a name its own answer can differ, or never come.
            final askNode = !upBehindAName;
            final nodeAnswers = _inNode(paths, askNode);
            for (var index = 0; index < paths.length; index++) {
              final p = paths[index];
              final real = _answer(() => realPathOf(p));
              final lexical = path.normalize(p);
              expect(
                [p, real.startsWith('/') ? _fileAt(real) : real],
                [p, _fileAt(lexical)],
                reason: 'lexically normalized path: $lexical',
              );
              if (real.startsWith('/')) {
                expect([p, path.normalize(real)], [p, real]);
                expect(_linksOnTheWayTo(real), isEmpty);
              }
              final there = nodeAnswers[index][0];
              final library = nodeAnswers[index][1];
              final own = nodeAnswers[index][2];
              // Not every C library asks whether what a link's target goes on
              // from is a directory.
              if (isMacOS && real == 'ENOTDIR') {
                if (library != real) print('$p: $library');
                continue;
              }
              expect([p, there, library], [p, real, real]);
              if (askNode) expect([p, own], [p, real]);
            }
          } finally {
            Directory(root).deleteSync(recursive: true);
          }
        }
      },
      timeout: const Timeout(Duration(seconds: 120)),
      skip: process.platform == 'win32'
          ? 'POSIX backslash-name behavior.'
          : File(_upstreamRealPath).existsSync()
          ? false
          : 'The sibling upstream TypeScript source is unavailable for the Node oracle.',
    );
  }, skip: process.platform == 'win32' ? 'POSIX backslash-name behavior.' : false);
}

String _resolve(String value) => path.normalize(path.absolute(value));
