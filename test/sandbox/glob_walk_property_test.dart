// Ported from sandbox-runtime test/sandbox/glob-walk.property.test.ts @ 24eb39e.
// ignore_for_file: slash_for_doc_comments, constant_identifier_names

import 'dart:io';
import 'dart:math';

import 'package:path/path.dart' as path;
import 'package:sandbox_runtime/src/node/fs.dart' as fs;
import 'package:sandbox_runtime/src/node/os.dart' as os;
import 'package:sandbox_runtime/src/node/process.dart' as process;
import 'package:sandbox_runtime/src/sandbox/sandbox_utils.dart'
    show globToRegex, walkGlobPattern;
import 'package:test/test.dart';

/**
 * The walk reads a pattern one path component at a time; globToRegex reads
 * the same pattern as one regular expression over a whole path, and nothing
 * else in the tree holds the two together.
 *
 * Over trees with no symlinks, where every path below the base is reached by
 * exactly one name, the two must agree exactly: what the walk returns is what
 * the regular expression matches beneath the pattern's base. A pattern the
 * walk cannot split is in the sample too.
 *
 * Seeded, so a failure is reproducible, and bounded, so the suite stays fast.
 * Not run on Windows, where a path is spelled with the other separator.
 */

/** Names that put the interesting readings next to each other: a bracket set
 *  that can match a separator (`[+-9]` spans `/`), a `**` written against
 *  text, a name that is a prefix of another, and brackets that spell no set
 *  (`b-a` runs backwards). */
const List<String> _NAME = [
  'a',
  'b',
  'ab',
  'cert',
  'certs',
  'x.pem',
  'y.pem',
  'a9',
  's',
  '[b-a]',
];

const List<String> _SEGMENT = [
  'a',
  'b',
  'ab',
  '*',
  '**',
  '?',
  'a*',
  '*b',
  'c*t',
  '[ab]',
  '[s/]',
  '[+-9]',
  '[a*]',
  '**.pem',
  '[b-a]',
];

const List<String> _LAST_SEGMENT = [
  '*',
  '**',
  '*.pem',
  'x.pem',
  '?.pem',
  '[xy].pem',
  '[+-9].pem',
];

/** A tree as the relative paths of its files. */

void _materialize(String root, List<List<String>> entries) {
  for (final entry in entries) {
    final file = path.joinAll([root, ...entry]);
    try {
      Directory(path.dirname(file)).createSync(recursive: true);
      File(file).writeAsStringSync('');
    } catch (_) {
      // A name already used the other way round (a file where this one wants
      // a directory): the tree keeps whichever came first.
    }
  }
}

/** Every path below `dir`, directories included, as the walk would spell them. */
List<String> _pathsUnder(String dir) {
  final found = <String>[];
  for (final entry in Directory(dir).listSync(followLinks: false)) {
    final p = entry.path;
    found.add(p);
    if (entry is Directory) found.addAll(_pathsUnder(p));
  }
  return found;
}

List<List<List<String>>> _treeSamples(Random random) {
  int between(int min, int max) => min + random.nextInt(max - min + 1);
  return List.generate(4, (_) {
    final entryCount = between(8, 24);
    return List.generate(entryCount, (_) {
      final segmentCount = between(1, 4);
      return List.generate(
        segmentCount,
        (_) => _NAME[random.nextInt(_NAME.length)],
      );
    });
  });
}

String _patternTail(Random random) {
  final count = random.nextInt(4);
  final segments = List.generate(
    count,
    (_) => _SEGMENT[random.nextInt(_SEGMENT.length)],
  );
  final last = _LAST_SEGMENT[random.nextInt(_LAST_SEGMENT.length)];
  return [...segments, last].join('/');
}

void main() {
  group(
    'property: walkGlobPattern against globToRegex',
    skip: process.platform == 'win32'
        ? 'Windows uses a different path separator'
        : false,
    () {
      late String scratch;
      final trees = <({String root, List<String> paths})>[];

      setUpAll(() {
        final rawScratch = Directory(
          os.tmpdir(),
        ).createTempSync('glob-walk-prop-').path;
        scratch = fs.realpathSync(rawScratch);
        final samples = _treeSamples(Random(20260918));
        for (var index = 0; index < samples.length; index++) {
          final root = path.join(scratch, 't$index');
          Directory(root).createSync();
          _materialize(root, samples[index]);
          trees.add((root: root, paths: _pathsUnder(root)));
        }
      });

      tearDownAll(() {
        Directory(scratch).deleteSync(recursive: true);
      });

      test(
        'returns exactly the paths beneath the base that the regex matches',
        () {
          /** Runs where the pattern had something to find, so that agreeing on
           *  nothing at all cannot carry the property. */
          /** Runs where the pattern had something to find, so nothing alone cannot carry the property. */
          var withMatches = 0;
          final random = Random(20260918);
          for (var run = 0; run < 500; run++) {
            final index = random.nextInt(trees.length);
            final tree = trees[index];
            final pattern = path.join(tree.root, _patternTail(random));
            // 's': the flag the walk compiles its own regular expressions with.
            final regex = RegExp(globToRegex(pattern), dotAll: true);
            final expected = tree.paths.where(regex.hasMatch).toList()..sort();
            if (expected.isNotEmpty) withMatches++;
            // `unlisted` is not compared: a base can be one of the generated
            // files, and a directory the walk really could not list would show
            // up as a path missing from `matches`.
            final walked = walkGlobPattern(
              pattern,
              followSymlinkedDirectories: true,
            );
            final actual = walked.matches..sort();
            expect(actual, expected, reason: 'run $run, pattern $pattern');
          }
          expect(withMatches, greaterThan(100));
        },
      );
    },
  );
}
