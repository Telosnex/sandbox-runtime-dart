// Ported from sandbox-runtime test/sandbox/glob-pattern.test.ts @ 0bbebed.
// ignore_for_file: curly_braces_in_flow_control_structures
// ignore_for_file: slash_for_doc_comments, constant_identifier_names, non_constant_identifier_names
import 'dart:math';
import 'package:test/test.dart';
import 'package:sandbox_runtime/src/sandbox/glob_pattern.dart';

GlobToken text(String t) => GlobTokenText(t);
GlobToken set(String members, [bool matchesSeparator = false]) =>
    GlobTokenSet(members, matchesSeparator);
const SEPARATOR = GlobTokenSimple(GlobTokenKind.Separator);
const ANY_CHAR = GlobTokenSimple(GlobTokenKind.AnyChar);
const STAR = GlobTokenSimple(GlobTokenKind.Star);
const GLOBSTAR = GlobTokenSimple(GlobTokenKind.Globstar);
const GLOBSTAR_SLASH = GlobTokenSimple(GlobTokenKind.GlobstarSlash);

Object _shape(GlobToken t) => switch (t) {
  GlobTokenText(:final kind, :final text) => {'kind': kind, 'text': text},
  GlobTokenSet(:final kind, :final members, :final matchesSeparator) => {
    'kind': kind,
    'members': members,
    'matchesSeparator': matchesSeparator,
  },
  GlobTokenSimple(:final kind) => {'kind': kind},
};

void main() {
  group('parseGlob', () {
    for (final (pattern, tokens) in <(String, List<GlobToken>)>[
      ('', []),
      ('/a/b.ts', [SEPARATOR, text('a'), SEPARATOR, text('b.ts')]),
      ('*.t?', [STAR, text('.t'), ANY_CHAR]),
      ('a/**/b', [text('a'), SEPARATOR, GLOBSTAR_SLASH, text('b')]),
      ('a/**', [text('a'), SEPARATOR, GLOBSTAR]),
      ('a**b', [text('a'), GLOBSTAR, text('b')]),
      (r'\(', [text(r'\(')]),
    ]) {
      test('reads $pattern', () {
        expect(parseGlob(pattern).map(_shape), tokens.map(_shape));
      });
    }
    for (final (run, tokens) in <(String, List<GlobToken>)>[
      ('*/', [STAR, SEPARATOR]),
      ('**/', [GLOBSTAR_SLASH]),
      ('***/', [STAR, GLOBSTAR_SLASH]),
      ('***', [GLOBSTAR]),
      ('****', [GLOBSTAR]),
    ]) {
      test('gives the last two of the run $run to the separator', () {
        expect(parseGlob(run).map(_shape), tokens.map(_shape));
      });
    }
    for (final (pattern, tokens) in <(String, List<GlobToken>)>[
      ('****/', [GLOBSTAR]),
      ('*****/', [GLOBSTAR]),
      ('**/**/', [GLOBSTAR_SLASH]),
      ('**/**', [GLOBSTAR]),
      ('***/**', [GLOBSTAR]),
      ('***/*', [GLOBSTAR]),
      ('**/***/', [GLOBSTAR]),
      ('***/***/***/', [GLOBSTAR]),
      ('a***/*b', [text('a'), GLOBSTAR, text('b')]),
    ]) {
      test('keeps the wildcards of $pattern to the fewest', () {
        expect(parseGlob(pattern).map(_shape), tokens.map(_shape));
      });
    }
    for (final (pattern, tokens) in <(String, List<GlobToken>)>[
      ('**/*', [GLOBSTAR_SLASH, STAR]),
      ('*a*', [STAR, text('a'), STAR]),
      ('*?*', [STAR, ANY_CHAR, STAR]),
      ('*/*', [STAR, SEPARATOR, STAR]),
      ('**/a**/', [GLOBSTAR_SLASH, text('a'), GLOBSTAR_SLASH]),
      ('**[a]**', [GLOBSTAR, set('a'), GLOBSTAR]),
    ]) {
      test('keeps the wildcards of $pattern as they are', () {
        expect(parseGlob(pattern).map(_shape), tokens.map(_shape));
      });
    }
    for (final (pattern, tokens) in <(String, List<GlobToken>)>[
      ('[abc]', [set('abc')]),
      ('x[a-z]y', [text('x'), set('a-z'), text('y')]),
      ('[-a]', [set('-a')]),
      ('[a-]', [set('a-')]),
      ('[a-a]', [set('a-a')]),
      ('[^a]', [set('^a')]),
      ('[!a]', [set('!a')]),
      ('[a[b]', [set('a[b')]),
      ('[a]]', [set('a'), text(']')]),
      ('[s/]', [set('s/', true)]),
      ('[+-9]', [set('+-9', true)]),
      ('[0-9]', [set('0-9')]),
      ('[*]', [set('*')]),
      ('[a?]', [set('a?')]),
      ('[*-a]', [set('*-a', true)]),
    ]) {
      test('reads $pattern as a set', () {
        expect(parseGlob(pattern).map(_shape), tokens.map(_shape));
      });
    }
    for (final (pattern, tokens) in <(String, List<GlobToken>)>[
      ('[z-a]', [text('[z-a]')]),
      ('[user-id]', [text('[user-id]')]),
      ('[]', [text('[]')]),
      ('[]a]', [text('[]a]')]), ('a]b', [text('a]b')]), ('a[b', [text('a[b')]),
      ('a[b[c', [text('a[b[c')]),
      ('[[z-a]', [text('[[z-a]')]),
      ('[z-a[b]', [text('[z-a[b]')]),
      ('[z-a][b]', [text('[z-a]'), set('b')]),
      // In code units: the halves of the two characters run backwards.
      ('[\u{1f600}-\u{1f601}]', [text('[\u{1f600}-\u{1f601}]')]),
    ]) {
      test('reads the brackets of $pattern as text', () {
        expect(parseGlob(pattern).map(_shape), tokens.map(_shape));
      });
    }
    for (final (pattern, tokens) in <(String, List<GlobToken>)>[
      ('[z-a*]', [text('[z-a'), STAR, text(']')]),
      ('[z-a/?]', [text('[z-a'), SEPARATOR, ANY_CHAR, text(']')]),
      ('a[b[c*', [text('a[b[c'), STAR]),
      ('[**/', [text('['), GLOBSTAR_SLASH]),
    ]) {
      test('keeps what is between such brackets a pattern: $pattern', () {
        expect(parseGlob(pattern).map(_shape), tokens.map(_shape));
      });
    }
    for (final unit in ['[', '[a', '[a]', '[z-a]', '[z-a[', '*', '?']) {
      test(
        'takes time that grows with the length: 1,000,000 characters of $unit',
        () {
          final began = Stopwatch()..start();
          parseGlob(unit * (1000000 ~/ unit.length));
          expect(began.elapsedMilliseconds, lessThan(2000));
        },
      );
    }
  });

  /** Whether `members` spell a set, and whether `char` is in it. */
  bool Function(String)? setOf(String members) {
    final ranges = <(String, String)>[];
    for (var i = 0; i < members.length; i++) {
      final isRange =
          i + 1 < members.length &&
          members[i + 1] == '-' &&
          i + 2 < members.length;
      ranges.add((members[i], members[isRange ? i + 2 : i]));
      if (isRange) i += 2;
    }
    if (ranges.isEmpty || ranges.any((r) => r.$1.compareTo(r.$2) > 0))
      return null;
    return (char) => ranges.any(
      (r) => r.$1.compareTo(char) <= 0 && char.compareTo(r.$2) <= 0,
    );
  }

  /// The glob syntax matched directly, by backtracking: no tokens, and nothing
  /// compiled. Shares nothing with [parseGlob] or [globToRegex], so
  /// the property below is two implementations checking each other.
  bool referenceGlobMatch(String pattern, String pathText) {
    bool from(int p, int s, int bracketsAreTextUntil) {
      if (p == pattern.length) return s == pathText.length;
      bool rest(int p2, int s2) => from(p2, s2, bracketsAreTextUntil);
      final head = pattern[p];
      if (head == '*') {
        var stars = 0;
        while (p + stars < pattern.length && pattern[p + stars] == '*') {
          stars++;
        }
        final directories =
            stars >= 2 &&
            p + stars < pattern.length &&
            pattern[p + stars] == '/';
        final next = p + stars + (directories ? 1 : 0);
        if (directories) stars -= 2;
        for (var end = s; end <= pathText.length; end++) {
          if (end > s && stars == 0) break;
          if (end > s && stars == 1 && pathText[end - 1] == '/') break;
          if (rest(next, end)) return true;
          if (!directories) continue;
          for (var i = end; i < pathText.length; i++) {
            if (pathText[i] == '/' && rest(next, i + 1)) return true;
          }
        }
        return false;
      }
      if (s == pathText.length) return false;
      if (head == '?') return pathText[s] != '/' && rest(p + 1, s + 1);
      if (head == '[' && p >= bracketsAreTextUntil) {
        final close = pattern.indexOf(']', p + 1);
        final has = close == -1 ? null : setOf(pattern.substring(p + 1, close));
        if (has != null) return has(pathText[s]) && rest(close + 1, s + 1);
        bracketsAreTextUntil = close == -1 ? pattern.length : close + 1;
      }
      return pathText[s] == head && from(p + 1, s + 1, bracketsAreTextUntil);
    }

    return from(0, 0, 0);
  }

  group('globToRegex', () {
    for (final wildcard in ['*', '?']) {
      test('takes a $wildcard in a set for the character', () {
        final regex = RegExp(globToRegex('/tmp/a[$wildcard]c'));
        expect(regex.hasMatch('/tmp/a${wildcard}c'), true);
        expect(regex.hasMatch('/tmp/abc'), false);
        expect(regex.hasMatch('/tmp/ac'), false);
        expect(regex.hasMatch('/tmp/a[$wildcard]c'), false);
      });
    }
    test('takes brackets with nothing in them for text', () {
      final regex = RegExp(globToRegex('/tmp/list[].ts'));
      expect(regex.hasMatch('/tmp/list[].ts'), true);
      expect(regex.hasMatch('/tmp/list.ts'), false);
    });
    test(
      'takes every [ that nothing closes for text, before a wildcard too',
      () {
        final regex = RegExp(globToRegex('/tmp/a[b[c*'));
        expect(regex.hasMatch('/tmp/a[b[c and more'), true);
        expect(regex.hasMatch('/tmp/a[b[c/more'), false);
        expect(regex.hasMatch('/tmp/a[bc'), false);
      },
    );
    for (final unit in ['*', '**/', '***/', '**/*']) {
      test('answers at once for 1,000 characters of $unit', () {
        final regex = RegExp(
          globToRegex('/x/${unit * (1000 ~/ unit.length)}y'),
        );
        final began = Stopwatch()..start();
        expect(regex.hasMatch('/x/${'a/' * 40}z'), false);
        expect(regex.hasMatch('/x/${'a/' * 40}y'), true);
        expect(began.elapsedMilliseconds, lessThan(1000));
      });
    }
    test(
      'agrees with a reference matcher over generated patterns and paths',
      () {
        final random = Random(20261015);
        final piece = [
          ...'[[]]--**??//az09+.^!\\'.split(''),
          '**/',
          '[a-z]',
          '[z-a]',
          '[+-9]',
          '[*]',
          '[]',
        ];
        String pattern() => List.generate(
          random.nextInt(9),
          (_) => piece[random.nextInt(piece.length)],
        ).join('');
        // A path like the pattern, so that a match is not rare, or any at all.
        final char = '[]-*?/az09+.^!\\'.split('');
        String pathFor(String p) => random.nextBool()
            ? List.generate(
                random.nextInt(7),
                (_) => char[random.nextInt(char.length)],
              ).join('')
            : p
                  .split('')
                  .map(
                    (c) => random.nextBool()
                        ? c
                        : char[random.nextInt(char.length)],
                  )
                  .join('');
        var matches = 0;
        for (var run = 0; run < 20000; run++) {
          final p = pattern();
          final f = pathFor(p);
          final expected = referenceGlobMatch(p, f);
          if (expected) matches++;
          expect(
            RegExp(globToRegex(p)).hasMatch(f),
            expected,
            reason: 'pattern $p path $f',
          );
        }
        expect(matches, greaterThan(1000));
      },
    );
  });
}
