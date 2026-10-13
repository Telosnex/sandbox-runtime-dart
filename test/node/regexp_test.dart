// Tests for lib/src/node/regexp.dart's RegExp capture-index shim.

import 'package:sandbox_runtime/src/node/regexp.dart';
import 'package:test/test.dart';

void main() {
  group('matchAllWithIndices', () {
    test(
      'indexes a capture even when its value occurs earlier in the match',
      () {
        final match = matchAllWithIndices('aa', r'a(a)').single;

        expect(match.group(1), 'a');
        expect(match.indices[1], (1, 2));
      },
    );

    test('indexes groups inside lookbehind', () {
      final match = matchAllWithIndices('xab', r'(?<=x(a))b').single;

      expect(match.group(1), 'a');
      expect(match.indices[1], (1, 2));

      final multipleGroups = matchAllWithIndices(
        'xabc',
        r'(?<=x(a)(b))c',
      ).single;
      expect(multipleGroups.indices[1], (1, 2));
      expect(multipleGroups.indices[2], (2, 3));
    });

    test('indexes nested groups', () {
      final match = matchAllWithIndices('xab', r'x((a)(b))').single;

      expect(match.group(1), 'ab');
      expect(match.indices[1], (1, 3));
      expect(match.group(2), 'a');
      expect(match.indices[2], (1, 2));
      expect(match.group(3), 'b');
      expect(match.indices[3], (2, 3));
    });

    test('renumbers numeric backreferences after instrumentation', () {
      final match = matchAllWithIndices('xaab', r'x(a)\1(b)').single;

      expect(match.group(1), 'a');
      expect(match.indices[1], (1, 2));
      expect(match.group(2), 'b');
      expect(match.indices[2], (3, 4));
    });

    test('handles escaped syntax and parentheses in character classes', () {
      final match = matchAllWithIndices('(a[)]', r'\((a)\[([()])\]').single;

      expect(match.group(1), 'a');
      expect(match.indices[1], (1, 2));
      expect(match.group(2), ')');
      expect(match.indices[2], (3, 4));
    });

    test(
      'handles non-capturing groups, lookahead, and named backreferences',
      () {
        final lookahead = matchAllWithIndices('xa', r'(?:x)(?=(a))').single;
        expect(lookahead.indices[1], (1, 2));

        final named = matchAllWithIndices(
          'aab',
          r'(?<first>a)\k<first>(?<second>b)',
        ).single;
        expect(named.group(1), 'a');
        expect(named.indices[1], (0, 1));
        expect(named.group(2), 'b');
        expect(named.indices[2], (2, 3));
      },
    );

    test('uses the active branch prefix for alternative captures', () {
      final match = matchAllWithIndices('yb', r'x(a)|y(b)').single;

      expect(match.group(1), isNull);
      expect(match.group(2), 'b');
      expect(match.indices[2], (1, 2));
    });

    test(
      'refuses quantified captures instead of guessing their last offset',
      () {
        expect(
          () => matchAllWithIndices('aaa', r'(a)+').toList(),
          throwsA(isA<UnimplementedError>()),
        );
      },
    );

    test('refuses legacy octal escapes rather than changing their meaning', () {
      expect(
        () => matchAllWithIndices('x', r'\01(a)').toList(),
        throwsA(isA<UnimplementedError>()),
      );
    });
  });
}
