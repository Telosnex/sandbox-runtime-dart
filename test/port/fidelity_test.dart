// Port audit as a test: no upstream counterpart (see tool/audit/README.md).
//
// Every ported test and tool file keeps all of upstream's comments, every
// test file has upstream's titles in order, and every header names an
// upstream file that exists and maps to the file's name. Skipped when the
// upstream checkout (../sandbox-runtime or $SRT_UPSTREAM) is absent.
import 'package:test/test.dart';

import '../../tool/audit/src/audit.dart';

/// Title differences that are intended, with the exact Dart titles expected.
/// Anything else in these files still fails.
final Map<String, List<String> Function(List<String> upstream)>
_intendedTitles = {
  // Upstream's describe-level `expect(vectors.length).toBe(22)` runs as a
  // test (Conventions: assertions in test declarations).
  'test/sandbox/aws_sigv4_test.dart': (up) => [
    up.first,
    'loads exactly 22 official test-suite vectors',
    ...up.skip(1),
  ],
  // Upstream is a standalone script with no titles; it runs as one test.
  'test/utils/which_node_test.dart': (up) => ['which-node-test'],
};

void main() {
  final roots = Roots.find();
  final skip = roots.hasUpstream
      ? false
      : 'upstream checkout not found at ${roots.upstream}';

  group('port fidelity', skip: skip, () {
    test('every header names an upstream file this file maps to', () {
      final problems = [
        for (final r in headerReports(roots))
          if (r.problem != null) '${r.file}: ${r.problem} (${r.upstream})',
      ];
      expect(problems, isEmpty);
    });

    test('test and tool files keep every upstream comment', () {
      final missing = [
        for (final r in commentReports(roots))
          if (!r.file.startsWith('lib/'))
            for (final m in r.missing) '${r.file}: $m',
      ];
      expect(
        missing,
        isEmpty,
        reason:
            'Restore these upstream comments where upstream has them '
            '(dart run tool/audit/comments.dart <file> lists them).',
      );
    });

    test('test files have upstream titles, in order', () {
      final diffs = <String>[];
      for (final r in titleReports(roots)) {
        if (r.upstream == null) continue; // No upstream counterpart.
        final want =
            _intendedTitles[r.file]?.call(r.upstreamTitles) ?? r.upstreamTitles;
        if (want.length == r.dartTitles.length &&
            Iterable<int>.generate(
              want.length,
            ).every((i) => want[i] == r.dartTitles[i])) {
          continue;
        }
        diffs
          ..add(r.file)
          ..addAll(unifiedDiff(want, r.dartTitles).map((l) => '    $l'));
      }
      expect(diffs, isEmpty, reason: diffs.join('\n'));
    });
  });
}
