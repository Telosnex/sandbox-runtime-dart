// Ported from sandbox-runtime test/sandbox/macos-deny-grouping.test.ts @ 0bbebed.
// ignore_for_file: constant_identifier_names, non_constant_identifier_names
// ignore_for_file: slash_for_doc_comments
import 'dart:convert';
import 'dart:io';

import 'package:path/path.dart' as path;
import 'package:test/test.dart';

import 'package:sandbox_runtime/src/sandbox/macos_sandbox_utils.dart';
import 'package:sandbox_runtime/src/sandbox/sandbox_schemas.dart';
import 'package:sandbox_runtime/src/utils/shell_quote.dart';

///
/// Many literal deny paths of the shape `<dir>/<name>/<leaf>` — git's
/// per-worktree registry is the common case — are folded into anchored
/// alternation regexes instead of one `subpath` filter per path. These tests
/// pin that the folded profile is small, compiles quickly, and enforces
/// exactly what the per-path filters did: each leaf is denied, its siblings
/// stay writable, the `<dir>/<name>` directory cannot be renamed away, and a
/// new `<dir>/<other>` can still be created.
///
void main() {
  group(
    'macOS literal deny grouping',
    skip: Platform.isMacOS ? false : 'requires macOS Seatbelt',
    () {
      final TEST_BASE_DIR = path.join(
        Directory.systemTemp.resolveSymbolicLinksSync(),
        'seatbelt-group-test-${DateTime.now().millisecondsSinceEpoch}',
      );
      final ALLOWED_DIR = path.join(TEST_BASE_DIR, 'allowed');
      final GIT_DIR = path.join(ALLOWED_DIR, 'repo', '.git');
      final REGISTRY = path.join(GIT_DIR, 'worktrees');
      const LEAVES = ['commondir', 'config.worktree', 'config.worktree.lock'];
      const NAMES = 1500;
      String name(int i) => 'feature-branch-$i';
      String repeat(String value, int count) =>
          List.filled(count, value).join();

      final denyWithinAllow = <String>[];
      // Every regex metacharacter that can reach a grouped name (glob
      // characters `*?[]` divert a path away from grouping) plus the two
      // characters the SBPL string literal itself escapes, and a non-ASCII
      // name: each must match byte-for-byte once rendered into a regex. Listed
      // first so they share a chunk with the probed plain name below and a
      // mis-parsed alternative would show up as a chunk-mate matching wrongly.
      const ODD_NAME = r'odd.name+(1){2}^$|\"q';
      const UNICODE_NAME = 'funci\u00f3n-\u540d\u524d';
      for (final n in [ODD_NAME, UNICODE_NAME]) {
        for (final leaf in LEAVES) {
          denyWithinAllow.add(path.join(REGISTRY, n, leaf));
        }
      }
      for (var i = 0; i < NAMES; i++) {
        for (final leaf in LEAVES) {
          denyWithinAllow.add(path.join(REGISTRY, name(i), leaf));
        }
      }
      // A different leaf set forms its own group; a lone path stays literal.
      for (var i = 0; i < 5; i++) {
        denyWithinAllow.add(path.join(REGISTRY, 'partial-$i', 'commondir'));
      }
      final LONE = path.join(ALLOWED_DIR, 'other', 'single', 'file');
      denyWithinAllow.add(LONE);
      // Under a deep directory a valid (<= 255 byte) name can still push the
      // group's regex past sandbox-exec's string cap; such names fall back to
      // literal filters, budgeted in bytes — the unit the cap is in — so a
      // non-ASCII name that is short in characters is not mis-grouped.
      final DEEP_REGISTRY = path.join(
        ALLOWED_DIR,
        repeat('d', 200),
        repeat('d', 200),
        repeat('d', 200),
        'reg',
      );
      final LONG_NAMES = [
        repeat('a', 240),
        repeat('b', 240),
        repeat('c', 240),
        repeat('\u00e9', 120),
      ];
      for (final n in LONG_NAMES) {
        for (final leaf in LEAVES) {
          denyWithinAllow.add(path.join(DEEP_REGISTRY, n, leaf));
        }
      }

      String wrap(String command) => wrapCommandWithSandboxMacOS(
        MacOSSandboxParams(
          command: command,
          needsNetworkRestriction: false,
          readConfig: null,
          writeConfig: FsWriteRestrictionConfig(
            allowOnly: [ALLOWED_DIR],
            denyWithinAllow: denyWithinAllow,
          ),
        ),
      );

      setUpAll(() {
        for (final n in [name(7), ODD_NAME, UNICODE_NAME, 'partial-2']) {
          Directory(path.join(REGISTRY, n)).createSync(recursive: true);
          File(
            path.join(REGISTRY, n, 'commondir'),
          ).writeAsStringSync('../..\n');
        }
        Directory(
          path.join(ALLOWED_DIR, 'other', 'single'),
        ).createSync(recursive: true);
      });

      tearDownAll(() {
        final base = Directory(TEST_BASE_DIR);
        if (base.existsSync()) base.deleteSync(recursive: true);
      });

      test(
        'renders each group as chunked regexes under the SBPL string cap',
        () {
          final wrapped = wrap('true');
          final regexes = RegExp(
            r'\(regex "(?:[^"\\]|\\.)*worktrees(?:[^"\\]|\\.)*"\)',
          ).allMatches(wrapped).map((match) => match.group(0)!).toList();
          expect(regexes.length, greaterThan(2));
          for (final filter in regexes) {
            expect(utf8.encode(filter).length, lessThan(1025));
          }
          // No per-path subpath filter survives for a grouped path.
          for (final n in [name(7), ODD_NAME, UNICODE_NAME]) {
            expect(
              wrapped,
              isNot(contains('(subpath "${path.join(REGISTRY, n)}')),
            );
          }
          // The metacharacter and non-ASCII names sit in the same alternation as
          // the probed plain name, escaped (regex) then escaped again (SBPL
          // string literal).
          final firstDenies = regexes
              .where((r) => r.contains('|${name(7)}|'))
              .toList();
          final firstDeny = firstDenies.isEmpty ? null : firstDenies.first;
          expect(firstDeny, isNotNull);
          expect(
            firstDeny,
            contains(
              r'(odd\\.name\\+\\(1\\)\\{2\\}\\^\\$\\|\\\\\"q|' +
                  UNICODE_NAME +
                  '|',
            ),
          );
          // The lone path is still a plain subpath filter.
          expect(wrapped, contains('(subpath "$LONE")'));
          // A name too long for its group's regex is emitted literally rather
          // than in a regex sandbox-exec would refuse.
          for (final n in LONG_NAMES) {
            expect(
              wrapped,
              contains(
                '(subpath "${path.join(DEEP_REGISTRY, n, 'commondir')}")',
              ),
            );
          }
          for (final filter in RegExp(
            r'\(regex "(?:[^"\\]|\\.)*"\)',
          ).allMatches(wrapped).map((match) => match.group(0)!)) {
            expect(utf8.encode(filter).length, lessThan(1025));
          }
          // Bytes: well under what one subpath filter per path would cost.
          expect(utf8.encode(wrapped).length, lessThan(200 * 1024));
        },
      );

      test('compiles quickly', () {
        final stopwatch = Stopwatch()..start();
        final result = Process.runSync(
          '/bin/bash',
          ['-c', wrap('true')],
          stdoutEncoding: utf8,
          stderrEncoding: utf8,
        );
        stopwatch.stop();
        expect(result.exitCode, 0);
        expect(stopwatch.elapsedMilliseconds, lessThan(5000));
      });

      test('enforces the per-path semantics', () {
        final entry = path.join(REGISTRY, name(7));
        final odd = path.join(REGISTRY, ODD_NAME);
        final uni = path.join(REGISTRY, UNICODE_NAME);
        final partial = path.join(REGISTRY, 'partial-2');
        final fresh = path.join(REGISTRY, 'brand-new');
        String q(String p) => quote([p]);
        final script = [
          'echo x > ${q(path.join(entry, 'commondir'))} && echo WROTE-LEAF',
          'echo x > ${q(path.join(entry, 'config.worktree'))} && echo WROTE-LEAF-2',
          'echo x > ${q(path.join(entry, 'other'))} && echo WROTE-SIBLING',
          'mv ${q(entry)} ${q(path.join(REGISTRY, 'moved'))} && echo MOVED-ENTRY',
          'mkdir ${q(fresh)} && echo x > ${q(path.join(fresh, 'commondir'))} && echo CREATED-NEW',
          'echo x > ${q(path.join(odd, 'commondir'))} && echo WROTE-ODD',
          'echo x > ${q(path.join(odd, 'other'))} && echo WROTE-ODD-SIBLING',
          'mv ${q(odd)} ${q(path.join(REGISTRY, 'moved-odd'))} && echo MOVED-ODD',
          'echo x > ${q(path.join(uni, 'commondir'))} && echo WROTE-UNICODE',
          'echo x > ${q(path.join(uni, 'other'))} && echo WROTE-UNICODE-SIBLING',
          'mv ${q(uni)} ${q(path.join(REGISTRY, 'moved-uni'))} && echo MOVED-UNICODE',
          'echo x > ${q(path.join(partial, 'commondir'))} && echo WROTE-PARTIAL',
          'echo x > ${q(path.join(partial, 'config.worktree'))} && echo WROTE-PARTIAL-OTHER-LEAF',
          'echo x > ${q(LONE)} && echo WROTE-LONE',
        ].join('; ');
        final result = Process.runSync(
          '/bin/bash',
          ['-c', wrap(script)],
          stdoutEncoding: utf8,
          stderrEncoding: utf8,
        );
        expect(result.exitCode, isNot(0));
        final out = result.stdout as String;
        expect(out, isNot(contains('WROTE-LEAF')));
        expect(out, contains('WROTE-SIBLING'));
        expect(out, isNot(contains('MOVED-ENTRY')));
        expect(out, contains('CREATED-NEW'));
        expect(out, isNot(contains('WROTE-ODD\n')));
        expect(out, contains('WROTE-ODD-SIBLING'));
        expect(out, isNot(contains('MOVED-ODD')));
        expect(out, isNot(contains('WROTE-UNICODE\n')));
        expect(out, contains('WROTE-UNICODE-SIBLING'));
        expect(out, isNot(contains('MOVED-UNICODE')));
        expect(out, isNot(contains('WROTE-PARTIAL\n')));
        expect(out, contains('WROTE-PARTIAL-OTHER-LEAF'));
        expect(out, isNot(contains('WROTE-LONE')));
        for (final dir in [entry, odd, uni]) {
          expect(
            File(path.join(dir, 'commondir')).readAsStringSync(),
            '../..\n',
          );
          expect(Directory(dir).existsSync(), isTrue);
        }
        expect(File(path.join(fresh, 'commondir')).existsSync(), isTrue);
      });
    },
  );
}
