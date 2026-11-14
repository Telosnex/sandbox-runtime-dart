// Ported from sandbox-runtime test/utils/which.test.ts @ 0bbebed.
// ignore_for_file: slash_for_doc_comments

import 'package:sandbox_runtime/src/utils/which.dart';
import 'package:test/test.dart';

void main() {
  /**
   * These tests verify the whichSync utility function.
   *
   * Note: These tests must run in isolation from linux-dependency-error.test.ts
   * which mocks the which.js module globally. Run with:
   *   bun test test/utils/which.test.ts
   *
   * The Node.js fallback is tested separately in which-node-test.mjs
   */
  group('whichSync', () {
    test('should find existing executables', () {
      // 'ls' should exist on all Unix systems
      final result = whichSync('ls');
      expect(result, isNotNull);
      expect(result, contains('/ls'));
    });

    test('should return null for non-existent executables', () {
      final result = whichSync('this-command-definitely-does-not-exist-12345');
      expect(result, isNull);
    });

    test('should find common tools', () {
      // These should exist in most environments
      final bash = whichSync('bash');
      expect(bash, isNotNull);

      final cat = whichSync('cat');
      expect(cat, isNotNull);
    });

    test('should be running in Bun environment', () {
      // // Verify we're in Bun - if this fails, Bun.which won't be used
      // expect(typeof globalThis.Bun).toBe('object')
      // expect(typeof globalThis.Bun.which).toBe('function')
    }, skip: 'Dart does not run in Bun; this checks the upstream Bun runtime.');

    test(
      'should return same result as Bun.which directly',
      () {
        // // Verify whichSync returns same result as Bun.which
        // // This indirectly confirms Bun.which is being used
        // const whichSyncResult = whichSync('ls')
        // const bunWhichResult = globalThis.Bun.which('ls')
        // expect(whichSyncResult).toBe(bunWhichResult)
      },
      skip: 'Dart has no Bun.which API; this checks the upstream Bun runtime.',
    );
  });
}
