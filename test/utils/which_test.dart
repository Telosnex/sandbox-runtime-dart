// Ported from sandbox-runtime test/utils/which.test.ts @ 24eb39e.

import 'package:sandbox_runtime/src/utils/which.dart';
import 'package:test/test.dart';

void main() {
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

    test(
      'should be running in Bun environment',
      () {},
      skip: 'Dart does not run in Bun; this checks the upstream Bun runtime.',
    );

    test(
      'should return same result as Bun.which directly',
      () {},
      skip: 'Dart has no Bun.which API; this checks the upstream Bun runtime.',
    );
  });
}
