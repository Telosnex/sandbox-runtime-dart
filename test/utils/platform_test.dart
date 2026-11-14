// Ported from sandbox-runtime test/utils/platform.test.ts @ 0bbebed.

import 'package:test/test.dart';
import 'package:sandbox_runtime/src/node/process.dart' as process;
import 'package:sandbox_runtime/src/utils/platform.dart';

void main() {
  group('platform utilities', () {
    group('getWslVersion', () {
      test('returns undefined on non-linux platforms', () {
        if (process.platform == 'linux') {
          // On Linux, it might be WSL or not - skip this test
          return;
        }
        expect(getWslVersion(), isNull);
      });
    });

    group('getPlatform', () {
      test('returns macos on darwin', () {
        if (process.platform == 'darwin') {
          expect(getPlatform(), 'macos');
        }
      });

      test('returns windows on win32', () {
        if (process.platform == 'win32') {
          expect(getPlatform(), 'windows');
        }
      });

      test('returns linux on linux', () {
        if (process.platform == 'linux') {
          expect(getPlatform(), 'linux');
        }
      });
    });
  });
}
