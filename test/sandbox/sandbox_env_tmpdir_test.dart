// Ported from sandbox-runtime test/sandbox/sandbox-env-tmpdir.test.ts @ 24eb39e.
import 'package:sandbox_runtime/src/node/process.dart' as process;
import 'package:sandbox_runtime/src/sandbox/sandbox_utils.dart'
    show generateProxyEnvVars;
import 'package:test/test.dart';

void main() {
  group('generateProxyEnvVars: TMPDIR', () {
    setUp(() {
      final env = Map<String, String>.of(process.env)
        ..remove('CLAUDE_CODE_TMPDIR')
        ..remove('CLAUDE_TMPDIR');
      process.setEnvForTesting(env);
    });

    tearDown(() => process.setEnvForTesting(null));

    test('reads CLAUDE_CODE_TMPDIR for TMPDIR', () {
      process.env['CLAUDE_CODE_TMPDIR'] = '/tmp/claude-1001';
      expect(generateProxyEnvVars(), contains('TMPDIR=/tmp/claude-1001'));
    });

    test('falls back to CLAUDE_TMPDIR when CLAUDE_CODE_TMPDIR is unset', () {
      process.env['CLAUDE_TMPDIR'] = '/tmp/legacy';
      expect(generateProxyEnvVars(), contains('TMPDIR=/tmp/legacy'));
    });

    test('prefers CLAUDE_CODE_TMPDIR over CLAUDE_TMPDIR when both set', () {
      process.env['CLAUDE_CODE_TMPDIR'] = '/tmp/claude-1001';
      process.env['CLAUDE_TMPDIR'] = '/tmp/legacy';
      expect(generateProxyEnvVars(), contains('TMPDIR=/tmp/claude-1001'));
    });

    test('falls back to /tmp/claude when neither is set', () {
      expect(generateProxyEnvVars(), contains('TMPDIR=/tmp/claude'));
    });

    test('omits TMPDIR when skipTmpdir is true', () {
      process.env['CLAUDE_CODE_TMPDIR'] = '/tmp/claude-1001';
      final vars = generateProxyEnvVars(null, null, null, null, true);
      expect(vars.any((value) => value.startsWith('TMPDIR=')), isFalse);
      expect(vars, contains('SANDBOX_RUNTIME=1'));
    });
  });
}
