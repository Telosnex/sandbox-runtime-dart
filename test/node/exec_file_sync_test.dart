import 'package:sandbox_runtime/src/node/child_process.dart';
import 'package:sandbox_runtime/src/node/errno.dart';
import 'package:test/test.dart';

void main() {
  test('execFileSync returns stdout', () {
    expect(execFileSync('sh', ['-c', 'echo hi'], {'encoding': 'utf8'}), 'hi\n');
  });
  test('execFileSync throws on non-zero status', () {
    expect(
      () => execFileSync(
        'sh',
        ['-c', 'echo bad >&2; exit 3'],
        {'encoding': 'utf8'},
      ),
      throwsA(
        isA<NodeError>()
            .having((e) => e.status, 'status', 3)
            .having((e) => e.message, 'message', contains('Command failed')),
      ),
    );
  });
}
