import 'package:sandbox_runtime/src/node/fd.dart';
import 'package:test/test.dart';

void main() {
  test('rejects an invalid file descriptor', () {
    expect(() => setCloseOnExec(-1), throwsA(isA<OSError>()));
  });
}
