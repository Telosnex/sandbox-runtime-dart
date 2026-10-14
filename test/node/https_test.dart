import 'package:sandbox_runtime/src/node/https.dart' as https;
import 'package:test/test.dart';

void main() {
  test('HTTPS exposes Node request, get, server, and Agent names', () {
    expect(https.globalAgent.secure, isTrue);
    expect(https.Agent, isNotNull);
    expect(https.createServer, isNotNull);
    expect(https.request, isNotNull);
    expect(https.get, isNotNull);
  });
}
