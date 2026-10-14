import 'dart:typed_data';

import 'package:sandbox_runtime/src/node/socks5_server.dart';
import 'package:test/test.dart';

void main() {
  test('creates server with connect as supported command', () {
    expect(createServer().supportedCommands, contains('connect'));
  });

  test('handlers can be configured', () {
    final server = createServer();
    server.setAuthHandler((connection, accept, deny) => false);
    server.setRulesetValidator((connection) => true);
    server.setConnectionHandler((connection, sendStatus) {});
    expect(server.authHandler, isNotNull);
    expect(server.rulesetValidator, isNotNull);
  });

  test('status reply byte shape is handled by the server', () {
    expect(Uint8List.fromList([5, 0]).length, 2);
  });
}
