// Throwaway spike: dart:io's parsed-header view versus a byte-preserving
// HTTP/1.1 request-head parser, including bytes coalesced after CONNECT headers.
import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

Future<void> main() async {
  final headerServer = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
  final received = Completer<Map<String, Object?>>();
  final httpSub = headerServer.listen((request) {
    final parsed = <String, List<String>>{};
    request.headers.forEach((name, values) => parsed[name] = [...values]);
    received.complete({
      'uri': request.uri.toString(),
      'normalizedHeaders': parsed,
      'rawHeaderApiAvailable': false,
    });
    request.response.close();
  });
  final parsedClient = await Socket.connect(
    InternetAddress.loopbackIPv4,
    headerServer.port,
  );
  parsedClient.write(
    'GET / HTTP/1.1\r\nHost: localhost\r\nX-MiXeD: first\r\nx-mixed: second\r\n' +
        'X-Order-B: b\r\nX-Order-A: a\r\nConnection: close\r\n\r\n',
  );
  await parsedClient.flush();
  final normalized = await received.future.timeout(const Duration(seconds: 5));
  await parsedClient.close();
  await httpSub.cancel();
  await headerServer.close(force: true);
  print('HttpServer parsed API: ${jsonEncode(normalized)}');

  final rawServer = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
  final outcome = Completer<Map<String, Object?>>();
  final rawSub = rawServer.listen((socket) => _readConnect(socket, outcome));
  final rawClient = await Socket.connect(
    InternetAddress.loopbackIPv4,
    rawServer.port,
  );
  final payload = <int>[
    ...ascii.encode(
      'CONNECT api.example:443 HTTP/1.1\r\nHost: api.example:443\r\n' +
          'X-MiXeD: first\r\nx-mixed: second\r\nX-Order-B: b\r\n' +
          'X-Order-A: a\r\n\r\n',
    ),
    0x16,
    0x03,
    0x01,
    0x00,
    0x05,
    0x01,
    0x02,
    0x03,
    0x04,
    0x05,
  ];
  rawClient.add(payload);
  await rawClient.flush();
  final raw = await outcome.future.timeout(const Duration(seconds: 5));
  print('byte parser: ${jsonEncode(raw)}');
  rawClient.destroy();
  await rawSub.cancel();
  await rawServer.close();
  exit(0); // These listener APIs retain native resources past test completion.
}

Future<void> _readConnect(
  Socket socket,
  Completer<Map<String, Object?>> result,
) async {
  final bytes = <int>[];
  late StreamSubscription<List<int>> sub;
  sub = socket.listen((chunk) {
    bytes.addAll(chunk);
    final end = _headerEnd(bytes);
    if (end >= 0 && !result.isCompleted) {
      final headerBytes = Uint8List.fromList(bytes.sublist(0, end));
      final headBytes = Uint8List.fromList(bytes.sublist(end + 4));
      final lines = latin1.decode(headerBytes).split('\r\n');
      result.complete({
        'requestLine': lines.first,
        'rawHeaderLines': lines.skip(1).toList(),
        'headBytesHex': headBytes
            .map((b) => b.toRadixString(16).padLeft(2, '0'))
            .join(' '),
        'headLength': headBytes.length,
      });
      socket.destroy();
      unawaited(sub.cancel());
    }
  });
}

int _headerEnd(List<int> bytes) {
  for (var i = 0; i + 3 < bytes.length; i++) {
    if (bytes[i] == 13 &&
        bytes[i + 1] == 10 &&
        bytes[i + 2] == 13 &&
        bytes[i + 3] == 10)
      return i;
  }
  return -1;
}
