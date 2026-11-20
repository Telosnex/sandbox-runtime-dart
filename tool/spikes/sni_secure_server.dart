// Throwaway spike: select a Dart SecureSocket server certificate from the
// ClientHello SNI by peeking, then replaying consumed TLS bytes via bufferedData.
import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

Future<void> main() async {
  final temp = await Directory.systemTemp.createTemp('dart-sni-spike-');
  try {
    final contexts = <String, SecurityContext>{};
    for (final host in ['alpha.test', 'beta.test']) {
      final cert = '${temp.path}/$host.crt';
      final key = '${temp.path}/$host.key';
      final result = await Process.run('openssl', [
        'req',
        '-x509',
        '-newkey',
        'rsa:2048',
        '-nodes',
        '-days',
        '1',
        '-keyout',
        key,
        '-out',
        cert,
        '-subj',
        '/CN=$host',
      ]);
      if (result.exitCode != 0) throw StateError('${result.stderr}');
      contexts[host] = SecurityContext()
        ..useCertificateChain(cert)
        ..usePrivateKey(key);
    }

    final listener = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    final accepted = <Future<void>>[];
    final acceptSub = listener.listen((raw) {
      accepted.add(_serve(raw, contexts));
    });
    for (final host in ['alpha.test', 'beta.test']) {
      final context = SecurityContext(withTrustedRoots: false);
      final raw = await Socket.connect(
        InternetAddress.loopbackIPv4,
        listener.port,
      );
      final tls = await SecureSocket.secure(
        raw,
        host: host,
        context: context,
        onBadCertificate: (_) => true,
        supportedProtocols: const ['http/1.1'],
      );
      final certSubject = tls.peerCertificate?.subject;
      final replyDone = Completer<String>();
      final replyBytes = <int>[];
      late StreamSubscription<List<int>> replySub;
      replySub = tls.listen(
        (chunk) {
          replyBytes.addAll(chunk);
          if (replyBytes.contains(10) && !replyDone.isCompleted) {
            replyDone.complete(latin1.decode(replyBytes));
          }
        },
        onError: replyDone.completeError,
        onDone: () {
          if (!replyDone.isCompleted) {
            replyDone.complete(latin1.decode(replyBytes));
          }
        },
      );
      tls.write('GET / HTTP/1.1\r\nHost: $host\r\nConnection: close\r\n\r\n');
      await tls.flush();
      final reply = await replyDone.future.timeout(const Duration(seconds: 5));
      await replySub.cancel();
      print(
        '$host => ${certSubject ?? '(no peer certificate)'}; ALPN(client)=${tls.selectedProtocol}; ${reply.split('\r\n').first}',
      );
      tls.destroy();
    }
    await acceptSub.cancel();
    await listener.close();
    await Future.wait(accepted).timeout(const Duration(seconds: 3));
  } finally {
    await temp.delete(recursive: true);
  }
}

Future<void> _serve(
  Socket socket,
  Map<String, SecurityContext> contexts,
) async {
  final consumed = <int>[];
  final gotHello = Completer<void>();
  late StreamSubscription<List<int>> sub;
  sub = socket.listen(
    (chunk) {
      consumed.addAll(chunk);
      if (_clientHelloSni(consumed) != null && !gotHello.isCompleted) {
        sub.pause();
        gotHello.complete();
      }
    },
    onError: (Object e) {
      if (!gotHello.isCompleted) gotHello.completeError(e);
    },
    onDone: () {
      if (!gotHello.isCompleted) {
        gotHello.completeError(StateError('EOF before ClientHello'));
      }
    },
  );
  try {
    await gotHello.future.timeout(const Duration(seconds: 5));
    final bytes = Uint8List.fromList(consumed);
    final host = _clientHelloSni(bytes)!;
    final context = contexts[host];
    if (context == null) throw StateError('no context for SNI $host');
    // secureServer takes over the paused Socket subscription. All bytes read
    // while identifying SNI must be replayed here, including the ClientHello.
    final tls = await SecureSocket.secureServer(
      socket,
      context,
      bufferedData: bytes,
      supportedProtocols: const ['http/1.1'],
    );
    print(
      'selected context for SNI=$host, negotiated ALPN=${tls.selectedProtocol}',
    );
    final requestBytes = <int>[];
    final requestDone = Completer<void>();
    late StreamSubscription<List<int>> requestSub;
    requestSub = tls.listen((chunk) {
      requestBytes.addAll(chunk);
      if (_containsHeaderEnd(requestBytes) && !requestDone.isCompleted) {
        requestDone.complete();
      }
    }, onError: requestDone.completeError);
    await requestDone.future.timeout(const Duration(seconds: 5));
    await requestSub.cancel();
    tls.write(
      'HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n',
    );
    await tls.flush();
    await tls.close();
  } catch (e) {
    stderr.writeln('server error: $e');
    await socket.close();
  }
}

/// TLS record + ClientHello parser for the small SNI spike. Returns null until
/// enough bytes are present; handles a ClientHello spread across TLS records.
String? _clientHelloSni(List<int> input) {
  var p = 0;
  final handshake = <int>[];
  while (p + 5 <= input.length) {
    final type = input[p];
    final length = (input[p + 3] << 8) | input[p + 4];
    if (p + 5 + length > input.length) return null;
    if (type != 22) return null;
    handshake.addAll(input.sublist(p + 5, p + 5 + length));
    p += 5 + length;
    if (handshake.length >= 4) {
      if (handshake[0] != 1) return null;
      final helloLength =
          (handshake[1] << 16) | (handshake[2] << 8) | handshake[3];
      if (handshake.length < helloLength + 4) continue;
      final b = handshake;
      var i = 4 + 2 + 32;
      i += 1 + b[i]; // session id
      final ciphers = (b[i] << 8) | b[i + 1];
      i += 2 + ciphers;
      i += 1 + b[i]; // compression methods
      if (i + 2 > b.length) return null;
      final extensionLength = (b[i] << 8) | b[i + 1];
      i += 2;
      final end = i + extensionLength;
      while (i + 4 <= end && i + 4 <= b.length) {
        final kind = (b[i] << 8) | b[i + 1];
        final size = (b[i + 2] << 8) | b[i + 3];
        i += 4;
        if (kind == 0) {
          final listLength = (b[i] << 8) | b[i + 1];
          var q = i + 2;
          final listEnd = q + listLength;
          while (q + 3 <= listEnd) {
            final nameType = b[q];
            final nameLength = (b[q + 1] << 8) | b[q + 2];
            q += 3;
            if (q + nameLength > listEnd) return null;
            if (nameType == 0) {
              return ascii.decode(b.sublist(q, q + nameLength));
            }
            q += nameLength;
          }
        }
        i += size;
      }
      return null;
    }
  }
  return null;
}

bool _containsHeaderEnd(List<int> b) {
  for (var i = 0; i + 3 < b.length; i++) {
    if (b[i] == 13 && b[i + 1] == 10 && b[i + 2] == 13 && b[i + 3] == 10) {
      return true;
    }
  }
  return false;
}
