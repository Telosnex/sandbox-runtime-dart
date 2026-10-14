import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:sandbox_runtime/src/node/errno.dart';
import 'package:sandbox_runtime/src/node/events.dart' as events;
import 'package:sandbox_runtime/src/node/forge.dart';
import 'package:sandbox_runtime/src/node/http.dart' as http;
import 'package:sandbox_runtime/src/node/net.dart' as net;
import 'package:sandbox_runtime/src/node/tls.dart' as node_tls;
import 'package:test/test.dart';

const _wait = Duration(seconds: 5);

/// An http proxy that answers CONNECT with 200 and hands the tunnel's
/// socket and head to [onTunnel].
Future<(int port, Future<void> Function() close)> _tunnelProxy(
  FutureOr<void> Function(net.NodeSocket socket, Uint8List head) onTunnel,
) async {
  final proxy = http.createServer();
  proxy.on('connect', (
    http.IncomingMessage request,
    net.NodeSocket socket,
    Uint8List head,
  ) {
    socket.on('error', (Object _) {});
    socket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
    unawaited(Future.sync(() => onTunnel(socket, head)));
  });
  proxy.listen(0, '127.0.0.1');
  await events.once(proxy, 'listening');
  final port = (proxy.address()! as net.NodeAddress).port;
  Future<void> close() {
    final done = Completer<void>();
    proxy.close(() => done.complete());
    return done.future;
  }

  return (port, close);
}

/// A raw client socket on a tunnel through the proxy on [proxyPort], after
/// its 200 line, and the paused subscription that read the line.
Future<(Socket, StreamSubscription<List<int>>)> _tunnel(int proxyPort) async {
  final raw = await Socket.connect(InternetAddress.loopbackIPv4, proxyPort);
  raw.add(
    ascii.encode(
      'CONNECT tls.example.test:443 HTTP/1.1\r\n'
      'Host: tls.example.test:443\r\n\r\n',
    ),
  );
  final established = Completer<void>();
  final seen = <int>[];
  late StreamSubscription<List<int>> subscription;
  subscription = raw.listen((chunk) {
    seen.addAll(chunk);
    if (latin1.decode(seen).endsWith('\r\n\r\n')) {
      subscription.pause();
      established.complete();
    }
  });
  await established.future.timeout(_wait);
  expect(latin1.decode(seen), startsWith('HTTP/1.1 200'));
  return (raw, subscription);
}

Future<Socket> _connectThrough(int proxyPort) async =>
    (await _tunnel(proxyPort)).$1;

/// A TLS client on a tunnel through the proxy on [port], trusting [caPem].
Future<SecureSocket> _tlsClient(int port, String caPem) async =>
    _secureClient(await _connectThrough(port), caPem);

/// A TLS client over [raw], trusting [caPem].
Future<SecureSocket> _secureClient(Socket raw, String caPem) {
  final trust = SecurityContext(withTrustedRoots: false)
    ..setTrustedCertificatesBytes(utf8.encode(caPem));
  return SecureSocket.secure(
    raw,
    host: 'tls.example.test',
    context: trust,
    supportedProtocols: const ['http/1.1'],
  ).timeout(_wait);
}

/// A plain relay to [proxyPort] that sends on what its client writes a few
/// bytes at a time, so a ClientHello reaches the proxy in pieces. It sends
/// the CONNECT line itself; its client speaks TLS at once.
Future<({int port, Future<void> Function() close})> _dribblingRelay(
  int proxyPort,
) async {
  final listener = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
  final connections = <Socket>[];
  listener.listen((client) async {
    connections.add(client);
    final (upstream, replies) = await _tunnel(proxyPort);
    connections.add(upstream);
    replies
      ..onData(client.add)
      ..onDone(client.destroy)
      ..resume();
    // ignore: cancel_subscriptions
    final pieces = StreamIterator(client);
    while (await pieces.moveNext()) {
      final chunk = pieces.current;
      for (var i = 0; i < chunk.length; i += 7) {
        upstream.add(
          chunk.sublist(i, i + 7 > chunk.length ? chunk.length : i + 7),
        );
        await upstream.flush();
        await Future<void>.delayed(const Duration(milliseconds: 1));
      }
    }
    upstream.destroy();
  });
  return (
    port: listener.port,
    close: () async {
      for (final socket in connections) {
        socket.destroy();
      }
      await listener.close();
    },
  );
}

/// Upstream `peekForClientHello`, ported: the tunnel's first bytes.
Future<({bool isTLS, Uint8List head})> _peekForClientHello(
  net.NodeSocket socket,
  Uint8List head,
) {
  bool looksLikeClientHello(List<int> b) =>
      b.length >= 3 && b[0] == 0x16 && b[1] == 0x03 && b[2] <= 0x03;
  if (head.length >= 3) {
    return Future.value((isTLS: looksLikeClientHello(head), head: head));
  }
  final result = Completer<({bool isTLS, Uint8List head})>();
  var buf = head;
  late void Function(Object?) onData;
  void done() {
    socket.removeListener('data', onData);
    socket.removeListener('close', done);
    result.complete((isTLS: looksLikeClientHello(buf), head: buf));
  }

  onData = (Object? chunk) {
    socket.pause();
    buf = Uint8List.fromList([...buf, ...chunk! as List<int>]);
    if (buf.length >= 3) return done();
    socket.resume();
  };
  socket.on('data', onData);
  socket.once('close', done);
  return result.future;
}

/// Upstream `readFirstRecord`, ported: pull until the first TLS record is in.
Future<Uint8List> _readFirstRecord(net.NodeSocket socket, Uint8List head) {
  int want(Uint8List b) =>
      b.length >= 5 ? 5 + min((b[3] << 8) | b[4], 16 << 10) : 5;
  if (head.length >= want(head)) return Future.value(head);
  final result = Completer<Uint8List>();
  var buf = head;
  late Timer timer;
  late void Function() pull;
  void done() {
    timer.cancel();
    socket.off('readable', pull);
    socket.off('close', done);
    if (!result.isCompleted) result.complete(buf);
  }

  pull = () {
    Uint8List? chunk;
    while ((chunk = socket.read() as Uint8List?) != null) {
      buf = Uint8List.fromList([...buf, ...chunk!]);
      if (buf.length >= want(buf)) {
        done();
        return;
      }
    }
  };
  timer = Timer(const Duration(seconds: 5), done);
  socket.on('readable', pull);
  socket.once('close', done);
  pull();
  return result.future;
}

/// A self-signed server certificate for [name].
({String certPem, String keyPem}) _certificate(String name) {
  final keys = forge.pki.rsa.generateKeyPair(2048);
  final cert = forge.pki.createCertificate()
    ..publicKey = keys.publicKey
    ..serialNumber = '500102030405060708090a0b0c0d0e0f'
    ..validity.notBefore = DateTime.now().toUtc().subtract(
      const Duration(days: 1),
    )
    ..validity.notAfter = DateTime.now().toUtc().add(const Duration(days: 30))
    ..setSubject([
      {'name': 'commonName', 'value': name},
    ])
    ..setIssuer([
      {'name': 'commonName', 'value': name},
    ])
    ..setExtensions([
      {'name': 'basicConstraints', 'cA': false, 'critical': true},
      {
        'name': 'keyUsage',
        'digitalSignature': true,
        'keyEncipherment': true,
        'critical': true,
      },
      {'name': 'extKeyUsage', 'serverAuth': true},
      {'name': 'subjectKeyIdentifier'},
      {
        'name': 'subjectAltName',
        'altNames': [
          {'type': 2, 'value': name},
        ],
      },
    ]);
  cert.sign(keys.privateKey);
  return (
    certPem: forge.pki.certificateToPem(cert),
    keyPem: forge.pki.privateKeyToPem(keys.privateKey),
  );
}

/// A self-signed certificate for [name], and a TLS echo server that uses it.
Future<({String certPem, int port, Future<void> Function() close})> _server(
  String name,
) async {
  final (:certPem, :keyPem) = _certificate(name);
  final context = node_tls.createSecureContext(cert: certPem, key: keyPem);
  final listener = await SecureServerSocket.bind(
    InternetAddress.loopbackIPv4,
    0,
    context,
    supportedProtocols: const ['http/1.1'],
  );
  listener.listen(
    (socket) => socket.listen(
      socket.add,
      onDone: socket.close,
      onError: (Object _) => socket.destroy(),
    ),
    onError: (Object _) {},
  );
  return (certPem: certPem, port: listener.port, close: listener.close);
}

void main() {
  group('node:tls compatibility', () {
    test('uses the pinned Mozilla root bundle', () {
      expect(node_tls.rootCertificates, isNotEmpty);
      expect(node_tls.rootCertificates.length, 121);
      expect(node_tls.mozillaRootBundleVersion, '2026-09-25');
      expect(
        node_tls.mozillaRootBundleSha256,
        'a41b5d356aea97a529fe27e0f7316d2f9d946d75927476cf9cf1b90637d00505',
      );
      expect(
        node_tls.rootCertificates.first,
        startsWith('-----BEGIN CERTIFICATE-----'),
      );
      expect(node_tls.trustedRootContext(), isA<SecurityContext>());
    });

    group('createServer', () {
      test('serves a secureConnection to tls.connect', () async {
        final (:certPem, :keyPem) = _certificate('srv.example.test');
        final server = node_tls.createServer({'cert': certPem, 'key': keyPem});
        server.on('secureConnection', (node_tls.TLSSocket socket) {
          socket.on('data', (Object? d) => socket.write(d as List<int>));
        });
        server.listen(0, '127.0.0.1');
        await events.once(server, 'listening');
        final port = (server.address() as net.NodeAddress).port;
        final socket = node_tls.connect({
          'host': '127.0.0.1',
          'port': port,
          'servername': 'srv.example.test',
          'ca': certPem,
        });
        socket.write('hi');
        final echoed = await events.once(socket, 'data').timeout(_wait);
        expect(echoed.single, 'hi'.codeUnits);
        socket.destroy();
        server.close();
        await events.once(server, 'close').timeout(_wait);
      });

      test(
        'an SNICallback answering (null, undefined) uses the default',
        () async {
          final (:certPem, :keyPem) = _certificate('srv.example.test');
          final server = node_tls.createServer({
            'cert': certPem,
            'key': keyPem,
            'SNICallback': (String name, Function cb) => cb(null, null),
          });
          server.on('secureConnection', (node_tls.TLSSocket s) => s.end('ok'));
          server.listen(0, '127.0.0.1');
          await events.once(server, 'listening');
          final port = (server.address() as net.NodeAddress).port;
          final socket = node_tls.connect({
            'host': '127.0.0.1',
            'port': port,
            'servername': 'srv.example.test',
            'ca': certPem,
          });
          final data = await events.once(socket, 'data').timeout(_wait);
          expect(data.single, 'ok'.codeUnits);
          socket.destroy();
          server.close();
        },
      );

      test('a non-TLS client is a tlsClientError', () async {
        final (:certPem, :keyPem) = _certificate('srv.example.test');
        final server = node_tls.createServer({'cert': certPem, 'key': keyPem});
        server.listen(0, '127.0.0.1');
        await events.once(server, 'listening');
        final port = (server.address() as net.NodeAddress).port;
        final failed = events.once(server, 'tlsClientError');
        final raw = net.connect({'host': '127.0.0.1', 'port': port});
        raw.on('error', (Object _) {});
        raw.write('GET / HTTP/1.1\r\n\r\n');
        await failed.timeout(_wait);
        raw.destroy();
        server.close();
      });
    });

    group('connect', () {
      late ({String certPem, int port, Future<void> Function() close}) server;
      setUpAll(() async => server = await _server('tls.example.test'));
      tearDownAll(() => server.close());

      test('connect({socket}) runs TLS over an existing stream', () async {
        final under = net.connect({'host': '127.0.0.1', 'port': server.port});
        await events.once(under, 'connect');
        final socket = node_tls.connect({
          'socket': under,
          'host': '127.0.0.1',
          'servername': 'tls.example.test',
          'ca': server.certPem,
        });
        await events.once(socket, 'secureConnect').timeout(_wait);
        socket.write('ping');
        final echoed = await events.once(socket, 'data').timeout(_wait);
        expect(echoed.single, 'ping'.codeUnits);
        expect(socket.authorized, isTrue);
        socket.destroy();
      });

      test('connect({socket}) sees the server end the stream', () async {
        final (:certPem, :keyPem) = _certificate('srv.example.test');
        final tlsServer = node_tls.createServer({
          'cert': certPem,
          'key': keyPem,
        });
        tlsServer.on('secureConnection', (node_tls.TLSSocket s) {
          s.on('error', (Object _) {});
          s.write('x');
          s.end();
        });
        tlsServer.listen(0, '127.0.0.1');
        await events.once(tlsServer, 'listening');
        final port = (tlsServer.address() as net.NodeAddress).port;
        final under = net.connect({'host': '127.0.0.1', 'port': port});
        await events.once(under, 'connect');
        final socket = node_tls.connect({
          'socket': under,
          'servername': 'srv.example.test',
          'ca': certPem,
        });
        final closed = events.once(socket, 'close');
        socket.resume();
        for (var i = 1; i <= 20; i++) {
          Timer(Duration(milliseconds: i * 10), () {
            if (!socket.destroyed) socket.write('b' * 9950);
          });
        }
        await closed.timeout(_wait);
        tlsServer.close();
      });

      test('checkServerIdentity gets subject.CN', () async {
        Object? seen;
        final socket = node_tls.connect({
          'host': '127.0.0.1',
          'port': server.port,
          'servername': 'tls.example.test',
          'ca': server.certPem,
          'checkServerIdentity': (String name, Object? cert) {
            seen = (cert as node_tls.PeerCertificate).subject.CN;
            return null;
          },
        });
        await events.once(socket, 'secureConnect').timeout(_wait);
        expect(seen, 'tls.example.test');
        socket.destroy();
      });

      test('returns at once, queues writes, emits secureConnect', () async {
        final order = <String>[];
        final socket = node_tls.connect({
          'host': '127.0.0.1',
          'port': server.port,
          'servername': 'tls.example.test',
          'ca': server.certPem,
          'ALPNProtocols': ['http/1.1'],
        }, () => order.add('cb'));
        expect(socket.connecting, isTrue);
        socket.on('connect', () => order.add('connect'));
        socket.on('secureConnect', () => order.add('secureConnect'));
        socket.write('ping');
        final echoed = await events
            .once(socket, 'data')
            .timeout(const Duration(seconds: 5));
        expect(echoed.single, 'ping'.codeUnits);
        expect(order, ['connect', 'cb', 'secureConnect']);
        expect(socket.authorized, isTrue);
        expect(socket.alpnProtocol, 'http/1.1');
        expect(socket.getPeerCertificate(), isNotNull);
        socket.destroy();
      });

      test('an untrusted certificate is an error', () async {
        final socket = node_tls.connect({
          'host': '127.0.0.1',
          'port': server.port,
          'servername': 'tls.example.test',
        });
        await expectLater(
          events.once(socket, 'secureConnect'),
          throwsA(isA<NodeError>()),
        );
      });

      test('a hostname mismatch is ERR_TLS_CERT_ALTNAME_INVALID', () async {
        final socket = node_tls.connect({
          'host': '127.0.0.1',
          'port': server.port,
          'servername': 'other.example.test',
          'ca': server.certPem,
        });
        Object? error;
        try {
          await events.once(socket, 'secureConnect');
        } catch (e) {
          error = e;
        }
        expect(error, isA<node_tls.NodeTlsIdentityError>(), reason: '$error');
      });

      test(
        'rejectUnauthorized: false connects with authorized false',
        () async {
          final socket = node_tls.connect({
            'host': '127.0.0.1',
            'port': server.port,
            'servername': 'tls.example.test',
            'rejectUnauthorized': false,
          });
          await events
              .once(socket, 'secureConnect')
              .timeout(const Duration(seconds: 5));
          expect(socket.authorized, isFalse);
          expect(socket.authorizationError, isNotNull);
          socket.destroy();
        },
      );
    });

    group('TLSSocket over a CONNECT tunnel (isServer)', () {
      late ({String certPem, String keyPem}) certificate;
      setUpAll(() => certificate = _certificate('tls.example.test'));

      node_tls.SecureContext context() => node_tls.createSecureContext(
        cert: certificate.certPem,
        key: certificate.keyPem,
      );

      test(
        'serves HTTP to a client whose ClientHello arrives in pieces',
        () async {
          final secured = <String>[];
          final (proxyPort, closeProxy) = await _tunnelProxy((
            net.NodeSocket socket,
            Uint8List head,
          ) async {
            // As upstream: peek, read the first record, put it back, and run
            // TLS on the socket itself.
            final peeked = await _peekForClientHello(socket, head);
            expect(peeked.isTLS, isTrue);
            final hello = await _readFirstRecord(socket, peeked.head);
            socket.unshift(hello);
            final tls = node_tls.TLSSocket(socket, {
              'ALPNProtocols': ['http/1.1'],
              'secureContext': context(),
              'isServer': true,
            });
            tls.once('secure', () {
              secured.add('${tls.alpnProtocol} ${tls.secureEstablished}');
            });
            final inner = http.createServer();
            inner.on('request', (
              http.IncomingMessage request,
              http.ServerResponse response,
            ) {
              response
                  .writeHead(200, {'Content-Length': '${request.url!.length}'})
                  .end(request.url);
            });
            inner.emit('connection', tls);
          });
          final relay = await _dribblingRelay(proxyPort);
          final client = await _secureClient(
            await Socket.connect(InternetAddress.loopbackIPv4, relay.port),
            certificate.certPem,
          );
          expect(client.selectedProtocol, 'http/1.1');
          client.add(
            ascii.encode(
              'GET /over-tls HTTP/1.1\r\nHost: tls.example.test\r\n'
              'Connection: close\r\n\r\n',
            ),
          );
          final reply = latin1.decode(
            await client
                .fold<List<int>>([], (all, chunk) => all..addAll(chunk))
                .timeout(_wait),
          );
          expect(reply, startsWith('HTTP/1.1 200'));
          expect(reply, endsWith('/over-tls'));
          expect(secured, ['http/1.1 true']);
          await relay.close();
          await closeProxy();
        },
      );

      test(
        'sends what the socket queued first, then queued TLS writes',
        () async {
          final (proxyPort, closeProxy) = await _tunnelProxy((
            net.NodeSocket socket,
            Uint8List head,
          ) {
            // Written in the same turn as the TLSSocket is made: the 200 line
            // above is still queued on the socket.
            socket.unshift(head);
            node_tls.TLSSocket(socket, {
              'isServer': true,
              'secureContext': context(),
            }).write('early');
          });
          final client = await _tlsClient(proxyPort, certificate.certPem);
          final first = await client.first.timeout(_wait);
          expect(ascii.decode(first), 'early');
          client.destroy();
          await closeProxy();
        },
      );

      test('a failed handshake is an error, then both sockets close', () async {
        final seen = <String>[];
        final closed = Completer<void>();
        final (proxyPort, closeProxy) = await _tunnelProxy((
          net.NodeSocket socket,
          Uint8List head,
        ) {
          socket.unshift(head);
          final tls = node_tls.TLSSocket(socket, {
            'isServer': true,
            'secureContext': context(),
          });
          tls.on('error', (Object error) {
            seen.add('tls error ${(error as NodeError).code}');
          });
          tls.on('close', () => seen.add('tls close'));
          socket.on('close', () {
            seen.add('socket close');
            closed.complete();
          });
        });
        final raw = await _connectThrough(proxyPort);
        // A TLS record header, then a body that is no ClientHello.
        raw.add([0x16, 0x03, 0x01, 0x00, 0x05, 1, 2, 3, 4, 5]);
        await closed.future.timeout(_wait);
        expect(seen, [
          'tls error ERR_SSL_HANDSHAKE_FAILURE',
          'tls close',
          'socket close',
        ]);
        raw.destroy();
        await closeProxy();
      });

      test('destroying either socket closes both', () async {
        for (final destroyUnder in [true, false]) {
          final closes = <String>[];
          final done = Completer<void>();
          final (proxyPort, closeProxy) = await _tunnelProxy((
            net.NodeSocket socket,
            Uint8List head,
          ) async {
            socket.unshift(head);
            final tls = node_tls.TLSSocket(socket, {
              'isServer': true,
              'secureContext': context(),
            });
            tls.on('close', () => closes.add('tls'));
            socket.on('close', () {
              closes.add('socket');
              if (closes.length == 2) done.complete();
            });
            tls.on('close', () {
              if (closes.length == 2) done.complete();
            });
            expect(() => socket.write('x'), throwsStateError);
            expect(() => socket.unshift([1]), throwsStateError);
            expect(socket.read, throwsStateError);
            await events.once(tls, 'secure');
            if (destroyUnder) {
              socket.destroy();
            } else {
              tls.destroy();
            }
          });
          final client = await _tlsClient(proxyPort, certificate.certPem);
          await done.future.timeout(_wait);
          expect(closes, unorderedEquals(['tls', 'socket']));
          // The client sees the connection end.
          await client.drain<void>().timeout(_wait, onTimeout: () => null);
          client.destroy();
          await closeProxy();
        }
      });

      test('destroy before the handshake closes the connection', () async {
        final closes = <String>[];
        final (proxyPort, closeProxy) = await _tunnelProxy((
          net.NodeSocket socket,
          Uint8List head,
        ) {
          final tls = node_tls.TLSSocket(socket, {
            'isServer': true,
            'secureContext': context(),
          });
          tls.on('close', () => closes.add('tls'));
          socket.on('close', () => closes.add('socket'));
          tls.destroy();
        });
        final raw = await Socket.connect(
          InternetAddress.loopbackIPv4,
          proxyPort,
        );
        raw.add(ascii.encode('CONNECT tls.example.test:443 HTTP/1.1\r\n\r\n'));
        // The connection ends; the 200 line may or may not have gone first.
        await raw.drain<void>().catchError((Object _) {}).timeout(_wait);
        expect(closes, ['tls', 'socket']);
        raw.destroy();
        await closeProxy();
      });

      test('refuses what it does not support', () async {
        final (proxyPort, closeProxy) = await _tunnelProxy((
          net.NodeSocket socket,
          Uint8List head,
        ) {
          expect(
            () => node_tls.TLSSocket(socket, {
              'isServer': true,
              'secureContext': context(),
              'requestCert': true,
            }),
            throwsUnimplementedError,
          );
          expect(
            () => node_tls.TLSSocket(socket, {'secureContext': context()}),
            throwsUnimplementedError,
          );
          expect(
            () => node_tls.TLSSocket(socket, {'isServer': true}),
            throwsArgumentError,
          );
          socket.destroy();
        });
        final raw = await _connectThrough(proxyPort);
        raw.destroy();
        await closeProxy();
      });
    });
  });
}
