import 'dart:async';
import 'dart:io';

import 'package:sandbox_runtime/src/node/forge.dart';
import 'package:sandbox_runtime/src/node/tls.dart' as node_tls;
import 'package:test/test.dart';

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

    test('parses SNI and preserves the ClientHello bytes', () async {
      final hello = _clientHello('api.example.test');
      expect(node_tls.parseClientHelloSni(hello), 'api.example.test');
      final handshake = hello.sublist(5);
      final fragmented = [
        ..._record(handshake.sublist(0, 3)),
        ..._record(handshake.sublist(3)),
      ];
      expect(node_tls.parseClientHelloSni(fragmented), 'api.example.test');
      expect(node_tls.parseClientHelloSni(_clientHello(null)), isNull);
    });

    test('rejects oversized and malformed ClientHello records', () {
      expect(
        () => node_tls.parseClientHelloSni(
          List<int>.filled(2048, 0),
          maxClientHelloBytes: 1024,
        ),
        throwsFormatException,
      );
      expect(
        () => node_tls.parseClientHelloSni([0x16, 3, 3, 0, 4, 0, 0, 0, 0]),
        throwsFormatException,
      );
    });

    test(
      'SecureContext selection replays ClientHello and negotiates HTTP/1.1',
      () async {
        final keys = forge.pki.rsa.generateKeyPair(2048);
        final cert = forge.pki.createCertificate()
          ..publicKey = keys.publicKey
          ..serialNumber = '400102030405060708090a0b0c0d0e0f'
          ..validity.notBefore = DateTime.now().toUtc().subtract(
            const Duration(days: 1),
          )
          ..validity.notAfter = DateTime.now().toUtc().add(
            const Duration(days: 30),
          )
          ..setSubject([
            {'name': 'commonName', 'value': 'tls.example.test'},
          ])
          ..setIssuer([
            {'name': 'commonName', 'value': 'tls.example.test'},
          ])
          ..setExtensions([
            {'name': 'basicConstraints', 'cA': true, 'critical': true},
            {'name': 'subjectKeyIdentifier'},
            {
              'name': 'subjectAltName',
              'altNames': [
                {'type': 2, 'value': 'tls.example.test'},
              ],
            },
          ]);
        cert.sign(keys.privateKey);
        final context = node_tls.createSecureContext(
          cert: forge.pki.certificateToPem(cert),
          key: forge.pki.privateKeyToPem(keys.privateKey),
        );
        final listener = await ServerSocket.bind(
          InternetAddress.loopbackIPv4,
          0,
        );
        final serverResult = Completer<String?>();
        final accepted = listener.first.then((raw) async {
          final peek = await node_tls.peekClientHello(raw);
          expect(peek.serverName, 'tls.example.test');
          final secure = await node_tls.secureServer(raw, context, peek);
          serverResult.complete(secure.selectedProtocol);
          await secure.drain<void>();
          await secure.close();
        });
        final raw = await Socket.connect(
          InternetAddress.loopbackIPv4,
          listener.port,
        );
        final clientContext = SecurityContext(withTrustedRoots: false);
        clientContext.setAlpnProtocols(['http/1.1'], false);
        final client = await SecureSocket.secure(
          raw,
          host: 'tls.example.test',
          context: clientContext,
          onBadCertificate: (_) => true,
          supportedProtocols: ['http/1.1'],
        );
        expect(client.selectedProtocol, 'http/1.1');
        final identityError = node_tls.checkServerIdentity(
          'tls.example.test',
          client.peerCertificate,
        );
        expect(identityError, isNull);
        expect(
          node_tls.checkServerIdentity(
            'wrong.example.test',
            client.peerCertificate,
          ),
          isNotNull,
        );
        await client.close();
        expect(
          await serverResult.future.timeout(const Duration(seconds: 5)),
          'http/1.1',
        );
        await accepted.timeout(const Duration(seconds: 5));
        await listener.close();
      },
    );
  });
}

List<int> _clientHello(String? sni) {
  final extensions = <int>[];
  if (sni != null) {
    final host = sni.codeUnits;
    final serverName = [
      (host.length + 3) >> 8,
      (host.length + 3) & 255,
      0,
      host.length >> 8,
      host.length & 255,
      ...host,
    ];
    extensions.addAll([
      0,
      0,
      serverName.length >> 8,
      serverName.length & 255,
      ...serverName,
    ]);
  }
  final body = [
    3, 3, ...List<int>.filled(32, 1), // TLS 1.2 legacy version + random
    0, // empty session ID
    0, 2, 0x13, 1, // TLS_AES_128_GCM_SHA256
    1, 0, // null compression
    if (extensions.isNotEmpty) ...[
      extensions.length >> 8,
      extensions.length & 255,
      ...extensions,
    ],
  ];
  final handshake = [
    1,
    body.length >> 16,
    (body.length >> 8) & 255,
    body.length & 255,
    ...body,
  ];
  return _record(handshake);
}

List<int> _record(List<int> handshake) => [
  22,
  3,
  3,
  handshake.length >> 8,
  handshake.length & 255,
  ...handshake,
];
