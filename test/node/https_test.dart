import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:sandbox_runtime/src/node/forge.dart';
import 'package:sandbox_runtime/src/node/http.dart' as http;
import 'package:sandbox_runtime/src/node/net.dart' as net;
import 'package:sandbox_runtime/src/node/https.dart' as https;
import 'package:sandbox_runtime/src/node/tls.dart' as node_tls;
import 'package:sandbox_runtime/src/node/url.dart' as url;
import 'package:test/test.dart';

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
          {'type': 7, 'ip': name},
        ],
      },
    ]);
  cert.sign(keys.privateKey);
  return (
    certPem: forge.pki.certificateToPem(cert),
    keyPem: forge.pki.privateKeyToPem(keys.privateKey),
  );
}

Future<({String body, int status})> _collect(http.ClientRequest req) {
  final done = Completer<({String body, int status})>();
  req.on('error', (Object e) {
    if (!done.isCompleted) done.completeError(e);
  });
  req.on('response', (http.IncomingMessage res) {
    final body = <int>[];
    res.on('data', (List<int> b) => body.addAll(b));
    res.on('end', () {
      done.complete((body: utf8.decode(body), status: res.statusCode!));
    });
  });
  return done.future.timeout(const Duration(seconds: 10));
}

void main() {
  late HttpServer server;
  late String certPem;

  setUpAll(() async {
    final pair = _certificate('127.0.0.1');
    certPem = pair.certPem;
    server = await HttpServer.bindSecure(
      InternetAddress.loopbackIPv4,
      0,
      node_tls.createSecureContext(cert: pair.certPem, key: pair.keyPem),
    );
    server.listen((r) {
      r.response
        ..write('${r.method} ${r.uri}')
        ..close();
    });
  });
  tearDownAll(() => server.close(force: true));

  test('request(url, options, cb) with ca verifies and merges', () async {
    final req = https.request('https://127.0.0.1:${server.port}/a?b=1', {
      'method': 'POST',
      'ca': certPem,
      'agent': https.Agent(),
    });
    req.end();
    final res = await _collect(req);
    expect(res, (body: 'POST /a?b=1', status: 200));
  });

  test('get with URL object', () async {
    final req = https.get(url.URL('https://127.0.0.1:${server.port}/x'), {
      'ca': certPem,
      'agent': https.Agent(),
    });
    expect((await _collect(req)).body, 'GET /x');
  });

  test('untrusted certificate is an error', () async {
    final req = https.get({
      'hostname': '127.0.0.1',
      'port': server.port,
      'path': '/',
      'agent': https.Agent(),
    });
    await expectLater(_collect(req), throwsA(anything));
  });

  test('Agent ca option and non-https protocol rejected', () async {
    final req = https.get({
      'hostname': '127.0.0.1',
      'port': server.port,
      'agent': https.Agent(ca: certPem),
    });
    expect((await _collect(req)).body, 'GET /');
    expect(() => https.request('http://a/'), throwsArgumentError);
  });

  test(
    'https.createServer round trip and plain client gets TLS error',
    () async {
      final pair = _certificate('127.0.0.1');
      final srv = https.createServer(
        {'key': pair.keyPem, 'cert': pair.certPem},
        (http.IncomingMessage req, http.ServerResponse res) {
          res.end('hi ${req.url}');
        },
      );
      var secure = 0;
      final tlsErrors = Completer<Object>();
      srv.on('secureConnection', (Object _) => secure++);
      srv.on('tlsClientError', (Object e, Object _) {
        if (!tlsErrors.isCompleted) tlsErrors.complete(e);
      });
      final up = Completer<void>();
      srv.listen(0, '127.0.0.1', () => up.complete());
      await up.future;
      final port = (srv.address() as net.NodeAddress).port;
      final req = https.get('https://127.0.0.1:$port/z', {
        'ca': pair.certPem,
        'agent': https.Agent(),
      });
      expect(await _collect(req), (body: 'hi /z', status: 200));
      expect(secure, 1);

      final raw = await Socket.connect('127.0.0.1', port);
      raw.add(utf8.encode('GET / HTTP/1.1\r\nHost: x\r\n\r\n'));
      final got = <int>[];
      raw.listen(got.addAll, onError: (_) {});
      await tlsErrors.future.timeout(const Duration(seconds: 10));
      await raw.close().catchError((_) {});
      expect(
        utf8.decode(got, allowMalformed: true),
        isNot(contains('HTTP/1.1 200')),
      );
      srv.close();
    },
  );
}
