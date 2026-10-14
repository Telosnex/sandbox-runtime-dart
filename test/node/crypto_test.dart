import 'dart:io';

import 'package:sandbox_runtime/src/node/crypto.dart';
import 'package:sandbox_runtime/src/node/forge.dart';
import 'package:test/test.dart';

void main() {
  final keys = forge.pki.rsa.generateKeyPair(2048);
  final pem = forge.pki.privateKeyToPem(keys.privateKey);

  test('randomBytes returns a Buffer with hex toString and iteration', () {
    final b = randomBytes(8);
    expect(b.length, 8);
    expect(b.toString('hex'), matches(RegExp(r'^[0-9a-f]{16}$')));
    expect([for (final x in b) x].length, 8);
  });

  test('sign matches forge PKCS#1 v1.5 SHA-256 and openssl', () {
    final data = Buffer.from('hello world');
    final sig = sign('sha256', data, pem);
    expect(sig.length, 256);
    final md = forge.md.sha256.create()..update('hello world');
    expect(sig.toString('binary'), keys.privateKey.sign(md));
    final dir = Directory.systemTemp.createTempSync('crypto-test-');
    try {
      File('${dir.path}/k.pem').writeAsStringSync(pem);
      File('${dir.path}/d').writeAsStringSync('hello world');
      final r = Process.runSync('openssl', [
        'dgst',
        '-sha256',
        '-sign',
        '${dir.path}/k.pem',
        '${dir.path}/d',
      ], stdoutEncoding: null);
      if (r.exitCode == 0) expect(sig.toUint8List(), r.stdout);
    } finally {
      dir.deleteSync(recursive: true);
    }
  });

  test('sign rejects other algorithms and non-PEM keys', () {
    expect(() => sign('sha1', Buffer.from('x'), pem), throwsArgumentError);
    expect(
      () => sign('sha256', Buffer.from('x'), 'nope'),
      throwsFormatException,
    );
  });

  test('X509Certificate fingerprint is colon-separated SHA-1', () {
    final cert = forge.pki.createCertificate()
      ..publicKey = keys.publicKey
      ..serialNumber = '01'
      ..validity.notBefore = DateTime.utc(2025)
      ..validity.notAfter = DateTime.utc(2030)
      ..setSubject([
        {'name': 'commonName', 'value': 'x'},
      ])
      ..setIssuer([
        {'name': 'commonName', 'value': 'x'},
      ]);
    cert.sign(keys.privateKey, forge.md.sha256.create());
    final certPem = forge.pki.certificateToPem(cert);
    final x = X509Certificate(certPem);
    expect(x.fingerprint, matches(RegExp(r'^([0-9A-F]{2}:){19}[0-9A-F]{2}$')));
    final dir = Directory.systemTemp.createTempSync('x509-test-');
    try {
      File('${dir.path}/c.pem').writeAsStringSync(certPem);
      final r = Process.runSync('openssl', [
        'x509',
        '-noout',
        '-fingerprint',
        '-sha1',
        '-in',
        '${dir.path}/c.pem',
      ]);
      if (r.exitCode == 0) {
        expect(x.fingerprint, (r.stdout as String).trim().split('=').last);
      }
    } finally {
      dir.deleteSync(recursive: true);
    }
    expect(() => X509Certificate('garbage'), throwsFormatException);
  });
}
