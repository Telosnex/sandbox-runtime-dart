import 'dart:io';

import 'package:sandbox_runtime/src/node/crypto.dart';
import 'package:test/test.dart';

void main() {
  // Expected values come from Node's crypto.X509Certificate on the same PEM.
  test('X509Certificate fields match Node formats', () {
    final c = X509Certificate(
      File('test/node/fixtures/x509_sample.pem').readAsStringSync(),
    );
    expect(c.subject, 'C=US\nO=Acme Co\nCN=test.example');
    expect(c.issuer, 'C=US\nO=Acme Co\nCN=test.example');
    expect(
      c.subjectAltName,
      'DNS:a.com, DNS:*.b.com, IP Address:1.2.3.4, email:x@y.z, '
      'URI:http://u/',
    );
    expect(c.keyUsage, ['1.3.6.1.5.5.7.3.1', '1.3.6.1.5.5.7.3.2']);
    expect(c.ca, isTrue);
    expect(c.validFrom, 'Oct 14 15:30:04 2026 GMT');
    expect(c.validTo, 'Nov 13 15:30:04 2026 GMT');
    expect(c.serialNumber, '19E59D3216C377F9D8C3CFB13E2BD4E3DC8587A9');
  });
}
