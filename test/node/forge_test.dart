import 'dart:io';

import 'package:sandbox_runtime/src/node/forge.dart';
import 'package:test/test.dart';

void main() {
  group('node-forge X.509 subset', () {
    test(
      'generates PEM certificates with RFC 5280 fields and raw AKI bytes',
      () async {
        if (!_opensslAvailable()) return;
        final caKeys = forge.pki.rsa.generateKeyPair(2048);
        final ca = forge.pki.createCertificate()
          ..publicKey = caKeys.publicKey
          ..serialNumber = '400102030405060708090a0b0c0d0e0f'
          ..validity.notBefore = DateTime.utc(2025, 1, 1)
          ..validity.notAfter = DateTime.utc(2030, 1, 1)
          ..setSubject([
            {'name': 'commonName', 'value': 'test CA'},
            {'name': 'organizationName', 'value': 'sandbox-runtime'},
          ])
          ..setIssuer([
            {'name': 'commonName', 'value': 'test CA'},
            {'name': 'organizationName', 'value': 'sandbox-runtime'},
          ])
          ..setExtensions([
            {'name': 'basicConstraints', 'cA': true, 'critical': true},
            {
              'name': 'keyUsage',
              'critical': true,
              'keyCertSign': true,
              'cRLSign': true,
              'digitalSignature': true,
            },
            {'name': 'subjectKeyIdentifier'},
          ]);
        ca.sign(caKeys.privateKey, forge.md.sha256.create());
        final caPem = forge.pki.certificateToPem(ca);
        final parsedCa = forge.pki.certificateFromPem(caPem);
        final ski =
            parsedCa.getExtension(
                  'subjectKeyIdentifier',
                )!['subjectKeyIdentifier']
                as String;
        expect(ski, hasLength(40));
        expect(parsedCa.getExtension('basicConstraints')!['critical'], isTrue);
        expect(parsedCa.getExtension('basicConstraints')!['cA'], isTrue);
        expect(parsedCa.getExtension('keyUsage')!['keyCertSign'], isTrue);

        final leafKeys = forge.pki.rsa.generateKeyPair(2048);
        final notBefore = DateTime.now().toUtc().subtract(
          const Duration(days: 1),
        );
        final leaf = forge.pki.createCertificate()
          ..publicKey = leafKeys.publicKey
          ..serialNumber = '4123456789abcdef0123456789abcdef'
          ..validity.notBefore = notBefore
          ..validity.notAfter = notBefore.add(const Duration(days: 99))
          ..setSubject([
            {'name': 'commonName', 'value': 'service.test'},
          ])
          ..setIssuer(parsedCa.subject.attributes)
          ..setExtensions([
            {'name': 'basicConstraints', 'cA': false, 'critical': true},
            {
              'name': 'keyUsage',
              'critical': true,
              'digitalSignature': true,
              'keyEncipherment': true,
            },
            {'name': 'extKeyUsage', 'serverAuth': true},
            {
              'name': 'subjectAltName',
              'altNames': [
                {'type': 2, 'value': 'service.test'},
                {'type': 7, 'ip': '127.0.0.1'},
              ],
            },
            {'name': 'subjectKeyIdentifier'},
            {
              'name': 'authorityKeyIdentifier',
              // Forge stores CA SKI as hex but AKI accepts raw binary.
              'keyIdentifier': forge.util.hexToBytes(ski),
            },
            {
              'name': 'cRLDistributionPoints',
              'altNames': [
                {'type': 6, 'value': 'http://127.0.0.1:60080/srt.crl'},
              ],
            },
          ])
          ..signatureOid = forge.pki.oids.sha256WithRSAEncryption;
        leaf.sign(caKeys.privateKey);
        final leafPem = forge.pki.certificateToPem(leaf);
        final parsedLeaf = forge.pki.certificateFromPem(leafPem);
        final aki =
            parsedLeaf.getExtension('authorityKeyIdentifier')!['keyIdentifier']
                as String;
        expect(aki, forge.util.hexToBytes(ski));
        final altNames =
            parsedLeaf.getExtension('subjectAltName')!['altNames'] as List;
        expect(
          altNames.where((name) => name['type'] == 7).single['ip'],
          '127.0.0.1',
        );
        expect(parsedLeaf.getExtension('extKeyUsage')!['critical'], isFalse);
        expect(
          parsedLeaf.getExtension('cRLDistributionPoints')!['value'],
          contains('127.0.0.1'),
        );
        expect(
          parsedLeaf.validity.notAfter
              .difference(parsedLeaf.validity.notBefore)
              .inDays,
          99,
        );

        final temp = await Directory.systemTemp.createTemp('forge-cert-test-');
        try {
          final caPath = '${temp.path}/ca.pem';
          final leafPath = '${temp.path}/leaf.pem';
          await File(caPath).writeAsString(caPem);
          await File(leafPath).writeAsString(leafPem);
          final openssl = await Process.run('openssl', [
            'verify',
            '-x509_strict',
            '-CAfile',
            caPath,
            leafPath,
          ]);
          if (openssl.exitCode != 0 &&
              openssl.stderr.toString().contains('No such file')) {
            return;
          }
          expect(
            openssl.exitCode,
            0,
            reason: '${openssl.stdout}\n${openssl.stderr}',
          );
          final text = await Process.run('openssl', [
            'x509',
            '-in',
            leafPath,
            '-noout',
            '-text',
          ]);
          expect(text.exitCode, 0, reason: '${text.stderr}');
          expect(text.stdout, contains('X509v3 Basic Constraints: critical'));
          expect(text.stdout, contains('X509v3 Key Usage: critical'));
          expect(text.stdout, contains('DNS:service.test'));
          expect(text.stdout, contains('IP Address:127.0.0.1'));
          expect(text.stdout, contains('X509v3 Extended Key Usage'));
          expect(text.stdout, contains('TLS Web Server Authentication'));
          expect(text.stdout, contains('http://127.0.0.1:60080/srt.crl'));
        } finally {
          await temp.delete(recursive: true);
        }
      },
    );

    test('RSA private key PEM round trips through PKCS#1', () {
      final pair = forge.pki.rsa.generateKeyPair(2048);
      final pem = forge.pki.privateKeyToPem(pair.privateKey);
      expect(pem, startsWith('-----BEGIN RSA PRIVATE KEY-----'));
      final parsed = forge.pki.privateKeyFromPem(pem);
      expect(parsed.n, pair.privateKey.n);
      expect(parsed.e, pair.privateKey.e);
    });

    test(
      'ASN.1 CRL layout verifies as an empty, numbered CRL in OpenSSL',
      () async {
        if (!_opensslAvailable()) return;
        final keys = forge.pki.rsa.generateKeyPair(2048);
        final ca = forge.pki.createCertificate()
          ..publicKey = keys.publicKey
          ..serialNumber = '400102030405060708090a0b0c0d0e0f'
          ..validity.notBefore = DateTime.now().toUtc().subtract(
            const Duration(days: 1),
          )
          ..validity.notAfter = DateTime.now().toUtc().add(
            const Duration(days: 30),
          )
          ..setSubject([
            {'name': 'commonName', 'value': 'crl test CA'},
          ])
          ..setIssuer([
            {'name': 'commonName', 'value': 'crl test CA'},
          ])
          ..setExtensions([
            {'name': 'basicConstraints', 'cA': true, 'critical': true},
            {
              'name': 'keyUsage',
              'keyCertSign': true,
              'cRLSign': true,
              'critical': true,
            },
            {'name': 'subjectKeyIdentifier'},
          ]);
        ca.sign(keys.privateKey);
        final caPem = forge.pki.certificateToPem(ca);
        final caSki =
            (ca.getExtension('subjectKeyIdentifier')!['subjectKeyIdentifier']
                as String);
        final rawKeyId = forge.util.hexToBytes(caSki);

        final asn1 = forge.asn1;
        ForgeAsn1 seq(List<ForgeAsn1> values) =>
            asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, values);
        ForgeAsn1 sigAlg() => seq([
          asn1.create(
            asn1.Class.UNIVERSAL,
            asn1.Type.OID,
            false,
            asn1.oidToDer(forge.pki.oids.sha256WithRSAEncryption).getBytes(),
          ),
          asn1.create(asn1.Class.UNIVERSAL, asn1.Type.NULL, false, ''),
        ]);
        ForgeAsn1 ext(String oid, ForgeAsn1 value) => seq([
          asn1.create(
            asn1.Class.UNIVERSAL,
            asn1.Type.OID,
            false,
            asn1.oidToDer(oid).getBytes(),
          ),
          asn1.create(
            asn1.Class.UNIVERSAL,
            asn1.Type.OCTETSTRING,
            false,
            asn1.toDer(value).getBytes(),
          ),
        ]);
        final extensions = asn1.create(asn1.Class.CONTEXT_SPECIFIC, 0, true, [
          seq([
            ext(
              forge.pki.oids.authorityKeyIdentifier,
              seq([
                asn1.create(asn1.Class.CONTEXT_SPECIFIC, 0, false, rawKeyId),
              ]),
            ),
            ext(
              '2.5.29.20',
              asn1.create(
                asn1.Class.UNIVERSAL,
                asn1.Type.INTEGER,
                false,
                '\x01',
              ),
            ),
          ]),
        ]);
        final now = DateTime.now().toUtc();
        final nextUpdate = now.add(const Duration(days: 1));
        ForgeAsn1 time(DateTime date) {
          return date.year < 2050
              ? asn1.create(
                  asn1.Class.UNIVERSAL,
                  asn1.Type.UTCTIME,
                  false,
                  asn1.dateToUtcTime(date),
                )
              : asn1.create(
                  asn1.Class.UNIVERSAL,
                  asn1.Type.GENERALIZEDTIME,
                  false,
                  asn1.dateToGeneralizedTime(date),
                );
        }

        final tbs = seq([
          asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false, '\x01'),
          sigAlg(),
          forge.pki.distinguishedNameToAsn1(ca.subject),
          time(now),
          time(nextUpdate),
          extensions,
        ]);
        final signature = keys.privateKey.sign(asn1.toDer(tbs).getBytes());
        final crl = asn1
            .toDer(
              seq([
                tbs,
                sigAlg(),
                asn1.create(
                  asn1.Class.UNIVERSAL,
                  asn1.Type.BITSTRING,
                  false,
                  '\x00$signature',
                ),
              ]),
            )
            .getBuffer();

        final temp = await Directory.systemTemp.createTemp('forge-crl-test-');
        try {
          final caPath = '${temp.path}/ca.pem';
          final crlPath = '${temp.path}/crl.der';
          await File(caPath).writeAsString(caPem);
          await File(crlPath).writeAsBytes(crl);
          final result = await Process.run('openssl', [
            'crl',
            '-inform',
            'DER',
            '-in',
            crlPath,
            '-noout',
            '-text',
            '-verify',
            '-CAfile',
            caPath,
          ]);
          expect(
            result.exitCode,
            0,
            reason: '${result.stdout}\n${result.stderr}',
          );
          expect(result.stdout, contains('No Revoked Certificates'));
          expect(result.stdout, contains('CRL Number:'));
          expect(result.stdout, contains('1'));
        } finally {
          await temp.delete(recursive: true);
        }
      },
    );

    test('asn1 DER encodes empty CRL-compatible structures and OIDs', () {
      final asn1 = forge.asn1;
      final node = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false, '\x01'),
        asn1.create(
          asn1.Class.UNIVERSAL,
          asn1.Type.OID,
          false,
          asn1.oidToDer('1.2.840.113549.1.1.11').getBytes(),
        ),
      ]);
      final der = asn1.toDer(node).getBytes();
      expect(der.codeUnits, [
        0x30,
        0x0e,
        0x02,
        0x01,
        0x01,
        0x06,
        0x09,
        0x2a,
        0x86,
        0x48,
        0x86,
        0xf7,
        0x0d,
        0x01,
        0x01,
        0x0b,
      ]);
    });
  });
}

bool _opensslAvailable() {
  try {
    return Process.runSync(Platform.isWindows ? 'where' : 'which', [
          'openssl',
        ]).exitCode ==
        0;
  } on Object {
    return false;
  }
}
