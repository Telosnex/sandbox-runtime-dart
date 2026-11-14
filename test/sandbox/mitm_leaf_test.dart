// Ported from sandbox-runtime test/sandbox/mitm-leaf.test.ts @ 0bbebed.
// ignore_for_file: constant_identifier_names, non_constant_identifier_names, slash_for_doc_comments
library;

import 'dart:io' show Directory;

import 'package:path/path.dart' show join;
import 'package:sandbox_runtime/src/node/child_process.dart' show execFileSync;
import 'package:sandbox_runtime/src/node/crypto.dart' show X509Certificate;
import 'package:sandbox_runtime/src/node/forge.dart' show ForgeRandomApi, forge;
import 'package:sandbox_runtime/src/node/fs.dart'
    show mkdtempSync, rmSync, writeFileSync;
import 'package:sandbox_runtime/src/node/os.dart' show tmpdir;
import 'package:sandbox_runtime/src/node/tls.dart' show createSecureContext;
import 'package:sandbox_runtime/src/sandbox/mitm_ca.dart';
import 'package:sandbox_runtime/src/sandbox/mitm_leaf.dart';
import 'package:sandbox_runtime/src/utils/which.dart' show whichSync;
import 'package:test/test.dart';

// Committed test-only CA — see test/fixtures/tls-terminate/README.md.
final FIXTURE_DIR = join(
  Directory.current.path,
  'test',
  'fixtures',
  'tls-terminate',
);
final CA_CERT = join(FIXTURE_DIR, 'ca.crt');
final CA_KEY = join(FIXTURE_DIR, 'ca.key');

// Dart: Date.parse for the "Jan  1 00:00:00 2030 GMT" form of validFrom and validTo.
int _dateParse(String s) {
  const months = [
    'Jan',
    'Feb',
    'Mar',
    'Apr',
    'May',
    'Jun',
    'Jul',
    'Aug',
    'Sep',
    'Oct',
    'Nov',
    'Dec',
  ];
  final m = RegExp(
    r'^(\w{3})\s+(\d+)\s+(\d+):(\d+):(\d+)\s+(\d+)\s+GMT$',
  ).firstMatch(s)!;
  return DateTime.utc(
    int.parse(m[6]!),
    months.indexOf(m[1]!) + 1,
    int.parse(m[2]!),
    int.parse(m[3]!),
    int.parse(m[4]!),
    int.parse(m[5]!),
  ).millisecondsSinceEpoch;
}

void main() {
  group('mitm-leaf: mintLeafCert', () {
    // One CA per describe — createMitmCA is pure, leaf cache is per-CA.
    final ca = createMitmCA(caCertPath: CA_CERT, caKeyPath: CA_KEY);

    test('mints a leaf with CN, DNS SAN, and serverAuth EKU', () {
      final leaf = mintLeafCert(ca, 'example.com');
      // certPem is leaf+CA chain — split off the first PEM block.
      final leafOnly = firstPemBlock(leaf.certPem);
      final x = X509Certificate(leafOnly);
      expect(x.subject, contains('CN=example.com'));
      expect(x.subjectAltName, contains('DNS:example.com'));
      expect(x.keyUsage, contains('1.3.6.1.5.5.7.3.1')); // serverAuth OID
      expect(x.ca, false);
      // Issuer matches the fixture CA's subject.
      expect(x.issuer, contains('CN=srt-test-ca DO NOT TRUST'));
    });

    test('carries SKI and an AKI matching the CA SKI', () async {
      // Python ≥3.13 enables ssl.VERIFY_X509_STRICT by default, which rejects
      // non-self-signed certs that lack authorityKeyIdentifier (RFC 5280
      // §4.2.1.1). Minted leaves must carry both, and the AKI keyid must equal
      // the CA's SKI byte-for-byte — not the hex-string form node-forge stores
      // internally. The `openssl verify -x509_strict` test below is the
      // end-to-end check; this asserts the extensions directly so a regression
      // is obvious even where openssl is unavailable.
      final pki = forge.pki;
      final ephemeral = createMitmCA();
      for (final c in [ca, ephemeral]) {
        final leaf = pki.certificateFromPem(
          firstPemBlock(mintLeafCert(c, 'ski.example').certPem),
        );
        expect(leaf.getExtension('subjectKeyIdentifier'), isNotNull);
        final aki = leaf.getExtension('authorityKeyIdentifier')!;
        expect(aki, isNotNull);
        // AKI's DER value is SEQUENCE { [0] keyid }. Hex-encode the whole thing
        // and check the CA's SKI hex appears as a suffix — proves we wrote raw
        // SKI bytes, not their ASCII-hex encoding.
        final caSki = c.cert.generateSubjectKeyIdentifier().toHex();
        expect(
          forge.util.bytesToHex(aki['value'] as String),
          matches(RegExp('$caSki\$')),
        );
      }
      await disposeMitmCA(ephemeral);
    });

    test(
      'carries a cRLDistributionPoints URI when ca.crlUrl is set (Schannel revocation)',
      () async {
        // Schannel checks revocation on the LEAF and hard-fails when there's no
        // CDP; the URL points at the empty CRL the proxy serves. Without crlUrl
        // (e.g. minted before the proxy port is bound) the extension is absent —
        // fine for OpenSSL-backed clients, which don't check by default. `ca` is
        // the file-level fixture CA (crlUrl unset).
        final pki = forge.pki;
        expect(
          pki
              .certificateFromPem(
                firstPemBlock(mintLeafCert(ca, 'cdp.example').certPem),
              )
              .getExtension('cRLDistributionPoints'),
          isNull,
        );

        final withUrl = createMitmCA(caCertPath: CA_CERT, caKeyPath: CA_KEY);
        withUrl.crlUrl = 'http://127.0.0.1:60080/srt.crl';
        try {
          final leaf = pki.certificateFromPem(
            firstPemBlock(mintLeafCert(withUrl, 'cdp.example').certPem),
          );
          final cdp = leaf.getExtension('cRLDistributionPoints');
          expect(cdp, isNotNull);
          // node-forge stores the DER value as a binary string; the URI is a
          // GeneralName IA5String inside it.
          expect(cdp!['value'], contains('http://127.0.0.1:60080/srt.crl'));
        } finally {
          await disposeMitmCA(withUrl);
        }
      },
    );

    test('uses an IP SAN for IP-literal hostnames', () {
      final leaf = mintLeafCert(ca, '127.0.0.1');
      final x = X509Certificate(firstPemBlock(leaf.certPem));
      expect(x.subjectAltName, contains('IP Address:127.0.0.1'));
    });

    test('Node tls accepts the cert+key as a SecureContext', () {
      final leaf = mintLeafCert(ca, 'example.com');
      expect(
        () => createSecureContext(cert: leaf.certPem, key: leaf.keyPem),
        returnsNormally,
      );
    });

    // Whatever the random source gives. All zeros is the far end of a serial
    // that begins with zero bytes, about one in 65,000.
    for (final (what, byte) in [('zeros', '\x00'), ('ones', '\xff')]) {
      test('a serial drawn as all $what gives a certificate that parses', () {
        // The leaves' key pair is made first, from the real source.
        mintLeafCert(ca, 'first.serial.example.com');
        // Dart: spyOn(forge.random, 'getBytesSync').mockImplementation(...)
        var drawn = false;
        ForgeRandomApi.getBytesSyncSpy = (int n) {
          drawn = true;
          return byte * n;
        };
        late LeafCert leaf;
        try {
          leaf = mintLeafCert(ca, '$what.serial.example.com');
          expect(drawn, true);
        } finally {
          ForgeRandomApi.getBytesSyncSpy = null;
        }
        expect(
          () => createSecureContext(cert: leaf.certPem, key: leaf.keyPem),
          returnsNormally,
        );
        final serial = X509Certificate(leaf.certPem).serialNumber;
        expect(serial, hasLength(32));
        expect(serial, matches(RegExp(r'^[4-7]')));
      });
    }

    test('caches per (CA instance, hostname)', () {
      final a = secureContextFor(ca, 'cached.example');
      expect(secureContextFor(ca, 'cached.example'), same(a));
      expect(secureContextFor(ca, 'other.example'), isNot(same(a)));
      // A different CA instance gets its own cache.
      final ca2 = createMitmCA(caCertPath: CA_CERT, caKeyPath: CA_KEY);
      expect(secureContextFor(ca2, 'cached.example'), isNot(same(a)));
    });

    test('mintLeafCert caches per (CA instance, hostname)', () {
      final a = mintLeafCert(ca, 'mint-cache.example');
      expect(mintLeafCert(ca, 'mint-cache.example'), same(a));
      final ca2 = createMitmCA(caCertPath: CA_CERT, caKeyPath: CA_KEY);
      expect(mintLeafCert(ca2, 'mint-cache.example'), isNot(same(a)));
    });

    test('leaf validity span is ≤99 days', () {
      final leaf = mintLeafCert(ca, 'validity.example');
      final x = X509Certificate(firstPemBlock(leaf.certPem));
      final days =
          (_dateParse(x.validTo) - _dateParse(x.validFrom)) /
          (1000 * 60 * 60 * 24);
      // Span must be exactly 99 days: notAfter must be clamped relative to
      // notBefore, not now — otherwise the 1-day backdate of notBefore pushes
      // the span to 100, eating into our margin under the public CA/B cap.
      expect(days, greaterThan(98));
      expect(days, lessThanOrEqualTo(99));
    });

    test('leaf notAfter never exceeds a short-lived CA notAfter', () {
      // CA expires in 10 days. Leaf must clamp to the CA, not to
      // notBefore+99d (which would mint a leaf valid long after its issuer).
      final shortCA = makeShortLivedCA(10);
      try {
        final leaf = mintLeafCert(shortCA, 'short.example');
        final x = X509Certificate(firstPemBlock(leaf.certPem));
        final leafEnd = _dateParse(x.validTo);
        final caEnd = shortCA.cert.validity.notAfter.millisecondsSinceEpoch;
        expect(leafEnd, lessThanOrEqualTo(caEnd));
        // Sanity: the leaf actually picked up the CA cap (within a few seconds)
        // rather than the 825-day cap.
        expect(caEnd - leafEnd, lessThan(5000));
      } finally {
        rmSync(shortCA.certPath.replaceAll(RegExp(r'/[^/]+$'), ''), {
          'recursive': true,
          'force': true,
        });
      }
    });

    // Chain verification via openssl — the strongest correctness signal.
    // Skipped only if openssl is unavailable.
    final verifyTest = whichSync('openssl') != null
        ? (String name, Future<void> Function() body) => test(name, body)
        : (String name, Future<void> Function() body) =>
              test(name, body, skip: true);
    verifyTest(
      'leaf verifies against the CA via `openssl verify` (fixture and ephemeral)',
      () async {
        // Regression: with an ephemeral (forge-generated) CA, node-forge stores
        // the SKI as a hex string, which the leaf's authorityKeyIdentifier was
        // copying verbatim → AKI ≠ SKI → chain verification failed.
        final ephemeral = createMitmCA();
        final dir = mkdtempSync(join(tmpdir(), 'srt-mitm-leaf-'));
        try {
          for (final c in [ca, ephemeral]) {
            final leaf = mintLeafCert(c, 'verify.example');
            final leafPath = join(dir, 'leaf.crt');
            writeFileSync(leafPath, firstPemBlock(leaf.certPem));
            // -x509_strict mirrors Python 3.13's ssl.VERIFY_X509_STRICT default
            // and rejects leaves missing AKI/SKI.
            final out = execFileSync(
              'openssl',
              ['verify', '-x509_strict', '-CAfile', c.certPath, leafPath],
              {'encoding': 'utf8'},
            );
            expect((out as String).trim(), matches(RegExp(r': OK$')));
          }
        } finally {
          rmSync(dir, {'recursive': true, 'force': true});
          await disposeMitmCA(ephemeral);
        }
      },
    );
  });
}

/**
 * Build an on-disk RSA CA whose notAfter is `days` from now, then load it via
 * createMitmCA. Used to exercise the CA-end branch of clampValidity.
 */
MitmCA makeShortLivedCA(int days) {
  final pki = forge.pki;
  final md = forge.md;
  final keys = pki.rsa.generateKeyPair(1024); // small key — test speed
  final cert = pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = '01';
  final now = DateTime.now();
  cert.validity.notBefore = now.subtract(
    const Duration(milliseconds: 24 * 60 * 60 * 1000),
  );
  cert.validity.notAfter = now.add(
    Duration(milliseconds: days * 24 * 60 * 60 * 1000),
  );
  final subject = [
    {'name': 'commonName', 'value': 'short-lived test CA'},
  ];
  cert.setSubject(subject);
  cert.setIssuer(subject);
  cert.setExtensions([
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
  cert.sign(keys.privateKey, md.sha256.create());

  final dir = mkdtempSync(join(tmpdir(), 'srt-short-ca-'));
  final certPath = join(dir, 'ca.crt');
  final keyPath = join(dir, 'ca.key');
  writeFileSync(certPath, pki.certificateToPem(cert));
  writeFileSync(keyPath, pki.privateKeyToPem(keys.privateKey));
  return createMitmCA(caCertPath: certPath, caKeyPath: keyPath);
}

String firstPemBlock(String pem) {
  final m = RegExp(
    r'-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----\r?\n?',
  ).firstMatch(pem);
  if (m == null) throw Exception('no PEM CERTIFICATE block found');
  return m.group(0)!;
}
