// Ported from sandbox-runtime test/sandbox/mitm-ca.test.ts @ 24eb39e.
// ignore_for_file: slash_for_doc_comments, avoid_dynamic_calls, non_constant_identifier_names
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:path/path.dart' show join, dirname;
import 'package:sandbox_runtime/src/node/child_process.dart' show spawnSync;
import 'package:sandbox_runtime/src/node/forge.dart' show ForgeAsn1, forge;
import 'package:sandbox_runtime/src/node/fs.dart'
    show existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync;
import 'package:sandbox_runtime/src/node/os.dart' show tmpdir;
import 'package:sandbox_runtime/src/sandbox/mitm_ca.dart';
import 'package:sandbox_runtime/src/sandbox/mitm_leaf.dart';
import 'package:sandbox_runtime/src/utils/which.dart' show whichSync;
import 'package:test/test.dart';

// Matches `expect(fn).toThrow(/regex/)`: the thrown error's text matches.
Matcher _throwsMatching(String pattern) => throwsA(
  predicate((Object? e) => RegExp(pattern, dotAll: false).hasMatch('$e')),
);

// Committed test-only CA — see test/fixtures/tls-terminate/README.md.
final FIXTURE_DIR = join(
  Directory.current.path, // import.meta.dir, '..'
  'test',
  'fixtures',
  'tls-terminate',
);
final certPath = join(FIXTURE_DIR, 'ca.crt');
final keyPath = join(FIXTURE_DIR, 'ca.key');
final certPem = readFileSync(certPath, 'utf8') as String;
final keyPem = readFileSync(keyPath, 'utf8') as String;

void main() {
  group('mitm-ca: createMitmCA', () {
    final scratch = mkdtempSync(join(tmpdir(), 'srt-mitm-ca-'));
    final junkPath = join(scratch, 'junk.txt');
    writeFileSync(junkPath, 'not pem\n');

    tearDownAll(() {
      rmSync(scratch, {'recursive': true, 'force': true});
    });

    test('returns parsed cert+key from a real CA', () {
      final ca = createMitmCA(caCertPath: certPath, caKeyPath: keyPath);
      expect(ca.certPath, certPath);
      expect(ca.keyPath, keyPath);
      expect(ca.certPem, certPem);
      expect(ca.keyPem, keyPem);
      expect(ca.certPem, contains('-----BEGIN CERTIFICATE-----'));
      // openssl req -nodes emits PKCS8 ("PRIVATE KEY"); the loader's regex also
      // accepts PKCS1 "RSA PRIVATE KEY" / "EC PRIVATE KEY".
      expect(
        ca.keyPem,
        matches(RegExp(r'-----BEGIN (RSA |EC )?PRIVATE KEY-----')),
      );
      expect(ca.cert.subject.getField('CN')!.value, contains('srt-test-ca'));
      expect(ca.key.n, isNotNull); // RSA modulus present
    });

    test('is a pure factory: each call returns a new instance', () {
      final a = createMitmCA(caCertPath: certPath, caKeyPath: keyPath);
      final b = createMitmCA(caCertPath: certPath, caKeyPath: keyPath);
      expect(b, isNot(same(a)));
      expect(b.certPem, a.certPem);
    });

    test('throws with field+path+code when cert path is missing', () {
      final missing = join(scratch, 'nope.crt');
      expect(
        () => createMitmCA(caCertPath: missing, caKeyPath: keyPath),
        _throwsMatching(
          r'tlsTerminate\.caCertPath: cannot read .*nope\.crt \(ENOENT\)',
        ),
      );
    });

    test('throws with field+path+code when key path is missing', () {
      final missing = join(scratch, 'nope.key');
      expect(
        () => createMitmCA(caCertPath: certPath, caKeyPath: missing),
        _throwsMatching(
          r'tlsTerminate\.caKeyPath: cannot read .*nope\.key \(ENOENT\)',
        ),
      );
    });

    test('throws when cert file is not PEM', () {
      expect(
        () => createMitmCA(caCertPath: junkPath, caKeyPath: keyPath),
        _throwsMatching(
          r'tlsTerminate\.caCertPath: .* is not a PEM CERTIFICATE',
        ),
      );
    });

    test('throws when key file is not PEM', () {
      expect(
        () => createMitmCA(caCertPath: certPath, caKeyPath: junkPath),
        _throwsMatching(
          r'tlsTerminate\.caKeyPath: .* is not a PEM PRIVATE KEY',
        ),
      );
    });

    test('throws when cert and key are swapped', () {
      expect(
        () => createMitmCA(caCertPath: keyPath, caKeyPath: certPath),
        _throwsMatching(r'is not a PEM CERTIFICATE'),
      );
    });
  });

  group('mitm-ca: ephemeral generation', () {
    test(
      'createMitmCA({}) generates a CA, writes PEMs to a temp dir',
      () async {
        final ca = createMitmCA();
        try {
          expect(ca.ephemeral, true);
          expect(ca.certPath, contains('srt-ca-'));
          expect(readFileSync(ca.certPath, 'utf8'), ca.certPem);
          expect(readFileSync(ca.keyPath, 'utf8'), ca.keyPem);
          expect(ca.certPem, contains('-----BEGIN CERTIFICATE-----'));
          expect(
            ca.cert.subject.getField('CN')!.value,
            'sandbox-runtime ephemeral CA',
          );
          expect(ca.key.n, isNotNull);
          // Can mint a leaf against it.
          final leaf = mintLeafCert(ca, 'example.com');
          expect(leaf.certPem, contains('-----BEGIN CERTIFICATE-----'));
        } finally {
          await disposeMitmCA(ca);
        }
      },
    );

    test(
      'disposeMitmCA removes the temp dir for ephemeral, no-ops for user CA',
      () async {
        final eph = createMitmCA();
        final dir = dirname(eph.certPath);
        expect(existsSync(dir), true);
        await disposeMitmCA(eph);
        expect(existsSync(dir), false);

        final user = createMitmCA(caCertPath: certPath, caKeyPath: keyPath);
        expect(user.ephemeral, false);
        await disposeMitmCA(user); // must not delete the fixture
        expect(existsSync(certPath), true);
      },
    );

    test(
      'writes a trust bundle: MITM CA first, then the host root store',
      () async {
        // The child's trust env vars (SSL_CERT_FILE etc.) REPLACE the tool's
        // root store, so the bundle must contain the system roots too or hosts
        // exempted from termination (tlsTerminate.excludeDomains) could never
        // be verified by the in-sandbox client.
        final ca = createMitmCA();
        try {
          final bundle = readFileSync(ca.trustBundlePath, 'utf8') as String;
          expect(bundle.startsWith(ca.certPem.trim()), true);
          final certCount = RegExp(
            r'-----BEGIN CERTIFICATE-----',
          ).allMatches(bundle).length;
          expect(certCount, greaterThan(1));
        } finally {
          await disposeMitmCA(ca);
        }
      },
    );

    test(
      'disposeMitmCA removes the trust-bundle dir of a user-supplied CA',
      () async {
        final user = createMitmCA(caCertPath: certPath, caKeyPath: keyPath);
        final bundleDir = dirname(user.trustBundlePath);
        expect(bundleDir, isNot(dirname(certPath)));
        expect(existsSync(user.trustBundlePath), true);
        await disposeMitmCA(user);
        expect(existsSync(bundleDir), false);
        expect(existsSync(certPath), true); // fixture untouched
      },
    );

    test(
      'disposeMitmCASync removes what disposeMitmCA does, before or after it',
      () async {
        final eph = createMitmCA();
        disposeMitmCASync(eph);
        expect(existsSync(dirname(eph.keyPath)), false);
        expect(existsSync(dirname(eph.trustBundlePath)), false);
        await disposeMitmCA(eph);
        disposeMitmCASync(eph);

        final user = createMitmCA(caCertPath: certPath, caKeyPath: keyPath);
        disposeMitmCASync(user);
        expect(existsSync(dirname(user.trustBundlePath)), false);
        expect(existsSync(keyPath), true); // fixture untouched
      },
    );

    test(
      'signCertificateNative is byte-identical to node-forge cert.sign()',
      () async {
        // RSASSA-PKCS1-v1_5 is deterministic, so signing the same TBSCertificate
        // with the same key via native crypto and via node-forge's pure-JS RSA
        // must produce the same signature bytes — and therefore the same PEM.
        // This is the equivalence guarantee that lets generateEphemeralCA(),
        // generateEmptyCrl(), and mintLeafCert() use native crypto for the RSA
        // private-key operation without changing what ends up on the wire.
        final ca = createMitmCA();
        try {
          final pki = forge.pki;
          final md = forge.md;
          // Rebuild an unsigned copy of the ephemeral CA's own cert (same
          // subject/issuer/serial/validity/extensions/public key), then sign that
          // one copy with node-forge. `ca.cert` was signed via the native path.
          final ref = pki.createCertificate();
          ref.publicKey = ca.cert.publicKey;
          ref.serialNumber = ca.cert.serialNumber;
          ref.validity.notBefore = ca.cert.validity.notBefore;
          ref.validity.notAfter = ca.cert.validity.notAfter;
          ref.setSubject(ca.cert.subject.attributes);
          ref.setIssuer(ca.cert.issuer.attributes);
          ref.setExtensions(ca.cert.extensions);
          ref.sign(ca.key, md.sha256.create());

          expect(
            latin1.encode(ca.cert.signature),
            latin1.encode(ref.signature),
          );
          expect(ca.certPem, pki.certificateToPem(ref));
          // Re-signing the reference cert via the native path is also identical.
          signCertificateNative(ref, ca.keyPem);
          expect(ca.certPem, pki.certificateToPem(ref));
          // And node-forge's own verifier accepts the native-signed cert.
          expect(ref.verify(ca.cert), true);
        } finally {
          await disposeMitmCA(ca);
        }
      },
    );

    test('throws when only one of caCertPath/caKeyPath is provided', () {
      expect(
        () => createMitmCA(caCertPath: certPath),
        _throwsMatching(r'must be provided together'),
      );
      expect(
        () => createMitmCA(caKeyPath: keyPath),
        _throwsMatching(r'must be provided together'),
      );
    });
  });

  group('mitm-ca: generateCa + validateCaPair', () {
    // One shared pair — RSA-2048 keygen dominates the cost.
    final g = generateCa(cn: 'srt-test-generateCa', validityDays: 7);

    test('generateCa: cn + validityDays are honoured; pair validates', () {
      final cert = forge.pki.certificateFromPem(g.certPem);
      expect(cert.subject.getField('CN')!.value, 'srt-test-generateCa');
      // notAfter within [6, 8] days from now (allow for slow CI + DST).
      final days =
          (cert.validity.notAfter.millisecondsSinceEpoch -
              DateTime.now().millisecondsSinceEpoch) /
          (24 * 60 * 60 * 1000);
      expect(days, greaterThan(5));
      expect(days, lessThan(9));
      final v = validateCaPair(g.certPem, g.keyPem);
      expect(v.ok, true);
      if (v.ok) {
        v as CaPairValidationSuccess;
        expect(
          v.notAfter.millisecondsSinceEpoch,
          cert.validity.notAfter.millisecondsSinceEpoch,
        );
        // 40 uppercase-hex chars, no separators — matches srt-win's
        // `CertDer::thumb()` and PowerShell's `Cert:\…\Thumbprint`.
        expect(v.thumbprint, matches(RegExp(r'^[0-9A-F]{40}$')));
        expect(v.thumbprint, certThumbprint(g.certPem));
      }
    });

    test('generateCa: defaults match the ephemeral CA (cn + 825d)', () {
      // The defaults are also what the ephemeral in-process CA uses, so
      // this row pins that generateEphemeralCA's refactor to call
      // generateCa() didn't change its output shape.
      final d = generateCa();
      final cert = forge.pki.certificateFromPem(d.certPem);
      expect(
        cert.subject.getField('CN')!.value,
        'sandbox-runtime ephemeral CA',
      );
      final days =
          (cert.validity.notAfter.millisecondsSinceEpoch -
              DateTime.now().millisecondsSinceEpoch) /
          (24 * 60 * 60 * 1000);
      expect(days.round(), 825);
    });

    test('validateCaPair: mismatched key → ok:false', () {
      // Fixture cert with the freshly-generated key: moduli differ.
      final v = validateCaPair(certPem, g.keyPem);
      expect(v.ok, false);
      if (!v.ok) {
        expect(
          (v as CaPairValidationFailure).reason,
          matches(RegExp(r'does not match')),
        );
      }
    });

    test('validateCaPair: unparseable input → ok:false, not throw', () {
      expect(validateCaPair('not pem', g.keyPem).ok, false);
      expect(validateCaPair(g.certPem, 'not pem').ok, false);
    });

    test('validateCaPair: fixture cert+key → ok:true', () {
      // The committed fixture is a real matching pair.
      final v = validateCaPair(certPem, keyPem);
      expect(v.ok, true);
    });

    test(
      'validateCaPair: notBefore in the future → ok:false (clock-skew guard)',
      () {
        // Re-sign the generated CA with notBefore pushed into the future,
        // as a system-clock-ahead-then-NTP-corrected machine would
        // produce. Without this check the persistent-CA layer would keep
        // reusing a cert schannel/OpenSSL both reject as not-yet-valid.
        final c = forge.pki.certificateFromPem(g.certPem);
        c.validity.notBefore = DateTime.now().add(const Duration(days: 1));
        signCertificateNative(c, g.keyPem);
        final v = validateCaPair(forge.pki.certificateToPem(c), g.keyPem);
        expect(v.ok, false);
        if (!v.ok) {
          expect(
            (v as CaPairValidationFailure).reason,
            matches(RegExp(r'notBefore .* is in the future')),
          );
        }
      },
    );
  });

  group('mitm-ca: generateEmptyCrl', () {
    // The CRL is what the proxy serves at /srt.crl so Schannel's revocation
    // check on MITM-minted leaves resolves to "not revoked" instead of
    // hard-failing CRYPT_E_NO_REVOCATION_CHECK. One ephemeral CA for the
    // whole describe — RSA-2048 keygen is the slow part.
    late MitmCA ca;
    setUpAll(() {
      ca = createMitmCA();
    });
    tearDownAll(() async {
      await disposeMitmCA(ca);
    });

    test('createMitmCA populates crlDer on both load paths', () async {
      final user = createMitmCA(caCertPath: certPath, caKeyPath: keyPath);
      try {
        for (final c in [ca, user]) {
          expect(c.crlDer, isA<Uint8List>());
          expect(c.crlDer.length, greaterThan(0));
        }
      } finally {
        await disposeMitmCA(user);
      }
    });

    test(
      'parses as a v2 CRL: issuer==CA subject, no revoked certs, AKI matches CA SKI',
      () {
        // node-forge has no CRL parser either, so validate the DER structurally
        // via asn1.fromDer. The `openssl crl` test below is the interop check.
        final asn1 = forge.asn1;
        final pki = forge.pki;
        final util = forge.util;
        final crl = asn1.fromDer(latin1.decode(ca.crlDer));
        // CertificateList ::= SEQUENCE { tbsCertList, signatureAlgorithm, signature }
        final [tbs, _, sig] = crl.value as List<dynamic>;
        expect(sig.type, asn1.Type.BITSTRING);
        // TBSCertList ::= SEQUENCE { version, signature, issuer, thisUpdate,
        //   nextUpdate, [revokedCertificates absent], crlExtensions }
        final tbsFields = (tbs.value as List<dynamic>).cast<ForgeAsn1>();
        expect(tbsFields, hasLength(6)); // absent revokedCertificates
        // issuer Name matches the CA subject byte-for-byte.
        final issuerDer = asn1.toDer(tbsFields[2]).getBytes();
        final caSubjectDer = asn1
            .toDer(pki.distinguishedNameToAsn1(ca.cert.subject))
            .getBytes();
        expect(issuerDer, caSubjectDer);
        // crlExtensions carries AKI whose keyid = the CA's SKI (raw bytes,
        // not the hex-string node-forge stores — same trap as mitm-leaf).
        final caSki = ca.cert.generateSubjectKeyIdentifier().toHex();
        final extsDer = util.bytesToHex(asn1.toDer(tbsFields[5]).getBytes());
        expect(extsDer, contains(caSki));
      },
    );

    // Signature verification via openssl — the strongest correctness signal.
    final hasOpenssl = whichSync('openssl') != null;
    void opensslTest(String name, dynamic Function() body) =>
        test(name, skip: hasOpenssl ? null : 'openssl not found', body);
    opensslTest(
      'openssl crl parses it and verifies the signature against the CA',
      () {
        // Pipe DER on stdin (no `-in` → stdin) — the CRL is served from
        // memory, not disk.
        final text = spawnSync(
          'openssl',
          ['crl', '-inform', 'DER', '-noout', '-text'],
          {'input': ca.crlDer, 'encoding': 'utf8'},
        );
        expect(text.status, 0);
        expect(
          text.stdout as String,
          matches(RegExp(r'Issuer:.*sandbox-runtime ephemeral CA')),
        );
        expect(text.stdout as String, contains('No Revoked Certificates'));
        expect(
          text.stdout as String,
          matches(RegExp(r'CRL Number:\s*\n?\s*1')),
        );
        // -CAfile makes openssl verify the CRL signature against the CA.
        // "verify OK" goes to stderr; a bad signature exits non-zero.
        final verify = spawnSync(
          'openssl',
          ['crl', '-inform', 'DER', '-noout', '-CAfile', ca.certPath],
          {'input': ca.crlDer, 'encoding': 'utf8'},
        );
        expect(verify.status, 0);
        expect(verify.stderr as String, matches(RegExp(r'verify OK')));
      },
    );
  });

  group('mitm-ca: extraCaCertPaths', () {
    // A site-local root (e.g. an internal mTLS CA) that excluded/passthrough
    // hosts present. Reuse the committed fixture CA as a structurally real PEM.
    final scratch = mkdtempSync(join(tmpdir(), 'srt-extra-ca-'));
    final extraRootPath = join(scratch, 'extra-root.pem');
    writeFileSync(extraRootPath, certPem);
    final notACert = join(scratch, 'not-a-cert.pem');
    writeFileSync(
      notACert,
      '-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n',
    );
    // Combined cert+key PEM — a common layout for "the CA file". Only the
    // CERTIFICATE block may reach the (world-readable) trust bundle.
    final combined = join(scratch, 'combined.pem');
    writeFileSync(combined, certPem + keyPem);

    tearDownAll(() {
      rmSync(scratch, {'recursive': true, 'force': true});
    });

    test('appends the PEM to the trust bundle (ephemeral CA path)', () async {
      final ca = createMitmCA(extraCaCertPaths: [extraRootPath]);
      try {
        final bundle = readFileSync(ca.trustBundlePath, 'utf8') as String;
        // MITM CA still first; the extra root rides along at the end.
        expect(bundle.startsWith(ca.certPem.trim()), true);
        expect(bundle, contains(certPem.trim()));
      } finally {
        await disposeMitmCA(ca);
      }
    });

    test('appends the PEM on the user-supplied CA path too (loadCA)', () async {
      final ca = createMitmCA(
        caCertPath: certPath,
        caKeyPath: keyPath,
        extraCaCertPaths: [extraRootPath],
      );
      try {
        final bundle = readFileSync(ca.trustBundlePath, 'utf8') as String;
        // The fixture CA is both the MITM CA and the "extra" root here, so it
        // must appear twice: once as the bundle head, once appended.
        final occurrences = bundle.split(certPem.trim()).length - 1;
        expect(occurrences, 2);
      } finally {
        await disposeMitmCA(ca);
      }
    });

    test('skips missing paths without throwing', () async {
      final ca = createMitmCA(
        extraCaCertPaths: [join(scratch, 'nope.pem'), extraRootPath],
      );
      try {
        final bundle = readFileSync(ca.trustBundlePath, 'utf8') as String;
        // The missing path is skipped; later entries are still appended.
        expect(bundle, contains(certPem.trim()));
      } finally {
        await disposeMitmCA(ca);
      }
    });

    test('skips files with no PEM CERTIFICATE block', () async {
      final ca = createMitmCA(extraCaCertPaths: [notACert]);
      try {
        expect(
          readFileSync(ca.trustBundlePath, 'utf8') as String,
          isNot(contains('PRIVATE KEY')),
        );
      } finally {
        await disposeMitmCA(ca);
      }
    });

    test(
      'copies only the CERTIFICATE blocks of a combined cert+key file',
      () async {
        // The trust bundle is world-readable and handed to the sandboxed child:
        // a private key sitting next to the cert must never reach it.
        final ca = createMitmCA(extraCaCertPaths: [combined]);
        try {
          final bundle = readFileSync(ca.trustBundlePath, 'utf8') as String;
          expect(bundle, contains(certPem.trim()));
          expect(bundle, isNot(contains('PRIVATE KEY')));
        } finally {
          await disposeMitmCA(ca);
        }
      },
    );
  });
}
