// Ported from sandbox-runtime src/sandbox/mitm-ca.ts @ 24eb39e.
// ignore_for_file: slash_for_doc_comments, dangling_library_doc_comments
// ignore_for_file: constant_identifier_names, doc_directive_unknown
// ignore_for_file: curly_braces_in_flow_control_structures, prefer_function_declarations_over_variables

import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import '../node/crypto.dart' as crypto;
import '../node/forge.dart' as forge;
import '../utils/debug.dart' show logForDebugging;
import '../node/tls.dart' as tls;
import 'mitm_leaf.dart';

/**
 * MITM CA loader/generator for the in-process TLS-terminating proxy.
 *
 * The CA is supplied via `network.tlsTerminate.{caCertPath,caKeyPath}` (see
 * sandbox-config.ts). If both paths are omitted, SRT generates an ephemeral
 * RSA-2048 self-signed CA into a temp directory; the cert path is what the
 * trust env vars point at. The caller is responsible for cleaning up via
 * `disposeMitmCA()` (SandboxManager.reset() does this).
 */
class MitmCA {
  final String certPath;
  final String keyPath;

  /**
   * PEM bundle the sandboxed child's trust env vars point at: this CA
   * followed by the host's regular roots (Node's bundled Mozilla store plus
   * the parent's NODE_EXTRA_CA_CERTS, if any) and any configured
   * tlsTerminate.extraCaCertPaths. Most of the per-tool vars
   * (SSL_CERT_FILE, CURL_CA_BUNDLE, REQUESTS_CA_BUNDLE, ...) REPLACE the
   * tool's trust store rather than extend it, so pointing them at the CA
   * alone would leave the child unable to verify any real certificate —
   * which matters for connections SRT does not terminate
   * (tlsTerminate.excludeDomains). Always lives in an SRT-owned temp dir.
   */
  final String trustBundlePath;
  final String certPem;
  final String keyPem;

  /// Parsed CA certificate (issuer for minted leaf certs).
  final forge.Certificate cert;

  /// Parsed CA private key. RSA only.
  final forge.PrivateKey key;

  /// Per-hostname cache of leaf certs minted against this CA.
  final Map<String, LeafCert> leafCerts;

  /// Per-hostname cache of TLS SecureContexts wrapping the leaf certs.
  final Map<String, tls.SecureContext> secureContexts;

  /// How many host names the two caches above keep (default 256).
  final int? cacheLimit;

  /// The key pair every leaf minted against this CA uses (see mintLeafCert).
  forge.KeyPair? leafKeyPair;

  /**
   * DER-encoded empty CRL signed by this CA. Schannel (Windows System32
   * curl, git's default backend, cargo) checks revocation on every leaf and
   * hard-fails when a CRL Distribution Point can't be reached — see
   * `crlUrl`. Serving this at that URL turns "revocation unknown" into
   * "checked; not revoked" without a per-tool `--ssl-no-revoke` /
   * `schannelCheckRevoke=false` / `CARGO_HTTP_CHECK_REVOKE=false`.
   */
  final Uint8List crlDer;

  /**
   * URL every minted leaf's `cRLDistributionPoints` extension points at
   * (`http://127.0.0.1:<proxyPort>/srt.crl`). Set by sandbox-manager on
   * Windows once the local mux port is bound; the proxy answers a plain
   * GET on that path with `crlDer`. Left unset on Linux/macOS (child sees
   * the proxy at a different port under bwrap --unshare-net, so a
   * host-namespace URL would be unreachable) and when the HTTP proxy is
   * external — in both cases leaves carry no CDP, i.e. pre-CRL behaviour.
   */
  final String? crlUrl;

  /**
   * True when SRT generated this CA into a temp directory. disposeMitmCA()
   * removes that directory; user-supplied CAs are left alone.
   */
  final bool ephemeral;

  MitmCA({
    required this.certPath,
    required this.keyPath,
    required this.trustBundlePath,
    required this.certPem,
    required this.keyPem,
    required this.cert,
    required this.key,
    required this.leafCerts,
    required this.secureContexts,
    this.cacheLimit,
    this.leafKeyPair,
    required this.crlDer,
    this.crlUrl,
    required this.ephemeral,
  });
}

/** Origin-form path the HTTP proxy answers with `crlDer`. */
const CRL_PATH = '/srt.crl';

/**
 * Return the CA's Subject Key Identifier as raw bytes for use as an
 * authorityKeyIdentifier.keyIdentifier (leaf certs and the CRL both need it).
 *
 * node-forge stores a cert's subjectKeyIdentifier extension value as a *hex
 * string* (both for in-memory certs and certs parsed from PEM), but expects
 * AKI's keyIdentifier as *raw bytes* — passing the hex through verbatim
 * encodes the ASCII hex chars as the key id and the chain fails to verify.
 * If the CA has no SKI extension (e.g. a v1 user-supplied CA), derive the
 * RFC 5280 method-1 value from its public key.
 */
String caSubjectKeyId(forge.Certificate caCert) =>
    (caCert.getExtension('subjectKeyIdentifier')?['subjectKeyIdentifier']
            as String?) !=
        null
    ? forge.forge.util.hexToBytes(
        caCert.getExtension('subjectKeyIdentifier')!['subjectKeyIdentifier']
            as String,
      )
    : caCert.generateSubjectKeyIdentifier().getBytes();

/**
 * Drop-in replacement for `cert.sign(key, md.sha256.create())` that computes
 * the RSASSA-PKCS1-v1_5 / SHA-256 signature via Node's native `crypto.sign()`
 * instead of node-forge's pure-JS RSA.
 *
 * node-forge routes RSA *keypair generation* to native `crypto` when available,
 * but its `PrivateKey.sign()` is always pure JS, which is slow enough to matter
 * because `generateEphemeralCA()` runs on the cold path of every process that
 * constructs a SandboxManager. RSASSA-PKCS1-v1_5 is deterministic, so native
 * `crypto.sign()` yields identical bytes.
 */
void signCertificateNative(forge.Certificate cert, String keyPem) {
  final oid = forge.forge.pki.oids.sha256WithRSAEncryption;
  cert.siginfo.algorithmOid = oid;
  cert.signatureOid = oid;
  cert.tbsCertificate = forge.forge.pki.getTBSCertificate(cert);
  final tbsDer = forge.forge.asn1.toDer(cert.tbsCertificate!).getBytes();
  cert.signature = rsaSha256SignNative(tbsDer, keyPem);
  // Match cert.sign()'s side effect so callers that read cert.md see the same
  // populated digest a forge-signed cert would carry.
  cert.md = forge.forge.md.sha256.create()..update(tbsDer);
}

/**
 * RSASSA-PKCS1-v1_5 / SHA-256 sign of a forge binary-string `der` with the
 * PEM-encoded RSA private key `keyPem`, returning the signature as a forge
 * binary string. Native equivalent of `forgeKey.sign(sha256Digest)`.
 */
String rsaSha256SignNative(String der, String keyPem) => String.fromCharCodes(
  (crypto.sign(
        'sha256',
        Uint8List.fromList(der.codeUnits.map((e) => e & 0xff).toList()),
        keyPem,
      )
      as Uint8List),
);

/**
 * Create a MitmCA. If `caCertPath`/`caKeyPath` are provided, load from disk
 * (throws if either file is missing, unreadable, not PEM, fails to parse, or
 * the key is not RSA). If both are omitted, generate an ephemeral CA into a
 * fresh temp directory.
 *
 * Pure factory: no module-level state. The caller (SandboxManager) owns the
 * returned object and its lifetime.
 */
MitmCA createMitmCA({
  String? caCertPath,
  String? caKeyPath,
  /**
   * PEM strings for the CA — used when the caller has already read /
   * generated them (e.g. the Windows persistent-CA path). When set,
   * `caCertPath`/`caKeyPath` are recorded on the returned {@link MitmCA}
   * but NOT read from disk.
   */
  String? caCertPem,
  String? caKeyPem,

  /// PEM CA files appended to the trust bundle; unreadable paths skipped.
  List<String>? extraCaCertPaths,
}) {
  if (caCertPem != null &&
      caCertPem.isNotEmpty &&
      caKeyPem != null &&
      caKeyPem.isNotEmpty) {
    final v = validateCaPair(caCertPem, caKeyPem);
    if (!v.ok)
      throw Exception(
        'tlsTerminate: CA PEM pair: ${(v as CaPairValidationFailure).reason}',
      );
    final ok = v as CaPairValidationSuccess;
    return _buildMitmCA(
      caCertPem,
      caKeyPem,
      ok.cert,
      ok.key,
      certPath: caCertPath ?? '',
      keyPath: caKeyPath ?? '',
      extraCaCertPaths: extraCaCertPaths,
    );
  }
  if (caCertPath != null && caKeyPath != null)
    return _loadCA(caCertPath, caKeyPath, extraCaCertPaths);
  if (caCertPath != null || caKeyPath != null)
    throw Exception(
      'tlsTerminate: caCertPath and caKeyPath must be provided together',
    );
  return _generateEphemeralCA(extraCaCertPaths);
}

/**
 * Remove the SRT-owned temp directories for this CA: the trust-bundle dir
 * always, and the cert/key dir, a directory of its own, too when SRT
 * generated the CA. User-supplied CA files are left alone.
 */
Future<void> disposeMitmCA(MitmCA ca) => Future.wait(
  _ownedDirs(ca).map((dir) async {
    try {
      await Directory(dir).delete(recursive: true);
    } catch (err) {
      logForDebugging('[mitm-ca] cleanup failed: $err', level: 'warn');
    }
  }),
);

/**
 * {@link disposeMitmCA} in one synchronous step, as a process 'exit' handler
 * needs it: nothing awaited runs there. Harmless before, during or after the
 * asynchronous one.
 */
void disposeMitmCASync(MitmCA ca) => _ownedDirs(ca).forEach((dir) {
  try {
    Directory(dir).deleteSync(recursive: true);
  } catch (err) {
    logForDebugging('[mitm-ca] cleanup failed: $err', level: 'warn');
  }
});

/**
 * Build a DER-encoded X.509 v2 CRL, signed by `key`, listing zero revoked
 * certificates. `nextUpdate` is the CA's `notAfter` (or now+1d if the CA is
 * already expired) so a single per-session CRL stays fresh for the CA's
 * lifetime.
 *
 * node-forge has no CRL builder, so this hand-assembles the RFC 5280 §5.1
 * `CertificateList` from asn1 primitives — the same approach the library
 * uses internally for certificates. Carries the two extensions RFC 5280
 * §5.2 says conforming issuers MUST include: `authorityKeyIdentifier`
 * (matching the CA's SKI) and `cRLNumber`.
 */
Uint8List generateEmptyCrl(forge.Certificate cert, String keyPem) {
  final asn1 = forge.forge.asn1;
  final pki = forge.forge.pki;
  final sigAlg = () => _seq([
    asn1.create(
      asn1.Class.UNIVERSAL,
      asn1.Type.OID,
      false,
      asn1.oidToDer(pki.oids.sha256WithRSAEncryption).getBytes(),
    ),
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.NULL, false, ''),
  ]);
  forge.ForgeAsn1 ext(String oid, forge.ForgeAsn1 value) => _seq([
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
    _seq([
      ext(
        pki.oids.authorityKeyIdentifier,
        _seq([
          asn1.create(
            asn1.Class.CONTEXT_SPECIFIC,
            0,
            false,
            caSubjectKeyId(cert),
          ),
        ]),
      ),
      ext(
        '2.5.29.20',
        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false, '\x01'),
      ),
    ]),
  ]);
  final now = DateTime.now();
  final nextUpdate = cert.validity.notAfter.isAfter(now)
      ? cert.validity.notAfter
      : daysFromNow(1);
  final tbs = _seq([
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false, '\x01'),
    sigAlg(),
    pki.distinguishedNameToAsn1(cert.subject),
    _asn1Time(now),
    _asn1Time(nextUpdate),
    extensions,
  ]);
  final sig = rsaSha256SignNative(asn1.toDer(tbs).getBytes(), keyPem);
  final crl = _seq([
    tbs,
    sigAlg(),
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.BITSTRING, false, '\x00$sig'),
  ]);
  return asn1.toDer(crl).getBuffer();
}

forge.ForgeAsn1 _seq(List<forge.ForgeAsn1> values) => forge.forge.asn1.create(
  forge.forge.asn1.Class.UNIVERSAL,
  forge.forge.asn1.Type.SEQUENCE,
  true,
  values,
);
forge.ForgeAsn1 _asn1Time(DateTime d) => d.toUtc().year < 2050
    ? forge.forge.asn1.create(
        forge.forge.asn1.Class.UNIVERSAL,
        forge.forge.asn1.Type.UTCTIME,
        false,
        forge.forge.asn1.dateToUtcTime(d),
      )
    : forge.forge.asn1.create(
        forge.forge.asn1.Class.UNIVERSAL,
        forge.forge.asn1.Type.GENERALIZEDTIME,
        false,
        forge.forge.asn1.dateToGeneralizedTime(d),
      );

/** Result of {@link generateCa}. PEMs plus the parsed forge objects. */
class GeneratedCa {
  final String certPem;
  final String keyPem;

  /// Parsed certificate — same object the PEM encodes.
  final forge.Certificate cert;

  /// Parsed RSA private key — same object the PEM encodes.
  final forge.PrivateKey key;

  const GeneratedCa({
    required this.certPem,
    required this.keyPem,
    required this.cert,
    required this.key,
  });
}

/**
 * Generate a self-signed RSA-2048 CA certificate + private key as PEM
 * strings. Pure — no filesystem side effects; the caller decides where (and
 * whether) to persist. This is the primitive under both the ephemeral
 * per-process CA and the Windows persistent CA
 * (`ensurePersistentWindowsCa`).
 *
 * @param opts.cn subject/issuer commonName. Default
 *   `'sandbox-runtime ephemeral CA'`.
 * @param opts.validityDays certificate `notAfter` in days from now.
 *   Default 825 (the CA/B Forum limit for publicly-trusted leaves; not
 *   binding on a private CA, but a reasonable rotation horizon).
 */
GeneratedCa generateCa({String? cn, int? validityDays}) =>
    _generateCa(cn: cn, validityDays: validityDays);

/**
 * SHA-1 thumbprint of `certPem` as uppercase hex with no separators —
 * the format `srt-win user status` reports (`ca_cert_thumb`) and
 * PowerShell's `Cert:\…\Thumbprint` uses. Throws if `certPem` is not a
 * parseable X.509 certificate.
 */
String certThumbprint(String certPem) => crypto.X509Certificate(
  certPem,
).fingerprint.replaceAll(':', '').toUpperCase();

/** Result of {@link validateCaPair}. */
sealed class CaPairValidation {
  const CaPairValidation();
  bool get ok;
}

class CaPairValidationSuccess extends CaPairValidation {
  final String thumbprint;
  final DateTime notAfter;

  /// Parsed certificate — reuse instead of re-parsing `certPem`.
  final forge.Certificate cert;

  /// Parsed RSA private key — reuse instead of re-parsing `keyPem`.
  final forge.PrivateKey key;

  const CaPairValidationSuccess({
    required this.thumbprint,
    required this.notAfter,
    required this.cert,
    required this.key,
  });

  @override
  bool get ok => true;
}

class CaPairValidationFailure extends CaPairValidation {
  final String reason;
  const CaPairValidationFailure(this.reason);

  @override
  bool get ok => false;
}

/**
 * Check that `certPem` + `keyPem` are a usable RSA CA pair: both parse, the
 * key is RSA (node-forge signs with nothing else), the private key's
 * modulus matches the certificate's public key (i.e. this key actually
 * signs for this cert), and `notBefore` is not in the future — a CA
 * minted while the system clock was ahead and later NTP-corrected would
 * otherwise be permanently not-yet-valid with nothing to trigger a
 * regenerate. Returns the cert's thumbprint and `notAfter` on success so
 * a caller can decide expiry policy without a second parse.
 *
 * Does not throw — a persistence layer that finds an unreadable/mismatched
 * pair on disk treats `{ok: false}` as "regenerate", not a hard error.
 */
CaPairValidation validateCaPair(String certPem, String keyPem) =>
    _validateCaPair(certPem, keyPem);

String randomSerial() => _randomSerial();

DateTime daysFromNow(int days) => DateTime.now().add(Duration(days: days));

Set<String> _ownedDirs(MitmCA ca) => {
  File(ca.trustBundlePath).parent.path,
  if (ca.ephemeral) File(ca.certPath).parent.path,
};

MitmCA _loadCA(
  String certPath,
  String keyPath,
  List<String>? extraCaCertPaths,
) {
  final certPem = _readPem(certPath, 'CERTIFICATE', 'tlsTerminate.caCertPath');
  final keyPem = _readPem(keyPath, 'PRIVATE KEY', 'tlsTerminate.caKeyPath');
  final v = validateCaPair(certPem, keyPem);
  if (!v.ok)
    throw Exception(
      'tlsTerminate: CA at $certPath: ${(v as CaPairValidationFailure).reason}',
    );
  final ok = v as CaPairValidationSuccess;
  logForDebugging('[mitm-ca] loaded CA from $certPath');
  return _buildMitmCA(
    certPem,
    keyPem,
    ok.cert,
    ok.key,
    certPath: certPath,
    keyPath: keyPath,
    extraCaCertPaths: extraCaCertPaths,
  );
}

MitmCA _buildMitmCA(
  String certPem,
  String keyPem,
  forge.Certificate cert,
  forge.PrivateKey key, {
  required String certPath,
  required String keyPath,
  List<String>? extraCaCertPaths,
  bool ephemeral = false,
}) {
  final bundleDir = Directory.systemTemp.createTempSync('srt-ca-');
  final trustPath = _writeTrustBundle(
    bundleDir.path,
    certPem,
    extraCaCertPaths,
  );
  return MitmCA(
    certPath: certPath,
    keyPath: keyPath,
    trustBundlePath: trustPath,
    certPem: certPem,
    keyPem: keyPem,
    cert: cert,
    key: key,
    leafCerts: {},
    secureContexts: {},
    crlDer: generateEmptyCrl(cert, keyPem),
    ephemeral: ephemeral,
  );
}

String _writeTrustBundle(
  String dir,
  String caCertPem,
  List<String>? extraCaCertPaths,
) {
  final parts = [caCertPem.trim(), ...tls.rootCertificates];
  final extra = Platform.environment['NODE_EXTRA_CA_CERTS'];
  if (extra != null) {
    try {
      parts.add(File(extra).readAsStringSync().trim());
    } catch (_) {}
  }
  for (final extraPath in extraCaCertPaths ?? <String>[]) {
    String raw;
    try {
      raw = File(extraPath).readAsStringSync();
    } catch (err) {
      logForDebugging(
        '[mitm-ca] extraCaCertPaths: cannot read $extraPath ($err); skipping',
        level: 'warn',
      );
      continue;
    }
    final certs = RegExp(
      r'-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----',
    ).allMatches(raw).map((m) => m.group(0)!).toList();
    if (certs.isEmpty) {
      logForDebugging(
        '[mitm-ca] extraCaCertPaths: $extraPath has no PEM CERTIFICATE block; skipping',
        level: 'warn',
      );
      continue;
    }
    parts.addAll(certs);
  }
  final path = '${Directory(dir).path}/trust-bundle.crt';
  File(path).writeAsStringSync(
    '${parts.join('\n')}\n',
    mode: FileMode.write,
    flush: true,
  );
  return path;
}

GeneratedCa _generateCa({String? cn, int? validityDays}) {
  final keys = forge.forge.pki.rsa.generateKeyPair(2048);
  final cert = forge.forge.pki.createCertificate()..publicKey = keys.publicKey;
  cert.serialNumber = randomSerial();
  cert.validity.notBefore = daysFromNow(-1);
  cert.validity.notAfter = daysFromNow(validityDays ?? 825);
  final subject = [
    {'name': 'commonName', 'value': cn ?? 'sandbox-runtime ephemeral CA'},
    {'name': 'organizationName', 'value': 'sandbox-runtime'},
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
  final keyPem = forge.forge.pki.privateKeyToPem(keys.privateKey);
  signCertificateNative(cert, keyPem);
  return GeneratedCa(
    certPem: forge.forge.pki.certificateToPem(cert),
    keyPem: keyPem,
    cert: cert,
    key: keys.privateKey,
  );
}

CaPairValidation _validateCaPair(String certPem, String keyPem) {
  late forge.Certificate cert;
  late forge.PrivateKey key;
  try {
    cert = forge.forge.pki.certificateFromPem(certPem);
    key = forge.forge.pki.privateKeyFromPem(keyPem);
  } catch (err) {
    return CaPairValidationFailure('parse: $err');
  }
  if (cert.publicKey == null || cert.publicKey!.n != key.n)
    return const CaPairValidationFailure(
      'key does not match certificate public key',
    );
  if (cert.validity.notBefore.isAfter(DateTime.now()))
    return CaPairValidationFailure(
      'notBefore ${cert.validity.notBefore.toIso8601String()} is in the future (clock skew?)',
    );
  try {
    return CaPairValidationSuccess(
      thumbprint: certThumbprint(certPem),
      notAfter: cert.validity.notAfter,
      cert: cert,
      key: key,
    );
  } catch (err) {
    return CaPairValidationFailure('thumbprint: $err');
  }
}

MitmCA _generateEphemeralCA(List<String>? extraCaCertPaths) {
  final generated = generateCa();
  final dir = Directory.systemTemp.createTempSync('srt-ca-');
  final certPath = '${dir.path}/ca.crt';
  final keyPath = '${dir.path}/ca.key';
  File(certPath).writeAsStringSync(generated.certPem);
  File(keyPath).writeAsStringSync(generated.keyPem);
  logForDebugging('[mitm-ca] generated ephemeral CA at $certPath');
  return _buildMitmCA(
    generated.certPem,
    generated.keyPem,
    generated.cert,
    generated.key,
    certPath: certPath,
    keyPath: keyPath,
    extraCaCertPaths: extraCaCertPaths,
    ephemeral: true,
  );
}

String _readPem(String path, String label, String field) {
  late String pem;
  try {
    pem = File(path).readAsStringSync();
  } catch (err) {
    throw Exception('$field: cannot read $path ($err)');
  }
  if (!RegExp('-----BEGIN [A-Z ]*$label-----').hasMatch(pem))
    throw Exception('$field: $path is not a PEM $label');
  return pem;
}

String _randomSerial() {
  final hex = forge.forge.util.bytesToHex(forge.forge.random.getBytesSync(16));
  final firstNibble = (int.parse(hex[0], radix: 16) & 0x3) | 0x4;
  return '${firstNibble.toRadixString(16)}${hex.substring(1)}';
}
