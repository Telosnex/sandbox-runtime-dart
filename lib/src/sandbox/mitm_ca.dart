// STUB: pending port of src/sandbox/mitm-ca.ts @ 24eb39e.
// ignore_for_file: slash_for_doc_comments, dangling_library_doc_comments
// ignore_for_file: constant_identifier_names, doc_directive_unknown

import 'dart:typed_data';

import '../node/forge.dart' as forge;
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
  final forge.KeyPair? leafKeyPair;

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

  const MitmCA({
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
    throw UnimplementedError('pending port of src/sandbox/mitm-ca.ts');

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
void signCertificateNative(forge.Certificate cert, String keyPem) =>
    throw UnimplementedError('pending port of src/sandbox/mitm-ca.ts');

/**
 * RSASSA-PKCS1-v1_5 / SHA-256 sign of a forge binary-string `der` with the
 * PEM-encoded RSA private key `keyPem`, returning the signature as a forge
 * binary string. Native equivalent of `forgeKey.sign(sha256Digest)`.
 */
String rsaSha256SignNative(String der, String keyPem) =>
    throw UnimplementedError('pending port of src/sandbox/mitm-ca.ts');

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
}) => throw UnimplementedError('pending port of src/sandbox/mitm-ca.ts');

/**
 * Remove the SRT-owned temp directories for this CA: the trust-bundle dir
 * always, and the cert/key dir, a directory of its own, too when SRT
 * generated the CA. User-supplied CA files are left alone.
 */
Future<void> disposeMitmCA(MitmCA ca) =>
    throw UnimplementedError('pending port of src/sandbox/mitm-ca.ts');

/**
 * {@link disposeMitmCA} in one synchronous step, as a process 'exit' handler
 * needs it: nothing awaited runs there. Harmless before, during or after the
 * asynchronous one.
 */
void disposeMitmCASync(MitmCA ca) =>
    throw UnimplementedError('pending port of src/sandbox/mitm-ca.ts');

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
Uint8List generateEmptyCrl(forge.Certificate cert, String keyPem) =>
    throw UnimplementedError('pending port of src/sandbox/mitm-ca.ts');

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
    throw UnimplementedError('pending port of src/sandbox/mitm-ca.ts');

/**
 * SHA-1 thumbprint of `certPem` as uppercase hex with no separators —
 * the format `srt-win user status` reports (`ca_cert_thumb`) and
 * PowerShell's `Cert:\…\Thumbprint` uses. Throws if `certPem` is not a
 * parseable X.509 certificate.
 */
String certThumbprint(String certPem) =>
    throw UnimplementedError('pending port of src/sandbox/mitm-ca.ts');

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
    throw UnimplementedError('pending port of src/sandbox/mitm-ca.ts');

String randomSerial() =>
    throw UnimplementedError('pending port of src/sandbox/mitm-ca.ts');

DateTime daysFromNow(int days) =>
    throw UnimplementedError('pending port of src/sandbox/mitm-ca.ts');
