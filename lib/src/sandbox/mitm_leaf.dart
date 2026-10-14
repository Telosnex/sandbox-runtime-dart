// STUB: pending port of src/sandbox/mitm-leaf.ts @ 24eb39e.
// ignore_for_file: slash_for_doc_comments, dangling_library_doc_comments
// ignore_for_file: unintended_html_in_doc_comment

import '../node/tls.dart' as tls;
import 'mitm_ca.dart';

/**
 * Per-host leaf certificate minter for the in-process TLS-terminating proxy.
 *
 * Given a MitmCA (see mitm-ca.ts), mints a leaf certificate for a specific
 * hostname on first use and caches it for the lifetime of that CA instance.
 * The leaf is signed by the CA and carries SAN=DNS:<host> (or IP:<addr>),
 * so a client that trusts the CA will accept it for that host.
 */
class LeafCert {
  /// Leaf cert PEM followed by the CA cert PEM (full chain).
  final String certPem;

  /// Leaf private key PEM.
  final String keyPem;

  const LeafCert({required this.certPem, required this.keyPem});
}

/**
 * Mint (or return cached) an RSA-2048 leaf cert for `hostname`, signed by `ca`.
 * The cache lives on `ca.leafCerts`.
 */
LeafCert mintLeafCert(MitmCA ca, String hostname) =>
    throw UnimplementedError('pending port of src/sandbox/mitm-leaf.ts');

/**
 * Mint-or-cache a Node TLS SecureContext for `hostname`. Intended as the
 * SNICallback target in the terminating proxy. The cache lives on
 * `ca.secureContexts`.
 */
tls.SecureContext secureContextFor(MitmCA ca, String hostname) =>
    throw UnimplementedError('pending port of src/sandbox/mitm-leaf.ts');
