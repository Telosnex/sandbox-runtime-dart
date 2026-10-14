// Node-compatible TLS helpers required by sandbox-runtime's MITM proxy.
// The checked-in Mozilla bundle is generated from curl's dated cacert.pem;
// no platform trust store is consulted by rootCertificates/trustedRootContext.
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:asn1lib/asn1lib.dart' as asn1lib;

import 'errno.dart';
import 'mozilla_roots.dart';
import 'net.dart' as net;

export 'mozilla_roots.dart'
    show mozillaRootBundleVersion, mozillaRootBundleSha256;

/// Node's `tls.rootCertificates`, each element is one PEM certificate.
/// Bundle version/hash are exported from mozilla_roots.dart and pinned in git.
final List<String> rootCertificates = List<String>.unmodifiable(
  mozillaRootCertificates,
);

/// The Dart object used as the Node `SecureContext` equivalent.
typedef SecureContext = SecurityContext;

/// Create a certificate-bearing server context. The ALPN setting belongs on
/// the SecurityContext as well as the secureServer call; otherwise Dart may
/// complete TLS with no selected protocol despite `supportedProtocols`.
SecureContext createSecureContext({
  required String cert,
  required String key,
  List<String> protocols = const ['http/1.1'],
}) {
  final context = SecurityContext(withTrustedRoots: false)
    ..useCertificateChainBytes(Uint8List.fromList(utf8.encode(cert)))
    ..usePrivateKeyBytes(Uint8List.fromList(utf8.encode(key)))
    ..setAlpnProtocols(protocols, true);
  return context;
}

/// Explicit Node-compatible Mozilla roots for outbound TLS.
SecurityContext trustedRootContext() {
  final context = SecurityContext(withTrustedRoots: false);
  for (final certificate in rootCertificates) {
    context.setTrustedCertificatesBytes(
      Uint8List.fromList(utf8.encode(certificate)),
    );
  }
  return context;
}

/// Node `tls.TLSSocket`: returned by [connect], or made over a connected
/// socket with `TLSSocket(socket, {'isServer': true, ...})`.
class TLSSocket extends net.NodeSocket {
  TLSSocket.pending({super.allowHalfOpen}) : super.pending();

  /// Node `new tls.TLSSocket(socket, options)`. Only the server side is
  /// supported: `isServer: true`, with the certificate in `secureContext`
  /// (see [createSecureContext]) and optional `ALPNProtocols`.
  ///
  /// Returns at once. Bytes [socket] holds unread, such as a ClientHello
  /// put back with `unshift`, are the start of the handshake. The socket
  /// emits 'secure' when the handshake is done, or 'error' then 'close';
  /// writes made before then are queued. [socket] stays a view of the
  /// connection, as in Node: see [net.NodeSocket.startServerTlsOver].
  ///
  /// Gap: [servername] stays null, since dart:io does not report the
  /// server name a client asked for. Read it from the ClientHello.
  TLSSocket(net.NodeSocket socket, [Map<Object?, Object?> options = const {}])
    // As in Node, not the socket's own setting.
    : super.over(allowHalfOpen: false) {
    final opts = Map<Object?, Object?>.of(options)
      ..removeWhere((key, value) => value == null);
    for (final key in opts.keys) {
      if (!_tlsSocketOptions.contains(key)) {
        throw UnimplementedError('tls.TLSSocket option "$key"');
      }
    }
    if (opts['isServer'] != true) {
      throw UnimplementedError('tls.TLSSocket on the client side');
    }
    final context = opts['secureContext'];
    if (context is! SecurityContext) {
      throw ArgumentError.value(
        context,
        'secureContext',
        'A server TLSSocket needs a SecureContext with its certificate',
      );
    }
    final protocols = (opts['ALPNProtocols'] as List?)?.cast<String>();
    // dart:io's server selects a protocol only from the context's list.
    if (protocols != null) context.setAlpnProtocols(protocols, true);
    startServerTlsOver(socket, (raw, buffered) async {
      final SecureSocket secured;
      try {
        secured = await SecureSocket.secureServer(
          raw,
          context,
          bufferedData: buffered,
          supportedProtocols: protocols,
        );
      } on HandshakeException catch (error) {
        throw NodeError(error.message, code: 'ERR_SSL_HANDSHAKE_FAILURE');
      } on TlsException catch (error) {
        throw NodeError(error.message, code: 'ERR_SSL_HANDSHAKE_FAILURE');
      }
      _setPeer(secured);
      secureEstablished = true;
      return secured;
    });
  }

  /// Node `tlsSocket.encrypted`.
  bool get encrypted => true;

  /// True once the handshake is done (Node's internal
  /// `_secureEstablished`, which upstream reads).
  bool secureEstablished = false;

  /// True when the peer certificate was verified, as in Node.
  bool authorized = false;

  /// Why [authorized] is false, when it is.
  Object? authorizationError;

  /// The ALPN protocol the server chose, or false, as in Node.
  Object alpnProtocol = false;

  String? servername;
  X509Certificate? _peer;

  /// The peer certificate (Node returns a parsed object; this is the
  /// dart:io certificate).
  X509Certificate? getPeerCertificate() => _peer;
}

const _tlsSocketOptions = {'isServer', 'secureContext', 'ALPNProtocols'};

const _tlsConnectOptions = {
  'host',
  'port',
  'path',
  'servername',
  'ca',
  'secureContext',
  'rejectUnauthorized',
  'checkServerIdentity',
  'ALPNProtocols',
  'lookup',
  'timeout',
  'allowHalfOpen',
  'noDelay',
};

/// Node `tls.connect(options[, secureConnectListener])`. Returns the socket
/// at once. It emits 'connect' when TCP connects and 'secureConnect' when
/// the handshake is done; writes made before then are queued.
///
/// As in Node, the certificate is checked against the trusted roots
/// ([rootCertificates], or `ca` / `secureContext`) and by
/// `checkServerIdentity(servername ?? host, cert)`. dart:io also checks the
/// name itself during the handshake; see the gap noted in the code. With
/// `rejectUnauthorized: false`, a failed check sets [TLSSocket.authorized]
/// to false and the connection stays open.
TLSSocket connect(Map<Object?, Object?> options, [Function? listener]) {
  final opts = Map<Object?, Object?>.of(options)
    ..removeWhere((key, value) => value == null);
  for (final key in opts.keys) {
    if (!_tlsConnectOptions.contains(key)) {
      throw UnimplementedError('tls.connect option "$key"');
    }
  }
  final host = opts['host'] as String? ?? 'localhost';
  // An empty servername asks for no SNI. Gap: dart:io always sends the name
  // it validates against, so '' only stops the name overriding [host].
  final requestedName = opts['servername'] as String?;
  final servername = requestedName == null
      ? (net.isIP(host) == 0 ? host : null)
      : (requestedName.isEmpty ? null : requestedName);
  final rejectUnauthorized = opts['rejectUnauthorized'] != false;
  final identity =
      opts['checkServerIdentity'] as Function? ?? checkServerIdentity;
  final context = secureContextFor(
    opts['ca'],
    opts['secureContext'] as SecurityContext?,
  );
  final protocols = (opts['ALPNProtocols'] as List?)?.cast<String>();
  final socket = TLSSocket.pending(allowHalfOpen: opts['allowHalfOpen'] == true)
    ..servername = servername;
  if (opts['noDelay'] == true) socket.setNoDelay();
  if (opts['timeout'] is int) socket.setTimeout(opts['timeout'] as int);
  if (listener != null) socket.once('secureConnect', listener);
  socket.startConnect(
    path: opts['path'] as String?,
    port: opts['port'] as int?,
    host: host,
    lookup: opts['lookup'] as net.LookupFunction?,
    secure: (raw) async {
      final name = servername ?? host;
      Object? failure;
      final SecureSocket secured;
      try {
        secured = await SecureSocket.secure(
          raw,
          // dart:io sends this name as SNI and checks the certificate against
          // it as well as against the trusted roots.
          host: name,
          context: context,
          supportedProtocols: protocols,
          onBadCertificate: (certificate) {
            // dart:io does not say which check failed. If the identity check
            // passes, the chain is not trusted; else report the identity
            // error. Gap: a custom checkServerIdentity that accepts a name
            // dart:io rejected is reported as an untrusted chain.
            failure =
                applyIdentity(identity, name, certificate) ??
                NodeError(
                  'unable to verify the first certificate',
                  code: 'UNABLE_TO_VERIFY_LEAF_SIGNATURE',
                );
            return !rejectUnauthorized;
          },
        );
      } on HandshakeException catch (error) {
        throw failure ??
            NodeError(
              'Client network socket disconnected before secure TLS '
              'connection was established: ${error.message}',
              code: 'ECONNRESET',
            );
      }
      socket._setPeer(secured);
      socket.secureEstablished = true;
      failure ??= applyIdentity(identity, name, secured.peerCertificate);
      socket.authorized = failure == null;
      socket.authorizationError = failure;
      if (failure != null && rejectUnauthorized) {
        secured.destroy();
        throw failure!;
      }
      return secured;
    },
  );
  return socket;
}

extension on TLSSocket {
  void _setPeer(SecureSocket secured) {
    _peer = secured.peerCertificate;
    alpnProtocol = secured.selectedProtocol ?? false;
  }
}

Object? applyIdentity(
  Function identity,
  String hostname,
  X509Certificate? certificate,
) => Function.apply(identity, [hostname, certificate]);

/// The context for a client connection: [context] as given, or one that
/// trusts [ca] (PEM text or bytes, or a list of them), or else
/// [trustedRootContext].
SecurityContext secureContextFor(Object? ca, SecurityContext? context) {
  if (context != null) {
    if (ca != null) {
      throw ArgumentError('Cannot combine a SecurityContext with a CA bundle');
    }
    return context;
  }
  if (ca == null) return trustedRootContext();
  final custom = SecurityContext(withTrustedRoots: false);
  void addCertificate(Object certificate) {
    if (certificate is String) {
      custom.setTrustedCertificatesBytes(utf8.encode(certificate));
    } else if (certificate is List<int>) {
      custom.setTrustedCertificatesBytes(Uint8List.fromList(certificate));
    } else {
      throw ArgumentError.value(
        certificate,
        'ca',
        'Expected PEM certificate bytes or text',
      );
    }
  }

  if (ca is Iterable && ca is! String) {
    for (final certificate in ca) {
      addCertificate(certificate as Object);
    }
  } else {
    addCertificate(ca);
  }
  return custom;
}

/// Node `tls.checkServerIdentity` result. A null result means the peer name
/// matches; errors are returned (rather than thrown) like Node's API.
NodeTlsIdentityError? checkServerIdentity(
  String hostname,
  X509Certificate? certificate,
) {
  if (certificate == null) {
    return NodeTlsIdentityError(
      hostname,
      'The TLS server did not provide a certificate',
    );
  }
  try {
    final names = _subjectAltNames(certificate.der);
    if (_isIp(hostname) != 0) {
      final wanted = _ipBytes(hostname);
      final ips = names.whereType<_CertificateIpName>();
      if (ips.any((name) => _sameBytes(name.bytes, wanted))) return null;
      if (names.isEmpty) {
        return NodeTlsIdentityError(
          hostname,
          'IP address is missing from certificate subject alternative names',
        );
      }
    } else {
      final dns = names
          .whereType<_CertificateDnsName>()
          .map((name) => name.value)
          .toList();
      if (dns.isNotEmpty) {
        if (dns.any((name) => _dnsNameMatches(hostname, name))) return null;
      } else if (names.isEmpty) {
        // Legacy certificates without SAN fall back to their subject CN.
        final cn = _commonName(certificate.subject);
        if (cn != null && _dnsNameMatches(hostname, cn)) return null;
      }
    }
    return NodeTlsIdentityError(
      hostname,
      'Hostname/IP does not match certificate\'s altnames: ${names.map((n) => n.display).join(', ')}, subject=${certificate.subject}',
    );
  } catch (error) {
    return NodeTlsIdentityError(
      hostname,
      'Unable to parse peer certificate: $error',
    );
  }
}

final class NodeTlsIdentityError implements Exception {
  NodeTlsIdentityError(this.hostname, this.message);
  final String hostname;
  final String message;
  final String code = 'ERR_TLS_CERT_ALTNAME_INVALID';
  @override
  String toString() => 'NodeTlsIdentityError: $message';
}

sealed class _CertificateName {
  const _CertificateName(this.display);
  final String display;
}

final class _CertificateDnsName extends _CertificateName {
  const _CertificateDnsName(this.value) : super(value);
  final String value;
}

final class _CertificateIpName extends _CertificateName {
  _CertificateIpName(this.bytes) : super(_formatIp(bytes));
  final List<int> bytes;
}

List<_CertificateName> _subjectAltNames(Uint8List der) {
  final cert = asn1lib.ASN1Parser(der).nextObject() as asn1lib.ASN1Sequence;
  final tbs = cert.elements.first as asn1lib.ASN1Sequence;
  for (final field in tbs.elements) {
    if (field.tag != 0xa3) continue;
    final extensions =
        asn1lib.ASN1Parser(field.valueBytes()).nextObject()
            as asn1lib.ASN1Sequence;
    for (final extension in extensions.elements.cast<asn1lib.ASN1Sequence>()) {
      final oid =
          (extension.elements.first as asn1lib.ASN1ObjectIdentifier).identifier;
      if (oid != '2.5.29.17') continue;
      final octets = extension.elements.last as asn1lib.ASN1OctetString;
      final names =
          asn1lib.ASN1Parser(octets.octets).nextObject()
              as asn1lib.ASN1Sequence;
      return [
        for (final name in names.elements)
          if (name.tag == 0x82)
            _CertificateDnsName(ascii.decode(name.valueBytes()))
          else if (name.tag == 0x87)
            _CertificateIpName(name.valueBytes()),
      ];
    }
  }
  return const [];
}

String? _commonName(String subject) {
  final match = RegExp(
    r'(?:^|[,/])\s*CN\s*=\s*([^,/]+)',
    caseSensitive: false,
  ).firstMatch(subject);
  return match?.group(1)?.trim();
}

bool _dnsNameMatches(String hostname, String pattern) {
  final host = hostname.toLowerCase().replaceFirst(RegExp(r'\.$'), '');
  final candidate = pattern.toLowerCase().replaceFirst(RegExp(r'\.$'), '');
  if (!candidate.startsWith('*.')) return host == candidate;
  final suffix = candidate.substring(1);
  return host.endsWith(suffix) &&
      host.substring(0, host.length - suffix.length).isNotEmpty &&
      !host.substring(0, host.length - suffix.length).contains('.');
}

List<int> _ipBytes(String hostname) {
  if (_isIp(hostname) == 4) {
    return hostname.split('.').map(int.parse).toList();
  }
  final parsed = InternetAddress.tryParse(hostname);
  if (parsed == null || parsed.type != InternetAddressType.IPv6) {
    throw FormatException('Invalid IPv6 address $hostname');
  }
  return parsed.rawAddress;
}

int _isIp(String hostname) {
  if (RegExp(
    r'^(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$',
  ).hasMatch(hostname)) {
    return 4;
  }
  final parsed = InternetAddress.tryParse(hostname);
  return parsed?.type == InternetAddressType.IPv6 ? 6 : 0;
}

String _formatIp(List<int> bytes) => bytes.length == 4
    ? bytes.join('.')
    : [
        for (var i = 0; i < bytes.length; i += 2)
          ((bytes[i] << 8) | bytes[i + 1]).toRadixString(16),
      ].join(':');

bool _sameBytes(List<int> left, List<int> right) =>
    left.length == right.length &&
    List<int>.generate(
      left.length,
      (i) => left[i] ^ right[i],
    ).every((b) => b == 0);
