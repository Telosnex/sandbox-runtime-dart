// Node-compatible TLS helpers required by sandbox-runtime's MITM proxy.
// The checked-in Mozilla bundle is generated from curl's dated cacert.pem;
// no platform trust store is consulted by rootCertificates/trustedRootContext.
import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:asn1lib/asn1lib.dart' as asn1lib;
import 'package:crypto/crypto.dart' as crypto;
import 'package:pointycastle/export.dart' as pc;

import 'errno.dart';
import 'mozilla_roots.dart';
import 'net.dart' as net;
import 'stream.dart' as stream;

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
    final requestCert = opts['requestCert'] == true;
    final rejectUnauthorized = opts['rejectUnauthorized'] != false;
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
          requestClientCertificate: requestCert,
          requireClientCertificate: requestCert && rejectUnauthorized,
        );
      } on HandshakeException catch (error) {
        throw NodeError(error.message, code: 'ERR_SSL_HANDSHAKE_FAILURE');
      } on TlsException catch (error) {
        throw NodeError(error.message, code: 'ERR_SSL_HANDSHAKE_FAILURE');
      }
      _setPeer(secured);
      // dart:io verifies a presented client certificate against the
      // context's trusted roots during the handshake.
      authorized = !requestCert || secured.peerCertificate != null;
      if (requestCert && !authorized) {
        authorizationError = 'UNABLE_TO_GET_ISSUER_CERT';
      }
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

const _tlsSocketOptions = {
  'isServer',
  'secureContext',
  'ALPNProtocols',
  'requestCert',
  'rejectUnauthorized',
};

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
  'socket',
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
  final existingSocket = opts['socket'];
  // Node: options.host, else options.socket._host, else 'localhost'.
  final host =
      opts['host'] as String? ??
      (existingSocket is net.NodeSocket ? existingSocket.connectHost : null) ??
      'localhost';
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
  final existing = opts['socket'];
  socket.startConnect(
    dialer: existing is stream.Duplex ? () => _bridgeDuplex(existing) : null,
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
            // dart:io does not say which check failed. Only a custom
            // checkServerIdentity can have made the name check fail while the
            // chain is fine; then verify the chain against `ca` ourselves and
            // still run the identity check. With the default identity
            // function, dart:io's rejection stands.
            if (opts['checkServerIdentity'] != null) {
              final identityError = applyIdentity(identity, name, certificate);
              if (identityError == null &&
                  _chainTrusted(certificate, opts['ca'])) {
                failure = null;
                return true;
              }
              failure =
                  identityError ??
                  NodeError(
                    'unable to verify the first certificate',
                    code: 'UNABLE_TO_VERIFY_LEAF_SIGNATURE',
                  );
            } else {
              // Never accepted here; the identity result only picks the error.
              failure =
                  applyIdentity(identity, name, certificate) ??
                  NodeError(
                    'unable to verify the first certificate',
                    code: 'UNABLE_TO_VERIFY_LEAF_SIGNATURE',
                  );
            }
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
) => Function.apply(identity, [
  hostname,
  identical(identity, checkServerIdentity) || certificate == null
      ? certificate
      : PeerCertificate(certificate),
]);

/// A distinguished name as Node's peer certificate shows it: `CN` is the
/// common name (null when absent) and [raw] the dart:io string.
class CertName {
  CertName(this.raw) : CN = _commonName(raw);
  final String raw;
  // ignore: non_constant_identifier_names
  final String? CN;
  @override
  String toString() => raw;
}

/// What a custom `checkServerIdentity` receives: Node's certificate shape
/// (`subject.CN`, `issuer.CN`, `raw`) over the dart:io certificate.
class PeerCertificate {
  PeerCertificate(this.certificate)
    : subject = CertName(certificate.subject),
      issuer = CertName(certificate.issuer);
  final X509Certificate certificate;
  final CertName subject;
  final CertName issuer;
  Uint8List get raw => certificate.der;
  String get pem => certificate.pem;
  DateTime get validFrom => certificate.startValidity;
  DateTime get validTo => certificate.endValidity;

  /// Node's `subjectaltname`: "DNS:a, IP Address:1.2.3.4", or null.
  String? get subjectaltname => _subjectAltName(certificate.der);

  /// Node's `fingerprint` (SHA-1) and `fingerprint256`: upper-case hex bytes
  /// joined by ':'.
  String get fingerprint => _colonHex(crypto.sha1.convert(raw).bytes);
  String get fingerprint256 => _colonHex(crypto.sha256.convert(raw).bytes);
}

String _colonHex(List<int> bytes) => bytes
    .map((b) => b.toRadixString(16).padLeft(2, '0').toUpperCase())
    .join(':');

String? _subjectAltName(Uint8List der) {
  try {
    final seq = asn1lib.ASN1Parser(der).nextObject() as asn1lib.ASN1Sequence;
    for (final ext in _extensions(seq.elements[0] as asn1lib.ASN1Sequence)) {
      if (_extOid(ext) != '2.5.29.17') continue;
      final names =
          asn1lib.ASN1Parser(_extValue(ext)).nextObject()
              as asn1lib.ASN1Sequence;
      final out = <String>[];
      for (final n in names.elements) {
        final v = n.valueBytes();
        switch (n.tag & 0x1f) {
          case 1:
            out.add('email:${utf8.decode(v)}');
          case 2:
            out.add('DNS:${utf8.decode(v)}');
          case 6:
            out.add('URI:${utf8.decode(v)}');
          case 7:
            out.add('IP Address:${InternetAddress.fromRawAddress(v).address}');
        }
      }
      return out.join(', ');
    }
  } catch (_) {}
  return null;
}

List<asn1lib.ASN1Sequence> _extensions(asn1lib.ASN1Sequence tbs) {
  for (final e in tbs.elements) {
    if (e.tag == 0xa3) {
      final list =
          asn1lib.ASN1Parser(e.valueBytes()).nextObject()
              as asn1lib.ASN1Sequence;
      return list.elements.cast<asn1lib.ASN1Sequence>();
    }
  }
  return const [];
}

String _extOid(asn1lib.ASN1Sequence ext) =>
    (ext.elements[0] as asn1lib.ASN1ObjectIdentifier).identifier!;

bool _extCritical(asn1lib.ASN1Sequence ext) =>
    ext.elements.length > 2 &&
    (ext.elements[1] as asn1lib.ASN1Boolean).booleanValue;

Uint8List _extValue(asn1lib.ASN1Sequence ext) =>
    (ext.elements.last as asn1lib.ASN1OctetString).valueBytes();

const _knownExtensions = {
  '2.5.29.14', // subjectKeyIdentifier
  '2.5.29.15', // keyUsage
  '2.5.29.17', // subjectAltName
  '2.5.29.19', // basicConstraints
  '2.5.29.31', // cRLDistributionPoints
  '2.5.29.32', // certificatePolicies
  '2.5.29.35', // authorityKeyIdentifier
  '2.5.29.37', // extKeyUsage
  '1.3.6.1.5.5.7.1.1', // authorityInfoAccess
};

/// Whether [der] may act as an issuer: basicConstraints CA:TRUE when present,
/// keyUsage keyCertSign when present, and within its validity dates.
bool _anchorUsable(asn1lib.ASN1Sequence tbs, DateTime now) {
  final f = _tbsFields(tbs);
  if (now.isBefore(f.notBefore) || now.isAfter(f.notAfter)) return false;
  for (final ext in _extensions(tbs)) {
    final oid = _extOid(ext);
    if (oid == '2.5.29.19') {
      final bc =
          asn1lib.ASN1Parser(_extValue(ext)).nextObject()
              as asn1lib.ASN1Sequence;
      final ca =
          bc.elements.isNotEmpty && bc.elements.first is asn1lib.ASN1Boolean
          ? (bc.elements.first as asn1lib.ASN1Boolean).booleanValue
          : false;
      if (!ca) return false;
    } else if (oid == '2.5.29.15') {
      final bits =
          (asn1lib.ASN1Parser(_extValue(ext)).nextObject()
                  as asn1lib.ASN1BitString)
              .contentBytes();
      if (bits.isEmpty || bits[0] & 0x04 == 0) return false;
    }
  }
  return true;
}

/// For tests: [_chainTrusted].
bool chainTrustedForTest(X509Certificate leaf, Object? ca) =>
    _chainTrusted(leaf, ca);

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
  Object? peerCertificate,
) {
  final certificate = peerCertificate is PeerCertificate
      ? peerCertificate.certificate
      : peerCertificate as X509Certificate?;
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

/// A loopback dart:io socket whose far end is [duplex], so dart:io can run
/// TLS over any Node stream. Bytes the duplex emits go in; bytes written out
/// go to the duplex.
Future<Socket> _bridgeDuplex(stream.Duplex duplex) async {
  final server = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
  final accepted = server.first;
  final client = await Socket.connect(
    InternetAddress.loopbackIPv4,
    server.port,
  );
  final far = await accepted;
  unawaited(server.close());
  far.setOption(SocketOption.tcpNoDelay, true);
  duplex.on('data', (Object? chunk) {
    far.add(chunk is String ? utf8.encode(chunk) : chunk as List<int>);
  });
  duplex.on('end', () => unawaited(far.close()));
  duplex.on('error', (Object? _) => far.destroy());
  duplex.on('close', () => far.destroy());
  far.listen(
    (data) => duplex.write(Uint8List.fromList(data)),
    onDone: () {
      if (!duplex.destroyed) duplex.end();
    },
    onError: (Object _) {},
    cancelOnError: true,
  );
  return client;
}

String _pem(Object? v) {
  if (v is List) v = v.isEmpty ? null : v.first;
  if (v is String) return v;
  if (v is List<int>) return utf8.decode(v);
  throw ArgumentError('tls.createServer needs "key" and "cert"');
}

/// The server-side context for `createServer` options: `secureContext`, the
/// `SNICallback`'s answer, or `key` and `cert` (with optional `ca`).
SecurityContext serverContextFor(Map<Object?, Object?> options) {
  Object? context = options['secureContext'];
  if (context == null) {
    final sni = options['SNICallback'];
    if (sni is Function) {
      // dart:io does not report the client's server name: ask with ''.
      Object? chosen;
      var answered = false;
      sni('', (Object? err, Object? ctx) {
        if (err != null) throw err;
        answered = true;
        chosen = ctx;
      });
      if (!answered) {
        throw UnimplementedError('SNICallback that answers later');
      }
      // Answered (null, undefined): the default context, as in Node.
      context = chosen;
    }
  }
  if (context == null) {
    final made = createSecureContext(
      cert: _pem(options['cert']),
      key: _pem(options['key']),
    );
    final ca = options['ca'];
    if (ca != null) {
      for (final c in ca is List ? ca : [ca]) {
        made.setTrustedCertificatesBytes(
          Uint8List.fromList(utf8.encode(_pem(c))),
        );
      }
    }
    context = made;
  }
  return context as SecurityContext;
}

/// Node `tls.Server`: a [net.NodeServer] whose connections are TLS. Emits
/// 'secureConnection' with the [TLSSocket] once the handshake is done and
/// 'tlsClientError' (error, socket) when it fails.
class Server extends net.NodeServer {
  Server(this.options, [Function? secureConnectionListener]) {
    if (secureConnectionListener != null) {
      on('secureConnection', secureConnectionListener);
    }
    on('connection', (net.NodeSocket accepted) {
      final TLSSocket secured;
      try {
        secured = TLSSocket(accepted, {
          'isServer': true,
          'secureContext': serverContextFor(options),
          'requestCert': options['requestCert'],
          'rejectUnauthorized': options['rejectUnauthorized'],
        });
      } catch (error) {
        accepted.destroy();
        emit('tlsClientError', error, accepted);
        return;
      }
      secured.once('secure', () => emit('secureConnection', secured));
      secured.on('error', (Object error) {
        if (!secured.secureEstablished) emit('tlsClientError', error, secured);
      });
    });
  }

  final Map<Object?, Object?> options;
}

/// Node `tls.createServer([options][, secureConnectionListener])`.
Server createServer([Object? options, Function? secureConnectionListener]) {
  if (options is Function) {
    secureConnectionListener = options;
    options = null;
  }
  final opts = options is Map
      ? Map<Object?, Object?>.of(options)
      : <Object?, Object?>{};
  return Server(opts, secureConnectionListener);
}

List<Uint8List> _caDers(Object? ca) {
  final out = <Uint8List>[];
  void add(Object c) {
    final text = c is String ? c : utf8.decode(c as List<int>);
    final blocks = RegExp(
      r'-----BEGIN CERTIFICATE-----([^-]+)-----END CERTIFICATE-----',
    );
    for (final m in blocks.allMatches(text)) {
      out.add(base64.decode(m.group(1)!.replaceAll(RegExp(r'\s'), '')));
    }
  }

  if (ca is Iterable && ca is! String) {
    ca.forEach((c) => add(c as Object));
  } else if (ca != null) {
    add(ca);
  }
  return out;
}

/// True when [leaf] is one of the PEM certificates in [ca], or is signed
/// (RSA) by one, and is within its validity period. Used only after dart:io
/// rejected the certificate, when the name check is the caller's.
bool _chainTrusted(X509Certificate leaf, Object? ca) {
  try {
    final now = DateTime.now();
    if (now.isBefore(leaf.startValidity) || now.isAfter(leaf.endValidity)) {
      return false;
    }
    final leafSeq =
        asn1lib.ASN1Parser(leaf.der).nextObject() as asn1lib.ASN1Sequence;
    final leafTbs = leafSeq.elements[0] as asn1lib.ASN1Sequence;
    final leafSigOid =
        ((leafSeq.elements[1] as asn1lib.ASN1Sequence).elements.first
                as asn1lib.ASN1ObjectIdentifier)
            .identifier;
    final leafFields = _tbsFields(leafTbs);
    // The outer and inner signature algorithms must agree.
    final innerAlg =
        leafTbs.elements[leafTbs.elements.first.tag == 0xa0 ? 2 : 1];
    if (!_sameBytes(innerAlg.encodedBytes, leafSeq.elements[1].encodedBytes)) {
      return false;
    }
    for (final ext in _extensions(leafTbs)) {
      if (_extCritical(ext) && !_knownExtensions.contains(_extOid(ext))) {
        return false;
      }
    }
    for (final der in _caDers(ca)) {
      if (_sameBytes(der, leaf.der)) return true;
      final caSeq =
          asn1lib.ASN1Parser(der).nextObject() as asn1lib.ASN1Sequence;
      final caTbs = caSeq.elements[0] as asn1lib.ASN1Sequence;
      final caFields = _tbsFields(caTbs);
      if (!_sameBytes(leafFields.issuer, caFields.subject)) continue;
      if (!_anchorUsable(caTbs, now)) continue;
      final spki =
          asn1lib.ASN1Parser(Uint8List.fromList(caFields.spki)).nextObject()
              as asn1lib.ASN1Sequence;
      final keyBits = (spki.elements[1] as asn1lib.ASN1BitString)
          .contentBytes();
      final key =
          asn1lib.ASN1Parser(Uint8List.fromList(keyBits)).nextObject()
              as asn1lib.ASN1Sequence;
      final publicKey = pc.RSAPublicKey(
        (key.elements[0] as asn1lib.ASN1Integer).valueAsBigInteger,
        (key.elements[1] as asn1lib.ASN1Integer).valueAsBigInteger,
      );
      final (digest, digestId) = switch (leafSigOid) {
        '1.2.840.113549.1.1.11' => (
          pc.SHA256Digest(),
          '0609608648016503040201',
        ),
        '1.2.840.113549.1.1.12' => (
          pc.SHA384Digest(),
          '0609608648016503040202',
        ),
        '1.2.840.113549.1.1.13' => (
          pc.SHA512Digest(),
          '0609608648016503040203',
        ),
        _ => throw const FormatException('unsupported signature algorithm'),
      };
      final signer = pc.RSASigner(digest, digestId)
        ..init(false, pc.PublicKeyParameter<pc.RSAPublicKey>(publicKey));
      final sigBytes =
          (leafSeq.elements[2] as asn1lib.ASN1BitString).stringValue;
      if (signer.verifySignature(
        leafTbs.encodedBytes,
        pc.RSASignature(Uint8List.fromList(sigBytes)),
      )) {
        return true;
      }
    }
  } catch (_) {
    return false;
  }
  return false;
}

({
  List<int> issuer,
  List<int> subject,
  List<int> spki,
  DateTime notBefore,
  DateTime notAfter,
})
_tbsFields(asn1lib.ASN1Sequence tbs) {
  var i = tbs.elements.first.tag == 0xa0 ? 1 : 0;
  // serial, signature, issuer, validity, subject, subjectPublicKeyInfo
  final e = tbs.elements;
  return (
    issuer: e[i + 2].encodedBytes,
    subject: e[i + 4].encodedBytes,
    spki: e[i + 5].encodedBytes,
    notBefore:
        ((e[i + 3] as asn1lib.ASN1Sequence).elements[0] as asn1lib.ASN1UtcTime)
            .dateTimeValue,
    notAfter:
        ((e[i + 3] as asn1lib.ASN1Sequence).elements[1] as asn1lib.ASN1UtcTime)
            .dateTimeValue,
  );
}
