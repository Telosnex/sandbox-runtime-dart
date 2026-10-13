// Node-compatible TLS helpers required by sandbox-runtime's MITM proxy.
// The checked-in Mozilla bundle is generated from curl's dated cacert.pem;
// no platform trust store is consulted by rootCertificates/trustedRootContext.
import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:asn1lib/asn1lib.dart' as asn1lib;

import 'mozilla_roots.dart';

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

/// Bytes consumed while inspecting a TLS ClientHello. Keep the paused
/// subscription alive until [secureServer] takes ownership of the socket.
final class ClientHelloPeek {
  ClientHelloPeek({
    required this.serverName,
    required this.bufferedData,
    required this.subscription,
  });

  final String? serverName;
  final Uint8List bufferedData;
  final StreamSubscription<List<int>> subscription;
}

/// Read a bounded ClientHello without losing any encrypted bytes. The socket
/// subscription is paused upon completion; callers must pass the returned
/// bytes to [secureServer], which replays them before reading the socket again.
Future<ClientHelloPeek> peekClientHello(
  Socket socket, {
  int maxClientHelloBytes = 64 * 1024,
  int maxRecords = 32,
  Duration timeout = const Duration(seconds: 10),
}) async {
  if (maxClientHelloBytes < 1024 || maxRecords < 1) {
    throw ArgumentError('ClientHello limits are too small');
  }
  final consumed = BytesBuilder(copy: false);
  final completer = Completer<ClientHelloPeek>();
  late StreamSubscription<List<int>> subscription;
  subscription = socket.listen(
    (chunk) {
      if (completer.isCompleted) return;
      if (consumed.length + chunk.length > maxClientHelloBytes) {
        completer.completeError(
          const FormatException(
            'TLS ClientHello exceeds configured size limit',
          ),
        );
        subscription.pause();
        return;
      }
      consumed.add(chunk);
      try {
        final bytes = consumed.toBytes();
        final hello = _parseClientHello(bytes, maxClientHelloBytes, maxRecords);
        if (hello != null) {
          subscription.pause();
          completer.complete(
            ClientHelloPeek(
              serverName: hello.serverName,
              bufferedData: Uint8List.fromList(bytes),
              subscription: subscription,
            ),
          );
        }
      } on Object catch (error, stack) {
        subscription.pause();
        completer.completeError(error, stack);
      }
    },
    onError: (Object error, StackTrace stack) {
      if (!completer.isCompleted) completer.completeError(error, stack);
    },
    onDone: () {
      if (!completer.isCompleted) {
        completer.completeError(
          const SocketException('EOF before complete TLS ClientHello'),
        );
      }
    },
  );
  try {
    return await completer.future.timeout(timeout);
  } catch (_) {
    await subscription.cancel();
    socket.destroy();
    rethrow;
  }
}

/// Parse the ClientHello SNI from TLS handshake records. Returns `null` when
/// the supplied bytes do not complete a hello or a complete hello has no
/// host_name extension; malformed messages throw and must not be routed as TLS.
String? parseClientHelloSni(
  List<int> bufferedData, {
  int maxClientHelloBytes = 64 * 1024,
  int maxRecords = 32,
}) => _parseClientHello(
  bufferedData,
  maxClientHelloBytes,
  maxRecords,
)?.serverName;

/// Wrap the original socket after a caller has selected an SNI context.
/// Bytes consumed by the bounded peek are replayed through `bufferedData`.
Future<SecureSocket> secureServer(
  Socket socket,
  SecureContext context,
  ClientHelloPeek hello, {
  List<String> protocols = const ['http/1.1'],
  bool requestClientCertificate = false,
  bool requireClientCertificate = false,
}) async {
  context.setAlpnProtocols(protocols, true);
  return SecureSocket.secureServer(
    socket,
    context,
    bufferedData: hello.bufferedData,
    supportedProtocols: protocols,
    requestClientCertificate: requestClientCertificate,
    requireClientCertificate: requireClientCertificate,
  );
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

_ParsedHello? _parseClientHello(List<int> data, int maxBytes, int maxRecords) {
  if (data.length > maxBytes) {
    throw const FormatException(
      'TLS ClientHello exceeds configured size limit',
    );
  }
  var offset = 0;
  var recordCount = 0;
  final handshake = <int>[];
  while (offset + 5 <= data.length) {
    if (++recordCount > maxRecords) {
      throw const FormatException('TLS ClientHello has too many records');
    }
    final contentType = data[offset];
    final major = data[offset + 1];
    final length = (data[offset + 3] << 8) | data[offset + 4];
    if (contentType != 22 || major != 3 || length == 0 || length > 18432) {
      throw const FormatException('Invalid TLS handshake record');
    }
    if (offset + 5 + length > data.length) return null;
    handshake.addAll(data.sublist(offset + 5, offset + 5 + length));
    offset += 5 + length;
    final bytes = handshake;
    if (bytes.length < 4) continue;
    if (bytes[0] != 1) {
      throw const FormatException('Expected TLS ClientHello handshake');
    }
    final helloLength = (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
    if (helloLength + 4 > maxBytes) {
      throw const FormatException(
        'TLS ClientHello exceeds configured size limit',
      );
    }
    if (bytes.length < helloLength + 4) continue;
    return _ParsedHello(_decodeSni(bytes.sublist(4, helloLength + 4)));
  }
  return null;
}

final class _ParsedHello {
  const _ParsedHello(this.serverName);
  final String? serverName;
}

String? _decodeSni(List<int> body) {
  var cursor = 0;
  void need(int amount) {
    if (amount < 0 || cursor + amount > body.length) {
      throw const FormatException('Truncated TLS ClientHello');
    }
  }

  need(34); // legacy_version + random
  cursor += 34;
  need(1);
  final sessionLength = body[cursor++];
  need(sessionLength);
  cursor += sessionLength;
  need(2);
  final cipherLength = (body[cursor] << 8) | body[cursor + 1];
  cursor += 2;
  if (cipherLength == 0 || cipherLength.isOdd) {
    throw const FormatException('Invalid ClientHello cipher suites');
  }
  need(cipherLength);
  cursor += cipherLength;
  need(1);
  final compressionLength = body[cursor++];
  if (compressionLength == 0) {
    throw const FormatException('Empty ClientHello compression methods');
  }
  need(compressionLength);
  cursor += compressionLength;
  if (cursor == body.length) return null; // ClientHello without extensions.
  need(2);
  final extensionsLength = (body[cursor] << 8) | body[cursor + 1];
  cursor += 2;
  if (cursor + extensionsLength != body.length) {
    throw const FormatException('Invalid ClientHello extension length');
  }
  final end = cursor + extensionsLength;
  String? serverName;
  var sawSniExtension = false;
  while (cursor < end) {
    if (cursor + 4 > end) {
      throw const FormatException('Truncated ClientHello extension');
    }
    final type = (body[cursor] << 8) | body[cursor + 1];
    final length = (body[cursor + 2] << 8) | body[cursor + 3];
    cursor += 4;
    if (cursor + length > end) {
      throw const FormatException('Truncated ClientHello extension data');
    }
    if (type == 0) {
      if (sawSniExtension) {
        throw const FormatException('Duplicate SNI extension');
      }
      sawSniExtension = true;
      final listLength = length >= 2
          ? (body[cursor] << 8) | body[cursor + 1]
          : -1;
      if (listLength != length - 2) {
        throw const FormatException('Invalid SNI server-name list');
      }
      var nameCursor = cursor + 2;
      final namesEnd = cursor + length;
      while (nameCursor < namesEnd) {
        if (nameCursor + 3 > namesEnd) {
          throw const FormatException('Truncated SNI name');
        }
        final kind = body[nameCursor];
        final size = (body[nameCursor + 1] << 8) | body[nameCursor + 2];
        nameCursor += 3;
        if (nameCursor + size > namesEnd) {
          throw const FormatException('Truncated SNI hostname');
        }
        if (kind == 0) {
          if (serverName != null) {
            throw const FormatException('Duplicate SNI hostname');
          }
          if (size == 0) throw const FormatException('Empty SNI hostname');
          final nameBytes = body.sublist(nameCursor, nameCursor + size);
          if (nameBytes.any((b) => b < 0x21 || b > 0x7e)) {
            throw const FormatException('SNI hostname is not printable ASCII');
          }
          serverName = ascii.decode(nameBytes);
        }
        nameCursor += size;
      }
    }
    cursor += length;
  }
  return serverName;
}
