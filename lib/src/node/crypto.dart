// Node `crypto` compatibility: createHash and createHmac (sha256), as
// aws-sigv4.ts uses them. No upstream counterpart. A digest without an
// encoding is a Node Buffer, which is a Uint8List here.

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:asn1lib/asn1lib.dart' as asn1;
import 'package:crypto/crypto.dart' as crypto;
import 'package:pointycastle/export.dart' as pc;

import 'buffer.dart';

export 'buffer.dart' show Buffer;

/// The subset of Node's Hash API used by aws-sigv4.dart.
class Hash {
  Hash(this.algorithm);

  final String algorithm;
  final BytesBuilder _updates = BytesBuilder(copy: false);
  bool _digested = false;

  Hash update(Object data, [String encoding = 'utf8']) {
    if (_digested) throw StateError('Digest already called');
    _updates.add(_bytes(data, encoding));
    return this;
  }

  Object digest([String? encoding]) {
    if (_digested) throw StateError('Digest already called');
    _digested = true;
    final result = _hash(algorithm).convert(_updates.takeBytes()).bytes;
    return _encode(result, encoding);
  }
}

/// The subset of Node's Hmac API used by aws-sigv4.dart.
class Hmac {
  Hmac(this.algorithm, this.key);

  final String algorithm;
  final Object key;
  final BytesBuilder _updates = BytesBuilder(copy: false);
  bool _digested = false;

  Hmac update(Object data, [String encoding = 'utf8']) {
    if (_digested) throw StateError('Digest already called');
    _updates.add(_bytes(data, encoding));
    return this;
  }

  Object digest([String? encoding]) {
    if (_digested) throw StateError('Digest already called');
    _digested = true;
    final keyBytes = _bytes(key, 'utf8');
    final result = crypto.Hmac(
      _hash(algorithm),
      keyBytes,
    ).convert(_updates.takeBytes()).bytes;
    return _encode(result, encoding);
  }
}

Hash createHash(String algorithm) => Hash(algorithm);

Hmac createHmac(String algorithm, Object key) => Hmac(algorithm, key);

/// Returns a [Buffer], so `randomBytes(n).toString('hex')` reads as in Node.
Buffer randomBytes(int size) {
  final random = Random.secure();
  return Buffer.wrap(
    Uint8List.fromList(List<int>.generate(size, (_) => random.nextInt(256))),
  );
}

String randomUUID() {
  final bytes = randomBytes(16);
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  final hex = _encode(bytes, 'hex') as String;
  return '${hex.substring(0, 8)}-${hex.substring(8, 12)}-${hex.substring(12, 16)}-${hex.substring(16, 20)}-${hex.substring(20)}';
}

/// Node `crypto.sign(algorithm, data, key)` for RSASSA-PKCS1-v1_5 with
/// SHA-256 over a PEM RSA private key (PKCS#1 or PKCS#8), in pure Dart.
Buffer sign(String? algorithm, Object data, Object privateKey) {
  final alg = algorithm?.toLowerCase();
  if (alg != 'sha256' && alg != 'rsa-sha256') {
    throw ArgumentError.value(algorithm, 'algorithm', 'unsupported algorithm');
  }
  final key = _parseRsaPrivateKey(
    privateKey is String ? privateKey : utf8.decode(_bytes(privateKey, 'utf8')),
  );
  final signer = pc.RSASigner(pc.SHA256Digest(), '0609608648016503040201')
    ..init(true, pc.PrivateKeyParameter<pc.RSAPrivateKey>(key));
  final signature = signer.generateSignature(
    Uint8List.fromList(_bytes(data, 'utf8')),
  );
  return Buffer.wrap(signature.bytes);
}

pc.RSAPrivateKey _parseRsaPrivateKey(String pem) {
  final pkcs1 = _pemBody(pem, 'RSA PRIVATE KEY');
  Uint8List der;
  if (pkcs1 != null) {
    der = pkcs1;
  } else {
    final pkcs8 = _pemBody(pem, 'PRIVATE KEY');
    if (pkcs8 == null) throw const FormatException('Unsupported key format');
    final info = asn1.ASN1Parser(pkcs8).nextObject() as asn1.ASN1Sequence;
    final algId = info.elements[1] as asn1.ASN1Sequence;
    final oid = (algId.elements[0] as asn1.ASN1ObjectIdentifier).identifier;
    if (oid != '1.2.840.113549.1.1.1') {
      throw const FormatException('Key is not RSA');
    }
    der = (info.elements[2] as asn1.ASN1OctetString).valueBytes();
  }
  final seq = asn1.ASN1Parser(der).nextObject() as asn1.ASN1Sequence;
  BigInt at(int i) => (seq.elements[i] as asn1.ASN1Integer).valueAsBigInteger;
  return pc.RSAPrivateKey(at(1), at(3), at(4), at(5));
}

Uint8List? _pemBody(String pem, String label) {
  final match = RegExp(
    '-----BEGIN $label-----([^-]*)-----END $label-----',
  ).firstMatch(pem);
  if (match == null) return null;
  return base64.decode(match.group(1)!.replaceAll(RegExp(r'\s'), ''));
}

/// Node `crypto.X509Certificate`, constructed from PEM or DER.
class X509Certificate {
  X509Certificate(Object certificate) : raw = _certificateDer(certificate);

  /// The DER encoding of the certificate.
  final Buffer raw;

  /// SHA-1 fingerprint, upper-case hex bytes joined by ':'.
  String get fingerprint => _colonHex(crypto.sha1.convert(raw).bytes);

  /// SHA-256 fingerprint, upper-case hex bytes joined by ':'.
  String get fingerprint256 => _colonHex(crypto.sha256.convert(raw).bytes);

  static Buffer _certificateDer(Object certificate) {
    final text = certificate is String
        ? certificate
        : String.fromCharCodes(_bytes(certificate, 'utf8'));
    Uint8List der;
    final body = _pemBody(text, 'CERTIFICATE');
    if (body != null) {
      der = body;
    } else if (certificate is! String) {
      der = Uint8List.fromList(_bytes(certificate, 'utf8'));
    } else {
      throw const FormatException('Invalid X509 certificate');
    }
    try {
      final cert = asn1.ASN1Parser(der).nextObject();
      if (cert is! asn1.ASN1Sequence || cert.elements.length != 3) {
        throw const FormatException('Invalid X509 certificate');
      }
    } on FormatException {
      rethrow;
    } catch (_) {
      throw const FormatException('Invalid X509 certificate');
    }
    return Buffer.wrap(der);
  }
}

String _colonHex(List<int> bytes) => bytes
    .map((b) => b.toRadixString(16).padLeft(2, '0').toUpperCase())
    .join(':');

crypto.Hash _hash(String algorithm) {
  if (algorithm == 'sha256') return crypto.sha256;
  throw ArgumentError.value(algorithm, 'algorithm', 'unsupported algorithm');
}

List<int> _bytes(Object data, String encoding) {
  if (data is Uint8List) return data;
  if (data is Buffer) return data.toUint8List();
  if (data is List<int>) return data;
  if (data is String && (encoding == 'utf8' || encoding == 'utf-8')) {
    return utf8.encode(data);
  }
  throw ArgumentError('Unsupported data or encoding for aws-sigv4 crypto shim');
}

Object _encode(List<int> bytes, String? encoding) {
  if (encoding == null) return Uint8List.fromList(bytes);
  if (encoding == 'hex') {
    return bytes.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join();
  }
  throw ArgumentError.value(encoding, 'encoding', 'unsupported encoding');
}
