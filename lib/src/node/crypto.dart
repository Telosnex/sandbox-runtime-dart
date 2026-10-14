// Node `crypto` compatibility: createHash and createHmac (sha256), as
// aws-sigv4.ts uses them. No upstream counterpart. A digest without an
// encoding is a Node Buffer, which is a Uint8List here.

import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;

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

Uint8List randomBytes(int size) {
  final random = Random.secure();
  return Uint8List.fromList(
    List<int>.generate(size, (_) => random.nextInt(256)),
  );
}

String randomUUID() {
  final bytes = randomBytes(16);
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  final hex = _encode(bytes, 'hex') as String;
  return '${hex.substring(0, 8)}-${hex.substring(8, 12)}-${hex.substring(12, 16)}-${hex.substring(16, 20)}-${hex.substring(20)}';
}

Uint8List sign(String algorithm, List<int> data, String privateKey) {
  if (algorithm != 'sha256') throw ArgumentError.value(algorithm, 'algorithm');
  final dir = Directory.systemTemp.createTempSync('dart-node-crypto-');
  try {
    final key = File('${dir.path}/key.pem')..writeAsStringSync(privateKey);
    final input = File('${dir.path}/input')..writeAsBytesSync(data);
    final output = '${dir.path}/signature';
    final result = Process.runSync('openssl', [
      'dgst',
      '-sha256',
      '-sign',
      key.path,
      '-out',
      output,
      input.path,
    ]);
    if (result.exitCode != 0)
      throw ProcessException(
        'openssl',
        ['dgst'],
        result.stderr.toString(),
        result.exitCode,
      );
    return Uint8List.fromList(File(output).readAsBytesSync());
  } finally {
    dir.deleteSync(recursive: true);
  }
}

class X509Certificate {
  X509Certificate(String pem) : _pem = pem;
  final String _pem;
  String get fingerprint {
    final dir = Directory.systemTemp.createTempSync('dart-node-x509-');
    try {
      final file = File('${dir.path}/cert.pem')..writeAsStringSync(_pem);
      final output = Process.runSync('openssl', [
        'x509',
        '-in',
        file.path,
        '-noout',
        '-fingerprint',
        '-sha1',
      ]);
      if (output.exitCode != 0)
        throw FormatException('Invalid X509 certificate');
      return output.stdout.toString().trim().split('=').last;
    } finally {
      dir.deleteSync(recursive: true);
    }
  }
}

crypto.Hash _hash(String algorithm) {
  if (algorithm == 'sha256') return crypto.sha256;
  throw ArgumentError.value(algorithm, 'algorithm', 'unsupported algorithm');
}

List<int> _bytes(Object data, String encoding) {
  if (data is Uint8List) return data;
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
