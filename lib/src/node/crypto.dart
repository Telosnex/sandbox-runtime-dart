// Node `crypto` compatibility: createHash and createHmac (sha256), as
// aws-sigv4.ts uses them. No upstream counterpart. A digest without an
// encoding is a Node Buffer, which is a Uint8List here.

import 'dart:convert';
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
