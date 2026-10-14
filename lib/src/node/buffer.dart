// Small Node Buffer surface used by sandbox-utils.ts.
import 'dart:collection';
import 'dart:convert';
import 'dart:typed_data';

/// A Node Buffer: a fixed-length list of bytes with Node's encodings.
/// `randomBytes`, `crypto.sign` and friends return this type, so
/// `randomBytes(8).toString('hex')` and `for (b of randomBytes(n))` work.
class Buffer with ListMixin<int> {
  Buffer._(this._bytes);
  final Uint8List _bytes;

  /// Wraps [bytes] without copying.
  Buffer.wrap(Uint8List bytes) : _bytes = bytes;

  static Buffer alloc(int size) => Buffer._(Uint8List(size));

  @override
  int get length => _bytes.length;
  @override
  set length(int value) => throw UnsupportedError('Buffer has a fixed length');
  @override
  int operator [](int index) => _bytes[index];
  @override
  void operator []=(int index, int value) => _bytes[index] = value & 0xff;

  factory Buffer.from(Object value, [String encoding = 'utf8']) {
    if (value is List<int>) return Buffer._(Uint8List.fromList(value));
    final text = value.toString();
    if (encoding == 'base64' || encoding == 'base64url') {
      // Node ignores whitespace, accepts base64url, and stops at padding.
      var clean = text.replaceAll(RegExp(r'[^A-Za-z0-9_+\-/=]'), '');
      clean = clean.replaceAll('-', '+').replaceAll('_', '/');
      final padding = clean.indexOf('=');
      if (padding >= 0) clean = clean.substring(0, padding);
      if (clean.length % 4 == 1) clean = clean.substring(0, clean.length - 1);
      clean = clean.padRight((clean.length + 3) ~/ 4 * 4, '=');
      if (clean.isEmpty) return Buffer._(Uint8List(0));
      try {
        return Buffer._(Uint8List.fromList(base64.decode(clean)));
      } on FormatException {
        return Buffer._(Uint8List(0));
      }
    }
    if (encoding == 'binary' || encoding == 'latin1') {
      return Buffer._(
        Uint8List.fromList([for (final c in text.codeUnits) c & 0xff]),
      );
    }
    if (encoding == 'hex') {
      final out = <int>[];
      for (var i = 0; i + 1 < text.length; i += 2) {
        final byte = int.tryParse(text.substring(i, i + 2), radix: 16);
        if (byte == null) break;
        out.add(byte);
      }
      return Buffer._(Uint8List.fromList(out));
    }
    return Buffer._(Uint8List.fromList(utf8.encode(text)));
  }

  static int byteLength(String value) => utf8.encode(value).length;

  @override
  String toString([String encoding = 'utf8']) {
    if (encoding == 'base64') return base64.encode(_bytes);
    if (encoding == 'base64url')
      return base64Url.encode(_bytes).replaceAll('=', '');
    if (encoding == 'hex')
      return _bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
    if (encoding == 'binary' || encoding == 'latin1')
      return String.fromCharCodes(_bytes);
    return utf8.decode(_bytes, allowMalformed: true);
  }

  Uint8List toUint8List() => Uint8List.fromList(_bytes);
}
