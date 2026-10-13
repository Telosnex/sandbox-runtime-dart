// Small Node Buffer surface used by sandbox-utils.ts.
import 'dart:convert';
import 'dart:typed_data';

class Buffer {
  Buffer._(this._bytes);
  final Uint8List _bytes;

  factory Buffer.from(Object value, [String encoding = 'utf8']) {
    if (value is List<int>) return Buffer._(Uint8List.fromList(value));
    final text = value.toString();
    if (encoding == 'base64') {
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
    return Buffer._(Uint8List.fromList(utf8.encode(text)));
  }

  static int byteLength(String value) => utf8.encode(value).length;

  @override
  String toString([String encoding = 'utf8']) {
    if (encoding == 'base64') return base64.encode(_bytes);
    return utf8.decode(_bytes, allowMalformed: true);
  }

  Uint8List toUint8List() => Uint8List.fromList(_bytes);
}
