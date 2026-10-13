// A focused Node-compatible URLSearchParams boundary for aws-sigv4.dart.
// This file has no upstream counterpart.

import 'dart:convert';
import 'dart:typed_data';

/// The URLSearchParams operations used by aws-sigv4.dart.
class URLSearchParams {
  URLSearchParams(String query) {
    for (final part in query.split('&')) {
      if (part.isEmpty) continue;
      final eq = part.indexOf('=');
      final name = _decode(eq == -1 ? part : part.substring(0, eq));
      final value = _decode(eq == -1 ? '' : part.substring(eq + 1));
      _values.putIfAbsent(name, () => <String>[]).add(value);
    }
  }

  final Map<String, List<String>> _values = {};

  /// Return the first value associated with [name], or `null` when absent.
  String? get(String name) => _values[name]?.first;

  /// Whether a parameter named [name] is present, even with an empty value.
  bool has(String name) => _values.containsKey(name);

  static String _decode(String value) {
    // URLSearchParams applies application/x-www-form-urlencoded decoding:
    // `+` becomes space, malformed `%` escapes remain literal, and invalid
    // UTF-8 byte sequences are replaced rather than causing an exception.
    final bytes = BytesBuilder(copy: false);
    final runes = value.runes.toList();
    for (var index = 0; index < runes.length; index++) {
      final rune = runes[index];
      if (rune == 0x2b) {
        bytes.addByte(0x20);
      } else if (rune == 0x25 && index + 2 < runes.length) {
        final high = _hexValue(runes[index + 1]);
        final low = _hexValue(runes[index + 2]);
        if (high != null && low != null) {
          bytes.addByte((high << 4) | low);
          index += 2;
        } else {
          bytes.add(utf8.encode(String.fromCharCode(rune)));
        }
      } else {
        bytes.add(utf8.encode(String.fromCharCode(rune)));
      }
    }
    return utf8.decode(bytes.takeBytes(), allowMalformed: true);
  }

  static int? _hexValue(int rune) {
    if (rune >= 0x30 && rune <= 0x39) return rune - 0x30;
    if (rune >= 0x41 && rune <= 0x46) return rune - 0x41 + 10;
    if (rune >= 0x61 && rune <= 0x66) return rune - 0x61 + 10;
    return null;
  }
}
