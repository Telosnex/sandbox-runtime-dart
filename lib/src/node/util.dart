// Node util subset used for credential-safe proxy error descriptions.

/// Node util.inspect of a flat object, at depth zero with no line wrapping.
String inspect(Map<String, Object?> object, {int? depth, num? breakLength}) {
  String value(Object? value) {
    if (value == null) return 'undefined';
    if (value is String) {
      final quote = value.contains("'") && !value.contains('"') ? '"' : "'";
      final escaped = value
          .replaceAll('\\', '\\\\')
          .replaceAll(quote, '\\$quote')
          .replaceAll('\n', r'\n')
          .replaceAll('\r', r'\r')
          .replaceAll('\t', r'\t');
      return '$quote$escaped$quote';
    }
    return value.toString();
  }

  return '{ ${object.entries.map((e) => '${e.key}: ${value(e.value)}').join(', ')} }';
}

/// Node util.isDeepStrictEqual: collections compare structurally, functions
/// and other objects by identity. The ported caller supplies plain fields
/// for its immutable Dart configuration classes.
bool isDeepStrictEqual(Object? left, Object? right) {
  final seen = <(Object, Object)>{};
  bool equal(Object? a, Object? b) {
    if (identical(a, b)) return true;
    if (a is num && b is num) {
      if (a.isNaN && b.isNaN) return true;
      if (a == 0 && b == 0) return a.isNegative == b.isNegative;
      return a == b;
    }
    if (a is String && b is String || a is bool && b is bool) return a == b;
    if (a == null || b == null) return false;
    final pair = (a, b);
    if (seen.contains(pair)) return true;
    seen.add(pair);
    if (a is List && b is List) {
      return a.length == b.length &&
          Iterable<int>.generate(a.length).every((i) => equal(a[i], b[i]));
    }
    if (a is Map && b is Map) {
      return a.length == b.length &&
          a.entries.every(
            (e) => b.containsKey(e.key) && equal(e.value, b[e.key]),
          );
    }
    if (a is Set && b is Set) {
      if (a.length != b.length) return false;
      final rest = b.toList();
      for (final item in a) {
        final at = rest.indexWhere((other) => equal(item, other));
        if (at < 0) return false;
        rest.removeAt(at);
      }
      return true;
    }
    return false;
  }

  return equal(left, right);
}
