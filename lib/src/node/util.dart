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
