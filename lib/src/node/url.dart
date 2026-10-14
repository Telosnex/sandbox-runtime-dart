// Node `url` compatibility: WHATWG URL host parsing (for canonicalizeHost)
// and URLSearchParams (for aws-sigv4). No upstream counterpart.
import 'dart:convert';
import 'dart:typed_data';

/// The web-global / `node:url` URL declaration used by the port.
///
/// This declaration is pending its full WHATWG implementation. The constructor
/// resolves a relative input against [base] and throws [FormatException] for
/// invalid URLs, rather than Node's `TypeError`.
class URL {
  URL(String input, [String? base]) : _href = _parseUrl(input, base);

  String _href;

  String get href => _href;
  set href(String value) => _href = _parseUrl(value, null);

  Uri get _uri => Uri.parse(_href);
  void _set(Uri value) => _href = value.toString();

  String get protocol => '${_uri.scheme}:';
  set protocol(String value) =>
      _set(_uri.replace(scheme: value.replaceAll(':', '')));

  String get username => _uri.userInfo.split(':').first;
  set username(String value) => _set(
    _uri.replace(
      userInfo: '$value:${_uri.userInfo.split(':').skip(1).join(':')}',
    ),
  );

  String get password => _uri.userInfo.split(':').skip(1).join(':');
  set password(String value) =>
      _set(_uri.replace(userInfo: '${_uri.userInfo.split(':').first}:$value'));

  String get host => _uri.hasPort ? '${_uri.host}:${_uri.port}' : _uri.host;
  set host(String value) {
    final parsed = Uri.parse('${_uri.scheme}://$value/');
    _set(
      _uri.replace(
        host: parsed.host,
        port: parsed.hasPort ? parsed.port : null,
      ),
    );
  }

  String get hostname => _uri.host;
  set hostname(String value) => _set(_uri.replace(host: value));

  String get port => _uri.hasPort ? '${_uri.port}' : '';
  set port(String value) =>
      _set(_uri.replace(port: value.isEmpty ? null : int.parse(value)));

  String get pathname => _uri.path;
  set pathname(String value) => _set(_uri.replace(path: value));

  String get search => _uri.hasQuery ? '?${_uri.query}' : '';
  set search(String value) => _set(
    _uri.replace(query: value.startsWith('?') ? value.substring(1) : value),
  );

  String get hash => _uri.hasFragment ? '#${_uri.fragment}' : '';
  set hash(String value) => _set(
    _uri.replace(fragment: value.startsWith('#') ? value.substring(1) : value),
  );

  String get origin => _uri.origin;

  URLSearchParams get searchParams => URLSearchParams(_uri.query);

  @override
  String toString() => href;
}

String _parseUrl(String input, String? base) {
  try {
    final parsedInput = Uri.parse(input);
    final Uri parsed;
    if (parsedInput.hasScheme) {
      parsed = parsedInput;
    } else if (base != null) {
      final parsedBase = Uri.parse(base);
      if (!parsedBase.hasScheme) {
        throw const FormatException('Invalid URL base');
      }
      parsed = parsedBase.resolveUri(parsedInput);
    } else {
      throw const FormatException('Invalid URL');
    }
    if (!parsed.hasScheme) throw const FormatException('Invalid URL');
    if (parsed.host.isNotEmpty) {
      // Reuse the URL-host parser used by address normalization so invalid
      // hosts fail rather than being accepted by dart:core Uri alone.
      whatwgUrlHostname(parsed.host);
    }
    if (const {'http', 'https', 'ftp', 'ws', 'wss'}.contains(parsed.scheme) &&
        parsed.host.isEmpty) {
      throw const FormatException('Invalid URL host');
    }
    return parsed.toString();
  } on FormatException catch (error) {
    throw FormatException('Invalid URL: $input', error);
  }
}

/// `node:url` file URL conversion. Its platform-specific behavior is pending.
String fileURLToPath(String url) =>
    throw UnimplementedError('node:url URL: pending (wave 1)');

/// Return the `hostname` of `new URL('http://$host/').hostname` for the
/// supported special-URL host forms. Throws [FormatException] when the input
/// is invalid or uses IDNA behavior outside this shim's supported subset.
///
/// The supported IDNA subset is ASCII plus Latin-1 letters encoded with
/// Punycode, the three WHATWG dot mappings, and fullwidth ASCII mappings.
/// Unsupported Unicode is rejected rather than guessed.
String whatwgUrlHostname(String host) {
  final withoutTabs = host.replaceAll(RegExp(r'[\t\n\r]'), '');
  final pathStart = _firstOf(withoutTabs, const ['/', '?', '#', r'\']);
  final authority = pathStart == -1
      ? withoutTabs
      : withoutTabs.substring(0, pathStart);
  final at = authority.lastIndexOf('@');
  final hostPort = at == -1 ? authority : authority.substring(at + 1);
  if (hostPort.isEmpty) throw const FormatException('Invalid URL host');

  if (hostPort.startsWith('[')) {
    final close = hostPort.indexOf(']');
    if (close == -1) throw const FormatException('Invalid IPv6 URL host');
    final address = hostPort.substring(1, close);
    final rest = hostPort.substring(close + 1);
    if (rest.isNotEmpty) {
      if (!rest.startsWith(':')) {
        throw const FormatException('Invalid URL host suffix');
      }
      _validatePort(rest.substring(1));
    }
    return '[${_serializeIpv6(address)}]';
  }

  if (hostPort.contains('[') || hostPort.contains(']')) {
    throw const FormatException('Invalid URL host brackets');
  }
  final colon = hostPort.lastIndexOf(':');
  final rawHost = colon == -1 ? hostPort : hostPort.substring(0, colon);
  if (colon != -1) {
    if (hostPort.indexOf(':') != colon) {
      throw const FormatException('Invalid unbracketed IPv6 URL host');
    }
    _validatePort(hostPort.substring(colon + 1));
  }
  if (rawHost.isEmpty) throw const FormatException('Invalid URL host');
  final decoded = _percentDecode(rawHost);
  final asciiDomain = _domainToAscii(decoded);
  if (_endsInNumber(asciiDomain)) return _parseIpv4(asciiDomain);
  return asciiDomain;
}

int _firstOf(String value, List<String> delimiters) {
  var first = -1;
  for (final delimiter in delimiters) {
    final index = value.indexOf(delimiter);
    if (index != -1 && (first == -1 || index < first)) first = index;
  }
  return first;
}

void _validatePort(String port) {
  if (port.isEmpty) return;
  if (!RegExp(r'^[0-9]+$').hasMatch(port)) {
    throw const FormatException('Invalid URL port');
  }
  final value = int.tryParse(port);
  if (value == null || value > 65535) {
    throw const FormatException('Invalid URL port');
  }
}

String _percentDecode(String input) {
  final bytes = BytesBuilder(copy: false);
  for (var index = 0; index < input.length;) {
    final code = input.codeUnitAt(index);
    if (code == 0x25) {
      if (index + 2 >= input.length) {
        throw const FormatException('Invalid percent escape in URL host');
      }
      final high = _hexValue(input.codeUnitAt(index + 1));
      final low = _hexValue(input.codeUnitAt(index + 2));
      if (high == -1 || low == -1) {
        throw const FormatException('Invalid percent escape in URL host');
      }
      bytes.addByte((high << 4) | low);
      index += 3;
      continue;
    }
    final first = input.codeUnitAt(index);
    final rune = first >= 0xd800 && first <= 0xdbff
        ? 0x10000 +
              ((first - 0xd800) << 10) +
              (input.codeUnitAt(index + 1) - 0xdc00)
        : first;
    // Preserve unescaped Unicode while percent-decoding escaped octets.
    final width = rune > 0xffff ? 2 : 1;
    final text = input.substring(index, index + width);
    bytes.add(utf8.encode(text));
    index += width;
  }
  try {
    return utf8.decode(bytes.takeBytes());
  } on FormatException {
    throw const FormatException('Invalid UTF-8 escape in URL host');
  }
}

int _hexValue(int code) {
  if (code >= 0x30 && code <= 0x39) return code - 0x30;
  if (code >= 0x41 && code <= 0x46) return code - 0x41 + 10;
  if (code >= 0x61 && code <= 0x66) return code - 0x61 + 10;
  return -1;
}

String _domainToAscii(String input) {
  final mapped = StringBuffer();
  for (final rune in input.runes) {
    switch (rune) {
      case 0x3002:
      case 0xff0e:
      case 0xff61:
        mapped.write('.');
      default:
        if (rune >= 0xff01 && rune <= 0xff5e) {
          mapped.writeCharCode(rune - 0xfee0);
        } else {
          mapped.writeCharCode(rune);
        }
    }
  }

  final lower = mapped.toString().toLowerCase();
  for (final rune in lower.runes) {
    if (_isForbiddenHostCodePoint(rune)) {
      throw const FormatException('Forbidden code point in URL host');
    }
    if (rune > 0x7f && !_isSupportedLatin1Letter(rune)) {
      throw const FormatException('Unsupported IDNA code point in URL host');
    }
  }

  final labels = lower.split('.');
  final asciiLabels = <String>[];
  for (final label in labels) {
    final runes = label.runes.toList();
    if (runes.any((rune) => rune > 0x7f)) {
      asciiLabels.add('xn--${_punycodeEncode(runes)}');
    } else {
      if (label.startsWith('xn--')) {
        final decoded = _punycodeDecode(label.substring(4));
        final normalized = String.fromCharCodes(decoded).toLowerCase();
        for (final rune in normalized.runes) {
          if (_isForbiddenHostCodePoint(rune) ||
              (rune > 0x7f && !_isSupportedLatin1Letter(rune))) {
            throw const FormatException(
              'Unsupported IDNA code point in Punycode host',
            );
          }
        }
        asciiLabels.add('xn--${_punycodeEncode(normalized.runes.toList())}');
      } else {
        asciiLabels.add(label);
      }
    }
  }
  return asciiLabels.join('.');
}

bool _isForbiddenHostCodePoint(int rune) =>
    rune <= 0x20 ||
    (rune >= 0x7f && rune <= 0x9f) ||
    rune == 0x23 || // #
    rune == 0x25 || // %
    rune == 0x2f || // /
    rune == 0x3a || // :
    rune == 0x3c || // <
    rune == 0x3e || // >
    rune == 0x3f || // ?
    rune == 0x40 || // @
    rune == 0x5b || // [
    rune == 0x5c || // \
    rune == 0x5d || // ]
    rune == 0x5e || // ^
    rune == 0x7c; // |

bool _isSupportedLatin1Letter(int rune) =>
    (rune >= 0x00c0 && rune <= 0x00d6) ||
    (rune >= 0x00d8 && rune <= 0x00f6) ||
    (rune >= 0x00f8 && rune <= 0x00ff);

bool _endsInNumber(String domain) {
  final parts = domain.split('.');
  if (parts.isNotEmpty && parts.last.isEmpty) {
    parts.removeLast();
  }
  if (parts.isEmpty) return false;
  final last = parts.last;
  return _parseIpv4Number(last) != null || RegExp(r'^[0-9]+$').hasMatch(last);
}

BigInt? _parseIpv4Number(String input) {
  if (input.isEmpty) return null;
  var value = input;
  var radix = 10;
  if (value.length >= 2 && value.substring(0, 2).toLowerCase() == '0x') {
    value = value.substring(2);
    radix = 16;
    if (value.isEmpty) return BigInt.zero;
  } else if (value.length >= 2 && value.startsWith('0')) {
    value = value.substring(1);
    radix = 8;
    if (value.isEmpty) return BigInt.zero;
  }
  final valid = switch (radix) {
    16 => RegExp(r'^[0-9a-fA-F]+$').hasMatch(value),
    8 => RegExp(r'^[0-7]+$').hasMatch(value),
    _ => RegExp(r'^[0-9]+$').hasMatch(value),
  };
  if (!valid) return null;
  return BigInt.tryParse(value, radix: radix);
}

String _parseIpv4(String domain) {
  final parts = domain.split('.');
  if (parts.isNotEmpty && parts.last.isEmpty) parts.removeLast();
  if (parts.isEmpty || parts.length > 4) {
    throw const FormatException('Invalid IPv4 URL host');
  }
  final numbers = <BigInt>[];
  for (final part in parts) {
    final number = _parseIpv4Number(part);
    if (number == null) throw const FormatException('Invalid IPv4 URL host');
    numbers.add(number);
  }
  for (final number in numbers.take(numbers.length - 1)) {
    if (number > BigInt.from(255)) {
      throw const FormatException('Invalid IPv4 URL host');
    }
  }
  final lastMax = BigInt.one << (8 * (5 - numbers.length));
  if (numbers.last >= lastMax) {
    throw const FormatException('Invalid IPv4 URL host');
  }
  var address = numbers.last;
  for (var index = 0; index < numbers.length - 1; index++) {
    address += numbers[index] << (8 * (3 - index));
  }
  final mask = (BigInt.one << 32) - BigInt.one;
  if (address > mask) throw const FormatException('Invalid IPv4 URL host');
  return [
    for (var shift = 24; shift >= 0; shift -= 8)
      ((address >> shift) & BigInt.from(255)).toInt(),
  ].join('.');
}

String _serializeIpv6(String address) {
  if (address.contains('%')) {
    throw const FormatException('IPv6 zone IDs are invalid URL hosts');
  }
  var source = address;
  if (source.contains('.')) {
    final colon = source.lastIndexOf(':');
    if (colon == -1) throw const FormatException('Invalid IPv6 URL host');
    final ipv4 = source.substring(colon + 1);
    final octets = _parseStrictIpv4(ipv4);
    final high = (octets[0] << 8) | octets[1];
    final low = (octets[2] << 8) | octets[3];
    source =
        '${source.substring(0, colon + 1)}${high.toRadixString(16)}:${low.toRadixString(16)}';
  }
  final compression = source.indexOf('::');
  final hasCompression = compression != -1;
  final List<String> left;
  final List<String> right;
  if (hasCompression) {
    if (source.indexOf('::', compression + 2) != -1) {
      throw const FormatException('Invalid IPv6 URL host');
    }
    final before = source.substring(0, compression);
    final after = source.substring(compression + 2);
    left = before.isEmpty ? <String>[] : before.split(':');
    right = after.isEmpty ? <String>[] : after.split(':');
  } else {
    left = source.split(':');
    right = <String>[];
  }
  final all = [...left, ...right];
  if (all.length > 8 ||
      all.any((group) => !RegExp(r'^[0-9a-fA-F]{1,4}$').hasMatch(group))) {
    throw const FormatException('Invalid IPv6 URL host');
  }
  final groups = all.map((group) => int.parse(group, radix: 16)).toList();
  if (hasCompression) {
    final zeroes = 8 - groups.length;
    if (zeroes < 1) throw const FormatException('Invalid IPv6 URL host');
    groups
      ..clear()
      ..addAll([
        ...left.map((group) => int.parse(group, radix: 16)),
        ...List<int>.filled(zeroes, 0),
        ...right.map((group) => int.parse(group, radix: 16)),
      ]);
  } else if (groups.length != 8) {
    throw const FormatException('Invalid IPv6 URL host');
  }

  var bestStart = -1;
  var bestLength = 1;
  for (var index = 0; index < groups.length;) {
    if (groups[index] != 0) {
      index++;
      continue;
    }
    var end = index;
    while (end < groups.length && groups[end] == 0) {
      end++;
    }
    if (end - index > bestLength) {
      bestStart = index;
      bestLength = end - index;
    }
    index = end;
  }
  if (bestStart == -1) {
    return groups.map((group) => group.toRadixString(16)).join(':');
  }
  final before = groups
      .take(bestStart)
      .map((group) => group.toRadixString(16))
      .join(':');
  final after = groups
      .skip(bestStart + bestLength)
      .map((group) => group.toRadixString(16))
      .join(':');
  return '$before::$after';
}

List<int> _parseStrictIpv4(String address) {
  final parts = address.split('.');
  if (parts.length != 4 ||
      parts.any((part) => !RegExp(r'^(0|[1-9][0-9]{0,2})$').hasMatch(part))) {
    throw const FormatException('Invalid embedded IPv4 URL host');
  }
  final values = parts.map(int.parse).toList();
  if (values.any((value) => value > 255)) {
    throw const FormatException('Invalid embedded IPv4 URL host');
  }
  return values;
}

String _punycodeEncode(List<int> input) {
  const base = 36;
  const tmin = 1;
  const tmax = 26;
  const skew = 38;
  const damp = 700;
  const initialBias = 72;
  const initialN = 128;

  final output = StringBuffer();
  for (final codePoint in input) {
    if (codePoint < 0x80) output.writeCharCode(codePoint);
  }
  final basicLength = output.length;
  var handled = basicLength;
  if (basicLength > 0) output.write('-');
  var n = initialN;
  var delta = 0;
  var bias = initialBias;
  while (handled < input.length) {
    var m = 0x10ffff;
    for (final codePoint in input) {
      if (codePoint >= n && codePoint < m) m = codePoint;
    }
    delta += (m - n) * (handled + 1);
    n = m;
    for (final codePoint in input) {
      if (codePoint < n) delta++;
      if (codePoint != n) continue;
      var q = delta;
      for (var k = base; ; k += base) {
        final t = k <= bias
            ? tmin
            : k >= bias + tmax
            ? tmax
            : k - bias;
        if (q < t) break;
        final code = t + ((q - t) % (base - t));
        output.writeCharCode(_punycodeDigit(code));
        q = (q - t) ~/ (base - t);
      }
      output.writeCharCode(_punycodeDigit(q));
      bias = _adaptPunycode(
        delta,
        handled + 1,
        handled == basicLength,
        base,
        tmin,
        tmax,
        skew,
        damp,
      );
      delta = 0;
      handled++;
    }
    delta++;
    n++;
  }
  return output.toString();
}

List<int> _punycodeDecode(String encoded) {
  const base = 36;
  const tmin = 1;
  const tmax = 26;
  const skew = 38;
  const damp = 700;
  const initialBias = 72;
  const initialN = 128;
  if (encoded.isEmpty) throw const FormatException('Invalid Punycode URL host');

  final output = <int>[];
  final delimiter = encoded.lastIndexOf('-');
  var index = 0;
  if (delimiter != -1) {
    for (final rune in encoded.substring(0, delimiter).runes) {
      if (rune >= 0x80) {
        throw const FormatException('Invalid Punycode URL host');
      }
      output.add(rune);
    }
    index = delimiter + 1;
  }
  var n = initialN;
  var i = 0;
  var bias = initialBias;
  while (index < encoded.length) {
    final oldI = i;
    var weight = 1;
    for (var k = base; ; k += base) {
      if (index >= encoded.length) {
        throw const FormatException('Invalid Punycode URL host');
      }
      final digit = _punycodeValue(encoded.codeUnitAt(index++));
      if (digit == -1) throw const FormatException('Invalid Punycode URL host');
      i += digit * weight;
      final t = k <= bias
          ? tmin
          : k >= bias + tmax
          ? tmax
          : k - bias;
      if (digit < t) break;
      weight *= base - t;
    }
    final outLength = output.length + 1;
    bias = _adaptPunycode(
      i - oldI,
      outLength,
      oldI == 0,
      base,
      tmin,
      tmax,
      skew,
      damp,
    );
    n += i ~/ outLength;
    i %= outLength;
    output.insert(i, n);
    i++;
  }
  return output;
}

int _adaptPunycode(
  int delta,
  int points,
  bool first,
  int base,
  int tmin,
  int tmax,
  int skew,
  int damp,
) {
  delta = first ? delta ~/ damp : delta ~/ 2;
  delta += delta ~/ points;
  var k = 0;
  final limit = ((base - tmin) * tmax) ~/ 2;
  while (delta > limit) {
    delta ~/= base - tmin;
    k += base;
  }
  return k + (((base - tmin + 1) * delta) ~/ (delta + skew));
}

int _punycodeDigit(int value) => value < 26 ? 0x61 + value : 0x30 + value - 26;

int _punycodeValue(int code) {
  if (code >= 0x61 && code <= 0x7a) return code - 0x61;
  if (code >= 0x41 && code <= 0x5a) return code - 0x41;
  if (code >= 0x30 && code <= 0x39) return code - 0x30 + 26;
  return -1;
}

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
