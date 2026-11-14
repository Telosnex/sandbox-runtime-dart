// Node `url` compatibility: WHATWG URL host parsing (for canonicalizeHost)
// and URLSearchParams (for aws-sigv4). No upstream counterpart.
import 'dart:isolate';
import 'dart:convert';
import 'dart:io' show Platform;
import 'dart:typed_data';

/// The web-global / `node:url` URL: the WHATWG URL Standard's basic URL
/// parser and serializer, with the setters' state overrides.
///
/// Invalid input throws [FormatException] rather than Node's `TypeError`.
/// Hosts go through [whatwgUrlHostname]'s parser, so IDNA input outside its
/// supported subset is rejected rather than guessed.
class URL {
  URL(String input, [String? base]) {
    _UrlRecord? baseRecord;
    if (base != null) {
      baseRecord = _UrlParser(base).parse();
      if (baseRecord == null) throw FormatException('Invalid URL: $base');
    }
    final record = _UrlParser(input, base: baseRecord).parse();
    if (record == null) throw FormatException('Invalid URL: $input');
    _url = record;
  }

  /// Whether [input] (against [base]) parses, as `URL.canParse`.
  static bool canParse(String input, [String? base]) {
    try {
      URL(input, base);
      return true;
    } on FormatException {
      return false;
    }
  }

  late _UrlRecord _url;

  String get href => _url.serialize();
  set href(String value) {
    final record = _UrlParser(value).parse();
    if (record == null) throw FormatException('Invalid URL: $value');
    _url = record;
  }

  String get origin {
    switch (_url.scheme) {
      case 'blob':
        final inner = _UrlParser(_url.pathString).parse();
        if (inner != null &&
            (inner.scheme == 'http' || inner.scheme == 'https')) {
          return URL(inner.serialize()).origin;
        }
        return 'null';
      case 'ftp' || 'http' || 'https' || 'ws' || 'wss':
        final port = _url.port == null ? '' : ':${_url.port}';
        return '${_url.scheme}://${_url.host}$port';
      default:
        return 'null';
    }
  }

  String get protocol => '${_url.scheme}:';
  set protocol(String value) =>
      _UrlParser('$value:', url: _url, override: _State.schemeStart).parse();

  String get username => _url.username;
  set username(String value) {
    if (_url.cannotHaveCredentialsOrPort) return;
    _url.username = _percentEncodeString(value, _isUserinfoEncode);
  }

  String get password => _url.password;
  set password(String value) {
    if (_url.cannotHaveCredentialsOrPort) return;
    _url.password = _percentEncodeString(value, _isUserinfoEncode);
  }

  String get host {
    if (_url.host == null) return '';
    if (_url.port == null) return _url.host!;
    return '${_url.host}:${_url.port}';
  }

  set host(String value) {
    if (_url.opaquePath != null) return;
    _UrlParser(value, url: _url, override: _State.host).parse();
  }

  String get hostname => _url.host ?? '';
  set hostname(String value) {
    if (_url.opaquePath != null) return;
    _UrlParser(value, url: _url, override: _State.hostname).parse();
  }

  String get port => _url.port == null ? '' : '${_url.port}';
  set port(String value) {
    if (_url.cannotHaveCredentialsOrPort) return;
    if (value.isEmpty) {
      _url.port = null;
    } else {
      _UrlParser(value, url: _url, override: _State.port).parse();
    }
  }

  String get pathname => _url.pathString;
  set pathname(String value) {
    if (_url.opaquePath != null) return;
    _url.path.clear();
    _UrlParser(value, url: _url, override: _State.pathStart).parse();
  }

  String get search {
    final query = _url.query;
    return query == null || query.isEmpty ? '' : '?$query';
  }

  set search(String value) {
    if (value.isEmpty) {
      _url.query = null;
      _stripTrailingSpacesFromOpaquePath();
      return;
    }
    final input = value.startsWith('?') ? value.substring(1) : value;
    _url.query = '';
    _UrlParser(input, url: _url, override: _State.query).parse();
  }

  String get hash {
    final fragment = _url.fragment;
    return fragment == null || fragment.isEmpty ? '' : '#$fragment';
  }

  set hash(String value) {
    if (value.isEmpty) {
      _url.fragment = null;
      _stripTrailingSpacesFromOpaquePath();
      return;
    }
    final input = value.startsWith('#') ? value.substring(1) : value;
    _url.fragment = '';
    _UrlParser(input, url: _url, override: _State.fragment).parse();
  }

  void _stripTrailingSpacesFromOpaquePath() {
    final path = _url.opaquePath;
    if (path == null || _url.fragment != null || _url.query != null) return;
    _url.opaquePath = path.replaceFirst(RegExp(r' +$'), '');
  }

  URLSearchParams get searchParams => URLSearchParams(_url.query ?? '');

  String toJSON() => href;

  @override
  String toString() => href;
}

const _specialPorts = <String, int?>{
  'ftp': 21,
  'file': null,
  'http': 80,
  'https': 443,
  'ws': 80,
  'wss': 443,
};

bool _isSpecialScheme(String scheme) => _specialPorts.containsKey(scheme);

class _UrlRecord {
  String scheme = '';
  String username = '';
  String password = '';
  String? host;
  int? port;
  List<String> path = [];
  String? opaquePath;
  String? query;
  String? fragment;

  bool get isSpecial => _isSpecialScheme(scheme);

  bool get includesCredentials => username.isNotEmpty || password.isNotEmpty;

  bool get cannotHaveCredentialsOrPort =>
      host == null || host == '' || scheme == 'file';

  String get pathString => opaquePath ?? path.map((s) => '/$s').join();

  void shortenPath() {
    if (scheme == 'file' &&
        path.length == 1 &&
        _isNormalizedWindowsDriveLetter(path[0])) {
      return;
    }
    if (path.isNotEmpty) path.removeLast();
  }

  _UrlRecord copy() => _UrlRecord()
    ..scheme = scheme
    ..username = username
    ..password = password
    ..host = host
    ..port = port
    ..path = List.of(path)
    ..opaquePath = opaquePath
    ..query = query
    ..fragment = fragment;

  String serialize({bool excludeFragment = false}) {
    final out = StringBuffer('$scheme:');
    if (host != null) {
      out.write('//');
      if (includesCredentials) {
        out.write(username);
        if (password.isNotEmpty) out.write(':$password');
        out.write('@');
      }
      out.write(host);
      if (port != null) out.write(':$port');
    }
    if (host == null &&
        opaquePath == null &&
        path.length > 1 &&
        path[0].isEmpty) {
      out.write('/.');
    }
    out.write(pathString);
    if (query != null) out.write('?$query');
    if (!excludeFragment && fragment != null) out.write('#$fragment');
    return out.toString();
  }
}

enum _State {
  schemeStart,
  scheme,
  noScheme,
  specialRelativeOrAuthority,
  pathOrAuthority,
  relative,
  relativeSlash,
  specialAuthoritySlashes,
  specialAuthorityIgnoreSlashes,
  authority,
  host,
  hostname,
  port,
  file,
  fileSlash,
  fileHost,
  pathStart,
  path,
  opaquePath,
  query,
  fragment,
}

const _eof = -1;

bool _isAsciiAlpha(int c) =>
    (c >= 0x41 && c <= 0x5a) || (c >= 0x61 && c <= 0x7a);
bool _isAsciiDigit(int c) => c >= 0x30 && c <= 0x39;
bool _isAsciiAlphanumeric(int c) => _isAsciiAlpha(c) || _isAsciiDigit(c);

bool _isWindowsDriveLetter(String s) {
  final r = s.runes.toList();
  return r.length == 2 && _isAsciiAlpha(r[0]) && (r[1] == 0x3a || r[1] == 0x7c);
}

bool _isNormalizedWindowsDriveLetter(String s) =>
    _isWindowsDriveLetter(s) && s.codeUnitAt(1) == 0x3a;

bool _startsWithWindowsDriveLetter(List<int> runes, int at) {
  if (runes.length - at < 2) return false;
  if (!_isAsciiAlpha(runes[at]) ||
      (runes[at + 1] != 0x3a && runes[at + 1] != 0x7c)) {
    return false;
  }
  if (runes.length - at == 2) return true;
  final c = runes[at + 2];
  return c == 0x2f || c == 0x5c || c == 0x3f || c == 0x23;
}

bool _isC0ControlEncode(int c) => c < 0x20 || c > 0x7e;
bool _isFragmentEncode(int c) =>
    _isC0ControlEncode(c) ||
    c == 0x20 ||
    c == 0x22 ||
    c == 0x3c ||
    c == 0x3e ||
    c == 0x60;
bool _isQueryEncode(int c) =>
    _isC0ControlEncode(c) ||
    c == 0x20 ||
    c == 0x22 ||
    c == 0x23 ||
    c == 0x3c ||
    c == 0x3e;
bool _isSpecialQueryEncode(int c) => _isQueryEncode(c) || c == 0x27;
bool _isPathEncode(int c) =>
    _isQueryEncode(c) || c == 0x3f || c == 0x60 || c == 0x7b || c == 0x7d;
bool _isUserinfoEncode(int c) =>
    _isPathEncode(c) ||
    c == 0x2f ||
    c == 0x3a ||
    c == 0x3b ||
    c == 0x3d ||
    c == 0x40 ||
    (c >= 0x5b && c <= 0x5e) ||
    c == 0x7c;

String _percentEncodeRune(int rune, bool Function(int) inSet) {
  if (!inSet(rune)) return String.fromCharCode(rune);
  final out = StringBuffer();
  for (final byte in utf8.encode(String.fromCharCode(rune))) {
    out.write('%${byte.toRadixString(16).toUpperCase().padLeft(2, '0')}');
  }
  return out.toString();
}

String _percentEncodeString(String input, bool Function(int) inSet) {
  final out = StringBuffer();
  for (final rune in input.runes) {
    out.write(_percentEncodeRune(rune, inSet));
  }
  return out.toString();
}

/// The basic URL parser. Returns null on failure (or, with a state override,
/// when the override leaves the URL unchanged).
class _UrlParser {
  _UrlParser(String input, {this.base, _UrlRecord? url, _State? override})
    : _override = override,
      _target = url {
    var text = input;
    if (url == null) {
      text = text.replaceFirst(RegExp(r'^[\u0000-\u0020]+'), '');
      text = text.replaceFirst(RegExp(r'[\u0000-\u0020]+$'), '');
    }
    text = text.replaceAll(RegExp(r'[\t\n\r]'), '');
    _input = text.runes.toList();
  }

  final _UrlRecord? base;
  final _State? _override;
  final _UrlRecord? _target;
  late final List<int> _input;

  _UrlRecord? parse() {
    final url = _target ?? _UrlRecord();
    final override = _override;
    var state = override ?? _State.schemeStart;
    final buffer = StringBuffer();
    var atSignSeen = false;
    var insideBrackets = false;
    var passwordTokenSeen = false;
    var pointer = 0;

    int c() => pointer < _input.length ? _input[pointer] : _eof;
    int remaining(int n) =>
        pointer + n < _input.length ? _input[pointer + n] : _eof;
    String buf() => buffer.toString();

    for (; ; pointer++) {
      final ch = c();
      switch (state) {
        case _State.schemeStart:
          if (ch != _eof && _isAsciiAlpha(ch)) {
            buffer.writeCharCode(ch | 0x20);
            state = _State.scheme;
          } else if (override == null) {
            state = _State.noScheme;
            pointer--;
          } else {
            return null;
          }
        case _State.scheme:
          if (ch != _eof &&
              (_isAsciiAlphanumeric(ch) ||
                  ch == 0x2b ||
                  ch == 0x2d ||
                  ch == 0x2e)) {
            buffer.writeCharCode(_isAsciiAlpha(ch) ? ch | 0x20 : ch);
          } else if (ch == 0x3a) {
            final candidate = buf();
            if (override != null) {
              if (url.isSpecial != _isSpecialScheme(candidate)) return null;
              if ((url.includesCredentials || url.port != null) &&
                  candidate == 'file') {
                return null;
              }
              if (url.scheme == 'file' && (url.host ?? '').isEmpty) {
                return null;
              }
            }
            url.scheme = candidate;
            if (override != null) {
              if (url.port == _specialPorts[url.scheme]) url.port = null;
              return null;
            }
            buffer.clear();
            if (url.scheme == 'file') {
              state = _State.file;
            } else if (url.isSpecial &&
                base != null &&
                base!.scheme == url.scheme) {
              state = _State.specialRelativeOrAuthority;
            } else if (url.isSpecial) {
              state = _State.specialAuthoritySlashes;
            } else if (remaining(1) == 0x2f) {
              state = _State.pathOrAuthority;
              pointer++;
            } else {
              url.opaquePath = '';
              state = _State.opaquePath;
            }
          } else if (override == null) {
            buffer.clear();
            state = _State.noScheme;
            pointer = -1;
          } else {
            return null;
          }
        case _State.noScheme:
          final b = base;
          if (b == null || (b.opaquePath != null && ch != 0x23)) {
            return null;
          } else if (b.opaquePath != null && ch == 0x23) {
            url
              ..scheme = b.scheme
              ..opaquePath = b.opaquePath
              ..query = b.query
              ..fragment = '';
            state = _State.fragment;
          } else if (b.scheme != 'file') {
            state = _State.relative;
            pointer--;
          } else {
            state = _State.file;
            pointer--;
          }
        case _State.specialRelativeOrAuthority:
          if (ch == 0x2f && remaining(1) == 0x2f) {
            state = _State.specialAuthorityIgnoreSlashes;
            pointer++;
          } else {
            state = _State.relative;
            pointer--;
          }
        case _State.pathOrAuthority:
          if (ch == 0x2f) {
            state = _State.authority;
          } else {
            state = _State.path;
            pointer--;
          }
        case _State.relative:
          final b = base!;
          url.scheme = b.scheme;
          if (ch == 0x2f) {
            state = _State.relativeSlash;
          } else if (url.isSpecial && ch == 0x5c) {
            state = _State.relativeSlash;
          } else {
            url
              ..username = b.username
              ..password = b.password
              ..host = b.host
              ..port = b.port
              ..path = List.of(b.path)
              ..query = b.query;
            if (ch == 0x3f) {
              url.query = '';
              state = _State.query;
            } else if (ch == 0x23) {
              url.fragment = '';
              state = _State.fragment;
            } else if (ch != _eof) {
              url.query = null;
              url.shortenPath();
              state = _State.path;
              pointer--;
            }
          }
        case _State.relativeSlash:
          if (url.isSpecial && (ch == 0x2f || ch == 0x5c)) {
            state = _State.specialAuthorityIgnoreSlashes;
          } else if (ch == 0x2f) {
            state = _State.authority;
          } else {
            final b = base!;
            url
              ..username = b.username
              ..password = b.password
              ..host = b.host
              ..port = b.port;
            state = _State.path;
            pointer--;
          }
        case _State.specialAuthoritySlashes:
          if (ch == 0x2f && remaining(1) == 0x2f) {
            state = _State.specialAuthorityIgnoreSlashes;
            pointer++;
          } else {
            state = _State.specialAuthorityIgnoreSlashes;
            pointer--;
          }
        case _State.specialAuthorityIgnoreSlashes:
          if (ch != 0x2f && ch != 0x5c) {
            state = _State.authority;
            pointer--;
          }
        case _State.authority:
          if (ch == 0x40) {
            final text = '${atSignSeen ? '%40' : ''}${buf()}';
            atSignSeen = true;
            for (final rune in text.runes) {
              if (rune == 0x3a && !passwordTokenSeen) {
                passwordTokenSeen = true;
                continue;
              }
              final encoded = _percentEncodeRune(rune, _isUserinfoEncode);
              if (passwordTokenSeen) {
                url.password += encoded;
              } else {
                url.username += encoded;
              }
            }
            buffer.clear();
          } else if (ch == _eof ||
              ch == 0x2f ||
              ch == 0x3f ||
              ch == 0x23 ||
              (url.isSpecial && ch == 0x5c)) {
            if (atSignSeen && buffer.isEmpty) return null;
            pointer -= buf().runes.length + 1;
            buffer.clear();
            state = _State.host;
          } else {
            buffer.writeCharCode(ch);
          }
        case _State.host || _State.hostname:
          if (override != null && url.scheme == 'file') {
            pointer--;
            state = _State.fileHost;
          } else if (ch == 0x3a && !insideBrackets) {
            if (buffer.isEmpty) return null;
            if (override == _State.hostname) return null;
            final host = _parseHost(buf(), !url.isSpecial);
            if (host == null) return null;
            url.host = host;
            buffer.clear();
            state = _State.port;
          } else if (ch == _eof ||
              ch == 0x2f ||
              ch == 0x3f ||
              ch == 0x23 ||
              (url.isSpecial && ch == 0x5c)) {
            pointer--;
            if (url.isSpecial && buffer.isEmpty) return null;
            if (override != null &&
                buffer.isEmpty &&
                (url.includesCredentials || url.port != null)) {
              return null;
            }
            final host = _parseHost(buf(), !url.isSpecial);
            if (host == null) return null;
            url.host = host;
            buffer.clear();
            state = _State.pathStart;
            if (override != null) return null;
          } else {
            if (ch == 0x5b) insideBrackets = true;
            if (ch == 0x5d) insideBrackets = false;
            buffer.writeCharCode(ch);
          }
        case _State.port:
          if (ch != _eof && _isAsciiDigit(ch)) {
            buffer.writeCharCode(ch);
          } else if (ch == _eof ||
              ch == 0x2f ||
              ch == 0x3f ||
              ch == 0x23 ||
              (url.isSpecial && ch == 0x5c) ||
              override != null) {
            if (buffer.isNotEmpty) {
              final port = int.parse(buf().length > 6 ? '999999' : buf());
              if (port > 65535) return null;
              url.port = port == _specialPorts[url.scheme] ? null : port;
              buffer.clear();
              if (override != null) return null;
            }
            if (override != null) return null;
            state = _State.pathStart;
            pointer--;
          } else {
            return null;
          }
        case _State.file:
          url
            ..scheme = 'file'
            ..host = '';
          final b = base;
          if (ch == 0x2f || ch == 0x5c) {
            state = _State.fileSlash;
          } else if (b != null && b.scheme == 'file') {
            url
              ..host = b.host
              ..path = List.of(b.path)
              ..query = b.query;
            if (ch == 0x3f) {
              url.query = '';
              state = _State.query;
            } else if (ch == 0x23) {
              url.fragment = '';
              state = _State.fragment;
            } else if (ch != _eof) {
              url.query = null;
              if (!_startsWithWindowsDriveLetter(_input, pointer)) {
                url.shortenPath();
              } else {
                url.path = [];
              }
              state = _State.path;
              pointer--;
            }
          } else {
            state = _State.path;
            pointer--;
          }
        case _State.fileSlash:
          if (ch == 0x2f || ch == 0x5c) {
            state = _State.fileHost;
          } else {
            final b = base;
            if (b != null && b.scheme == 'file') {
              url.host = b.host;
              if (!_startsWithWindowsDriveLetter(_input, pointer) &&
                  b.path.isNotEmpty &&
                  _isNormalizedWindowsDriveLetter(b.path[0])) {
                url.path.add(b.path[0]);
              }
            }
            state = _State.path;
            pointer--;
          }
        case _State.fileHost:
          if (ch == _eof ||
              ch == 0x2f ||
              ch == 0x5c ||
              ch == 0x3f ||
              ch == 0x23) {
            pointer--;
            if (override == null && _isWindowsDriveLetter(buf())) {
              state = _State.path;
            } else if (buffer.isEmpty) {
              url.host = '';
              if (override != null) return null;
              state = _State.pathStart;
            } else {
              var host = _parseHost(buf(), !url.isSpecial);
              if (host == null) return null;
              if (host == 'localhost') host = '';
              url.host = host;
              if (override != null) return null;
              buffer.clear();
              state = _State.pathStart;
            }
          } else {
            buffer.writeCharCode(ch);
          }
        case _State.pathStart:
          if (url.isSpecial) {
            state = _State.path;
            if (ch != 0x2f && ch != 0x5c) pointer--;
          } else if (override == null && ch == 0x3f) {
            url.query = '';
            state = _State.query;
          } else if (override == null && ch == 0x23) {
            url.fragment = '';
            state = _State.fragment;
          } else if (ch != _eof) {
            state = _State.path;
            if (ch != 0x2f) pointer--;
          } else if (override != null && url.host == null) {
            url.path.add('');
          }
        case _State.path:
          if (ch == _eof ||
              ch == 0x2f ||
              (url.isSpecial && ch == 0x5c) ||
              (override == null && (ch == 0x3f || ch == 0x23))) {
            final segment = buf();
            final lower = segment.toLowerCase();
            final isDoubleDot =
                lower == '..' ||
                lower == '.%2e' ||
                lower == '%2e.' ||
                lower == '%2e%2e';
            final isSingleDot = lower == '.' || lower == '%2e';
            final slash = ch == 0x2f || (url.isSpecial && ch == 0x5c);
            if (isDoubleDot) {
              url.shortenPath();
              if (!slash) url.path.add('');
            } else if (isSingleDot && !slash) {
              url.path.add('');
            } else if (!isSingleDot) {
              var part = segment;
              if (url.scheme == 'file' &&
                  url.path.isEmpty &&
                  _isWindowsDriveLetter(part)) {
                part = '${part[0]}:';
              }
              url.path.add(part);
            }
            buffer.clear();
            if (ch == 0x3f) {
              url.query = '';
              state = _State.query;
            }
            if (ch == 0x23) {
              url.fragment = '';
              state = _State.fragment;
            }
          } else {
            buffer.write(_percentEncodeRune(ch, _isPathEncode));
          }
        case _State.opaquePath:
          if (ch == 0x3f) {
            url.query = '';
            state = _State.query;
          } else if (ch == 0x23) {
            url.fragment = '';
            state = _State.fragment;
          } else if (ch == 0x20) {
            final next = remaining(1);
            url.opaquePath =
                '${url.opaquePath}${next == 0x3f || next == 0x23 ? '%20' : ' '}';
          } else if (ch != _eof) {
            url.opaquePath =
                '${url.opaquePath}${_percentEncodeRune(ch, _isC0ControlEncode)}';
          }
        case _State.query:
          if ((override == null && ch == 0x23) || ch == _eof) {
            final inSet = url.isSpecial
                ? _isSpecialQueryEncode
                : _isQueryEncode;
            url.query =
                '${url.query ?? ''}${_percentEncodeString(buf(), inSet)}';
            buffer.clear();
            if (ch == 0x23) {
              url.fragment = '';
              state = _State.fragment;
            }
          } else {
            buffer.writeCharCode(ch);
          }
        case _State.fragment:
          if (ch != _eof) {
            url.fragment =
                '${url.fragment}${_percentEncodeRune(ch, _isFragmentEncode)}';
          }
      }
      if (pointer >= _input.length) break;
    }
    return override == null ? url : null;
  }
}

/// The host parser: a bracketed IPv6 address, an opaque host when
/// [isOpaque], else a domain or IPv4 address. Returns null on failure.
String? _parseHost(String input, bool isOpaque) {
  if (input.startsWith('[')) {
    if (!input.endsWith(']')) return null;
    try {
      return '[${_serializeIpv6(input.substring(1, input.length - 1))}]';
    } on FormatException {
      return null;
    }
  }
  if (isOpaque) {
    for (final rune in input.runes) {
      if (rune != 0x25 && _isForbiddenOpaqueHostCodePoint(rune)) return null;
    }
    return _percentEncodeString(input, _isC0ControlEncode);
  }
  if (input.isEmpty) return null;
  try {
    final asciiDomain = _domainToAscii(_percentDecode(input));
    if (asciiDomain.isEmpty) return null;
    if (_endsInNumber(asciiDomain)) return _parseIpv4(asciiDomain);
    return asciiDomain;
  } on FormatException {
    return null;
  }
}

bool _isForbiddenOpaqueHostCodePoint(int rune) =>
    rune == 0x00 ||
    rune == 0x09 ||
    rune == 0x0a ||
    rune == 0x0d ||
    rune == 0x20 ||
    rune == 0x23 ||
    rune == 0x2f ||
    rune == 0x3a ||
    rune == 0x3c ||
    rune == 0x3e ||
    rune == 0x3f ||
    rune == 0x40 ||
    rune == 0x5b ||
    rune == 0x5c ||
    rune == 0x5d ||
    rune == 0x5e ||
    rune == 0x7c;

/// `node:url` fileURLToPath.
///
/// As Node: [url] is a URL string or [URL]; a non-file URL, an encoded `/`
/// (or `\\` on Windows), a host on POSIX, or a Windows path without a drive
/// letter throws [ArgumentError] (Node's TypeError).
String fileURLToPath(Object url, {bool? windows}) {
  final parsed = url is URL ? url : URL(url as String);
  if (parsed.protocol != 'file:') {
    throw ArgumentError.value(url, 'url', 'The URL must be of scheme file');
  }
  final isWindows = windows ?? Platform.isWindows;
  final pathname = parsed.pathname;
  for (var n = 0; n + 2 < pathname.length; n++) {
    if (pathname[n] != '%') continue;
    final third = pathname.codeUnitAt(n + 2) | 0x20;
    if ((pathname[n + 1] == '2' && third == 0x66) ||
        (isWindows && pathname[n + 1] == '5' && third == 0x63)) {
      throw ArgumentError.value(
        url,
        'url',
        'File URL path must not include encoded ${isWindows ? '\\ or /' : '/'} characters',
      );
    }
  }
  if (isWindows) {
    final path = Uri.decodeComponent(pathname.replaceAll('/', '\\'));
    if (parsed.hostname.isNotEmpty) return '\\\\${parsed.hostname}$path';
    final letter = path.length > 1 ? path.codeUnitAt(1) | 0x20 : 0;
    if (letter < 0x61 || letter > 0x7a || path.length < 3 || path[2] != ':') {
      throw ArgumentError.value(url, 'url', 'File URL path must be absolute');
    }
    return path.substring(1);
  }
  if (parsed.hostname.isNotEmpty) {
    throw ArgumentError.value(
      url,
      'url',
      'File URL host must be "localhost" or empty on ${Platform.operatingSystem}',
    );
  }
  return Uri.decodeComponent(pathname);
}

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

/// The file of [packageUri] (`package:sandbox_runtime/...`), the Dart stand-in
/// for `fileURLToPath(import.meta.url)`. Null when the program has no package
/// files: compiled into an application, where dart:isolate cannot resolve
/// package URIs and throws.
String? resolveOwnPackageFile(String packageUri) {
  final Uri? resolved;
  try {
    resolved = Isolate.resolvePackageUriSync(Uri.parse(packageUri));
  } on UnsupportedError {
    return null;
  }
  return resolved != null && resolved.scheme == 'file'
      ? resolved.toFilePath()
      : null;
}
