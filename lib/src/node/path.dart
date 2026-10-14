/// Node's `path` module (posix flavour) over package:path.
library;

import 'package:path/path.dart' as p;

/// `path.sep`.
const String sep = '/';

/// `path.delimiter`.
const String delimiter = ':';

String _join(List<String> parts) =>
    p.posix.joinAll(parts.where((x) => x.isNotEmpty));

/// `path.join(...parts)`; normalizes the result, '.' when empty.
String join(String a, [String? b, String? c, String? d]) {
  final r = _join([a, ?b, ?c, ?d]);
  return p.posix.normalize(r.isEmpty ? '.' : r);
}

/// `path.resolve(...parts)` against the process cwd.
String resolve(String a, [String? b, String? c, String? d]) {
  var r = '';
  for (final x in [a, ?b, ?c, ?d].reversed) {
    if (x.isEmpty) continue;
    r = r.isEmpty ? x : '$x/$r';
    if (x.startsWith('/')) break;
  }
  return p.posix
      .normalize(p.posix.absolute(r.isEmpty ? '.' : r))
      .replaceAllMapped(RegExp(r'(.)/$'), (m) => m[1]!);
}

String _dirname(String path) {
  // Node's lib/path.js posix.dirname.
  if (path.isEmpty) return '.';
  final hasRoot = path.codeUnitAt(0) == 0x2f;
  var end = -1;
  var matchedSlash = true;
  for (var i = path.length - 1; i >= 1; --i) {
    if (path.codeUnitAt(i) == 0x2f) {
      if (!matchedSlash) {
        end = i;
        break;
      }
    } else {
      matchedSlash = false;
    }
  }
  if (end == -1) return hasRoot ? '/' : '.';
  if (hasRoot && end == 1) return '//';
  return path.substring(0, end);
}

/// `path.dirname`. A variable so a test can replace it.
String Function(String path) dirname = _dirname;

bool _isAbsolute(String path) => p.posix.isAbsolute(path);

/// `path.isAbsolute`. A variable so a test can replace it.
bool Function(String path) isAbsolute = _isAbsolute;

/// `path.basename(path, [suffix])`.
String basename(String path, [String? suffix]) {
  final b = p.posix.basename(path);
  return suffix != null && b != suffix && b.endsWith(suffix)
      ? b.substring(0, b.length - suffix.length)
      : b;
}

/// `path.extname`.
String extname(String path) => p.posix.extension(path);

/// `path.relative(from, to)`.
String relative(String from, String to) =>
    p.posix.relative(resolve(to), from: resolve(from));

/// `path.normalize`.
String normalize(String path) => p.posix.normalize(path);
