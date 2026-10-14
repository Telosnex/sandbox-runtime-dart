// Just enough of a TypeScript lexer for the port tools: string, template and
// regex literals, and bracket matching. No upstream counterpart.

bool isQuote(String c) => c == "'" || c == '"' || c == '`';

/// Index after the string literal starting at [i] (`'`, `"` or a template
/// with `${...}`).
int scanString(String t, int i) {
  // A Dart multi-line string, as _quoteKeys writes a multi-line template.
  for (final triple in const ["'''", '"""']) {
    if (!t.startsWith(triple, i)) continue;
    var j = i + 3;
    while (j < t.length) {
      if (t[j] == r'\') {
        j += 2;
        continue;
      }
      if (t.startsWith(triple, j)) return j + 3;
      j++;
    }
    throw const FormatException('unterminated');
  }
  final q = t[i];
  var j = i + 1;
  while (j < t.length) {
    if (t[j] == r'\') {
      j += 2;
      continue;
    }
    if (q == '`' && t.startsWith(r'${', j)) {
      var depth = 1;
      j += 2;
      while (depth > 0) {
        if (j >= t.length) throw const FormatException('unterminated');
        if (isQuote(t[j])) {
          j = scanString(t, j);
          continue;
        }
        if (isRegexStart(t, j)) {
          j = scanRegex(t, j);
          continue;
        }
        if (t[j] == '{') depth++;
        if (t[j] == '}') depth--;
        j++;
      }
      continue;
    }
    if (t[j] == q) return j + 1;
    j++;
  }
  throw const FormatException('unterminated');
}

final _valueEnd = RegExp('[\\w\$)\\]}\'"`]');
final _keywordBefore = RegExp(r'(?:^|[^\w$])(?:return|typeof|case|in|of)$');

/// Whether the `/` at [i] starts a regex literal: it is not a comment, and
/// it does not follow a value (a word, `)`, `]`, `}` or a quote), which
/// would make it a division. `return /x/` is a regex.
bool isRegexStart(String t, int i) {
  if (t[i] != '/' || i + 1 >= t.length) return false;
  if (t[i + 1] == '/' || t[i + 1] == '*') return false;
  var k = i - 1;
  while (k >= 0 &&
      (t[k] == ' ' || t[k] == '\t' || t[k] == '\n' || t[k] == '\r')) {
    k--;
  }
  if (k < 0) return true;
  final from = k >= 8 ? k - 8 : 0;
  if (_keywordBefore.hasMatch(t.substring(from, k + 1))) return true;
  return !_valueEnd.hasMatch(t[k]);
}

/// Index after the regex literal at [i] (its flags included).
int scanRegex(String t, int i) {
  var j = i + 1;
  var inClass = false;
  while (j < t.length) {
    final c = t[j];
    if (c == '\n') throw const FormatException('unterminated regex');
    if (c == r'\') {
      j += 2;
      continue;
    }
    if (c == '[') inClass = true;
    if (c == ']') inClass = false;
    if (c == '/' && !inClass) {
      j++;
      while (j < t.length && RegExp(r'[a-z]').hasMatch(t[j])) {
        j++;
      }
      return j;
    }
    j++;
  }
  throw const FormatException('unterminated regex');
}

/// A regex literal as a Dart `RegExp`: `/a'b/i` ->
/// `RegExp(r"a'b", caseSensitive: false)`. `g` and `y` have no Dart flag.
String dartRegExp(String literal) {
  final end = literal.lastIndexOf('/');
  final source = literal.substring(1, end);
  final flags = literal.substring(end + 1);
  final quoted = !source.contains("'")
      ? "r'$source'"
      : !source.contains('"')
      ? 'r"$source"'
      : "'${source.replaceAll(r'\', r'\\').replaceAll("'", r"\'").replaceAll(r'$', r'\$')}'";
  return 'RegExp(${[quoted, if (flags.contains('i')) 'caseSensitive: false', if (flags.contains('m')) 'multiLine: true', if (flags.contains('s')) 'dotAll: true', if (flags.contains('u') || flags.contains('v')) 'unicode: true'].join(', ')})';
}

const _pairs = {'(': ')', '[': ']', '{': '}'};

/// [t]`[i]` is `(`, `[` or `{`: the index after its match.
int matchClose(String t, int i) {
  final stack = [_pairs[t[i]]!];
  var j = i + 1;
  while (stack.isNotEmpty) {
    final c = t[j];
    if (isQuote(c)) {
      j = scanString(t, j);
      continue;
    }
    if (isRegexStart(t, j)) {
      j = scanRegex(t, j);
      continue;
    }
    if (t.startsWith('//', j)) {
      j = t.indexOf('\n', j);
      continue;
    }
    if (t.startsWith('/*', j)) {
      j = t.indexOf('*/', j) + 2;
      continue;
    }
    if (_pairs.containsKey(c)) {
      stack.add(_pairs[c]!);
    } else if (c == ')' || c == ']' || c == '}') {
      if (c != stack.last) {
        throw FormatException('unbalanced $c', t, j);
      }
      stack.removeLast();
    }
    j++;
  }
  return j;
}
