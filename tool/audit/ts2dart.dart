// Rough first draft of a test port: TypeScript (bun:test) to Dart
// (package:test). No upstream counterpart; see tool/audit/README.md.
//
//   dart run tool/audit/ts2dart.dart <upstream test .ts> > test/x_test.dart
//
// It rewrites text, it does not parse TypeScript: the output is a draft that
// keeps upstream's statements, order and comments, and still needs hand
// fixes (types, local functions, spies, anything it does not know). Then run
// `dart analyze`, and `dart test test/port` for comments and titles.
//
// Handles: the `Ported from` header and imports (upstream src/ and test/
// files map to their Dart names; others become comments), describe/test,
// `it`, and the `.each` (a for loop), `.if`/`.skipIf`/`.skip`/`.todo`
// (a skip) and `.only` forms, expect matchers, object
// literal keys, `.find`, const/let, ===, for...of, and semicolons. An
// expect matcher it does not know becomes `TODO_<name>(...)`, which the
// analyzer reports.
import 'dart:io';

import 'package:path/path.dart' as p;

import 'src/lex.dart';

void main(List<String> args) {
  if (args.length != 1) {
    stderr.writeln('usage: dart run tool/audit/ts2dart.dart <file.test.ts>');
    exit(64);
  }
  final file = p.absolute(args.single);
  // Upstream's root: the nearest directory up from the file with a
  // package.json.
  var root = p.dirname(file);
  while (!File(p.join(root, 'package.json')).existsSync()) {
    final parent = p.dirname(root);
    if (parent == root) {
      stderr.writeln('$file is not inside an npm package (upstream checkout)');
      exit(66);
    }
    root = parent;
  }
  stdout.write(
    translateTestFile(
      File(file).readAsStringSync(),
      upstreamPath: p.relative(file, from: root),
      upstreamCommit: _commit(root),
    ),
  );
}

String _commit(String upstream) {
  try {
    final r = Process.runSync('git', [
      '-C',
      upstream,
      'rev-parse',
      '--short=7',
      'HEAD',
    ]);
    if (r.exitCode == 0) return (r.stdout as String).trim();
  } on ProcessException {
    // No git.
  }
  return 'UNKNOWN';
}

/// [source] translated, with the header for [upstreamPath], imports, and
/// top-level describes wrapped in `main`.
String translateTestFile(
  String source, {
  required String upstreamPath,
  required String upstreamCommit,
}) {
  final (imports, rest) = _takeImports(source, upstreamPath);
  final t = translate(rest);
  final lines = t.split('\n');
  final first = lines.indexWhere((l) => l.startsWith('group('));
  final top = first < 0 ? lines : lines.sublist(0, first);
  final body = first < 0 ? <String>[] : lines.sublist(first);
  final out = StringBuffer()
    ..writeln('// Ported from sandbox-runtime $upstreamPath @ $upstreamCommit.')
    ..writeln(t.contains('jsonEncode(') ? "import 'dart:convert';\n" : '')
    ..writeln("import 'package:test/test.dart';");
  for (final i in imports) {
    out.writeln(i);
  }
  out
    ..writeln(
      top.join('\n').trim().isEmpty ? '' : '\n${top.join('\n').trim()}\n',
    )
    ..writeln('void main() {');
  for (final l in body) {
    out.writeln(l.trim().isEmpty ? '' : '  $l');
  }
  out.writeln('}');
  return out.toString().replaceAll(RegExp(r'\n{3,}'), '\n\n');
}

// ---------------------------------------------------------------------------
// Imports

final _importLine = RegExp(
  r"^import\s+(?:type\s+)?(?:[\s\S]*?)\s+from\s+'([^']+)'\s*;?[ \t]*$",
  multiLine: true,
);

String _snake(String segment) =>
    segment.replaceAll('-', '_').replaceAll('.', '_');

/// Upstream's import declarations as Dart imports, and the source without
/// them. Relative imports of upstream src/ files become package imports;
/// of test/ files, relative imports of their Dart names. Others (node:,
/// bun:test, packages) are kept as comments for the porter.
(List<String>, String) _takeImports(String source, String upstreamPath) {
  final dartImports = <String>[];
  final notes = <String>[];
  final dir = p.posix.dirname(upstreamPath);
  final rest = source.replaceAllMapped(_importLine, (m) {
    final spec = m[1]!;
    // `import * as name from` keeps its prefix.
    final namespace = RegExp(r'^import\s+\*\s+as\s+(\w+)').firstMatch(m[0]!);
    final prefix = namespace == null ? '' : ' as ${namespace[1]}';
    if (spec.startsWith('.')) {
      final target = p.posix.normalize(p.posix.join(dir, spec));
      final parts = p.posix.split(p.posix.withoutExtension(target));
      final snake = [
        ...parts.take(parts.length - 1).map(_snake),
        _snake(parts.last),
      ];
      if (parts.first == 'src') {
        dartImports.add(
          "import 'package:sandbox_runtime/src/${snake.skip(1).join('/')}.dart'$prefix;",
        );
        return '';
      }
      if (parts.first == 'test') {
        final from = p.posix.split(dir).map(_snake).join('/');
        final rel = p.posix.relative(snake.join('/'), from: from);
        dartImports.add("import '$rel.dart'$prefix;");
        return '';
      }
    }
    if (spec != 'bun:test') {
      notes.add('// upstream: ${m[0]!.replaceAll(RegExp(r'\s+'), ' ').trim()}');
    }
    return '';
  });
  return (
    [
      ...{...dartImports},
      if (notes.isNotEmpty) '',
      ...notes,
    ],
    rest,
  );
}

// ---------------------------------------------------------------------------
// Lexing helpers

/// The last [n] characters of the text in [out], after trailing whitespace.
String _tail(List<String> out, int n) {
  final b = StringBuffer();
  final chunks = <String>[];
  var size = 0;
  var trimming = true;
  for (var k = out.length - 1; k >= 0 && size < n; k--) {
    var s = out[k];
    if (trimming) {
      s = s.trimRight();
      if (s.isEmpty) continue;
      trimming = false;
    }
    chunks.add(s);
    size += s.length;
  }
  for (final s in chunks.reversed) {
    b.write(s);
  }
  final all = b.toString();
  return all.length <= n ? all : all.substring(all.length - n);
}

/// The text in [out] after its last newline.
String _lastLine(List<String> out) {
  final chunks = <String>[];
  for (var k = out.length - 1; k >= 0; k--) {
    final nl = out[k].lastIndexOf('\n');
    if (nl >= 0) {
      chunks.add(out[k].substring(nl + 1));
      break;
    }
    chunks.add(out[k]);
  }
  return chunks.reversed.join();
}

// ---------------------------------------------------------------------------
// Passes

/// `x.find(f)` -> `x.where(f).firstOrNull`.
String _convFind(String t) {
  final out = StringBuffer();
  var i = 0;
  while (true) {
    final k = t.indexOf('.find(', i);
    if (k < 0) {
      out.write(t.substring(i));
      break;
    }
    final e = matchClose(t, k + 5);
    out
      ..write(t.substring(i, k))
      ..write('.where(${_convFind(t.substring(k + 6, e - 1))}).firstOrNull');
    i = e;
  }
  return out.toString();
}

const _matchers = {
  'toBe': '{a}',
  'toEqual': '{a}',
  'toStrictEqual': '{a}',
  'toContain': 'contains({a})',
  'toContainEqual': 'contains({a})',
  'toBeDefined': 'isNotNull',
  'toBeUndefined': 'isNull',
  'toBeNull': 'isNull',
  'toHaveLength': 'hasLength({a})',
  'toMatch': 'matches({a})',
  'toBeGreaterThan': 'greaterThan({a})',
  'toBeGreaterThanOrEqual': 'greaterThanOrEqualTo({a})',
  'toBeLessThan': 'lessThan({a})',
  'toBeLessThanOrEqual': 'lessThanOrEqualTo({a})',
  'toBeInstanceOf': 'isA<{a}>()',
  'toThrow': 'throwsA(anything)',
  'toBeTruthy': 'isTrue',
  'toBeFalsy': 'isFalse',
};

String _trimComma(String s) {
  s = s.trimRight();
  return s.endsWith(',') ? s.substring(0, s.length - 1) : s;
}

/// `expect(x).[not.]matcher(y)` -> `expect(x, [isNot(]matcher[)])`.
String _convExpect(String t) {
  final out = StringBuffer();
  var i = 0;
  while (true) {
    final k = t.indexOf('expect(', i);
    if (k < 0) {
      out.write(t.substring(i));
      break;
    }
    if (k > 0 && RegExp(r'[A-Za-z0-9_]').hasMatch(t[k - 1])) {
      out.write(t.substring(i, k + 7));
      i = k + 7;
      continue;
    }
    out.write(t.substring(i, k));
    final e = matchClose(t, k + 6);
    final arg = _trimComma(_convExpect(t.substring(k + 7, e - 1)));
    final m = RegExp(r'^\s*\.(not\.)?(\w+)\(').firstMatch(t.substring(e));
    if (m == null) {
      out.write('expect($arg)');
      i = e;
      continue;
    }
    final name = m[2]!;
    final open = e + m.end - 1;
    final q = matchClose(t, open);
    final a = _trimComma(_convExpect(t.substring(open + 1, q - 1)).trim());
    String matcher;
    if (name == 'toBe' && (a == 'true' || a == 'false')) {
      matcher = a == 'true' ? 'isTrue' : 'isFalse';
    } else if (name == 'toBe' && a == 'undefined') {
      matcher = 'isNull';
    } else {
      matcher = (_matchers[name] ?? 'TODO_$name({a})').replaceAll('{a}', a);
    }
    if (m[1] != null) matcher = 'isNot($matcher)';
    out.write('expect(${arg.trim()}, $matcher)');
    i = q;
  }
  return out.toString();
}

final _identifier = RegExp(r'^([A-Za-z_$][\w$]*)(\s*):');
final _shorthand = RegExp(r'^([A-Za-z_$][\w$]*)(\s*)(?=[,}\n])');
const _objectBefore = {'=', ':', '(', ',', '[', '?', ''};

/// Object-literal keys quoted (`{a: 1, b}` -> `{'a': 1, 'b': b}`), and
/// template literals as Dart strings.
String _quoteKeys(String t) {
  final out = <String>[];
  final stack = <String>[];
  var i = 0;
  while (i < t.length) {
    final c = t[i];
    if (isQuote(c)) {
      final j = scanString(t, i);
      var s = t.substring(i, j);
      if (c == '`') {
        final inner = s.substring(1, s.length - 1);
        s = inner.contains('\n')
            ? "'''$inner'''"
            : "'${inner.replaceAll("'", r"\'")}'";
      }
      out.add(s);
      i = j;
      continue;
    }
    if (isRegexStart(t, i)) {
      final j = scanRegex(t, i);
      out.add(dartRegExp(t.substring(i, j)));
      i = j;
      continue;
    }
    if (t.startsWith('//', i)) {
      final j = t.indexOf('\n', i);
      final end = j < 0 ? t.length : j;
      out.add(t.substring(i, end));
      i = end;
      continue;
    }
    if (t.startsWith('/*', i)) {
      final j = t.indexOf('*/', i) + 2;
      out.add(t.substring(i, j));
      i = j;
      continue;
    }
    if (c == '(' || c == '[' || c == '{') {
      var kind = c;
      if (c == '{') {
        final before = _tail(out, 6);
        final prev = before.isEmpty ? '' : before[before.length - 1];
        kind = _objectBefore.contains(prev) || before.endsWith('return')
            ? 'obj'
            : 'block';
      }
      stack.add(kind);
      out.add(c);
      i++;
      continue;
    }
    if (c == ')' || c == ']' || c == '}') {
      if (stack.isNotEmpty) stack.removeLast();
      out.add(c);
      i++;
      continue;
    }
    if (stack.isNotEmpty && stack.last == 'obj') {
      final before = _tail(out, 1);
      if (before == '{' || before == ',') {
        final rest = t.substring(i, i + 200 > t.length ? t.length : i + 200);
        final key = _identifier.firstMatch(rest);
        if (key != null) {
          out.add("'${key[1]}'${key[2]}:");
          i += key.end;
          continue;
        }
        final short = _shorthand.firstMatch(rest);
        if (short != null &&
            !const {'true', 'false', 'null', 'undefined'}.contains(short[1])) {
          out.add("'${short[1]}': ${short[1]}${short[2]}");
          i += short.end;
          continue;
        }
      }
    }
    out.add(c);
    i++;
  }
  return out.join();
}

/// A line split into its code and a trailing `//` comment (with a leading
/// space), honoring strings.
(String, String) _splitComment(String l) {
  var i = 0;
  while (i < l.length) {
    final c = l[i];
    if (c == "'" || c == '"') {
      try {
        i = scanString(l, i);
      } on FormatException {
        return (l, '');
      }
      continue;
    }
    if (l.startsWith('//', i)) {
      return (l.substring(0, i).trimRight(), ' ${l.substring(i)}');
    }
    i++;
  }
  return (l, '');
}

const _noSemicolonAfter = [
  ';',
  ',',
  '{',
  '(',
  '[',
  '=',
  '?',
  ':',
  '&&',
  '||',
  '+',
];
const _continuesWith = ['.', '?', ':', '&&', '||', '+', ')', ']', ','];

/// Statement-ending semicolons, by line: a line ends a statement unless it
/// ends in an operator or opener, or the next code line continues it.
String _semicolons(String t) {
  final lines = t.split('\n');
  final split = lines.map(_splitComment).toList();
  final out = <String>[];
  // The delimiter of the multi-line string a line is inside, if any: those
  // lines are string content, and a line that opens one ends no statement.
  String? inTriple;
  for (var idx = 0; idx < lines.length; idx++) {
    if (inTriple != null) {
      var line = lines[idx];
      if ((inTriple.allMatches(line).length).isOdd) {
        inTriple = null;
        // The string ends here: end the statement too, by the same rule.
        final next = _nextCode(split, idx);
        if ((line.trimRight().endsWith("'''") ||
                line.trimRight().endsWith('"""')) &&
            !_continuesWith.any(next.startsWith)) {
          line = '${line.trimRight()};';
        }
      }
      out.add(line);
      continue;
    }
    final opens = [
      for (final d in const ["'''", '"""'])
        if (d.allMatches(lines[idx]).length.isOdd) d,
    ];
    if (opens.isNotEmpty) {
      inTriple = opens.first;
      out.add(lines[idx]);
      continue;
    }
    final s0 = lines[idx].trimRight();
    var (s, comment) = _splitComment(s0);
    if (s.trim().isEmpty) {
      out.add(s0);
      continue;
    }
    final next = _nextCode(split, idx);
    final code = s.trim();
    if (!code.startsWith('//') &&
        !code.startsWith('*') &&
        !code.startsWith('/*') &&
        !_noSemicolonAfter.any(s.endsWith) &&
        !_continuesWith.any(next.startsWith) &&
        !RegExp(r'^(if|else|for|while)\b').hasMatch(code) &&
        !code.endsWith('=>')) {
      s += ';';
    }
    out.add(s + comment);
  }
  return out.join('\n');
}

/// The code of the first line after [idx] that has any.
String _nextCode(List<(String, String)> split, int idx) {
  for (var k = idx + 1; k < split.length; k++) {
    final code = split[k].$1.trim();
    if (code.isNotEmpty) return code;
  }
  return '';
}

/// `};` at the end of a line that closes a block (after `)` or `else`), not
/// an object literal, -> `}`.
String _fixBlockSemicolons(String t) {
  final out = <String>[];
  final stack = <String>[];
  var i = 0;
  while (i < t.length) {
    final c = t[i];
    if (c == "'" || c == '"') {
      int j;
      try {
        j = scanString(t, i);
      } on FormatException {
        j = i + 1;
      }
      out.add(t.substring(i, j));
      i = j;
      continue;
    }
    if (t.startsWith('//', i)) {
      final j = t.indexOf('\n', i);
      final end = j < 0 ? t.length : j;
      out.add(t.substring(i, end));
      i = end;
      continue;
    }
    if (c == '{') {
      final before = out
          .sublist(out.length > 40 ? out.length - 40 : 0)
          .join()
          .trimRight();
      stack.add(
        before.endsWith(')') || before.endsWith('else') ? 'block' : 'obj',
      );
    }
    if (c == '}') {
      final kind = stack.isEmpty ? 'obj' : stack.removeLast();
      if (kind == 'block' &&
          t.startsWith('};', i) &&
          (i + 2 >= t.length || t[i + 2] == '\n')) {
        out.add('}');
        i += 2;
        continue;
      }
    }
    out.add(c);
    i++;
  }
  return out.join();
}

/// Top-level comma-separated arguments.
List<String> _splitArgs(String a) {
  final parts = <String>[];
  var depth = 0;
  final cur = StringBuffer();
  var i = 0;
  while (i < a.length) {
    final c = a[i];
    if (isQuote(c)) {
      final j = scanString(a, i);
      cur.write(a.substring(i, j));
      i = j;
      continue;
    }
    if (a.startsWith('/*', i)) {
      final j = a.indexOf('*/', i + 2);
      final end = j < 0 ? a.length : j + 2;
      cur.write(a.substring(i, end));
      i = end;
      continue;
    }
    if (isRegexStart(a, i)) {
      final j = scanRegex(a, i);
      cur.write(a.substring(i, j));
      i = j;
      continue;
    }
    if (a.startsWith('//', i)) {
      final j = a.indexOf('\n', i);
      final end = j < 0 ? a.length : j;
      cur.write(a.substring(i, end));
      i = end;
      continue;
    }
    if (c == '(' || c == '[' || c == '{') depth++;
    if (c == ')' || c == ']' || c == '}') depth--;
    if (c == ',' && depth == 0) {
      parts.add(cur.toString());
      cur.clear();
      i++;
      continue;
    }
    cur.write(c);
    i++;
  }
  if (cur.toString().trim().isNotEmpty) parts.add(cur.toString());
  return parts;
}

/// bun:test's modifier forms as package:test calls, for `describe`
/// (-> `group`), `it` and `test` (-> `test`):
///
/// - `.if(cond)(title, fn)` -> `skip: (cond) ? false : 'requires ...'`
/// - `.skipIf(cond)(title, fn)` -> `skip: (cond) ? 'skipped when ...' : false`
/// - `.each(rows)(title, (a, b) => ...)` -> a for loop over the rows
/// - `.skip(title, fn)`, `.todo(title)` -> a skip; `.only`, `.concurrent`,
///   `.serial` -> the plain call.
String _convModifiers(String t) {
  final out = <String>[];
  var i = 0;
  final call = RegExp(
    r'(?<![\w.$])(describe|it|test)\.(each|if|skipIf|skip|todo|only|concurrent|serial)\(',
  );
  while (true) {
    final m = call.firstMatch(t.substring(i));
    if (m == null) {
      out.add(t.substring(i));
      break;
    }
    final k = i + m.start;
    out.add(t.substring(i, k));
    final kind = m[1] == 'describe' ? 'group' : 'test';
    final modifier = m[2]!;
    final open = k + m[1]!.length + 1 + modifier.length;
    final e1 = matchClose(t, open);
    final ind = _lastLine(out);
    String unquoted(String s) => s.replaceAll(RegExp('[\'"`\\\\\$]'), '');
    String? skipFor(String modifier, String? cond) => switch (modifier) {
      'if' => "($cond) ? false : 'requires ${unquoted(cond!)}'",
      'skipIf' => "($cond) ? 'skipped when ${unquoted(cond!)}' : false",
      'skip' => "'skipped upstream'",
      'todo' => "'todo upstream'",
      _ => null,
    };
    final String title, fn;
    String? first;
    int end;
    if (const {'each', 'if', 'skipIf'}.contains(modifier)) {
      first = t.substring(open + 1, e1 - 1).trim();
      // `it.if(cond).each(rows)(title, fn)`: a loop of skippable tests.
      final chained = RegExp(r'^\.each\(').firstMatch(t.substring(e1));
      if (modifier != 'each' && chained != null) {
        final rowsOpen = e1 + chained.end - 1;
        final rowsEnd = matchClose(t, rowsOpen);
        final callEnd = matchClose(t, rowsEnd);
        final args = _splitArgs(t.substring(rowsEnd + 1, callEnd - 1));
        out.add(
          _convModifiers(
            _eachLoop(
              kind,
              t.substring(rowsOpen + 1, rowsEnd - 1).trim(),
              args[0].trim(),
              args[1].trim(),
              ind,
              skip: skipFor(modifier, first),
              extra: _extraArgs(args, '$ind    '),
            ),
          ),
        );
        i = callEnd;
        if (t.startsWith(';', i)) i++;
        continue;
      }
      if (e1 >= t.length || t[e1] != '(') {
        // An alias such as `const itOnLinux = it.if(isLinux)`: a function
        // that declares a skippable test.
        final skip = skipFor(modifier, first);
        out.add(
          skip == null
              ? '/* TODO(ts2dart): $kind.each without a call */'
              : '(Object? title, dynamic Function() body) =>\n'
                    '$ind    $kind(title, body, skip: $skip)',
        );
        i = e1;
        continue;
      }
      end = matchClose(t, e1);
    } else {
      end = e1;
    }
    final args = _splitArgs(
      first == null
          ? t.substring(open + 1, e1 - 1)
          : t.substring(e1 + 1, end - 1),
    );
    title = args[0].trim();
    fn = args.length > 1 ? args[1].trim() : '() {}';
    String res;
    var keepSemicolon = true;
    if (modifier == 'each') {
      keepSemicolon = false;
      res = _eachLoop(
        kind,
        first!,
        title,
        fn,
        ind,
        extra: _extraArgs(args, '$ind    '),
      );
    } else {
      final skip = skipFor(modifier, first);
      res =
          '$kind(\n$ind  $title,\n$ind  $fn,\n'
          '${skip == null ? '' : '$ind  skip: $skip,\n'}'
          '${_extraArgs(args, '$ind  ')}$ind)';
    }
    out.add(_convModifiers(res));
    i = end;
    if (!keepSemicolon && t.startsWith(';', i)) i++;
  }
  return out.join();
}

/// `.each(rows)(title, (a, b) => body)` as a for loop over [rows].
String _eachLoop(
  String kind,
  String rows,
  String title,
  String fn,
  String ind, {
  String? skip,
  String extra = '',
}) {
  final fm = RegExp(
    r'^(async\s+)?(?:\(([^()]*)\)|([A-Za-z_$][\w$]*))\s*(?::[^=]+)?=>\s*([\s\S]*)$',
  ).firstMatch(fn);
  if (fm == null) throw FormatException('.each callback', fn);
  final rawParams = (fm[2] ?? fm[3]!).trim();
  final isAsync = fm[1] != null;
  final body = fm[4]!.trim();
  String pattern;
  List<String> params;
  var note = '';
  if (rawParams.startsWith('{') || rawParams.startsWith('[')) {
    // A destructured row: bind the whole row and leave the rest to the
    // porter.
    pattern = 'row';
    params = ['row'];
    note = '$ind  // TODO(ts2dart): destructure $rawParams from row\n';
  } else {
    // Parameter names, without their TS types.
    params = rawParams
        .split(',')
        .map((x) => x.split(':').first.trim())
        .where((x) => x.isNotEmpty)
        .toList();
    pattern = params.length > 1 || RegExp(r'^\[\s*\[').hasMatch(rows)
        ? '[${params.join(', ')}]'
        : params.isEmpty
        ? '_'
        : params.first;
  }
  // bun's printf placeholders, one per parameter in order.
  var dartTitle = title;
  for (final v in params) {
    dartTitle = dartTitle.replaceFirstMapped(
      RegExp(r'%[spdifjo#]'),
      (m) => m[0] == '%j' ? '\${jsonEncode($v)}' : '\$$v',
    );
  }
  final a = isAsync ? 'async ' : '';
  final fnb = body.startsWith('{') ? '() $a$body' : '() $a=> $body';
  final skipArg = skip == null ? '' : '$ind    skip: $skip,\n';
  return 'for (final $pattern in $rows) {\n$note$ind  $kind(\n$ind    $dartTitle,\n'
      '$ind    $fnb,\n$skipArg$extra$ind  );\n$ind}';
}

/// A test's arguments after its function, as named arguments: a number of
/// milliseconds is a `timeout:`; anything else is left for the porter.
/// Comments on them are kept.
String _extraArgs(List<String> args, String ind) {
  final out = StringBuffer();
  for (final raw in args.skip(2)) {
    final lines = raw.trim().split('\n').map((l) => l.trim()).toList();
    final value = lines.where((l) => !l.startsWith('//')).join(' ').trim();
    for (final l in lines.where((l) => l.startsWith('//'))) {
      out.writeln('$ind$l');
    }
    if (value.isEmpty) continue;
    out.writeln(
      RegExp(r'^[\d_]+$').hasMatch(value)
          ? '${ind}timeout: Timeout(Duration(milliseconds: $value)),'
          : '$ind/* TODO(ts2dart): test option */ $value,',
    );
  }
  return out.toString();
}

/// `name.key` -> `name['key']!` for each `name` bound to an object literal
/// (`const name = {`): in Dart the literal is a Map. Calls (`name.key(`)
/// are left alone, and so is shadowing.
String _objectMemberReads(String t) {
  final names = {
    for (final m in RegExp(
      r'\b(?:const|let)\s+(\w+)\s*(?::[^=\n]+)?=\s*\{',
    ).allMatches(t))
      m[1]!,
  };
  if (names.isEmpty) return t;
  final read = RegExp(
    '(?:(?<=\\.\\.\\.)|(?<![\\w.\$]))'
    '(${names.map(RegExp.escape).join('|')})'
    '\\.([A-Za-z_]\\w*)\\b(?!\\s*\\()',
  );
  // Not in strings or comments: `opts.timeout` in prose stays prose.
  return _inCode(
    t,
    (code) => code.replaceAllMapped(read, (m) => "${m[1]}['${m[2]}']!"),
  );
}

/// [rewrite] applied to the code of [t] only, not to its strings (template
/// literals whole, interpolations included), regex literals and comments,
/// so titles and upstream comments keep their words.
String _inCode(String t, String Function(String code) rewrite) {
  final out = StringBuffer();
  final code = StringBuffer();
  void flush() {
    out.write(rewrite(code.toString()));
    code.clear();
  }

  var i = 0;
  while (i < t.length) {
    final c = t[i];
    int? end;
    if (isQuote(c) || isRegexStart(t, i)) {
      try {
        end = isQuote(c) ? scanString(t, i) : scanRegex(t, i);
      } on FormatException {
        end = null;
      }
    } else if (t.startsWith('//', i)) {
      final j = t.indexOf('\n', i);
      end = j < 0 ? t.length : j;
    } else if (t.startsWith('/*', i)) {
      final j = t.indexOf('*/', i + 2);
      end = j < 0 ? t.length : j + 2;
    }
    if (end == null) {
      code.write(c);
      i++;
      continue;
    }
    flush();
    out.write(t.substring(i, end));
    i = end;
  }
  flush();
  return out.toString();
}

/// Translate the body of a bun:test file (no imports).
String translate(String t) {
  t = _convFind(t);
  t = _convExpect(t);
  // On the TypeScript: its lexer knows TS strings and regex literals.
  t = _convModifiers(t);
  t = t.replaceAllMapped(
    RegExp(r'(?<=[(,\s])([A-Za-z_]\w*) =>'),
    (m) => '(${m[1]}) =>',
  );
  t = t.replaceAll('?.[', '?[');
  t = _objectMemberReads(t);
  t = _quoteKeys(t);
  t = t.replaceAllMapped(
    RegExp(r'\bdescribe\((.*?), \(\) => \{'),
    (m) => 'group(${m[1]}, () {',
  );
  t = t.replaceAll('() => {', '() {');
  t = t.replaceAllMapped(
    RegExp(r'\bconst (\w+)\s*='),
    (m) => 'final ${m[1]} =',
  );
  t = t.replaceAllMapped(RegExp(r'\blet (\w+)\s*='), (m) => 'var ${m[1]} =');
  // After _quoteKeys, so template literals are plain Dart strings here.
  t = _inCode(
    t,
    (code) => code
        .replaceAll(RegExp(r'\bundefined\b'), 'null')
        .replaceAll(RegExp(r' as const\b'), '')
        .replaceAll('===', '==')
        .replaceAll('!==', '!='),
  );
  t = t.replaceAll('.slice(', '.sublist(');
  t = _inCode(
    t,
    (code) => code.replaceAll(RegExp(r'(?<![\w.$])it(?=\(|\.)'), 'test'),
  );
  t = t.replaceAllMapped(
    RegExp(r'for \(const (\w+) of '),
    (m) => 'for (final ${m[1]} in ',
  );
  t = _semicolons(t);
  t = _fixBlockSemicolons(t);
  return t.replaceAll('});;', '});');
}
