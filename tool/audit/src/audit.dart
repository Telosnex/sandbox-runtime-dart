// Port audit: checks that ported files keep upstream's comments, test
// titles and file mapping. No upstream counterpart; see tool/audit/README.md.
import 'dart:convert';
import 'dart:io';

import 'package:path/path.dart' as p;

import 'lex.dart';

/// This repo and the upstream checkout it is ported from.
class Roots {
  Roots(this.repo, this.upstream);

  final String repo;
  final String upstream;

  /// The repo is the nearest directory up from the current one with this
  /// package's pubspec; upstream is `$SRT_UPSTREAM`, else its sibling
  /// `sandbox-runtime`.
  factory Roots.find() {
    var dir = p.absolute(Directory.current.path);
    while (true) {
      final pubspec = File(p.join(dir, 'pubspec.yaml'));
      if (pubspec.existsSync() &&
          pubspec.readAsStringSync().startsWith('name: sandbox_runtime')) {
        break;
      }
      final parent = p.dirname(dir);
      if (parent == dir) {
        throw StateError('not inside the sandbox_runtime package');
      }
      dir = parent;
    }
    final upstream =
        Platform.environment['SRT_UPSTREAM'] ??
        p.join(p.dirname(dir), 'sandbox-runtime');
    return Roots(dir, upstream);
  }

  bool get hasUpstream =>
      Directory(p.join(upstream, 'src')).existsSync() &&
      Directory(p.join(upstream, 'test')).existsSync();

  String rel(String path) => p.relative(path, from: repo);
}

/// `*.dart` under [dir], skipping hidden entries, sorted.
List<String> _dartFiles(String dir, {bool recursive = true}) {
  final d = Directory(dir);
  if (!d.existsSync()) return [];
  return d
      .listSync(recursive: recursive)
      .whereType<File>()
      .map((f) => f.path)
      .where((f) => f.endsWith('.dart'))
      .where(
        (f) => !p.split(p.relative(f, from: dir)).any((s) => s.startsWith('.')),
      )
      .toList()
    ..sort();
}

/// Ported files: lib/src, test and tool (not tool's subdirectories).
List<String> portedFileCandidates(Roots roots) => [
  ..._dartFiles(p.join(roots.repo, 'lib', 'src')),
  ..._dartFiles(p.join(roots.repo, 'test')),
  ..._dartFiles(p.join(roots.repo, 'tool'), recursive: false),
]..sort();

List<String> _lines(String text) => const LineSplitter().convert(text);

String _head(String text, int lines) => _lines(text).take(lines).join('\n');

// ---------------------------------------------------------------------------
// Comments

final _anyHeader = RegExp(
  r'(?:Ported from sandbox-runtime|STUB: pending port of|PARTIAL:.*?of(?: the rest of)?)\s+(\S+\.(?:ts|mjs))\s+@',
);

/// The text of every comment in TypeScript source [t], one entry per line of
/// a block comment. Skips string, template and regex literals.
List<String> tsComments(String t) {
  final out = <String>[];
  var i = 0;
  final n = t.length;
  while (i < n) {
    final c = t[i];
    if (t.startsWith('//', i)) {
      var j = t.indexOf('\n', i);
      if (j < 0) j = n;
      out.add(t.substring(i + 2, j));
      i = j;
      continue;
    }
    if (t.startsWith('/*', i)) {
      var j = t.indexOf('*/', i + 2);
      if (j < 0) j = n;
      out.addAll(t.substring(i + 2, j).split('\n'));
      i = j + 2;
      continue;
    }
    if (isQuote(c) || isRegexStart(t, i)) {
      try {
        i = isQuote(c) ? scanString(t, i) : scanRegex(t, i);
      } on FormatException {
        i++; // Broken source, or not a literal after all: read on.
      }
      continue;
    }
    i++;
  }
  return out;
}

/// A comment line with markup and comment syntax removed, so the same words
/// match in TypeScript and Dart.
String normalizeComment(String s) {
  s = s.trim();
  s = s.replaceAllMapped(
    RegExp(r'\{@link\s+([^}\s]+)\s*\}'),
    (m) => '[${m[1]}]',
  );
  s = s.replaceAll(r'**\/', '**/').replaceAll(r'*\/', '*/');
  s = s.replaceAll('`', '');
  s = s.replaceAllMapped(RegExp(r'\[([A-Za-z0-9_.]+)\]'), (m) => m[1]!);
  s = s.replaceFirst(RegExp(r'^[/*!\s]+'), '');
  return s.replaceAll(RegExp(r'\s+'), ' ').trim();
}

/// All of a Dart file's text, comments first per line, normalized: an
/// upstream comment may survive as a comment or inside a string.
String _dartSearchText(String t) {
  final parts = <String>[];
  for (final line in t.split('\n')) {
    final m = RegExp(r'//+(.*)$').firstMatch(line);
    if (m != null) parts.add(m[1]!);
    parts.add(line);
  }
  return parts.map(normalizeComment).join(' ').replaceAll(RegExp(r'\s+'), ' ');
}

class CommentReport {
  CommentReport(this.file, this.upstream, this.total, this.missing);

  /// Repo-relative path of the Dart file.
  final String file;

  /// Upstream-relative path it is ported from.
  final String upstream;
  final int total;
  final List<String> missing;
}

/// For each ported file: the upstream comment lines (12+ characters, not
/// lint directives) that do not appear in it.
List<CommentReport> commentReports(Roots roots) {
  final reports = <CommentReport>[];
  for (final f in portedFileCandidates(roots)) {
    final t = File(f).readAsStringSync();
    final m = _anyHeader.firstMatch(_head(t, 6));
    if (m == null) continue;
    final up = File(p.join(roots.upstream, m[1]!));
    if (!up.existsSync()) continue;
    final wanted = tsComments(up.readAsStringSync())
        .map(normalizeComment)
        .where(
          (x) =>
              x.length >= 12 &&
              !x.startsWith('eslint') &&
              !x.startsWith('@ts-') &&
              !x.startsWith('biome-ignore'),
        )
        .toList();
    final text = _dartSearchText(t);
    reports.add(
      CommentReport(
        roots.rel(f),
        m[1]!,
        wanted.length,
        wanted.where((x) => !text.contains(x)).toList(),
      ),
    );
  }
  return reports;
}

// ---------------------------------------------------------------------------
// Titles

final _portedHeader = RegExp(
  r'Ported from sandbox-runtime\s+(\S+\.(?:ts|mjs))\s+@',
);

const _ws = {' ', '\t', '\n', '\r'};

/// The string literal at [i] (after whitespace), with `+`-joined and
/// (Dart) adjacent literals joined; escapes are kept as written.
String? _literalAt(String t, int i) {
  final parts = <String>[];
  while (true) {
    while (i < t.length && _ws.contains(t[i])) {
      i++;
    }
    if (i >= t.length || !"'\"`".contains(t[i])) break;
    final q = t[i];
    var j = i + 1;
    final s = StringBuffer();
    while (j < t.length && t[j] != q) {
      if (t[j] == r'\') {
        s.write(t.substring(j, j + 2 > t.length ? t.length : j + 2));
        j += 2;
        continue;
      }
      s.write(t[j]);
      j++;
    }
    parts.add(s.toString());
    i = j + 1;
    var k = i;
    while (k < t.length && _ws.contains(t[k])) {
      k++;
    }
    if (k < t.length && t[k] == '+') {
      i = k + 1;
      continue;
    }
    if (k < t.length && (t[k] == "'" || t[k] == '"')) {
      i = k;
      continue;
    }
    break;
  }
  return parts.isEmpty ? null : parts.join();
}

/// Titles of `describe`/`it`/`test` (TS) or `group`/`test` (Dart) calls,
/// in source order, including `.skip`/`.if(...)`/`.each(...)` forms.
List<String> testTitles(String t, List<String> declared) {
  // `const onLinux = it.if(isLinux)`: calls of the alias are tests too.
  final kinds = [
    ...declared,
    for (final m in RegExp(
      '(?:const|let|final)\\s+(\\w+)\\s*=\\s*(?:[^;\\n=]*\\?\\s*)?(?:${declared.join('|')})(?:\\.|\\s*(?:\\n|;|:|\$))',
    ).allMatches(t))
      m[1]!,
  ];
  final call = RegExp('(?<![\\w.\$])(?:${kinds.join('|')})(?=[.(\\s])');
  final modifier = RegExp(
    r'\.(skip|skipIf|if|only|failing|todo|each|concurrent|serial)\b',
  );
  final titles = <String>[];
  for (final m in call.allMatches(t)) {
    var i = m.end;
    try {
      // `.if(cond)`, `.each(rows)`, `.only`...: step over each, and over
      // the arguments of those that take their own, however they nest.
      while (true) {
        final mod = modifier.matchAsPrefix(t, i);
        if (mod == null) break;
        i = mod.end;
        if (mod[1] == 'each' && i < t.length && t[i] == '<') {
          var depth = 0;
          while (i < t.length) {
            if (t[i] == '<') depth++;
            if (t[i] == '>' && t[i - 1] != '=' && --depth == 0) {
              i++;
              break;
            }
            i++;
          }
        }
        if (const {'if', 'skipIf', 'each'}.contains(mod[1]) &&
            i < t.length &&
            t[i] == '(') {
          i = matchClose(t, i);
        }
      }
    } on FormatException {
      continue;
    }
    while (i < t.length && _ws.contains(t[i])) {
      i++;
    }
    if (i >= t.length || t[i] != '(') continue;
    final title = _literalAt(t, i + 1);
    // A title that is only an interpolation (`${when}`) is a variable in
    // Dart, which has no literal to compare.
    if (title != null && !RegExp(r'^\$(?:\{[^}]*\}|\w+)$').hasMatch(title)) {
      titles.add(title);
    }
  }
  return titles;
}

/// A title with escapes undone and interpolations (`${x}`, `$x`, and
/// test.each's `%s`) as `<v>`.
String normalizeTitle(String s) {
  s = s
      .replaceAll(r"\'", "'")
      .replaceAll(r'\"', '"')
      .replaceAll(r'\`', '`')
      .replaceAll(r'\$', r'$');
  s = s.replaceAll(RegExp(r'\$\{[^}]*\}|\$\w+'), '<v>');
  return s.replaceAll(RegExp(r'%[sjdifpo#%]'), '<v>');
}

class TitleReport {
  TitleReport(this.file, this.upstream, this.upstreamTitles, this.dartTitles);

  final String file;

  /// Null when the test file has no `Ported from` header.
  final String? upstream;
  final List<String> upstreamTitles;
  final List<String> dartTitles;

  bool get matches =>
      upstream != null &&
      upstreamTitles.length == dartTitles.length &&
      Iterable<int>.generate(
        dartTitles.length,
      ).every((i) => upstreamTitles[i] == dartTitles[i]);
}

/// For each `*_test.dart`: its titles beside upstream's.
List<TitleReport> titleReports(Roots roots) {
  final reports = <TitleReport>[];
  for (final f in _dartFiles(p.join(roots.repo, 'test'))) {
    if (!f.endsWith('_test.dart')) continue;
    final t = File(f).readAsStringSync();
    final m = _portedHeader.firstMatch(_head(t, 5));
    if (m == null) {
      reports.add(TitleReport(roots.rel(f), null, const [], const []));
      continue;
    }
    final up = File(p.join(roots.upstream, m[1]!)).readAsStringSync();
    reports.add(
      TitleReport(
        roots.rel(f),
        m[1]!,
        testTitles(up, ['describe', 'it', 'test']).map(normalizeTitle).toList(),
        testTitles(t, ['group', 'test']).map(normalizeTitle).toList(),
      ),
    );
  }
  return reports;
}

/// A unified diff of two title lists with no context, as difflib's
/// `unified_diff(a, b, n=0)` prints it (hunks from a longest common
/// subsequence, so ties may split differently).
List<String> unifiedDiff(List<String> a, List<String> b) {
  final n = a.length, m = b.length;
  final lcs = List.generate(n + 1, (_) => List.filled(m + 1, 0));
  for (var i = n - 1; i >= 0; i--) {
    for (var j = m - 1; j >= 0; j--) {
      lcs[i][j] = a[i] == b[j]
          ? lcs[i + 1][j + 1] + 1
          : (lcs[i + 1][j] > lcs[i][j + 1] ? lcs[i + 1][j] : lcs[i][j + 1]);
    }
  }
  String range(int start, int stop) {
    var begin = start + 1;
    final length = stop - start;
    if (length == 1) return '$begin';
    if (length == 0) begin--;
    return '$begin,$length';
  }

  final out = <String>[];
  var i = 0, j = 0;
  while (i < n || j < m) {
    if (i < n && j < m && a[i] == b[j]) {
      i++;
      j++;
      continue;
    }
    final i0 = i, j0 = j;
    while (i < n || j < m) {
      if (i < n && j < m && a[i] == b[j]) break;
      if (j >= m || (i < n && lcs[i + 1][j] >= lcs[i][j + 1])) {
        i++;
      } else {
        j++;
      }
    }
    if (out.isEmpty) out.addAll(['--- ', '+++ ']);
    out.add('@@ -${range(i0, i)} +${range(j0, j)} @@');
    out.addAll([for (final x in a.sublist(i0, i)) '-$x']);
    out.addAll([for (final x in b.sublist(j0, j)) '+$x']);
  }
  return out;
}

// ---------------------------------------------------------------------------
// Headers and file mapping

final _headerLine = RegExp(
  r'(Ported from sandbox-runtime|STUB: pending port of|PARTIAL:.*?of(?: the rest of)?)\s+(\S+\.(?:ts|mjs))\s+@\s+(\w+)',
);

int _commentLines(String t, {required bool dart}) {
  var n = 0;
  var inBlock = false;
  for (final line in _lines(t)) {
    final s = line.trim();
    if (inBlock) {
      n++;
      if (s.contains('*/')) inBlock = false;
      continue;
    }
    if (s.startsWith('/*')) {
      n++;
      if (!s.substring(2).contains('*/')) inBlock = true;
    } else if (s.startsWith('//')) {
      if (!dart ||
          !(s.startsWith('// ignore') ||
              s.startsWith('// Ported') ||
              s.startsWith('// STUB') ||
              s.startsWith('// PARTIAL'))) {
        n++;
      }
    } else if (RegExp(r'[^:]//\s').hasMatch(s) &&
        (dart || !s.startsWith("'"))) {
      n++; // A trailing comment.
    }
  }
  return n;
}

/// The Dart file name upstream file [src] maps to: kebab-case and dots to
/// snake_case (`x.test.ts` -> `x_test`); a vendor build script
/// `vendor/<name>/build.ts` -> `build_<name>`.
String expectedDartName(String src) {
  final parts = p.posix.split(src);
  if (parts.length == 3 && parts[0] == 'vendor' && parts[2] == 'build.ts') {
    return 'build_${parts[1].replaceAll('-', '_')}';
  }
  final base = p.posix.basenameWithoutExtension(src);
  final name = base.replaceAll('-', '_').replaceAll('.', '_');
  return src.endsWith('.mjs') && !name.endsWith('_test')
      ? '${name}_test'
      : name;
}

class HeaderReport {
  HeaderReport(
    this.file, {
    this.kind,
    this.upstream,
    this.commit,
    this.problem,
    this.upstreamCommentLines,
    this.dartCommentLines,
  });

  final String file;

  /// `Ported`, `STUB` or `PARTIAL`; null when the file has no header.
  final String? kind;
  final String? upstream;
  final String? commit;

  /// Null if the header is sound; else what is wrong.
  final String? problem;
  final int? upstreamCommentLines;
  final int? dartCommentLines;
}

/// Every Dart file's header: the upstream file exists and maps to this
/// file's name. Comment-line counts are informational.
List<HeaderReport> headerReports(Roots roots) {
  final reports = <HeaderReport>[];
  for (final f in portedFileCandidates(roots)) {
    final rel = roots.rel(f);
    final t = File(f).readAsStringSync();
    final m = _headerLine.firstMatch(_head(t, 3));
    if (m == null) {
      reports.add(HeaderReport(rel));
      continue;
    }
    final kind = m[1]!.split(' ').first.replaceAll(':', '');
    final src = m[2]!;
    final up = File(p.join(roots.upstream, src));
    if (!up.existsSync()) {
      reports.add(
        HeaderReport(
          rel,
          kind: kind,
          upstream: src,
          commit: m[3],
          problem: 'upstream file missing',
        ),
      );
      continue;
    }
    final want = expectedDartName(src);
    final have = p.basenameWithoutExtension(f);
    reports.add(
      HeaderReport(
        rel,
        kind: kind,
        upstream: src,
        commit: m[3],
        problem: have == want ? null : 'expected file name $want.dart',
        upstreamCommentLines: _commentLines(up.readAsStringSync(), dart: false),
        dartCommentLines: _commentLines(t, dart: true),
      ),
    );
  }
  return reports;
}
