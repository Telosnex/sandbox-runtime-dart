// Stub gate: no upstream counterpart (see tool/audit/README.md).
//
// Usage, from the repo or a worktree:
//   dart run tool/audit/stubcheck.dart src/sandbox/<file>.ts ...
//
// Per upstream file, its Dart file (Rule 1 path) must have:
// - every exported name (also `export { a, b }` lists) as a top-level
//   declaration, in upstream order;
// - every public member of an exported class, interface, object type or
//   object constant, by name;
// - the doc comment of every export and of those members;
// - no `typedef X = Object`.
// Exits 1 on any gap. Also lists, without failing, each line of code that
// uses `Object` or `dynamic`: a reviewer checks that each stands for an
// upstream `unknown`, `any` or union, not for a type that was erased.
import 'dart:io';

import 'package:path/path.dart' as p;

import 'src/audit.dart';

String _norm(String s) => s
    .replaceAllMapped(RegExp(r'\{@link\s+([^}\s]+)[^}]*\}'), (m) => m[1]!)
    .replaceAll(r'*\/', '*/')
    .replaceAll(RegExp(r'^\s*(/\*\*|\*/|\*|///|//)', multiLine: true), ' ')
    .replaceAll('*/', ' ')
    .replaceAll(RegExp(r'[\[\]`]'), '')
    .replaceAll(RegExp(r'\s+'), ' ')
    .trim();

/// [t] with `//` and `/* */` comments blanked out (strings are not
/// special-cased: good enough to count identifiers in declarations).
String _code(String t) {
  final out = StringBuffer();
  void blank(int from, int to) {
    for (var k = from; k < to; k++) {
      out.write(t[k] == '\n' ? '\n' : ' ');
    }
  }

  var i = 0;
  final n = t.length;
  while (i < n) {
    if (t.startsWith('//', i)) {
      var j = t.indexOf('\n', i);
      if (j < 0) j = n;
      blank(i, j);
      i = j;
    } else if (t.startsWith('/*', i)) {
      var depth = 0;
      var j = i;
      while (j < n) {
        if (t.startsWith('/*', j)) {
          depth++;
          j += 2;
        } else if (t.startsWith('*/', j)) {
          depth--;
          j += 2;
          if (depth == 0) break;
        } else {
          j++;
        }
      }
      blank(i, j);
      i = j;
    } else if (t[i] == "'" || t[i] == '"') {
      final raw = i > 0 && t[i - 1] == 'r';
      final q = t.startsWith(t[i] * 3, i) ? t[i] * 3 : t[i];
      var j = i + q.length;
      while (j < n && !t.startsWith(q, j)) {
        if (!raw && t[j] == r'\') j++;
        j++;
      }
      j = (j + q.length).clamp(0, n);
      out.write(q);
      blank(i + q.length, (j - q.length).clamp(i + q.length, n));
      out.write(q);
      i = j;
    } else {
      out.write(t[i]);
      i++;
    }
  }
  return out.toString();
}

final _decl = RegExp(
  r'^export (?:declare )?(?:async )?(function\*?|const|let|class|interface|type|enum|abstract class) +([A-Za-z_$][\w$]*)',
);
final _member = RegExp(
  r'^\s+(?:readonly |static |async |public |get |set |\*)*([A-Za-z_$][\w$]*)\??\s*[:(<,]',
);

class _Export {
  _Export(this.name, this.line);
  final String name;
  final int line;
  final members = <String>[];
  final docs = <String>[];
}

/// The doc comment ending just above line [i], if any.
String? _docAbove(List<String> up, int i) {
  var j = i - 1;
  while (j >= 0 && up[j].trim().startsWith('@')) {
    j--;
  }
  if (j < 0 || !up[j].trim().endsWith('*/')) return null;
  var k = j;
  while (k > 0 && !up[k].contains('/**')) {
    k--;
  }
  if (!up[k].contains('/**')) return null;
  return up.sublist(k, j + 1).join('\n');
}

List<_Export> _exports(List<String> up) {
  final out = <_Export>[];
  for (var i = 0; i < up.length; i++) {
    final line = up[i];
    if (RegExp(r'^export (type )?\{').hasMatch(line)) {
      // `export { a, b }` without `from`: names declared elsewhere in file.
      var k = i;
      final buf = StringBuffer();
      while (k < up.length) {
        buf.write(' ${up[k]}');
        if (up[k].contains('}')) break;
        k++;
      }
      final s = buf.toString();
      if (!s.contains(' from ')) {
        final inner = s.substring(s.indexOf('{') + 1, s.indexOf('}'));
        for (final part in inner.split(',')) {
          final n = part.trim().replaceFirst(RegExp(r'^type\s+'), '');
          final name = n.split(RegExp(r'\s+as\s+')).last.trim();
          if (RegExp(r'^[A-Za-z_$][\w$]*$').hasMatch(name)) {
            out.add(_Export(name, i));
          }
        }
      }
      i = k;
      continue;
    }
    final m = _decl.firstMatch(line);
    if (m == null) continue;
    final e = _Export(m[2]!, i)..docs.addAll([?_docAbove(up, i)]);
    out.add(e);
    final kind = m[1]!;
    final bodied = line.trimRight().endsWith('{');
    if (bodied &&
        (const {
          'class',
          'interface',
          'type',
          'abstract class',
          'const',
        }.contains(kind))) {
      // Members at depth 1 of the body, up to its closing brace.
      var depth = 0;
      var parens = 0; // Inside a multi-line signature: parameters, not members.
      var k = i;
      for (; k < up.length; k++) {
        final l = up[k];
        if (k > i && depth == 1 && parens == 0) {
          final mm = _member.firstMatch(l);
          final private =
              RegExp(r'^\s+(private|protected|#)').hasMatch(l) ||
              (mm != null && mm[1]!.startsWith('#'));
          if (mm != null &&
              !private &&
              !RegExp(r'^\d+$').hasMatch(mm[1]!) &&
              mm[1] != 'constructor' &&
              !l.trim().startsWith('//') &&
              !l.trim().startsWith('*')) {
            e.members.add(mm[1]!);
            final doc = _docAbove(up, k);
            if (doc != null) e.docs.add(doc);
          }
        }
        depth += '{'.allMatches(l).length - '}'.allMatches(l).length;
        if (k > i) {
          parens += '('.allMatches(l).length - ')'.allMatches(l).length;
          if (parens < 0) parens = 0;
        }
        if (k > i && depth <= 0) break;
      }
      i = k;
    }
  }
  return out;
}

void main(List<String> args) {
  final roots = Roots.find();
  var bad = false;
  for (final f in args) {
    final upFile = File(p.join(roots.upstream, f));
    if (!upFile.existsSync()) {
      print('$f: NO UPSTREAM FILE');
      bad = true;
      continue;
    }
    final upText = upFile.readAsStringSync();
    final up = upText.split('\n');
    final dartPath = p.join(
      roots.repo,
      'lib/src',
      '${f.substring(4).replaceAll('.ts', '').replaceAll('-', '_')}.dart',
    );
    final dartFile = File(dartPath);
    if (!dartFile.existsSync()) {
      print('$f: NO DART FILE ${roots.rel(dartPath)}');
      bad = true;
      continue;
    }
    final dart = dartFile.readAsStringSync();
    final code = _code(dart);
    final codeLines = code.split('\n');
    final dartNorm = _norm(dart);
    final problems = <String>[];

    final exports = _exports(up);
    // Names: a line that declares the name at top level: a class, typedef,
    // enum, mixin or extension type; a function (`name(`, `name<T>(`); a
    // variable (`name =`, `name;`); a getter. The declaration may start on
    // the line after its return type, so any unindented line counts.
    final positions = <String, int>{};
    for (final e in exports) {
      final x = RegExp.escape(e.name);
      final re = RegExp(
        '(?:\\b(?:class|typedef|enum|mixin|extension type)\\s+$x\\b)'
        '|(?:^|[\\s>?)])$x\\s*(?:<[^()]*>)?\\s*(?:\\(|=(?!=)|;|\$)'
        '|(?:\\bget\\s+$x\\b)',
      );
      final at = codeLines.indexWhere(
        (l) =>
            l.isNotEmpty &&
            !l.startsWith(RegExp(r'[\s})\]]')) &&
            re.hasMatch(l),
      );
      if (at < 0) {
        problems.add('missing export: ${e.name}');
      } else {
        positions[e.name] = at;
      }
      for (final m in e.members) {
        if (!RegExp(
          '(?<![\\w\$])${RegExp.escape(m)}(?![\\w\$])',
        ).hasMatch(code)) {
          problems.add('missing member: ${e.name}.$m');
        }
      }
    }
    // Order.
    final found = [
      for (final e in exports)
        if (positions[e.name] != null) e,
    ];
    for (var i = 1; i < found.length; i++) {
      if (positions[found[i].name]! < positions[found[i - 1].name]!) {
        problems.add(
          'out of order: ${found[i].name} comes before ${found[i - 1].name}',
        );
      }
    }
    // Docs.
    var docs = 0;
    for (final e in exports) {
      for (final b in e.docs) {
        final n = _norm(b);
        if (n.length < 12) continue;
        docs++;
        final mid = n.length > 60 ? n.substring(10, n.length - 10) : n;
        if (!dartNorm.contains(n) && !dartNorm.contains(mid)) {
          problems.add(
            'missing doc: ${e.name}: '
            '${n.length > 90 ? '${n.substring(0, 90)}...' : n}',
          );
        }
      }
    }
    // Erasure.
    for (final m in RegExp(
      r'^typedef \w+(<[^>]*>)? = Object\??;',
      multiLine: true,
    ).allMatches(dart)) {
      problems.add('erased type: ${m[0]}');
    }
    final objectUse = RegExp(r'(?<![\w$.])(Object|dynamic)(?![\w$.])');
    final dartLines = dart.split('\n');
    final objectLines = <String>[];
    for (var i = 0; i < codeLines.length; i++) {
      // `operator ==(Object other)` is Dart's signature, not an erasure.
      final l = codeLines[i].replaceAll(RegExp(r'==\s*\(\s*Object\b'), '');
      if (objectUse.hasMatch(l)) {
        objectLines.add('${i + 1}: ${dartLines[i].trim()}');
      }
    }
    final todo = RegExp(r'TODO\(stub\)').allMatches(dart).length;
    if (problems.isNotEmpty) bad = true;
    final memberCount = exports.fold(0, (n, e) => n + e.members.length);
    print(
      '$f: ${problems.isEmpty ? 'OK' : 'GAPS'}  exports ${exports.length}, '
      'members $memberCount, docs $docs'
      '${todo > 0 ? ', TODO(stub) $todo' : ''}',
    );
    for (final pr in problems) {
      print('  $pr');
    }
    if (objectLines.isNotEmpty) {
      print(
        '  review: ${objectLines.length} lines use Object/dynamic; each must '
        'stand for an upstream unknown, any or union:',
      );
      for (final l in objectLines) {
        print('    $l');
      }
    }
  }
  exit(bad ? 1 : 0);
}
