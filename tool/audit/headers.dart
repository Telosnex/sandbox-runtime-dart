// Checks every Dart file's `Ported from` / `STUB` / `PARTIAL` header: the
// upstream file exists, and this file has the name it maps to.
//
//   dart run tool/audit/headers.dart
//
// Columns: file | kind | upstream | comment lines upstream->Dart | commit
// and `ok` or the problem. Exits 1 if any header has a problem.
import 'dart:io';

import 'src/audit.dart';

void main() {
  final roots = Roots.find();
  if (!roots.hasUpstream) {
    stderr.writeln('upstream checkout not found at ${roots.upstream}');
    exit(2);
  }
  var bad = 0;
  for (final r in headerReports(roots)) {
    if (r.kind == null) {
      stdout.writeln('${r.file} | NOHEADER');
      continue;
    }
    if (r.problem != null) bad++;
    final counts = r.upstreamCommentLines == null
        ? ''
        : 'cm ${r.upstreamCommentLines}->${r.dartCommentLines}';
    stdout.writeln(
      '${r.file} | ${r.kind} | ${r.upstream} | $counts | '
      '${r.commit} ${r.problem ?? 'ok'}',
    );
  }
  if (bad > 0) exit(1);
}
