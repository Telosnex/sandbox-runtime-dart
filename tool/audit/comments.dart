// Lists, per ported file, how many upstream comment lines it keeps.
//
//   dart run tool/audit/comments.dart [name-fragment]
//
// With a name fragment, also prints the missing lines of matching files.
import 'dart:io';

import 'src/audit.dart';

void main(List<String> args) {
  final roots = Roots.find();
  if (!roots.hasUpstream) {
    stderr.writeln('upstream checkout not found at ${roots.upstream}');
    exit(2);
  }
  final reports = commentReports(roots);
  for (final r in reports) {
    final found = r.total - r.missing.length;
    final flag = r.missing.isEmpty ? '' : '  MISSING ${r.missing.length}';
    stdout.writeln('${r.file}: $found/${r.total}$flag');
  }
  if (args.isNotEmpty) {
    for (final r in reports) {
      if (!r.file.contains(args.first)) continue;
      for (final m in r.missing) {
        stdout.writeln('  - $m');
      }
    }
  }
}
