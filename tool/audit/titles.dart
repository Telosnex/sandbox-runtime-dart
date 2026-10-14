// Compares each test file's group/test titles with upstream's
// describe/it/test titles, in order.
//
//   dart run tool/audit/titles.dart [name-fragment | all]
//
// Prints the difference for files that match the fragment, or for all.
import 'dart:io';

import 'src/audit.dart';

void main(List<String> args) {
  final roots = Roots.find();
  if (!roots.hasUpstream) {
    stderr.writeln('upstream checkout not found at ${roots.upstream}');
    exit(2);
  }
  final filter = args.isEmpty ? null : args.first;
  for (final r in titleReports(roots)) {
    if (r.upstream == null) {
      stdout.writeln('${r.file}: NOHEADER');
      continue;
    }
    stdout.writeln(
      '${r.file}: up ${r.upstreamTitles.length} '
      'dart ${r.dartTitles.length} ${r.matches ? 'OK' : 'DIFF'}',
    );
    if (!r.matches &&
        filter != null &&
        (filter == 'all' || r.file.contains(filter))) {
      for (final line in unifiedDiff(r.upstreamTitles, r.dartTitles)) {
        stdout.writeln('    $line');
      }
    }
  }
}
