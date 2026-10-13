// Ported from sandbox-runtime src/utils/real-path.ts @ 24eb39e.
// ignore_for_file: slash_for_doc_comments, constant_identifier_names

import 'package:path/path.dart' as path;

import '../node/fs.dart' as fs;
import '../node/errno.dart';
import '../node/process.dart' as process;

/** As many links as the kernel follows on the way to one path. */
const _MAX_LINKS = 40;

/**
 * `p` with every symbolic link on the way to it resolved, as
 * `fs.realpathSync` gives it, whatever characters its names hold.
 *
 * Off Windows a backslash is a character of a name like any other, and
 * runtimes differ in what `realpathSync` does with one. So the real path of a
 * name is asked of the file system component by component, split at `/`
 * alone, where the name holds a backslash. Every other name goes to
 * `realpathSync` as it is.
 *
 * A `.`, `..` or `//` in `p` itself is folded in text before anything is
 * looked at, which is what `realpathSync` does with them: `link/..` is the
 * directory that holds the link. In a link's target they are read as the
 * kernel reads them, `..` being the parent of the real directory reached.
 *
 * An error carries the `code` the kernel gave the call that failed, and
 * ELOOP past the number of links the kernel follows.
 */
String realPathOf(String p) {
  // What a relative `p` is resolved against is part of the name.
  final from = path.isAbsolute(p) ? '' : process.cwd();
  if (process.platform == 'win32' || !(from + p).contains('\\')) {
    return fs.realpathSync(p);
  }
  var real = '';
  var links = 0;
  // path.resolve(from, p) uses host path semantics, whereas this loop splits
  // on `/` alone to retain a backslash as an ordinary filename byte.
  final resolved = path.normalize(path.isAbsolute(p) ? p : path.join(from, p));
  final rest = resolved.split('/');
  while (rest.isNotEmpty) {
    final name = rest.removeAt(0);
    if (name.isEmpty || name == '.' || name == '..') {
      // Only a directory that can be searched has them: ENOTDIR, EACCES.
      fs.lstatSync('$real/.');
      if (name == '..') {
        // JavaScript slice(0, -1) yields an empty string; Dart substring does
        // not accept a negative end index.
        final slash = real.lastIndexOf('/');
        final end = slash < 0 ? (real.length - 1).clamp(0, real.length) : slash;
        real = real.substring(0, end);
      }
      continue;
    }
    final next = '$real/$name';
    if (!fs.lstatSync(next).isSymbolicLink()) {
      real = next;
      continue;
    }
    if (++links > _MAX_LINKS) {
      throw NodeError(
        "ELOOP: too many symbolic links encountered, realpath '$p'",
        code: 'ELOOP',
        syscall: 'realpath',
        path: p,
      );
    }
    final target = fs.readlinkSync(next);
    if (target.startsWith('/')) real = '';
    rest.insertAll(0, target.split('/'));
  }
  return real.isEmpty ? '/' : real;
}
