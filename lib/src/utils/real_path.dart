// Ported from sandbox-runtime src/utils/real-path.ts @ 0bbebed.
// ignore_for_file: slash_for_doc_comments, constant_identifier_names

import 'dart:convert';
import 'dart:typed_data';

import 'package:path/path.dart' as path;

import '../node/fs.dart' as fs;
import '../node/errno.dart';
import '../node/process.dart' as process;

/** As many links as the kernel follows on the way to one path. */
const _MAX_LINKS = 40;

/**
 * What `ask` says of `at`. U+FFFD in it stands for itself, or for bytes that
 * are no text: the string made of those names another file or none, so it is
 * refused.
 */
String _textOf(
  String Function(String) ask,
  Uint8List Function(String) askBuffer,
  String at,
) {
  final text = ask(at);
  if (text.contains('\uFFFD')) {
    final raw = askBuffer(at);
    final encoded = utf8.encode(text);
    if (raw.length != encoded.length ||
        !Iterable<int>.generate(
          raw.length,
        ).every((i) => raw[i] == encoded[i])) {
      throw NodeError("EILSEQ: illegal byte sequence, '$at'", code: 'EILSEQ');
    }
  }
  return text;
}

/**
 * `p` with every symbolic link on the way to it resolved. The real path is
 * the kernel's on every runtime, whatever characters its names hold.
 *
 * Off Windows a backslash is a character of a name like any other, and
 * runtimes differ in what `realpathSync` does with one. So the real path of a
 * name is asked of the file system component by component, split at `/`
 * alone, where the name holds a backslash. Every other name is asked of
 * `realpathSync.native`, since runtimes differ in how they read a link's
 * target too. On Windows `realpathSync` is asked, of `p` as it is.
 *
 * A `.`, `..` or `//` in `p` itself, and a `/` at its end, is folded in text
 * before anything is looked at: `link/..` is the directory that holds the
 * link. In a link's target they are read as the kernel reads them, `..` being
 * the parent of the real directory reached.
 *
 * An error carries the `code` the kernel gave the call that failed, ELOOP
 * past the number of links the kernel follows, and EILSEQ where the way leads
 * through a name that is no text.
 */
String realPathOf(String p) {
  if (process.platform == 'win32') return fs.realpathSync(p);
  // What a relative `p` is resolved against is part of the name.
  final from = path.isAbsolute(p) ? '' : process.cwd();
  final folded = path.normalize(path.isAbsolute(p) ? p : path.join(from, p));
  if (!(from + p).contains('\\')) {
    return _textOf(fs.realpathSyncNative, fs.realpathSyncNativeBuffer, folded);
  }
  final way = wayTo(folded);
  if (way.notThere != null) throw way.notThere!;
  return way.real.isEmpty ? '/' : way.real;
}

/**
 * The kernel's way to `folded`, an absolute path with no `.`, `..` or `//` of
 * its own: name by name, split at `/` alone, every link followed. `real` is
 * as far as it leads, '' being the root. `rest` is what it has not come to:
 * nothing, or first the name that is not there, or that `real` lets nobody
 * look for (EACCES), with what the kernel said of it. Whatever else stops the
 * way is thrown. POSIX only.
 */
({String real, List<String> rest, Object? notThere}) wayTo(String folded) {
  var real = '';
  var links = 0;
  final rest = folded.split('/');
  while (rest.isNotEmpty) {
    final name = rest.removeAt(0);
    if (name == '' || name == '.' || name == '..') {
      // Only a directory that can be searched has them: ENOTDIR, EACCES.
      try {
        fs.lstatSync('$real/.');
      } catch (notThere) {
        if (notThere is! NodeError || notThere.code != 'EACCES') rethrow;
        return (real: real, rest: [name, ...rest], notThere: notThere);
      }
      if (name == '..') {
        final slash = real.lastIndexOf('/');
        real = real.substring(
          0,
          slash < 0 ? (real.length - 1).clamp(0, real.length) : slash,
        );
      }
      continue;
    }
    final next = '$real/$name';
    late bool isLink;
    try {
      isLink = fs.lstatSync(next).isSymbolicLink();
    } catch (notThere) {
      final code = notThere is NodeError ? notThere.code : null;
      if (code != 'ENOENT' && code != 'ENOTDIR' && code != 'EACCES') rethrow;
      return (real: real, rest: [name, ...rest], notThere: notThere);
    }
    if (!isLink) {
      real = next;
      continue;
    }
    if (++links > _MAX_LINKS) {
      throw NodeError(
        "ELOOP: too many symbolic links encountered, realpath '$folded'",
        code: 'ELOOP',
        syscall: 'realpath',
        path: folded,
      );
    }
    final target = _textOf(fs.readlinkSync, fs.readlinkSyncBuffer, next);
    if (target.startsWith('/')) real = '';
    rest.insertAll(0, target.split('/'));
  }
  return (real: real, rest: rest, notThere: null);
}
