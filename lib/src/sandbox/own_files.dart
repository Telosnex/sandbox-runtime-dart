// Ported from sandbox-runtime src/sandbox/own-files.ts @ 24eb39e.
// ignore_for_file: slash_for_doc_comments

import 'dart:io';

import 'package:path/path.dart' as path;

import '../node/fs.dart' as fs;
import 'sandbox_utils.dart';

/**
 * A warning when a sandboxed command could rewrite this copy of the library:
 * the host side runs unsandboxed, so whoever may write
 * `<project>/node_modules/` decides what the next run there executes.
 *
 * That is when the package directory holding `moduleFile` lies at or under one
 * of `allowedWritePaths`, as spelled or where it really is. Undefined
 * otherwise, and for a copy not under a `node_modules` (a checkout, which is
 * the project being worked on) or with no manifest on disk (compiled into an
 * application). An allowed write path that is a pattern is not judged.
 */
String? ownInstallWarning(
  List<String> allowedWritePaths, [
  String? moduleFile,
]) {
  var root = path.dirname(moduleFile ?? Platform.script.toFilePath());
  while (!fs.existsSync(path.join(root, 'package.json'))) {
    if (root == path.dirname(root)) return null;
    root = path.dirname(root);
  }
  if (!root.split(path.separator).contains('node_modules')) return null;

  final writable = allowedWritePaths
      .expand((allowed) => pathSpellings(normalizePathForSandbox(allowed)))
      .toList();
  final covered = pathSpellings(
    root,
  ).any((form) => writable.any((allowed) => isAtOrUnder(form, allowed)));
  return covered
      ? 'sandbox-runtime is installed in $root, where a sandboxed command '
            'can write it - install it outside the allowed write paths'
      : null;
}
