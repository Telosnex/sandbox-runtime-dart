// Ported from sandbox-runtime src/utils/which.ts @ 0bbebed.
// ignore_for_file: slash_for_doc_comments

import 'dart:convert';
import 'dart:io';

/**
 * Find the path to an executable, similar to the `which` command.
 * Uses Bun.which when running in Bun, falls back to spawnSync for Node.js.
 *
 * @param bin - The name of the executable to find
 * @returns The full path to the executable, or null if not found
 */
String? _whichSync(String bin) {
  // Check if we're running in Bun
  // Dart: JS-only branch (Bun.which); never taken.

  // Fallback to Node.js implementation
  try {
    // Run the `which` command synchronously.
    final result = Process.runSync(
      'which',
      [bin],
      stdoutEncoding: utf8,
      stderrEncoding: utf8,
    );

    final stdout = result.stdout.toString();
    if (result.exitCode == 0 && stdout.isNotEmpty) {
      return stdout.trim();
    }
  } on ProcessException {
    // spawnSync reports a missing command in its result rather than throwing.
    // Return null to preserve that behavior when `which` itself is unavailable.
  }

  return null;
}

/// Node's `whichSync`. A variable so a test can replace it, as upstream's
/// tests do with `spyOn(which, 'whichSync')`.
String? Function(String bin) whichSync = _whichSync;
