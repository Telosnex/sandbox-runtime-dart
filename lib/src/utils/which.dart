// Ported from sandbox-runtime src/utils/which.ts @ 24eb39e.
// ignore_for_file: slash_for_doc_comments

import 'dart:convert';
import 'dart:io';

/**
 * Find the path to an executable, similar to the `which` command.
 * Uses the system `which` command to find executables.
 *
 * @param bin - The name of the executable to find
 * @returns The full path to the executable, or null if not found
 */
String? whichSync(String bin) {
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
