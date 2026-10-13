// Ported from sandbox-runtime src/utils/platform.ts @ 24eb39e.
// ignore_for_file: dangling_library_doc_comments, slash_for_doc_comments

/**
 * Platform detection utilities
 */

import 'dart:io' show File;

import '../node/process.dart' as process;

// Dart has no string-literal union; these are the upstream string values.
typedef Platform = String;

/**
 * Get the WSL version (1 or 2+) if running in WSL.
 * Returns undefined if not running in WSL.
 */
String? getWslVersion() {
  if (process.platform != 'linux') {
    return null;
  }

  try {
    final procVersion = File('/proc/version').readAsStringSync();

    // Check for explicit WSL version markers (e.g., "WSL2", "WSL3", etc.)
    final wslVersionMatch = RegExp(
      r'WSL(\d+)',
      caseSensitive: false,
    ).firstMatch(procVersion);
    if (wslVersionMatch != null && wslVersionMatch.group(1) != null) {
      return wslVersionMatch.group(1);
    }

    // If no explicit WSL version but contains Microsoft, assume WSL1
    // This handles the original WSL1 format: "4.4.0-19041-Microsoft"
    if (procVersion.toLowerCase().contains('microsoft')) {
      return '1';
    }

    return null;
  } catch (_) {
    return null;
  }
}

/**
 * Detect the current platform.
 * Note: All Linux including WSL returns 'linux'. Use getWslVersion() to detect WSL1 (unsupported).
 */
Platform getPlatform() {
  switch (process.platform) {
    case 'darwin':
      return 'macos';
    case 'linux':
      // WSL2+ is treated as Linux (same sandboxing)
      // WSL1 is also returned as 'linux' but will fail isSupportedPlatform check
      return 'linux';
    case 'win32':
      return 'windows';
    default:
      return 'unknown';
  }
}
