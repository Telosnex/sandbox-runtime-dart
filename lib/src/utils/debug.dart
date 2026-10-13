// Ported from sandbox-runtime src/utils/debug.ts @ 24eb39e.
// ignore_for_file: dangling_library_doc_comments, slash_for_doc_comments
/**
 * Simple debug logging for standalone sandbox
 */

import 'dart:io';

import '../node/process.dart' as process;

void logForDebugging(String message, {String? level}) {
  // Only log if SRT_DEBUG environment variable is set
  // Using SRT_DEBUG instead of DEBUG to avoid conflicts with other tools
  // (DEBUG is commonly used by Node.js debug libraries and VS Code)
  if (!(process.env['SRT_DEBUG'] ?? '').isNotEmpty) {
    return;
  }

  final selectedLevel = (level == null || level.isEmpty) ? 'info' : level;
  const prefix = '[SandboxDebug]';

  // Always use stderr to avoid corrupting stdout JSON streams
  switch (selectedLevel) {
    case 'error':
      stderr.writeln('$prefix $message');
      break;
    case 'warn':
      stderr.writeln('$prefix $message');
      break;
    default:
      stderr.writeln('$prefix $message');
  }
}
