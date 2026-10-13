// Small Node `os` compatibility shim used by sandbox-utils.ts.
import 'dart:io';

import 'process.dart' as process;

/// Node's `os.homedir()` spelling, using the process environment at call time.
String homedir() {
  final env = process.env;
  if (process.platform == 'win32') {
    final profile = env['USERPROFILE'];
    if (profile != null && profile.isNotEmpty) return profile;
    final drive = env['HOMEDRIVE'] ?? '';
    final homePath = env['HOMEPATH'] ?? '';
    if (drive.isNotEmpty || homePath.isNotEmpty) return '$drive$homePath';
  } else {
    final home = env['HOME'];
    if (home != null && home.isNotEmpty) return home;
  }
  // Dart exposes the OS account home when the corresponding environment key
  // is absent, as Node's native os.homedir() does.
  final fallback =
      Platform.environment['HOME'] ?? Platform.environment['USERPROFILE'];
  if (fallback != null && fallback.isNotEmpty) return fallback;
  throw UnsupportedError(
    'os.homedir requires a HOME/USERPROFILE environment value or a passwd lookup',
  );
}

/// Node's `os.tmpdir()` order of environment-variable preference.
String tmpdir() {
  final env = process.env;
  final keys = process.platform == 'win32'
      ? const ['TEMP', 'TMP']
      : const ['TMPDIR', 'TMP', 'TEMP'];
  for (final key in keys) {
    final candidate = env[key];
    if (candidate != null && candidate.isNotEmpty) {
      return candidate.replaceFirst(RegExp(r'[\\/]+$'), '');
    }
  }
  if (process.platform == 'win32') {
    final systemRoot = env['SystemRoot'] ?? env['SYSTEMROOT'] ?? r'C:\Windows';
    return '$systemRoot\\Temp';
  }
  return '/tmp';
}
