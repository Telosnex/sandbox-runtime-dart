// Builds vendor/spawn-helper/<arch>/srt-spawn (Linux), the static helper that
// child_process.dart uses to get exact exit statuses. Optional: without it
// the status of a child the VM reaped first is reported as ECHILD.

import 'dart:io';

import 'package:path/path.dart' as path;

import 'package:sandbox_runtime/src/node/process.dart' as process;

void main() {
  if (!Platform.isLinux) {
    stderr.writeln('spawn-helper build: linux only');
    exit(1);
  }
  final arch = {'x64': 'x64', 'arm64': 'arm64'}[process.arch];
  if (arch == null) {
    stderr.writeln('spawn-helper build: unsupported arch ${process.arch}');
    exit(1);
  }
  final here = path.dirname(path.fromUri(Platform.script));
  final src = path.join(
    here,
    '..',
    'vendor',
    'spawn-helper-src',
    'srt-spawn.c',
  );
  final out = path.join(here, '..', 'vendor', 'spawn-helper', arch);
  Directory(out).createSync(recursive: true);
  final bin = path.join(out, 'srt-spawn');
  for (final argv in [
    ['gcc', '-static', '-O2', '-Wall', '-Wextra', '-o', bin, src],
    ['strip', bin],
  ]) {
    final r = Process.runSync(argv.first, argv.skip(1).toList());
    stdout.write(r.stdout);
    stderr.write(r.stderr);
    if (r.exitCode != 0) exit(1);
  }
  stdout.writeln('built $bin');
}
