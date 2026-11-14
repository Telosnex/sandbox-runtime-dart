// Ported from sandbox-runtime vendor/seccomp/build.ts @ 0bbebed.

import 'dart:io';
import 'dart:typed_data';

import 'package:path/path.dart' as path;

import 'package:sandbox_runtime/src/node/process.dart' as process;

const Map<String, String> _nodeArchToDir = {'x64': 'x64', 'arm64': 'arm64'};

void main() {
  if (!Platform.isLinux) {
    stderr.writeln(
      'seccomp-src build: linux only (running on ${Platform.operatingSystem})',
    );
    exit(1);
  }
  final arch = _nodeArchToDir[process.arch];
  if (arch == null) {
    stderr.writeln('seccomp-src build: unsupported arch ${process.arch}');
    exit(1);
  }

  final here = path.dirname(path.fromUri(Platform.script));
  final src = path.join(here, '..', 'vendor', 'seccomp-src');
  final out = path.join(here, '..', 'vendor', 'seccomp', arch);
  Directory(out).createSync(recursive: true);

  String toCArray(Uint8List bytes) {
    final hex = bytes
        .map((byte) => '0x${byte.toRadixString(16).padLeft(2, '0')}')
        .toList();
    final lines = <String>[];
    for (var i = 0; i < hex.length; i += 8) {
      lines.add('    ${hex.skip(i).take(8).join(', ')},');
    }
    return lines.join('\n');
  }

  final cflags = ['-static', '-O2', '-Wall', '-Wextra'];

  final generator = path.join(out, 'seccomp-unix-block');
  _run([
    'gcc',
    ...cflags,
    '-o',
    generator,
    path.join(src, 'seccomp-unix-block.c'),
    '-lseccomp',
  ]);

  // The two filters apply-seccomp stacks (see seccomp-unix-block.c), as separate
  // arrays so that a command opted out of `namespaces` keeps `unix`. For the
  // builder's own architecture only: the generator can put a call its libseccomp
  // cannot name into a filter by number for that architecture alone.
  final target = arch == 'x64' ? 'x86_64' : 'aarch64';
  final bpf = <String, Uint8List>{};
  for (final rules in ['unix', 'namespaces']) {
    final temporary = path.join(out, '$target.$rules.bpf');
    _run([generator, temporary, target, rules]);
    bpf[rules] = File(temporary).readAsBytesSync();
    File(temporary).deleteSync();
  }
  File(generator).deleteSync();

  final header = path.join(out, 'unix-block-bpf.h');
  File(header).writeAsStringSync(
    '#if defined(__${target}__)\n'
    'static const unsigned char unix_block_bpf[] = {\n'
    '${toCArray(bpf['unix']!)}\n'
    '};\n'
    'static const unsigned char namespace_block_bpf[] = {\n'
    '${toCArray(bpf['namespaces']!)}\n'
    '};\n'
    '#else\n'
    '#error "these filters were generated for another architecture"\n'
    '#endif\n',
  );

  _run([
    'gcc',
    ...cflags,
    '-I',
    out,
    '-o',
    path.join(out, 'apply-seccomp'),
    path.join(src, 'apply-seccomp.c'),
  ]);
  _run(['strip', path.join(out, 'apply-seccomp')]);
  File(header).deleteSync();

  stdout.writeln('built ${path.join(out, 'apply-seccomp')}');
}

void _run(List<String> argv) {
  final command = argv.first;
  final arguments = argv.skip(1).toList();
  try {
    final result = Process.runSync(command, arguments, runInShell: false);
    // Upstream spawns with inherited stdio, so compiler output is shown.
    stdout.write(result.stdout);
    stderr.write(result.stderr);
    if (result.exitCode != 0) {
      stderr.writeln('${argv.join(' ')} exited ${result.exitCode}');
      exit(1);
    }
  } on ProcessException catch (error) {
    stderr.writeln('${argv.join(' ')} failed to spawn: ${error.message}');
    exit(1);
  }
}
