// Ported from sandbox-runtime vendor/java-proxy-agent/build.ts @ 24eb39e.
// ignore_for_file: constant_identifier_names, non_constant_identifier_names, slash_for_doc_comments, dangling_library_doc_comments

/**
 * Build the JVM proxy agent (vendor/java-proxy-agent-src) into
 * vendor/java-proxy-agent/srt-proxy-agent.jar.
 *
 * Same model as the seccomp / srt-win helpers: only the source is in git,
 * the artifact is built by the release workflow and shipped in the npm
 * package, and consumers that bundle srt point at their own copy via the
 * `javaAgentJarPath` config key. The jar is reproducible: `jar --date`
 * pins entry timestamps, and STORED entries in a fixed order.
 *
 *   dart run tool/build_java_proxy_agent.dart  (needs a JDK >= 17 on PATH or JAVA_HOME)
 */
import 'dart:io';

import 'package:path/path.dart' as path;

// Upstream's build.ts lives in vendor/java-proxy-agent/; this one lives in
// tool/, so `here` is the package's vendor/java-proxy-agent directory.
final String here = path.join(
  path.dirname(path.dirname(path.fromUri(Platform.script))),
  'vendor',
  'java-proxy-agent',
);
final String SRC = path.join(here, '..', 'java-proxy-agent-src');
final String OUT = path.join(here, 'srt-proxy-agent.jar');
const String AGENT_CLASS = 'com.anthropic.srt.ProxyAgent';

String bin(String tool) => Platform.environment['JAVA_HOME'] != null
    ? path.join(Platform.environment['JAVA_HOME']!, 'bin', tool)
    : tool;
final String javac = bin('javac');
final String jar = bin('jar');

List<String> walk(String dir) {
  final out = <String>[];
  final names =
      Directory(
          dir,
        ).listSync(followLinks: true).map((e) => path.basename(e.path)).toList()
        ..sort();
  for (final name in names) {
    final p = path.join(dir, name);
    if (FileSystemEntity.isDirectorySync(p)) {
      out.addAll(walk(p));
    } else {
      out.add(p);
    }
  }
  return out;
}

/// Port of vendor/build-common.ts `run`: spawn `argv` with inherited stdio,
/// exit on spawn failure or a non-zero exit.
Future<void> run(List<String> argv) async {
  final Process child;
  try {
    child = await Process.start(
      argv.first,
      argv.sublist(1),
      mode: ProcessStartMode.inheritStdio,
    );
  } on ProcessException catch (e) {
    stderr.writeln('${argv.join(' ')} failed to spawn: ${e.message}');
    exit(1);
  }
  final status = await child.exitCode;
  if (status != 0) {
    stderr.writeln('${argv.join(' ')} exited $status');
    exit(1);
  }
}

Future<void> main() async {
  try {
    Process.runSync(javac, ['-version']);
  } on ProcessException catch (e) {
    stderr.writeln('java-proxy-agent build: cannot run $javac: ${e.message}');
    exit(1);
  }

  final work = Directory.systemTemp.createTempSync('srt-java-agent-').path;
  try {
    final classes = path.join(work, 'classes');
    final sources = walk(SRC).where((f) => f.endsWith('.java')).toList();
    // --release 8: the agent runs inside whatever JVM the sandboxed tool
    // brings, and Java 8 is still common in build tooling.
    await run([
      javac,
      '--release',
      '8',
      '-Xlint:all,-options',
      '-Werror',
      '-g:none',
      '-d',
      classes,
      ...sources,
    ]);

    final manifest = path.join(work, 'MANIFEST.MF');
    File(manifest).writeAsStringSync(
      'Premain-Class: $AGENT_CLASS\nAgent-Class: $AGENT_CLASS\n',
    );
    // -0: STORED (no compression). --date: fixed entry timestamps. Entries
    // are added in a fixed order (walk() sorts) so the bytes are reproducible.
    final entries = walk(
      classes,
    ).map((f) => f.substring(classes.length + 1)).toList();
    await run([
      jar,
      '--create',
      '--file',
      OUT,
      '--manifest',
      manifest,
      '--no-compress',
      '--date',
      '1980-01-01T00:00:02Z',
      // -C applies to the single following file, so repeat it per entry.
      for (final e in entries) ...['-C', classes, e],
    ]);
    stdout.writeln('built $OUT (${File(OUT).lengthSync()} bytes)');
  } finally {
    Directory(work).deleteSync(recursive: true);
  }
}
