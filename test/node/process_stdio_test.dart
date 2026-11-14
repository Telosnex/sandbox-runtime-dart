// Tests for the Node process stdio shim; no upstream counterpart.
import 'dart:convert';
import 'dart:io';

import 'package:path/path.dart' as path;
import 'package:test/test.dart';

void main() {
  late Directory dir;
  late String packages;

  setUp(() {
    dir = Directory.systemTemp.createTempSync('srt-process-stdio-');
    packages = path.join(
      Directory.current.path,
      '.dart_tool',
      'package_config.json',
    );
  });
  tearDown(() => dir.deleteSync(recursive: true));

  test(
    'stdout and stderr accept pipes and flush callbacks without ending',
    () async {
      final script = File(path.join(dir.path, 'stdio.dart'));
      script.writeAsStringSync(r'''
import 'dart:async';
import 'dart:typed_data';
import 'package:sandbox_runtime/src/node/process.dart' as process;
import 'package:sandbox_runtime/src/node/stream.dart' as stream;
import 'package:sandbox_runtime/src/node/stream_promises.dart' as promises;

Future<void> flush(process.WriteStream out) {
  final done = Completer<void>();
  out.write('', () => done.complete());
  return done.future;
}

Future<void> main() async {
  final out = stream.Readable.from([
    Uint8List.fromList([0, 255, 10]),
    Uint8List.fromList(List<int>.filled(100000, 65)),
  ], objectMode: false);
  final err = stream.Readable.from(['stderr'], objectMode: false);
  out.pipe(process.stdout, end: false);
  err.pipe(process.stderr, end: false);
  await Future.wait([promises.finished(out), promises.finished(err)]);
  await Future.wait([flush(process.stdout), flush(process.stderr)]);
  if (process.stdout.writableEnded || process.stderr.writableEnded) {
    throw StateError('stdio was ended');
  }
}
''');
      final result = await Process.run(
        Platform.resolvedExecutable,
        ['--packages=$packages', script.path],
        stdoutEncoding: null,
        stderrEncoding: null,
      );
      expect(
        result.exitCode,
        0,
        reason: utf8.decode(result.stderr as List<int>),
      );
      expect(result.stdout, [0, 255, 10, ...List<int>.filled(100000, 65)]);
      expect(result.stderr, utf8.encode('stderr'));
    },
  );

  test('stdin is a readable stream that can pipe bytes into stdout', () async {
    final script = File(path.join(dir.path, 'stdin.dart'));
    script.writeAsStringSync(r'''
import 'dart:async';
import 'package:sandbox_runtime/src/node/process.dart' as process;
import 'package:sandbox_runtime/src/node/stream_promises.dart' as promises;

Future<void> main() async {
  process.stdin.pipe(process.stdout, end: false);
  await promises.finished(process.stdin);
  final done = Completer<void>();
  process.stdout.write('', () => done.complete());
  await done.future;
}
''');
    final child = await Process.start(Platform.resolvedExecutable, [
      '--packages=$packages',
      script.path,
    ]);
    final output = child.stdout.fold<List<int>>(
      [],
      (all, chunk) => all..addAll(chunk),
    );
    final errors = child.stderr.transform(utf8.decoder).join();
    final input = List<int>.generate(100000, (i) => i & 255);
    child.stdin.add(input);
    await child.stdin.close();
    expect(await child.exitCode, 0, reason: await errors);
    expect(await output, input);
  });
}
