// No upstream counterpart: tests the Telosnex deviation in
// lib/src/sandbox/mxc_sandbox_utils.dart (PORT_WORKLOG.md, "Deviations from
// upstream").
library;

import 'package:sandbox_runtime/src/node/fs.dart' as fs;
import 'package:sandbox_runtime/src/sandbox/mxc_sandbox_utils.dart';
import 'package:test/test.dart';

void main() {
  late bool Function(String) originalExists;
  setUp(() => originalExists = fs.existsSync);
  tearDown(() => fs.existsSync = originalExists);

  MxcRequest build({
    List<String> denyRead = const [],
    required List<String> denyWrite,
  }) => buildMxcRequest(
    MxcSandboxParams(
      command: 'x',
      cwd: r'C:\work',
      allowWrite: [r'C:\work'],
      denyRead: denyRead,
      denyWrite: denyWrite,
    ),
  );

  test('an existing write-denied path is read-only, not denied', () {
    fs.existsSync = (p) => p == r'C:\work\.git\config';
    final req = build(denyWrite: [r'C:\work\.git\config']);
    expect(req.filesystem.readonlyPaths, contains(r'C:\work\.git\config'));
    expect(req.filesystem.deniedPaths, isNot(contains(r'C:\work\.git\config')));
    expect(req.filesystem.readwritePaths, contains(r'C:\work'));
  });

  test('a missing write-denied path stays denied', () {
    fs.existsSync = (_) => false;
    final req = build(denyWrite: [r'C:\work\.vscode']);
    expect(req.filesystem.deniedPaths, [r'C:\work\.vscode']);
    expect(req.filesystem.readonlyPaths, isNot(contains(r'C:\work\.vscode')));
  });

  test('a write-denied path beneath a read deny stays denied', () {
    fs.existsSync = (_) => true;
    final req = build(
      denyRead: [r'C:\work\secret'],
      denyWrite: [r'C:\work\secret\keys'],
    );
    expect(req.filesystem.deniedPaths, [
      r'C:\work\secret',
      r'C:\work\secret\keys',
    ]);
    expect(
      req.filesystem.readonlyPaths,
      isNot(contains(r'C:\work\secret\keys')),
    );
  });
}
