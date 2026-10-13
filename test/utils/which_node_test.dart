// Ported from sandbox-runtime test/utils/which-node-test.mjs @ 24eb39e.

import 'dart:convert';
import 'dart:io';

import 'package:sandbox_runtime/src/utils/which.dart';
import 'package:test/test.dart';

void main() {
  test('should find existing executable', () {
    final lsPath = whichSync('ls');
    expect(lsPath, isNotNull, reason: 'whichSync should find ls');
    expect(lsPath, contains('/ls'));
  });

  test('should return null for non-existent command', () {
    final nonExistent = whichSync(
      'this-command-definitely-does-not-exist-12345',
    );
    expect(
      nonExistent,
      isNull,
      reason: 'Should return null for non-existent command',
    );
  });

  test('should find bash', () {
    final bashPath = whichSync('bash');
    expect(bashPath, isNotNull, reason: 'whichSync should find bash');
  });

  test('output matches which command', () {
    final lsPath = whichSync('ls');
    final whichResult = Process.runSync('which', ['ls'], stdoutEncoding: utf8);
    final expectedPath = (whichResult.stdout as String).trim();
    expect(lsPath, expectedPath);
  });
}
