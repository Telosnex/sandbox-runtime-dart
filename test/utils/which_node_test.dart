// Ported from sandbox-runtime test/utils/which-node-test.mjs @ 24eb39e.
// ignore_for_file: slash_for_doc_comments, avoid_print, dangling_library_doc_comments

/**
 * Test whichSync behavior in Node.js environment
 * Run with: node --experimental-vm-modules test/utils/which-node.test.mjs
 */

import 'dart:convert';
import 'dart:io';

import 'package:test/test.dart';

import 'package:sandbox_runtime/src/utils/which.dart';

// Upstream is a standalone script, not a bun:test suite; it runs here as one
// test, top to bottom.
void main() {
  test('which-node-test', () {
    // Verify we're running in Node.js, not Bun
    // (Dart is never Bun: runsOnBun() is false, so whichSync takes the
    // non-Bun path this script checks.)

    print('Running whichSync Node.js fallback tests...');

    // Build the project first to get the JS output
    // (Nothing to build: the Dart test imports the library directly.)

    // Dynamically import the built module
    // (A static import above.)

    // Test 1: Should find existing executable
    final lsPath = whichSync('ls');
    expect(lsPath, isNotNull, reason: 'whichSync should find ls');
    expect(
      lsPath!.contains('/ls'),
      isTrue,
      reason: 'Expected path to contain /ls, got: $lsPath',
    );
    print('✓ Found ls at: $lsPath');

    // Test 2: Should return null for non-existent executable
    final nonExistent = whichSync(
      'this-command-definitely-does-not-exist-12345',
    );
    expect(
      nonExistent,
      isNull,
      reason: 'Should return null for non-existent command',
    );
    print('✓ Returns null for non-existent command');

    // Test 3: Should find bash
    final bashPath = whichSync('bash');
    expect(bashPath, isNotNull, reason: 'whichSync should find bash');
    print('✓ Found bash at: $bashPath');

    // Test 4: Verify spawnSync is being used (by checking behavior matches which command)
    final whichResult = Process.runSync('which', ['ls'], stdoutEncoding: utf8);
    final expectedPath = (whichResult.stdout as String).trim();
    expect(
      lsPath,
      expectedPath,
      reason: 'whichSync output should match which command',
    );
    print('✓ Output matches which command');

    print('\n✅ All Node.js fallback tests passed!');
  });
}
