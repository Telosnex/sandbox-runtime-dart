// Ported from sandbox-runtime test/cli-config-loading.test.ts @ 0bbebed.
import 'dart:convert';
import 'dart:io';

import 'package:path/path.dart' as path;
import 'package:test/test.dart';

import 'package:sandbox_runtime/src/utils/config_loader.dart';

void main() {
  group('loadConfig', () {
    late String tmpDir;
    late String configPath;

    setUp(() {
      tmpDir = Directory.systemTemp
          .createTempSync('config-test-')
          .resolveSymbolicLinksSync();
      configPath = path.join(tmpDir, 'config.json');
    });

    tearDown(() {
      final directory = Directory(tmpDir);
      if (directory.existsSync()) directory.deleteSync(recursive: true);
    });

    // The caller has to tell a file that is not there — the one case that
    // may fall back to the built-in defaults — from one that is there and
    // did not load, so each of those gets its own kind.
    test('should report missing when the file does not exist', () {
      final result = loadConfig('/nonexistent/path/config.json');
      expect(result, isA<LoadConfigResultMissing>());
      expect(result.kind, 'missing');
    });

    test(
      'should report unreadable, not missing, when the path is a directory',
      () {
        Directory(configPath).createSync();
        final result = loadConfig(configPath);
        expect(result.kind, 'unreadable');
        expect(
          result is LoadConfigResultUnreadable ? result.reason : false,
          contains('EISDIR'),
        );
      },
    );

    test('should report empty for an empty file', () {
      File(configPath).writeAsStringSync('');
      expect(loadConfig(configPath), isA<LoadConfigResultEmpty>());
    });

    test('should report empty for a whitespace-only file', () {
      File(configPath).writeAsStringSync('   \n\t  ');
      expect(loadConfig(configPath), isA<LoadConfigResultEmpty>());
    });

    test('should report invalid for invalid JSON', () {
      File(configPath).writeAsStringSync('{ invalid json }');

      final result = loadConfig(configPath);

      expect(result.kind, 'invalid');
      expect(
        result is LoadConfigResultInvalid ? result.reason : false,
        contains('is not valid JSON'),
      );
    });

    test(
      'should report invalid and name the failing keys for a schema mismatch',
      () {
        // Valid JSON but missing required fields
        File(configPath).writeAsStringSync(jsonEncode({'network': {}}));

        final result = loadConfig(configPath);

        expect(result.kind, 'invalid');
        expect(
          result is LoadConfigResultInvalid ? result.reason : false,
          contains('network.allowedDomains'),
        );
      },
    );

    test('should return valid config for valid file', () {
      final validConfig = {
        'network': {
          'allowedDomains': ['example.com'],
          'deniedDomains': [],
        },
        'filesystem': {'denyRead': [], 'allowWrite': [], 'denyWrite': []},
      };
      File(configPath).writeAsStringSync(jsonEncode(validConfig));

      final result = loadConfig(configPath);

      expect(result.kind, 'ok');
      expect(
        result is LoadConfigResultOk
            ? result.config.network.allowedDomains
            : false,
        contains('example.com'),
      );
    });
  });

  group('loadConfigFromString', () {
    test('should return null for empty string', () {
      final result = loadConfigFromString('');
      expect(result, isNull);
    });

    test('should return null for whitespace-only string', () {
      final result = loadConfigFromString('   \n\t  ');
      expect(result, isNull);
    });

    test('should return null for invalid JSON', () {
      final result = loadConfigFromString('{ invalid json }');
      expect(result, isNull);
    });

    test('should return null for valid JSON with invalid schema', () {
      // Valid JSON but missing required fields
      final result = loadConfigFromString(jsonEncode({'network': {}}));
      expect(result, isNull);
    });

    test('should return valid config for valid JSON', () {
      final validConfig = {
        'network': {
          'allowedDomains': ['example.com'],
          'deniedDomains': [],
        },
        'filesystem': {'denyRead': [], 'allowWrite': [], 'denyWrite': []},
      };
      final result = loadConfigFromString(jsonEncode(validConfig));

      expect(result, isNotNull);
      expect(result?.network.allowedDomains, contains('example.com'));
    });
  });
}
