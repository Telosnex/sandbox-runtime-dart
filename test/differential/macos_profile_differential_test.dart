// Differential test: no upstream counterpart (see PORT_WORKLOG.md).
//
// Compiles upstream with its own tsc and checks that the Dart
// wrapCommandWithSandboxMacOS builds the same Seatbelt profile as upstream's
// for equal inputs. Skipped when ../sandbox-runtime/node_modules is absent.
// ignore_for_file: slash_for_doc_comments
import 'dart:convert';
import 'dart:io';

import 'package:path/path.dart' as path;
import 'package:test/test.dart';

import 'package:sandbox_runtime/src/node/process.dart' as process;
import 'package:sandbox_runtime/src/sandbox/macos_sandbox_utils.dart';
import 'package:sandbox_runtime/src/sandbox/sandbox_schemas.dart';

void main() {
  final upstreamRoot = Directory(
    path.join(Directory.current.parent.path, 'sandbox-runtime'),
  );
  final hasUpstreamNodeModules = Directory(
    path.join(upstreamRoot.path, 'node_modules'),
  ).existsSync();
  test(
    'matches the upstream Seatbelt profile byte-for-byte for equal inputs',
    () {
      final environment = Map<String, String>.of(Platform.environment)
        ..remove('JAVA_TOOL_OPTIONS')
        ..remove('CLAUDE_CODE_TMPDIR')
        ..remove('CLAUDE_TMPDIR')
        ..remove('SRT_DEBUG');
      process.setEnvForTesting(environment);
      final originalCwd = Directory.current;
      Directory.current = upstreamRoot.path;
      final temporary = upstreamRoot.createTempSync('.profile-differential-');
      try {
        final compiled = path.join(temporary.path, 'compiled');
        final tsc = path.join(upstreamRoot.path, 'node_modules', '.bin', 'tsc');
        final build = Process.runSync(
          tsc,
          ['--outDir', compiled],
          workingDirectory: upstreamRoot.path,
          environment: environment,
          stdoutEncoding: utf8,
          stderrEncoding: utf8,
        );
        expect(build.exitCode, 0, reason: '${build.stdout}\n${build.stderr}');

        const upstreamScript = r'''
          import { pathToFileURL } from 'node:url'
          const { wrapCommandWithSandboxMacOS } = await import(
            pathToFileURL(process.argv.at(-1)).href
          )
          const wrapped = wrapCommandWithSandboxMacOS({
            command: 'echo PROFILE_DIFF',
            needsNetworkRestriction: true,
            httpProxyPort: 3131,
            socksProxyPort: 3132,
            proxyAuthToken: 'differential-token',
            caCertPath: '/tmp/profile-differential.pem',
            allowUnixSockets: ['/tmp/profile-differential.sock'],
            allowLocalBinding: true,
            allowMachLookup: ['com.example.service', 'com.example.prefix.*'],
            readConfig: {
              denyOnly: ['/tmp/profile-differential/secret', '/tmp/profile-differential/**/.env'],
              allowWithinDeny: ['/tmp/profile-differential/work'],
            },
            writeConfig: {
              allowOnly: ['/tmp/profile-differential/work'],
              denyWithinAllow: ['/tmp/profile-differential/work/secrets', '/tmp/profile-differential/work/**/secret'],
            },
            allowPty: true,
            allowGitConfig: true,
            enableWeakerNetworkIsolation: true,
            allowAppleEvents: true,
          })
          process.stdout.write(wrapped)
        ''';
        final upstreamProfile = Process.runSync(
          'node',
          [
            '--input-type=module',
            '-e',
            upstreamScript,
            path.join(compiled, 'sandbox', 'macos-sandbox-utils.js'),
          ],
          workingDirectory: upstreamRoot.path,
          environment: environment,
          stdoutEncoding: utf8,
          stderrEncoding: utf8,
        );
        expect(
          upstreamProfile.exitCode,
          0,
          reason: '${upstreamProfile.stdout}\n${upstreamProfile.stderr}',
        );

        final dartProfile = wrapCommandWithSandboxMacOS(
          MacOSSandboxParams(
            command: 'echo PROFILE_DIFF',
            needsNetworkRestriction: true,
            httpProxyPort: 3131,
            socksProxyPort: 3132,
            proxyAuthToken: 'differential-token',
            caCertPath: '/tmp/profile-differential.pem',
            allowUnixSockets: ['/tmp/profile-differential.sock'],
            allowLocalBinding: true,
            allowMachLookup: ['com.example.service', 'com.example.prefix.*'],
            readConfig: FsReadRestrictionConfig(
              denyOnly: [
                '/tmp/profile-differential/secret',
                '/tmp/profile-differential/**/.env',
              ],
              allowWithinDeny: ['/tmp/profile-differential/work'],
            ),
            writeConfig: FsWriteRestrictionConfig(
              allowOnly: ['/tmp/profile-differential/work'],
              denyWithinAllow: [
                '/tmp/profile-differential/work/secrets',
                '/tmp/profile-differential/work/**/secret',
              ],
            ),
            allowPty: true,
            allowGitConfig: true,
            enableWeakerNetworkIsolation: true,
            allowAppleEvents: true,
          ),
        );
        final tag = RegExp(r'(_END_)_?[^_]+_SBX');
        String normalizeTag(String value) =>
            value.replaceAllMapped(tag, (match) => '${match[1]}<session>_SBX');
        expect(
          normalizeTag(dartProfile),
          normalizeTag(upstreamProfile.stdout as String),
        );
      } finally {
        process.setEnvForTesting(null);
        temporary.deleteSync(recursive: true);
        Directory.current = originalCwd;
      }
    },
    skip: hasUpstreamNodeModules ? false : 'requires upstream node_modules',
  );
}
