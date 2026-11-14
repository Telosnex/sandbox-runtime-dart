// Ported from sandbox-runtime test/sandbox/tls-terminate-trust-env.test.ts @ 0bbebed.
// ignore_for_file: non_constant_identifier_names
import 'dart:convert';
import 'dart:io';

import 'package:path/path.dart' as path;
import 'package:test/test.dart';

import 'package:sandbox_runtime/src/sandbox/macos_sandbox_utils.dart';
import 'package:sandbox_runtime/src/sandbox/sandbox_schemas.dart';
import 'package:sandbox_runtime/src/sandbox/sandbox_utils.dart'
    show CA_TRUST_VARS;

// Committed test-only CA — see test/fixtures/tls-terminate/README.md.
final _FIXTURE_DIR = path.join(
  Directory.current.path,
  'test',
  'fixtures',
  'tls-terminate',
);
final _CA_CERT = path.join(_FIXTURE_DIR, 'ca.crt');

ProcessResult _spawnSync(String command, List<String> args) =>
    Process.runSync(command, args, stdoutEncoding: utf8, stderrEncoding: utf8);

void main() {
  group(
    'tls-terminate trust env injection (macOS)',
    skip: Platform.isMacOS ? false : 'requires macOS Seatbelt',
    () {
      String wrap(String cmd, [String? caCertPath]) =>
          wrapCommandWithSandboxMacOS(
            MacOSSandboxParams(
              command: cmd,
              needsNetworkRestriction: true,
              httpProxyPort: 3128,
              socksProxyPort: 1080,
              caCertPath: caCertPath,
              readConfig: FsReadRestrictionConfig(
                denyOnly: [],
                allowWithinDeny: [],
              ),
              writeConfig: FsWriteRestrictionConfig(
                allowOnly: ['/tmp'],
                denyWithinAllow: [],
              ),
            ),
          );

      test('wrapped command contains all trust env vars', () {
        final wrapped = wrap('env', _CA_CERT);
        for (final variable in CA_TRUST_VARS) {
          expect(wrapped, contains('$variable=$_CA_CERT'));
        }
      });

      test('wrapped command omits trust env vars when caCertPath unset', () {
        final wrapped = wrap('env');
        for (final variable in CA_TRUST_VARS) {
          expect(wrapped, isNot(contains(variable)));
        }
      });

      test('child process sees the trust env vars and can read the cert', () {
        final wrapped = wrap(
          r'''printf '%s\n' "$SSL_CERT_FILE" && head -1 "$SSL_CERT_FILE"''',
          _CA_CERT,
        );
        final result = _spawnSync('bash', ['-c', wrapped]);
        expect(result.exitCode, 0);
        final lines = (result.stdout as String).trim().split('\n');
        expect(lines[0], _CA_CERT);
        expect(lines[1], '-----BEGIN CERTIFICATE-----');
      });
    },
  );
}
