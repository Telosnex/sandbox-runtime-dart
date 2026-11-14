// Ported from sandbox-runtime test/sandbox/macos-apple-events.test.ts @ 0bbebed.
import 'dart:convert';
import 'dart:io';

import 'package:test/test.dart';

import 'package:sandbox_runtime/src/sandbox/macos_sandbox_utils.dart';

/// Tests for the opt-in allowAppleEvents option (macOS only).
///
/// By default the Seatbelt profile's (deny default) blocks appleevent-send and
/// the com.apple.coreservices.appleevents mach-lookup, so commands like `open`
/// and `osascript` fail with AppleScript error -600 ("Application isn't
/// running") inside the sandbox. allowAppleEvents: true re-enables them.
/// It is opt-in because Apple Events let sandboxed commands script other
/// applications (e.g. Terminal), weakening sandbox isolation.
String wrapCommand(String command, [bool? allowAppleEvents]) =>
    wrapCommandWithSandboxMacOS(
      MacOSSandboxParams(
        command: command,
        needsNetworkRestriction: true,
        allowAppleEvents: allowAppleEvents,
        readConfig: null,
        writeConfig: null,
      ),
    );

ProcessResult _spawnShell(String command) => Process.runSync(
  '/bin/sh',
  ['-c', command],
  stdoutEncoding: utf8,
  stderrEncoding: utf8,
);

void main() {
  group(
    'macOS Seatbelt allowAppleEvents profile generation',
    skip: Platform.isMacOS ? false : 'requires macOS Seatbelt',
    () {
      test('omits Apple Events rules by default', () {
        final wrapped = wrapCommand('echo test');

        expect(wrapped, isNot(contains('appleevent-send')));
        expect(wrapped, isNot(contains('com.apple.coreservices.appleevents')));
      });

      test(
        'generates an identical command when unset and when explicitly false',
        () {
          final unset = wrapCommand('echo test');
          final explicitFalse = wrapCommand('echo test', false);

          expect(explicitFalse, unset);
        },
      );

      test('includes Apple Events rules when enabled', () {
        final wrapped = wrapCommand('echo test', true);

        // The profile is embedded byte-literal inside a single-quoted argument;
        // matching rule fragments keeps the assertion focused on the rules.
        expect(wrapped, contains('(allow appleevent-send)'));
        expect(wrapped, contains('com.apple.coreservices.appleevents'));
      });

      test('produces a profile that sandbox-exec accepts when enabled', () {
        final wrapped = wrapCommand('echo APPLE_EVENTS_OK', true);
        final result = _spawnShell(wrapped);

        expect(result.exitCode, 0);
        expect(result.stdout, contains('APPLE_EVENTS_OK'));
      });
    },
  );

  // `open -g -a Finder .` requires sending an Apple Event to Finder via
  // appleeventsd, so it probes the Seatbelt layer. Some CI runners cannot run
  // it at all (no usable GUI session / TCC automation grant for the runner
  // user) — there the failure sits in front of Seatbelt, so only assert the
  // sandbox's behavior when the probe works outside the sandbox.
  const openCommand = 'open -g -a Finder .';
  final baselineOpenWorks =
      Platform.isMacOS && _spawnShell(openCommand).exitCode == 0;

  if (Platform.isMacOS && baselineOpenWorks) {
    group('macOS Seatbelt allowAppleEvents end to end', () {
      test('blocks `open` by default', () {
        final result = _spawnShell(wrapCommand(openCommand));

        expect(result.exitCode, isNot(0));
      });

      test('allows `open` when allowAppleEvents is true', () {
        final result = _spawnShell(wrapCommand(openCommand, true));

        if (result.exitCode != 0) {
          // Surface what failed: open's own error plus any Seatbelt denials
          // (deny messages carry the profile's CMD64_ log tag).
          stderr.writeln(
            'open probe failed (status ${result.exitCode})\n'
            'stdout: ${result.stdout}\nstderr: ${result.stderr}',
          );
          final denials = _spawnShell(
            'log show --last 1m --style compact --predicate '
            "'eventMessage CONTAINS \"CMD64_\"'",
          );
          final logText = denials.stdout as String;
          stderr.writeln(
            'sandbox denials:\n${logText.length > 6000 ? logText.substring(logText.length - 6000) : logText}',
          );
        }

        expect(result.exitCode, 0);
      });
    });
  }

  if (Platform.isMacOS && !baselineOpenWorks) {
    group(
      'macOS Seatbelt allowAppleEvents end to end (environment cannot send Apple Events)',
      () {
        test(
          'skipped: `open -g -a Finder .` fails outside the sandbox in this environment',
          () {},
          skip:
              '`open -g -a Finder .` fails outside the sandbox in this environment',
        );
      },
    );
  }
}
