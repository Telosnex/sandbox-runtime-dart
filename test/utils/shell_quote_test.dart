// Ported from sandbox-runtime test/utils/shell-quote.test.ts @ 24eb39e.
// ignore_for_file: slash_for_doc_comments
// ignore_for_file: no_leading_underscores_for_local_identifiers
// ignore_for_file: non_constant_identifier_names

import 'dart:convert';
import 'dart:io';
import 'dart:math';

import 'package:test/test.dart';
import 'package:sandbox_runtime/src/sandbox/macos_sandbox_utils.dart';
import 'package:sandbox_runtime/src/sandbox/sandbox_schemas.dart';
import 'package:sandbox_runtime/src/utils/shell_quote.dart';

/**
 * Regression coverage for the `!` corruption bug, plus the round-trip
 * contract a shell quoter must satisfy.
 *
 * The npm `shell-quote` package this module replaces switched to a
 * double-quote + backslash strategy whenever an argument contained a single
 * quote, and in that mode it backslash-escaped `!`. The wrapper string is
 * only ever run through a non-interactive `<shell> -c`, where bash keeps
 * that backslash, so every `!` in the user command reached the program as
 * the two characters `\!`: heredoc-written `if (!x)` became unparseable
 * JavaScript, and `jq 'a != b'` / `awk '!seen[$0]++'` / `find ! -name`
 * filters were silently rewritten. The user command almost always contains
 * a `'`, so this fired on essentially every sandboxed command.
 */
void main() {
  group('quote', () {
    // The string-level tests are pure JS and run on every CI leg.
    test('never backslash-escapes ! (the shell-quote regression)', () {
      // The embedded `'` is what pushed shell-quote into its buggy branch.
      const command = "node -e 'if (!ok) throw new Error(\"bad\")'";
      final quoted = quote(['/bin/bash', '-c', command]);
      expect(quoted, contains('!ok'));
      expect(quoted, isNot(contains(r'\!')));
    });

    test('the assembled macOS wrapper never contains a backslash-bang', () {
      // End to end through the real wrapper builder: the input has no `\!`,
      // and correct POSIX quoting never needs to introduce one.
      final wrapped = wrapCommandWithSandboxMacOS(
        MacOSSandboxParams(
          command: "node -e 'if (!ok) throw new Error(\"bad\")'",
          needsNetworkRestriction: false,
          readConfig: null,
          writeConfig: FsWriteRestrictionConfig(
            allowOnly: ['/tmp'],
            denyWithinAllow: [],
          ),
        ),
      );
      expect(wrapped, contains('!ok'));
      expect(wrapped, isNot(contains(r'\!')));
    });

    test('leaves shell-safe words bare and single-quotes the rest', () {
      expect(
        quote(['env', 'A=b', '/usr/bin/sandbox-exec', '-p']),
        'env A=b /usr/bin/sandbox-exec -p',
      );
      expect(quote(['']), "''");
      expect(quote(['a b']), "'a b'");
      expect(quote(["don't"]), "'don'\"'\"'t'");
    });

    // The round-trip contract: re-parsing the quoted string with a real POSIX
    // shell must yield exactly the original argument list. This is the test
    // that would have caught the `!` bug on day one. It runs against EVERY
    // POSIX shell available on the machine, not just bash: the wrapper is
    // executed via the caller-supplied `binShell` (frequently zsh on macOS),
    // and zsh has word-position semantics bash does not — e.g. "equals
    // expansion" rewrites or aborts an unquoted word starting with `=` — so a
    // bash-only round-trip structurally cannot detect a zsh-only bug.
    final _SHELLS = [
      'bash',
      'zsh',
      'sh',
      'dash',
    ].map(_whichSync).whereType<String>().toList();

    group('round-trips through a real shell', () {
      /**
         * Runs <shell> -c on quote(['printf', '%s\0', ...args]) and splits
         * the NUL-delimited output back into an argument list. printf appends
         * a trailing NUL, hence the final slice.
         */
      List<String> _roundTrip(String shell, List<String> args) {
        final result = Process.runSync(
          shell,
          [
            '-c',
            quote(['printf', r'%s\0', ...args]),
          ],
          stdoutEncoding: utf8,
          stderrEncoding: utf8,
        );
        expect(result.exitCode, 0, reason: result.stderr.toString());
        final output = result.stdout as String;
        return output
            .split('\u0000')
            .sublist(0, output.split('\u0000').length - 1);
      }

      for (final shell in _SHELLS) {
        group(shell, () {
          test('preserves every shell metacharacter byte for byte', () {
            final args = [
              'if (!ok) { throw new Error("bad") }',
              'a != b',
              r'!seen[$0]++',
              "don't",
              r'$HOME `id` $(id)',
              '* ? [a-z] ~ # | & ; < > ( )',
              r'back\slash',
              'new\nline',
              'tab\there',
              '!',
              '',
            ];
            expect(_roundTrip(shell, args), args);
          });

          test('quotes a leading `=` so zsh equals-expansion cannot fire', () {
            // zsh rewrites an UNQUOTED word starting with `=` to a command
            // path (`=ls` -> /bin/ls) and aborts the entire command line for
            // an unknown name. quote() must therefore never emit a bare
            // leading-`=` word; `=` elsewhere (A=b) stays bare.
            final args = ['=ls', '=definitely-not-a-command', '==', '=', 'A=b'];
            expect(_roundTrip(shell, args), args);
          });

          // Each fast-check sample spawns one real shell process, so cap the
          // run count and give the test an explicit budget — the default 5s
          // per-test timeout is not enough on a loaded CI runner.
          test('property: any printable-ASCII argv round-trips exactly', () {
            final random = Random(0x24eb39e);
            for (var sample = 0; sample < 25; sample++) {
              final args = List<String>.generate(
                1 + random.nextInt(6),
                (_) => String.fromCharCodes(
                  List<int>.generate(
                    random.nextInt(25),
                    (_) => 32 + random.nextInt(95),
                  ),
                ),
              );
              expect(_roundTrip(shell, args), args);
            }
          }, timeout: const Timeout(Duration(seconds: 30)));
        });
      }
    }, skip: _SHELLS.isEmpty ? 'No POSIX shell is available.' : false);
  });
}

String? _whichSync(String name) {
  for (final directory in (Platform.environment['PATH'] ?? '').split(
    Platform.isWindows ? ';' : ':',
  )) {
    if (directory.isEmpty) continue;
    final candidate = '$directory${Platform.pathSeparator}$name';
    if (File(candidate).existsSync()) return candidate;
  }
  return null;
}
