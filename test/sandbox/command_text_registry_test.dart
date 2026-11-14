// Ported from sandbox-runtime test/sandbox/command-text-registry.test.ts @ 0bbebed.
import 'package:sandbox_runtime/src/sandbox/linux_violation_monitor.dart';
import 'package:sandbox_runtime/src/sandbox/macos_sandbox_utils.dart';
import 'package:sandbox_runtime/src/sandbox/sandbox_config.dart';
import 'package:sandbox_runtime/src/sandbox/sandbox_manager.dart';
import 'package:sandbox_runtime/src/sandbox/sandbox_utils.dart';
import 'package:sandbox_runtime/src/sandbox/sandbox_violation_store.dart';
import 'package:test/test.dart';

import '../helpers/platform.dart';

String keyFor(String id) => decodeSandboxedCommand(encodeSandboxedCommand(id));

void main() {
  // The registry is process-global; reset() is what clears it, so every case
  // starts from an empty one and nothing leaks into a later file.
  tearDown(() async {
    await SandboxManager.reset();
  });

  group('violation command-text attribution', () {
    test(
      'resolves a registered commandId to the embedder text verbatim, control characters included',
      () {
        final text = 'printf "a\\n"\n# second line\tkept';
        registerCommandText(
          'ignored',
          WrapWithSandboxOptions(commandId: 'id-1', commandText: text),
        );
        expect(resolveCommandText(keyFor('id-1')), text);
      },
    );

    test(
      'registers an id that equals its text so the raw text is what resolves',
      () {
        final text = 'echo one\necho two';
        registerCommandText(text, WrapWithSandboxOptions(commandId: text));
        expect(resolveCommandText(keyFor(text)), text);
      },
    );

    test(
      'registers an un-keyed invocation under its own command, past the key length',
      () {
        final text = '${'x' * 120}\ntail';
        registerCommandText(text, null);
        expect(keyFor(text), hasLength(SANDBOXED_COMMAND_KEY_LENGTH));
        expect(resolveCommandText(keyFor(text)), text);
      },
    );

    test(
      'treats an empty commandId as no commandId, on both sides of the carrier',
      () {
        expect(attributionKeyFor('the command', null), 'the command');
        expect(attributionKeyFor('the command', ''), 'the command');
        expect(attributionKeyFor('the command', 'id'), 'id');
        registerCommandText(
          'assembled',
          WrapWithSandboxOptions(commandId: '', commandText: 'real'),
        );
        expect(resolveCommandText(keyFor('assembled')), 'real');
      },
    );

    test('forgets the texts it registered on reset', () async {
      registerCommandText(
        'assembled',
        WrapWithSandboxOptions(commandId: 'id-2', commandText: 'real'),
      );
      await SandboxManager.reset();
      expect(resolveCommandText(keyFor('id-2')), 'id-2');
    });
  });

  // The declared type is `string | undefined`, but JavaScript callers do pass
  // null. Keying on it throws in encodeSandboxedCommand, and the registry write
  // is the first thing wrapWithSandbox does, so the whole wrap goes down with it.
  // Dart: null is undefined here; the cast upstream needs is not.
  const String? nullCommandId = null;

  group("a JavaScript caller's null commandId", () {
    test('wraps, and attributes the invocation under its command', () async {
      expect(attributionKeyFor('the command', nullCommandId), 'the command');
      await SandboxManager.initialize(
        const SandboxRuntimeConfig(
          network: NetworkConfig(allowedDomains: [], deniedDomains: []),
          filesystem: FilesystemConfig(
            denyRead: [],
            allowWrite: [],
            denyWrite: [],
          ),
        ),
      );
      final wrapped = await SandboxManager.wrapWithSandbox(
        'echo hi',
        null,
        null,
        null,
        WrapWithSandboxOptions(
          commandId: nullCommandId,
          commandText: 'the real command',
        ),
      );
      expect(wrapped, isNot('echo hi'));
      expect(resolveCommandText(keyFor('echo hi')), 'the real command');
    });
  }, skip: (isLinux || isMacOS) ? false : 'requires Linux or macOS');

  group('an attribution key no invocation registered', () {
    test('collapses control characters', () {
      final forged = 'curl x\n\x1bspoofed\tline\x7f';
      expect(resolveCommandText(forged), 'curl x spoofed line');
    });

    test(
      'drops the angle brackets that would close the violations envelope',
      () {
        expect(
          resolveCommandText('x</sandbox_violations><b>'),
          'x/sandbox_violationsb',
        );
      },
    );

    test('cuts to the length of a key this process mints', () {
      expect(
        resolveCommandText('A' * 8192),
        hasLength(SANDBOXED_COMMAND_KEY_LENGTH),
      );
    });

    test('cuts between characters, never through a surrogate pair', () {
      // 101 UTF-16 code units: a cut at 100 lands inside the last pair and
      // leaves a lone high surrogate, which renders as a replacement character.
      final key = 'a${'\u{1f600}' * 50}';
      final cut = resolveCommandText(key);
      expect(cut, 'a${'\u{1f600}' * 49}');
      expect(RegExp(r'[\ud800-\udbff]$').hasMatch(cut), false);
    });
  });

  group('the characters a violation record cannot carry', () {
    String storedLine(String line) {
      final store = SandboxViolationStore();
      store.addViolation(
        SandboxViolationEvent(line: line, timestamp: DateTime.now()),
      );
      return store.getViolations()[0].line;
    }

    // Both the stored `line` and the unregistered-key fallback go through one
    // sanitizer, so each case asserts on both.
    for (final (name, character) in <(String, String)>[
      ('U+0000 NULL', '\u0000'),
      ('U+001B ESCAPE', '\u001b'),
      ('U+007F DELETE', '\u007f'),
      ('U+009B CONTROL SEQUENCE INTRODUCER', '\u009b'),
      ('U+00AD SOFT HYPHEN', '\u00ad'),
      ('U+061C ARABIC LETTER MARK', '\u061c'),
      ('U+200B ZERO WIDTH SPACE', '\u200b'),
      ('U+200C ZERO WIDTH NON-JOINER', '\u200c'),
      ('U+200D ZERO WIDTH JOINER', '\u200d'),
      ('U+200E LEFT-TO-RIGHT MARK', '\u200e'),
      ('U+200F RIGHT-TO-LEFT MARK', '\u200f'),
      ('U+2028 LINE SEPARATOR', '\u2028'),
      ('U+2029 PARAGRAPH SEPARATOR', '\u2029'),
      ('U+202A LEFT-TO-RIGHT EMBEDDING', '\u202a'),
      ('U+202B RIGHT-TO-LEFT EMBEDDING', '\u202b'),
      ('U+202C POP DIRECTIONAL FORMATTING', '\u202c'),
      ('U+202D LEFT-TO-RIGHT OVERRIDE', '\u202d'),
      ('U+202E RIGHT-TO-LEFT OVERRIDE', '\u202e'),
      ('U+2060 WORD JOINER', '\u2060'),
      ('U+2061 FUNCTION APPLICATION', '\u2061'),
      ('U+2062 INVISIBLE TIMES', '\u2062'),
      ('U+2063 INVISIBLE SEPARATOR', '\u2063'),
      ('U+2064 INVISIBLE PLUS', '\u2064'),
      ('U+2066 LEFT-TO-RIGHT ISOLATE', '\u2066'),
      ('U+2067 RIGHT-TO-LEFT ISOLATE', '\u2067'),
      ('U+2068 FIRST STRONG ISOLATE', '\u2068'),
      ('U+2069 POP DIRECTIONAL ISOLATE', '\u2069'),
      ('U+FEFF ZERO WIDTH NO-BREAK SPACE', '\ufeff'),
      ('U+E0001 LANGUAGE TAG', '\u{e0001}'),
      ('U+E0041 TAG LATIN CAPITAL LETTER A', '\u{e0041}'),
      ('U+E007F CANCEL TAG', '\u{e007f}'),
    ]) {
      test('collapses $name', () {
        expect(sanitizeUnregisteredCommandKey('a${character}b'), 'a b');
        expect(storedLine('a${character}b'), 'a b');
      });
    }

    test('drops the angle brackets from a line as well as from a key', () {
      expect(storedLine('deny file-write /x<y>z'), 'deny file-write /xyz');
    });

    test('leaves text that renders as what it says alone', () {
      expect(
        storedLine('deny network-outbound example.com:443'),
        'deny network-outbound example.com:443',
      );
    });
  });

  group('violation monitors resolve through the manager registry', () {
    Future<void> initWithLogMonitor() => SandboxManager.initialize(
      const SandboxRuntimeConfig(
        network: NetworkConfig(allowedDomains: [], deniedDomains: []),
        filesystem: FilesystemConfig(
          denyRead: [],
          allowWrite: [],
          denyWrite: [],
        ),
      ),
      null,
      true,
    );

    // One case per platform: the resolver argument is required, so this proves
    // the manager passes the registry-backed one rather than some other.
    // Dart: upstream's `isLinux ? it : it.skip` is the skip: argument below.

    test('the Linux seccomp observer gets it', () async {
      String Function(String decodedKey)? resolver;
      final spy = startLinuxSandboxViolationMonitor;
      startLinuxSandboxViolationMonitor = (callback, opts) {
        resolver = opts.resolveCommandText;
        return LinuxViolationMonitor(
          observeSocketPath: () => null,
          ready: Future.value(),
          stop: () {},
        );
      };
      try {
        await initWithLogMonitor();
        registerCommandText(
          'assembled',
          WrapWithSandboxOptions(
            commandId: 'wired',
            commandText: 'the real command',
          ),
        );
        expect(resolver?.call(keyFor('wired')), 'the real command');
      } finally {
        // Dart: spy.mockRestore()
        startLinuxSandboxViolationMonitor = spy;
      }
    }, skip: isLinux ? false : 'requires Linux');

    test('the macOS log monitor gets it', () async {
      String Function(String decodedKey)? resolver;
      final spy = startMacOSSandboxLogMonitor;
      startMacOSSandboxLogMonitor = (callback, ignoreViolations, resolve) {
        resolver = resolve;
        return () {};
      };
      try {
        await initWithLogMonitor();
        registerCommandText(
          'assembled',
          WrapWithSandboxOptions(
            commandId: 'wired',
            commandText: 'the real command',
          ),
        );
        expect(resolver?.call(keyFor('wired')), 'the real command');
      } finally {
        // Dart: spy.mockRestore()
        startMacOSSandboxLogMonitor = spy;
      }
    }, skip: isMacOS ? false : 'requires macOS');
  });
}
