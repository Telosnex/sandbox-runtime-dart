// Ported from sandbox-runtime src/sandbox/sandbox-violation-store.ts @ 24eb39e.
// ignore_for_file: dangling_library_doc_comments, slash_for_doc_comments, constant_identifier_names
// ignore_for_file: non_constant_identifier_names, unintended_html_in_doc_comment

import 'macos_sandbox_utils.dart';
import 'sandbox_config.dart';
import 'sandbox_utils.dart';

/**
 * In-memory tail for sandbox violations
 */
class SandboxViolationStore {
  List<SandboxViolationEvent> _violations = [];
  int _totalCount = 0;
  final int _maxSize = 100;
  final Set<void Function(List<SandboxViolationEvent>)> _listeners = {};

  void addViolation(SandboxViolationEvent violation) {
    // Every producer funnels through here (seatbelt log lines and seccomp
    // events embed raw paths, which may legally contain `<`, `>` or
    // newlines; proxy lines carry embedder-supplied reasons), so `line` is
    // reduced to one physical, tag-free line here rather than per producer.
    _violations.add(
      SandboxViolationEvent(
        line: _sanitizeViolationText(violation.line),
        command: violation.command,
        encodedCommand: violation.encodedCommand,
        timestamp: violation.timestamp,
      ),
    );
    _totalCount++;
    if (_violations.length > _maxSize) {
      _violations = _violations.sublist(_violations.length - _maxSize);
    }
    _notifyListeners();
  }

  List<SandboxViolationEvent> getViolations([num? limit]) {
    if (limit == null) {
      return [..._violations];
    }
    // Match Array.slice(-limit), including its truncation and infinity rules.
    final startArgument = -limit;
    var start = 0;
    if (startArgument.isNaN) {
      start = 0;
    } else if (startArgument.isInfinite) {
      start = startArgument.isNegative ? 0 : _violations.length;
    } else {
      final integer = startArgument.truncate();
      start = integer < 0
          ? (_violations.length + integer).clamp(0, _violations.length).toInt()
          : integer.clamp(0, _violations.length).toInt();
    }
    return _violations.sublist(start);
  }

  int getCount() {
    return _violations.length;
  }

  int getTotalCount() {
    return _totalCount;
  }

  List<SandboxViolationEvent> getViolationsForCommand(String command) {
    final commandBase64 = encodeSandboxedCommand(command);
    return _violations.where((v) => v.encodedCommand == commandBase64).toList();
  }

  void clear() {
    _violations = [];
    // Don't reset totalCount when clearing
    _notifyListeners();
  }

  void Function() subscribe(
    void Function(List<SandboxViolationEvent>) listener,
  ) {
    _listeners.add(listener);
    listener(getViolations());
    return () {
      _listeners.remove(listener);
    };
  }

  void _notifyListeners() {
    // Always notify with all violations so listeners can track the full count
    final violations = getViolations();
    // A listener can unsubscribe while handling a notification. Iterate over a
    // copy so callbacks cannot invalidate iteration.
    for (final listener in _listeners.toList()) {
      if (_listeners.contains(listener)) {
        listener(violations);
      }
    }
  }
}

/**
 * Whether a violation should be suppressed by the user's `ignoreViolations`
 * config: `'*'` patterns apply to every command, other keys are matched as
 * substrings of the (decoded) command. `line` is the violation text the
 * patterns are substring-matched against. Shared by every violation
 * producer (macOS log monitor, Linux seccomp observer, proxy denies) so a
 * pattern suppresses the same event regardless of which one saw it.
 */
bool shouldIgnoreViolation(
  String line,
  String? command,
  IgnoreViolationsConfig? ignoreViolations,
) {
  if (ignoreViolations == null) {
    return false;
  }
  final wildcardPatterns = ignoreViolations['*'] ?? [];
  if (wildcardPatterns.any((p) => line.contains(p))) {
    return true;
  }
  if (command == null) {
    return false;
  }
  for (final entry in ignoreViolations.entries) {
    if (entry.key != '*' &&
        command.contains(entry.key) &&
        entry.value.any((p) => line.contains(p))) {
      return true;
    }
  }
  return false;
}

/**
 * Four kinds of code point that make stored text render as something other
 * than what it says: the control characters (C0, DEL and C1 — the latter
 * covers the 8-bit CSI/OSC introducers); the U+2028/U+2029 line terminators;
 * the bidi controls (embedding, override, isolate, and U+061C); and the
 * zero-width invisibles, the Tags block among them. Not a complete account of
 * what Unicode can be made to do to a renderer.
 */
/* eslint-disable no-control-regex -- stripping control chars is the point */
final RegExp _DISPLAY_UNSAFE_CHARACTERS = RegExp(
  r'[\x00-\x1f\x7f-\x9f\u00ad\u061c\u200b-\u200f\u2028\u2029\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff\u{e0000}-\u{e007f}]+',
  unicode: true,
);
/* eslint-enable no-control-regex */

/**
 * Collapse those to spaces and drop the angle brackets that would close an
 * embedder's <sandbox_violations> envelope early, so that what is stored is
 * what is displayed. Shared by the store (for `line`) and by the
 * unregistered-key fallback, so the two carry the same guarantee.
 */
String _sanitizeViolationText(String text) {
  return text
      .replaceAll(_DISPLAY_UNSAFE_CHARACTERS, ' ')
      .replaceAll(RegExp(r'[<>]'), '')
      .trim();
}

/**
 * What a violation reports for an attribution key no invocation registered.
 * Such a key arrived over a carrier the sandboxed process can write, so it is
 * bytes rather than text: sanitize it and cut it to the length a key this
 * process minted can have — the carriers are bounded far more loosely than
 * that (an HTTP proxy header budget is kilobytes).
 */
String sanitizeUnregisteredCommandKey(String decodedKey) {
  return _cutBetweenCharacters(
    _sanitizeViolationText(decodedKey),
    SANDBOXED_COMMAND_KEY_LENGTH,
  );
}

/**
 * How much of a denial reason supplied by the ask callback a violation line
 * carries, in UTF-16 code units: a few sentences fit, a document does not.
 */
const int MAX_DENIAL_REASON_LENGTH = 500;

/**
 * A denial reason the ask callback supplied, as a violation line may carry
 * it: sanitized first, so the cut counts what is displayed, then cut so that
 * one answer cannot flood the text a model reads. The end is trimmed after
 * the cut: the reason sits inside parentheses, where the store's own trim of
 * the line's ends does not reach.
 */
String sanitizeDenialReason(String reason) {
  return _cutBetweenCharacters(
    _sanitizeViolationText(reason),
    MAX_DENIAL_REASON_LENGTH,
  ).trimRight();
}

String _cutBetweenCharacters(String text, int length) {
  final cut = text.substring(0, length.clamp(0, text.length).toInt());
  // A cut by UTF-16 code unit can land between a surrogate pair; the lone
  // high surrogate left behind renders as a replacement character.
  if (cut.isNotEmpty) {
    final last = cut.codeUnitAt(cut.length - 1);
    if (last >= 0xd800 && last <= 0xdbff) {
      return cut.substring(0, cut.length - 1);
    }
  }
  return cut;
}
