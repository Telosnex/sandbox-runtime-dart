// Ported from sandbox-runtime src/sandbox/glob-pattern.ts @ 0bbebed.
// ignore_for_file: slash_for_doc_comments, constant_identifier_names
// ignore_for_file: dangling_library_doc_comments, non_constant_identifier_names

/**
 * The glob syntax of a filesystem entry. {@link parseGlob} alone reads it;
 * what else needs it goes by the tokens.
 */

import '../utils/debug.dart';

abstract final class GlobTokenKind {
  /** Characters that stand for themselves, none of them a separator. */
  static const Text = 'text';
  /** `/` */
  static const Separator = 'separator';
  /** `?`: one character of a name. */
  static const AnyChar = 'anyChar';
  /** `*`: any number of characters of a name. */
  static const Star = 'star';
  /** `**`: any number of characters, separators among them. */
  static const Globstar = 'globstar';
  /** `**` with the `/` after it: any number of directories. */
  static const GlobstarSlash = 'globstarSlash';
  /** `[abc]`, `[a-z]`: one character of a set. */
  static const Set = 'set';
}

sealed class GlobToken {
  const GlobToken(this.kind);
  final String kind;
}

final class GlobTokenText extends GlobToken {
  const GlobTokenText(this.text) : super(GlobTokenKind.Text);
  final String text;
}

final class GlobTokenSet extends GlobToken {
  const GlobTokenSet(this.members, this.matchesSeparator)
    : super(GlobTokenKind.Set);
  /** What is written between the brackets. */
  final String members;
  /** `[+-9]` does: a `/` lies between the two. */
  final bool matchesSeparator;
}

final class GlobTokenSimple extends GlobToken {
  const GlobTokenSimple(super.kind);
}

/** The kinds that match any number of characters. */
// GlobTokenKind.Star | GlobTokenKind.Globstar | GlobTokenKind.GlobstarSlash
typedef _WildcardKind = String;

/**
 * The ranges that `members` spells, a single character as a range of one, in
 * UTF-16 code units as a regular expression without the `u` flag reads them.
 * A `-` is a member where it is the first or the last. Undefined where they
 * spell no set: there are none, or a range runs backwards (`[user-id]`: `r-i`).
 */
List<(int, int)>? _setRanges(String members) {
  if (members == '') return null;
  final ranges = <(int, int)>[];
  for (var i = 0; i < members.length; i++) {
    final isRange =
        i + 1 < members.length &&
        members[i + 1] == '-' &&
        i + 2 < members.length;
    final from = members.codeUnitAt(i);
    if (isRange) i += 2;
    final to = members.codeUnitAt(i);
    if (to < from) return null;
    ranges.add((from, to));
  }
  return ranges;
}

final _SEPARATOR = '/'.codeUnitAt(0);

/**
 * `pattern` as its tokens, in time that grows with its length. Every string
 * is a pattern, and no character escapes another:
 *
 * - A set runs from a `[` to the first `]` after it, be that the next
 *   character. All between the two are members, a `*`, a `?`, a `/` or another
 *   `[` too, and `^` and `!` do not negate.
 * - Brackets that spell no set (see {@link setRanges}) are text, as POSIX
 *   reads a `[` that opens none, and what is between them keeps its meaning.
 *   So are a `[` that nothing closes and a `]` that nothing opens.
 * - Of a run of `*`, the last two go with a `/` that follows. Two or more of
 *   the rest are a `**`.
 */
List<GlobToken> parseGlob(String pattern) {
  final tokens = <GlobToken>[];
  var textStart = 0;
  void endText(int at) {
    if (textStart < at) {
      final text = pattern.substring(textStart, at);
      tokens.add(GlobTokenText(text));
    }
  }

  /**
   * Adds a wildcard that stands right after the last token. Wildcards side by
   * side are kept to the fewest that match the same, two at most: a regular
   * expression tries every way to share a path out among them, which takes a
   * power of its length.
   */
  void addWildcard(_WildcardKind kind) {
    const Star = GlobTokenKind.Star;
    const Globstar = GlobTokenKind.Globstar;
    const GlobstarSlash = GlobTokenKind.GlobstarSlash;
    String? kindAt(int fromEnd) =>
        tokens.length >= fromEnd ? tokens[tokens.length - fromEnd].kind : null;
    // A `**` matches whatever there is, with any of them after it. And
    // `**/**/` is `**/`.
    if (kindAt(1) == Globstar || kindAt(1) == kind) return;
    // So it does with any before it. `*` `**/` `*` and `**/` `*` `**/` are
    // one too: whatever there is, is directories and then a name.
    final isGlobstar =
        kind == Globstar ||
        (kindAt(2) == kind &&
            (kindAt(1) == Star || kindAt(1) == GlobstarSlash));
    if (!isGlobstar) {
      tokens.add(GlobTokenSimple(kind));
      return;
    }
    while (kindAt(1) == Star || kindAt(1) == GlobstarSlash) {
      tokens.removeLast();
    }
    tokens.add(const GlobTokenSimple(Globstar));
  }

  // Found to open no set once, for all of them: looking for a `]` from every
  // `[` anew takes the square of the length.
  var bracketsAreTextUntil = 0;
  final noSets = <String>[];

  var i = 0;
  while (i < pattern.length) {
    switch (pattern[i]) {
      case '/':
        endText(i);
        tokens.add(const GlobTokenSimple(GlobTokenKind.Separator));
        textStart = ++i;
      case '?':
        endText(i);
        tokens.add(const GlobTokenSimple(GlobTokenKind.AnyChar));
        textStart = ++i;
      case '*':
        endText(i);
        final start = i;
        while (i < pattern.length && pattern[i] == '*') {
          i++;
        }
        final withSeparator =
            i - start >= 2 && i < pattern.length && pattern[i] == '/';
        final rest = i - start - (withSeparator ? 2 : 0);
        if (rest >= 2) addWildcard(GlobTokenKind.Globstar);
        if (rest == 1) addWildcard(GlobTokenKind.Star);
        if (withSeparator) addWildcard(GlobTokenKind.GlobstarSlash);
        textStart = withSeparator ? ++i : i;
      case '[':
        if (i < bracketsAreTextUntil) {
          i++;
          break;
        }
        final close = pattern.indexOf(']', i + 1);
        if (close == -1) {
          noSets.add(pattern.substring(i));
          bracketsAreTextUntil = pattern.length;
          i++;
          break;
        }
        final members = pattern.substring(i + 1, close);
        final ranges = _setRanges(members);
        if (ranges == null) {
          noSets.add('[$members]');
          bracketsAreTextUntil = close + 1;
          i++;
          break;
        }
        endText(i);
        tokens.add(
          GlobTokenSet(
            members,
            ranges.any((r) => r.$1 <= _SEPARATOR && _SEPARATOR <= r.$2),
          ),
        );
        textStart = i = close + 1;
      default:
        i++;
    }
  }
  endText(i);
  if (noSets.isNotEmpty) {
    logForDebugging(
      '[Sandbox] The brackets in ${noSets.join(', ')} spell no set of characters, so they are read as text: $pattern',
      level: 'warn',
    );
  }
  return tokens;
}

/** A regular expression that matches `text` and nothing else. */
String escapeRegexLiteral(String text) =>
    text.replaceAllMapped(RegExp(r'[.*+?^${}()|[\]\\]'), (m) => '\\${m[0]}');

/** The regular expression for what `token` matches. */
String globTokenToRegex(GlobToken token) {
  switch (token.kind) {
    case GlobTokenKind.Text:
      return escapeRegexLiteral((token as GlobTokenText).text);
    case GlobTokenKind.Separator:
      return '/';
    case GlobTokenKind.AnyChar:
      return '[^/]';
    case GlobTokenKind.Star:
      return '[^/]*';
    case GlobTokenKind.Globstar:
      return '.*';
    case GlobTokenKind.GlobstarSlash:
      return '(.*/)?';
    case GlobTokenKind.Set:
      // A `-` stays what it is to the set, and the rest are its members.
      return '[${(token as GlobTokenSet).members.replaceAllMapped(RegExp(r'[.^$+{}()|\\]'), (m) => '\\${m[0]}')}]';
    default:
      throw StateError('Unknown glob token: ${token.kind}');
  }
}

/// Convert a glob pattern to a regular expression
///
/// This implements gitignore-style pattern matching to match the behavior of the
/// `ignore` library used by the permission system.
///
/// Supported patterns:
/// - * matches any characters except / (e.g., *.ts matches foo.ts but not foo/bar.ts)
/// - ** matches any characters including / (e.g., src/**/*.ts matches all .ts files in src/)
/// - ? matches any single character except / (e.g., file?.txt matches file1.txt)
/// - [abc] matches any character in the set (e.g., file[0-9].txt matches file3.txt)
///
/// Whatever a pattern spells, what is returned compiles, so that no entry keeps
/// a sandbox from starting (see [parseGlob]). Only its size can be more
/// than an engine takes.
///
/// Shared between macOS sandbox profiles and Linux glob expansion.
String globToRegex(String globPattern) =>
    '^${parseGlob(globPattern).map(globTokenToRegex).join('')}\$';

/// Regex for a glob used in a DENY rule: [globToRegex] plus an optional
/// `/…` tail, so the deny covers everything beneath each match the way
/// `subpath` does for literals. Callers strip a trailing `/**` before the
/// pattern gets here (removeTrailingGlobSuffix), so `**/secrets/**` arrives
/// as `**/secrets` and, matched exactly, would deny only the directory
/// vnode while `secrets/key` stayed readable. This is what the Linux backend
/// already does (a deny masks the whole subtree). Only ever widens a deny.
///
/// Takes a whole pattern, so every character in it is glob syntax: right for
/// the pattern reading of a spelling the caller wrote, which is what
/// `readRuleCovers` passes. A pattern anchored at a directory that is a
/// name on disk goes through the macOS `denyGlobEntryRegex`, which splices
/// that directory back in escaped and calls this for the tail.
String denyGlobRegex(String normalizedGlob) {
  // globToRegex() always returns '^…$'.
  final regex = globToRegex(normalizedGlob);
  return '${regex.substring(0, regex.length - 1)}(/.*)?\$';
}
