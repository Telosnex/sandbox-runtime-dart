// Ported from sandbox-runtime src/sandbox/credential-extract.ts @ 24eb39e.
// ignore_for_file: slash_for_doc_comments, dangling_library_doc_comments

import '../node/errno.dart';
import '../node/regexp.dart' as node_regexp;

/**
 * Structured credential extraction, shared by file masking
 * (credential-mask-files.ts) and env-var masking (credential-mask-env.ts).
 *
 * `extract` is a regex whose capture group 1 picks the credential value(s)
 * out of a larger text (a config file, a connection-string env var). Only
 * the captured span(s) are replaced with sentinels; the rest of the text is
 * preserved byte-for-byte so parsers still succeed inside the sandbox.
 */

/**
 * Result of {@link extractAndSubstitute}: the content with each matched
 * capture-group-1 span replaced by `sentinelFor(capture, i)`, plus the
 * distinct captured values in first-seen (index) order.
 */
class ExtractResult {
  ExtractResult({required this.fakeContent, required this.captures});

  String fakeContent;
  List<String> captures;
}

/**
 * Match with the Node `d`-flag offset array supplied by the Node shim.
 */
typedef _MatchWithIndices = node_regexp.NodeMatchWithIndices;

/** Options for {@link extractAndSubstitute}. */
class ExtractOptions {
  ExtractOptions({this.maskDuplicates = false});

  /**
   * If true, verbatim occurrences of each captured value *outside* the
   * regex-matched spans are also replaced with that capture's sentinel —
   * for a secret repeated where the regex does not reach (e.g. pasted
   * into a comment). The scan matches raw substrings: a short or common
   * captured value may corrupt unrelated content that happens to contain
   * it, so this option is intended for long, high-entropy secrets.
   */
  bool maskDuplicates;
}

/** A `[start, end)` slice of the original content to replace. */
class _ReplacementSpan {
  const _ReplacementSpan(this.start, this.end, this.sentinel);

  final int start;
  final int end;
  final String sentinel;
}

/**
 * Apply `pattern` globally to `content` and return `content` with each
 * matched capture-group-1 span replaced by `sentinelFor(capture, i)`,
 * where `i` is the zero-based index of the distinct captured value in
 * first-seen order.
 *
 * Offset-based: Dart's Match exposes capture-group offsets directly, so the
 * output is built by slicing between spans and splicing the sentinel in
 * at the exact `[start, end)` of group 1. By default only the
 * regex-matched span is replaced — a captured value that coincidentally
 * appears elsewhere in the content (outside any match) is left intact. No
 * placeholder pass, no substring-ordering concern.
 *
 * With `maskDuplicates` (see {@link ExtractOptions}), an indexOf scan
 * additionally collects every verbatim occurrence of each captured value
 * elsewhere in the content. All spans are computed against the ORIGINAL
 * content — never the partially substituted output — so an inserted
 * sentinel can never be re-matched and corrupted, even when a captured
 * value is a substring of the sentinel literal. Regex-match spans win
 * over verbatim ones, and verbatim scans run longest-capture-first so a
 * shorter capture that is a substring of a longer one cannot claim part
 * of the longer secret's occurrence. A capture the callback declined to
 * mask (returned unchanged — the decode-verification gate) is excluded
 * from the verbatim scan.
 *
 * Returns `null` when the pattern matches nothing — the caller routes
 * that per the entry's `onExtractNoMatch` option (warn / deny / error).
 *
 * Throws when a match has no group-1 capture. The schema already rejects
 * patterns with zero groups, so this only fires when group 1 is optional
 * and absent for some match (e.g. `"token: (\\S+)?"`); accepting that
 * would silently mask nothing for that occurrence.
 *
 * Pure on `content`/`pattern`; the callback may close over a registry.
 */
ExtractResult? extractAndSubstitute(
  String content,
  String pattern,
  String Function(String capture, int index) sentinelFor, {
  bool maskDuplicates = false,
}) {
  // The schema validates `pattern` compiles; the Node shim iterates every
  // occurrence and supplies the capture-group offset array.
  final indexByCapture = <String, int>{};
  // First sentinel returned per capture — reused for verbatim spans so
  // the duplicate pass never re-invokes the callback.
  final sentinelByCapture = <String, String>{};
  final spans = <_ReplacementSpan>[];
  for (final _MatchWithIndices m in node_regexp.matchAllWithIndices(
    content,
    pattern,
  )) {
    final cap = m.group(1);
    if (cap == null) {
      throw NodeException(
        'extract pattern /$pattern/ matched at offset ${m.index} but '
        'capture group 1 is undefined — group 1 must capture the '
        'credential value on every match.',
      );
    }
    // Empty captures are skipped: a zero-width span has nothing to mask.
    if (cap.isEmpty) continue;
    var i = indexByCapture[cap];
    if (i == null) {
      i = indexByCapture.length;
      indexByCapture[cap] = i;
    }
    final (start, end) = m.indices[1]!;
    final sentinel = sentinelFor(cap, i);
    sentinelByCapture.putIfAbsent(cap, () => sentinel);
    spans.add(_ReplacementSpan(start, end, sentinel));
  }
  if (indexByCapture.isEmpty) return null;

  if (maskDuplicates) {
    // Longest capture first: a shorter capture that is a substring of a
    // longer one would otherwise claim part of the longer secret's
    // occurrence and leave the remainder exposed.
    final byLength = indexByCapture.keys.toList()
      ..sort((a, b) => b.length.compareTo(a.length));
    for (final cap in byLength) {
      final sentinel = sentinelByCapture[cap]!;
      // The callback declines masking by returning the capture itself
      // (decode verification failed). Replacing a value with itself is a
      // no-op, and its spans must not block other captures' duplicates —
      // skip declined captures entirely.
      if (sentinel == cap) continue;
      for (
        var start = content.indexOf(cap);
        start != -1;
        start = content.indexOf(cap, start + 1)
      ) {
        final end = start + cap.length;
        // Spans already collected (regex matches, then earlier — longer —
        // captures' verbatim occurrences) win over this occurrence.
        if (spans.any((s) => start < s.end && s.start < end)) continue;
        spans.add(_ReplacementSpan(start, end, sentinel));
      }
    }
    spans.sort((a, b) => a.start.compareTo(b.start));
  }

  // Spans are non-overlapping and sorted by offset (allMatches yields
  // matches in order; the verbatim pass re-sorts), so a single
  // slice-and-concat pass over the original content is sound.
  final out = StringBuffer();
  var pos = 0;
  for (final s in spans) {
    out.write(content.substring(pos, s.start));
    out.write(s.sentinel);
    pos = s.end;
  }
  return ExtractResult(
    fakeContent: out.toString() + content.substring(pos),
    captures: indexByCapture.keys.toList(),
  );
}
