// Minimal `RegExp`-with-indices behavior for ported Node callers.
// Dart's Match API reports whole-match offsets but not capture-group offsets.

/// A match with the index data the upstream code reads from `d`-flag matches.
class NodeMatchWithIndices {
  NodeMatchWithIndices(this._match);

  final Match _match;

  String? group(int group) => _match.group(group);

  int get index => _match.start;

  List<(int, int)?> get indices {
    final result = <(int, int)?>[(_match.start, _match.end)];
    for (var group = 1; group <= _match.groupCount; group++) {
      final capture = _match.group(group);
      if (capture == null) {
        result.add(null);
      } else {
        // Dart exposes no capture offsets. Current extraction patterns place
        // group 1 at its value's first occurrence in the full match; repeated
        // values in a regex prefix cannot be distinguished at this boundary.
        final offset = _match.group(0)!.indexOf(capture);
        result.add((
          _match.start + offset,
          _match.start + offset + capture.length,
        ));
      }
    }
    return result;
  }
}

/// Global matches with a Dart-side approximation of Node's RegExp `d` indices.
Iterable<NodeMatchWithIndices> matchAllWithIndices(
  String content,
  String pattern,
) => RegExp(pattern).allMatches(content).map(NodeMatchWithIndices.new);
