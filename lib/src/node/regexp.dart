// Minimal `RegExp`-with-indices behavior for ported Node callers.
// Dart's Match API reports whole-match offsets but not capture-group offsets.

/// A match with the index data the upstream code reads from `d`-flag matches.
class NodeMatchWithIndices {
  NodeMatchWithIndices._(
    this._match,
    this._indices,
    this._originalToGeneratedGroup,
  );

  final Match _match;
  final List<(int, int)?> _indices;
  final Map<int, int> _originalToGeneratedGroup;

  String? group(int group) =>
      _match.group(group == 0 ? 0 : _originalToGeneratedGroup[group]!);

  int get index => _match.start;

  List<(int, int)?> get indices => _indices;
}

/// Global matches with capture-group offsets reconstructed by instrumenting
/// the pattern with captures for the consumed text preceding each group.
Iterable<NodeMatchWithIndices> matchAllWithIndices(
  String content,
  String pattern,
) {
  final instrumented = _InstrumentedPattern(pattern);
  return instrumented.regExp.allMatches(content).map((match) {
    final indices = <(int, int)?>[(match.start, match.end)];
    for (var group = 1; group <= instrumented.captureCount; group++) {
      final value = match.group(instrumented.groupNumberByOriginal[group]!);
      if (value == null) {
        indices.add(null);
        continue;
      }
      var start = match.start;
      for (final measurement in instrumented.prefixMeasurements[group]!) {
        final measured = match.group(measurement);
        if (measured == null) {
          throw StateError(
            'RegExp index instrumentation did not match prefix capture '
            '$measurement for group $group.',
          );
        }
        start += measured.length;
      }
      for (final lookbehind in instrumented.lookbehindMeasurements[group]!) {
        final measured = match.group(lookbehind);
        if (measured == null) {
          throw StateError(
            'RegExp index instrumentation did not match lookbehind capture '
            '$lookbehind for group $group.',
          );
        }
        start -= measured.length;
      }
      indices.add((start, start + value.length));
    }
    return NodeMatchWithIndices._(
      match,
      indices,
      instrumented.groupNumberByOriginal,
    );
  });
}

class _InstrumentedPattern {
  _InstrumentedPattern(String pattern) {
    _nextMeasurementId = 1;
    final parser = _PatternParser(pattern);
    final root = parser.parse();
    captureCount = parser.captureCount;
    _transform(root, const [], const []);
    final measurementNumberById = <int, int>{};
    _assignCaptureNumbers(root, measurementNumberById);
    groupNumberByOriginal = {
      for (final group in parser.originalGroups)
        group.originalNumber: group.captureNumber!,
    };
    prefixMeasurements = {
      for (final group in parser.originalGroups)
        group.originalNumber: [
          for (final measurement in group.prefixMeasurements)
            measurementNumberById[measurement]!,
        ],
    };
    lookbehindMeasurements = {
      for (final group in parser.originalGroups)
        group.originalNumber: [
          for (final measurement in group.lookbehindMeasurements)
            measurementNumberById[measurement]!,
        ],
    };
    for (final backreference in parser.backreferences) {
      final originalNumber = backreference.originalNumber;
      if (originalNumber == null || originalNumber > captureCount) {
        throw UnimplementedError(
          'RegExp index instrumentation cannot safely rewrite an invalid or '
          'legacy-octal numeric escape in "$pattern".',
        );
      }
      backreference.replacement = '\\${groupNumberByOriginal[originalNumber]}';
    }
    regExp = RegExp(root.render());
  }

  late final RegExp regExp;
  late final int captureCount;
  late final Map<int, int> groupNumberByOriginal;
  late final Map<int, List<int>> prefixMeasurements;
  late final Map<int, List<int>> lookbehindMeasurements;
}

void _transform(
  _Expression expression,
  List<int> activeMeasurements,
  List<int> activeLookbehinds,
) {
  for (final alternative in expression.alternatives) {
    var measurements = List<int>.of(activeMeasurements);
    final output = <_RegexNode>[];
    final pending = <_RegexNode>[];
    for (final originalNode in alternative.nodes) {
      if (!originalNode.containsOriginalCapture) {
        _transformNode(originalNode, measurements, activeLookbehinds);
        pending.add(originalNode);
        continue;
      }
      if (originalNode is _QuantifiedNode) {
        throw UnimplementedError(
          'RegExp capture indices for a quantified capture group are not '
          'supported exactly; pattern: ${expression.source}',
        );
      }
      if (pending.isNotEmpty) {
        final measurement = _MeasurementNode(pending.toList());
        output.add(measurement);
        measurements.add(measurement.id);
        pending.clear();
      }
      _transformNode(originalNode, measurements, activeLookbehinds);
      if (originalNode is _OriginalCaptureNode) {
        originalNode.prefixMeasurements = List<int>.of(measurements);
        originalNode.lookbehindMeasurements = List<int>.of(activeLookbehinds);
      }
      pending.add(originalNode);
    }
    output.addAll(pending);
    alternative.transformedNodes = output;
  }
}

void _transformNode(
  _RegexNode node,
  List<int> activeMeasurements,
  List<int> activeLookbehinds,
) {
  if (node is _GroupNode) {
    if (node.isLookbehind) {
      final measurement = _MeasurementNode(const []);
      node.lookbehindMeasurement = measurement;
      _transform(node.expression, activeMeasurements, [
        ...activeLookbehinds,
        measurement.id,
      ]);
      measurement.nodes = node.expression.renderNodes;
      return;
    }
    _transform(node.expression, activeMeasurements, activeLookbehinds);
    return;
  }
  if (node is _QuantifiedNode) {
    if (node.node.containsOriginalCapture) {
      throw UnimplementedError(
        'RegExp capture indices for a quantified capture group are not '
        'supported exactly; pattern: ${node.source}',
      );
    }
    _transformNode(node.node, activeMeasurements, activeLookbehinds);
  }
}

void _assignCaptureNumbers(
  _Expression expression,
  Map<int, int> measurementNumberById,
) {
  var number = 0;
  void visit(_RegexNode node) {
    if (node is _MeasurementNode) {
      node.captureNumber = ++number;
      measurementNumberById[node.id] = node.captureNumber!;
      for (final child in node.nodes) {
        visit(child);
      }
    } else if (node is _OriginalCaptureNode) {
      node.captureNumber = ++number;
      for (final child in node.expression.renderNodes) {
        visit(child);
      }
    } else if (node is _GroupNode) {
      if (node.lookbehindMeasurement != null) {
        final measurement = node.lookbehindMeasurement!;
        measurement.captureNumber = ++number;
        measurementNumberById[measurement.id] = measurement.captureNumber!;
        for (final child in measurement.nodes) {
          visit(child);
        }
      } else {
        for (final child in node.expression.renderNodes) {
          visit(child);
        }
      }
    } else if (node is _QuantifiedNode) {
      visit(node.node);
    }
  }

  for (final alternative in expression.alternatives) {
    for (final node in alternative.renderNodes) {
      visit(node);
    }
  }
}

abstract class _RegexNode {
  bool get containsOriginalCapture => false;
  String render();
}

class _RawNode extends _RegexNode {
  _RawNode(this.text);
  final String text;
  @override
  String render() => text;
}

class _BackreferenceNode extends _RegexNode {
  _BackreferenceNode(this.originalNumber, this.source);
  final int? originalNumber;
  final String source;
  String? replacement;
  @override
  String render() => replacement ?? source;
}

class _QuantifiedNode extends _RegexNode {
  _QuantifiedNode(this.node, this.quantifier, this.source);
  final _RegexNode node;
  final String quantifier;
  final String source;
  @override
  bool get containsOriginalCapture => node.containsOriginalCapture;
  @override
  String render() => '${node.render()}$quantifier';
}

class _MeasurementNode extends _RegexNode {
  _MeasurementNode(this.nodes);
  final int id = _nextMeasurementId++;
  List<_RegexNode> nodes;
  int? captureNumber;
  @override
  String render() => '(${nodes.map((node) => node.render()).join()})';
}

var _nextMeasurementId = 1;

class _OriginalCaptureNode extends _GroupNode {
  _OriginalCaptureNode(super.prefix, super.expression, this.originalNumber)
    : super(isCapture: true);
  final int originalNumber;
  int? captureNumber;
  List<int> prefixMeasurements = const [];
  List<int> lookbehindMeasurements = const [];
  @override
  bool get containsOriginalCapture => true;
}

class _GroupNode extends _RegexNode {
  _GroupNode(
    this.prefix,
    this.expression, {
    this.isCapture = false,
    this.isLookbehind = false,
  });
  final String prefix;
  final _Expression expression;
  final bool isCapture;
  final bool isLookbehind;
  _MeasurementNode? lookbehindMeasurement;
  @override
  bool get containsOriginalCapture =>
      isCapture || expression.containsOriginalCapture;
  @override
  String render() {
    final body = expression.render();
    if (lookbehindMeasurement != null) {
      return '$prefix(${lookbehindMeasurement!.nodes.map((node) => node.render()).join()}))';
    }
    return '$prefix$body)';
  }
}

class _Expression {
  _Expression(this.alternatives, this.source);
  final List<_Alternative> alternatives;
  final String source;
  bool get containsOriginalCapture =>
      alternatives.any((alternative) => alternative.containsOriginalCapture);
  List<_RegexNode> get renderNodes => [
    for (var i = 0; i < alternatives.length; i++) ...[
      if (i > 0) _RawNode('|'),
      ...alternatives[i].renderNodes,
    ],
  ];
  String render() => renderNodes.map((node) => node.render()).join();
}

class _Alternative {
  _Alternative(this.nodes, this.source);
  final List<_RegexNode> nodes;
  final String source;
  List<_RegexNode>? transformedNodes;
  List<_RegexNode> get renderNodes => transformedNodes ?? nodes;
  bool get containsOriginalCapture =>
      nodes.any((node) => node.containsOriginalCapture);
}

class _PatternParser {
  _PatternParser(this.pattern);
  final String pattern;
  final List<_OriginalCaptureNode> originalGroups = [];
  final List<_BackreferenceNode> backreferences = [];
  int offset = 0;
  int captureCount = 0;

  _Expression parse() {
    final expression = _parseExpression(untilClose: false);
    if (offset != pattern.length) {
      throw FormatException('Unexpected regex syntax at offset $offset.');
    }
    return expression;
  }

  _Expression _parseExpression({required bool untilClose}) {
    final alternatives = <_Alternative>[];
    while (true) {
      final nodes = <_RegexNode>[];
      final start = offset;
      while (offset < pattern.length &&
          pattern[offset] != '|' &&
          !(untilClose && pattern[offset] == ')')) {
        nodes.add(_parseAtom());
      }
      alternatives.add(_Alternative(nodes, pattern.substring(start, offset)));
      if (offset < pattern.length && pattern[offset] == '|') {
        offset++;
        continue;
      }
      break;
    }
    return _Expression(alternatives, '');
  }

  _RegexNode _parseAtom() {
    final start = offset;
    final char = pattern[offset];
    _RegexNode node;
    if (char == '[') {
      offset = _characterClassEnd(offset);
      node = _RawNode(pattern.substring(start, offset));
    } else if (char == r'\') {
      node = _parseEscape();
    } else if (char == '(') {
      node = _parseGroup();
    } else if (char == ')') {
      throw FormatException('Unexpected ) at offset $offset.');
    } else if (char == '*' || char == '+' || char == '?') {
      throw FormatException('Unexpected quantifier at offset $offset.');
    } else {
      offset++;
      node = _RawNode(pattern.substring(start, offset));
    }
    final quantifier = _parseQuantifier();
    if (quantifier != null) {
      if (node.containsOriginalCapture) {
        throw UnimplementedError(
          'RegExp capture indices for a quantified capture group are not '
          'supported exactly; pattern: $pattern',
        );
      }
      node = _QuantifiedNode(
        node,
        quantifier,
        pattern.substring(start, offset),
      );
    }
    return node;
  }

  int _characterClassEnd(int start) {
    var i = start + 1;
    while (i < pattern.length) {
      if (pattern[i] == r'\') {
        i += 2;
      } else if (pattern[i] == ']') {
        return i + 1;
      } else {
        i++;
      }
    }
    throw FormatException('Unterminated character class at offset $start.');
  }

  _RegexNode _parseEscape() {
    final start = offset++;
    if (offset >= pattern.length) {
      throw FormatException('Trailing escape at offset $start.');
    }
    final escaped = pattern[offset];
    if (escaped == '0' &&
        offset + 1 < pattern.length &&
        RegExp(r'\d').hasMatch(pattern[offset + 1])) {
      throw UnimplementedError(
        'RegExp index instrumentation cannot safely rewrite a legacy-octal '
        'escape in "$pattern".',
      );
    }
    if (RegExp(r'[1-9]').hasMatch(escaped)) {
      var end = offset + 1;
      while (end < pattern.length && RegExp(r'\d').hasMatch(pattern[end])) {
        end++;
      }
      final source = pattern.substring(start, end);
      final number = int.parse(pattern.substring(offset, end));
      offset = end;
      final reference = _BackreferenceNode(number, source);
      backreferences.add(reference);
      return reference;
    }
    if (escaped == 'k' &&
        offset + 1 < pattern.length &&
        pattern[offset + 1] == '<') {
      final close = pattern.indexOf('>', offset + 2);
      if (close < 0) {
        throw FormatException('Unterminated named backreference at $start.');
      }
      offset = close + 1;
      return _RawNode(pattern.substring(start, offset));
    }
    offset++;
    return _RawNode(pattern.substring(start, offset));
  }

  _RegexNode _parseGroup() {
    final start = offset++;
    var prefix = '(';
    var isLookbehind = false;
    var isCapture = true;
    if (offset < pattern.length && pattern[offset] == '?') {
      if (offset + 1 >= pattern.length) {
        throw FormatException('Unterminated group at offset $start.');
      }
      final next = pattern[offset + 1];
      if (next == ':') {
        prefix = '(?:';
        isCapture = false;
        offset += 2;
      } else if (next == '=') {
        prefix = '(?=';
        isCapture = false;
        offset += 2;
      } else if (next == '!') {
        prefix = '(?!';
        isCapture = false;
        offset += 2;
      } else if (next == '<' && offset + 2 < pattern.length) {
        final after = pattern[offset + 2];
        if (after == '=' || after == '!') {
          prefix = after == '=' ? '(?<=' : '(?<!';
          isCapture = false;
          isLookbehind = true;
          offset += 3;
        } else {
          final end = pattern.indexOf('>', offset + 2);
          if (end < 0) {
            throw FormatException('Unterminated named capture at $start.');
          }
          prefix = pattern.substring(start, end + 1);
          offset = end + 1;
        }
      } else {
        throw UnimplementedError(
          'Unsupported JavaScript RegExp group syntax at offset $start: '
          '${pattern.substring(start)}',
        );
      }
    }
    final originalNumber = isCapture ? ++captureCount : null;
    final expression = _parseExpression(untilClose: true);
    if (offset >= pattern.length || pattern[offset] != ')') {
      throw FormatException('Unterminated group at offset $start.');
    }
    offset++;
    if (!isCapture) {
      return _GroupNode(prefix, expression, isLookbehind: isLookbehind);
    }
    final group = _OriginalCaptureNode(prefix, expression, originalNumber!);
    originalGroups.add(group);
    return group;
  }

  String? _parseQuantifier() {
    if (offset >= pattern.length) return null;
    final start = offset;
    final ch = pattern[offset];
    if (ch == '*' || ch == '+' || ch == '?') {
      offset++;
    } else if (ch == '{') {
      final close = pattern.indexOf('}', offset + 1);
      if (close < 0 ||
          !RegExp(
            r'^\{\d+(,\d*)?\}$',
          ).hasMatch(pattern.substring(offset, close + 1))) {
        return null;
      }
      offset = close + 1;
    } else {
      return null;
    }
    if (offset < pattern.length && pattern[offset] == '?') offset++;
    return pattern.substring(start, offset);
  }
}
