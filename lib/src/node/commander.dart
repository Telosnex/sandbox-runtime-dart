// The parts of npm `commander` 12.1.0 that src/cli.ts and src/proxy-cli.ts
// use, with commander's parsing, help text, error messages and exit codes.
// There is no upstream counterpart; commander is the spec.
import 'dart:convert';
import 'dart:io' as io;

import 'process.dart' as process;

const _omitted = Object();

/// Commander's `CommanderError`.
class CommanderError extends Error {
  CommanderError(this.exitCode, this.code, this.message);

  final int exitCode;
  final String code;
  final String message;

  @override
  String toString() => 'CommanderError: $message';
}

/// Commander's `InvalidArgumentError`, thrown from a custom option parser.
class InvalidArgumentError extends CommanderError {
  InvalidArgumentError(String message)
    : super(1, 'commander.invalidArgument', message);
}

/// Commander's `Option`.
class Option {
  Option(this.flags, [String? description])
    : description = description ?? '',
      required = flags.contains('<'),
      optional = flags.contains('['),
      variadic = RegExp(r'\w\.\.\.[>\]]$').hasMatch(flags) {
    final flagParts = flags.split(RegExp(r'[ |,]+'));
    String? shortFlag;
    if (flagParts.length > 1 && !RegExp(r'^[[<]').hasMatch(flagParts[1])) {
      shortFlag = flagParts.removeAt(0);
    }
    String? longFlag = flagParts.removeAt(0);
    if (shortFlag == null && RegExp(r'^-[^-]$').hasMatch(longFlag)) {
      shortFlag = longFlag;
      longFlag = null;
    }
    short = shortFlag;
    long = longFlag;
  }

  final String flags;
  final String description;
  final bool required;
  final bool optional;
  final bool variadic;
  late final String? short;
  late final String? long;
  Object? Function(String value)? parseArg;
  Object? Function(String value, Object? previous)? parseArgWithPrevious;
  Object? defaultValue = _omitted;

  String name() {
    if (long != null) return long!.replaceFirst(RegExp(r'^--'), '');
    return short!.replaceFirst(RegExp(r'^-'), '');
  }

  String attributeName() => name()
      .replaceFirst(RegExp(r'^no-'), '')
      .split('-')
      .indexed
      .map((e) => e.$1 == 0 ? e.$2 : e.$2[0].toUpperCase() + e.$2.substring(1))
      .join();

  bool isBoolean() => !required && !optional;

  bool is_(String arg) => short == arg || long == arg;

  Object? _concatValue(String value, Object? previous) {
    if (previous == null || previous is! List) return [value];
    return [...previous, value];
  }
}

/// Commander's `Argument`.
class Argument {
  Argument(String name, [this.description = '']) {
    switch (name[0]) {
      case '<':
        required = true;
        _name = name.substring(1, name.length - 1);
      case '[':
        required = false;
        _name = name.substring(1, name.length - 1);
      default:
        required = true;
        _name = name;
    }
    variadic = _name.length > 3 && _name.endsWith('...');
    if (variadic) _name = _name.substring(0, _name.length - 3);
  }

  late String _name;
  late final bool required;
  late final bool variadic;
  final String description;

  String name() => _name;

  String humanReadableArgName() {
    final nameOutput = _name + (variadic ? '...' : '');
    return required ? '<$nameOutput>' : '[$nameOutput]';
  }
}

/// The action handler: the processed arguments, then `opts()`, then the
/// command, as commander passes them.
typedef ActionHandler = Future<void> Function(List<Object?> args);

/// Commander's `Command`.
class Command {
  Command([String? name]) : _name = name ?? '';

  String _name;
  String _description = '';
  final List<Command> commands = [];
  final List<Option> options = [];
  final List<Argument> registeredArguments = [];
  Command? parent;
  bool _allowUnknownOption = false;
  bool _helpOptionDisabled = false;
  void Function(CommanderError err)? _exitCallback;
  ActionHandler? _actionHandler;
  final Map<String, Object?> _optionValues = {};
  final Map<String, void Function(String? value)> _optionListeners = {};
  List<String> args = [];
  List<Object?> processedArgs = [];

  Command name(String str) {
    _name = str;
    return this;
  }

  Command description(String str) {
    _description = str;
    return this;
  }

  Command version(String str) {
    final versionOption = Option('-V, --version', 'output the version number');
    _registerOption(versionOption);
    _optionListeners[versionOption.name()] = (_) {
      io.stdout.write('$str\n');
      _exit(0, 'commander.version', str);
    };
    return this;
  }

  Command command(String nameAndArgs) {
    final cmd = Command(nameAndArgs);
    cmd._exitCallback = _exitCallback;
    cmd.parent = this;
    commands.add(cmd);
    return cmd;
  }

  Command option(
    String flags, [
    String? description,
    Object? Function(String value)? parseArg,
    Object? defaultValue = _omitted,
    Object? Function(String value, Object? previous)? parseArgWithPrevious,
  ]) {
    final option = Option(flags, description)
      ..parseArg = parseArg
      ..parseArgWithPrevious = parseArgWithPrevious
      ..defaultValue = defaultValue;
    _registerOption(option);
    final name = option.attributeName();
    if (!identical(defaultValue, _omitted)) {
      _optionValues[name] = defaultValue;
    }
    _optionListeners[option.name()] = (val) {
      final invalidValueMessage =
          "error: option '${option.flags}' argument '$val' is invalid.";
      Object? value = val;
      final oldValue = _optionValues[name];
      if (val != null &&
          (option.parseArg != null || option.parseArgWithPrevious != null)) {
        value = _callParseArg(option, val, invalidValueMessage);
      } else if (val != null && option.variadic) {
        value = option._concatValue(val, oldValue);
      }
      if (value == null) {
        if (option.isBoolean() || option.optional) {
          value = true;
        } else {
          value = '';
        }
      }
      _optionValues[name] = value;
    };
    return this;
  }

  Command argument(String name, [String? description]) {
    registeredArguments.add(Argument(name, description ?? ''));
    return this;
  }

  Command allowUnknownOption([bool allowUnknown = true]) {
    _allowUnknownOption = allowUnknown;
    return this;
  }

  /// Only `helpOption(false)` (disable) and `helpOption(true)` are supported.
  Command helpOption(bool enabled) {
    _helpOptionDisabled = !enabled;
    return this;
  }

  Command exitOverride([void Function(CommanderError err)? fn]) {
    _exitCallback =
        fn ??
        (err) {
          throw err;
        };
    return this;
  }

  Command action(ActionHandler fn) {
    _actionHandler = (args) {
      final expectedArgsCount = registeredArguments.length;
      final actionArgs = <Object?>[...args.take(expectedArgsCount)];
      while (actionArgs.length < expectedArgsCount) {
        actionArgs.add(null);
      }
      actionArgs.add(opts());
      actionArgs.add(this);
      return fn(actionArgs);
    };
    return this;
  }

  Map<String, Object?> opts() => _optionValues;

  /// `parse(argv, { from: 'user' })`; Dart's `main` arguments are already
  /// the user arguments, so only `from: 'user'` exists. Resolves when an
  /// async action has finished (commander's `parseAsync`).
  Future<void> parse(List<String> argv) async {
    await _parseCommand([], argv);
  }

  Option? _getHelpOption() => _helpOptionDisabled
      ? null
      : Option('-h, --help', 'display help for command');

  Option? _findOption(String arg) {
    for (final option in options) {
      if (option.is_(arg)) return option;
    }
    return null;
  }

  Command? _findCommand(String? name) {
    if (name == null) return null;
    for (final cmd in commands) {
      if (cmd._name == name) return cmd;
    }
    return null;
  }

  void _registerOption(Option option) {
    final matchingOption =
        (option.short != null ? _findOption(option.short!) : null) ??
        (option.long != null ? _findOption(option.long!) : null);
    if (matchingOption != null) {
      final matchingFlag =
          option.long != null && _findOption(option.long!) != null
          ? option.long
          : option.short;
      throw StateError(
        "Cannot add option '${option.flags}'${_name.isNotEmpty ? " to command '$_name'" : ''} due to conflicting flag '$matchingFlag'\n-  already used by option '${matchingOption.flags}'",
      );
    }
    options.add(option);
  }

  Object? _callParseArg(Option target, String value, String message) {
    try {
      final accumulate = target.parseArgWithPrevious;
      return accumulate != null
          ? accumulate(value, _optionValues[target.attributeName()])
          : target.parseArg!(value);
    } on CommanderError catch (err) {
      if (err.code == 'commander.invalidArgument') {
        error(
          '$message ${err.message}',
          exitCode: err.exitCode,
          code: err.code,
        );
      }
      rethrow;
    }
  }

  void _emitOption(Option option, [String? value]) =>
      _optionListeners[option.name()]!(value);

  ({List<String> operands, List<String> unknown}) parseOptions(
    List<String> argv,
  ) {
    final operands = <String>[];
    final unknown = <String>[];
    var dest = operands;
    final args = [...argv];

    bool maybeOption(String arg) => arg.length > 1 && arg[0] == '-';

    Option? activeVariadicOption;
    while (args.isNotEmpty) {
      final arg = args.removeAt(0);

      if (arg == '--') {
        if (identical(dest, unknown)) dest.add(arg);
        dest.addAll(args);
        break;
      }

      if (activeVariadicOption != null && !maybeOption(arg)) {
        _emitOption(activeVariadicOption, arg);
        continue;
      }
      activeVariadicOption = null;

      if (maybeOption(arg)) {
        final option = _findOption(arg);
        if (option != null) {
          if (option.required) {
            final value = args.isEmpty ? null : args.removeAt(0);
            if (value == null) optionMissingArgument(option);
            _emitOption(option, value);
          } else if (option.optional) {
            String? value;
            if (args.isNotEmpty && !maybeOption(args[0])) {
              value = args.removeAt(0);
            }
            _emitOption(option, value);
          } else {
            _emitOption(option);
          }
          activeVariadicOption = option.variadic ? option : null;
          continue;
        }
      }

      if (arg.length > 2 && arg[0] == '-' && arg[1] != '-') {
        final option = _findOption('-${arg[1]}');
        if (option != null) {
          if (option.required) {
            _emitOption(option, arg.substring(2));
          } else {
            _emitOption(option);
            args.insert(0, '-${arg.substring(2)}');
          }
          continue;
        }
      }

      if (RegExp(r'^--[^=]+=').hasMatch(arg)) {
        final index = arg.indexOf('=');
        final option = _findOption(arg.substring(0, index));
        if (option != null && (option.required || option.optional)) {
          _emitOption(option, arg.substring(index + 1));
          continue;
        }
      }

      if (maybeOption(arg)) {
        dest = unknown;
      }

      dest.add(arg);
    }

    return (operands: operands, unknown: unknown);
  }

  Future<void> _parseCommand(
    List<String> operands,
    List<String> unknown,
  ) async {
    final parsed = parseOptions(unknown);
    operands = [...operands, ...parsed.operands];
    unknown = parsed.unknown;
    args = [...operands, ...unknown];

    if (operands.isNotEmpty && _findCommand(operands[0]) != null) {
      return _dispatchSubcommand(operands[0], operands.sublist(1), unknown);
    }
    if (_hasImplicitHelpCommand() &&
        operands.isNotEmpty &&
        operands[0] == 'help') {
      return _dispatchHelpCommand(operands.length > 1 ? operands[1] : null);
    }
    if (commands.isNotEmpty && args.isEmpty && _actionHandler == null) {
      help(error: true);
    }

    _outputHelpIfRequested(parsed.unknown);

    void checkForUnknownOptions() {
      if (parsed.unknown.isNotEmpty) {
        unknownOption(parsed.unknown[0]);
      }
    }

    if (_actionHandler != null) {
      checkForUnknownOptions();
      _processArguments();
      await _actionHandler!(processedArgs);
      return;
    }
    if (operands.isNotEmpty) {
      if (commands.isNotEmpty) {
        unknownCommand();
      } else {
        checkForUnknownOptions();
        _processArguments();
      }
    } else if (commands.isNotEmpty) {
      checkForUnknownOptions();
      help(error: true);
    } else {
      checkForUnknownOptions();
      _processArguments();
    }
  }

  bool _hasImplicitHelpCommand() =>
      commands.isNotEmpty &&
      _actionHandler == null &&
      _findCommand('help') == null;

  Future<void> _dispatchSubcommand(
    String commandName,
    List<String> operands,
    List<String> unknown,
  ) {
    final subCommand = _findCommand(commandName);
    if (subCommand == null) help(error: true);
    return subCommand._parseCommand(operands, unknown);
  }

  Future<void> _dispatchHelpCommand(String? subcommandName) {
    if (subcommandName == null) {
      help();
    }
    final subCommand = _findCommand(subcommandName);
    if (subCommand != null) {
      subCommand.help();
    }
    final helpOption = _getHelpOption();
    return _dispatchSubcommand(subcommandName, [], [
      helpOption?.long ?? helpOption?.short ?? '--help',
    ]);
  }

  void _processArguments() {
    final processed = <Object?>[];
    for (final (index, declaredArg) in registeredArguments.indexed) {
      Object? value;
      if (declaredArg.variadic) {
        if (index < args.length) {
          value = args.sublist(index);
        } else {
          value = <String>[];
        }
      } else if (index < args.length) {
        value = args[index];
      }
      processed.add(value);
    }
    processedArgs = processed;
  }

  void _outputHelpIfRequested(List<String> args) {
    final helpOption = _getHelpOption();
    final helpRequested =
        helpOption != null && args.any((arg) => helpOption.is_(arg));
    if (helpRequested) {
      outputHelp();
      _exit(0, 'commander.helpDisplayed', '(outputHelp)');
    }
  }

  void outputHelp({bool error = false}) {
    final helpWidth = error
        ? (io.stderr.hasTerminal ? io.stderr.terminalColumns : 80)
        : (io.stdout.hasTerminal ? io.stdout.terminalColumns : 80);
    final text = helpInformation(helpWidth);
    if (error) {
      io.stderr.write(text);
    } else {
      io.stdout.write(text);
    }
  }

  Never help({bool error = false}) {
    outputHelp(error: error);
    _exit(error ? 1 : 0, 'commander.help', '(outputHelp)');
  }

  Never error(String message, {int? exitCode, String? code}) {
    io.stderr.write('$message\n');
    _exit(exitCode ?? 1, code ?? 'commander.error', message);
  }

  Never optionMissingArgument(Option option) {
    error(
      "error: option '${option.flags}' argument missing",
      code: 'commander.optionMissingArgument',
    );
  }

  void unknownOption(String flag) {
    if (_allowUnknownOption) return;
    var suggestion = '';
    if (flag.startsWith('--')) {
      var candidateFlags = <String>[];
      Command? command = this;
      do {
        candidateFlags = [
          ...candidateFlags,
          for (final option in command!._visibleOptions())
            if (option.long != null) option.long!,
        ];
        command = command.parent;
      } while (command != null);
      suggestion = _suggestSimilar(flag, candidateFlags);
    }
    error(
      "error: unknown option '$flag'$suggestion",
      code: 'commander.unknownOption',
    );
  }

  Never unknownCommand() {
    final unknownName = args[0];
    final candidateNames = [for (final c in commands) c._name];
    if (_hasImplicitHelpCommand()) candidateNames.add('help');
    final suggestion = _suggestSimilar(unknownName, candidateNames);
    error(
      "error: unknown command '$unknownName'$suggestion",
      code: 'commander.unknownCommand',
    );
  }

  Never _exit(int exitCode, String code, String message) {
    _exitCallback?.call(CommanderError(exitCode, code, message));
    process.exit(exitCode);
  }

  // Help (commander's Help class).

  String usage() => [
    if (options.isNotEmpty || !_helpOptionDisabled) '[options]',
    if (commands.isNotEmpty) '[command]',
    for (final arg in registeredArguments) arg.humanReadableArgName(),
  ].join(' ');

  List<Option> _visibleOptions() {
    final visible = [...options];
    final helpOption = _getHelpOption();
    if (helpOption != null) {
      final removeShort = _findOption(helpOption.short!) != null;
      final removeLong = _findOption(helpOption.long!) != null;
      if (!removeShort && !removeLong) {
        visible.add(helpOption);
      } else if (!removeLong) {
        visible.add(Option(helpOption.long!, helpOption.description));
      } else if (!removeShort) {
        visible.add(Option(helpOption.short!, helpOption.description));
      }
    }
    return visible;
  }

  List<Argument> _visibleArguments() =>
      registeredArguments.any((a) => a.description.isNotEmpty)
      ? registeredArguments
      : [];

  List<(String, String)> _visibleCommands() => [
    for (final cmd in commands)
      (
        cmd._name +
            (cmd.options.isNotEmpty ? ' [options]' : '') +
            (cmd.registeredArguments.isNotEmpty
                ? ' ${cmd.registeredArguments.map((a) => a.humanReadableArgName()).join(' ')}'
                : ''),
        cmd._description,
      ),
    if (_hasImplicitHelpCommand())
      ('help [command]', 'display help for command'),
  ];

  String _commandUsage() {
    var ancestorCmdNames = '';
    for (var a = parent; a != null; a = a.parent) {
      ancestorCmdNames = '${a._name} $ancestorCmdNames';
    }
    return '$ancestorCmdNames$_name ${usage()}';
  }

  String helpInformation([int helpWidth = 80]) {
    final optionItems = [
      for (final o in _visibleOptions())
        (
          o.flags,
          o.description +
              (!identical(o.defaultValue, _omitted) &&
                      (o.required ||
                          o.optional ||
                          (o.isBoolean() && o.defaultValue is bool))
                  ? ' (default: ${jsonEncode(o.defaultValue)})'
                  : ''),
        ),
    ];
    final argumentItems = [
      for (final a in _visibleArguments()) (a.name(), a.description),
    ];
    final commandItems = _visibleCommands();
    var termWidth = 0;
    for (final item in [...optionItems, ...argumentItems, ...commandItems]) {
      if (item.$1.length > termWidth) termWidth = item.$1.length;
    }
    const itemIndentWidth = 2;
    const itemSeparatorWidth = 2;
    String formatItem(String term, String description) {
      if (description.isNotEmpty) {
        final fullText =
            '${term.padRight(termWidth + itemSeparatorWidth)}$description';
        return _wrap(
          fullText,
          helpWidth - itemIndentWidth,
          termWidth + itemSeparatorWidth,
        );
      }
      return term;
    }

    String formatList(List<String> textArray) => textArray
        .join('\n')
        .replaceAll(RegExp(r'^', multiLine: true), ' ' * itemIndentWidth);

    var output = ['Usage: ${_commandUsage()}', ''];
    if (_description.isNotEmpty) {
      output = [...output, _wrap(_description, helpWidth, 0), ''];
    }
    final argumentList = [for (final (t, d) in argumentItems) formatItem(t, d)];
    if (argumentList.isNotEmpty) {
      output = [...output, 'Arguments:', formatList(argumentList), ''];
    }
    final optionList = [for (final (t, d) in optionItems) formatItem(t, d)];
    if (optionList.isNotEmpty) {
      output = [...output, 'Options:', formatList(optionList), ''];
    }
    final commandList = [for (final (t, d) in commandItems) formatItem(t, d)];
    if (commandList.isNotEmpty) {
      output = [...output, 'Commands:', formatList(commandList), ''];
    }
    return output.join('\n');
  }
}

String _wrap(String str, int width, int indent, [int minColumnWidth = 40]) {
  const indents = ' \\f\\t\\v\u00a0\u1680\u2000-\u200a\u202f\u205f\u3000\ufeff';
  final manualIndent = RegExp('[\\n][$indents]+');
  if (manualIndent.hasMatch(str)) return str;
  final columnWidth = width - indent;
  if (columnWidth < minColumnWidth) return str;

  final leadingStr = str.substring(0, indent);
  final columnText = str.substring(indent).replaceFirst('\r\n', '\n');
  final indentString = ' ' * indent;
  const zeroWidthSpace = '\u200B';
  const breaks = '\\s$zeroWidthSpace';
  final regex = RegExp(
    '\n|.{1,${columnWidth - 1}}([$breaks]|\$)|[^$breaks]+?([$breaks]|\$)',
  );
  final lines = [for (final m in regex.allMatches(columnText)) m[0]!]
    ..removeWhere((l) => l.isEmpty);
  final out = <String>[];
  for (final (i, line) in lines.indexed) {
    if (line == '\n') {
      out.add('');
    } else {
      out.add((i > 0 ? indentString : '') + line.trimRight());
    }
  }
  return leadingStr + out.join('\n');
}

const int _maxDistance = 3;

int _editDistance(String a, String b) {
  if ((a.length - b.length).abs() > _maxDistance) {
    return a.length > b.length ? a.length : b.length;
  }
  final d = [
    for (var i = 0; i <= a.length; i++) List<int>.filled(b.length + 1, 0),
  ];
  for (var i = 0; i <= a.length; i++) {
    d[i][0] = i;
  }
  for (var j = 0; j <= b.length; j++) {
    d[0][j] = j;
  }
  for (var j = 1; j <= b.length; j++) {
    for (var i = 1; i <= a.length; i++) {
      final cost = a[i - 1] == b[j - 1] ? 0 : 1;
      var v = d[i - 1][j] + 1;
      if (d[i][j - 1] + 1 < v) v = d[i][j - 1] + 1;
      if (d[i - 1][j - 1] + cost < v) v = d[i - 1][j - 1] + cost;
      d[i][j] = v;
      if (i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1]) {
        if (d[i - 2][j - 2] + 1 < d[i][j]) d[i][j] = d[i - 2][j - 2] + 1;
      }
    }
  }
  return d[a.length][b.length];
}

String _suggestSimilar(String word, List<String> candidates) {
  if (candidates.isEmpty) return '';
  candidates = candidates.toSet().toList();
  final searchingOptions = word.startsWith('--');
  if (searchingOptions) {
    word = word.substring(2);
    candidates = [for (final c in candidates) c.substring(2)];
  }
  var similar = <String>[];
  var bestDistance = _maxDistance;
  const minSimilarity = 0.4;
  for (final candidate in candidates) {
    if (candidate.length <= 1) continue;
    final distance = _editDistance(word, candidate);
    final length = word.length > candidate.length
        ? word.length
        : candidate.length;
    final similarity = (length - distance) / length;
    if (similarity > minSimilarity) {
      if (distance < bestDistance) {
        bestDistance = distance;
        similar = [candidate];
      } else if (distance == bestDistance) {
        similar.add(candidate);
      }
    }
  }
  similar.sort();
  if (searchingOptions) {
    similar = [for (final c in similar) '--$c'];
  }
  if (similar.length > 1) {
    return '\n(Did you mean one of ${similar.join(', ')}?)';
  }
  if (similar.length == 1) {
    return '\n(Did you mean ${similar[0]}?)';
  }
  return '';
}
