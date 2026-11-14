import 'package:sandbox_runtime/src/node/commander.dart';
import 'package:test/test.dart';

// Expected values were produced by commander 12.1.0 (node_modules).
Command _program(void Function(List<Object?> a) onAction, {bool proxy = true}) {
  final p = Command();
  p.name('srt').description('d').version('1.0.0');
  if (proxy) {
    p
        .command('proxy')
        .description('Run proxy')
        .allowUnknownOption()
        .helpOption(false)
        .argument('[args...]')
        .action((a) async {});
  }
  p
      .argument('[command...]', 'command to run')
      .option('-d, --debug', 'enable debug logging')
      .option('-s, --settings <path>', 'path to config')
      .option('-c <command>', 'run string')
      .option(
        '--control-fd <fd>',
        'read config updates from an inherited file descriptor >= 3 (JSON '
            'lines protocol; give srt a dedicated read-only end — see the '
            'README)',
        (v) => num.parse(v),
      )
      .allowUnknownOption()
      .action((a) async => onAction(a));
  return p;
}

void main() {
  test('help text matches commander 12.1.0', () {
    expect(
      _program((_) {}).helpInformation(),
      'Usage: srt [options] [command] [command...]\n\nd\n\nArguments:\n'
      '  command                command to run\n\nOptions:\n'
      '  -V, --version          output the version number\n'
      '  -d, --debug            enable debug logging\n'
      '  -s, --settings <path>  path to config\n'
      '  -c <command>           run string\n'
      '  --control-fd <fd>      read config updates from an inherited file '
      'descriptor\n'
      '                         >= 3 (JSON lines protocol; give srt a '
      'dedicated\n'
      '                         read-only end — see the README)\n'
      '  -h, --help             display help for command\n\n'
      'Commands:\n  proxy [args...]        Run proxy\n',
    );
  });

  test('unknown options pass through, variadic collects, -- kept', () async {
    List<Object?>? got;
    await _program((a) => got = a).parse([
      'x', 'y', '-d', '--foo', 'a', 'b', '--', '-c', //
    ]);
    expect((got![0] as List).cast<String>(), [
      'x',
      'y',
      '--foo',
      'a',
      'b',
      '--',
      '-c',
    ]);
    expect(got![1], {'debug': true});
  });

  test('value options and parser', () async {
    List<Object?>? got;
    await _program(
      (a) => got = a,
    ).parse(['-s', 'f.json', '--control-fd=5', '-c', 'ls']);
    expect(got![1], {'settings': 'f.json', 'controlFd': 5, 'c': 'ls'});
  });

  test(
    'repeatable option parser receives the default and prior values',
    () async {
      final p = Command();
      p.option(
        '--profile-exclude <path>',
        'excluded paths',
        null,
        <String>[],
        (v, acc) => [...(acc as List<String>), v],
      );
      p.option(
        '--profile-include <path>',
        'included paths',
        null,
        <String>[],
        (v, acc) => [...(acc as List<String>), v],
      );
      await p.parse([
        '--profile-exclude',
        'first',
        '--profile-exclude=second',
        '--profile-exclude',
        'first',
      ]);
      expect(p.opts(), {
        'profileExclude': ['first', 'second', 'first'],
        'profileInclude': <String>[],
      });
      expect(p.helpInformation(), contains('excluded paths (default: [])'));
      expect(p.helpInformation(), contains('included paths (default: [])'));
    },
  );

  // Expected codes/messages from commander 12.1.0 with exitOverride().
  Command strict() {
    final p = Command();
    p.name('srt').description('d').version('1.0.0').exitOverride();
    p
        .command('proxy')
        .description('Run proxy')
        .allowUnknownOption()
        .helpOption(false)
        .argument('[args...]')
        .action((a) async {});
    p
        .argument('[command...]', 'command to run')
        .option('-d, --debug', 'enable debug logging')
        .option('-s, --settings <path>', 'path to config')
        .option('-c <command>', 'run string')
        .option('--control-fd <fd>', 'x', (v) {
          final n = int.tryParse(v);
          if (n == null || n < 3) throw InvalidArgumentError('must be >= 3');
          return n;
        })
        .action((a) async {});
    return p;
  }

  Future<CommanderError?> run(List<String> argv) async {
    try {
      await strict().parse(argv);
    } on CommanderError catch (e) {
      return e;
    }
    return null;
  }

  test('exitOverride: --version', () async {
    final e = (await run(['--version']))!;
    expect([e.code, e.exitCode], ['commander.version', 0]);
  });

  test('exitOverride: -h', () async {
    final e = (await run(['-h']))!;
    expect([e.code, e.exitCode], ['commander.helpDisplayed', 0]);
  });

  test('unknown option', () async {
    final e = (await run(['--bogus']))!;
    expect([e.code, e.exitCode], ['commander.unknownOption', 1]);
    expect(e.message, "error: unknown option '--bogus'");
  });

  test('unknown option suggests a similar one', () async {
    final e = (await run(['--debg']))!;
    expect([e.code, e.exitCode], ['commander.unknownOption', 1]);
    expect(e.message, contains('(Did you mean --debug?)'));
  });

  test('InvalidArgumentError from an option parser', () async {
    for (final v in ['1', 'x']) {
      final e = (await run(['--control-fd', v]))!;
      expect([e.code, e.exitCode], ['commander.invalidArgument', 1]);
      expect(
        e.message,
        "error: option '--control-fd <fd>' argument '$v' is invalid. "
        'must be >= 3',
      );
    }
  });

  test('missing option argument', () async {
    final e = (await run(['-s']))!;
    expect([e.code, e.exitCode], ['commander.optionMissingArgument', 1]);
    expect(e.message, "error: option '-s, --settings <path>' argument missing");
  });

  test('subcommand with helpOption(false) takes -h as an argument', () async {
    expect(await run(['proxy', '-h']), isNull);
  });
}
