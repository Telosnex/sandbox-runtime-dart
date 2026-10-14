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
}
