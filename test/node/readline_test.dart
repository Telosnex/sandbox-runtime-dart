import 'dart:convert';

import 'package:sandbox_runtime/src/node/events.dart';
import 'package:sandbox_runtime/src/node/readline.dart' as readline;
import 'package:test/test.dart';

class _Input extends EventEmitter {
  bool resumed = false;
  bool paused = false;
  void resume() => resumed = true;
  void pause() => paused = true;
}

void main() {
  // Expected values come from Node v22: readline.createInterface({ input:
  // a PassThrough, crlfDelay: Infinity }) fed the same chunks.
  List<String> feed(List<Object> chunks, List<String> events) {
    final input = _Input();
    final lines = <String>[];
    final rl = readline.createInterface(
      input: input,
      crlfDelay: double.infinity,
    );
    rl.on('line', (String l) => lines.add(l));
    rl.on('close', () => events.add('close'));
    expect(input.resumed, isTrue);
    for (final c in chunks) {
      input.emit('data', c);
    }
    input.emit('end');
    return lines;
  }

  test('splits on \\n, \\r\\n and \\r, keeping empty lines', () {
    final events = <String>[];
    expect(feed(['a\nb\r\nc\rd\n\ne'], events), ['a', 'b', 'c', 'd', '', 'e']);
    expect(events, ['close']);
  });

  test('a \\r\\n split across chunks is one break', () {
    expect(feed(['x\r', '\ny\n'], []), ['x', 'y']);
  });

  test('a UTF-8 sequence split across byte chunks decodes whole', () {
    final bytes = utf8.encode('é\n');
    expect(feed([bytes.sublist(0, 1), bytes.sublist(1)], []), ['é']);
  });

  test('no trailing line for input ending in a newline', () {
    expect(feed(['a\n'], []), ['a']);
  });

  test('an input error is re-emitted on the interface', () {
    final input = _Input();
    final rl = readline.createInterface(input: input);
    Object? seen;
    rl.on('error', (Object e) => seen = e);
    final err = StateError('boom');
    input.emit('error', err);
    expect(seen, same(err));
  });

  test('close() emits close once, pauses input and stops lines', () {
    final input = _Input();
    final rl = readline.createInterface(input: input);
    final lines = <String>[];
    var closes = 0;
    rl.on('line', (String l) => lines.add(l));
    rl.on('close', () => closes++);
    rl.close();
    rl.close();
    input.emit('data', 'late\n');
    expect(closes, 1);
    expect(input.paused, isTrue);
    expect(lines, isEmpty);
  });
}
