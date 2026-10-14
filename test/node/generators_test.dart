import 'package:sandbox_runtime/src/node/generators.dart';
import 'package:test/test.dart';

Iterable<Step<int>> inner(int n) sync* {
  for (var i = 0; i < n; i++) {
    yield Pause();
  }
  yield Done(n * 10);
  return;
}

Iterable<Step<String>> outer() sync* {
  final a = Box<int>();
  yield* yieldStar(inner(2), a);
  final b = Box<int>();
  yield* yieldStar(inner(1), b);
  yield Done('${a.value}+${b.value}');
  return;
}

void main() {
  test('yieldStar forwards pauses and captures the result', () {
    final steps = outer().toList();
    expect(steps.whereType<Pause<String>>(), hasLength(3));
    expect((steps.last as Done<String>).value, '20+10');
  });

  test('yieldStar throws when the inner steps end without Done', () {
    Iterable<Step<int>> bad() sync* {
      yield Pause();
    }
    expect(() => yieldStar(bad(), Box<int>()).toList(), throwsStateError);
  });

  test('yieldStar throws when the inner steps yield after Done', () {
    Iterable<Step<int>> bad() sync* {
      yield Done(1);
      yield Pause();
    }
    expect(() => yieldStar(bad(), Box<int>()).toList(), throwsStateError);
  });
}
