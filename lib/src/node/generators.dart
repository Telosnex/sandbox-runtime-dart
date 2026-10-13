// Shim for TS generators that return a value (no upstream counterpart).
// See PORT_WORKLOG.md "Generators that return a value (`Steps<T>`)".

/// One step of a TS `Generator<undefined, T, undefined>`.
sealed class Step<T> {
  const Step();
}

/// A TS `yield` (or `yield undefined`): work can pause here.
final class Pause<T> extends Step<T> {
  const Pause();
}

/// A TS `return value`: the generator's result. Always the last step.
final class Done<T> extends Step<T> {
  const Done(this.value);
  final T value;
}

/// Holds the value of a TS `const x = yield* g()`.
class Box<T> {
  late T value;
}

/// TS `yield* steps` inside another generator: re-yields every pause of
/// [steps] and stores its result in [into]. Throws [StateError] if [steps]
/// ends without a [Done], or yields after it.
Iterable<Step<R>> yieldStar<T, R>(Iterable<Step<T>> steps, Box<T> into) sync* {
  var done = false;
  for (final step in steps) {
    if (done) throw StateError('Steps yielded after Done');
    switch (step) {
      case Pause<T>():
        yield Pause<R>();
      case Done<T>(:final value):
        into.value = value;
        done = true;
    }
  }
  if (!done) throw StateError('Steps ended without Done');
}
