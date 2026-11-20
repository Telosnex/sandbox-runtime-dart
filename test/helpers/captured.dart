// Ported from sandbox-runtime test/helpers/captured.ts @ 0bbebed.
class Captured<T> {
  Captured() : value = null;
  T? value;

  /// Forget the recorded value, so the next read is about the next request.
  void clear() {
    value = null;
  }
}

/// A slot an upstream server's request handler records into and the test that
/// triggered the request reads back.
///
/// A plain `let` does not type: the compiler cannot see a callback's write, so
/// a test that clears the variable before its request narrows it to
/// `undefined` for the rest of that test and every read afterwards is an error
/// on `never`. Clearing through a method leaves the declared type in place.
Captured<T> captured<T>() => Captured<T>();
