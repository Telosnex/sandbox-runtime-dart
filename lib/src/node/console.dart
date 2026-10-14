// The Node `console` globals used by the port. No upstream counterpart.

import 'dart:io';

const Object _omitted = Object();

typedef ConsoleMethod =
    void Function([
      Object? first,
      Object? second,
      Object? third,
      Object? fourth,
    ]);

/// Node's `console.warn`. A variable so a test can replace it, as upstream's
/// tests do with `spyOn(console, 'warn')`.
ConsoleMethod warn = _warn;

/// Node's `console.error`. A variable so a test can replace it, as upstream's
/// tests do with `spyOn(console, 'error')`.
ConsoleMethod error = _error;

/// Node's `console.log`. A variable so a test can replace it, as upstream's
/// tests do with `spyOn(console, 'log')`.
ConsoleMethod log = _log;

void _warn([
  Object? first = _omitted,
  Object? second = _omitted,
  Object? third = _omitted,
  Object? fourth = _omitted,
]) => _write(stderr, [first, second, third, fourth]);

void _error([
  Object? first = _omitted,
  Object? second = _omitted,
  Object? third = _omitted,
  Object? fourth = _omitted,
]) => _write(stderr, [first, second, third, fourth]);

void _log([
  Object? first = _omitted,
  Object? second = _omitted,
  Object? third = _omitted,
  Object? fourth = _omitted,
]) => _write(stdout, [first, second, third, fourth]);

void _write(IOSink sink, List<Object?> arguments) {
  while (arguments.isNotEmpty && identical(arguments.last, _omitted)) {
    arguments.removeLast();
  }
  sink.writeln(arguments.join(' '));
}
