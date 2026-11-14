// `node:events`: the EventEmitter base class that the net, tls and http shims
// extend, and the `once` helper.
//
// A listener receives as many of the emitted arguments as it accepts. In Node
// a listener ignores extra arguments and reads a missing one as undefined;
// here a missing one is null.
//
// Node throws when an 'error' event has no listener, which ends the process.
// Here, the error goes to the zone's uncaught-error handler; in a test, that
// fails the test. A listener that throws is reported the same way, and the
// remaining listeners still run.
import 'dart:async';

class _Listener {
  _Listener(this.fn, {required this.once});
  final Function fn;
  final bool once;
}

class EventEmitter {
  final Map<String, List<_Listener>> _events = {};

  EventEmitter on(String event, Function listener) {
    (_events[event] ??= []).add(_Listener(listener, once: false));
    return this;
  }

  EventEmitter addListener(String event, Function listener) =>
      on(event, listener);

  EventEmitter prependListener(String event, Function listener) {
    (_events[event] ??= []).insert(0, _Listener(listener, once: false));
    return this;
  }

  EventEmitter once(String event, Function listener) {
    (_events[event] ??= []).add(_Listener(listener, once: true));
    return this;
  }

  /// Removes the most recently added instance of [listener], as Node does.
  EventEmitter off(String event, Function listener) {
    final list = _events[event];
    if (list == null) return this;
    for (var i = list.length - 1; i >= 0; i--) {
      if (list[i].fn == listener) {
        list.removeAt(i);
        break;
      }
    }
    if (list.isEmpty) _events.remove(event);
    return this;
  }

  EventEmitter removeListener(String event, Function listener) =>
      off(event, listener);

  EventEmitter removeAllListeners([String? event]) {
    if (event == null) {
      _events.clear();
    } else {
      _events.remove(event);
    }
    return this;
  }

  /// Node EventEmitter.eventNames().
  List<String> eventNames() => _events.keys.toList();

  int listenerCount(String event) => _events[event]?.length ?? 0;

  List<Function> listeners(String event) => [
    for (final entry in _events[event] ?? const <_Listener>[]) entry.fn,
  ];

  bool emit(String event, [Object? a, Object? b, Object? c, Object? d]) {
    final args = trimArgs([a, b, c, d]);
    final list = _events[event];
    if (list == null || list.isEmpty) {
      if (event == 'error') {
        final error = args.isEmpty || args[0] == null
            ? StateError('Unhandled error.')
            : args[0]!;
        Zone.current.handleUncaughtError(
          error,
          (error is Error ? error.stackTrace : null) ?? StackTrace.current,
        );
      }
      return false;
    }
    for (final entry in List<_Listener>.of(list)) {
      if (entry.once) {
        final current = _events[event];
        if (current == null || !current.remove(entry)) continue;
        if (current.isEmpty) _events.remove(event);
      }
      try {
        applyListener(entry.fn, args);
      } catch (error, stack) {
        Zone.current.handleUncaughtError(error, stack);
      }
    }
    return true;
  }
}

/// Drop trailing nulls: the arguments an emit call did not pass.
List<Object?> trimArgs(List<Object?> args) {
  final out = List<Object?>.of(args);
  while (out.isNotEmpty && out.last == null) {
    out.removeLast();
  }
  return out;
}

/// Call [listener] with as many of [args] as it accepts. Pad with null when
/// it requires more.
void applyListener(Function listener, List<Object?> args) {
  for (var n = args.length; n >= 0; n--) {
    if (_accepts(listener, n)) {
      Function.apply(listener, args.sublist(0, n));
      return;
    }
  }
  for (var n = args.length + 1; n <= 6; n++) {
    if (_accepts(listener, n)) {
      Function.apply(listener, [
        ...args,
        ...List<Object?>.filled(n - args.length, null),
      ]);
      return;
    }
  }
  Function.apply(listener, args);
}

bool _accepts(Function f, int n) => switch (n) {
  0 => f is Function(),
  1 => f is Function(Never),
  2 => f is Function(Never, Never),
  3 => f is Function(Never, Never, Never),
  4 => f is Function(Never, Never, Never, Never),
  5 => f is Function(Never, Never, Never, Never, Never),
  6 => f is Function(Never, Never, Never, Never, Never, Never),
  _ => false,
};

/// Node `events.once(emitter, name)`: completes with the event's arguments,
/// or fails with the first 'error' event.
Future<List<Object?>> once(EventEmitter emitter, String name) {
  final completer = Completer<List<Object?>>();
  late final Function onError;
  void onEvent([Object? a, Object? b, Object? c, Object? d]) {
    if (name != 'error') emitter.off('error', onError);
    if (!completer.isCompleted) completer.complete(trimArgs([a, b, c, d]));
  }

  onError = ([Object? error]) {
    emitter.off(name, onEvent);
    if (!completer.isCompleted) {
      completer.completeError(error ?? StateError('Unhandled error.'));
    }
  };
  emitter.once(name, onEvent);
  if (name != 'error') emitter.once('error', onError);
  return completer.future;
}
