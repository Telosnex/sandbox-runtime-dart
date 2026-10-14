// Small AbortController boundary for APIs ported from Node's AbortSignal.
import 'dart:async';

/// The error emitted when an operation is cancelled through [AbortSignal].
class AbortError extends Error {
  AbortError([this.message = 'The operation was aborted']);

  final String message;

  @override
  String toString() => 'AbortError: $message';
}

/// A cancellation signal with the Node `AbortSignal` surface used by the port.
class AbortSignal {
  AbortSignal._();

  final Completer<void> _abort = Completer<void>();
  Object? _reason;

  bool get aborted => _abort.isCompleted;
  Object? get reason => _reason;
  Future<void> get whenAborted => _abort.future;

  final List<(Function, bool)> _listeners = [];

  /// Node's `signal.throwIfAborted()`.
  void throwIfAborted() {
    if (aborted) throw _reason!;
  }

  /// `addEventListener('abort', fn, {once})`. Listeners run synchronously in
  /// order when the signal aborts; each runs at most once since a signal
  /// aborts once. A listener added twice is kept once, as in the DOM.
  void addEventListener(
    String type,
    Function listener, [
    Map<String, Object?> options = const {},
  ]) {
    if (type != 'abort') return;
    if (_listeners.any((l) => identical(l.$1, listener))) return;
    _listeners.add((listener, options['once'] == true));
  }

  void removeEventListener(String type, Function listener) {
    if (type != 'abort') return;
    _listeners.removeWhere((l) => identical(l.$1, listener));
  }

  void _abortWith([Object? reason]) {
    if (aborted) return;
    _reason = reason ?? AbortError();
    _abort.complete();
    final listeners = List.of(_listeners);
    _listeners.clear();
    for (final (fn, _) in listeners) {
      if (fn is void Function(Object?)) {
        fn(this);
      } else {
        (fn as void Function())();
      }
    }
  }
}

/// Creates and aborts [AbortSignal]s, mirroring Node's `AbortController`.
class AbortController {
  AbortController() : signal = AbortSignal._();

  final AbortSignal signal;

  void abort([Object? reason]) => signal._abortWith(reason);
}
