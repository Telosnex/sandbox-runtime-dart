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

  void _abortWith([Object? reason]) {
    if (aborted) return;
    _reason = reason ?? AbortError();
    _abort.complete();
  }
}

/// Creates and aborts [AbortSignal]s, mirroring Node's `AbortController`.
class AbortController {
  AbortController() : signal = AbortSignal._();

  final AbortSignal signal;

  void abort([Object? reason]) => signal._abortWith(reason);
}
