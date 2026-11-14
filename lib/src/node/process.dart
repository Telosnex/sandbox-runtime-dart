// Node process values reproduced for the ported files. Overrides let tests
// model upstream tests which temporarily replace process.platform/env/cwd.
import 'dart:async';
import 'dart:convert';
import 'dart:ffi';
import 'dart:io' as io;
import 'dart:io'
    show Directory, Platform, ProcessInfo, ProcessSignal, SignalException;

import 'package:ffi/ffi.dart';

import 'child_process.dart' as child_process;
import 'errno.dart';
import 'events.dart' show applyListener;
import 'stream.dart' as stream;

String? _platformOverride;
Map<String, String>? _envOverride;
String? _cwdOverride;

typedef _GetuidNative = Uint32 Function();
typedef _GetuidDart = int Function();

int Function()? _loadGetuid() {
  if (Platform.isWindows) return null;
  try {
    return DynamicLibrary.process().lookupFunction<_GetuidNative, _GetuidDart>(
      'getuid',
    );
  } on ArgumentError {
    return null;
  }
}

/// Node's `process.getuid`. A nullable variable so a test can replace it as
/// upstream does with `spyOn(process, 'getuid')`; Node does not expose it on
/// Windows.
int Function()? getuid = _loadGetuid();

int Function()? _loadGeteuid() {
  if (Platform.isWindows) return null;
  try {
    return DynamicLibrary.process().lookupFunction<_GetuidNative, _GetuidDart>(
      'geteuid',
    );
  } on ArgumentError {
    return null;
  }
}

/// Node's `process.geteuid`; null on Windows, as in Node.
int Function()? geteuid = _loadGeteuid();

/// Node's `process.pid`.
int get pid => io.pid;

/// Node's `process.argv`: `[runtime, script, ...args]`. Dart exposes the
/// command-line arguments only to `main`; an entry point stores them here.
List<String> argv = [Platform.resolvedExecutable, Platform.script.toFilePath()];

/// Node's `process.version`. This runtime is the Dart VM, so the value is the
/// Dart SDK version in Node's `v`-prefixed form.
String get version => 'v${Platform.version.split(' ').first}';

/// Node's `process.versions`: `node` is absent; `dart` names the runtime.
/// `versions['bun']` is null, as upstream's Bun probes expect.
Map<String, String> get versions => {'dart': Platform.version.split(' ').first};

/// Node's `process.memoryUsage()`. Only `rss` is measurable from Dart.
({int rss}) memoryUsage() => (rss: ProcessInfo.currentRss);

/// Node's `process.stdout` / `process.stderr`: `write(String | bytes)`.
class WriteStream extends stream.Writable {
  WriteStream._(this._sink) : super(autoDestroy: false);
  final io.Stdout _sink;

  @override
  void writeImpl(Object chunk, String encoding, Function callback) {
    if (chunk is List<int>) {
      _sink.add(chunk);
    } else {
      _sink.write(chunk);
    }
    _sink.flush().then(
      (_) => applyListener(callback, const []),
      onError: (Object error) => applyListener(callback, [error]),
    );
  }

  bool get isTTY => _sink.hasTerminal;
  int? get columns => _sink.hasTerminal ? _sink.terminalColumns : null;
}

final WriteStream stdout = WriteStream._(io.stdout);
final WriteStream stderr = WriteStream._(io.stderr);

/// Node's `process.stdin`: read lazily, only once a caller reads or pipes it.
final stream.Readable stdin = stream.Readable.from(io.stdin, objectMode: false);

/// Node's `process.kill(pid, signal)`.
bool kill(int pid, [Object signal = 'SIGTERM']) =>
    child_process.killPid(pid, signal);

/// Node's `process.exitCode`.
int? exitCode;

/// Node's `process.exit(code)`: runs the 'exit' listeners, then exits.
/// Dart cannot observe a natural end of `main`, so 'exit' listeners run
/// only through this call.
Never exit([int? code]) {
  final status = code ?? exitCode ?? 0;
  exitCode = status;
  if (!_exiting) {
    _exiting = true;
    for (final l in List.of(_listeners['exit'] ?? const <_Listener>[])) {
      if (l.once) _listeners['exit']!.remove(l);
      _call(l.fn, status);
    }
  }
  io.exit(exitCode ?? status);
}

bool _exiting = false;

class _Listener {
  _Listener(this.fn, this.once);
  final Function fn;
  final bool once;
}

final Map<String, List<_Listener>> _listeners = {};
final Map<String, StreamSubscription<ProcessSignal>> _signalWatches = {};

void _call(Function fn, Object? arg) {
  if (fn is void Function()) {
    fn();
  } else {
    (fn as dynamic)(arg);
  }
}

ProcessSignal? _signal(String event) => switch (event) {
  'SIGINT' => ProcessSignal.sigint,
  'SIGTERM' => ProcessSignal.sigterm,
  'SIGHUP' => ProcessSignal.sighup,
  'SIGUSR1' => ProcessSignal.sigusr1,
  'SIGUSR2' => ProcessSignal.sigusr2,
  'SIGWINCH' => ProcessSignal.sigwinch,
  'SIGQUIT' => ProcessSignal.sigquit,
  _ => null,
};

void _add(String event, Function fn, bool once) {
  (_listeners[event] ??= []).add(_Listener(fn, once));
  final signal = _signal(event);
  if (signal != null && !_signalWatches.containsKey(event)) {
    // As in Node, a listener replaces the default action (termination).
    // Node accepts a listener for a signal that the platform does not
    // deliver (SIGTERM on Windows) and never calls it. dart:io reports a
    // SignalException on the stream instead, which is dropped here.
    _signalWatches[event] = signal.watch().listen(
      (_) {
        for (final l in List.of(_listeners[event] ?? const <_Listener>[])) {
          if (l.once) off(event, l.fn);
          _call(l.fn, event);
        }
      },
      onError: (Object error) {
        if (error is! SignalException) throw error;
      },
    );
  } else if (signal == null &&
      !_errorEvents.contains(event) &&
      event != 'exit') {
    throw UnsupportedError('process.on($event)');
  }
}

const _errorEvents = {'unhandledRejection', 'uncaughtException'};

/// Dispatches an uncaught async error to 'unhandledRejection' /
/// 'uncaughtException' listeners (listener gets `(error, stack)`).
/// Returns true if any listener handled it.
bool dispatchUncaught(Object error, StackTrace stack) {
  var handled = false;
  for (final event in _errorEvents) {
    for (final l in List.of(_listeners[event] ?? const <_Listener>[])) {
      handled = true;
      if (l.once) off(event, l.fn);
      (l.fn as dynamic)(error, stack);
    }
  }
  return handled;
}

/// Runs [body] in an error zone that feeds [dispatchUncaught]. Limits: Dart
/// cannot hook the root zone, so only code started through this call (an
/// entry point) is covered; Node's rejection-vs-exception distinction is
/// not made (both events fire); with no listener the error is rethrown to
/// the parent zone.
R? runWithProcessErrorHandlers<R>(R Function() body) =>
    runZonedGuarded(body, (e, st) {
      if (!dispatchUncaught(e, st)) Zone.root.handleUncaughtError(e, st);
    });

/// Node's `process.on(event, fn)` for 'exit' and the signal events.
void on(String event, Function listener) => _add(event, listener, false);

/// Node's `process.once(event, fn)`.
void once(String event, Function listener) => _add(event, listener, true);

/// Node's `process.off(event, fn)`. With no listener left for a signal, its
/// default action is restored.
void off(String event, Function listener) {
  final list = _listeners[event];
  if (list == null) return;
  final i = list.lastIndexWhere((l) => l.fn == listener);
  if (i >= 0) list.removeAt(i);
  if (list.isEmpty) {
    _listeners.remove(event);
    unawaited(_signalWatches.remove(event)?.cancel());
  }
}

int listenerCount(String event) => _listeners[event]?.length ?? 0;

/// The Node `process.platform` spelling for the current Dart host.
String get platform =>
    _platformOverride ??
    (Platform.isMacOS
        ? 'darwin'
        : Platform.isLinux
        ? 'linux'
        : Platform.isWindows
        ? 'win32'
        : Platform.operatingSystem);

/// The Node `process.arch` spelling (`x64`, `arm64`, `ia32`, ...).
String get arch => Abi.current().toString().split('_').last;

/// Node's live `process.env` map, unless a test has supplied an override.
/// Node's live, mutable `process.env`, unless a test supplied an override.
Map<String, String> get env => _envOverride ?? _env;
final Map<String, String> _env = Map.of(Platform.environment);

typedef _GetcwdNative = Pointer<Uint8> Function(Pointer<Uint8>, UintPtr);
typedef _GetcwdDart = Pointer<Uint8> Function(Pointer<Uint8>, int);
typedef _ErrnoLocationNative = Pointer<Int32> Function();
typedef _ErrnoLocationDart = Pointer<Int32> Function();

String _cwd() {
  if (Platform.isWindows) return Directory.current.path;
  final libc = DynamicLibrary.process();
  final getcwd = libc.lookupFunction<_GetcwdNative, _GetcwdDart>('getcwd');
  final errnoLocation = libc
      .lookupFunction<_ErrnoLocationNative, _ErrnoLocationDart>(
        Platform.isMacOS ? '__error' : '__errno_location',
      );
  for (var size = 4096; ; size *= 2) {
    final buffer = calloc<Uint8>(size);
    try {
      if (getcwd(buffer, size) == nullptr) {
        final errno = errnoLocation().value;
        if (errno == 34) continue; // ERANGE: the name needs a larger buffer.
        final error = nodeError(codeForErrno(errno), 'uv_cwd', '');
        // Unlike a file call, uv_cwd has no path argument in Node's error.
        throw NodeError(
          error.message.replaceFirst(RegExp(r" ''$"), ''),
          code: error.code,
          syscall: 'uv_cwd',
          errno: -errno,
        );
      }
      var length = 0;
      while (buffer[length] != 0) {
        length++;
      }
      // Node replaces malformed UTF-8 in cwd, unlike dart:io's fatal decoder.
      return utf8.decode(buffer.asTypedList(length), allowMalformed: true);
    } finally {
      calloc.free(buffer);
    }
  }
}

/// Node's `process.cwd()` value, unless a test has supplied an override.
String cwd() => _cwdOverride ?? _cwd();

/// Override `process.platform` in tests; pass null to use the host value.
void setPlatformForTesting(String? value) => _platformOverride = value;

/// Override `process.env` in tests; pass null to use the host environment.
void setEnvForTesting(Map<String, String>? value) => _envOverride = value;

/// Node's `process.chdir`. A variable so a test can replace it.
void Function(String directory) chdir = _chdir;

void _chdir(String directory) {
  Directory.current = directory;
  _cwdOverride = null;
}

/// Override `process.cwd()` in tests; pass null to use `Directory.current`.
void setCwdForTesting(String? value) => _cwdOverride = value;
