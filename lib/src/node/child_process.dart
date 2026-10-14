// Node `child_process` compatibility: spawn, spawnSync, execSync and exec as
// the ported files use them. No upstream counterpart.
//
// On POSIX hosts children are launched with posix_spawnp through FFI, so the
// pid is known synchronously (as Node's `child.pid` is), a launch failure
// keeps its errno, and spawnSync can feed `input`, honour `timeout` and
// route `stdio` without a helper process. Windows falls back to dart:io and
// refuses the options dart:io cannot honour.
import 'dart:async';
import 'dart:convert';
import 'dart:ffi';
import 'dart:io' as io;
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'buffer.dart';
import 'errno.dart';
import 'events.dart';
import 'process.dart' as process;

// --- libc bindings --------------------------------------------------------

final DynamicLibrary? _libc = io.Platform.isWindows
    ? null
    : DynamicLibrary.process();

typedef _SpawnpN =
    Int32 Function(
      Pointer<Int32>,
      Pointer<Utf8>,
      Pointer<Void>,
      Pointer<Void>,
      Pointer<Pointer<Utf8>>,
      Pointer<Pointer<Utf8>>,
    );
typedef _SpawnpD =
    int Function(
      Pointer<Int32>,
      Pointer<Utf8>,
      Pointer<Void>,
      Pointer<Void>,
      Pointer<Pointer<Utf8>>,
      Pointer<Pointer<Utf8>>,
    );
typedef _PtrN = Int32 Function(Pointer<Void>);
typedef _PtrD = int Function(Pointer<Void>);
typedef _PtrIntN = Int32 Function(Pointer<Void>, Int32);
typedef _PtrIntD = int Function(Pointer<Void>, int);
typedef _PtrShortN = Int32 Function(Pointer<Void>, Int16);
typedef _PtrIntIntN = Int32 Function(Pointer<Void>, Int32, Int32);
typedef _PtrIntIntD = int Function(Pointer<Void>, int, int);
typedef _AddOpenN =
    Int32 Function(Pointer<Void>, Int32, Pointer<Utf8>, Int32, Uint16);
typedef _AddOpenD = int Function(Pointer<Void>, int, Pointer<Utf8>, int, int);
typedef _PtrPtrN = Int32 Function(Pointer<Void>, Pointer<Void>);
typedef _PtrPtrD = int Function(Pointer<Void>, Pointer<Void>);
typedef _AddChdirN = Int32 Function(Pointer<Void>, Pointer<Utf8>);
typedef _AddChdirD = int Function(Pointer<Void>, Pointer<Utf8>);
typedef _PipeN = Int32 Function(Pointer<Int32>);
typedef _PipeD = int Function(Pointer<Int32>);
typedef _IntN = Int32 Function(Int32);
typedef _IntD = int Function(int);
typedef _RwN = IntPtr Function(Int32, Pointer<Uint8>, IntPtr);
typedef _RwD = int Function(int, Pointer<Uint8>, int);
typedef _PollN = Int32 Function(Pointer<Int32>, Uint32, Int32);
typedef _PollD = int Function(Pointer<Int32>, int, int);
typedef _WaitpidN = Int32 Function(Int32, Pointer<Int32>, Int32);
typedef _WaitpidD = int Function(int, Pointer<Int32>, int);
typedef _KillN = Int32 Function(Int32, Int32);
typedef _KillD = int Function(int, int);
typedef _FcntlN = Int32 Function(Int32, Int32, VarArgs<(Int32,)>);
typedef _FcntlD = int Function(int, int, int);

class _Libc {
  _Libc(DynamicLibrary l)
    : spawnp = l.lookupFunction<_SpawnpN, _SpawnpD>('posix_spawnp'),
      faInit = l.lookupFunction<_PtrN, _PtrD>('posix_spawn_file_actions_init'),
      faDestroy = l.lookupFunction<_PtrN, _PtrD>(
        'posix_spawn_file_actions_destroy',
      ),
      faDup2 = l.lookupFunction<_PtrIntIntN, _PtrIntIntD>(
        'posix_spawn_file_actions_adddup2',
      ),
      faClose = l.lookupFunction<_PtrIntN, _PtrIntD>(
        'posix_spawn_file_actions_addclose',
      ),
      faOpen = l.lookupFunction<_AddOpenN, _AddOpenD>(
        'posix_spawn_file_actions_addopen',
      ),
      attrInit = l.lookupFunction<_PtrN, _PtrD>('posix_spawnattr_init'),
      attrDestroy = l.lookupFunction<_PtrN, _PtrD>('posix_spawnattr_destroy'),
      attrFlags = l.lookupFunction<_PtrShortN, _PtrIntD>(
        'posix_spawnattr_setflags',
      ),
      attrSigDefault = l.lookupFunction<_PtrPtrN, _PtrPtrD>(
        'posix_spawnattr_setsigdefault',
      ),
      attrSigMask = l.lookupFunction<_PtrPtrN, _PtrPtrD>(
        'posix_spawnattr_setsigmask',
      ),
      sigfillset = l.lookupFunction<_PtrN, _PtrD>('sigfillset'),
      sigemptyset = l.lookupFunction<_PtrN, _PtrD>('sigemptyset'),
      pipe = l.lookupFunction<_PipeN, _PipeD>('pipe'),
      close = l.lookupFunction<_IntN, _IntD>('close'),
      read = l.lookupFunction<_RwN, _RwD>('read'),
      write = l.lookupFunction<_RwN, _RwD>('write'),
      poll = l.lookupFunction<_PollN, _PollD>('poll'),
      waitpid = l.lookupFunction<_WaitpidN, _WaitpidD>('waitpid'),
      kill = l.lookupFunction<_KillN, _KillD>('kill'),
      fcntl = l.lookupFunction<_FcntlN, _FcntlD>('fcntl'),
      errnoLocation = l
          .lookupFunction<Pointer<Int32> Function(), Pointer<Int32> Function()>(
            io.Platform.isMacOS ? '__error' : '__errno_location',
          ) {
    try {
      faChdir = l.lookupFunction<_AddChdirN, _AddChdirD>(
        'posix_spawn_file_actions_addchdir_np',
      );
    } on ArgumentError {
      faChdir = null;
    }
  }

  final _SpawnpD spawnp;
  final _PtrD faInit, faDestroy, attrInit, attrDestroy;
  final _PtrIntIntD faDup2;
  final _PtrIntD faClose, attrFlags;
  final _AddOpenD faOpen;
  late final _AddChdirD? faChdir;
  final _PtrPtrD attrSigDefault, attrSigMask;
  final _PtrD sigfillset, sigemptyset;
  final _PipeD pipe;
  final _IntD close;
  final _RwD read, write;
  final _PollD poll;
  final _WaitpidD waitpid;
  final _KillD kill;
  final _FcntlD fcntl;
  final Pointer<Int32> Function() errnoLocation;

  int get errno => errnoLocation().value;
}

final _Libc? _native = _libc == null ? null : _Libc(_libc!);

const _wnohang = 1;
const _pollIn = 0x1;
const _pollOut = 0x4;
const _pollErr = 0x8;
const _pollHup = 0x10;

// --- signals ----------------------------------------------------------------

const Map<String, int> _darwinSignals = {
  'SIGHUP': 1, 'SIGINT': 2, 'SIGQUIT': 3, 'SIGILL': 4, 'SIGTRAP': 5, //
  'SIGABRT': 6, 'SIGFPE': 8, 'SIGKILL': 9, 'SIGBUS': 10, 'SIGSEGV': 11,
  'SIGSYS': 12, 'SIGPIPE': 13, 'SIGALRM': 14, 'SIGTERM': 15, 'SIGURG': 16,
  'SIGSTOP': 17, 'SIGTSTP': 18, 'SIGCONT': 19, 'SIGCHLD': 20, 'SIGTTIN': 21,
  'SIGTTOU': 22, 'SIGIO': 23, 'SIGXCPU': 24, 'SIGXFSZ': 25,
  'SIGVTALRM': 26, 'SIGPROF': 27, 'SIGWINCH': 28, 'SIGINFO': 29,
  'SIGUSR1': 30, 'SIGUSR2': 31,
};

const Map<String, int> _linuxSignals = {
  'SIGHUP': 1, 'SIGINT': 2, 'SIGQUIT': 3, 'SIGILL': 4, 'SIGTRAP': 5, //
  'SIGABRT': 6, 'SIGBUS': 7, 'SIGFPE': 8, 'SIGKILL': 9, 'SIGUSR1': 10,
  'SIGSEGV': 11, 'SIGUSR2': 12, 'SIGPIPE': 13, 'SIGALRM': 14, 'SIGTERM': 15,
  'SIGSTKFLT': 16, 'SIGCHLD': 17, 'SIGCONT': 18, 'SIGSTOP': 19,
  'SIGTSTP': 20, 'SIGTTIN': 21, 'SIGTTOU': 22, 'SIGURG': 23, 'SIGXCPU': 24,
  'SIGXFSZ': 25, 'SIGVTALRM': 26, 'SIGPROF': 27, 'SIGWINCH': 28, 'SIGIO': 29,
  'SIGPWR': 30, 'SIGSYS': 31,
};

/// Node's `os.constants.signals` for the host.
Map<String, int> get signalNumbers =>
    io.Platform.isMacOS ? _darwinSignals : _linuxSignals;

/// The signal number for a Node signal name or number; throws Node's
/// ERR_UNKNOWN_SIGNAL otherwise.
int signalNumber(Object signal) {
  if (signal is int) return signal;
  final number = signalNumbers[signal];
  if (number == null) {
    throw NodeError('Unknown signal: $signal', code: 'ERR_UNKNOWN_SIGNAL');
  }
  return number;
}

String? signalName(int number) {
  for (final entry in signalNumbers.entries) {
    if (entry.value == number) return entry.key;
  }
  return null;
}

/// Send [signal] to [pid] with kill(2): Node's `process.kill`. Returns true;
/// a failure throws a Node error (`ESRCH`, `EPERM`).
bool killPid(int pid, [Object signal = 'SIGTERM']) {
  final native = _native;
  final number = signalNumber(signal);
  if (native == null) {
    if (!io.Process.killPid(pid)) {
      throw NodeError('kill ESRCH', code: 'ESRCH', syscall: 'kill');
    }
    return true;
  }
  if (native.kill(pid, number) != 0) {
    final code = codeForErrno(native.errno);
    throw NodeError('kill $code', code: code, syscall: 'kill');
  }
  return true;
}

// --- launching ----------------------------------------------------------------

class _Launched {
  _Launched(this.pid, this.fds);
  final int pid;

  /// Parent ends of the stdio pipes, -1 where the slot is not 'pipe'.
  final List<int> fds;
}

class _LaunchError implements Exception {
  _LaunchError(this.code);
  final String code;
}

List<Object?> _stdioSpecs(Object? stdio) {
  if (stdio == null) return ['pipe', 'pipe', 'pipe'];
  if (stdio is String) return [stdio, stdio, stdio];
  final list = List<Object?>.of(stdio as List);
  while (list.length < 3) {
    list.add('pipe');
  }
  return list;
}

Map<String, String> _envFor(Map<String, Object?> options) {
  final env = options['env'];
  if (env == null) return process.env;
  return {
    for (final e in (env as Map).entries)
      if (e.value != null) '${e.key}': '${e.value}',
  };
}

_Launched _launch(
  _Libc n,
  String command,
  List<String> args,
  Map<String, Object?> options,
) {
  final shell = options['shell'];
  if (shell != null && shell != false) {
    // Node joins command and args with spaces and runs them through the shell.
    final line = [command, ...args].join(' ');
    command = shell is String ? shell : '/bin/sh';
    args = ['-c', line];
  }
  if (options['detached'] == true) {
    throw UnsupportedError('child_process detached is not supported');
  }
  final specs = _stdioSpecs(options['stdio']);
  if (specs.length > 3) {
    throw UnsupportedError('child_process stdio beyond fd 2');
  }
  final cwd = options['cwd'] as String?;
  final env = _envFor(options);
  final arena = Arena();
  final childEnds = <int>[];
  final parentEnds = <int>[-1, -1, -1];
  try {
    final actions = arena<Uint8>(512).cast<Void>();
    final attr = arena<Uint8>(512).cast<Void>();
    final sigset = arena<Uint8>(256).cast<Void>();
    n.faInit(actions);
    n.attrInit(attr);
    try {
      for (var i = 0; i < 3; i++) {
        final spec = specs[i] ?? 'pipe';
        if (spec == 'pipe' || spec == 'overlapped') {
          final fds = arena<Int32>(2);
          if (n.pipe(fds) != 0) throw _LaunchError(codeForErrno(n.errno));
          final childEnd = i == 0 ? fds[0] : fds[1];
          final parentEnd = i == 0 ? fds[1] : fds[0];
          childEnds.add(childEnd);
          parentEnds[i] = parentEnd;
          // FD_CLOEXEC on the parent's end: no other child may inherit it.
          n.fcntl(parentEnd, 2, 1);
          n.faDup2(actions, childEnd, i);
          n.faClose(actions, parentEnd);
        } else if (spec == 'ignore') {
          n.faOpen(
            actions,
            i,
            '/dev/null'.toNativeUtf8(allocator: arena),
            i == 0 ? 0 : 1,
            0,
          );
        } else if (spec == 'inherit') {
          // The child keeps the parent's descriptor i.
        } else if (spec is int) {
          n.faDup2(actions, spec, i);
        } else {
          throw ArgumentError.value(spec, 'stdio[$i]');
        }
      }
      for (final end in childEnds) {
        if (end > 2) n.faClose(actions, end);
      }
      if (cwd != null) {
        final chdir = n.faChdir;
        if (chdir == null) {
          throw UnsupportedError(
            'child_process cwd needs posix_spawn_file_actions_addchdir_np',
          );
        }
        chdir(actions, cwd.toNativeUtf8(allocator: arena));
      }
      // Reset every signal disposition and the mask: the Dart VM ignores
      // SIGPIPE, and a child would otherwise inherit that.
      n.sigfillset(sigset);
      n.attrSigDefault(attr, sigset);
      n.sigemptyset(sigset);
      n.attrSigMask(attr, sigset);
      n.attrFlags(attr, 0x04 | 0x08);

      final argv = arena<Pointer<Utf8>>(args.length + 2);
      argv[0] = ((options['argv0'] as String?) ?? command).toNativeUtf8(
        allocator: arena,
      );
      for (var i = 0; i < args.length; i++) {
        argv[i + 1] = args[i].toNativeUtf8(allocator: arena);
      }
      argv[args.length + 1] = nullptr;
      final entries = env.entries.toList();
      final envp = arena<Pointer<Utf8>>(entries.length + 1);
      for (var i = 0; i < entries.length; i++) {
        envp[i] = '${entries[i].key}=${entries[i].value}'.toNativeUtf8(
          allocator: arena,
        );
      }
      envp[entries.length] = nullptr;
      // posix_spawnp searches the PATH of the calling process; Node searches
      // the child's env PATH. Resolve against the child's PATH here.
      final file = _resolve(command, env['PATH']);
      final pid = arena<Int32>();
      final rc = n.spawnp(
        pid,
        file.toNativeUtf8(allocator: arena),
        actions,
        attr,
        argv,
        envp,
      );
      if (rc != 0) throw _LaunchError(codeForErrno(rc));
      return _Launched(pid.value, List.of(parentEnds));
    } finally {
      n.faDestroy(actions);
      n.attrDestroy(attr);
    }
  } on Object {
    for (final fd in parentEnds) {
      if (fd >= 0) n.close(fd);
    }
    rethrow;
  } finally {
    for (final end in childEnds) {
      n.close(end);
    }
    arena.releaseAll();
  }
}

String _resolve(String command, String? path) {
  if (command.contains('/') || path == null) return command;
  for (final dir in path.split(':')) {
    final candidate = '${dir.isEmpty ? '.' : dir}/$command';
    if (io.FileSystemEntity.isFileSync(candidate)) return candidate;
  }
  return command;
}

NodeError _spawnError(
  String syscall,
  String code,
  String command,
  List<String> args,
) {
  return NodeError(
    '$syscall $command $code',
    code: code,
    syscall: '$syscall $command',
    path: command,
  )..spawnargs = args;
}

/// Decoded `waitpid` status: (exit status, signal name).
(int?, String?) _decodeStatus(int status) {
  final signal = status & 0x7f;
  if (signal == 0) return ((status >> 8) & 0xff, null);
  return (null, signalName(signal) ?? '$signal');
}

// --- exit status --------------------------------------------------------------
//
// The Dart VM reaps children with waitpid(-1) while any dart:io Process is
// alive, and drops the status of a pid it did not start. On macOS the status
// is taken from kqueue (EVFILT_PROC, NOTE_EXITSTATUS), which sees the exit
// before anyone reaps. On Linux a pidfd tells when the child exits, then
// waitpid reads the status; if the VM reaped it first the status is lost and
// the result fails closed (status null, error ECHILD).

typedef _KeventN =
    Int32 Function(
      Int32,
      Pointer<Uint8>,
      Int32,
      Pointer<Uint8>,
      Int32,
      Pointer<Int64>,
    );
typedef _KeventD =
    int Function(int, Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Int64>);
typedef _SyscallN = Long Function(Long, VarArgs<(Int32, Int32)>);
typedef _SyscallD = int Function(int, int, int);

/// Outcome of waiting: `exited` false means the wait timed out.
typedef _Exit = ({bool exited, int? status});

class _ExitWatcher {
  _ExitWatcher(this._n, this.pid) {
    if (io.Platform.isMacOS) {
      final kq = _libc!.lookupFunction<Int32 Function(), int Function()>(
        'kqueue',
      )();
      _fd = kq;
      final ev = calloc<Uint8>(32);
      try {
        _setKevent(ev, pid);
        if (_kevent(kq, ev, 1, nullptr, 0, nullptr) != 0) {
          // Already gone from the process table: the status is lost.
          _fd = -1;
          _n.close(kq);
        }
      } finally {
        calloc.free(ev);
      }
    } else {
      final syscall = _libc!.lookupFunction<_SyscallN, _SyscallD>('syscall');
      _fd = syscall(434, pid, 0); // pidfd_open
    }
  }

  final _Libc _n;
  final int pid;
  int _fd = -1;
  _Exit? _done;

  static final _KeventD _kevent = _libc!.lookupFunction<_KeventN, _KeventD>(
    'kevent',
  );

  static void _setKevent(Pointer<Uint8> ev, int pid) {
    final d = ByteData.sublistView(ev.asTypedList(32));
    d.setUint64(0, pid, Endian.host);
    d.setInt16(8, -5, Endian.host); // EVFILT_PROC
    d.setUint16(10, 0x1 | 0x10, Endian.host); // EV_ADD | EV_ONESHOT
    d.setUint32(12, 0x80000000 | 0x04000000, Endian.host); // EXIT|EXITSTATUS
  }

  /// Wait up to [timeoutMs] (-1: forever) for the child to exit.
  _Exit wait(int timeoutMs) {
    final done = _done;
    if (done != null) return done;
    if (io.Platform.isMacOS) {
      if (_fd < 0) return _finish(_reap());
      final ev = calloc<Uint8>(32);
      final ts = calloc<Int64>(2);
      try {
        ts[0] = timeoutMs ~/ 1000;
        ts[1] = (timeoutMs % 1000) * 1000000;
        int got;
        do {
          got = _kevent(_fd, nullptr, 0, ev, 1, timeoutMs < 0 ? nullptr : ts);
        } while (got < 0 && codeForErrno(_n.errno) == 'EINTR');
        if (got == 0) return (exited: false, status: null);
        final status = ByteData.sublistView(
          ev.asTypedList(32),
        ).getInt64(16, Endian.host);
        _reap();
        return _finish(status);
      } finally {
        calloc.free(ev);
        calloc.free(ts);
      }
    }
    if (_fd >= 0) {
      final pfd = calloc<Int32>(2);
      try {
        pfd[0] = _fd;
        pfd[1] = _pollIn;
        int ready;
        do {
          ready = _n.poll(pfd, 1, timeoutMs);
        } while (ready < 0 && codeForErrno(_n.errno) == 'EINTR');
        if (ready == 0) return (exited: false, status: null);
      } finally {
        calloc.free(pfd);
      }
    }
    return _finish(_reap(blocking: _fd < 0));
  }

  int? _reap({bool blocking = false}) {
    final status = calloc<Int32>();
    try {
      int r;
      do {
        r = _n.waitpid(pid, status, blocking ? 0 : _wnohang);
      } while (r < 0 && codeForErrno(_n.errno) == 'EINTR');
      return r == pid ? status.value : null;
    } finally {
      calloc.free(status);
    }
  }

  _Exit _finish(int? status) {
    if (_fd >= 0) _n.close(_fd);
    _fd = -1;
    return _done = (exited: true, status: status);
  }
}

// --- spawnSync -----------------------------------------------------------------

class SpawnSyncResult {
  SpawnSyncResult({
    required this.pid,
    required this.output,
    required this.stdout,
    required this.stderr,
    required this.status,
    this.signal,
    this.error,
  });
  final int pid;
  final List<Object?> output;

  /// A String with `encoding`, otherwise a [Buffer]; null when not piped.
  final Object? stdout;
  final Object? stderr;
  final int? status;
  final String? signal;
  final Object? error;
}

Object? _decodeOutput(List<int>? bytes, Object? encoding) {
  if (bytes == null) return null;
  if (encoding == null || encoding == 'buffer') {
    return Buffer.wrap(Uint8List.fromList(bytes));
  }
  return Buffer.wrap(Uint8List.fromList(bytes)).toString(encoding as String);
}

/// Node's `spawnSync(command, args, options)`. Options: `cwd`, `env`,
/// `input` (String or bytes, written to a piped stdin), `stdio`, `timeout`
/// (ms), `killSignal`, `encoding`, `maxBuffer`, `argv0`. A launch failure
/// or timeout is reported in `error`, never thrown.
SpawnSyncResult spawnSync(
  String command, [
  List<String> args = const [],
  Map<String, Object?> options = const {},
]) {
  final native = _native;
  if (native == null) return _spawnSyncDartIo(command, args, options);
  final encoding = options['encoding'];
  final timeout = options['timeout'] as int?;
  final killSignal = signalNumber(options['killSignal'] ?? 'SIGTERM');
  final maxBuffer = (options['maxBuffer'] as int?) ?? 1024 * 1024;
  final input = options['input'];
  final inputBytes = input == null
      ? const <int>[]
      : input is List<int>
      ? input
      : utf8.encode(input.toString());

  _Launched launched;
  try {
    launched = _launch(native, command, args, options);
  } on _LaunchError catch (error) {
    return SpawnSyncResult(
      pid: 0,
      output: [null, null, null],
      stdout: null,
      stderr: null,
      status: null,
      error: _spawnError('spawnSync', error.code, command, args),
    );
  }

  final watcher = _ExitWatcher(native, launched.pid);
  final fds = launched.fds;
  final outputs = <List<int>?>[
    null,
    fds[1] >= 0 ? <int>[] : null,
    fds[2] >= 0 ? <int>[] : null,
  ];
  var inputOffset = 0;
  if (fds[0] >= 0 && inputBytes.isEmpty) {
    native.close(fds[0]);
    fds[0] = -1;
  }
  final deadline = timeout != null && timeout > 0
      ? DateTime.now().add(Duration(milliseconds: timeout))
      : null;
  NodeError? error;
  var killed = false;
  final pollfds = calloc<Int32>(6);
  final chunk = calloc<Uint8>(65536);
  try {
    while (fds.any((fd) => fd >= 0)) {
      final active = <int>[];
      for (var i = 0; i < 3; i++) {
        if (fds[i] < 0) continue;
        pollfds[active.length * 2] = fds[i];
        // events (short) then revents (short) in the second int.
        pollfds[active.length * 2 + 1] = i == 0 ? _pollOut : _pollIn;
        active.add(i);
      }
      var wait = -1;
      if (deadline != null && !killed) {
        wait = deadline.difference(DateTime.now()).inMilliseconds;
        if (wait < 0) wait = 0;
      }
      final ready = native.poll(pollfds, active.length, wait);
      if (ready < 0) {
        if (codeForErrno(native.errno) == 'EINTR') continue;
        break;
      }
      if (ready == 0) {
        if (deadline != null && !killed) {
          native.kill(launched.pid, killSignal);
          killed = true;
          error = _spawnError('spawnSync', 'ETIMEDOUT', command, args);
        }
        continue;
      }
      for (var k = 0; k < active.length; k++) {
        final i = active[k];
        final revents = (pollfds[k * 2 + 1] >> 16) & 0xffff;
        if (revents == 0) continue;
        if (i == 0) {
          if (revents & (_pollErr | _pollHup) != 0) {
            native.close(fds[0]);
            fds[0] = -1;
            continue;
          }
          // POLLOUT guarantees room for PIPE_BUF (>= 512) bytes.
          final n = (inputBytes.length - inputOffset).clamp(0, 512);
          chunk.asTypedList(n).setRange(0, n, inputBytes, inputOffset);
          final written = native.write(fds[0], chunk, n);
          if (written > 0) inputOffset += written;
          if (written < 0 || inputOffset >= inputBytes.length) {
            native.close(fds[0]);
            fds[0] = -1;
          }
          continue;
        }
        final count = native.read(fds[i], chunk, 65536);
        if (count <= 0) {
          if (count < 0 && codeForErrno(native.errno) == 'EINTR') continue;
          native.close(fds[i]);
          fds[i] = -1;
          continue;
        }
        outputs[i]!.addAll(chunk.asTypedList(count));
        if (outputs[i]!.length > maxBuffer && !killed) {
          native.kill(launched.pid, killSignal);
          killed = true;
          error = _spawnError('spawnSync', 'ENOBUFS', command, args);
        }
      }
    }
  } finally {
    calloc.free(pollfds);
    calloc.free(chunk);
  }
  var remaining = -1;
  if (deadline != null && !killed) {
    remaining = deadline.difference(DateTime.now()).inMilliseconds;
    if (remaining < 0) remaining = 0;
  }
  var exit = watcher.wait(remaining);
  if (!exit.exited) {
    native.kill(launched.pid, killSignal);
    error = _spawnError('spawnSync', 'ETIMEDOUT', command, args);
    exit = watcher.wait(-1);
  }
  final stdout = _decodeOutput(outputs[1], encoding);
  final stderr = _decodeOutput(outputs[2], encoding);
  final raw = exit.status;
  final (code, signal) = raw == null ? (null, null) : _decodeStatus(raw);
  return SpawnSyncResult(
    pid: launched.pid,
    output: [null, stdout, stderr],
    stdout: stdout,
    stderr: stderr,
    status: code,
    signal: signal,
    error:
        error ??
        (raw == null
            ? _spawnError('spawnSync', 'ECHILD', command, args)
            : null),
  );
}

SpawnSyncResult _spawnSyncDartIo(
  String command,
  List<String> args,
  Map<String, Object?> options,
) {
  if (options['timeout'] != null || options['input'] != null) {
    throw UnsupportedError(
      'spawnSync timeout/input need posix_spawn; not available on Windows',
    );
  }
  try {
    final result = io.Process.runSync(
      command,
      args,
      workingDirectory: options['cwd'] as String?,
      environment: options['env'] == null ? null : _envFor(options),
      includeParentEnvironment: options['env'] == null,
      stdoutEncoding: null,
      stderrEncoding: null,
    );
    final stdout = _decodeOutput(
      result.stdout as List<int>,
      options['encoding'],
    );
    final stderr = _decodeOutput(
      result.stderr as List<int>,
      options['encoding'],
    );
    return SpawnSyncResult(
      pid: result.pid,
      output: [null, stdout, stderr],
      stdout: stdout,
      stderr: stderr,
      status: result.exitCode,
    );
  } on io.ProcessException catch (e) {
    final code = e.errorCode == 2 ? 'ENOENT' : codeForErrno(e.errorCode);
    return SpawnSyncResult(
      pid: 0,
      output: [null, null, null],
      stdout: null,
      stderr: null,
      status: null,
      error: _spawnError('spawnSync', code, command, args),
    );
  }
}

/// The writable end of a child's piped stdin: Node's `write` and `end`.
/// Writes go straight to the pipe and block while it is full (dart:io cannot
/// open a pipe descriptor for asynchronous writing).
class ChildStdin {
  ChildStdin._(this._native, this._fd);
  final _Libc _native;
  int _fd;

  bool write(Object data) {
    if (_fd < 0) throw StateError('write after end');
    final bytes = data is List<int> ? data : utf8.encode(data.toString());
    final buffer = calloc<Uint8>(bytes.isEmpty ? 1 : bytes.length);
    try {
      buffer.asTypedList(bytes.length).setAll(0, bytes);
      var offset = 0;
      while (offset < bytes.length) {
        final n = _native.write(_fd, buffer + offset, bytes.length - offset);
        if (n < 0) {
          if (codeForErrno(_native.errno) == 'EINTR') continue;
          throw NodeError('write EPIPE', code: 'EPIPE', syscall: 'write');
        }
        offset += n;
      }
    } finally {
      calloc.free(buffer);
    }
    return true;
  }

  void end([Object? data]) {
    if (data != null) write(data);
    if (_fd >= 0) _native.close(_fd);
    _fd = -1;
  }

  void close() => end();
}

// --- spawn ------------------------------------------------------------------------

/// Node's `ChildProcess`: an EventEmitter with 'error', 'spawn', 'exit'
/// (code, signal) and 'close' (code, signal) events. `pid` is null when the
/// launch failed; the 'error' event then follows asynchronously, as in Node.
class ChildProcess extends EventEmitter {
  ChildProcess._();

  int? pid;
  int? exitCode;
  String? signalCode;
  bool killed = false;
  ChildStdin? stdin;
  Stream<List<int>>? stdout;
  Stream<List<int>>? stderr;
  io.Process? _dartIo;

  /// Node's `child.kill(signal)`: true when the signal was delivered.
  bool kill([Object signal = 'SIGTERM']) {
    final p = pid;
    if (p == null || exitCode != null || signalCode != null) return false;
    final native = _native;
    bool sent;
    if (native == null) {
      sent = _dartIo?.kill() ?? false;
    } else {
      sent = native.kill(p, signalNumber(signal)) == 0;
    }
    if (sent) killed = true;
    return sent;
  }

  void _exited(int? code, String? signal, List<Future<void>> streams) {
    exitCode = code;
    signalCode = signal;
    emit('exit', code, signal);
    unawaited(Future.wait(streams).then((_) => emit('close', code, signal)));
  }
}

/// Node's `spawn(command, args, options)`, with `cwd`, `env`, `stdio`.
ChildProcess spawn(
  String command, [
  List<String> args = const [],
  Map<String, Object?> options = const {},
]) {
  final child = ChildProcess._();
  final native = _native;
  if (native == null) {
    _spawnDartIo(child, command, args, options);
    return child;
  }
  _Launched launched;
  try {
    launched = _launch(native, command, args, options);
  } on _LaunchError catch (error) {
    final err = _spawnError('spawn', error.code, command, args);
    Timer.run(() {
      child.emit('error', err);
      child.emit('close', -2, null);
    });
    return child;
  }
  child.pid = launched.pid;
  final streams = <Future<void>>[];
  final fds = launched.fds;
  if (fds[0] >= 0) child.stdin = ChildStdin._(native, fds[0]);
  Stream<List<int>>? reader(int fd) {
    if (fd < 0) return null;
    final controller = StreamController<List<int>>.broadcast();
    final done = Completer<void>();
    streams.add(done.future);
    io.File('/dev/fd/$fd').openRead().listen(
      controller.add,
      onError: controller.addError,
      onDone: () {
        native.close(fd);
        controller.close();
        done.complete();
      },
    );
    return controller.stream;
  }

  child.stdout = reader(fds[1]);
  child.stderr = reader(fds[2]);
  Timer.run(() => child.emit('spawn'));
  final watcher = _ExitWatcher(native, launched.pid);
  Timer.periodic(const Duration(milliseconds: 10), (timer) {
    final exit = watcher.wait(0);
    if (!exit.exited) return;
    timer.cancel();
    final raw = exit.status;
    if (raw == null) {
      child.emit('error', _spawnError('spawn', 'ECHILD', command, args));
    }
    final (code, signal) = raw == null ? (null, null) : _decodeStatus(raw);
    child._exited(code, signal, streams);
  });
  return child;
}

void _spawnDartIo(
  ChildProcess child,
  String command,
  List<String> args,
  Map<String, Object?> options,
) {
  final specs = _stdioSpecs(options['stdio']);
  unawaited(() async {
    io.Process p;
    try {
      p = await io.Process.start(
        command,
        args,
        workingDirectory: options['cwd'] as String?,
        environment: options['env'] == null ? null : _envFor(options),
        includeParentEnvironment: options['env'] == null,
        mode: specs.every((s) => s == 'inherit')
            ? io.ProcessStartMode.inheritStdio
            : io.ProcessStartMode.normal,
      );
    } on io.ProcessException catch (e) {
      child.emit(
        'error',
        _spawnError(
          'spawn',
          e.errorCode == 2 ? 'ENOENT' : 'UNKNOWN',
          command,
          args,
        ),
      );
      return;
    }
    child._dartIo = p;
    child.pid = p.pid;
    child.emit('spawn');
    final code = await p.exitCode;
    child._exited(code, null, const []);
  }());
}

// --- execSync / exec --------------------------------------------------------------

/// Synchronously run a command and return stdout, matching the used part of
/// Node's `execSync` (`encoding: 'utf8'`, failures reported by throwing).
String execSync(String command, List<String> arguments, {Duration? timeout}) {
  final result = spawnSync(command, arguments, {
    'encoding': 'utf8',
    'stdio': ['ignore', 'pipe', 'pipe'],
    if (timeout != null) 'timeout': timeout.inMilliseconds,
  });
  final error = result.error;
  if (error != null) throw error;
  if (result.status != 0) {
    throw NodeError(
      'Command failed: $command ${arguments.join(' ')}\n${result.stderr}',
      code: 'ERR_CHILD_PROCESS',
    )..status = result.status;
  }
  return result.stdout as String;
}

/// Asynchronously run a command and return stdout, or null on an exec error.
/// This is the callback-error behavior needed by Node's `exec` call site.
Future<String?> exec(
  String command,
  List<String> arguments, {
  required Duration timeout,
}) {
  final completer = Completer<String?>();
  final child = spawn(command, arguments, {
    'stdio': ['ignore', 'pipe', 'ignore'],
  });
  final out = <int>[];
  child.stdout?.listen(out.addAll);
  final timer = Timer(timeout, () => child.kill('SIGTERM'));
  child.on('error', (Object _) {
    timer.cancel();
    if (!completer.isCompleted) completer.complete(null);
  });
  child.on('close', (int? code, String? signal) {
    timer.cancel();
    if (!completer.isCompleted) {
      completer.complete(
        code == 0 ? utf8.decode(out, allowMalformed: true) : null,
      );
    }
  });
  return completer.future;
}

/// Former name of [ChildProcess], kept for callers not yet updated.
typedef NodeChildProcess = ChildProcess;
