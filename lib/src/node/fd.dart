// POSIX file-descriptor flags used by the CLI; there is no upstream counterpart.
import 'dart:ffi';
import 'dart:io';

import 'errno.dart';

// fcntl is variadic: the third argument must be passed as a variadic one, or
// on macOS arm64 it is read from the wrong place.
typedef _FcntlNative = Int32 Function(Int32, Int32, VarArgs<(Int32,)>);
typedef _FcntlDart = int Function(int, int, int);
typedef _ErrnoLocationNative = Pointer<Int32> Function();

final _FcntlDart _fcntl = DynamicLibrary.process()
    .lookupFunction<_FcntlNative, _FcntlDart>('fcntl', isLeaf: true);
final Pointer<Int32> Function() _errnoLocation = DynamicLibrary.process()
    .lookupFunction<_ErrnoLocationNative, _ErrnoLocationNative>(
      Platform.isMacOS ? '__error' : '__errno_location',
      isLeaf: true,
    );

/// `fcntl(fd, F_GETFD)`: the descriptor flags of [fd] (bit 0 is
/// FD_CLOEXEC). Throws a Node-shaped error (`code` such as `EBADF`).
int getFdFlags(int fd) {
  final flags = _fcntl(fd, 1, 0);
  if (flags < 0) throw _fcntlError(fd);
  return flags;
}

/// Set close-on-exec on [fd], preventing it from reaching spawned commands.
/// Throws a Node-shaped error (`code` such as `EBADF`) on failure.
void setCloseOnExec(int fd) {
  if (!Platform.isLinux && !Platform.isMacOS) {
    throw UnsupportedError('FD_CLOEXEC is only supported on POSIX platforms');
  }
  // F_GETFD = 1; F_SETFD = 2; FD_CLOEXEC = 1 on Linux and macOS.
  final flags = getFdFlags(fd);
  if (_fcntl(fd, 2, flags | 1) < 0) throw _fcntlError(fd);
}

NodeError _fcntlError(int fd) {
  final code = codeForErrno(_errnoLocation().value);
  return nodeError(code, 'fcntl', '$fd');
}
