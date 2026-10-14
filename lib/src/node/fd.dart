// POSIX file-descriptor flags used by the CLI; there is no upstream counterpart.
import 'dart:ffi';
import 'dart:io';

typedef _FcntlNative = Int32 Function(Int32, Int32, Int32);
typedef _FcntlDart = int Function(int, int, int);

/// Set close-on-exec on [fd], preventing it from reaching spawned commands.
void setCloseOnExec(int fd) {
  if (!Platform.isLinux && !Platform.isMacOS) {
    throw UnsupportedError('FD_CLOEXEC is only supported on POSIX platforms');
  }
  final fcntl = DynamicLibrary.process()
      .lookupFunction<_FcntlNative, _FcntlDart>('fcntl');
  // F_GETFD = 1; F_SETFD = 2; FD_CLOEXEC = 1 on Linux and macOS.
  final flags = fcntl(fd, 1, 0);
  if (flags < 0 || fcntl(fd, 2, flags | 1) < 0) {
    throw OSError('fcntl(FD_CLOEXEC) failed', fd);
  }
}
