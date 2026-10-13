// Node-compatible error-code data used where dart:io exposes an OS errno but
// not Node's stable `error.code` string. POSIX callers capture errno directly
// through FFI before Dart can overwrite it.
import 'dart:io';

/// The `Error` message and stringification used by Node's generic `Error`.
class NodeException extends Error {
  NodeException(this.message);

  final String message;

  @override
  String toString() => 'Error: $message';
}

/// An error with the Node fields `code`, `syscall`, and `path`.
class NodeError extends NodeException {
  NodeError(super.message, {required this.code, this.syscall, this.path});

  final String code;
  final String? syscall;
  final String? path;
}

const Map<int, String> _linuxErrnoCodes = {
  1: 'EPERM',
  2: 'ENOENT',
  4: 'EINTR',
  5: 'EIO',
  6: 'ENXIO',
  9: 'EBADF',
  11: 'EAGAIN',
  12: 'ENOMEM',
  13: 'EACCES',
  14: 'EFAULT',
  16: 'EBUSY',
  17: 'EEXIST',
  18: 'EXDEV',
  19: 'ENODEV',
  20: 'ENOTDIR',
  21: 'EISDIR',
  22: 'EINVAL',
  24: 'EMFILE',
  25: 'ENOTTY',
  26: 'ETXTBSY',
  27: 'EFBIG',
  28: 'ENOSPC',
  30: 'EROFS',
  31: 'EMLINK',
  32: 'EPIPE',
  34: 'ERANGE',
  36: 'ENAMETOOLONG',
  38: 'ENOSYS',
  39: 'ENOTEMPTY',
  40: 'ELOOP',
};

const Map<int, String> _darwinErrnoCodes = {
  1: 'EPERM',
  2: 'ENOENT',
  3: 'ESRCH',
  4: 'EINTR',
  5: 'EIO',
  6: 'ENXIO',
  7: 'E2BIG',
  8: 'ENOEXEC',
  9: 'EBADF',
  10: 'ECHILD',
  11: 'EDEADLK',
  12: 'ENOMEM',
  13: 'EACCES',
  14: 'EFAULT',
  15: 'ENOTBLK',
  16: 'EBUSY',
  17: 'EEXIST',
  18: 'EXDEV',
  19: 'ENODEV',
  20: 'ENOTDIR',
  21: 'EISDIR',
  22: 'EINVAL',
  24: 'EMFILE',
  25: 'ENOTTY',
  26: 'ETXTBSY',
  27: 'EFBIG',
  28: 'ENOSPC',
  30: 'EROFS',
  31: 'EMLINK',
  32: 'EPIPE',
  35: 'EAGAIN',
  34: 'ERANGE',
  45: 'EOPNOTSUPP',
  63: 'ENAMETOOLONG',
  65: 'ENOTEMPTY',
  62: 'ELOOP',
};

/// Translate the macOS/Linux errno values which the port needs into Node's
/// symbolic codes. Unknown values remain explicit rather than guessed.
String codeForErrno(int errno) {
  final codes = Platform.isMacOS ? _darwinErrnoCodes : _linuxErrnoCodes;
  return codes[errno] ?? 'UNKNOWN';
}

/// Build Node-style error text while retaining Node's inspectable fields.
NodeError nodeError(
  String code,
  String syscall,
  String path, {
  String? message,
}) {
  final reason = message ?? _reasonForCode(code);
  return NodeError(
    '$code: $reason, $syscall \'$path\'',
    code: code,
    syscall: syscall,
    path: path,
  );
}

String _reasonForCode(String code) {
  switch (code) {
    case 'ENOENT':
      return 'no such file or directory';
    case 'ENOTDIR':
      return 'not a directory';
    case 'EACCES':
      return 'permission denied';
    case 'ELOOP':
      return 'too many symbolic links encountered';
    case 'ENAMETOOLONG':
      return 'file name too long';
    case 'EEXIST':
      return 'file already exists';
    case 'EISDIR':
      return 'illegal operation on a directory';
    default:
      return 'operating system error';
  }
}
