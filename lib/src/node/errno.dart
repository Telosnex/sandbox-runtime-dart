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
  NodeError(
    super.message, {
    required this.code,
    this.syscall,
    this.path,
    this.address,
    this.port,
    this.dest,
    this.errno,
  });

  /// Set on two-path errors (`rename`), as Node sets `err.dest`.
  final String? dest;

  /// Node's negative errno (`-2` for ENOENT), when known.
  final int? errno;

  /// Set on child_process errors, as Node sets `err.spawnargs`.
  List<String>? spawnargs;

  /// Set on execSync failures, as Node sets `err.status`.
  int? status;

  final String code;
  final String? syscall;
  final String? path;

  /// Set on socket errors, as Node sets `err.address` and `err.port`.
  final String? address;
  final int? port;
}

const Map<int, String> _linuxErrnoCodes = {
  1: 'EPERM',
  2: 'ENOENT',
  3: 'ESRCH',
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
  98: 'EADDRINUSE',
  99: 'EADDRNOTAVAIL',
  100: 'ENETDOWN',
  101: 'ENETUNREACH',
  103: 'ECONNABORTED',
  104: 'ECONNRESET',
  107: 'ENOTCONN',
  110: 'ETIMEDOUT',
  111: 'ECONNREFUSED',
  113: 'EHOSTUNREACH',
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
  48: 'EADDRINUSE',
  49: 'EADDRNOTAVAIL',
  50: 'ENETDOWN',
  51: 'ENETUNREACH',
  53: 'ECONNABORTED',
  54: 'ECONNRESET',
  57: 'ENOTCONN',
  60: 'ETIMEDOUT',
  61: 'ECONNREFUSED',
  62: 'ELOOP',
  63: 'ENAMETOOLONG',
  65: 'EHOSTUNREACH',
  66: 'ENOTEMPTY',
};

/// Winsock codes, which dart:io reports in `OSError.errorCode` on Windows.
const Map<int, String> _windowsSocketCodes = {
  10013: 'EACCES',
  10048: 'EADDRINUSE',
  10049: 'EADDRNOTAVAIL',
  10050: 'ENETDOWN',
  10051: 'ENETUNREACH',
  10053: 'ECONNABORTED',
  10054: 'ECONNRESET',
  10057: 'ENOTCONN',
  10060: 'ETIMEDOUT',
  10061: 'ECONNREFUSED',
  10065: 'EHOSTUNREACH',
};

/// Translate the macOS/Linux errno values which the port needs into Node's
/// symbolic codes. Unknown values remain explicit rather than guessed.
String codeForErrno(int errno) {
  final codes = Platform.isMacOS
      ? _darwinErrnoCodes
      : Platform.isWindows
      ? _windowsSocketCodes
      : _linuxErrnoCodes;
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

/// Node's error for a failed socket call, built from a dart:io
/// [SocketException]. The message has Node's form:
/// `connect ECONNREFUSED 127.0.0.1:1`, `connect ENOENT /tmp/x.sock`,
/// `listen EADDRINUSE: address already in use 127.0.0.1:8080`.
NodeError socketError(
  Object error,
  String syscall, {
  String? address,
  int? port,
}) {
  if (error is NodeError) return error;
  final errno = error is SocketException ? error.osError?.errorCode : null;
  final osMessage = error is SocketException
      ? error.osError?.message ?? ''
      : '';
  // dart:io refuses a second bind in the same process before the OS sees it
  // ("The shared flag to bind() needs to be `true`"), and refuses an existing
  // Unix-domain path ("File exists with given unix domain address"). Both
  // report errno -1. The OS, and so Node, reports EADDRINUSE for each.
  final code =
      errno == -1 &&
          (osMessage.contains('shared flag') ||
              osMessage.contains('File exists with given unix domain'))
      ? 'EADDRINUSE'
      : errno == null
      ? 'UNKNOWN'
      : codeForErrno(errno);
  final where = address == null
      ? ''
      : port == null
      ? ' $address'
      : ' $address:$port';
  final message = syscall == 'listen'
      ? '$syscall $code: ${_reasonForCode(code)}$where'
      : '$syscall $code$where';
  return NodeError(
    message,
    code: code,
    syscall: syscall,
    address: address,
    port: port,
  );
}

String _reasonForCode(String code) {
  switch (code) {
    case 'EADDRINUSE':
      return 'address already in use';
    case 'EADDRNOTAVAIL':
      return 'address not available';
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

/// JS `(err as Error).message`: the message of a NodeException, Exception
/// or Error, and `String(err)` otherwise.
String errorMessage(Object? err) {
  if (err is NodeException) return err.message;
  if (err is OSError) return err.message;
  if (err is IOException || err is FormatException) {
    final dynamic e = err;
    try {
      return e.message as String;
    } catch (_) {}
  }
  if (err is ArgumentError) return '${err.message}';
  if (err is StateError) return err.message;
  if (err is UnsupportedError) return err.message ?? '';
  try {
    return '$err';
  } catch (_) {
    return 'Error';
  }
}

/// JS `(err as NodeJS.ErrnoException).code`: the Node error code, or null.
String? errorCode(Object? err) {
  if (err is NodeError) return err.code;
  return null;
}
