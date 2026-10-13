// Small Node fsSync compatibility shim for real-path.dart. POSIX calls use
// libc directly so that failures retain errno/code before dart:io translates
// them to a lossy FileSystemException.
import 'dart:convert';
import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';
import 'package:path/path.dart' as path_utils;

import 'errno.dart';

final DynamicLibrary? _libc = _loadLibc();
typedef _LstatNative = Int32 Function(Pointer<Uint8>, Pointer<Void>);
typedef _LstatDart = int Function(Pointer<Uint8>, Pointer<Void>);
typedef _ReadlinkNative =
    IntPtr Function(Pointer<Uint8>, Pointer<Uint8>, IntPtr);
typedef _ReadlinkDart = int Function(Pointer<Uint8>, Pointer<Uint8>, int);
typedef _RealpathNative =
    Pointer<Uint8> Function(Pointer<Uint8>, Pointer<Uint8>);
typedef _RealpathDart = Pointer<Uint8> Function(Pointer<Uint8>, Pointer<Uint8>);
typedef _ErrnoLocationNative = Pointer<Int32> Function();
typedef _ErrnoLocationDart = Pointer<Int32> Function();
typedef _FreeNative = Void Function(Pointer<Void>);
typedef _FreeDart = void Function(Pointer<Void>);

DynamicLibrary? _loadLibc() {
  if (Platform.isMacOS || Platform.isLinux) return DynamicLibrary.process();
  return null;
}

int Function()? _errnoFunction() {
  final libc = _libc;
  if (libc == null) return null;
  try {
    final symbol = Platform.isMacOS ? '__error' : '__errno_location';
    final location = libc
        .lookupFunction<_ErrnoLocationNative, _ErrnoLocationDart>(symbol);
    return () => location().value;
  } catch (_) {
    return null;
  }
}

final int Function()? _readErrno = _errnoFunction();

/// The only lstat field needed by realPathOf: whether the final name is a link.
class NodeFileStat {
  const NodeFileStat(this._isSymbolicLink);
  final bool _isSymbolicLink;

  bool isSymbolicLink() => _isSymbolicLink;
}

/// Optional observation hook used by the `what it asks` real-path tests.
void Function(String call)? fsCallObserver;

void _observe(String call, String path) => fsCallObserver?.call('$call $path');

/// Reproduce `fs.lstatSync(path)` and its Node `Stats.isSymbolicLink()` use.
NodeFileStat lstatSync(String path) {
  _observe('lstatSync', path);
  final libc = _libc;
  if (libc != null) {
    final lstat = libc.lookupFunction<_LstatNative, _LstatDart>('lstat');
    final nativePath = path.toNativeUtf8(allocator: calloc);
    final statBuffer = calloc<Uint8>(512);
    try {
      if (lstat(nativePath.cast(), statBuffer.cast()) != 0) {
        final errno = _readErrno?.call() ?? 0;
        throw nodeError(codeForErrno(errno), 'lstat', path);
      }
    } finally {
      calloc.free(nativePath);
      calloc.free(statBuffer);
    }
  }
  try {
    final type = FileSystemEntity.typeSync(path, followLinks: false);
    if (type == FileSystemEntityType.notFound) {
      throw nodeError('ENOENT', 'lstat', path);
    }
    return NodeFileStat(type == FileSystemEntityType.link);
  } on NodeError {
    rethrow;
  } on FileSystemException catch (error) {
    throw nodeError(_codeFromIoError(error), 'lstat', path);
  }
}

/// Return `dev:ino`, the identity pair read by the upstream property test's
/// `fs.statSync`. POSIX `struct stat` places these fields at the same offsets
/// on Darwin and 64-bit Linux; dart:io intentionally does not expose them.
String statIdentitySync(String path) {
  final libc = _libc;
  if (libc != null) {
    final stat = libc.lookupFunction<_LstatNative, _LstatDart>('stat');
    final nativePath = path.toNativeUtf8(allocator: calloc);
    final statBuffer = calloc<Uint8>(512);
    try {
      if (stat(nativePath.cast(), statBuffer.cast()) != 0) {
        final errno = _readErrno?.call() ?? 0;
        throw nodeError(codeForErrno(errno), 'stat', path);
      }
      final data = ByteData.view(statBuffer.asTypedList(512).buffer);
      final device = Platform.isMacOS
          ? data.getUint32(0, Endian.host)
          : data.getUint64(0, Endian.host);
      final inode = data.getUint64(8, Endian.host);
      return '$device:$inode';
    } finally {
      calloc.free(nativePath);
      calloc.free(statBuffer);
    }
  }
  try {
    final stat = FileStat.statSync(path);
    return '${stat.type}:${stat.size}';
  } on FileSystemException catch (error) {
    throw nodeError(_codeFromIoError(error), 'stat', path);
  }
}

/// Reproduce `fs.readlinkSync(path)`, preserving the exact target text.
String readlinkSync(String path) {
  _observe('readlinkSync', path);
  final libc = _libc;
  if (libc != null) {
    final readlink = libc.lookupFunction<_ReadlinkNative, _ReadlinkDart>(
      'readlink',
    );
    final nativePath = path.toNativeUtf8(allocator: calloc);
    final output = calloc<Uint8>(65536);
    try {
      final count = readlink(nativePath.cast(), output, 65536);
      if (count < 0) {
        final errno = _readErrno?.call() ?? 0;
        throw nodeError(codeForErrno(errno), 'readlink', path);
      }
      return utf8.decode(output.asTypedList(count), allowMalformed: true);
    } finally {
      calloc.free(nativePath);
      calloc.free(output);
    }
  }
  try {
    return Link(path).targetSync();
  } on FileSystemException catch (error) {
    throw nodeError(_codeFromIoError(error), 'readlink', path);
  }
}

/// Reproduce `fs.realpathSync(path)` using libc realpath on POSIX hosts.
String realpathSync(String path) {
  _observe('realpathSync', path);
  // Node folds dot segments in the supplied path before touching the file
  // system (`link/..` means the directory holding link, even if link is bad).
  final resolvedPath = path_utils.normalize(path_utils.absolute(path));
  final libc = _libc;
  if (libc != null) {
    final realpath = libc.lookupFunction<_RealpathNative, _RealpathDart>(
      'realpath',
    );
    final free = libc.lookupFunction<_FreeNative, _FreeDart>('free');
    final nativePath = resolvedPath.toNativeUtf8(allocator: calloc);
    try {
      final result = realpath(nativePath.cast(), nullptr);
      if (result.address == 0) {
        final errno = _readErrno?.call() ?? 0;
        throw nodeError(codeForErrno(errno), 'realpath', path);
      }
      try {
        return result.cast<Utf8>().toDartString();
      } finally {
        free(result.cast());
      }
    } finally {
      calloc.free(nativePath);
    }
  }
  try {
    return File(resolvedPath).resolveSymbolicLinksSync();
  } on FileSystemException catch (error) {
    throw nodeError(_codeFromIoError(error), 'realpath', path);
  }
}

String _codeFromIoError(FileSystemException error) {
  final errno = error.osError?.errorCode;
  if (errno != null) {
    final code = codeForErrno(errno);
    if (code != 'UNKNOWN') return code;
  }
  // Windows reports Win32 error numbers through dart:io. This is only the
  // fallback; POSIX paths use the exact errno tables above.
  switch (errno) {
    case 2:
    case 3:
      return 'ENOENT';
    case 5:
      return 'EACCES';
    case 17:
      return 'EEXIST';
    case 267:
      return 'ENOTDIR';
    default:
      return 'UNKNOWN';
  }
}
