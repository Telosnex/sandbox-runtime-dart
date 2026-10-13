// Small Node fsSync compatibility shim for path-entries.dart. This module is
// separate from fs.dart so its established lstat/realpath behavior is unchanged.
import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'errno.dart';
import 'fs.dart' as fs;

final DynamicLibrary? _libc = _loadLibc();
typedef _StatNative = Int32 Function(Pointer<Uint8>, Pointer<Void>);
typedef _StatDart = int Function(Pointer<Uint8>, Pointer<Void>);
typedef _ErrnoLocationNative = Pointer<Int32> Function();
typedef _ErrnoLocationDart = Pointer<Int32> Function();

DynamicLibrary? _loadLibc() =>
    Platform.isMacOS || Platform.isLinux ? DynamicLibrary.process() : null;

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

/// The Stats predicates used by the upstream path-entries rules.
class NodePathEntriesStat {
  const NodePathEntriesStat(this._directory, this._symbolicLink);

  final bool _directory;
  final bool _symbolicLink;

  bool isDirectory() => _directory;
  bool isSymbolicLink() => _symbolicLink;
}

/// Reproduce `fs.lstatSync(path)` predicates used by path-entries.ts.
NodePathEntriesStat lstatSync(String path) {
  if (_libc != null) return _posixStat(path, 'lstat', followLinks: false);

  // The established fs shim retains Node's error fields on the fallback host.
  final link = fs.lstatSync(path).isSymbolicLink();
  final type = _typeSync(path, 'lstat', followLinks: false);
  return NodePathEntriesStat(type == FileSystemEntityType.directory, link);
}

/// Reproduce `fs.statSync(path).isDirectory()` used by path-entries.ts.
NodePathEntriesStat statSync(String path) {
  if (_libc != null) return _posixStat(path, 'stat', followLinks: true);
  final type = _typeSync(path, 'stat');
  return NodePathEntriesStat(type == FileSystemEntityType.directory, false);
}

NodePathEntriesStat _posixStat(
  String path,
  String syscall, {
  required bool followLinks,
}) {
  fs.fsCallObserver?.call(
    '$syscall'
    'Sync $path',
  );
  final libc = _libc!;
  final stat = libc.lookupFunction<_StatNative, _StatDart>(
    followLinks ? 'stat' : 'lstat',
  );
  final nativePath = path.toNativeUtf8(allocator: calloc);
  final statBuffer = calloc<Uint8>(512);
  try {
    if (stat(nativePath.cast(), statBuffer.cast()) != 0) {
      // Capture errno before any other native call can overwrite it.
      final errno = _readErrno?.call() ?? 0;
      throw nodeError(codeForErrno(errno), syscall, path);
    }
    // Darwin's struct stat has st_mode at byte 4; 64-bit Linux at byte 24.
    final data = ByteData.view(statBuffer.asTypedList(512).buffer);
    final mode = Platform.isMacOS
        ? data.getUint16(4, Endian.host)
        : data.getUint32(24, Endian.host);
    final fileType = mode & 0xf000;
    return NodePathEntriesStat(
      fileType == 0x4000,
      !followLinks && fileType == 0xa000,
    );
  } finally {
    calloc.free(nativePath);
    calloc.free(statBuffer);
  }
}

FileSystemEntityType _typeSync(
  String path,
  String syscall, {
  bool followLinks = true,
}) {
  try {
    final type = FileSystemEntity.typeSync(path, followLinks: followLinks);
    if (type == FileSystemEntityType.notFound) {
      throw nodeError('ENOENT', syscall, path);
    }
    return type;
  } on NodeError {
    rethrow;
  } on FileSystemException catch (error) {
    final code = _codeFromIoError(error);
    throw nodeError(code, syscall, path);
  }
}

String _codeFromIoError(FileSystemException error) {
  final errno = error.osError?.errorCode;
  if (errno == null) return 'UNKNOWN';
  if (Platform.isWindows) {
    switch (errno) {
      case 2:
      case 3:
        return 'ENOENT';
      case 5:
        return 'EACCES';
      case 267:
        return 'ENOTDIR';
      default:
        return 'UNKNOWN';
    }
  }
  return codeForErrno(errno);
}
