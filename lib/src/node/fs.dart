// Node `fs` compatibility: the synchronous calls the ported files make.
// No upstream counterpart. POSIX calls go to libc directly, so a failure keeps
// its errno (and so Node's `code`); dart:io would turn it into a lossy
// FileSystemException. File types come from dart:io once the libc call has
// succeeded; only the test-only statIdentitySync reads `struct stat` fields.
import 'dart:convert';
import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';
import 'package:path/path.dart' as path_utils;

import 'errno.dart';

final DynamicLibrary? _libc = _loadLibc();

class _Constants {
  const _Constants();
  int get O_RDONLY => 0;
  int get O_RDWR => 2;
  int get O_DIRECTORY => Platform.isMacOS ? 0x100000 : 0x10000;
  int get R_OK => 4;
  int get X_OK => 1;
  int get O_CREAT => 0x40;
  int get O_TRUNC => 0x200;
  int get O_WRONLY => 1;
  int get O_CLOEXEC => Platform.isMacOS ? 0x1000000 : 0x80000;
  int get O_NOFOLLOW => Platform.isMacOS ? 0x100 : 0x20000;
}

const constants = _Constants();
typedef _OpenN = Int32 Function(Pointer<Uint8>, Int32, Int32);
typedef _OpenD = int Function(Pointer<Uint8>, int, int);
typedef _CloseN = Int32 Function(Int32);
typedef _CloseD = int Function(int);
typedef _FchmodN = Int32 Function(Int32, Int32);
typedef _FchmodD = int Function(int, int);
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

/// Node's `fs.Stats` predicates. A `statSync` result never answers
/// `isSymbolicLink()`, since stat follows links.
class Stats {
  const Stats(this._type);
  final FileSystemEntityType _type;

  bool isFile() => _type == FileSystemEntityType.file;
  bool isDirectory() => _type == FileSystemEntityType.directory;
  bool isSymbolicLink() => _type == FileSystemEntityType.link;
  bool isFIFO() => _type == FileSystemEntityType.pipe;
  bool isSocket() => _type == FileSystemEntityType.unixDomainSock;
}

/// Node's `fs.Dirent`, as `readdirSync(p, {withFileTypes: true})` returns it.
/// dart:io does not tell character and block devices from files, so those
/// two predicates always answer false.
class Dirent {
  const Dirent(this.name, this._type);
  final String name;
  final FileSystemEntityType _type;

  bool isFile() => _type == FileSystemEntityType.file;
  bool isDirectory() => _type == FileSystemEntityType.directory;
  bool isSymbolicLink() => _type == FileSystemEntityType.link;
  bool isFIFO() => _type == FileSystemEntityType.pipe;
  bool isSocket() => _type == FileSystemEntityType.unixDomainSock;
  bool isCharacterDevice() => false;
  bool isBlockDevice() => false;
}

/// Test hook: sees `<call> <path>` for each lstatSync, statSync,
/// realpathSync and readlinkSync (the real-path `what it asks` tests).
void Function(String call)? fsCallObserver;

void _observe(String call, String path) => fsCallObserver?.call('$call $path');

/// Reproduce `fs.lstatSync(path)`.
Stats lstatSync(String path) {
  _observe('lstatSync', path);
  return _stat(path, 'lstat', followLinks: false);
}

/// Reproduce `fs.statSync(path)`.
Stats _statSync(String path) {
  _observe('statSync', path);
  return _stat(path, 'stat', followLinks: true);
}

/// Node's `fs.statSync`. A variable so a test can replace it, as upstream's
/// tests do with `spyOn(fs, 'statSync')`.
Stats Function(String path) statSync = _statSync;

/// Reproduce `fs.existsSync(path)`: true when `stat` succeeds, so a dangling
/// symbolic link does not exist.
bool existsSync(String path) {
  try {
    _stat(path, 'stat', followLinks: true);
    return true;
  } catch (_) {
    return false;
  }
}

/// Reproduce `fs.readdirSync(path, {withFileTypes: true})`.
List<Dirent> _readdirSync(String path, {bool withFileTypes = true}) {
  if (!withFileTypes) {
    throw UnimplementedError('readdirSync without withFileTypes');
  }
  try {
    return Directory(path).listSync(followLinks: false).map((entity) {
      final type = FileSystemEntity.typeSync(entity.path, followLinks: false);
      final name = entity.path.replaceAll('\\', '/').split('/').last;
      return Dirent(name, type);
    }).toList();
  } on FileSystemException catch (error) {
    throw nodeError(
      _codeFromIoError(error),
      'scandir',
      path,
      message: error.message,
    );
  }
}

/// Node's `fs.readdirSync`. A variable so a test can replace it, as upstream's
/// tests do with `spyOn(fs, 'readdirSync')`.
List<Dirent> Function(String path, {bool withFileTypes}) readdirSync =
    _readdirSync;

Stats _stat(String path, String syscall, {required bool followLinks}) {
  final libc = _libc;
  if (libc != null) {
    final call = libc.lookupFunction<_LstatNative, _LstatDart>(syscall);
    final nativePath = path.toNativeUtf8(allocator: calloc);
    final statBuffer = calloc<Uint8>(512);
    try {
      if (call(nativePath.cast(), statBuffer.cast()) != 0) {
        // Read errno before any other native call can overwrite it.
        final errno = _readErrno?.call() ?? 0;
        throw nodeError(codeForErrno(errno), syscall, path);
      }
    } finally {
      calloc.free(nativePath);
      calloc.free(statBuffer);
    }
  }
  try {
    final type = FileSystemEntity.typeSync(path, followLinks: followLinks);
    if (type == FileSystemEntityType.notFound) {
      throw nodeError('ENOENT', syscall, path);
    }
    return Stats(type);
  } on NodeError {
    rethrow;
  } on FileSystemException catch (error) {
    throw nodeError(_codeFromIoError(error), syscall, path);
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
String _realpathSync(String path) {
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

/// Node's `fs.realpathSync`. A variable so a test can replace it, as upstream's
/// tests do with `spyOn(fs, 'realpathSync')`.
String Function(String path) realpathSync = _realpathSync;

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

Object readFileSync(String path, [Object? options]) {
  final bytes = File(path).readAsBytesSync();
  final encoding = options is String
      ? options
      : options is Map
      ? options['encoding'] as String?
      : null;
  return encoding == null ? bytes : utf8.decode(bytes, allowMalformed: true);
}

void writeFileSync(
  Object target,
  Object contents, [
  Map<String, Object?> options = const {},
]) {
  final bytes = contents is List<int>
      ? contents
      : utf8.encode(contents.toString());
  final path = target.toString();
  File(path).writeAsBytesSync(bytes);
  final mode = options['mode'];
  if (mode is int && (Platform.isLinux || Platform.isMacOS)) {
    Process.runSync('chmod', [mode.toRadixString(8), path]);
  }
}

String mkdtempSync(String prefix) =>
    Directory.systemTemp.createTempSync(prefix).path;

void unlinkSync(String path) => File(path).deleteSync();
void rmdirSync(String path) => Directory(path).deleteSync();
void chmodSync(String path, int mode) {
  if (Platform.isWindows) throw UnimplementedError('chmodSync on Windows');
  final result = Process.runSync('chmod', [mode.toRadixString(8), path]);
  if (result.exitCode != 0) throw nodeError('EACCES', 'chmod', path);
}

void accessSync(String path, [int mode = 0]) {
  final stat = FileStat.statSync(path);
  if (stat.type == FileSystemEntityType.notFound)
    throw nodeError('ENOENT', 'access', path);
  if ((mode & constants.X_OK) != 0 &&
      Platform.isLinux &&
      (stat.mode & 0x49) == 0)
    throw nodeError('EACCES', 'access', path);
}

int openSync(String path, int flags, [int mode = 0o666]) {
  final libc = _libc;
  if (libc == null) throw UnimplementedError('openSync on Windows');
  final open = libc.lookupFunction<_OpenN, _OpenD>('open');
  final nativePath = path.toNativeUtf8(allocator: calloc);
  try {
    final fd = open(nativePath.cast(), flags, mode);
    if (fd < 0) throw nodeError('ENOENT', 'open', path);
    return fd;
  } finally {
    calloc.free(nativePath);
  }
}

void closeSync(int fd) {
  final libc = _libc;
  if (libc == null) throw UnimplementedError('closeSync on Windows');
  if (libc.lookupFunction<_CloseN, _CloseD>('close')(fd) != 0) {
    throw nodeError('EBADF', 'close', '$fd');
  }
}

void fchmodSync(int fd, int mode) {
  final libc = _libc;
  if (libc == null) throw UnimplementedError('fchmodSync on Windows');
  if (libc.lookupFunction<_FchmodN, _FchmodD>('fchmod')(fd, mode) != 0) {
    throw nodeError('EBADF', 'fchmod', '$fd');
  }
}

void rmSync(String path, [Map<String, Object?> options = const {}]) {
  final entity = FileSystemEntity.typeSync(path, followLinks: false);
  if (entity == FileSystemEntityType.notFound) {
    if (options['force'] == true) return;
    throw nodeError('ENOENT', 'lstat', path);
  }
  if (entity == FileSystemEntityType.directory) {
    Directory(path).deleteSync(recursive: options['recursive'] == true);
  } else {
    Link(path).deleteSync();
  }
}
