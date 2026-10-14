// Node `fs` compatibility: the synchronous calls the ported files make.
// No upstream counterpart. POSIX calls go to libc directly, so a failure keeps
// its errno (and so Node's `code`); dart:io would turn it into a lossy
// FileSystemException. File types come from dart:io once the libc call has
// succeeded; only the test-only statIdentitySync reads `struct stat` fields.
import 'dart:async';
import 'dart:convert';
import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';
import 'package:path/path.dart' as path_utils;

import 'buffer.dart';
import 'errno.dart';
import 'fd_io.dart';
import 'stream.dart' as stream;

final DynamicLibrary? _libc = _loadLibc();

bool get _linuxGeneric => Platform.isLinux && Abi.current() != Abi.linuxX64;

/// `fs.constants` with the host's values (Darwin, Linux x86-64, and the
/// generic Linux layout used by arm64 and riscv64).
class _Constants {
  const _Constants();
  int get O_RDONLY => 0;
  int get O_WRONLY => 1;
  int get O_RDWR => 2;
  int get O_CREAT => Platform.isMacOS ? 0x200 : 0x40;
  int get O_EXCL => Platform.isMacOS ? 0x800 : 0x80;
  int get O_TRUNC => Platform.isMacOS ? 0x400 : 0x200;
  int get O_APPEND => Platform.isMacOS ? 0x8 : 0x400;
  int get O_DIRECTORY =>
      Platform.isMacOS ? 0x100000 : (_linuxGeneric ? 0x4000 : 0x10000);
  int get O_NOFOLLOW =>
      Platform.isMacOS ? 0x100 : (_linuxGeneric ? 0x8000 : 0x20000);
  int get O_CLOEXEC => Platform.isMacOS ? 0x1000000 : 0x80000;
  int get F_OK => 0;
  int get X_OK => 1;
  int get W_OK => 2;
  int get R_OK => 4;
  int get S_IFMT => 0xf000;
  int get S_IFREG => 0x8000;
  int get S_IFDIR => 0x4000;
  int get S_IFCHR => 0x2000;
  int get S_IFBLK => 0x6000;
  int get S_IFIFO => 0x1000;
  int get S_IFLNK => 0xa000;
  int get S_IFSOCK => 0xc000;
}

const constants = _Constants();
typedef _OpenN = Int32 Function(Pointer<Uint8>, Int32, VarArgs<(Int32,)>);
typedef _OpenD = int Function(Pointer<Uint8>, int, int);
typedef _CloseN = Int32 Function(Int32);
typedef _CloseD = int Function(int);
typedef _FchmodN = Int32 Function(Int32, Int32);
typedef _FchmodD = int Function(int, int);
typedef _WriteN = IntPtr Function(Int32, Pointer<Uint8>, IntPtr);
typedef _WriteD = int Function(int, Pointer<Uint8>, int);
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

/// Node's `fs.Stats`: the `struct stat` fields and type predicates. A
/// `statSync` result never answers `isSymbolicLink()`, since stat follows
/// links.
class Stats {
  Stats({
    required this.dev,
    required this.ino,
    required this.mode,
    required this.nlink,
    required this.uid,
    required this.gid,
    required this.rdev,
    required this.size,
    required this.blksize,
    required this.blocks,
    required this.atimeMs,
    required this.mtimeMs,
    required this.ctimeMs,
    required this.birthtimeMs,
  });

  /// Stats carrying only a file type, for tests replacing `statSync`.
  factory Stats.ofType(FileSystemEntityType type, {int size = 0}) => Stats(
    dev: 0,
    ino: 0,
    mode: _modeForType(type),
    nlink: 1,
    uid: 0,
    gid: 0,
    rdev: 0,
    size: size,
    blksize: 4096,
    blocks: 0,
    atimeMs: 0,
    mtimeMs: 0,
    ctimeMs: 0,
    birthtimeMs: 0,
  );

  final int dev;
  final int ino;
  final int mode;
  final int nlink;
  final int uid;
  final int gid;
  final int rdev;
  final int size;
  final int blksize;
  final int blocks;
  final double atimeMs;
  final double mtimeMs;
  final double ctimeMs;
  final double birthtimeMs;

  DateTime get atime => _date(atimeMs);
  DateTime get mtime => _date(mtimeMs);
  DateTime get ctime => _date(ctimeMs);
  DateTime get birthtime => _date(birthtimeMs);

  static DateTime _date(double ms) =>
      DateTime.fromMicrosecondsSinceEpoch((ms * 1000).round());

  int get _format => mode & 0xf000;
  bool isFile() => _format == 0x8000;
  bool isDirectory() => _format == 0x4000;
  bool isSymbolicLink() => _format == 0xa000;
  bool isFIFO() => _format == 0x1000;
  bool isSocket() => _format == 0xc000;
  bool isCharacterDevice() => _format == 0x2000;
  bool isBlockDevice() => _format == 0x6000;
}

int _modeForType(FileSystemEntityType type) => switch (type) {
  FileSystemEntityType.file => 0x8000,
  FileSystemEntityType.directory => 0x4000,
  FileSystemEntityType.link => 0xa000,
  FileSystemEntityType.pipe => 0x1000,
  FileSystemEntityType.unixDomainSock => 0xc000,
  _ => 0,
};

/// Decode `struct stat` as the host's `stat`, `lstat` and `fstat` fill it.
Stats _parseStat(ByteData d) {
  int u32(int o) => d.getUint32(o, Endian.host);
  int i64(int o) => d.getInt64(o, Endian.host);
  double ts(int o) => i64(o) * 1000 + i64(o + 8) / 1e6;
  if (Platform.isMacOS) {
    // struct stat (64-bit inode layout).
    return Stats(
      dev: d.getInt32(0, Endian.host),
      mode: d.getUint16(4, Endian.host),
      nlink: d.getUint16(6, Endian.host),
      ino: d.getUint64(8, Endian.host),
      uid: u32(16),
      gid: u32(20),
      rdev: d.getInt32(24, Endian.host),
      atimeMs: ts(32),
      mtimeMs: ts(48),
      ctimeMs: ts(64),
      birthtimeMs: ts(80),
      size: i64(96),
      blocks: i64(104),
      blksize: d.getInt32(112, Endian.host),
    );
  }
  if (_linuxGeneric) {
    return Stats(
      dev: d.getUint64(0, Endian.host),
      ino: d.getUint64(8, Endian.host),
      mode: u32(16),
      nlink: u32(20),
      uid: u32(24),
      gid: u32(28),
      rdev: d.getUint64(32, Endian.host),
      size: i64(48),
      blksize: d.getInt32(56, Endian.host),
      blocks: i64(64),
      atimeMs: ts(72),
      mtimeMs: ts(88),
      ctimeMs: ts(104),
      // Linux stat(2) has no birth time; Node reports ctime's epoch zero.
      birthtimeMs: 0,
    );
  }
  return Stats(
    dev: d.getUint64(0, Endian.host),
    ino: d.getUint64(8, Endian.host),
    nlink: d.getUint64(16, Endian.host),
    mode: u32(24),
    uid: u32(28),
    gid: u32(32),
    rdev: d.getUint64(40, Endian.host),
    size: i64(48),
    blksize: i64(56),
    blocks: i64(64),
    atimeMs: ts(72),
    mtimeMs: ts(88),
    ctimeMs: ts(104),
    birthtimeMs: 0,
  );
}

typedef _FstatN = Int32 Function(Int32, Pointer<Void>);
typedef _FstatD = int Function(int, Pointer<Void>);
typedef _XstatN = Int32 Function(Int32, Pointer<Uint8>, Pointer<Void>);
typedef _XstatD = int Function(int, Pointer<Uint8>, Pointer<Void>);
typedef _FxstatN = Int32 Function(Int32, Int32, Pointer<Void>);
typedef _FxstatD = int Function(int, int, Pointer<Void>);

/// The libc symbol for [name]: Darwin x86-64 exports the 64-bit-inode
/// variant under a suffix.
String _statSymbol(String name) =>
    Platform.isMacOS && Abi.current() == Abi.macosX64 ? '$name\$INODE64' : name;

/// glibc before 2.33 exports only `__xstat` and friends.
int get _statVersion => _linuxGeneric ? 0 : 1;

int Function(Pointer<Uint8>, Pointer<Void>) _pathStatCall(
  DynamicLibrary libc,
  String name,
) {
  try {
    return libc.lookupFunction<_LstatNative, _LstatDart>(_statSymbol(name));
  } on ArgumentError {
    final x = libc.lookupFunction<_XstatN, _XstatD>('__x$name');
    return (p, b) => x(_statVersion, p, b);
  }
}

int Function(int, Pointer<Void>) _fstatCall(DynamicLibrary libc) {
  try {
    return libc.lookupFunction<_FstatN, _FstatD>(_statSymbol('fstat'));
  } on ArgumentError {
    final x = libc.lookupFunction<_FxstatN, _FxstatD>('__fxstat');
    return (fd, b) => x(_statVersion, fd, b);
  }
}

int _errno() => _readErrno?.call() ?? 0;

NodeError _errnoError(String syscall, [String? path]) {
  final code = codeForErrno(_errno());
  if (path != null) return nodeError(code, syscall, path);
  return NodeError(
    '$code: ${_reason(code)}, $syscall',
    code: code,
    syscall: syscall,
  );
}

String _reason(String code) => nodeError(
  code,
  '',
  '',
).message.split(', ').first.substring(code.length + 2);

DynamicLibrary _requireLibc(String call) {
  final libc = _libc;
  if (libc == null) {
    throw UnsupportedError('fs.$call needs a POSIX libc');
  }
  return libc;
}

/// Reproduce `fs.fstatSync(fd)`.
Stats fstatSync(int fd) {
  final libc = _libc;
  if (libc == null) throw UnsupportedError('fs.fstatSync needs a POSIX libc');
  final buffer = calloc<Uint8>(512);
  try {
    if (_fstatCall(libc)(fd, buffer.cast()) != 0) throw _errnoError('fstat');
    return _parseStat(ByteData.sublistView(buffer.asTypedList(512)));
  } finally {
    calloc.free(buffer);
  }
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

Stats _lstatSync(String path) {
  _observe('lstatSync', path);
  return _stat(path, 'lstat', followLinks: false);
}

/// Node's `fs.lstatSync`. A variable so a test can replace it, as upstream's
/// tests do with `spyOn(fs, 'lstatSync')`.
Stats Function(String path) lstatSync = _lstatSync;

void _symlinkSync(String target, String path) => Link(path).createSync(target);

/// Node's `fs.symlinkSync(target, path)`. A variable so a test can replace it.
void Function(String target, String path) symlinkSync = _symlinkSync;

/// Node's `fs.linkSync(existingPath, newPath)`: a hard link, via `ln` since
/// dart:io has no link(2).
void linkSync(String existingPath, String newPath) {
  _observe('linkSync', newPath);
  final r = Process.runSync('ln', [existingPath, newPath]);
  if (r.exitCode != 0) {
    throw FileSystemException('link failed: ${r.stderr}', newPath);
  }
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
bool _existsSync(String path) {
  try {
    _stat(path, 'stat', followLinks: true);
    return true;
  } catch (_) {
    return false;
  }
}

/// Node's `fs.existsSync`. A variable so a test can replace it, as upstream's
/// tests do with `spyOn(fs, 'existsSync')`.
bool Function(String path) existsSync = _existsSync;

/// Reproduce `fs.readdirSync(path, {withFileTypes: true})`.
List<Dirent> _readdirSync(String path, {bool withFileTypes = false}) {
  try {
    if (!withFileTypes) {
      // Statically callers read `.name`; use readdirNamesSync for Strings.
      return readdirNamesSync(
        path,
      ).map((n) => Dirent(n, FileSystemEntityType.file)).toList();
    }
    return Directory(path).listSync(followLinks: false).map((entity) {
      final type = FileSystemEntity.typeSync(entity.path, followLinks: false);
      final name =
          (Platform.isWindows ? entity.path.replaceAll('\\', '/') : entity.path)
              .split('/')
              .last;
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
    final call = _pathStatCall(libc, syscall);
    final nativePath = path.toNativeUtf8(allocator: calloc);
    final statBuffer = calloc<Uint8>(512);
    try {
      if (call(nativePath.cast(), statBuffer.cast()) != 0) {
        // Read errno before any other native call can overwrite it.
        throw nodeError(codeForErrno(_errno()), syscall, path);
      }
      return _parseStat(ByteData.sublistView(statBuffer.asTypedList(512)));
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
    final stat = FileStat.statSync(path);
    final ms = stat.modified.millisecondsSinceEpoch.toDouble();
    return Stats(
      dev: 0,
      ino: 0,
      mode: _modeForType(type) | (stat.mode & 0xfff),
      nlink: 1,
      uid: 0,
      gid: 0,
      rdev: 0,
      size: stat.size,
      blksize: 4096,
      blocks: (stat.size + 511) ~/ 512,
      atimeMs: stat.accessed.millisecondsSinceEpoch.toDouble(),
      mtimeMs: ms,
      ctimeMs: stat.changed.millisecondsSinceEpoch.toDouble(),
      birthtimeMs: ms,
    );
  } on NodeError {
    rethrow;
  } on FileSystemException catch (error) {
    throw nodeError(_codeFromIoError(error), syscall, path);
  }
}

/// Return `dev:ino`, the identity pair read by the upstream property test's
/// `fs.statSync`.
String statIdentitySync(String path) {
  final stat = _stat(path, 'stat', followLinks: true);
  if (_libc == null) return '${stat.mode}:${stat.size}';
  return '${stat.dev}:${stat.ino}';
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

/// The real path of [path] as the kernel names it, by opening it with O_PATH
/// and reading /proc/self/fd. Null when that cannot be done or says nothing.
String? _realpathViaProc(String path) {
  final libc = _libc;
  if (libc == null) return null;
  const oPath = 0x200000; // O_PATH, asm-generic (arm64) value is 0x200000
  final open = libc.lookupFunction<_OpenN, _OpenD>('open');
  final fd = _withPath(path, (p) => open(p, oPath | 0x80000, 0));
  if (fd < 0) return null;
  try {
    final target = readlinkSync('/proc/self/fd/$fd');
    return target.startsWith('/') && !target.endsWith(' (deleted)')
        ? target
        : null;
  } on Object {
    return null;
  } finally {
    libc.lookupFunction<_CloseN, _CloseD>('close')(fd);
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
        final code = codeForErrno(errno);
        if (Platform.isLinux && (code == 'ENAMETOOLONG' || code == 'EACCES')) {
          // glibc fails when a link is followed to a name over PATH_MAX, or
          // through a directory it cannot search, but the kernel resolves it
          // (as Bun's realpathSync does, which upstream's tests run under):
          // ask it for the opened object's location.
          final viaProc = _realpathViaProc(resolvedPath);
          if (viaProc != null) return viaProc;
        }
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

/// Node `fs.createReadStream(path, {fd})`: a Readable over [path], or over
/// the open descriptor [fd] (then [path] is ignored, as in Node).
stream.Readable createReadStream(String path, {int? fd}) {
  final Stream<List<int>> source;
  final void Function() close;
  if (fd != null) {
    final s = fdSocket(fd, writable: false);
    source = s;
    close = s.destroy;
  } else {
    source = File(path).openRead();
    close = () {};
  }
  late final StreamSubscription<List<int>> sub;
  late final stream.Readable readable;
  readable = stream.Readable(
    read: (int _) => sub.resume(),
    destroy: (Object? error, Function callback) {
      sub.cancel();
      close();
      callback(error);
    },
  );
  sub = source.listen(
    (chunk) {
      if (!readable.push(Uint8List.fromList(chunk))) sub.pause();
    },
    onError: (Object e) => readable.destroy(e),
    onDone: () => readable.push(null),
  );
  sub.pause();
  return readable;
}

typedef _ReadN = IntPtr Function(Int32, Pointer<Uint8>, IntPtr);
typedef _ReadD = int Function(int, Pointer<Uint8>, int);

/// Reproduce `fs.readFileSync(pathOrFd, options)`: a [Buffer], or a String
/// when an encoding is given. An int [target] reads the descriptor to EOF.
Object readFileSync(Object target, [Object? options]) {
  final encoding = options is String
      ? options
      : options is Map
      ? options['encoding'] as String?
      : null;
  List<int> bytes;
  if (target is int) {
    final libc = _requireLibc('readFileSync');
    final read = libc.lookupFunction<_ReadN, _ReadD>('read');
    final chunk = calloc<Uint8>(65536);
    final out = BytesBuilder();
    try {
      while (true) {
        final n = read(target, chunk, 65536);
        if (n < 0) {
          if (codeForErrno(_errno()) == 'EINTR') continue;
          throw _errnoError('read');
        }
        if (n == 0) break;
        out.add(chunk.asTypedList(n));
      }
    } finally {
      calloc.free(chunk);
    }
    bytes = out.takeBytes();
  } else {
    final path = target.toString();
    if (_libc != null) {
      final fd = openSync(path, 'r');
      try {
        return readFileSync(fd, options);
      } finally {
        closeSync(fd);
      }
    }
    try {
      bytes = File(path).readAsBytesSync();
    } on FileSystemException catch (error) {
      throw nodeError(_codeFromIoError(error), 'open', path);
    }
  }
  final buffer = Buffer.wrap(Uint8List.fromList(bytes));
  return encoding == null ? buffer : buffer.toString(encoding);
}

typedef _ReadvN = IntPtr Function(Int32, Pointer<Uint8>, Int32);
typedef _ReadvD = int Function(int, Pointer<Uint8>, int);
typedef _PreadvN = IntPtr Function(Int32, Pointer<Uint8>, Int32, Int64);
typedef _PreadvD = int Function(int, Pointer<Uint8>, int, int);
typedef _PathModeN = Int32 Function(Pointer<Uint8>, Int32);
typedef _PathModeD = int Function(Pointer<Uint8>, int);
typedef _PathN = Int32 Function(Pointer<Uint8>);
typedef _PathD = int Function(Pointer<Uint8>);
typedef _TwoPathN = Int32 Function(Pointer<Uint8>, Pointer<Uint8>);
typedef _TwoPathD = int Function(Pointer<Uint8>, Pointer<Uint8>);

T _withPath<T>(String path, T Function(Pointer<Uint8>) body) {
  final native = path.toNativeUtf8(allocator: calloc);
  try {
    return body(native.cast());
  } finally {
    calloc.free(native);
  }
}

List<int> _contentBytes(Object contents, String? encoding) {
  if (contents is List<int>) return contents;
  final text = contents.toString();
  if (encoding == null || encoding == 'utf8' || encoding == 'utf-8') {
    return utf8.encode(text);
  }
  return Buffer.from(text, encoding).toUint8List();
}

void _writeAll(DynamicLibrary libc, int fd, List<int> bytes) {
  final write = libc.lookupFunction<_WriteN, _WriteD>('write');
  final data = calloc<Uint8>(bytes.isEmpty ? 1 : bytes.length);
  try {
    data.asTypedList(bytes.length).setAll(0, bytes);
    var offset = 0;
    while (offset < bytes.length) {
      final count = write(fd, data + offset, bytes.length - offset);
      if (count < 0) {
        if (codeForErrno(_errno()) == 'EINTR') continue;
        throw _errnoError('write');
      }
      offset += count;
    }
  } finally {
    calloc.free(data);
  }
}

/// Node's flag strings for `openSync` and `writeFileSync`'s `flag`.
int _flagsFor(Object flags) {
  if (flags is int) return flags;
  final c = constants;
  return switch (flags) {
    'r' => c.O_RDONLY,
    'r+' => c.O_RDWR,
    'w' => c.O_TRUNC | c.O_CREAT | c.O_WRONLY,
    'wx' || 'xw' => c.O_TRUNC | c.O_CREAT | c.O_WRONLY | c.O_EXCL,
    'w+' => c.O_TRUNC | c.O_CREAT | c.O_RDWR,
    'wx+' || 'xw+' => c.O_TRUNC | c.O_CREAT | c.O_RDWR | c.O_EXCL,
    'a' => c.O_APPEND | c.O_CREAT | c.O_WRONLY,
    'ax' || 'xa' => c.O_APPEND | c.O_CREAT | c.O_WRONLY | c.O_EXCL,
    'a+' => c.O_APPEND | c.O_CREAT | c.O_RDWR,
    'ax+' || 'xa+' => c.O_APPEND | c.O_CREAT | c.O_RDWR | c.O_EXCL,
    _ => throw ArgumentError.value(flags, 'flags', 'Invalid value'),
  };
}

/// Reproduce `fs.writeFileSync(file, data, options)`. [target] is a path or
/// an open descriptor; [options] is an encoding string or a map with
/// `encoding`, `mode` (applied only when the file is created) and `flag`.
void writeFileSync(Object target, Object contents, [Object? options]) {
  final map = options is Map ? options : const {};
  final encoding = options is String ? options : map['encoding'] as String?;
  final bytes = _contentBytes(contents, encoding);
  final libc = _libc;
  if (target is int) {
    _writeAll(_requireLibc('writeFileSync'), target, bytes);
    return;
  }
  final path = target.toString();
  if (libc == null) {
    try {
      File(path).writeAsBytesSync(
        bytes,
        mode: (map['flag'] as String? ?? 'w').startsWith('a')
            ? FileMode.append
            : FileMode.write,
      );
    } on FileSystemException catch (error) {
      throw nodeError(_codeFromIoError(error), 'open', path);
    }
    return;
  }
  final fd = openSync(
    path,
    (map['flag'] as Object?) ?? 'w',
    (map['mode'] as int?) ?? 438,
  );
  try {
    _writeAll(libc, fd, bytes);
  } finally {
    closeSync(fd);
  }
}

/// Reproduce `fs.readvSync(fd, buffers[, position])`: fills each buffer in
/// turn and returns the number of bytes read.
int readvSync(int fd, List<List<int>> buffers, [int? position]) {
  final libc = _requireLibc('readvSync');
  final total = buffers.fold<int>(0, (sum, b) => sum + b.length);
  final data = calloc<Uint8>(total == 0 ? 1 : total);
  // struct iovec { void *base; size_t len; }
  final iov = calloc<IntPtr>(buffers.isEmpty ? 2 : buffers.length * 2);
  try {
    var offset = 0;
    for (var i = 0; i < buffers.length; i++) {
      iov[i * 2] = (data + offset).address;
      iov[i * 2 + 1] = buffers[i].length;
      offset += buffers[i].length;
    }
    final count = position == null
        ? libc.lookupFunction<_ReadvN, _ReadvD>('readv')(
            fd,
            iov.cast(),
            buffers.length,
          )
        : libc.lookupFunction<_PreadvN, _PreadvD>('preadv')(
            fd,
            iov.cast(),
            buffers.length,
            position,
          );
    if (count < 0) throw _errnoError('read');
    final read = data.asTypedList(total == 0 ? 1 : total);
    var remaining = count;
    offset = 0;
    for (final buffer in buffers) {
      final n = remaining < buffer.length ? remaining : buffer.length;
      buffer.setRange(0, n, read, offset);
      offset += buffer.length;
      remaining -= n;
    }
    return count;
  } finally {
    calloc.free(data);
    calloc.free(iov);
  }
}

String mkdtempSync(String prefix) {
  final libc = _libc;
  if (libc == null) {
    return Directory(
      path_utils.dirname(prefix),
    ).createTempSync(path_utils.basename(prefix)).path;
  }
  final template = '${prefix}XXXXXX';
  return _withPath(template, (p) {
    final result = libc
        .lookupFunction<
          Pointer<Uint8> Function(Pointer<Uint8>),
          Pointer<Uint8> Function(Pointer<Uint8>)
        >('mkdtemp')(p);
    if (result.address == 0) throw _errnoError('mkdtemp', template);
    return result.cast<Utf8>().toDartString();
  });
}

/// Reproduce `fs.mkdirSync(path, {recursive, mode})`. With `recursive`,
/// returns the first directory created (null if it already existed).
String? mkdirSync(String path, [Map<String, Object?> options = const {}]) {
  final mode = (options['mode'] as int?) ?? 0x1ff;
  final recursive = options['recursive'] == true;
  final libc = _libc;
  if (libc == null) {
    final existed = Directory(path).existsSync();
    try {
      Directory(path).createSync(recursive: recursive);
    } on FileSystemException catch (error) {
      throw nodeError(_codeFromIoError(error), 'mkdir', path);
    }
    return recursive && !existed ? path_utils.absolute(path) : null;
  }
  final mkdir = libc.lookupFunction<_PathModeN, _PathModeD>('mkdir');
  int make(String p) => _withPath(p, (n) => mkdir(n, mode));
  if (!recursive) {
    if (make(path) != 0) throw _errnoError('mkdir', path);
    return null;
  }
  final absolute = path_utils.normalize(path_utils.absolute(path));
  final missing = <String>[];
  var current = absolute;
  while (true) {
    try {
      final stat = _stat(current, 'stat', followLinks: true);
      if (!stat.isDirectory()) throw nodeError('EEXIST', 'mkdir', path);
      break;
    } on NodeError catch (error) {
      if (error.code != 'ENOENT') {
        if (error.code == 'EEXIST') rethrow;
        throw nodeError(error.code, 'mkdir', path);
      }
    }
    missing.add(current);
    final parent = path_utils.dirname(current);
    if (parent == current) break;
    current = parent;
  }
  for (final dir in missing.reversed) {
    if (make(dir) != 0) {
      final code = codeForErrno(_errno());
      if (code == 'EEXIST' && Directory(dir).existsSync()) continue;
      throw nodeError(code, 'mkdir', path);
    }
  }
  return missing.isEmpty ? null : missing.last;
}

void renameSync(String from, String to) {
  final libc = _libc;
  if (libc == null) {
    try {
      FileSystemEntity.typeSync(from) == FileSystemEntityType.directory
          ? Directory(from).renameSync(to)
          : File(from).renameSync(to);
    } on FileSystemException catch (error) {
      throw _twoPathError(_codeFromIoError(error), 'rename', from, to);
    }
    return;
  }
  final rename = libc.lookupFunction<_TwoPathN, _TwoPathD>('rename');
  final status = _withPath(from, (a) => _withPath(to, (b) => rename(a, b)));
  if (status != 0) {
    throw _twoPathError(codeForErrno(_errno()), 'rename', from, to);
  }
}

NodeError _twoPathError(String code, String syscall, String from, String to) =>
    NodeError(
      '$code: ${_reason(code)}, $syscall \'$from\' -> \'$to\'',
      code: code,
      syscall: syscall,
      path: from,
      dest: to,
    );

void _pathCall(String symbol, String syscall, String path) {
  final libc = _libc!;
  final call = libc.lookupFunction<_PathN, _PathD>(symbol);
  if (_withPath(path, call) != 0) throw _errnoError(syscall, path);
}

void unlinkSync(String path) {
  if (_libc != null) return _pathCall('unlink', 'unlink', path);
  try {
    File(path).deleteSync();
  } on FileSystemException catch (error) {
    throw nodeError(_codeFromIoError(error), 'unlink', path);
  }
}

/// Node's `fs.writeSync(fd, data)`: one write(2) of a String (UTF-8, or
/// [encoding]) or bytes; returns the number of bytes written.
int writeSync(int fd, Object data, [int? position, String? encoding]) {
  if (position != null) {
    throw UnsupportedError('writeSync with a position is not supported');
  }
  final bytes = data is List<int>
      ? data
      : Buffer.from(data.toString(), encoding ?? 'utf8').toUint8List();
  final libc = _requireLibc('writeSync');
  final write = libc.lookupFunction<_WriteN, _WriteD>('write');
  final buffer = calloc<Uint8>(bytes.isEmpty ? 1 : bytes.length);
  try {
    buffer.asTypedList(bytes.length).setAll(0, bytes);
    while (true) {
      final count = write(fd, buffer, bytes.length);
      if (count >= 0) return count;
      if (codeForErrno(_errno()) == 'EINTR') continue;
      throw _errnoError('write');
    }
  } finally {
    calloc.free(buffer);
  }
}

/// Node's `fs.copyFileSync(src, dest, mode)`. `mode` 1 is COPYFILE_EXCL:
/// fail with EEXIST when [dest] exists.
void copyFileSync(String src, String dest, [int mode = 0]) {
  if (mode & 1 != 0 &&
      FileSystemEntity.typeSync(dest, followLinks: false) !=
          FileSystemEntityType.notFound) {
    throw nodeError('EEXIST', 'copyfile', src);
  }
  try {
    File(src).copySync(dest);
  } on FileSystemException catch (error) {
    throw nodeError(_codeFromIoError(error), 'copyfile', src);
  }
}

void rmdirSync(String path) {
  if (_libc != null) return _pathCall('rmdir', 'rmdir', path);
  try {
    Directory(path).deleteSync();
  } on FileSystemException catch (error) {
    throw nodeError(_codeFromIoError(error), 'rmdir', path);
  }
}

void chmodSync(String path, int mode) {
  final libc = _requireLibc('chmodSync');
  final chmod = libc.lookupFunction<_PathModeN, _PathModeD>('chmod');
  if (_withPath(path, (p) => chmod(p, mode)) != 0) {
    throw _errnoError('chmod', path);
  }
}

void accessSync(String path, [int mode = 0]) {
  final libc = _libc;
  if (libc == null) {
    if (FileSystemEntity.typeSync(path) == FileSystemEntityType.notFound) {
      throw nodeError('ENOENT', 'access', path);
    }
    return;
  }
  final access = libc.lookupFunction<_PathModeN, _PathModeD>('access');
  if (_withPath(path, (p) => access(p, mode)) != 0) {
    throw _errnoError('access', path);
  }
}

/// Reproduce `fs.openSync(path, flags, mode)`; [flags] is a number or a
/// Node flag string such as `'r'`.
int openSync(String path, [Object flags = 'r', int mode = 438]) {
  final libc = _requireLibc('openSync');
  final open = libc.lookupFunction<_OpenN, _OpenD>('open');
  final fd = _withPath(path, (p) => open(p, _flagsFor(flags), mode));
  if (fd < 0) throw _errnoError('open', path);
  return fd;
}

void closeSync(int fd) {
  final libc = _requireLibc('closeSync');
  if (libc.lookupFunction<_CloseN, _CloseD>('close')(fd) != 0) {
    throw _errnoError('close');
  }
}

void fchmodSync(int fd, int mode) {
  final libc = _requireLibc('fchmodSync');
  if (libc.lookupFunction<_FchmodN, _FchmodD>('fchmod')(fd, mode) != 0) {
    throw _errnoError('fchmod');
  }
}

void rmSync(String path, [Map<String, Object?> options = const {}]) {
  final entity = FileSystemEntity.typeSync(path, followLinks: false);
  if (entity == FileSystemEntityType.notFound) {
    if (options['force'] == true) return;
    throw nodeError('ENOENT', 'lstat', path);
  }
  if (entity == FileSystemEntityType.directory) {
    if (options['recursive'] != true) {
      throw NodeError(
        'Path is a directory: rm returned EISDIR (is a directory) $path',
        code: 'ERR_FS_EISDIR',
        syscall: 'rm',
        path: path,
      );
    }
    try {
      Directory(path).deleteSync(recursive: true);
    } on FileSystemException catch (error) {
      throw nodeError(_codeFromIoError(error), 'rm', path);
    }
  } else {
    try {
      unlinkSync(path);
    } on NodeError catch (error) {
      if (error.code == 'ENOENT' && options['force'] == true) return;
      rethrow;
    }
  }
}

/// Node's `fs.readdirSync(path)` without file types: entry names.
List<String> readdirNamesSync(String path) {
  try {
    return Directory(path)
        .listSync(followLinks: false)
        .map((e) => e.path.replaceAll('\\', '/').split('/').last)
        .toList();
  } on FileSystemException catch (error) {
    throw nodeError(
      _codeFromIoError(error),
      'scandir',
      path,
      message: error.message,
    );
  }
}
