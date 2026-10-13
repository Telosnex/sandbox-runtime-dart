// Additional Node fs surface needed by sandbox-utils.ts.
import 'dart:io';

import 'errno.dart';

/// The Dirent subset read by the glob walker.
class Dirent {
  const Dirent(this.name, this._kind);
  final String name;
  final FileSystemEntityType _kind;

  bool isFile() => _kind == FileSystemEntityType.file;
  bool isDirectory() => _kind == FileSystemEntityType.directory;
  bool isSymbolicLink() => _kind == FileSystemEntityType.link;
  bool isFIFO() => false;
  bool isSocket() => false;
  bool isCharacterDevice() => false;
  bool isBlockDevice() => false;
}

/// The Stats subset used when following links.
class Stats {
  const Stats(this._kind);
  final FileSystemEntityType _kind;
  bool isDirectory() => _kind == FileSystemEntityType.directory;
}

/// The lstat `isDirectory()` query needed when a Dirent has no known type.
bool isDirectorySync(String path, {bool followLinks = false}) {
  try {
    final type = FileSystemEntity.typeSync(path, followLinks: followLinks);
    if (type == FileSystemEntityType.notFound) {
      throw nodeError('ENOENT', 'lstat', path);
    }
    return type == FileSystemEntityType.directory;
  } on FileSystemException catch (error) {
    throw _nodeFsError(error, 'lstat', path);
  }
}

/// Node's synchronous `readdirSync(path, {withFileTypes: true})` subset.
List<Dirent> readdirSync(String path, {bool withFileTypes = true}) {
  try {
    return Directory(path).listSync(followLinks: false).map((entity) {
      final type = FileSystemEntity.typeSync(entity.path, followLinks: false);
      final name = entity.path.replaceAll('\\', '/').split('/').last;
      return Dirent(name, type);
    }).toList();
  } on FileSystemException catch (error) {
    throw _nodeFsError(error, 'scandir', path);
  }
}

/// Node's synchronous `statSync(path)` subset.
Stats statSync(String path) {
  try {
    final type = FileSystemEntity.typeSync(path, followLinks: true);
    if (type == FileSystemEntityType.notFound) {
      throw nodeError('ENOENT', 'stat', path);
    }
    return Stats(type);
  } on FileSystemException catch (error) {
    throw _nodeFsError(error, 'stat', path);
  }
}

NodeError _nodeFsError(FileSystemException error, String syscall, String path) {
  final errno = error.osError?.errorCode;
  String code;
  if (errno == null) {
    code = 'UNKNOWN';
  } else {
    code = codeForErrno(errno);
    if (code == 'UNKNOWN') {
      code = switch (errno) {
        2 || 3 => 'ENOENT',
        5 => 'EACCES',
        20 || 267 => 'ENOTDIR',
        40 || 62 => 'ELOOP',
        63 || 36 => 'ENAMETOOLONG',
        _ => 'UNKNOWN',
      };
    }
  }
  return nodeError(code, syscall, path, message: error.message);
}
