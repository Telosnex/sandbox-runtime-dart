// Node `fs/promises`: the asynchronous calls the ported files make, with
// Node-shaped errors from the synchronous shims.
import 'fs.dart' as fs;

/// Node's `fsPromises.unlink(path)`.
Future<void> unlink(String path) async => fs.unlinkSync(path);

/// Node's `fsPromises.rm(path, {force, recursive})`.
Future<void> rm(String path, [Map<String, Object?> options = const {}]) async =>
    fs.rmSync(path, options);
