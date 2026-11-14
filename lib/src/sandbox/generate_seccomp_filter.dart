// Ported from sandbox-runtime src/sandbox/generate-seccomp-filter.ts @ 0bbebed.
// ignore_for_file: constant_identifier_names, slash_for_doc_comments

import 'package:path/path.dart' as path;

import '../node/child_process.dart' as child_process;
import '../node/fs.dart' as fs;
import '../node/os.dart' as os;
import '../node/process.dart' as process;
import '../node/url.dart' show resolveOwnPackageFile;
import '../utils/debug.dart';

// Cache for path lookups (key: explicit path or empty string, value: resolved path or null)
final Map<String, String?> _applySeccompPathCache = <String, String?>{};

// Cache for global npm paths (computed once per process)
List<String>? _cachedGlobalNpmPaths;
Future<List<String>>? _pendingGlobalNpmPaths;

const String _NPM_ROOT_COMMAND = 'npm root -g';
const int _NPM_ROOT_TIMEOUT_MS = 5000;

/**
 * Get paths to check for globally installed @anthropic-ai/sandbox-runtime package.
 * This is used as a fallback when the binaries aren't bundled (e.g., native builds).
 *
 * Blocks the event loop on `npm root -g` (~100 ms) the first time it is
 * called in a process unless {@link getGlobalNpmPathsAsync} has already
 * filled the cache; initialize() goes through the async variant.
 */
List<String> getGlobalNpmPaths() {
  if (_cachedGlobalNpmPaths != null) return _cachedGlobalNpmPaths!;

  String? npmRoot;
  try {
    final command = _NPM_ROOT_COMMAND.split(' ');
    npmRoot = child_process.execSync(
      command.first,
      command.skip(1).toList(),
      timeout: const Duration(milliseconds: _NPM_ROOT_TIMEOUT_MS),
    );
  } catch (_) {
    // npm not available or failed
  }
  _cachedGlobalNpmPaths = _buildGlobalNpmPaths(npmRoot);
  return _cachedGlobalNpmPaths!;
}

/**
 * Async variant of {@link getGlobalNpmPaths}: runs `npm root -g` without
 * blocking the event loop and shares the same per-process cache, so a
 * later sync call returns immediately. Never rejects — a failed or
 * timed-out npm yields just the static fallback locations, as the sync
 * variant does.
 */
Future<List<String>> getGlobalNpmPathsAsync() {
  if (_cachedGlobalNpmPaths != null) {
    return Future<List<String>>.value(_cachedGlobalNpmPaths);
  }
  if (_pendingGlobalNpmPaths != null) return _pendingGlobalNpmPaths!;

  _pendingGlobalNpmPaths = (() async {
    final command = _NPM_ROOT_COMMAND.split(' ');
    final npmRoot = await child_process.exec(
      command.first,
      command.skip(1).toList(),
      timeout: const Duration(milliseconds: _NPM_ROOT_TIMEOUT_MS),
    );
    // Match execSync's closed stdin: npm never waits on it.
    // Dart: child_process.exec closes stdin itself.
    // A sync call that ran while npm was in flight already filled the cache;
    // keep its array so every caller sees the same one.
    _cachedGlobalNpmPaths ??= _buildGlobalNpmPaths(npmRoot);
    _pendingGlobalNpmPaths = null;
    return _cachedGlobalNpmPaths!;
  })();
  return _pendingGlobalNpmPaths!;
}

List<String> _buildGlobalNpmPaths(String? npmRootOutput) {
  final paths = <String>[];

  // The actual global npm root, when npm answered
  final npmRoot = npmRootOutput?.trim();
  if (npmRoot != null && npmRoot.isNotEmpty) {
    paths.add(path.join(npmRoot, '@anthropic-ai', 'sandbox-runtime'));
  }

  // Common global npm locations as fallbacks
  final home = os.homedir();
  paths.addAll([
    // npm global (Linux/macOS)
    path.join(
      '/usr',
      'lib',
      'node_modules',
      '@anthropic-ai',
      'sandbox-runtime',
    ),
    path.join(
      '/usr',
      'local',
      'lib',
      'node_modules',
      '@anthropic-ai',
      'sandbox-runtime',
    ),
    // npm global with prefix (common on macOS with homebrew)
    path.join(
      '/opt',
      'homebrew',
      'lib',
      'node_modules',
      '@anthropic-ai',
      'sandbox-runtime',
    ),
    // User-local npm global
    path.join(
      home,
      '.npm',
      'lib',
      'node_modules',
      '@anthropic-ai',
      'sandbox-runtime',
    ),
    path.join(
      home,
      '.npm-global',
      'lib',
      'node_modules',
      '@anthropic-ai',
      'sandbox-runtime',
    ),
  ]);

  return paths;
}

/**
 * Map Node.js process.arch to our vendor directory architecture names
 * Returns null for unsupported architectures
 */
String? _getVendorArchitecture() {
  final arch = process.arch;
  switch (arch) {
    case 'x64':
      return 'x64';
    case 'arm64':
      return 'arm64';
    case 'ia32':
      // ia32 multiplexes every socket operation through socketcall(), whose
      // sub-function argument the filter cannot inspect, so AF_UNIX is not
      // blockable there. vendor/seccomp-src/seccomp-unix-block.c carries what
      // supporting it would take.
      logForDebugging(
        '[SeccompFilter] 32-bit x86 (ia32) is not currently supported due to missing socketcall() syscall blocking. '
        'The current seccomp filter only blocks socket(AF_UNIX, ...), but on 32-bit x86, socketcall() can be used to bypass this.',
        level: 'error',
      );
      return null;
    default:
      logForDebugging(
        '[SeccompFilter] Unsupported architecture: $arch. Only x64 and arm64 are supported.',
      );
      return null;
  }
}

/**
 * Get local paths to check for seccomp files (bundled or package installs).
 */
List<String> _getLocalSeccompPaths(String filename) {
  final arch = _getVendorArchitecture();
  if (arch == null) return [];

  // Dart libraries do not expose their own file URL. The isolate's package
  // resolver supplies the equivalent of import.meta.url without consulting
  // the current directory (which a caller may have changed since loading).
  final moduleFile = resolveOwnPackageFile(
    'package:sandbox_runtime/src/sandbox/generate_seccomp_filter.dart',
  );
  String? packageRoot;
  if (moduleFile != null) {
    packageRoot = path.normalize(
      path.join(path.dirname(moduleFile), '..', '..', '..'),
    );
  }
  // A source checkout launched without package_config is still rooted at cwd.
  final currentDirectory = packageRoot == null ? process.cwd() : '';
  if (packageRoot == null &&
      fs.existsSync(
        path.join(
          currentDirectory,
          'lib',
          'src',
          'sandbox',
          'generate_seccomp_filter.dart',
        ),
      )) {
    packageRoot = currentDirectory;
  }
  // An AOT-compiled embedder has neither, and passes seccompBinaryPath. With
  // no local path to try, the lookup goes on to the global npm install.
  if (packageRoot == null) return [];
  final baseDir = path.join(packageRoot, 'lib', 'src', 'sandbox');
  final relativePath = path.join('vendor', 'seccomp', arch, filename);

  return [
    path.join(
      baseDir,
      relativePath,
    ), // bundled: same directory as bundle (e.g., when bundled into claude-cli)
    path.join(
      baseDir,
      '..',
      '..',
      '..',
      relativePath,
    ), // package root: vendor/seccomp/...
    path.join(
      baseDir,
      '..',
      '..',
      relativePath,
    ), // dist: dist/vendor/seccomp/...
  ];
}

/**
 * Get the path to the apply-seccomp binary from the vendor directory
 * Returns the path if it exists, null otherwise
 *
 * Pre-built apply-seccomp binaries are organized by architecture:
 * - vendor/seccomp/{x64,arm64}/apply-seccomp
 *
 * Tries multiple paths for resilience:
 * 0. Explicit path provided via parameter (checked first if provided)
 * 1. vendor/seccomp/{arch}/apply-seccomp (bundled - when bundled into consuming packages)
 * 2. ../../vendor/seccomp/{arch}/apply-seccomp (package root - standard npm installs)
 * 3. ../vendor/seccomp/{arch}/apply-seccomp (dist/vendor - for bundlers)
 * 4. Global npm install (if seccompBinaryPath not provided) - for native builds
 *
 * @param seccompBinaryPath - Optional explicit path to the apply-seccomp binary. If provided
 *   and exists, it will be used. If not provided, falls back to searching local paths and
 *   then global npm install (for native builds where vendor directory isn't bundled).
 */
String? Function([String? seccompBinaryPath]) getApplySeccompBinaryPath =
    _getApplySeccompBinaryPath;

String? _getApplySeccompBinaryPath([String? seccompBinaryPath]) {
  final cacheKey = seccompBinaryPath ?? '';
  if (_applySeccompPathCache.containsKey(cacheKey)) {
    return _applySeccompPathCache[cacheKey];
  }

  final local = _findLocalApplySeccompPath(seccompBinaryPath);
  final String? result = local.$1
      ? local.$2
      : _findGlobalApplySeccompPath(getGlobalNpmPaths());
  _applySeccompPathCache[cacheKey] = result;
  return result;
}

/**
 * Async variant of {@link getApplySeccompBinaryPath}: same lookup order and
 * shared cache, but the global-npm fallback resolves `npm root -g` without
 * blocking the event loop. Resolving once through here (as
 * checkDependenciesAsync does) makes later sync calls cache hits.
 */
Future<String?> getApplySeccompBinaryPathAsync([
  String? seccompBinaryPath,
]) async {
  final cacheKey = seccompBinaryPath ?? '';
  if (_applySeccompPathCache.containsKey(cacheKey)) {
    return _applySeccompPathCache[cacheKey];
  }

  final local = _findLocalApplySeccompPath(seccompBinaryPath);
  final String? result = local.$1
      ? local.$2
      : _findGlobalApplySeccompPath(await getGlobalNpmPathsAsync());
  _applySeccompPathCache[cacheKey] = result;
  return result;
}

/**
 * Explicit path, then bundled/package locations. Returns the path when
 * found, null when there is nothing to look for (unsupported architecture),
 * or undefined to fall through to the global npm install.
 */
(bool, String?) _findLocalApplySeccompPath([String? seccompBinaryPath]) {
  // Check explicit path first (highest priority)
  if (seccompBinaryPath != null && seccompBinaryPath.isNotEmpty) {
    if (fs.existsSync(seccompBinaryPath)) {
      logForDebugging(
        '[SeccompFilter] Using apply-seccomp binary from explicit path: $seccompBinaryPath',
      );
      return (true, seccompBinaryPath);
    }
    logForDebugging(
      '[SeccompFilter] Explicit path provided but file not found: $seccompBinaryPath',
    );
  }

  final arch = _getVendorArchitecture();
  if (arch == null) {
    logForDebugging(
      '[SeccompFilter] Cannot find apply-seccomp binary: unsupported architecture ${process.arch}',
    );
    return (true, null);
  }

  logForDebugging(
    '[SeccompFilter] Looking for apply-seccomp binary for architecture: $arch',
  );

  // Check local paths first (bundled or package install)
  for (final binaryPath in _getLocalSeccompPaths('apply-seccomp')) {
    if (fs.existsSync(binaryPath)) {
      logForDebugging(
        '[SeccompFilter] Found apply-seccomp binary: $binaryPath ($arch)',
      );
      return (true, binaryPath);
    }
  }

  return (false, null);
}

/**
 * Fallback: check global npm install (for native builds without bundled vendor)
 */
String? _findGlobalApplySeccompPath(List<String> globalBases) {
  final arch = _getVendorArchitecture();
  if (arch == null) return null;

  for (final globalBase in globalBases) {
    final binaryPath = path.join(
      globalBase,
      'vendor',
      'seccomp',
      arch,
      'apply-seccomp',
    );
    if (fs.existsSync(binaryPath)) {
      logForDebugging(
        '[SeccompFilter] Found apply-seccomp binary in global install: $binaryPath ($arch)',
      );
      return binaryPath;
    }
  }

  logForDebugging(
    '[SeccompFilter] apply-seccomp binary not found in any expected location ($arch)',
  );
  return null;
}
