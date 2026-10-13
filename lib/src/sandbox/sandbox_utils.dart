// Ported from sandbox-runtime src/sandbox/sandbox-utils.ts @ 24eb39e.
// ignore_for_file: constant_identifier_names, dangling_library_doc_comments
// ignore_for_file: slash_for_doc_comments, non_constant_identifier_names
// ignore_for_file: avoid_dynamic_calls, curly_braces_in_flow_control_structures

import 'dart:convert';

import 'package:path/path.dart' as path;

import '../node/abort.dart';
import '../node/buffer.dart';
import '../node/errno.dart';
import '../node/fs.dart' as fs;
import '../node/fs_sandbox_utils.dart' as fs_walk;
import '../node/generators.dart';
import '../node/os.dart' show homedir;
import '../node/process.dart' as process;
import '../utils/debug.dart';
import '../utils/platform.dart' show getPlatform;
import '../utils/real_path.dart' show realPathOf;
import 'sandbox_config.dart'
    show FilesystemPathEntry, FilesystemPathLiteral, FilesystemPathSpelling;

/// Work that can be left between two steps and taken up again.
typedef Steps<T> = Iterable<Step<T>>;

/**
 * Dangerous files that should be protected from writes.
 * These files can be used for code execution or data exfiltration.
 */
const List<String> DANGEROUS_FILES = [
  '.gitconfig',
  '.gitmodules',
  '.bashrc',
  '.bash_profile',
  '.zshrc',
  '.zprofile',
  '.profile',
  '.ripgreprc',
  '.mcp.json',
];

/**
 * Dangerous directories that should be protected from writes.
 * These directories contain sensitive configuration or executable files.
 */
const List<String> DANGEROUS_DIRECTORIES = ['.git', '.vscode', '.idea'];

/**
 * Get the list of dangerous directories to deny writes to.
 * Excludes .git since we need it writable for git operations -
 * instead we block specific paths within .git (hooks and config).
 */
List<String> getDangerousDirectories() => [
  ...DANGEROUS_DIRECTORIES.where((directory) => directory != '.git'),
  '.claude/commands',
  '.claude/agents',
];

/**
 * Normalizes a path for case-insensitive comparison.
 * This prevents bypassing security checks using mixed-case paths on case-insensitive
 * filesystems (macOS/Windows) like `.cLauDe/Settings.locaL.json`.
 *
 * We always normalize to lowercase regardless of platform for consistent security.
 * @param path The path to normalize
 * @returns The lowercase path for safe comparison
 */
String normalizeCaseForComparison(String pathStr) => pathStr.toLowerCase();

/**
 * `p` is `dir` itself or lies beneath it, by path segment ('/xy' is not under
 * '/x'); root-aware, since '/' + '/' is a prefix of nothing.
 */
bool isAtOrUnder(String p, String dir) =>
    p == dir || p.startsWith(dir == '/' ? '/' : '$dir/');

/** `p` lies strictly beneath `dir` (isAtOrUnder, excluding `dir` itself). */
bool isStrictlyUnder(String p, String dir) => p != dir && isAtOrUnder(p, dir);

/** The proper ancestors of an absolute POSIX path, nearest first, ending at '/'. */
Iterable<String> properAncestors(String absolutePath) sync* {
  for (
    var slash = absolutePath.lastIndexOf('/');
    slash > 0;
    slash = absolutePath.lastIndexOf('/', slash - 1)
  ) {
    yield absolutePath.substring(0, slash);
  }
  if (absolutePath != '/') yield '/';
}

/**
 * The spellings that name `candidatePath` for a mount comparison: as spelled,
 * plus with every symlink resolved when that differs. A path that cannot be
 * resolved (dangling, vanished) is named by its spelling alone.
 */
List<String> pathSpellings(String candidatePath) {
  try {
    final resolved = realPathOf(candidatePath);
    if (resolved != candidatePath) return [candidatePath, resolved];
  } catch (_) {
    // Dangling or vanished: only the spelling names it.
  }
  return [candidatePath];
}

/**
 * Where the name `p` lives: its parent directories as `canonicalOf` resolves
 * them, its last component as written. An allowRead entry is read so: one
 * that is a symlink names the link, and nothing the link points at.
 */
String nameLocation(String p, String Function(String dir) canonicalOf) {
  if (p == '/') return p;
  final parent = canonicalOf(path.dirname(p));
  return '${parent == '/' ? '' : parent}/${path.basename(p)}';
}

/** `process.cwd()`, or undefined where that throws: it has been removed. */
String? workingDirectory() {
  try {
    return process.cwd();
  } catch (_) {
    return null;
  }
}

/** An fs error that means the name resolves to no file — it is missing, or
 * the path cannot name one at all — as opposed to one that means a file is
 * there but could not be looked at (EACCES, EPERM, EIO, anything
 * unrecognised). */
bool isAbsenceErrno(Object? err) {
  final code = err is NodeError
      ? err.code
      : err is Map && err['code'] is String
      ? err['code'] as String
      : null;
  return code == 'ENOENT' ||
      code == 'ENOTDIR' ||
      code == 'ELOOP' ||
      code == 'ENAMETOOLONG';
}

/** Check if a path pattern contains glob characters */
bool containsGlobChars(String pathPattern) =>
    pathPattern.contains('*') ||
    pathPattern.contains('?') ||
    pathPattern.contains('[') ||
    pathPattern.contains(']');

/**
 * Windows-specific glob-char check. `[` and `]` are NOT
 * metachars here — they are legal in Win32 filenames, so a
 * literal `C:\app\[prod].env` must route to the literal-path
 * branch, not glob expansion (where it would match nothing and
 * be silently dropped). Only `*` and `?` trigger expansion.
 */
bool containsGlobCharsWin(String p) => p.contains('*') || p.contains('?');

/** Platform-appropriate glob-char check. */
bool containsGlobCharsForPlatform(String p) =>
    getPlatform() == 'windows' ? containsGlobCharsWin(p) : containsGlobChars(p);

/**
 * The path of an entry that is not a spelling. Throws unless the entry is
 * `{ path: string, literal: true }`: a config built in code skips the
 * schema, and reading `{ path }` either way would be a guess about a deny.
 */
String markedLiteralPath(FilesystemPathEntry entry) {
  if (entry is FilesystemPathLiteral && entry.path.isNotEmpty)
    return entry.path;
  throw ArgumentError(
    'A filesystem path entry must be a path, or { path, literal: true }; '
    'got ${jsonEncode(entry.toString())}',
  );
}

/**
 * Strip the Win32 `\\?\` extended-path prefix so the residue is
 * a conventional absolute path (drive-letter or UNC) with no `?`
 * for the glob-char check to misclassify. `\\?\UNC\srv\share\f`
 * → `\\srv\share\f`; `\\?\C:\f` → `C:\f`; anything else → input.
 * The UNC marker is matched case-insensitively (Windows accepts
 * `\\?\unc\…` in any casing; a case-sensitive check would
 * fall through to the 4-char strip and yield a cwd-relative residue).
 */
String stripExtendedPathPrefix(String p) {
  if (RegExp(r'^\\\\\?\\unc\\', caseSensitive: false).hasMatch(p)) {
    return r'\\' + p.substring(8);
  }
  if (p.startsWith(r'\\?\')) return p.substring(4);
  return p;
}

/**
 * True for a Windows UNC path in any spelling — `\\server\share\…`,
 * extended-length `\\?\UNC\server\share\…`, device-namespace
 * `\\.\UNC\server\share\…` (all any casing, either separator).
 */
bool isUncPath(String p) {
  final normalized = p.replaceAll('/', r'\');
  final lower = normalized.toLowerCase();
  String? body;
  if (lower.startsWith(r'\\?\unc\') || lower.startsWith(r'\\.\unc\')) {
    body = normalized.substring(8);
  } else if (lower.startsWith(r'\\?\') || lower.startsWith(r'\\.\')) {
    return false;
  } else if (normalized.startsWith(r'\\')) {
    body = normalized.substring(2);
  } else {
    return false;
  }
  final parts = body.split(r'\').where((part) => part.isNotEmpty).toList();
  return parts.length >= 2;
}

/** Remove a trailing double-asterisk slash glob suffix from a path pattern. */
String removeTrailingGlobSuffix(String pathPattern) {
  final stripped = pathPattern.replaceFirst(RegExp(r'/\*\*$'), '');
  return stripped.isEmpty ? '/' : stripped;
}

/**
 * Check if a symlink resolution crosses expected path boundaries.
 */
bool isSymlinkOutsideBoundary(String originalPath, String resolvedPath) {
  final normalizedOriginal = path.normalize(originalPath);
  final normalizedResolved = path.normalize(resolvedPath);
  if (normalizedResolved == normalizedOriginal) return false;
  if (normalizedOriginal.startsWith('/tmp/') &&
      normalizedResolved == '/private$normalizedOriginal')
    return false;
  if (normalizedOriginal.startsWith('/var/') &&
      normalizedResolved == '/private$normalizedOriginal')
    return false;
  if (normalizedResolved == '/') return true;
  final resolvedParts = normalizedResolved
      .split('/')
      .where((p) => p.isNotEmpty);
  if (resolvedParts.length <= 1) return true;
  if (normalizedOriginal.startsWith('$normalizedResolved/')) return true;
  var canonicalOriginal = normalizedOriginal;
  if (normalizedOriginal.startsWith('/tmp/')) {
    canonicalOriginal = '/private$normalizedOriginal';
  } else if (normalizedOriginal.startsWith('/var/')) {
    canonicalOriginal = '/private$normalizedOriginal';
  }
  if (canonicalOriginal != normalizedOriginal &&
      canonicalOriginal.startsWith('$normalizedResolved/'))
    return true;
  final resolvedStartsWithOriginal = normalizedResolved.startsWith(
    '$normalizedOriginal/',
  );
  final resolvedStartsWithCanonical =
      canonicalOriginal != normalizedOriginal &&
      normalizedResolved.startsWith('$canonicalOriginal/');
  final resolvedIsCanonical =
      canonicalOriginal != normalizedOriginal &&
      normalizedResolved == canonicalOriginal;
  if (!resolvedIsCanonical &&
      !resolvedStartsWithOriginal &&
      !resolvedStartsWithCanonical)
    return true;
  return false;
}

/** Expand a leading `~` to the home directory. */
String expandTilde(String p) {
  if (p == '~') return homedir();
  if (p.startsWith('~/') ||
      (process.platform == 'win32' && p.startsWith(r'~\'))) {
    return homedir() + p.substring(1);
  }
  return p;
}

/** Expand Windows-style home-directory environment references. */
String expandWindowsEnvRefs(String p) {
  final home = homedir();
  final driveMatch = RegExp(r'^[A-Za-z]:').firstMatch(home);
  final drive = driveMatch == null ? '' : home.substring(0, 2);
  final homePath = drive.isNotEmpty ? home.substring(2) : home;
  return p
      .replaceAll(RegExp(r'%USERPROFILE%', caseSensitive: false), home)
      .replaceAll(RegExp(r'%HOMEDRIVE%', caseSensitive: false), drive)
      .replaceAll(RegExp(r'%HOMEPATH%', caseSensitive: false), homePath);
}

/** Runs of `/` collapsed to one and `/./` components dropped, leaving the rest
 * of the spelling (a trailing `/` or `/.`, a `..`) to the caller. POSIX only. */
String collapseInteriorSpellings(String pathPattern) => pathPattern
    .replaceAll(RegExp(r'/{2,}'), '/')
    .replaceAll(RegExp(r'/\.(?=/)'), '');

/** Says so when a `..` reaches a backend unfolded; debug-only. */
String _warnIfParentRefUnfolded(String normalizedPath) {
  if (getPlatform() != 'windows' &&
      RegExp(r'(?:^|/)\.\.(?:/|$)').hasMatch(normalizedPath)) {
    logForDebugging(
      '[Sandbox] "$normalizedPath" could not be resolved and still contains '
      'a ".." component, so a rule spelled this way may not match.',
      level: 'warn',
    );
  }
  return normalizedPath;
}

/** Normalize a path for use in sandbox configurations. */
String normalizePathForSandbox(String pathPattern, {bool literal = false}) {
  bool isGlobSpelling(String p) => !literal && containsGlobCharsForPlatform(p);
  if (getPlatform() == 'windows') {
    pathPattern = stripExtendedPathPrefix(expandWindowsEnvRefs(pathPattern));
    if (RegExp(r'^[a-z]:').hasMatch(pathPattern)) {
      pathPattern = pathPattern[0].toUpperCase() + pathPattern.substring(1);
    }
    if (isUncPath(pathPattern) && !isGlobSpelling(pathPattern)) {
      return path.Context(style: path.Style.windows).normalize(pathPattern);
    }
  }
  if (getPlatform() != 'windows' &&
      pathPattern.endsWith('/') &&
      !isGlobSpelling(pathPattern)) {
    pathPattern = pathPattern.replaceFirst(RegExp(r'/+$'), '');
    if (pathPattern.isEmpty) pathPattern = '/';
  }
  var normalizedPath = expandTilde(pathPattern);
  if (normalizedPath == pathPattern && !path.isAbsolute(pathPattern)) {
    normalizedPath = path.normalize(path.join(process.cwd(), pathPattern));
  }
  if (getPlatform() != 'windows') {
    normalizedPath = collapseInteriorSpellings(normalizedPath);
  }
  if (isGlobSpelling(normalizedPath)) {
    final splitRe = getPlatform() == 'windows'
        ? RegExp(r'[*?]')
        : RegExp(r'[*?[\]]');
    final staticPrefix = normalizedPath.split(splitRe).first;
    if (staticPrefix.isNotEmpty && staticPrefix != '/') {
      final baseDir = staticPrefix.endsWith('/')
          ? staticPrefix.substring(0, staticPrefix.length - 1)
          : path.dirname(staticPrefix);
      try {
        final resolvedBaseDir = realPathOf(baseDir);
        if (!isSymlinkOutsideBoundary(baseDir, resolvedBaseDir)) {
          final patternSuffix = normalizedPath.substring(baseDir.length);
          return _warnIfParentRefUnfolded('$resolvedBaseDir$patternSuffix');
        }
      } catch (_) {
        // If directory doesn't exist or can't be resolved, keep the original pattern.
      }
    }
    return _warnIfParentRefUnfolded(normalizedPath);
  }
  if (getPlatform() != 'windows' && normalizedPath.isNotEmpty) {
    normalizedPath = normalizedPath.replaceFirst(RegExp(r'/\.$'), '');
    normalizedPath = normalizedPath.replaceFirst(RegExp(r'/+$'), '');
    if (normalizedPath.isEmpty) normalizedPath = '/';
  }
  try {
    final resolvedPath = realPathOf(normalizedPath);
    if (!isSymlinkOutsideBoundary(normalizedPath, resolvedPath)) {
      normalizedPath = resolvedPath;
    }
  } catch (_) {
    // Absent, or unreadable: keep the normalized spelling.
  }
  return _warnIfParentRefUnfolded(normalizedPath);
}

/**
 * What the sandbox itself needs writable: the child's stdio and the TMPDIR it
 * is handed (generateProxyEnvVars). Kept whatever is read-denied.
 */
const List<String> _SANDBOX_OWN_WRITE_PATHS = [
  '/dev/stdout',
  '/dev/stderr',
  '/dev/null',
  '/dev/tty',
  '/dev/dtracehelper',
  '/dev/autofs_nowait',
  '/tmp/claude',
  '/private/tmp/claude',
];

/**
 * Directories under the home directory made writable as a convenience the
 * caller never asked for. Every entry is subject to the read-rule check in
 * [getDefaultWritePaths].
 */
const List<String> _HOME_CONVENIENCE_WRITE_DIRS = [
  '.npm/_logs',
  '.claude/debug',
];

/** Get recommended system paths that should be writable for commands to work properly. */
List<String> getDefaultWritePaths({
  List<FilesystemPathEntry>? denyRead,
  List<FilesystemPathEntry>? allowRead,
}) {
  final home = homedir();
  final keptDirs = denyRead == null || denyRead.isEmpty
      ? _HOME_CONVENIENCE_WRITE_DIRS
      : _homeDirsNotReadDenied(home, denyRead, allowRead ?? const []);
  return [
    ..._SANDBOX_OWN_WRITE_PATHS,
    ...keptDirs.map((rel) => path.join(home, rel)),
  ];
}

/** The home convenience dirs no denyRead entry covers or allowRead re-opens. */
List<String> _homeDirsNotReadDenied(
  String home,
  List<FilesystemPathEntry> denyRead,
  List<FilesystemPathEntry> allowRead,
) {
  final homes = <String>{home, normalizePathForSandbox(home, literal: true)};
  final denies = denyRead.map(_readRuleCovers).toList();
  final reopened = allowRead
      .map((entry) {
        if (entry is FilesystemPathLiteral) return markedLiteralPath(entry);
        final spelling = (entry as FilesystemPathSpelling).path;
        final stripped = removeTrailingGlobSuffix(spelling);
        return containsGlobCharsForPlatform(stripped) ? null : stripped;
      })
      .whereType<String>()
      .map((entry) => normalizePathForSandbox(entry, literal: true))
      .toList();
  return _HOME_CONVENIENCE_WRITE_DIRS.where((rel) {
    final spellings = homes.map((home) => path.join(home, rel)).toList();
    return !denies.any(
      (denyCovers) =>
          spellings.any(denyCovers) &&
          !reopened.any(
            (allow) =>
                denyCovers(allow) &&
                spellings.any((s) => isAtOrUnder(s, allow)),
          ),
    );
  }).toList();
}

/** Whether a read rule covers a path. */
bool Function(String p) _readRuleCovers(FilesystemPathEntry entry) {
  if (entry is FilesystemPathLiteral) {
    final rule = normalizePathForSandbox(
      markedLiteralPath(entry),
      literal: true,
    );
    return (p) => isAtOrUnder(p, rule);
  }
  final spelling = (entry as FilesystemPathSpelling).path;
  final stripped = removeTrailingGlobSuffix(spelling);
  if (containsGlobCharsForPlatform(stripped)) {
    try {
      final regex = RegExp(denyGlobRegex(normalizePathForSandbox(stripped)));
      regex.hasMatch('');
      return (p) => regex.hasMatch(p);
    } catch (_) {
      return (_) => true;
    }
  }
  final rule = normalizePathForSandbox(stripped, literal: true);
  return (p) => isAtOrUnder(p, rule);
}

/** Generate proxy environment variables for sandboxed processes. */
/** Per-tool trust-store env vars set to the TLS-termination CA cert path. */
const List<String> CA_TRUST_VARS = [
  'NODE_EXTRA_CA_CERTS',
  'SSL_CERT_FILE',
  'CURL_CA_BUNDLE',
  'REQUESTS_CA_BUNDLE',
  'PIP_CERT',
  'GIT_SSL_CAINFO',
  'AWS_CA_BUNDLE',
  'CARGO_HTTP_CAINFO',
  'DENO_CERT',
  'CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE',
  'NIX_SSL_CERT_FILE',
];

List<String> generateProxyEnvVars([
  int? httpProxyPort,
  int? socksProxyPort,
  String? caCertPath,
  String? proxyAuthToken,
  bool? skipTmpdir,
  String? encodedCommand,
]) {
  final userRaw = proxyUsernameFor(encodedCommand);
  final userPct = userRaw == PROXY_AUTH_USER
      ? userRaw
      : Uri.encodeComponent(userRaw);
  final auth = proxyAuthToken != null && proxyAuthToken.isNotEmpty
      ? '$userPct:$proxyAuthToken@'
      : '';
  final envVars = <String>['SANDBOX_RUNTIME=1'];
  if (skipTmpdir != true) {
    final tmpdir =
        process.env['CLAUDE_CODE_TMPDIR'] ??
        process.env['CLAUDE_TMPDIR'] ??
        '/tmp/claude';
    envVars.add('TMPDIR=$tmpdir');
  }
  if (caCertPath != null && caCertPath.isNotEmpty) {
    for (final variable in CA_TRUST_VARS) {
      envVars.add('$variable=$caCertPath');
    }
  }
  if ((httpProxyPort == null || httpProxyPort == 0) &&
      (socksProxyPort == null || socksProxyPort == 0))
    return envVars;

  const noProxyAddresses =
      'localhost,127.0.0.1,::1,169.254.0.0/16,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16';
  envVars.add('NO_PROXY=$noProxyAddresses');
  envVars.add('no_proxy=$noProxyAddresses');
  if (httpProxyPort != null && httpProxyPort != 0) {
    final proxyUrl = 'http://${auth}localhost:$httpProxyPort';
    envVars.add('HTTP_PROXY=$proxyUrl');
    envVars.add('HTTPS_PROXY=$proxyUrl');
    envVars.add('http_proxy=$proxyUrl');
    envVars.add('https_proxy=$proxyUrl');
    if (proxyAuthToken != null && proxyAuthToken.isNotEmpty) {
      envVars.add("GIT_CONFIG_PARAMETERS='http.proxyAuthMethod=basic'");
    }
  }
  final connectProxyUrl = httpProxyPort != null && httpProxyPort != 0
      ? 'http://${auth}localhost:$httpProxyPort'
      : 'socks5h://${auth}localhost:$socksProxyPort';
  envVars.add('ALL_PROXY=$connectProxyUrl');
  envVars.add('all_proxy=$connectProxyUrl');
  envVars.add('GRPC_PROXY=$connectProxyUrl');
  envVars.add('grpc_proxy=$connectProxyUrl');
  if (socksProxyPort != null && socksProxyPort != 0) {
    const sshMuxOverride = '-o ControlMaster=no -o ControlPath=none';
    final platform = getPlatform();
    if (platform == 'macos' &&
        proxyAuthToken != null &&
        proxyAuthToken.isNotEmpty &&
        httpProxyPort == socksProxyPort) {
      final basic = Buffer.from('$userRaw:$proxyAuthToken').toString('base64');
      envVars.addAll([
        'SRT_SSH_PROXY_COMMAND=${sshConnectScript(socksProxyPort, basic)}',
        'GIT_SSH_COMMAND=ssh $sshMuxOverride -o ProxyCommand="/bin/sh -c '
            r'''eval \"\${SRT_SSH_PROXY_COMMAND:?unset, but GIT_SSH_COMMAND needs it}\"' sh '%h' %p''',
      ]);
    } else if (platform == 'macos') {
      envVars.add(
        "GIT_SSH_COMMAND=ssh $sshMuxOverride -o ProxyCommand='nc -X 5 -x "
        "localhost:$socksProxyPort %h %p'",
      );
    } else if (platform == 'linux' && httpProxyPort != null) {
      final socatAuth = proxyAuthToken != null && proxyAuthToken.isNotEmpty
          ? ',proxyauth=$userRaw:$proxyAuthToken'
          : '';
      envVars.add(
        "GIT_SSH_COMMAND=ssh $sshMuxOverride -o ProxyCommand='socat - "
        "PROXY:localhost:%h:%p,proxyport=$httpProxyPort$socatAuth'",
      );
    }
    envVars.add('FTP_PROXY=socks5h://${auth}localhost:$socksProxyPort');
    envVars.add('ftp_proxy=socks5h://${auth}localhost:$socksProxyPort');
    envVars.add('RSYNC_PROXY=localhost:$socksProxyPort');
    final dockerPort = httpProxyPort ?? socksProxyPort;
    envVars.add('DOCKER_HTTP_PROXY=http://${auth}localhost:$dockerPort');
    envVars.add('DOCKER_HTTPS_PROXY=http://${auth}localhost:$dockerPort');
    if (httpProxyPort != null && httpProxyPort != 0) {
      envVars.addAll([
        'CLOUDSDK_PROXY_TYPE=http',
        'CLOUDSDK_PROXY_ADDRESS=localhost',
        'CLOUDSDK_PROXY_PORT=$httpProxyPort',
      ]);
      if (proxyAuthToken != null && proxyAuthToken.isNotEmpty) {
        envVars.add('CLOUDSDK_PROXY_USERNAME=$userRaw');
        envVars.add('CLOUDSDK_PROXY_PASSWORD=$proxyAuthToken');
      }
    }
  }
  return envVars;
}

/** A POSIX sh script for an ssh ProxyCommand through the proxy. */
String sshConnectScript(
  int proxyPort,
  String basic, [
  String nc = '/usr/bin/nc',
]) =>
    'LC_ALL=C; no() { printf "sandbox proxy: %s\\n" "\$*" >&2; exit 1; }; '
    'case \$1 in ""|*[!A-Za-z0-9._:-]*) no bad host;; *:*) set -- "[\$1]" "\$2";; esac; '
    'case \$2 in ""|*[!0-9]*) no bad port;; esac; '
    'exec 3<&0; '
    '{ printf "CONNECT %s HTTP/1.1\\r\\nHost: %s\\r\\nProxy-Authorization: Basic $basic\\r\\n\\r\\n" "\$1:\$2" "\$1:\$2"; exec /bin/cat <&3; } | '
    '$nc 127.0.0.1 $proxyPort | '
    '{ read -r v why; while read -r v; do case \$v in ""|?) break;; esac; done; '
    'case \$why in "200 "*) exec /bin/cat;; esac; '
    'why=\${why%?}; no "\$1:\$2: \${why:-no answer}"; } & '
    'exec >&-; wait \$!';

/** `safe.directory` entries above this count collapse to a single wildcard. */
const int _SAFE_DIRECTORY_WILDCARD_THRESHOLD = 8;

/** Build the `GIT_CONFIG_COUNT` / `GIT_CONFIG_KEY_<n>` / value env set. */
Map<String, String> buildGitConfigEnv({
  required List<String> safeDirs,
  bool schannelCa = false,
  Map<String, String?>? baseEnv,
}) {
  if (baseEnv?['GIT_CONFIG_COUNT'] == '0') return {};
  final rawCount = baseEnv?['GIT_CONFIG_COUNT'] ?? '';
  final parsed =
      int.tryParse(
        RegExp(r'^\s*([+-]?\d+)').firstMatch(rawCount)?.group(1) ?? '',
      ) ??
      0;
  final start = parsed >= 0 ? parsed : 0;
  var n = start;
  final out = <String, String>{};
  void emit(String key, String value) {
    out['GIT_CONFIG_KEY_$n'] = key;
    out['GIT_CONFIG_VALUE_$n'] = value;
    n++;
  }

  final dirs = <String>{};
  for (final directory in safeDirs) {
    if (directory.isEmpty) continue;
    final fwd = directory.replaceAll('\\', '/');
    final stripped = fwd.replaceFirst(RegExp(r'/+$'), '');
    if (stripped.isEmpty || RegExp(r'^[A-Za-z]:$').hasMatch(stripped)) {
      dirs.add('$stripped/');
    } else {
      dirs.add(stripped);
    }
  }
  if (dirs.length > _SAFE_DIRECTORY_WILDCARD_THRESHOLD) {
    emit('safe.directory', '*');
  } else {
    for (final directory in dirs) {
      emit('safe.directory', directory);
      emit(
        'safe.directory',
        directory.endsWith('/') ? '$directory*' : '$directory/*',
      );
    }
  }
  if (schannelCa) {
    emit('http.schannelUseSSLCAInfo', 'true');
    emit('http.schannelCheckRevoke', 'false');
  }
  if (n == start) return {};
  out['GIT_CONFIG_COUNT'] = '$n';
  return out;
}

/** POSIX-side wrapper over [buildGitConfigEnv]. */
Map<String, String> buildPosixGitSafeDirEnv({
  required List<String> safeDirs,
  List<String> unsetEnvVars = const [],
  Map<String, String> setEnvVars = const {},
}) {
  final baseEnv = <String, String?>{
    'GIT_CONFIG_COUNT': process.env['GIT_CONFIG_COUNT'],
  };
  for (final key in unsetEnvVars) {
    baseEnv.remove(key);
  }
  baseEnv.addAll(setEnvVars);
  return buildGitConfigEnv(safeDirs: safeDirs, baseEnv: baseEnv);
}

/** How much of an attribution key rides the carriers. */
const int SANDBOXED_COMMAND_KEY_LENGTH = 100;

/** The attribution key for an invocation. */
String attributionKeyFor(String command, String? commandId) =>
    commandId == null || commandId.isEmpty ? command : commandId;

/** Encode a command for sandbox monitoring. */
String encodeSandboxedCommand(String command) => Buffer.from(
  command.substring(
    0,
    command.length < SANDBOXED_COMMAND_KEY_LENGTH
        ? command.length
        : SANDBOXED_COMMAND_KEY_LENGTH,
  ),
).toString('base64');

/** Decode a base64-encoded command from sandbox monitoring. */
String decodeSandboxedCommand(String encodedCommand) =>
    Buffer.from(encodedCommand, 'base64').toString('utf8');

/** Base proxy username; the auth token is the credential, this is a label. */
const String PROXY_AUTH_USER = 'srt';
const int _MAX_PROXY_USERNAME_BYTES = 255;

/** The longest encoded command a carrier this process mints can hold. */
const int MAX_ENCODED_COMMAND_BYTES = _MAX_PROXY_USERNAME_BYTES - 4;

/** Build the proxy username for a sandboxed command. */
String proxyUsernameFor(String? encodedCommand) {
  if (encodedCommand == null || encodedCommand.isEmpty) return PROXY_AUTH_USER;
  final user = '$PROXY_AUTH_USER.$encodedCommand';
  return Buffer.byteLength(user) <= _MAX_PROXY_USERNAME_BYTES
      ? user
      : PROXY_AUTH_USER;
}

/** Extract an encoded command suffix from an `srt.<suffix>` username. */
String? encodedCommandFromProxyUser(String? username) {
  if (username == null || !username.startsWith('$PROXY_AUTH_USER.'))
    return null;
  final suffix = username.substring(PROXY_AUTH_USER.length + 1);
  if (suffix.isEmpty || Buffer.byteLength(suffix) > MAX_ENCODED_COMMAND_BYTES) {
    return null;
  }
  return suffix;
}

/** Convert a glob pattern to a regular expression. */
String globToRegex(String globPattern) {
  final splitParts = <String>[];
  var cursor = 0;
  for (final match in RegExp(r'\[[^\]]*\]').allMatches(globPattern)) {
    splitParts.add(globPattern.substring(cursor, match.start));
    splitParts.add(match[0]!);
    cursor = match.end;
  }
  splitParts.add(globPattern.substring(cursor));
  final sources = splitParts.map((part) {
    final source = _globPartToRegex(part);
    if (_isRegex(source)) return source;
    logForDebugging(
      '[Sandbox] The brackets in $part spell no set of characters, so they are read as text: $globPattern',
      level: 'warn',
    );
    final pieces = <String>[];
    var cursor = 0;
    for (final bracket in RegExp(r'[\[\]]').allMatches(part)) {
      pieces.add(part.substring(cursor, bracket.start));
      pieces.add(bracket[0]!);
      cursor = bracket.end;
    }
    pieces.add(part.substring(cursor));
    return pieces.indexed
        .map(
          (entry) =>
              entry.$1.isOdd ? '\\${entry.$2}' : _globPartToRegex(entry.$2),
        )
        .join();
  }).join();
  return '^$sources\$';
}

bool _isRegex(String source) {
  try {
    RegExp(source);
    return true;
  } catch (_) {
    return false;
  }
}

/** [globToRegex] for one bracket expression, or for what lies between two. */
String _globPartToRegex(String part) => part
    .replaceAllMapped(RegExp(r'[.^$+{}()|\\]'), (match) => '\\${match[0]}')
    .replaceAllMapped(RegExp(r'\[([^\]]*?)$'), (match) => '\\[${match[1]}')
    .replaceAll('**/', '__GLOBSTAR_SLASH__')
    .replaceAll('**', '__GLOBSTAR__')
    .replaceAll('*', '[^/]*')
    .replaceAll('?', '[^/]')
    .replaceAll('__GLOBSTAR_SLASH__', '(.${'*'}/)?')
    .replaceAll('__GLOBSTAR__', '.*');

/** Regex for a glob used in a DENY rule. */
String denyGlobRegex(String normalizedGlob) =>
    '${globToRegex(normalizedGlob).substring(0, globToRegex(normalizedGlob).length - 1)}(/.*)?\$';

class ExpandGlobOptions {
  const ExpandGlobOptions({this.caseInsensitive = false, this.anchor});
  final bool caseInsensitive;
  final String? anchor;
}

/// What the walk reads of a listed entry.
class _GlobWalkEntry {
  const _GlobWalkEntry({
    required this.name,
    required this.isDirectory,
    required this.isSymbolicLink,
  });
  final String name;
  final bool Function() isDirectory;
  final bool Function() isSymbolicLink;
}

/// What listing a real directory gave, its entries or the error that has it denied whole.
typedef GlobWalkListings = Map<String, Object>;

class GlobWalkOptions extends ExpandGlobOptions {
  const GlobWalkOptions({
    super.caseInsensitive = false,
    super.anchor,
    this.withDirectoryForm = false,
    this.followSymlinkedDirectories = false,
    this.listings,
  });
  final bool withDirectoryForm;
  final bool followSymlinkedDirectories;
  final GlobWalkListings? listings;
}

/** Runs `steps` to the end, on the spot. */
T finish<T>(Steps<T> steps) {
  for (final step in steps) {
    switch (step) {
      case Pause<T>():
        break;
      case Done<T>(:final value):
        return value;
    }
  }
  throw StateError('Steps ended without Done');
}

/** How long [finishInTurns] works before it lets others have a turn. */
const int _TURN_MS = 10;

/** Runs `steps` to the end, letting the event loop have a turn regularly. */
Future<T> finishInTurns<T>(Steps<T> steps, [AbortSignal? signal]) async {
  void throwIfAborted() {
    if (signal?.aborted == true) throw signal!.reason ?? AbortError();
  }

  throwIfAborted();
  final iterator = steps.iterator;
  final stopwatch = Stopwatch()..start();
  for (;;) {
    if (!iterator.moveNext()) throw StateError('Steps ended without Done');
    final step = iterator.current;
    if (step case Done<T>(:final value)) {
      throwIfAborted();
      return value;
    }
    if (stopwatch.elapsedMilliseconds >= _TURN_MS) {
      await Future<void>.delayed(Duration.zero);
      throwIfAborted();
      stopwatch
        ..reset()
        ..start();
    }
  }
}

/** What one recursive walk of a glob's base directory found. */
class GlobWalk {
  String baseLocation = '';
  final List<String> matches = [];
  final List<String> directoryMatches = [];
  final Set<String> symlinks = {};
  final Set<String> uninspectableLinks = {};
  final List<String> unlisted = [];
  final Map<String, String> realOf = {};
}

/** Expand a glob pattern into the concrete paths matching it. */
List<String> expandGlobPattern(
  String globPath, {
  bool caseInsensitive = false,
  String? anchor,
}) => walkGlobPattern(
  globPath,
  caseInsensitive: caseInsensitive,
  anchor: anchor,
).matches;

sealed class _GlobPiece {
  const _GlobPiece();
}

final class _GlobPieceAny extends _GlobPiece {
  const _GlobPieceAny();
}

final class _GlobPieceAnyDirs extends _GlobPiece {
  const _GlobPieceAnyDirs();
}

final class _GlobPieceSlash extends _GlobPiece {
  const _GlobPieceSlash();
}

final class _GlobPieceSource extends _GlobPiece {
  const _GlobPieceSource(this.source, {this.canBeSeparator = false});
  final String source;
  final bool canBeSeparator;
}

class _GlobPositions {
  const _GlobPositions({
    required this.splits,
    required this.start,
    required this.next,
    required this.matches,
    required this.matchesDirectoryForm,
  });
  final bool splits;
  final List<int> start;
  final List<int> Function(List<int>, String) next;
  final bool Function(List<int>, String, String) matches;
  final bool Function(List<int>, String, String) matchesDirectoryForm;
}

RegExp _globRegExp(String source, String flags) => RegExp(
  source,
  caseSensitive: !flags.contains('i'),
  dotAll: flags.contains('s'),
);

List<_GlobPiece>? _globPieces(String pattern, String flags) {
  if (pattern.contains('__GLOBSTAR')) return null;
  String sourceOf(String text) =>
      globToRegex(text).substring(1, globToRegex(text).length - 1);
  final pieces = <_GlobPiece>[];
  var unclosed = 0;
  final tokenizerPattern = StringBuffer(r'(\[[^\]]*\])|(\*+)(/?)|(/)|([^[*')
    ..write('/')
    ..write(r']+|\[');
  final tokenizer = RegExp(tokenizerPattern.toString());
  for (final match in tokenizer.allMatches(pattern)) {
    final text = match[0]!;
    final bracket = match[1];
    final stars = match[2];
    final separatorAfterStars = match[3];
    final separator = match[4];
    if (bracket != null) {
      if (RegExp(r'[*?]').hasMatch(bracket)) return null;
      final source = sourceOf(bracket);
      final regex = _globRegExp('^$source\$', flags);
      if (regex.hasMatch(bracket)) {
        for (final item in source.split('/').indexed) {
          if (item.$1 > 0) pieces.add(const _GlobPieceSlash());
          pieces.add(_GlobPieceSource(item.$2));
        }
      } else {
        pieces.add(
          _GlobPieceSource(
            source,
            canBeSeparator: _globRegExp('^$source\$', flags).hasMatch('/'),
          ),
        );
      }
    } else if (stars != null) {
      final withSeparator = separatorAfterStars == '/' && stars.length >= 2;
      final left = stars.length - (withSeparator ? 2 : 0);
      if (left >= 2) {
        pieces.add(const _GlobPieceAny());
      } else if (left == 1) {
        pieces.add(const _GlobPieceSource('[^/]*'));
      }
      if (withSeparator) {
        pieces.add(const _GlobPieceAnyDirs());
      } else if (separatorAfterStars == '/') {
        pieces.add(const _GlobPieceSlash());
      }
    } else if (separator != null) {
      pieces.add(const _GlobPieceSlash());
    } else {
      if (text == '[' && unclosed++ > 0) return null;
      pieces.add(_GlobPieceSource(sourceOf(text)));
    }
  }
  return pieces.indexed
      .where(
        (item) =>
            item.$2 is! _GlobPieceAnyDirs ||
            ((item.$1 + 1 >= pieces.length ||
                    pieces[item.$1 + 1] is! _GlobPieceAnyDirs) &&
                (item.$1 + 1 >= pieces.length ||
                    pieces[item.$1 + 1] is! _GlobPieceAny)),
      )
      .map((item) => item.$2)
      .toList();
}

_GlobPositions _globPositions(String normalizedPattern, String flags) {
  final regex = _globRegExp(globToRegex(normalizedPattern), flags);
  final directoryForm = removeTrailingGlobSuffix(normalizedPattern);
  final directoryRegex = directoryForm != normalizedPattern
      ? _globRegExp(globToRegex(directoryForm), flags)
      : null;
  final unsplit = _GlobPositions(
    splits: false,
    start: const [0],
    next: (_, __) => const [0],
    matches: (_, __, spelled) => regex.hasMatch(spelled),
    matchesDirectoryForm: (_, __, spelled) =>
        directoryRegex?.hasMatch(spelled) == true,
  );
  final states = <Object>[];
  const star = '[^/]*';
  int build(List<_GlobPiece> pieces) {
    final memo = <String, int>{};
    int globstar(int? then) {
      states.add(_Globstar(then));
      return states.length - 1;
    }

    int componentAt(int i, bool lead) {
      final key = '$i${lead ? '*' : ''}';
      final known = memo[key];
      if (known != null) return known;
      if (!lead && i < pieces.length && pieces[i] is _GlobPieceAnyDirs) {
        final id = globstar(null);
        memo[key] = id;
        (states[id] as _Globstar).then = componentAt(i + 1, false);
        return id;
      }
      if (!lead && i == pieces.length - 1 && pieces[i] is _GlobPieceAny) {
        final id = globstar(null);
        memo[key] = id;
        return id;
      }
      final component = _GlobComponent();
      states.add(component);
      final id = states.length - 1;
      memo[key] = id;
      void endsWith(String source, int? to) =>
          component.edges.add(_GlobEdge(_globRegExp('^$source\$', flags), to));
      var source = lead ? star : '';
      for (var j = i; ; j++) {
        final piece = j < pieces.length ? pieces[j] : null;
        if (piece == null) {
          endsWith(source, null);
          break;
        }
        if (piece is _GlobPieceSlash) {
          endsWith(source, componentAt(j + 1, false));
          break;
        }
        if (piece is _GlobPieceAny) {
          endsWith('$source$star', globstar(componentAt(j + 1, true)));
          source += star;
        } else if (piece is _GlobPieceAnyDirs) {
          endsWith('$source$star', globstar(componentAt(j + 1, false)));
        } else if ((piece as _GlobPieceSource).canBeSeparator) {
          endsWith(source, componentAt(j + 1, false));
          source += '(?!/)${piece.source}';
        } else {
          source += piece.source;
        }
      }
      return id;
    }

    return componentAt(0, false);
  }

  late List<int> starts;
  late int firstOfDirectoryForm;
  try {
    final pieces = _globPieces(normalizedPattern, flags);
    final directoryPieces = directoryRegex == null
        ? <_GlobPiece>[]
        : _globPieces(directoryForm, flags);
    if (pieces == null || directoryPieces == null) return unsplit;
    starts = [build(pieces)];
    firstOfDirectoryForm = states.length;
    if (directoryRegex != null) starts.add(build(directoryPieces));
  } catch (_) {
    return unsplit;
  }
  void open(Set<int> into, int? position) {
    var p = position;
    while (p != null && !into.contains(p)) {
      into.add(p);
      final state = states[p];
      p = state is _Globstar ? state.then : null;
    }
  }

  List<int> sorted(Set<int> positions) => positions.toList()..sort();
  bool endsAt(List<int> positions, String name, bool directory) =>
      positions.any((p) {
        if ((p >= firstOfDirectoryForm) != directory) return false;
        final state = states[p];
        return state is _Globstar
            ? state.then == null
            : (state as _GlobComponent).edges.any(
                (edge) => edge.to == null && edge.regex.hasMatch(name),
              );
      });
  final start = <int>{};
  for (final position in starts) {
    open(start, position);
  }
  return _GlobPositions(
    splits: true,
    start: sorted(start),
    next: (positions, name) {
      final next = <int>{};
      for (final position in positions) {
        final state = states[position];
        if (state is _Globstar) {
          open(next, position);
        } else {
          for (final edge in (state as _GlobComponent).edges) {
            if (edge.to != null && edge.regex.hasMatch(name))
              open(next, edge.to);
          }
        }
      }
      return sorted(next);
    },
    matches: (positions, name, _) => endsAt(positions, name, false),
    matchesDirectoryForm: (positions, name, _) => endsAt(positions, name, true),
  );
}

class _Globstar {
  _Globstar(this.then);
  int? then;
}

class _GlobComponent {
  final List<_GlobEdge> edges = [];
}

class _GlobEdge {
  const _GlobEdge(this.regex, this.to);
  final RegExp regex;
  final int? to;
}

/** The literal directory a glob's walk starts from. */
String globPatternBaseDir(String normalizedPattern) {
  final staticPrefix = normalizedPattern.split(RegExp(r'[*?[\]]')).first;
  if (staticPrefix.isEmpty) return '';
  return staticPrefix.endsWith('/')
      ? staticPrefix.substring(0, staticPrefix.length - 1)
      : path.posix.dirname(staticPrefix);
}

/** Whether a base from [globPatternBaseDir] is empty or the root. */
bool globBaseDirIsRoot(String baseDir) => baseDir.isEmpty || baseDir == '/';

/** Normalize to `/` separators on Windows. */
String toForwardSlashes(String s) =>
    process.platform == 'win32' ? s.replaceAll('\\', '/') : s;

/** The walk behind [expandGlobPattern]. */
GlobWalk walkGlobPattern(
  String globPath, {
  bool caseInsensitive = false,
  String? anchor,
  bool withDirectoryForm = false,
  bool followSymlinkedDirectories = false,
  GlobWalkListings? listings,
}) => finish(
  walkGlobPatternSteps(
    globPath,
    caseInsensitive: caseInsensitive,
    anchor: anchor,
    withDirectoryForm: withDirectoryForm,
    followSymlinkedDirectories: followSymlinkedDirectories,
    listings: listings,
  ),
);

/** [walkGlobPattern], a step to a directory. */
Steps<GlobWalk> walkGlobPatternSteps(
  String globPath, {
  bool caseInsensitive = false,
  String? anchor,
  bool withDirectoryForm = false,
  bool followSymlinkedDirectories = false,
  GlobWalkListings? listings,
}) sync* {
  final walk = GlobWalk();
  final walkAnchor = anchor == null ? null : toForwardSlashes(anchor);
  final normalizedPattern = walkAnchor == null
      ? toForwardSlashes(normalizePathForSandbox(globPath))
      : toForwardSlashes(globPath).substring(walkAnchor.length);
  if (walkAnchor != null &&
      (!RegExp(r'[^/]').hasMatch(walkAnchor) ||
          !toForwardSlashes(globPath).startsWith(walkAnchor) ||
          !(walkAnchor.endsWith('/') ||
              RegExp(r'^(\/|$)').hasMatch(normalizedPattern)))) {
    throw ArgumentError(
      'Glob pattern $globPath does not lie beneath the anchor $anchor',
    );
  }
  final patternBaseDir = globPatternBaseDir(normalizedPattern);
  final baseDirBelowAnchor = patternBaseDir == '/' ? '' : patternBaseDir;
  final baseDir = walkAnchor == null
      ? patternBaseDir
      : '$walkAnchor$baseDirBelowAnchor';
  if (globBaseDirIsRoot(baseDir)) {
    logForDebugging(
      '[Sandbox] Glob pattern has no literal directory below the root to start from, skipping: $globPath',
      level: 'warn',
    );
    yield Done(walk);
    return;
  }
  final flags = caseInsensitive ? 'is' : 's';
  final positions = _globPositions(normalizedPattern, flags);
  if (followSymlinkedDirectories && !positions.splits) {
    logForDebugging(
      '[Sandbox] Glob pattern $globPath cannot be followed one path component at a time, so it is matched against real paths only and not through symlinked directories',
      level: 'warn',
    );
  }
  final records = <String, _DirectoryRecord>{};
  final cachedListings = listings ?? <String, Object>{};
  final pending = <_WalkFrame>[];
  String? codeOf(Object? error) => error is NodeError ? error.code : null;

  T onRealPath<T>(
    String real,
    String short,
    T Function(String) call,
    bool Function(Object) absent,
    void Function() unread,
  ) {
    try {
      return call(real);
    } catch (first) {
      if (short == real) rethrow;
      late T answer;
      try {
        answer = call(short);
      } catch (second) {
        throw absent(first) ? (!absent(second) ? second : first) : first;
      }
      if (!absent(first) && codeOf(first) != 'ENAMETOOLONG') {
        logForDebugging(
          '[Sandbox] $real could not be read for glob pattern $globPath, so it is covered whole, whatever $short leads to: $first',
          level: 'warn',
        );
        unread();
      }
      return answer;
    }
  }

  final linkTargets = <String, _LinkTarget>{};
  _LinkTarget linkTargetOf(String linkPath, String realLinkPath) {
    final cached = linkTargets[realLinkPath];
    if (cached != null) return cached;
    late _LinkTarget target;
    try {
      var unread = false;
      final found = onRealPath(
        realLinkPath,
        linkPath,
        (p) => _FoundLinkTarget(
          isDirectory: fs_walk.statSync(p).isDirectory(),
          real: realPathOf(p),
          unread: false,
        ),
        isAbsenceErrno,
        () => unread = true,
      );
      target = _FoundLinkTarget(
        isDirectory: found.isDirectory,
        real: found.real,
        unread: unread,
      );
    } catch (error) {
      target = isAbsenceErrno(error)
          ? const _AbsentLinkTarget()
          : const _UninspectableLinkTarget();
    }
    linkTargets[realLinkPath] = target;
    return target;
  }

  _GlobWalkEntry withType(fs_walk.Dirent entry, String listedAs, String real) {
    if (entry.isFile() ||
        entry.isDirectory() ||
        entry.isSymbolicLink() ||
        entry.isFIFO() ||
        entry.isSocket() ||
        entry.isCharacterDevice() ||
        entry.isBlockDevice()) {
      return _GlobWalkEntry(
        name: entry.name,
        isDirectory: entry.isDirectory,
        isSymbolicLink: entry.isSymbolicLink,
      );
    }
    final name = entry.name;
    final spelled = path.join(listedAs, name);
    var type = 'other';
    try {
      final stats = fs.lstatSync(spelled);
      if (stats.isSymbolicLink()) {
        type = 'link';
      } else if (fs_walk.isDirectorySync(spelled)) {
        type = 'directory';
      }
    } catch (_) {
      try {
        final isDirectory = fs_walk.statSync(spelled).isDirectory();
        if (realPathOf(spelled) != path.join(real, name)) {
          type = 'link';
        } else if (isDirectory) {
          type = 'directory';
        }
      } catch (error) {
        final code = codeOf(error);
        if (code == 'ELOOP') {
          type = 'link';
        } else if (code != 'ENOENT') {
          type = 'directory';
          cachedListings[path.join(real, name)] = error is Error
              ? error
              : NodeException(error.toString());
        }
      }
    }
    return _GlobWalkEntry(
      name: name,
      isDirectory: () => type == 'directory',
      isSymbolicLink: () => type == 'link',
    );
  }

  final baseSpelling = RegExp(r'^[A-Za-z]:$').hasMatch(baseDir)
      ? '$baseDir/'
      : baseDir;
  var baseReal = baseSpelling;
  try {
    baseReal = realPathOf(baseSpelling);
  } catch (_) {
    // Not there, or a component of it cannot be resolved: list the spelling.
  }
  walk.baseLocation = baseReal;
  final initialPositions = (walkAnchor == null ? baseDir : baseDirBelowAnchor)
      .split('/')
      .fold<List<int>>(positions.start, positions.next);
  pending.add(
    _WalkFrame(
      dir: baseSpelling,
      real: baseReal,
      short: baseSpelling.length < baseReal.length ? baseSpelling : baseReal,
      positions: initialPositions,
    ),
  );
  while (pending.isNotEmpty) {
    final frame = pending.removeLast();
    final dir = frame.dir;
    final real = frame.real;
    final record = records.putIfAbsent(real, _DirectoryRecord.new);
    final fresh = frame.positions
        .where((p) => !record.listedFor.contains(p))
        .toList();
    if (fresh.isEmpty) continue;
    yield Pause<GlobWalk>();
    void denyWhole() {
      if (record.unlisted) return;
      record.unlisted = true;
      walk.unlisted.add(dir);
      if (real != dir) walk.realOf[dir] = real;
    }

    late List<_GlobWalkEntry> entries;
    try {
      final known = cachedListings[real];
      if (known is Error) throw known;
      entries = known is List<_GlobWalkEntry>
          ? known
          : onRealPath(
              real,
              frame.short,
              (p) => fs_walk
                  .readdirSync(p, withFileTypes: true)
                  .map((entry) => withType(entry, p, real))
                  .toList(),
              (error) => codeOf(error) == 'ENOENT',
              denyWhole,
            );
      cachedListings[real] = entries;
    } catch (error) {
      final errorCode = codeOf(error);
      logForDebugging(
        '[Sandbox] Error listing $dir for glob pattern $globPath: $error',
        level: errorCode == 'ENOENT' ? 'info' : 'warn',
      );
      if (errorCode != 'ENOENT') {
        if (listings != null) {
          cachedListings[real] = error is Error
              ? error
              : NodeException(error.toString());
        }
        denyWhole();
      }
      continue;
    }
    record.listedFor.addAll(fresh);
    for (final entry in entries) {
      if (positions.splits &&
          !entry.isDirectory() &&
          !entry.isSymbolicLink() &&
          !positions.matches(fresh, entry.name, '')) {
        continue;
      }
      final fullPath = path.join(dir, entry.name);
      final realPath = path.join(real, entry.name);
      final spelled = toForwardSlashes(fullPath);
      final candidate = walkAnchor != null && spelled.startsWith(walkAnchor)
          ? spelled.substring(walkAnchor.length)
          : spelled;
      final isMatch = positions.matches(fresh, entry.name, candidate);
      if (isMatch) walk.matches.add(fullPath);
      if (entry.isDirectory()) {
        final beneath = positions.next(fresh, entry.name);
        final isDirectoryMatch =
            withDirectoryForm &&
            positions.matchesDirectoryForm(fresh, entry.name, candidate);
        if (isDirectoryMatch) walk.directoryMatches.add(fullPath);
        if ((isMatch || isDirectoryMatch) && realPath != fullPath) {
          walk.realOf[fullPath] = realPath;
        }
        if (beneath.isNotEmpty) {
          pending.add(
            _WalkFrame(
              dir: fullPath,
              real: realPath,
              short: path.join(frame.short, entry.name),
              positions: beneath,
            ),
          );
        }
        continue;
      }
      if (!entry.isSymbolicLink()) {
        if (isMatch && realPath != fullPath) walk.realOf[fullPath] = realPath;
        continue;
      }
      walk.symlinks.add(fullPath);
      if (!followSymlinkedDirectories) continue;
      final isDirectoryFormCandidate =
          withDirectoryForm &&
          positions.matchesDirectoryForm(fresh, entry.name, candidate);
      final beneath = positions.splits
          ? positions.next(fresh, entry.name)
          : <int>[];
      if (!isMatch && !isDirectoryFormCandidate && beneath.isEmpty) continue;
      final shortPath = path.join(frame.short, entry.name);
      final target = linkTargetOf(shortPath, realPath);
      if (target is _AbsentLinkTarget) continue;
      final unread =
          target is _UninspectableLinkTarget ||
          (target as _FoundLinkTarget).unread;
      if (unread) {
        walk.uninspectableLinks.add(fullPath);
        if (isDirectoryFormCandidate) walk.directoryMatches.add(fullPath);
      }
      if (target is _UninspectableLinkTarget) continue;
      final found = target as _FoundLinkTarget;
      if (unread &&
          (isMatch || (isDirectoryFormCandidate && found.isDirectory))) {
        walk.matches.add(found.real == '/' ? real : found.real);
      }
      if (isMatch && !unread) walk.realOf[fullPath] = found.real;
      if (!found.isDirectory) continue;
      if (isDirectoryFormCandidate && !unread) {
        walk.directoryMatches.add(fullPath);
        walk.realOf[fullPath] = found.real;
      }
      if (beneath.isEmpty) continue;
      if (isAtOrUnder(real, found.real) || isAtOrUnder(baseReal, found.real)) {
        logForDebugging(
          '[Sandbox] Not following symlink $fullPath -> ${found.real} for glob pattern $globPath: it leads back up the tree',
        );
        continue;
      }
      logForDebugging(
        '[Sandbox] Following symlink $fullPath -> ${found.real} for glob pattern $globPath',
      );
      pending.add(
        _WalkFrame(
          dir: found.real,
          real: found.real,
          short: shortPath.length < found.real.length ? shortPath : found.real,
          positions: beneath,
        ),
      );
    }
  }
  yield Done(walk);
}

class _WalkFrame {
  const _WalkFrame({
    required this.dir,
    required this.real,
    required this.short,
    required this.positions,
  });
  final String dir;
  final String real;
  final String short;
  final List<int> positions;
}

class _DirectoryRecord {
  final Set<int> listedFor = {};
  bool unlisted = false;
}

sealed class _LinkTarget {
  const _LinkTarget();
}

final class _FoundLinkTarget extends _LinkTarget {
  const _FoundLinkTarget({
    required this.real,
    required this.isDirectory,
    required this.unread,
  });
  final String real;
  final bool isDirectory;
  final bool unread;
}

final class _AbsentLinkTarget extends _LinkTarget {
  const _AbsentLinkTarget();
}

final class _UninspectableLinkTarget extends _LinkTarget {
  const _UninspectableLinkTarget();
}
