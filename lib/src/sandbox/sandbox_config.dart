// Ported from sandbox-runtime src/sandbox/sandbox-config.ts @ 24eb39e.
// ignore_for_file: constant_identifier_names, dangling_library_doc_comments
// ignore_for_file: slash_for_doc_comments, curly_braces_in_flow_control_structures
// ignore_for_file: prefer_interpolation_to_compose_strings, non_constant_identifier_names

import 'package:path/path.dart' as node_path;

import '../utils/platform.dart';
import 'address.dart';
import 'domain_pattern.dart';
import 'request_filter.dart';
import 'sandbox_utils.dart';

/**
 * Configuration for Sandbox Runtime
 * This is the main configuration interface that consumers pass to SandboxManager.initialize()
 */

/** One validation issue, using the path and message fields exposed by Zod. */
class ConfigIssue {
  final String message;
  final List<Object> path;
  final String code;

  const ConfigIssue({
    required this.message,
    required this.path,
    this.code = 'custom',
  });
}

/** The error returned by [ConfigSchema.safeParse]. */
class ConfigValidationError {
  final List<ConfigIssue> issues;
  const ConfigValidationError(this.issues);
}

/** Result returned by [ConfigSchema.safeParse]. */
class ConfigParseResult<T> {
  final bool success;
  final T? _data;
  final ConfigValidationError? _error;

  const ConfigParseResult._(this.success, this._data, this._error);

  T get data =>
      _data ?? (throw StateError('No parsed data on an unsuccessful result'));
  ConfigValidationError get error =>
      _error ??
      (throw StateError('No validation error on a successful result'));
}

typedef _ConfigParser<T> =
    T? Function(Object? value, List<ConfigIssue> issues, List<Object> path);

/** Hand-written counterpart of the upstream Zod schemas. */
class ConfigSchema<T> {
  final _ConfigParser<T> _parser;
  const ConfigSchema(this._parser);

  ConfigParseResult<T> safeParse(Object? value) {
    final issues = <ConfigIssue>[];
    final data = _parser(value, issues, const []);
    if (issues.isNotEmpty || data == null) {
      return ConfigParseResult<T>._(false, null, ConfigValidationError(issues));
    }
    return ConfigParseResult<T>._(true, data, null);
  }
}

void _addIssue(
  List<ConfigIssue> issues,
  List<Object> path,
  String message, {
  String code = 'custom',
}) {
  issues.add(
    ConfigIssue(message: message, path: List.unmodifiable(path), code: code),
  );
}

String _received(Object? value) {
  if (value == null) return 'null';
  if (value is bool) return 'boolean';
  if (value is num) return 'number';
  if (value is String) return 'string';
  if (value is List) return 'array';
  return 'object';
}

Map<String, Object?>? _object(
  Object? value,
  List<Object> path,
  List<ConfigIssue> issues,
) {
  if (value is Map) {
    final result = <String, Object?>{};
    for (final entry in value.entries) {
      if (entry.key is! String) {
        _addIssue(issues, path, 'Expected string keys', code: 'invalid_type');
        return null;
      }
      result[entry.key as String] = entry.value;
    }
    return result;
  }
  _addIssue(
    issues,
    path,
    'Expected object, received ${_received(value)}',
    code: 'invalid_type',
  );
  return null;
}

bool _has(Map<String, Object?> object, String key) => object.containsKey(key);

String? _string(
  Object? value,
  List<Object> path,
  List<ConfigIssue> issues, {
  int? min,
  int? max,
  String? minMessage,
  String? maxMessage,
  RegExp? regex,
  String? regexMessage,
}) {
  if (value is! String) {
    _addIssue(
      issues,
      path,
      'Expected string, received ${_received(value)}',
      code: 'invalid_type',
    );
    return null;
  }
  if (min != null && value.length < min) {
    _addIssue(
      issues,
      path,
      minMessage ?? 'String must contain at least $min character(s)',
      code: 'too_small',
    );
  }
  if (max != null && value.length > max) {
    _addIssue(
      issues,
      path,
      maxMessage ?? 'String must contain at most $max character(s)',
      code: 'too_big',
    );
  }
  if (regex != null && !regex.hasMatch(value)) {
    _addIssue(issues, path, regexMessage ?? 'Invalid', code: 'invalid_string');
  }
  return value;
}

bool? _boolean(Object? value, List<Object> path, List<ConfigIssue> issues) {
  if (value is bool) return value;
  _addIssue(
    issues,
    path,
    'Expected boolean, received ${_received(value)}',
    code: 'invalid_type',
  );
  return null;
}

num? _number(
  Object? value,
  List<Object> path,
  List<ConfigIssue> issues, {
  int? min,
  int? max,
  bool integer = false,
}) {
  if (value is! num) {
    _addIssue(
      issues,
      path,
      'Expected number, received ${_received(value)}',
      code: 'invalid_type',
    );
    return null;
  }
  if (integer && value % 1 != 0)
    _addIssue(
      issues,
      path,
      'Expected integer, received float',
      code: 'invalid_type',
    );
  if (min != null && value < min)
    _addIssue(
      issues,
      path,
      'Number must be greater than or equal to $min',
      code: 'too_small',
    );
  if (max != null && value > max)
    _addIssue(
      issues,
      path,
      'Number must be less than or equal to $max',
      code: 'too_big',
    );
  return value;
}

List<Object?>? _array(
  Object? value,
  List<Object> path,
  List<ConfigIssue> issues,
) {
  if (value is List) return value.cast<Object?>();
  _addIssue(
    issues,
    path,
    'Expected array, received ${_received(value)}',
    code: 'invalid_type',
  );
  return null;
}

String? _enumValue(
  Object? value,
  List<Object> path,
  List<ConfigIssue> issues,
  List<String> values,
) {
  if (value is String && values.contains(value)) return value;
  _addIssue(
    issues,
    path,
    'Invalid enum value. Expected ${values.map((v) => '\'$v\'').join(' | ')}, received ${value is String ? '\'$value\'' : _received(value)}',
    code: 'invalid_enum_value',
  );
  return null;
}

bool _url(String value) {
  final uri = Uri.tryParse(value);
  return uri != null && uri.hasScheme && uri.scheme.isNotEmpty;
}

/**
 * An entry of `denyRead`, `allowRead`, `allowWrite` or `denyWrite`: a
 * spelling, which is a pattern when it reads as one, or a path marked
 * `literal: true`, which never is. An object without the mark, or with a
 * key this does not know, is refused rather than read either way.
 */
sealed class FilesystemPathEntry {
  const FilesystemPathEntry();
}

/** An ordinary path spelling (which may be a glob). */
class FilesystemPathSpelling extends FilesystemPathEntry {
  final String path;
  const FilesystemPathSpelling(this.path);
  @override
  String toString() => path;
}

/** A literal path spelling; `literal` is always true. */
class FilesystemPathLiteral extends FilesystemPathEntry {
  final String path;
  const FilesystemPathLiteral(this.path);
  bool get literal => true;
  @override
  String toString() => path;
}

/**
 * Schema for domain patterns (e.g., "example.com", "*.npmjs.org")
 * Validates that domain patterns are safe and don't include overly broad wildcards
 */
final ConfigSchema<String> _domainPatternSchema = ConfigSchema((
  value,
  issues,
  path,
) {
  final val = _string(value, path, issues);
  if (val != null && !isValidDomainPattern(val))
    _addIssue(issues, path, DOMAIN_PATTERN_MESSAGE);
  return val;
});

/**
 * Domain pattern with an optional `:port` suffix (e.g., "example.com:443",
 * "*.npmjs.org:8443"). Used for allowedDomains / deniedDomains, where the
 * proxy knows the destination port; an entry without a port matches any port.
 * The check and its message live in domain-pattern.ts, which says why.
 */
final ConfigSchema<String> _domainPortPatternSchema = ConfigSchema((
  value,
  issues,
  path,
) {
  final val = _string(value, path, issues);
  if (val != null && !isValidAllowedDomainEntry(val))
    _addIssue(issues, path, ALLOWED_DOMAIN_ENTRY_MESSAGE);
  return val;
});

/**
 * deniedDomains entry: a domainPortPattern, or a bare "*" / "*:port"
 * (deny-all, optionally per-port).
 */
final ConfigSchema<String> _deniedDomainPatternSchema = ConfigSchema((
  value,
  issues,
  path,
) {
  final val = _string(value, path, issues);
  if (val != null) {
    if (!hasValidIpv6Bracketing(val)) {
      _addIssue(
        issues,
        path,
        DOMAIN_PATTERN_MESSAGE +
            ' In deniedDomains a bare "*" (deny-all) is also accepted, and an optional ":port" suffix (1-65535) restricts the entry to that port.',
      );
    } else {
      final split = splitDomainPatternPort(val);
      if (split.hostPattern != '*' &&
          !isValidDomainPattern(split.hostPattern)) {
        _addIssue(
          issues,
          path,
          DOMAIN_PATTERN_MESSAGE +
              ' In deniedDomains a bare "*" (deny-all) is also accepted, and an optional ":port" suffix (1-65535) restricts the entry to that port.',
        );
      }
    }
  }
  return val;
});

/** IP literal or CIDR range (`10.0.0.0/8`, `fc00::/7`, `169.254.169.254`). */
final ConfigSchema<String> _addressRangeSchema = ConfigSchema((
  value,
  issues,
  path,
) {
  final val = _string(value, path, issues);
  if (val != null && parseAddressRange(val) == null) {
    _addIssue(
      issues,
      path,
      'Invalid IP address or CIDR range. Use an IPv4/IPv6 literal or CIDR, e.g. "10.0.0.0/8", "192.168.1.10", "fc00::/7" (IPv6 unbracketed).',
    );
  }
  return val;
});

/** Schema for filesystem paths */
final ConfigSchema<String> _filesystemPathSchema = ConfigSchema(
  (value, issues, path) =>
      _string(value, path, issues, min: 1, minMessage: 'Path cannot be empty'),
);

/**
 * An entry of `denyRead`, `allowRead`, `allowWrite` or `denyWrite`: a
 * spelling, which is a pattern when it reads as one, or a path marked
 * `literal: true`, which never is. An object without the mark, or with a
 * key this does not know, is refused rather than read either way.
 */
final ConfigSchema<FilesystemPathEntry> _filesystemPathEntrySchema =
    ConfigSchema((value, issues, path) {
      if (value is String) {
        final checked = _filesystemPathSchema._parser(value, issues, path);
        return checked == null ? null : FilesystemPathSpelling(checked);
      }
      if (value is Map &&
          value['path'] is String &&
          value['literal'] == true &&
          value.keys.every((key) => key == 'path' || key == 'literal')) {
        final checked = _filesystemPathSchema._parser(value['path'], issues, [
          ...path,
          'path',
        ]);
        return checked == null ? null : FilesystemPathLiteral(checked);
      }
      if (value is Map && value['path'] is String && value['literal'] == true) {
        final unknown = value.keys
            .where((key) => key != 'path' && key != 'literal')
            .join("', '");
        _addIssue(
          issues,
          path,
          "Unrecognized key(s) in object: '$unknown'",
          code: 'unrecognized_keys',
        );
        return null;
      }
      final issue = issues.length;
      _addIssue(
        issues,
        path,
        'Expected a path, or { "path": "<path>", "literal": true }',
        code: 'invalid_union',
      );
      // Preserve the dedicated empty-path issue for the two accepted shapes.
      if (value is Map && value['path'] == '') {
        issues.removeRange(issue, issues.length);
        _addIssue(
          issues,
          [...path, 'path'],
          'Path cannot be empty',
          code: 'too_small',
        );
      }
      return null;
    });

/** Schema for an absolute path to an external binary. */
final ConfigSchema<String> _binaryPathSchema = ConfigSchema((
  value,
  issues,
  path,
) {
  final val = _string(
    value,
    path,
    issues,
    min: 1,
    minMessage: 'Path cannot be empty',
  );
  if (val != null && !node_path.isAbsolute(val))
    _addIssue(issues, path, 'Binary path must be absolute');
  return val;
});

// String-valued unions retain their wire spelling, rather than becoming enums.
typedef CredentialMode = String;
const List<String> CREDENTIAL_MODES = ['deny', 'mask'];
typedef ExtractNoMatch = String;
const List<String> EXTRACT_NO_MATCH_VALUES = ['warn', 'deny', 'error'];
typedef CredentialDecode = String;
const List<String> CREDENTIAL_DECODE_VALUES = ['jwt'];
typedef Sigv4Policy = String;
const List<String> SIGV4_POLICY_VALUES = ['deny', 'passthrough'];

class MitmProxyConfig {
  final String socketPath;
  final List<String> domains;
  const MitmProxyConfig({required this.socketPath, required this.domains});
}

class ParentProxyConfig {
  final String? http;
  final String? https;
  final String? noProxy;
  const ParentProxyConfig({this.http, this.https, this.noProxy});
}

class CredentialFileConfig {
  final String path;
  final CredentialMode mode;
  final String? extract;
  final ExtractNoMatch? onExtractNoMatch;
  final CredentialDecode? decode;
  final List<String>? maskClaims;
  final bool? maskDuplicates;
  final List<String>? injectHosts;
  const CredentialFileConfig({
    required this.path,
    required this.mode,
    this.extract,
    this.onExtractNoMatch,
    this.decode,
    this.maskClaims,
    this.maskDuplicates,
    this.injectHosts,
  });
}

class CredentialEnvVarConfig {
  final String name;
  final CredentialMode mode;
  final String? extract;
  final ExtractNoMatch? onExtractNoMatch;
  final CredentialDecode? decode;
  final List<String>? maskClaims;
  final List<String>? injectHosts;
  const CredentialEnvVarConfig({
    required this.name,
    required this.mode,
    this.extract,
    this.onExtractNoMatch,
    this.decode,
    this.maskClaims,
    this.injectHosts,
  });
}

class AwsPairConfig {
  final String accessKeyIdVar;
  final String secretAccessKeyVar;
  final String? sessionTokenVar;
  const AwsPairConfig({
    required this.accessKeyIdVar,
    required this.secretAccessKeyVar,
    this.sessionTokenVar,
  });
}

class Sigv4Config {
  final Sigv4Policy? streaming;
  final Sigv4Policy? presigned;
  final Sigv4Policy? sigv4a;
  const Sigv4Config({this.streaming, this.presigned, this.sigv4a});
}

class CredentialsConfig {
  final List<CredentialFileConfig>? files;
  final List<CredentialEnvVarConfig>? envVars;
  final bool? allowPlaintextInject;
  final List<AwsPairConfig>? awsPairs;
  final Sigv4Config? sigv4;
  const CredentialsConfig({
    this.files,
    this.envVars,
    this.allowPlaintextInject,
    this.awsPairs,
    this.sigv4,
  });
}

class TlsTerminateConfig {
  final String? caCertPath;
  final String? caKeyPath;
  final List<String>? excludeDomains;
  final List<String>? extraCaCertPaths;
  final int? maxTunnels;
  final int? handshakeTimeoutMs;
  const TlsTerminateConfig({
    this.caCertPath,
    this.caKeyPath,
    this.excludeDomains,
    this.extraCaCertPaths,
    this.maxTunnels,
    this.handshakeTimeoutMs,
  });
}

class NetworkConfig {
  final List<String> allowedDomains;
  final List<String> deniedDomains;
  final Map<String, String>? deniedDomainReasons;
  final bool? strictAllowlist;
  final List<String>? deniedResolvedAddresses;
  final List<String>? allowUnixSockets;
  final bool? allowAllUnixSockets;
  final bool? allowLocalBinding;
  final List<String>? allowMachLookup;
  final int? httpProxyPort;
  final int? socksProxyPort;
  final MitmProxyConfig? mitmProxy;
  final FilterRequestCallback? filterRequest;
  final bool? allowPlaintextHeaderSet;
  final List<String>? stripResponseHeaders;
  final bool? refuseOpaqueTunnels;
  final bool? requireHostMatch;
  final TlsTerminateConfig? tlsTerminate;
  final ParentProxyConfig? parentProxy;
  const NetworkConfig({
    required this.allowedDomains,
    required this.deniedDomains,
    this.deniedDomainReasons,
    this.strictAllowlist,
    this.deniedResolvedAddresses,
    this.allowUnixSockets,
    this.allowAllUnixSockets,
    this.allowLocalBinding,
    this.allowMachLookup,
    this.httpProxyPort,
    this.socksProxyPort,
    this.mitmProxy,
    this.filterRequest,
    this.allowPlaintextHeaderSet,
    this.stripResponseHeaders,
    this.refuseOpaqueTunnels,
    this.requireHostMatch,
    this.tlsTerminate,
    this.parentProxy,
  });
}

class FilesystemConfig {
  final bool? disabled;
  final List<FilesystemPathEntry> denyRead;
  final List<FilesystemPathEntry>? allowRead;
  final List<FilesystemPathEntry> allowWrite;
  final List<FilesystemPathEntry> denyWrite;
  final bool? allowGitConfig;
  const FilesystemConfig({
    this.disabled,
    required this.denyRead,
    this.allowRead,
    required this.allowWrite,
    required this.denyWrite,
    this.allowGitConfig,
  });
}

typedef IgnoreViolationsConfig = Map<String, List<String>>;

class RipgrepConfig {
  final String command;
  final List<String>? args;
  final String? argv0;
  const RipgrepConfig({required this.command, this.args, this.argv0});
}

class GitConfig {
  final List<String> safeDirectories;
  const GitConfig({this.safeDirectories = const []});
}

class SrtWinConfig {
  final String path;
  const SrtWinConfig({required this.path});
}

class WindowsConfig {
  final String? sandboxUser;
  final String? sublayerGuid;
  final String? wfpSublayerGuid;
  final (int, int)? proxyPortRange;
  final SrtWinConfig? srtWin;
  const WindowsConfig({
    this.sandboxUser,
    this.sublayerGuid,
    this.wfpSublayerGuid,
    this.proxyPortRange,
    this.srtWin,
  });
}

class SeccompConfig {
  final String? applyPath;
  final String? argv0;
  const SeccompConfig({this.applyPath, this.argv0});
}

class SandboxRuntimeConfig {
  final NetworkConfig network;
  final FilesystemConfig filesystem;
  final CredentialsConfig? credentials;
  final IgnoreViolationsConfig? ignoreViolations;
  final bool? enableWeakerNestedSandbox;
  final bool? enableWeakerNetworkIsolation;
  final bool? allowAppleEvents;
  final RipgrepConfig? ripgrep;
  final int? mandatoryDenySearchDepth;
  final bool? allowPty;
  final SeccompConfig? seccomp;
  final String? bwrapPath;
  final String? socatPath;
  final String? javaAgentJarPath;
  final WindowsConfig? windows;
  final GitConfig? git;
  const SandboxRuntimeConfig({
    required this.network,
    required this.filesystem,
    this.credentials,
    this.ignoreViolations,
    this.enableWeakerNestedSandbox,
    this.enableWeakerNetworkIsolation,
    this.allowAppleEvents,
    this.ripgrep,
    this.mandatoryDenySearchDepth,
    this.allowPty,
    this.seccomp,
    this.bwrapPath,
    this.socatPath,
    this.javaAgentJarPath,
    this.windows,
    this.git,
  });
}

List<String>? _stringList(
  Object? value,
  List<Object> path,
  List<ConfigIssue> issues, {
  int? minItems,
  ConfigSchema<String>? itemSchema,
  int itemMin = 0,
}) {
  final input = _array(value, path, issues);
  if (input == null) return null;
  if (minItems != null && input.length < minItems)
    _addIssue(
      issues,
      path,
      'Array must contain at least $minItems element(s)',
      code: 'too_small',
    );
  final out = <String>[];
  for (var i = 0; i < input.length; i++) {
    final itemPath = [...path, i];
    String? item;
    if (itemSchema != null) {
      item = itemSchema._parser(input[i], issues, itemPath);
    } else {
      item = _string(
        input[i],
        itemPath,
        issues,
        min: itemMin,
        minMessage: itemMin == 1
            ? 'String must contain at least 1 character(s)'
            : null,
      );
    }
    if (item != null) out.add(item);
  }
  return out;
}

List<FilesystemPathEntry>? _pathEntryList(
  Object? value,
  List<Object> path,
  List<ConfigIssue> issues,
) {
  final input = _array(value, path, issues);
  if (input == null) return null;
  final out = <FilesystemPathEntry>[];
  for (var i = 0; i < input.length; i++) {
    final entry = _filesystemPathEntrySchema._parser(input[i], issues, [
      ...path,
      i,
    ]);
    if (entry != null) out.add(entry);
  }
  return out;
}

List<String>? _domainList(
  Object? value,
  List<Object> path,
  List<ConfigIssue> issues, {
  int? minItems,
}) => _stringList(
  value,
  path,
  issues,
  minItems: minItems,
  itemSchema: _domainPatternSchema,
);

String? _parseExtract(
  Object? value,
  List<Object> path,
  List<ConfigIssue> issues,
) {
  final pattern = _string(value, path, issues);
  if (pattern == null) return null;
  try {
    final regex = RegExp(pattern);
    // This mirrors the source's appended-alternation group-count check.
    final groupCount =
        RegExp('${regex.pattern}|').firstMatch('')?.groupCount ?? 0;
    if (groupCount < 1) {
      _addIssue(
        issues,
        path,
        'extract must contain at least one capturing group — group 1 is the credential value to mask (e.g. "token:\\s*(\\S+)").',
      );
    }
  } on FormatException catch (err) {
    _addIssue(
      issues,
      path,
      'extract is not a valid regular expression: ${err.message}',
    );
  }
  return pattern;
}

CredentialFileConfig? _parseCredentialFile(
  Object? value,
  List<ConfigIssue> issues,
  List<Object> path,
) {
  final obj = _object(value, path, issues);
  if (obj == null) return null;
  final before = issues.length;
  final filePath = _string(
    obj['path'],
    [...path, 'path'],
    issues,
    min: 1,
    minMessage: 'Path cannot be empty',
  );
  final mode = _enumValue(
    obj['mode'],
    [...path, 'mode'],
    issues,
    CREDENTIAL_MODES,
  );
  final extract = _has(obj, 'extract')
      ? _parseExtract(obj['extract'], [...path, 'extract'], issues)
      : null;
  final onMatch = _has(obj, 'onExtractNoMatch')
      ? _enumValue(
          obj['onExtractNoMatch'],
          [...path, 'onExtractNoMatch'],
          issues,
          EXTRACT_NO_MATCH_VALUES,
        )
      : null;
  final decode = _has(obj, 'decode')
      ? _enumValue(
          obj['decode'],
          [...path, 'decode'],
          issues,
          CREDENTIAL_DECODE_VALUES,
        )
      : null;
  final claims = _has(obj, 'maskClaims')
      ? _stringList(
          obj['maskClaims'],
          [...path, 'maskClaims'],
          issues,
          itemMin: 1,
        )
      : null;
  final duplicates = _has(obj, 'maskDuplicates')
      ? _boolean(obj['maskDuplicates'], [...path, 'maskDuplicates'], issues)
      : null;
  final inject = _has(obj, 'injectHosts')
      ? _domainList(obj['injectHosts'], [...path, 'injectHosts'], issues)
      : null;
  if (filePath == null || mode == null || issues.length != before) return null;
  return CredentialFileConfig(
    path: filePath,
    mode: mode,
    extract: extract,
    onExtractNoMatch: onMatch,
    decode: decode,
    maskClaims: claims,
    maskDuplicates: duplicates,
    injectHosts: inject,
  );
}

CredentialEnvVarConfig? _parseCredentialEnvVar(
  Object? value,
  List<ConfigIssue> issues,
  List<Object> path,
) {
  final obj = _object(value, path, issues);
  if (obj == null) return null;
  final before = issues.length;
  final name = _string(
    obj['name'],
    [...path, 'name'],
    issues,
    regex: RegExp(r'^[A-Za-z_][A-Za-z0-9_]*$'),
    regexMessage:
        'Environment variable name must start with a letter or underscore and contain only letters, digits, and underscores',
  );
  final mode = _enumValue(
    obj['mode'],
    [...path, 'mode'],
    issues,
    CREDENTIAL_MODES,
  );
  final extract = _has(obj, 'extract')
      ? _parseExtract(obj['extract'], [...path, 'extract'], issues)
      : null;
  final onMatch = _has(obj, 'onExtractNoMatch')
      ? _enumValue(
          obj['onExtractNoMatch'],
          [...path, 'onExtractNoMatch'],
          issues,
          EXTRACT_NO_MATCH_VALUES,
        )
      : null;
  final decode = _has(obj, 'decode')
      ? _enumValue(
          obj['decode'],
          [...path, 'decode'],
          issues,
          CREDENTIAL_DECODE_VALUES,
        )
      : null;
  final claims = _has(obj, 'maskClaims')
      ? _stringList(
          obj['maskClaims'],
          [...path, 'maskClaims'],
          issues,
          itemMin: 1,
        )
      : null;
  final inject = _has(obj, 'injectHosts')
      ? _domainList(obj['injectHosts'], [...path, 'injectHosts'], issues)
      : null;
  if (name == null || mode == null || issues.length != before) return null;
  return CredentialEnvVarConfig(
    name: name,
    mode: mode,
    extract: extract,
    onExtractNoMatch: onMatch,
    decode: decode,
    maskClaims: claims,
    injectHosts: inject,
  );
}

final ConfigSchema<CredentialFileConfig> CredentialFileConfigSchema =
    ConfigSchema(_parseCredentialFile);
final ConfigSchema<CredentialEnvVarConfig> CredentialEnvVarConfigSchema =
    ConfigSchema(_parseCredentialEnvVar);

AwsPairConfig? _parseAwsPair(
  Object? value,
  List<ConfigIssue> issues,
  List<Object> path,
) {
  final obj = _object(value, path, issues);
  if (obj == null) return null;
  for (final key in obj.keys) {
    if (!{
      'accessKeyIdVar',
      'secretAccessKeyVar',
      'sessionTokenVar',
    }.contains(key))
      _addIssue(
        issues,
        [...path, key],
        'Unrecognized key(s) in object: \'$key\'',
        code: 'unrecognized_keys',
      );
  }
  final before = issues.length;
  String? envName(String key) => _string(
    obj[key],
    [...path, key],
    issues,
    regex: RegExp(r'^[A-Za-z_][A-Za-z0-9_]*$'),
    regexMessage:
        'Environment variable name must start with a letter or underscore and contain only letters, digits, and underscores',
  );
  final access = envName('accessKeyIdVar');
  final secret = envName('secretAccessKeyVar');
  final session = _has(obj, 'sessionTokenVar')
      ? envName('sessionTokenVar')
      : null;
  if (access == null || secret == null || issues.length != before) return null;
  return AwsPairConfig(
    accessKeyIdVar: access,
    secretAccessKeyVar: secret,
    sessionTokenVar: session,
  );
}

final ConfigSchema<AwsPairConfig> AwsPairConfigSchema =
    ConfigSchema(_parseAwsPair);

Sigv4Config? _parseSigv4(
  Object? value,
  List<ConfigIssue> issues,
  List<Object> path,
) {
  final obj = _object(value, path, issues);
  if (obj == null) return null;
  final streaming = _has(obj, 'streaming')
      ? _enumValue(
          obj['streaming'],
          [...path, 'streaming'],
          issues,
          SIGV4_POLICY_VALUES,
        )
      : null;
  final presigned = _has(obj, 'presigned')
      ? _enumValue(
          obj['presigned'],
          [...path, 'presigned'],
          issues,
          SIGV4_POLICY_VALUES,
        )
      : null;
  final sigv4a = _has(obj, 'sigv4a')
      ? _enumValue(
          obj['sigv4a'],
          [...path, 'sigv4a'],
          issues,
          SIGV4_POLICY_VALUES,
        )
      : null;
  return Sigv4Config(
    streaming: streaming,
    presigned: presigned,
    sigv4a: sigv4a,
  );
}

final ConfigSchema<Sigv4Config> Sigv4ConfigSchema = ConfigSchema(_parseSigv4);

ConfigSchema<T> _notNull<T>(
  T? Function(Object?, List<ConfigIssue>, List<Object>) parser,
) => ConfigSchema(parser);

final ConfigSchema<MitmProxyConfig> _MitmProxyConfigSchema = _notNull((
  value,
  issues,
  path,
) {
  final obj = _object(value, path, issues);
  if (obj == null) return null;
  final socket = _string(
    obj['socketPath'],
    [...path, 'socketPath'],
    issues,
    min: 1,
  );
  final domains = _domainList(
    obj['domains'],
    [...path, 'domains'],
    issues,
    minItems: 1,
  );
  return socket == null || domains == null
      ? null
      : MitmProxyConfig(socketPath: socket, domains: domains);
});

final ConfigSchema<ParentProxyConfig> _ParentProxyConfigSchema = _notNull((
  value,
  issues,
  path,
) {
  final obj = _object(value, path, issues);
  if (obj == null) return null;
  String? url(String key) {
    if (!_has(obj, key)) return null;
    final item = _string(obj[key], [...path, key], issues);
    if (item != null && !_url(item))
      _addIssue(issues, [...path, key], 'Invalid url', code: 'invalid_string');
    return item;
  }

  final http = url('http');
  final https = url('https');
  final noProxy = _has(obj, 'noProxy')
      ? _string(obj['noProxy'], [...path, 'noProxy'], issues)
      : null;
  return ParentProxyConfig(http: http, https: https, noProxy: noProxy);
});

final ConfigSchema<FilesystemConfig> FilesystemConfigSchema = _notNull((
  value,
  issues,
  path,
) {
  final obj = _object(value, path, issues);
  if (obj == null) return null;
  final disabled = _has(obj, 'disabled')
      ? _boolean(obj['disabled'], [...path, 'disabled'], issues)
      : null;
  final denyRead = _pathEntryList(obj['denyRead'], [
    ...path,
    'denyRead',
  ], issues);
  final allowRead = _has(obj, 'allowRead')
      ? _pathEntryList(obj['allowRead'], [...path, 'allowRead'], issues)
      : null;
  final allowWrite = _pathEntryList(obj['allowWrite'], [
    ...path,
    'allowWrite',
  ], issues);
  final denyWrite = _pathEntryList(obj['denyWrite'], [
    ...path,
    'denyWrite',
  ], issues);
  final allowGitConfig = _has(obj, 'allowGitConfig')
      ? _boolean(obj['allowGitConfig'], [...path, 'allowGitConfig'], issues)
      : null;
  if (denyRead == null || allowWrite == null || denyWrite == null) return null;
  return FilesystemConfig(
    disabled: disabled,
    denyRead: denyRead,
    allowRead: allowRead,
    allowWrite: allowWrite,
    denyWrite: denyWrite,
    allowGitConfig: allowGitConfig,
  );
});

final ConfigSchema<CredentialsConfig> CredentialsConfigSchema = _notNull((
  value,
  issues,
  path,
) {
  final obj = _object(value, path, issues);
  if (obj == null) return null;
  for (final key in obj.keys) {
    if (!{
      'files',
      'envVars',
      'allowPlaintextInject',
      'awsPairs',
      'sigv4',
    }.contains(key))
      _addIssue(
        issues,
        [...path, key],
        'Unrecognized key(s) in object: \'$key\'',
        code: 'unrecognized_keys',
      );
  }
  List<T>? entries<T>(
    String key,
    T? Function(Object?, List<ConfigIssue>, List<Object>) parser,
  ) {
    if (!_has(obj, key)) return null;
    final raw = _array(obj[key], [...path, key], issues);
    if (raw == null) return null;
    final result = <T>[];
    for (var i = 0; i < raw.length; i++) {
      final parsed = parser(raw[i], issues, [...path, key, i]);
      if (parsed != null) result.add(parsed);
    }
    return result;
  }

  final files = entries('files', _parseCredentialFile);
  final envVars = entries('envVars', _parseCredentialEnvVar);
  final allowPlaintext = _has(obj, 'allowPlaintextInject')
      ? _boolean(obj['allowPlaintextInject'], [
          ...path,
          'allowPlaintextInject',
        ], issues)
      : null;
  final awsPairs = entries('awsPairs', _parseAwsPair);
  final sigv4 = _has(obj, 'sigv4')
      ? _parseSigv4(obj['sigv4'], issues, [...path, 'sigv4'])
      : null;
  return CredentialsConfig(
    files: files,
    envVars: envVars,
    allowPlaintextInject: allowPlaintext,
    awsPairs: awsPairs,
    sigv4: sigv4,
  );
});

TlsTerminateConfig? _parseTlsTerminate(
  Object? value,
  List<ConfigIssue> issues,
  List<Object> path,
) {
  final obj = _object(value, path, issues);
  if (obj == null) return null;
  final before = issues.length;
  String? optionalString(String key, {int? min}) => _has(obj, key)
      ? _string(obj[key], [...path, key], issues, min: min)
      : null;
  final caCert = optionalString('caCertPath', min: 1);
  final caKey = optionalString('caKeyPath', min: 1);
  final excludes = _has(obj, 'excludeDomains')
      ? _domainList(obj['excludeDomains'], [...path, 'excludeDomains'], issues)
      : null;
  final extraCa = _has(obj, 'extraCaCertPaths')
      ? _stringList(
          obj['extraCaCertPaths'],
          [...path, 'extraCaCertPaths'],
          issues,
          itemMin: 1,
        )
      : null;
  final maxTunnels = _has(obj, 'maxTunnels')
      ? _number(
          obj['maxTunnels'],
          [...path, 'maxTunnels'],
          issues,
          min: 1,
          max: 65536,
          integer: true,
        )?.toInt()
      : null;
  final handshake = _has(obj, 'handshakeTimeoutMs')
      ? _number(
          obj['handshakeTimeoutMs'],
          [...path, 'handshakeTimeoutMs'],
          issues,
          min: 100,
          max: 600000,
          integer: true,
        )?.toInt()
      : null;
  if (issues.length == before &&
      _has(obj, 'caCertPath') != _has(obj, 'caKeyPath')) {
    _addIssue(
      issues,
      path,
      'caCertPath and caKeyPath must be provided together',
    );
  }
  return TlsTerminateConfig(
    caCertPath: caCert,
    caKeyPath: caKey,
    excludeDomains: excludes,
    extraCaCertPaths: extraCa,
    maxTunnels: maxTunnels,
    handshakeTimeoutMs: handshake,
  );
}

final ConfigSchema<NetworkConfig> NetworkConfigSchema = _notNull((
  value,
  issues,
  path,
) {
  final obj = _object(value, path, issues);
  if (obj == null) return null;
  final allowed = _stringList(
    obj['allowedDomains'],
    [...path, 'allowedDomains'],
    issues,
    itemSchema: _domainPortPatternSchema,
  );
  final denied = _stringList(
    obj['deniedDomains'],
    [...path, 'deniedDomains'],
    issues,
    itemSchema: _deniedDomainPatternSchema,
  );
  Map<String, String>? reasons;
  if (_has(obj, 'deniedDomainReasons')) {
    final raw = _object(obj['deniedDomainReasons'], [
      ...path,
      'deniedDomainReasons',
    ], issues);
    if (raw != null) {
      reasons = {};
      for (final entry in raw.entries) {
        final val = _string(
          entry.value,
          [...path, 'deniedDomainReasons', entry.key],
          issues,
          min: 1,
        );
        if (val != null) reasons[entry.key] = val;
      }
    }
  }
  bool? boolean(String key) =>
      _has(obj, key) ? _boolean(obj[key], [...path, key], issues) : null;
  List<String>? strings(String key, {int min = 0}) => _has(obj, key)
      ? _stringList(obj[key], [...path, key], issues, itemMin: min)
      : null;
  final strict = boolean('strictAllowlist');
  final deniedAddresses = _has(obj, 'deniedResolvedAddresses')
      ? _stringList(
          obj['deniedResolvedAddresses'],
          [...path, 'deniedResolvedAddresses'],
          issues,
          itemSchema: _addressRangeSchema,
        )
      : null;
  final unix = strings('allowUnixSockets');
  final allUnix = boolean('allowAllUnixSockets');
  final localBinding = boolean('allowLocalBinding');
  List<String>? mach;
  if (_has(obj, 'allowMachLookup')) {
    mach = _stringList(obj['allowMachLookup'], [
      ...path,
      'allowMachLookup',
    ], issues);
    if (mach != null) {
      for (var i = 0; i < mach.length; i++) {
        final val = mach[i];
        final prefix = val.endsWith('*')
            ? val.substring(0, val.length - 1)
            : val;
        if (prefix.contains('*'))
          _addIssue(
            issues,
            [...path, 'allowMachLookup', i],
            'Wildcards are only allowed as a single trailing "*" (e.g., "com.example.*" or "*" for all services).',
          );
      }
    }
  }
  int? port(String key) => _has(obj, key)
      ? _number(
          obj[key],
          [...path, key],
          issues,
          min: 1,
          max: 65535,
          integer: true,
        )?.toInt()
      : null;
  final httpPort = port('httpProxyPort');
  final socksPort = port('socksProxyPort');
  final mitm = _has(obj, 'mitmProxy')
      ? _MitmProxyConfigSchema._parser(obj['mitmProxy'], issues, [
          ...path,
          'mitmProxy',
        ])
      : null;
  final rawFilter = _has(obj, 'filterRequest') ? obj['filterRequest'] : null;
  final filter = rawFilter is Function
      ? (request, [info]) async =>
            await Function.apply(rawFilter, [request, info]) as Object?
      : null;
  if (_has(obj, 'filterRequest') && filter == null)
    _addIssue(issues, [
      ...path,
      'filterRequest',
    ], 'filterRequest must be a function');
  final plaintextHeaderSet = boolean('allowPlaintextHeaderSet');
  final stripHeaders = _has(obj, 'stripResponseHeaders')
      ? _stringList(
          obj['stripResponseHeaders'],
          [...path, 'stripResponseHeaders'],
          issues,
          itemMin: 1,
        )
      : null;
  final opaque = boolean('refuseOpaqueTunnels');
  final hostMatch = boolean('requireHostMatch');
  final tls = _has(obj, 'tlsTerminate')
      ? _parseTlsTerminate(obj['tlsTerminate'], issues, [
          ...path,
          'tlsTerminate',
        ])
      : null;
  final parent = _has(obj, 'parentProxy')
      ? _ParentProxyConfigSchema._parser(obj['parentProxy'], issues, [
          ...path,
          'parentProxy',
        ])
      : null;
  if (allowed == null || denied == null) return null;
  return NetworkConfig(
    allowedDomains: allowed,
    deniedDomains: denied,
    deniedDomainReasons: reasons,
    strictAllowlist: strict,
    deniedResolvedAddresses: deniedAddresses,
    allowUnixSockets: unix,
    allowAllUnixSockets: allUnix,
    allowLocalBinding: localBinding,
    allowMachLookup: mach,
    httpProxyPort: httpPort,
    socksProxyPort: socksPort,
    mitmProxy: mitm,
    filterRequest: filter,
    allowPlaintextHeaderSet: plaintextHeaderSet,
    stripResponseHeaders: stripHeaders,
    refuseOpaqueTunnels: opaque,
    requireHostMatch: hostMatch,
    tlsTerminate: tls,
    parentProxy: parent,
  );
});

final ConfigSchema<RipgrepConfig> RipgrepConfigSchema = _notNull((
  value,
  issues,
  path,
) {
  final obj = _object(value, path, issues);
  if (obj == null) return null;
  final command = _string(obj['command'], [...path, 'command'], issues);
  final args = _has(obj, 'args')
      ? _stringList(obj['args'], [...path, 'args'], issues)
      : null;
  final argv0 = _has(obj, 'argv0')
      ? _string(obj['argv0'], [...path, 'argv0'], issues)
      : null;
  return command == null
      ? null
      : RipgrepConfig(command: command, args: args, argv0: argv0);
});

final ConfigSchema<GitConfig> GitConfigSchema = _notNull((value, issues, path) {
  final obj = _object(value, path, issues);
  if (obj == null) return null;
  final directories = _has(obj, 'safeDirectories')
      ? _stringList(obj['safeDirectories'], [
          ...path,
          'safeDirectories',
        ], issues)
      : <String>[];
  return directories == null ? null : GitConfig(safeDirectories: directories);
});

final ConfigSchema<SrtWinConfig> SrtWinConfigSchema = _notNull((
  value,
  issues,
  path,
) {
  final obj = _object(value, path, issues);
  if (obj == null) return null;
  final binary = _string(obj['path'], [...path, 'path'], issues, min: 1);
  return binary == null ? null : SrtWinConfig(path: binary);
});

bool _uuid(String value) => RegExp(
  r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$',
).hasMatch(value);

final ConfigSchema<WindowsConfig> WindowsConfigSchema = _notNull((
  value,
  issues,
  path,
) {
  final obj = _object(value, path, issues);
  if (obj == null) return null;
  final user = _has(obj, 'sandboxUser')
      ? _string(
          obj['sandboxUser'],
          [...path, 'sandboxUser'],
          issues,
          min: 1,
          max: 20,
          maxMessage: 'Windows local usernames are limited to 20 characters',
        )
      : null;
  String? uuidField(String key) {
    if (!_has(obj, key)) return null;
    final val = _string(obj[key], [...path, key], issues);
    if (val != null && !_uuid(val))
      _addIssue(issues, [...path, key], 'Invalid uuid', code: 'invalid_string');
    return val;
  }

  final sublayer = uuidField('sublayerGuid');
  final oldSublayer = uuidField('wfpSublayerGuid');
  (int, int)? range;
  if (_has(obj, 'proxyPortRange')) {
    final raw = _array(obj['proxyPortRange'], [
      ...path,
      'proxyPortRange',
    ], issues);
    if (raw == null || raw.length != 2) {
      if (raw != null)
        _addIssue(
          issues,
          [...path, 'proxyPortRange'],
          'Array must contain 2 element(s)',
          code: 'invalid_tuple',
        );
    } else {
      final lo = _number(
        raw[0],
        [...path, 'proxyPortRange', 0],
        issues,
        min: 1,
        integer: true,
      )?.toInt();
      final hi = _number(
        raw[1],
        [...path, 'proxyPortRange', 1],
        issues,
        max: 65535,
        integer: true,
      )?.toInt();
      if (lo != null && hi != null) {
        range = (lo, hi);
        if (lo > hi || hi - lo > 64)
          _addIssue(issues, [
            ...path,
            'proxyPortRange',
          ], 'low must be ≤ high and range width ≤ 64');
      }
    }
  }
  final srtWin = _has(obj, 'srtWin')
      ? SrtWinConfigSchema._parser(obj['srtWin'], issues, [...path, 'srtWin'])
      : null;
  return WindowsConfig(
    sandboxUser: user,
    sublayerGuid: sublayer,
    wfpSublayerGuid: oldSublayer,
    proxyPortRange: range,
    srtWin: srtWin,
  );
});

final ConfigSchema<SeccompConfig> SeccompConfigSchema = _notNull((
  value,
  issues,
  path,
) {
  final obj = _object(value, path, issues);
  if (obj == null) return null;
  final applyPath = _has(obj, 'applyPath')
      ? _string(obj['applyPath'], [...path, 'applyPath'], issues)
      : null;
  final argv0 = _has(obj, 'argv0')
      ? _string(obj['argv0'], [...path, 'argv0'], issues)
      : null;
  return SeccompConfig(applyPath: applyPath, argv0: argv0);
});

IgnoreViolationsConfig? _parseIgnoreViolations(
  Object? value,
  List<ConfigIssue> issues,
  List<Object> path,
) {
  final obj = _object(value, path, issues);
  if (obj == null) return null;
  final out = <String, List<String>>{};
  for (final entry in obj.entries) {
    final paths = _stringList(entry.value, [...path, entry.key], issues);
    if (paths != null) out[entry.key] = paths;
  }
  return out;
}

final ConfigSchema<IgnoreViolationsConfig> IgnoreViolationsConfigSchema =
    ConfigSchema(_parseIgnoreViolations);

void _addInertSlashedDenyGlobIssue(
  String value,
  List<Object> path,
  List<ConfigIssue> issues,
) {
  final onWindows = getPlatform() == 'windows';
  final trailing = onWindows ? RegExp(r'[\\/]+$') : RegExp(r'/+$');
  if (!trailing.hasMatch(value)) return;
  if (!containsGlobCharsForPlatform(value)) return;
  final rooted = onWindows
      ? node_path.Context(style: node_path.Style.windows).isAbsolute(value)
      : node_path.Context(style: node_path.Style.posix).isAbsolute(value);
  if (!rooted && !value.startsWith('~')) return;
  final spelling = value.replaceFirst(trailing, '');
  _addIssue(
    issues,
    path,
    'Deny glob "$value" ends in a separator, so as a pattern it can match no path. Write "$spelling", which is also read as the path of that name where it exists, or add a "**" segment to match at any depth.',
  );
}

/**
 * Main configuration schema for Sandbox Runtime validation
 */
final ConfigSchema<SandboxRuntimeConfig>
SandboxRuntimeConfigSchema = ConfigSchema((value, issues, path) {
  final obj = _object(value, path, issues);
  if (obj == null) return null;
  final before = issues.length;
  final network = NetworkConfigSchema._parser(obj['network'], issues, [
    ...path,
    'network',
  ]);
  final filesystem = FilesystemConfigSchema._parser(obj['filesystem'], issues, [
    ...path,
    'filesystem',
  ]);
  final credentials = _has(obj, 'credentials')
      ? CredentialsConfigSchema._parser(obj['credentials'], issues, [
          ...path,
          'credentials',
        ])
      : null;
  final ignore = _has(obj, 'ignoreViolations')
      ? _parseIgnoreViolations(obj['ignoreViolations'], issues, [
          ...path,
          'ignoreViolations',
        ])
      : null;
  bool? boolField(String key) =>
      _has(obj, key) ? _boolean(obj[key], [...path, key], issues) : null;
  final weakerNested = boolField('enableWeakerNestedSandbox');
  final weakerNetwork = boolField('enableWeakerNetworkIsolation');
  final appleEvents = boolField('allowAppleEvents');
  final ripgrep = _has(obj, 'ripgrep')
      ? RipgrepConfigSchema._parser(obj['ripgrep'], issues, [
          ...path,
          'ripgrep',
        ])
      : null;
  final searchDepth = _has(obj, 'mandatoryDenySearchDepth')
      ? _number(
          obj['mandatoryDenySearchDepth'],
          [...path, 'mandatoryDenySearchDepth'],
          issues,
          min: 1,
          max: 10,
          integer: true,
        )?.toInt()
      : null;
  final pty = boolField('allowPty');
  final seccomp = _has(obj, 'seccomp')
      ? SeccompConfigSchema._parser(obj['seccomp'], issues, [
          ...path,
          'seccomp',
        ])
      : null;
  String? binary(String key) => _has(obj, key)
      ? _binaryPathSchema._parser(obj[key], issues, [...path, key])
      : null;
  final bwrap = binary('bwrapPath');
  final socat = binary('socatPath');
  final javaAgent = binary('javaAgentJarPath');
  final windows = _has(obj, 'windows')
      ? WindowsConfigSchema._parser(obj['windows'], issues, [
          ...path,
          'windows',
        ])
      : null;
  final git = _has(obj, 'git')
      ? GitConfigSchema._parser(obj['git'], issues, [...path, 'git'])
      : null;
  if (network == null || filesystem == null) return null;
  final config = SandboxRuntimeConfig(
    network: network,
    filesystem: filesystem,
    credentials: credentials,
    ignoreViolations: ignore,
    enableWeakerNestedSandbox: weakerNested,
    enableWeakerNetworkIsolation: weakerNetwork,
    allowAppleEvents: appleEvents,
    ripgrep: ripgrep,
    mandatoryDenySearchDepth: searchDepth,
    allowPty: pty,
    seccomp: seccomp,
    bwrapPath: bwrap,
    socatPath: socat,
    javaAgentJarPath: javaAgent,
    windows: windows,
    git: git,
  );
  if (issues.length != before) return null;

  final fsEnforced = config.filesystem.disabled != true;
  if (fsEnforced) {
    for (var i = 0; i < config.filesystem.denyRead.length; i++) {
      final entry = config.filesystem.denyRead[i];
      if (entry is FilesystemPathSpelling)
        _addInertSlashedDenyGlobIssue(entry.path, [
          ...path,
          'filesystem',
          'denyRead',
          i,
        ], issues);
    }
    for (var i = 0; i < config.filesystem.denyWrite.length; i++) {
      final entry = config.filesystem.denyWrite[i];
      if (entry is FilesystemPathSpelling)
        _addInertSlashedDenyGlobIssue(entry.path, [
          ...path,
          'filesystem',
          'denyWrite',
          i,
        ], issues);
    }
  }
  final creds = config.credentials;
  if (creds == null) return config;
  final allowedHosts = config.network.allowedDomains
      .map(stripDomainPatternPort)
      .toList();
  void checkSubset(List<String> hosts, List<Object> issuePath) {
    for (var i = 0; i < hosts.length; i++) {
      final host = hosts[i];
      if (!isInjectHostCoveredByAllowedDomains(host, allowedHosts)) {
        _addIssue(
          issues,
          [...issuePath, i],
          'injectHosts entry "$host" is not reachable via network.allowedDomains — add "$host" (or a covering wildcard) to allowedDomains, or remove it from injectHosts.',
        );
      }
    }
  }

  var hasMasked = false;
  void checkMaskedEntry(
    String mode,
    List<String>? injectHosts,
    List<Object> issuePath,
  ) {
    if (injectHosts != null)
      checkSubset(injectHosts, [...issuePath, 'injectHosts']);
    if (mode != 'mask') return;
    hasMasked = true;
    final exclude = config.network.tlsTerminate?.excludeDomains;
    if (exclude != null && exclude.isNotEmpty) {
      if (injectHosts != null) {
        for (var i = 0; i < injectHosts.length; i++) {
          final host = injectHosts[i];
          if (isInjectHostCoveredByAllowedDomains(host, exclude)) {
            _addIssue(
              issues,
              [...issuePath, 'injectHosts', i],
              'injectHosts entry "$host" is entirely covered by network.tlsTerminate.excludeDomains. Credential injection only runs on TLS-terminated connections, so this host would receive the placeholder instead of the credential. Remove it from one of the two lists.',
            );
          }
        }
      } else if (allowedHosts.isNotEmpty &&
          allowedHosts.every(
            (host) => isInjectHostCoveredByAllowedDomains(host, exclude),
          )) {
        _addIssue(
          issues,
          issuePath,
          'This masked credential has no injectHosts, so it defaults to network.allowedDomains — but network.tlsTerminate.excludeDomains covers every allowed domain, so it could never be injected anywhere. Credential injection only runs on TLS-terminated connections.',
        );
      }
    }
    if (injectHosts != null && injectHosts.isEmpty) {
      _addIssue(
        issues,
        issuePath,
        'injectHosts is explicitly empty — the credential would be masked but never injected. Omit injectHosts to default to network.allowedDomains, or list the intended hosts.',
      );
    }
  }

  for (
    var i = 0;
    i < (creds.envVars ?? const <CredentialEnvVarConfig>[]).length;
    i++
  ) {
    final entry = creds.envVars![i];
    final issuePath = [...path, 'credentials', 'envVars', i];
    checkMaskedEntry(entry.mode, entry.injectHosts, issuePath);
    if (entry.maskClaims != null && entry.decode == null)
      _addIssue(
        issues,
        [...issuePath, 'maskClaims'],
        'maskClaims requires decode — it names claims inside the decoded payload. Set decode (e.g. "jwt"), or remove maskClaims to mask the whole value.',
      );
    if (entry.maskClaims != null && entry.maskClaims!.isEmpty)
      _addIssue(
        issues,
        [...issuePath, 'maskClaims'],
        'maskClaims is explicitly empty — no claim would ever be masked. Omit maskClaims to mask the whole token, or list the claims to protect.',
      );
  }
  for (
    var i = 0;
    i < (creds.files ?? const <CredentialFileConfig>[]).length;
    i++
  ) {
    final entry = creds.files![i];
    final issuePath = [...path, 'credentials', 'files', i];
    checkMaskedEntry(entry.mode, entry.injectHosts, issuePath);
    if (entry.maskClaims != null && entry.decode == null)
      _addIssue(
        issues,
        [...issuePath, 'maskClaims'],
        'maskClaims requires decode — it names claims inside the decoded payload. Set decode (e.g. "jwt"), or remove maskClaims to mask the extracted value whole.',
      );
    if (entry.maskClaims != null && entry.maskClaims!.isEmpty)
      _addIssue(
        issues,
        [...issuePath, 'maskClaims'],
        'maskClaims is explicitly empty — no claim would ever be masked. Omit maskClaims to mask the whole token, or list the claims to protect.',
      );
    if (entry.mode == 'mask' && entry.path.endsWith('/'))
      _addIssue(
        issues,
        [...issuePath, 'path'],
        'Credential mode "mask" applies to a single file, not a directory. Use mode "deny" for "${entry.path}", or point at the credential file inside it.',
      );
    if (fsEnforced && entry.mode == 'deny')
      _addInertSlashedDenyGlobIssue(entry.path, [...issuePath, 'path'], issues);
  }
  final seenPairVars = <String>{};
  for (var i = 0; i < (creds.awsPairs ?? const <AwsPairConfig>[]).length; i++) {
    final pair = creds.awsPairs![i];
    final vars = <(String, String)>[
      ('accessKeyIdVar', pair.accessKeyIdVar),
      ('secretAccessKeyVar', pair.secretAccessKeyVar),
    ];
    if (pair.sessionTokenVar != null)
      vars.add(('sessionTokenVar', pair.sessionTokenVar!));
    for (final (field, name) in vars) {
      final issuePath = [...path, 'credentials', 'awsPairs', i, field];
      if (!seenPairVars.add(name)) {
        _addIssue(
          issues,
          issuePath,
          '"$name" appears in more than one awsPairs slot (within or across pairs) — each variable can fill exactly one slot.',
        );
        continue;
      }
      CredentialEnvVarConfig? entry;
      for (final candidate
          in creds.envVars ?? const <CredentialEnvVarConfig>[]) {
        if (candidate.name == name) {
          entry = candidate;
          break;
        }
      }
      if (entry == null || entry.mode != 'mask') {
        _addIssue(
          issues,
          issuePath,
          '"$name" does not reference a credentials.envVars entry with mode "mask" — an AWS pair links already-masked variables; add the entry (masking is the opt-in for SigV4 re-signing).',
        );
      } else if (entry.extract != null || entry.decode != null) {
        _addIssue(
          issues,
          issuePath,
          '"$name" uses extract/decode, but an AWS pair member must be masked whole-value: the SigV4 trigger is an exact match of the fake access key id, and the signer needs the entire real value.',
        );
      }
    }
  }
  if (hasMasked &&
      config.network.tlsTerminate == null &&
      creds.allowPlaintextInject != true) {
    _addIssue(
      issues,
      [...path, 'credentials'],
      'Credential masking requires network.tlsTerminate so substitution runs only over a verified TLS connection. Enable tlsTerminate, or set credentials.allowPlaintextInject to opt out (not recommended).',
    );
  }
  return config;
});
