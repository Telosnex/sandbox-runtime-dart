// Ported from sandbox-runtime src/sandbox/sandbox-config.ts @ 24eb39e.
// ignore_for_file: constant_identifier_names, dangling_library_doc_comments
// ignore_for_file: slash_for_doc_comments, curly_braces_in_flow_control_structures
// ignore_for_file: prefer_interpolation_to_compose_strings, non_constant_identifier_names
// ignore_for_file: doc_directive_unknown, unintended_html_in_doc_comment

import 'package:path/path.dart' as node_path;

import '../utils/platform.dart';
import 'address.dart';
import 'domain_pattern.dart';
import 'request_filter.dart';
import 'sandbox_utils.dart';

// The 'zod/v3' subpath, not bare 'zod': it exists from zod 3.25 on and is the
// v3 API under both zod 3.25+ and zod 4. Where a consumer's dependency tree
// resolves this package's zod to version 4, the bare import would hand these
// schemas the v4 API they are not written against.

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

/// zod `.strict()`: one issue at the object's path naming every unknown key,
/// added after the object's own properties are checked.
void _unrecognizedKeys(
  Map<Object?, Object?> obj,
  Set<String> known,
  List<ConfigIssue> issues,
  List<Object> path,
) {
  final unknown = obj.keys.where((key) => !known.contains(key)).toList();
  if (unknown.isEmpty) return;
  _addIssue(
    issues,
    path,
    "Unrecognized key(s) in object: '${unknown.join("', '")}'",
    code: 'unrecognized_keys',
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

/**
 * Schema for filesystem paths
 */
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

/**
 * Schema for an absolute path to an external binary.
 * Relative paths are rejected to prevent PATH/CWD-based hijacking — these
 * overrides are intended for admin-managed installs at fixed locations.
 */
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

/**
 * Schema for MITM proxy configuration
 * Allows routing specific domains through an upstream MITM proxy via Unix socket
 */
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

/**
 * Schema for upstream/parent HTTP proxy configuration.
 * Used when SRT itself runs behind a corporate proxy and cannot make direct
 * outbound connections.
 */
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

/**
 * Schema for the access mode of a declared credential source.
 *
 * - `deny` — the sandboxed process cannot read the file / does not see the
 *   environment variable.
 * - `mask` — the sandboxed process sees a per-session sentinel value; the
 *   host proxy substitutes sentinel→real on egress to `injectHosts`.
 *   For files this is whole-file masking (Linux only; degrades to `deny`
 *   on macOS and Windows — see {@link CredentialFileConfigSchema}).
 */
final ConfigSchema<CredentialMode> _credentialModeSchema = ConfigSchema(
  (value, issues, path) => _enumValue(value, path, issues, CREDENTIAL_MODES),
);

/**
 * Schema for an environment variable name. Restricted to POSIX identifiers so
 * the name can never be parsed as a flag by `env -u` (macOS) or bwrap
 * `--unsetenv` (Linux).
 */
final ConfigSchema<String> _envVarNameSchema = ConfigSchema(
  (value, issues, path) => _string(
    value,
    path,
    issues,
    regex: RegExp(r'^[A-Za-z_][A-Za-z0-9_]*$'),
    regexMessage:
        'Environment variable name must start with a letter or underscore and contain only letters, digits, and underscores',
  ),
);

/**
 * Schema for the optional structured-extraction regex on a masked file.
 *
 * Validates that the string compiles as a JavaScript RegExp and declares at
 * least one capturing group — capture group 1 is the contract for "the
 * credential value to mask". A pattern with zero groups would silently mask
 * nothing useful, so it is rejected at config time rather than at runtime.
 *
 * Group count is determined by appending `|` (alternation with empty) and
 * matching the empty string: the result array length is `1 + groupCount`,
 * which counts capturing groups (including named ones) and ignores
 * non-capturing `(?:…)`.
 */
final ConfigSchema<String> _extractPatternSchema = ConfigSchema(
  (value, issues, path) => _parseExtract(value, path, issues),
);

/**
 * Schema for a single credential file/directory entry.
 *
 * `mode: "mask"` without `extract` is **whole-file** masking: the entire
 * file content is replaced inside the sandbox with one sentinel string,
 * and the proxy substitutes that sentinel back to the real bytes on egress.
 * This works for files whose content *is* the credential (a token file, a
 * single-line secret).
 *
 * `mode: "mask"` with `extract` is **structured** masking: the regex is
 * applied globally to the real file, capture group 1 of each match is a
 * credential value, and only those captured spans are replaced with
 * sentinels — the rest of the file is preserved byte-for-byte. This lets a
 * tool that parses the file (`.netrc`, JSON/YAML configs) still succeed
 * inside the sandbox while the credential values are protected. If the
 * pattern matches nothing, behaviour is governed by `onExtractNoMatch`
 * (default `"warn"` — the file is left readable as-is and a stderr
 * warning is emitted).
 *
 * `mode: "mask"` with `decode: "jwt"` extends structured masking into
 * encoded values: where `extract` opens plain text to mask a span inside
 * it, `decode` opens the encoding so masking can target fields inside the
 * decoded payload (`maskClaims`):
 *
 * - **Default pattern**: when `extract` is absent, a built-in JWT regex is
 *   used (every JWT starts `eyJ` — base64url of `{"`), so authors don't
 *   hand-write it. An explicit `extract` wins; its group-1 captures are the
 *   candidates.
 * - **Decode-verification**: each candidate must actually BE a JWT (three
 *   segments, JSON header/payload, `alg` in the header) before it is
 *   masked; candidates failing verification are left untouched.
 * - **Claim-level masking** (`maskClaims`): each named top-level payload
 *   claim present with a string value is replaced by its own sentinel and
 *   the token is rebuilt around the modified payload (original header,
 *   filler signature). All other claims stay real, so a client that
 *   decodes the token and reads a non-secret claim keeps working. The
 *   proxy substitutes both the whole rebuilt token (sent as a bearer
 *   credential) and each claim sentinel (extracted and sent alone).
 * - **Whole-token fallback** (no `maskClaims`): the whole decoded value is
 *   treated as the credential — for bearer-style usage where the token
 *   itself is the secret — and replaced with a structurally valid fake JWT
 *   (parseable header/payload, far-future `exp`), so client-side token
 *   parsing inside the sandbox doesn't break. Its header declares
 *   `alg: HS256` (not `alg: none`, which misconfigured validators accept)
 *   with a garbage signature, so any validator the unswapped fake reaches
 *   rejects it.
 * - **No verified candidate**: if nothing matches, no candidate verifies,
 *   or (with `maskClaims`) no named claim matches in any verified token,
 *   behaviour is governed by `onExtractNoMatch` — same as a non-matching
 *   `extract` (default `"warn"`: stderr warning, file left readable
 *   as-is).
 *
 * `maskDuplicates: true` (only meaningful with `extract` or `decode`)
 * additionally replaces every verbatim occurrence of each masked value
 * *outside* the regex-matched spans — for a secret repeated where the
 * regex does not reach (e.g. pasted into a comment). The scan is raw
 * substring matching, so a short or common captured value may also hit
 * unrelated content that happens to contain it; intended for long,
 * high-entropy secrets. Composed with `decode`, only captures that passed
 * verification are scanned — a duplicate is the same value and reuses the
 * verified capture's fake without re-verification.
 *
 * On macOS, SBPL cannot redirect reads, so `mode: "mask"` (with or without
 * `extract`/`decode`) currently degrades to `mode: "deny"` (the file is
 * unreadable inside the sandbox). Nor can an ACL, so on Windows it does too.
 */
final ConfigSchema<CredentialFileConfig> CredentialFileConfigSchema =
    ConfigSchema(_parseCredentialFile);

/**
 * Schema for a single credential environment variable entry.
 *
 * `mode: "mask"` replaces the variable's value inside the sandbox with a
 * per-session sentinel; the proxy substitutes sentinel→real on egress to
 * the credential's injectHosts. A masked var that is unset on the host is
 * skipped — there is nothing to protect.
 *
 * `mode: "mask"` without `extract` is **whole-value** masking: the entire
 * value is replaced inside the sandbox with one sentinel string, and the
 * proxy substitutes that sentinel back to the real value on egress. This
 * works for variables whose value *is* the credential (a bare token).
 *
 * `mode: "mask"` with `extract` is **structured** masking: the regex is
 * applied globally to the real value, capture group 1 of each match is a
 * credential value, and only those captured spans are replaced with
 * sentinels — the rest of the value is preserved byte-for-byte. This lets
 * a tool that parses the value (a `DATABASE_URL` connection string, a
 * composite `KEY:SECRET` pair) still succeed inside the sandbox while the
 * credential spans are protected. If the pattern matches nothing,
 * behaviour is governed by `onExtractNoMatch` (default `"warn"` — the
 * variable passes through unmasked and a stderr warning is emitted).
 *
 * `mode: "mask"` with `decode: "jwt"` handles a variable whose whole value
 * is a JWT (CI OIDC tokens, Supabase keys, ...). `decode` opens the encoded
 * value for masking: without claim-level configuration the entire token is
 * replaced by a structurally valid fake JWT — parseable three-segment shape
 * with JSON header/payload and far-future `exp`, so a tool that inspects
 * the token before sending it (segment count, exp, claims) keeps working.
 * The fake's header declares `alg: HS256` — never `alg: none`, which
 * misconfigured validators accept — with a filler signature, so a verifier
 * the unswapped fake ever reaches rejects it cryptographically. The proxy
 * swaps the whole fake token for the real one on egress.
 *
 * `decode: "jwt"` with `maskClaims` masks at the claim level instead: each
 * named top-level payload claim present with a string value is replaced by
 * its own sentinel and the token is rebuilt around the modified payload
 * (original header segment, filler signature). All other claims stay real,
 * so a client that decodes the token and reads a non-secret claim keeps
 * working. The proxy substitutes both the whole rebuilt token (sent as a
 * bearer credential) and each claim sentinel (extracted and sent alone).
 *
 * If the variable is set but its value does not verify as a JWT — or, with
 * `maskClaims`, no named claim is present as a string — nothing was masked:
 * the entry currently fails open — the real value stays in the sandbox
 * environment and a loud stderr warning names the variable.
 */
final ConfigSchema<CredentialEnvVarConfig> CredentialEnvVarConfigSchema =
    ConfigSchema(_parseCredentialEnvVar);

/**
 * Explicit grouping of masked env vars into an AWS credential pair for
 * SigV4 re-signing.
 *
 * A SigV4 signature is an HMAC derived from the secret access key, so a
 * client signing with a masked (fake) secret produces a signature no
 * substitution can repair — the proxy must re-sign with the real secret.
 * Re-signing needs the access key id, secret, and optional session token
 * *linked* as one credential: this entry names the `credentials.envVars`
 * entries (all `mode: "mask"`, whole-value — no `extract`/`decode`) that
 * hold each part.
 *
 * The conventional trio AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY /
 * AWS_SESSION_TOKEN is paired automatically when those vars are masked
 * whole-value and no explicit awsPairs entry references them — this
 * config exists for non-standard variable names.
 *
 * Re-signing triggers only on requests whose signature scope references
 * the pair's fake access key id (exact match); everything else — including
 * requests signed with real, unmasked AWS credentials — is untouched. The
 * substitution gate is the access-key-id entry's `injectHosts` (defaulting
 * to network.allowedDomains); the secret/session-token entries' own
 * injectHosts are not consulted for re-signing.
 */
final ConfigSchema<AwsPairConfig> AwsPairConfigSchema = ConfigSchema(
  _parseAwsPair,
);

final ConfigSchema<Sigv4Policy> _sigv4PolicySchema = ConfigSchema(
  (value, issues, path) => _enumValue(value, path, issues, SIGV4_POLICY_VALUES),
);

/**
 * Per-shape policy for AWS SigV4 request forms the proxy cannot re-sign.
 * Applies only to requests whose signature references a masked pair's
 * fake access key id; requests signed with unmasked credentials are never
 * affected.
 *
 * - `"deny"` (default): fail closed with a 403 naming the case, so the
 *   sandboxed client sees a policy block instead of a confusing upstream
 *   signature error.
 * - `"passthrough"`: forward the request without re-signing. Ordinary
 *   header substitution still applies, but the signature was computed
 *   from the masked placeholder secret, so the upstream will reject it —
 *   set this only when that failure mode is preferable to a proxy denial.
 *
 * Re-signable header-SigV4 requests that sign a literal body hash are
 * buffered (up to 64 MiB — MAX_SIGV4_RESIGN_BODY_BYTES in
 * tls-terminate-proxy.ts) so the hash can be recomputed over the bytes
 * actually forwarded; larger bodies are denied with a 403. Payloads
 * signed as UNSIGNED-PAYLOAD stream through without buffering.
 */
final ConfigSchema<Sigv4Config> Sigv4ConfigSchema = ConfigSchema(_parseSigv4);

/**
 * Credentials configuration schema for validation.
 *
 * Declares credential sources (files and environment variables) with a
 * per-source mode; see {@link credentialModeSchema} for what each mode does.
 *
 * Only the sources declared here are affected; the section applies no
 * implicit restrictions beyond them.
 */
// Reject unknown keys so a stale `credentials.injectHosts` (the removed
// block-level default) fails loudly instead of being silently stripped.
final ConfigSchema<CredentialsConfig> CredentialsConfigSchema = _notNull((
  value,
  issues,
  path,
) {
  final obj = _object(value, path, issues);
  if (obj == null) return null;
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
  _unrecognizedKeys(
    obj,
    const {'files', 'envVars', 'allowPlaintextInject', 'awsPairs', 'sigv4'},
    issues,
    path,
  );
  return CredentialsConfig(
    files: files,
    envVars: envVars,
    allowPlaintextInject: allowPlaintext,
    awsPairs: awsPairs,
    sigv4: sigv4,
  );
});

/**
 * Network configuration schema for validation
 */
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

/**
 * Filesystem configuration schema for validation
 */
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

/**
 * Configuration schema for ignoring specific sandbox violations
 * Maps command patterns to filesystem paths to ignore violations for.
 */
final ConfigSchema<IgnoreViolationsConfig> IgnoreViolationsConfigSchema =
    ConfigSchema(_parseIgnoreViolations);

/**
 * Ripgrep configuration schema
 */
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

/**
 * Git configuration schema (cross-platform). Injected via
 * `GIT_CONFIG_COUNT` / `GIT_CONFIG_KEY_<n>` / `GIT_CONFIG_VALUE_<n>`
 * env vars — see `buildGitConfigEnv` in `sandbox-utils.ts`.
 */
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

/**
 * Configuration for locating/invoking the `srt-win` helper (Windows
 * only). An embedder that links `srt-win`'s CLI into its own
 * multicall binary points `path` at that binary; spawns then pass
 * `--srt-win` as `argv[1]` (see `SRT_WIN_DISPATCH_ARG1` in
 * `windows-sandbox-utils.ts` / `srt_win::SRT_WIN_DISPATCH_ARG1`) so
 * the embedder's dispatcher can route to `srt_win::run_from_args`.
 * Windows cannot reliably preserve a spoofed `argv[0]` across
 * `CreateProcessWithLogonW` / `ShellExecuteExW(runas)`, so dispatch
 * keys on `argv[1]`, not on `argv[0]` like
 * {@link SeccompConfigSchema} does on Linux.
 */
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

/**
 * Windows-specific configuration schema. See
 * `windows-sandbox-utils.ts` for the install flow these settings
 * must agree with.
 *
 * Canonical: `sublayerGuid`; the `wfpSublayerGuid` alias is resolved
 * at read sites (`sublayerGuid ?? wfpSublayerGuid`) rather than via
 * `.transform()` so this stays a plain `ZodObject` for consumers that
 * `.extend()`/`.shape` it.
 */
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

/**
 * Seccomp configuration schema (Linux only)
 */
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
  final mode = _credentialModeSchema._parser(obj['mode'], issues, [
    ...path,
    'mode',
  ]);
  final extract = _has(obj, 'extract')
      ? _extractPatternSchema._parser(obj['extract'], issues, [
          ...path,
          'extract',
        ])
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
  final name = _envVarNameSchema._parser(obj['name'], issues, [
    ...path,
    'name',
  ]);
  final mode = _credentialModeSchema._parser(obj['mode'], issues, [
    ...path,
    'mode',
  ]);
  final extract = _has(obj, 'extract')
      ? _extractPatternSchema._parser(obj['extract'], issues, [
          ...path,
          'extract',
        ])
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

AwsPairConfig? _parseAwsPair(
  Object? value,
  List<ConfigIssue> issues,
  List<Object> path,
) {
  final obj = _object(value, path, issues);
  if (obj == null) return null;
  final before = issues.length;
  String? envName(String key) =>
      _envVarNameSchema._parser(obj[key], issues, [...path, key]);
  final access = envName('accessKeyIdVar');
  final secret = envName('secretAccessKeyVar');
  final session = _has(obj, 'sessionTokenVar')
      ? envName('sessionTokenVar')
      : null;
  final valid = access != null && secret != null && issues.length == before;
  // Unknown keys leave zod's result dirty, not aborted: the credentials
  // refinement still sees the pair.
  _unrecognizedKeys(
    obj,
    const {'accessKeyIdVar', 'secretAccessKeyVar', 'sessionTokenVar'},
    issues,
    path,
  );
  if (!valid) return null;
  return AwsPairConfig(
    accessKeyIdVar: access,
    secretAccessKeyVar: secret,
    sessionTokenVar: session,
  );
}

Sigv4Config? _parseSigv4(
  Object? value,
  List<ConfigIssue> issues,
  List<Object> path,
) {
  final obj = _object(value, path, issues);
  if (obj == null) return null;
  final streaming = _has(obj, 'streaming')
      ? _sigv4PolicySchema._parser(obj['streaming'], issues, [
          ...path,
          'streaming',
        ])
      : null;
  final presigned = _has(obj, 'presigned')
      ? _sigv4PolicySchema._parser(obj['presigned'], issues, [
          ...path,
          'presigned',
        ])
      : null;
  final sigv4a = _has(obj, 'sigv4a')
      ? _sigv4PolicySchema._parser(obj['sigv4a'], issues, [...path, 'sigv4a'])
      : null;
  _unrecognizedKeys(
    obj,
    const {'streaming', 'presigned', 'sigv4a'},
    issues,
    path,
  );
  return Sigv4Config(
    streaming: streaming,
    presigned: presigned,
    sigv4a: sigv4a,
  );
}

ConfigSchema<T> _notNull<T>(
  T? Function(Object?, List<ConfigIssue>, List<Object>) parser,
) => ConfigSchema(parser);

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

bool _uuid(String value) => RegExp(
  r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$',
).hasMatch(value);

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

/**
 * An inert deny is fail-open, so a deny glob whose trailing separator leaves
 * it matching nothing is rejected; the same glob as an allow fails closed,
 * so the allow lists keep the plain path schema. Such an entry may also be
 * the name of a path (`/w/[WIP]/keep/`), but only the disk can say so and
 * validation does not ask it: the message gives the spelling read both ways.
 */
void _addInertSlashedDenyGlobIssue(
  String value,
  List<Object> path,
  List<ConfigIssue> issues,
) {
  final onWindows = getPlatform() == 'windows';
  final trailing = onWindows ? RegExp(r'[\\/]+$') : RegExp(r'/+$');
  if (!trailing.hasMatch(value)) return;
  if (!containsGlobCharsForPlatform(value)) return;
  // Only absolute and `~`-rooted spellings reach a backend with the
  // separator still attached: normalizePathForSandbox resolves a relative
  // spelling through path.resolve, which drops it, so `build/*/` is live.
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

  // filesystem.disabled drops every filesystem rule, the credential file
  // denies included (getFsReadConfig, getFsWriteConfig and
  // computeWindowsFsAccessSet all short-circuit on it), so an inert deny
  // under it is not a hole.
  final fsEnforced = config.filesystem.disabled != true;
  if (fsEnforced) {
    // A marked entry is never a glob, so a separator at its end is the
    // end of a name.
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
  // Every per-entry injectHosts pattern must be reachable via
  // allowedDomains — semantic (wildcard-aware) coverage, not literal
  // string membership, so `injectHosts: ['api.github.com']` is accepted
  // when `allowedDomains: ['*.github.com']`.
  // Host-scoped view of the allowlist (":port" suffixes dropped) —
  // injection is per-host, not per-port.
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

  // Per-credential checks. Substitution is gated per sentinel; an entry
  // with no injectHosts defaults to network.allowedDomains (every
  // reachable host), so absence is fine. An *explicit* empty list is
  // rejected — "mask but never inject" is self-contradictory and almost
  // certainly a config mistake. Applies to both env vars and files.
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
    // Credential substitution only runs on the TLS-terminated path, so a
    // host covered by tlsTerminate.excludeDomains can never receive the
    // real value — the upstream sees the placeholder. Reject the
    // spellings that are *entirely* self-contradictory:
    //   - an explicit injectHosts entry whose every concrete host is
    //     excluded (isInjectHostCoveredByAllowedDomains is the generic
    //     "pattern fully covered by pattern list" predicate);
    //   - no injectHosts (= every allowedDomain) while excludeDomains
    //     covers all of allowedDomains, i.e. injection could never
    //     happen anywhere.
    // A *partial* overlap is legitimate (excluded hosts simply don't get
    // the credential) and is reported at runtime instead.
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
    // maskClaims names fields inside a decoded payload; without decode
    // there is no payload to look inside — reject the contradiction
    // loudly rather than silently masking nothing.
    if (entry.maskClaims != null && entry.decode == null)
      _addIssue(
        issues,
        [...issuePath, 'maskClaims'],
        'maskClaims requires decode — it names claims inside the decoded payload. Set decode (e.g. "jwt"), or remove maskClaims to mask the whole value.',
      );
    // Same posture as an explicitly empty injectHosts: "decode but mask
    // no claims" is self-contradictory and almost certainly a mistake.
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
    // maskClaims names fields inside a decoded payload; without decode
    // there is no payload to look inside — reject the contradiction
    // loudly rather than silently masking nothing.
    if (entry.maskClaims != null && entry.decode == null)
      _addIssue(
        issues,
        [...issuePath, 'maskClaims'],
        'maskClaims requires decode — it names claims inside the decoded payload. Set decode (e.g. "jwt"), or remove maskClaims to mask the extracted value whole.',
      );
    // Same posture as an explicitly empty injectHosts: "decode but mask
    // no claims" is self-contradictory and almost certainly a mistake.
    if (entry.maskClaims != null && entry.maskClaims!.isEmpty)
      _addIssue(
        issues,
        [...issuePath, 'maskClaims'],
        'maskClaims is explicitly empty — no claim would ever be masked. Omit maskClaims to mask the whole token, or list the claims to protect.',
      );
    // Whole-file masking replaces one file's bytes with one sentinel;
    // a directory has no single content to mask. The hard check is at
    // runtime (stat after path normalization) — this catches the obvious
    // syntactic case (trailing slash) early with a clearer error.
    if (entry.mode == 'mask' && entry.path.endsWith('/'))
      _addIssue(
        issues,
        [...issuePath, 'path'],
        'Credential mode "mask" applies to a single file, not a directory. Use mode "deny" for "${entry.path}", or point at the credential file inside it.',
      );
    // A `mode: 'deny'` path is unioned into the read-deny set and takes
    // the same glob branches as filesystem.denyRead.
    if (fsEnforced && entry.mode == 'deny')
      _addInertSlashedDenyGlobIssue(entry.path, [...issuePath, 'path'], issues);
  }
  // awsPairs entries must reference whole-value masked env vars: the
  // re-signer needs the fake value to BE the sentinel (exact-match
  // trigger on the access key id in the credential scope) and the real
  // value to be the entire secret. extract/decode entries violate both.
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
  // Masked credentials require the TLS-terminated proxy path so the real
  // value is only sent to a cert-verified upstream. allowPlaintextInject
  // is the explicit escape hatch.
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

// Export inferred types
class MitmProxyConfig {
  /// Unix socket path to the MITM proxy
  final String socketPath;

  /// Domains to route through the MITM proxy (e.g., ["api.example.com", "*.internal.org"])
  final List<String> domains;
  const MitmProxyConfig({required this.socketPath, required this.domains});
}

class ParentProxyConfig {
  /// Upstream proxy URL for plain HTTP traffic
  final String? http;

  /// Upstream proxy URL for HTTPS/CONNECT traffic (falls back to http if unset)
  final String? https;

  /// Comma-separated NO_PROXY list (hostname suffixes and CIDR ranges). Matching destinations connect directly instead of via the parent proxy.
  final String? noProxy;
  const ParentProxyConfig({this.http, this.https, this.noProxy});
}

class TlsTerminateConfig {
  /// Path to a PEM-encoded CA certificate. The sandboxed child is configured to trust this CA, and the TLS-terminating proxy uses it to sign per-host certificates. If omitted, on Windows SRT generates-if-absent a persistent CA under %ProgramData%\sandbox-runtime\ca\ and trusts it in the sandbox user's Root store; on other platforms SRT generates an ephemeral CA into a temp directory for the lifetime of the session.
  final String? caCertPath;

  /// Path to the PEM-encoded private key for caCertPath.
  final String? caKeyPath;

  /// Domain patterns (same syntax as allowedDomains) whose HTTPS connections are NOT terminated. Matching CONNECTs are opaque byte tunnels: still subject to the allow/deny domain lists, but the sandboxed client completes its own TLS handshake with the upstream, so filterRequest and credential injection do not apply to their HTTPS traffic (plain-HTTP requests to the same hosts keep the normal request pipeline). Use for hosts the proxy must not re-originate: mTLS upstreams (only the client holds the client certificate) and clients that pin the upstream certificate and would reject the MITM CA. Hosts still need to be reachable via allowedDomains; this list only changes how they are tunnelled.
  final List<String>? excludeDomains;

  /// Paths to PEM CA certificate files appended to the trust bundle the sandboxed child is pointed at, after the MITM CA and the host's regular roots. Use for site-local roots (e.g. an internal mTLS CA) presented by excluded/passthrough hosts, so the child can verify them itself. Only the CERTIFICATE blocks of each file are copied; files that are missing, unreadable, or contain no PEM CERTIFICATE block are skipped (with a debug log), so paths that exist on only some hosts are safe to list.
  final List<String>? extraCaCertPaths;

  /// At most this many CONNECT tunnels are TLS-terminated at once (default 256); past it a CONNECT is answered 503 with "X-Proxy-Error: too-many-tunnels". A tunnel holds its slot from its CONNECT until it closes, so idle keep-alive tunnels count; one that turns out not to carry TLS frees it. The slot is taken before the first bytes are seen, so at the cap a non-TLS CONNECT (SSH, say) to a host that would be terminated is refused too. Hosts in excludeDomains do not count. Read when the proxy starts; updateConfig does not change it.
  final int? maxTunnels;

  /// A tunnel to be TLS-terminated must finish its TLS handshake within this many milliseconds of its CONNECT (default 10000), or it is closed and its slot freed. A tunnel past its handshake is never timed out by it. Read when the proxy starts; updateConfig does not change it.
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
  /// List of allowed domains (e.g., ["github.com", "*.npmjs.org", "api.example.com:443"]). An optional ":port" suffix restricts the entry to that destination port.
  final List<String> allowedDomains;

  /// List of denied domains. Unlike allowedDomains, a bare "*" is accepted here (deny-all). An optional ":port" suffix (e.g., "*:22") restricts the entry to that destination port.
  final List<String> deniedDomains;

  /// Optional model-facing reason keyed by the exact deniedDomains entry it explains (e.g., {"github.com:22": "SSH pushes to GitHub are blocked; use an https remote"}). Reported in the <sandbox_violations> line when that entry denies a connection, and to the sandboxed client as the status phrase of the 403 that answers its CONNECT; entries without one use a generic reason. Keys are matched by exact entry string, so a key with no matching deniedDomains entry never fires.
  final Map<String, String>? deniedDomainReasons;

  /// If true, hosts not in allowedDomains are denied without consulting the ask callback, and a per-command allow list (registerCommandNetworkLists) is ignored. Set this when allowedDomains is policy enforcement, not a prompt-suppression hint.
  final bool? strictAllowlist;

  /// IP addresses / CIDR ranges (IPv4 or IPv6, unbracketed) that an allowed HOSTNAME must not resolve to, in addition to the built-in set (see README "Resolved-address check") and any IP literal listed in deniedDomains. A permitted name that resolves only into these is refused instead of dialed. A name may resolve to a denied address only if that IP literal (and port) is itself in allowedDomains. Not evaluated for connections routed through parentProxy (including one taken from HTTP_PROXY/HTTPS_PROXY) or mitmProxy (that hop resolves the name).
  final List<String>? deniedResolvedAddresses;

  /// macOS only: Unix socket paths to allow. Ignored on Linux (seccomp cannot filter by path).
  final List<String>? allowUnixSockets;

  /// If true, allow all Unix sockets (disables blocking on both platforms). On Linux this also unblocks VM sockets (AF_VSOCK).
  final bool? allowAllUnixSockets;

  /// Whether to allow binding to local ports (default: false)
  final bool? allowLocalBinding;

  /// macOS only: Additional XPC/Mach service names to allow looking up. Supports trailing-wildcard prefix matching (e.g., "2BUA8C4S2C.com.1password.*"). Needed for tools like 1Password CLI, Playwright, or the iOS Simulator that communicate via XPC.
  final List<String>? allowMachLookup;

  /// Port of an external HTTP proxy to use instead of starting a local one. When provided, the library will skip starting its own HTTP proxy and use this port. The external proxy must handle domain filtering.
  final int? httpProxyPort;

  /// Port of an external SOCKS proxy to use instead of starting a local one. When provided, the library will skip starting its own SOCKS proxy and use this port. The external proxy must handle domain filtering.
  final int? socksProxyPort;

  /// Optional MITM proxy configuration. Routes matching domains through an upstream proxy via Unix socket while SRT still handles allow/deny filtering.
  final MitmProxyConfig? mitmProxy;

  /// Per-request filter callback. Receives the parsed HTTP request (web-standard Request) and request details, and returns {action, reason?, status?} or, for an allow, header edits (removeHeaders, setHeaders) and an onResponse observer. Denied requests get the status (403 by default) with the reason. If the callback throws, the request is denied. Applies to plain HTTP through the proxy and, when tlsTerminate is configured, to terminated HTTPS. SRT does not provide a policy language; library consumers own matching. This and the four options after it are read when the proxy starts; updateConfig does not change them.
  final FilterRequestCallback? filterRequest;

  /// Let a filterRequest allow set headers on plain-HTTP requests. Off by default: a header set there travels in cleartext, so while it is off an allow that carries setHeaders is refused with 403 for every request the proxy receives in cleartext, an absolute https:// URI included. An allow without setHeaders is unaffected and removals always apply.
  final bool? allowPlaintextHeaderSet;

  /// Response headers never passed back to the sandboxed client, matched case-insensitively with "-", "_" and "." folded (e.g. ["set-cookie"]).
  final List<String>? stripResponseHeaders;

  /// Refuse every tunnel filterRequest cannot see into: an HTTP CONNECT that would not be TLS-terminated or carries no TLS, and every SOCKS CONNECT (refused at the handshake). Requires tlsTerminate to serve HTTPS at all, and stops CONNECT-carried SSH such as GIT_SSH_COMMAND through the proxy. Refusals are recorded as violations.
  final bool? refuseOpaqueTunnels;

  /// Answer 421 to a request whose Host header, TLS server name or absolute-form authority does not name the host and port it is sent to, before filterRequest is asked. Refusals are recorded as violations.
  final bool? requireHostMatch;

  /// [EXPERIMENTAL] Enable in-process TLS termination so HTTPS request/response bodies are visible to SRT. Provide a CA cert+key, or omit both to have SRT generate an ephemeral one. Needs Node, or Bun 1.4 or later: SandboxManager.initialize throws on an older runtime.
  final TlsTerminateConfig? tlsTerminate;

  /// Upstream HTTP proxy for outbound connections. When set, SRT's proxy tunnels non-mitmProxy traffic through this parent instead of connecting directly. Falls back to HTTP_PROXY/HTTPS_PROXY/NO_PROXY env vars if unset.
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
  /// Disable all filesystem policy enforcement. When true, no read or write rules are emitted: denyRead/allowRead/allowWrite/denyWrite are ignored, and the built-in mandatory write protections (.git/hooks, .git/config, shell rc files, .mcp.json, .vscode/.idea, .claude/commands, .claude/agents) are NOT applied. Use only when the sandboxed process is trusted with full host filesystem access. Network and credential-env restrictions still apply. On Linux, /dev is still replaced by the bwrap minimal devtmpfs.
  final bool? disabled;

  /// Paths denied for reading
  final List<FilesystemPathEntry> denyRead;

  /// Paths to re-allow reading within denied regions (takes precedence over denyRead). Use with denyRead to deny a broad region then allow back specific subdirectories.
  final List<FilesystemPathEntry>? allowRead;

  /// Paths allowed for writing
  final List<FilesystemPathEntry> allowWrite;

  /// Paths denied for writing (takes precedence over allowWrite)
  final List<FilesystemPathEntry> denyWrite;

  /// Allow writes to .git/config files (default: false). Enables git remote URL updates while keeping .git/hooks protected.
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

sealed class FilesystemPathEntry {
  const FilesystemPathEntry();
}

class FilesystemPathSpelling extends FilesystemPathEntry {
  final String path;
  const FilesystemPathSpelling(this.path);
  @override
  String toString() => path;
}

class FilesystemPathLiteral extends FilesystemPathEntry {
  final String path;
  const FilesystemPathLiteral(this.path);
  bool get literal => true;
  @override
  String toString() => path;
}

typedef CredentialMode = String;
const List<String> CREDENTIAL_MODES = ['deny', 'mask'];
typedef ExtractNoMatch = String;
const List<String> EXTRACT_NO_MATCH_VALUES = ['warn', 'deny', 'error'];
typedef CredentialDecode = String;
const List<String> CREDENTIAL_DECODE_VALUES = ['jwt'];

class CredentialFileConfig {
  /// Path to a credential file or directory. Supports the same path forms as a string in filesystem.denyRead (absolute paths and ~ expansion).
  final String path;

  /// Access mode for this path
  final CredentialMode mode;

  /// Optional regex for structured masking. Applied globally; capture group 1 of each match is masked, the rest of the file is preserved. If the pattern matches nothing, behaviour is governed by onExtractNoMatch (default "warn"). Only meaningful when mode is "mask"; accepted but ignored for "deny".
  final String? extract;

  ///
  /// What to do when `extract` matches nothing in the file at runtime —
  /// or, with `decode`, when no candidate survives verification.
  ///
  /// - `"warn"` (default): emit a stderr warning and leave the file
  ///   readable as-is inside the sandbox (fail-open). A non-matching
  ///   pattern is treated as a config error to surface and fix, not a
  ///   reason to break a tool that needs the file when the credential is
  ///   legitimately absent.
  /// - `"deny"`: degrade the entry to `mode: "deny"` so the file is
  ///   unreadable inside the sandbox (fail-closed). The operator declared
  ///   this file as containing a credential; if the regex cannot find it,
  ///   block access rather than expose it.
  /// - `"error"`: throw at wrap time so nothing runs until the operator
  ///   fixes the config.
  ///
  /// Only meaningful when `mode` is `"mask"` and `extract` or `decode` is
  /// set; accepted but ignored otherwise.
  /// What to do when extract matches nothing (or, with decode, no candidate verifies): "warn" (default — stderr warning, file left readable), "deny" (degrade to mode "deny" — file unreadable), or "error" (throw at wrap time). Only meaningful with mode "mask" and extract or decode set.
  final ExtractNoMatch? onExtractNoMatch;

  /// Optional encoded-credential format. "jwt": decodes recognized JWTs so masking can target fields inside them (see maskClaims). Candidates are located with a built-in JWT regex (or the explicit extract pattern, if set) and verified to actually be JWTs before masking. Without maskClaims, the whole decoded value is treated as the credential and replaced with a structurally valid fake JWT, so client-side token parsing keeps working. If no candidate verifies, behaviour is governed by onExtractNoMatch (default "warn"). Only meaningful when mode is "mask"; accepted but ignored for "deny".
  final CredentialDecode? decode;

  ///
  /// Names of top-level payload claims to mask inside each decoded value —
  /// the claim-level counterpart of `extract`: where `extract` opens plain
  /// text to mask a span inside it, `decode` + `maskClaims` opens the
  /// encoding to mask a field inside the decoded payload.
  ///
  /// For each verified JWT candidate, every named claim present with a
  /// string value is replaced by its own sentinel and the token is rebuilt
  /// around the modified payload (original header, filler signature). All
  /// other claims are preserved verbatim, so a tool that decodes the token
  /// and reads a non-secret claim (issuer, audience, user id) keeps
  /// working while the secret claim is protected. A named claim that is
  /// absent or non-string in a given token is skipped. If no named claim
  /// matches in any verified token, behaviour is governed by
  /// `onExtractNoMatch` — same as no candidate verifying.
  ///
  /// Requires `decode` (there is no payload to look inside otherwise); an
  /// explicitly empty list is rejected — see the superRefine below.
  /// Names of top-level payload claims to mask inside each decoded value, instead of replacing the whole token. Each named claim present with a string value gets its own sentinel; all other claims are preserved so claim-reading clients keep working. Requires decode. If no named claim matches in any verified token, behaviour is governed by onExtractNoMatch (default "warn"). Only meaningful when mode is "mask"; accepted but ignored for "deny".
  final List<String>? maskClaims;

  /// If true, verbatim occurrences of each captured credential value outside the regex-matched spans are also replaced with the corresponding sentinel — for a secret repeated where the regex does not reach (e.g. in a comment). Matches raw substrings: short or common credential values may corrupt unrelated content, so this is intended for long, high-entropy secrets. With decode, only values that passed verification are scanned; duplicates reuse the verified value's fake without re-verification. Defaults to false. Only meaningful with mode "mask" and extract or decode set; accepted but ignored otherwise.
  final bool? maskDuplicates;

  /// Optional narrowing of where the proxy substitutes this credential. If unset, defaults to network.allowedDomains — the credential is injected at every reachable host. Only meaningful when mode is "mask"; accepted but ignored for "deny".
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
  /// Environment variable name
  final String name;

  /// Access mode for this environment variable
  final CredentialMode mode;

  /// Optional regex for structured masking. Applied globally; capture group 1 of each match is masked, the rest of the value is preserved. If the pattern matches nothing, behaviour is governed by onExtractNoMatch (default "warn"). Only meaningful when mode is "mask"; accepted but ignored for "deny".
  final String? extract;

  ///
  /// What to do when `extract` matches nothing in the value at runtime.
  ///
  /// - `"warn"` (default): emit a stderr warning and let the variable pass
  ///   through unmasked inside the sandbox (fail-open). A non-matching
  ///   pattern is treated as a config error to surface and fix, not a
  ///   reason to break a tool that needs the variable when the credential
  ///   is legitimately absent from it.
  /// - `"deny"`: unset the variable inside the sandbox (fail-closed) — the
  ///   env analog of degrading a file to `mode: "deny"`. The operator
  ///   declared this variable as containing a credential; if the regex
  ///   cannot find it, withhold the value rather than expose it.
  /// - `"error"`: throw at wrap time so nothing runs until the operator
  ///   fixes the regex.
  ///
  /// Only meaningful when `mode` is `"mask"` and `extract` is set;
  /// accepted but ignored otherwise.
  /// What to do when extract matches nothing: "warn" (default — stderr warning, variable passes through unmasked), "deny" (variable unset inside the sandbox), or "error" (throw at wrap time). Only meaningful with mode "mask" and extract set.
  final ExtractNoMatch? onExtractNoMatch;

  /// Optional encoded-credential format. "jwt": the variable's whole value is verified to actually be a JWT and replaced with a structurally valid fake JWT so client-side token parsing keeps working; the proxy swaps the whole fake token on egress. If the value does not verify, the variable is left unmasked with a stderr warning (fail-open). Only meaningful when mode is "mask"; accepted but ignored for "deny".
  final CredentialDecode? decode;

  ///
  /// Names of top-level payload claims to mask inside the decoded value —
  /// the env-var counterpart of the `maskClaims` on a file entry: `decode`
  /// opens the variable's encoded value so masking can target a field
  /// inside the decoded payload instead of replacing the whole token.
  ///
  /// Every named claim present with a string value is replaced by its own
  /// sentinel and the token is rebuilt around the modified payload
  /// (original header segment, filler signature). All other claims are
  /// preserved verbatim, so a tool that decodes the token and reads a
  /// non-secret claim (issuer, audience, user id) keeps working while the
  /// secret claim is protected. A named claim that is absent or non-string
  /// is skipped. If no named claim matches, nothing was masked and the
  /// entry fails open with a stderr warning — same path as a value that
  /// does not verify as a JWT.
  ///
  /// Requires `decode` (there is no payload to look inside otherwise); an
  /// explicitly empty list is rejected — see the superRefine below.
  /// Names of top-level payload claims to mask inside the decoded value, instead of replacing the whole token. Each named claim present with a string value gets its own sentinel; all other claims are preserved so claim-reading clients keep working. Requires decode. If no named claim matches, the variable is left unmasked with a stderr warning (fail-open). Only meaningful when mode is "mask"; accepted but ignored for "deny".
  final List<String>? maskClaims;

  /// Optional narrowing of where the proxy substitutes this credential. If unset, defaults to network.allowedDomains — the credential is injected at every reachable host. Only meaningful when mode is "mask"; accepted but ignored for "deny".
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

class CredentialsConfig {
  /// Credential files or directories to protect
  final List<CredentialFileConfig>? files;

  /// Environment variables to protect
  final List<CredentialEnvVarConfig>? envVars;

  /// Allow sentinel→real substitution on the plain-HTTP proxy path. Defaults to false: without TLS termination the upstream identity is unverified and the credential travels in cleartext. Set only for trusted-network test fixtures.
  final bool? allowPlaintextInject;

  /// Explicit groupings of masked env vars into AWS credential pairs for SigV4 re-signing, for non-standard variable names. The conventional AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / AWS_SESSION_TOKEN trio is paired automatically when masked.
  final List<AwsPairConfig>? awsPairs;

  /// Policies for AWS SigV4 request shapes the proxy cannot re-sign (streaming, presigned, sigv4a) when they reference a masked credential pair: "deny" (default) or "passthrough".
  final Sigv4Config? sigv4;
  const CredentialsConfig({
    this.files,
    this.envVars,
    this.allowPlaintextInject,
    this.awsPairs,
    this.sigv4,
  });
}

typedef Sigv4Policy = String;
const List<String> SIGV4_POLICY_VALUES = ['deny', 'passthrough'];

class AwsPairConfig {
  /// Name of the masked env var holding the AWS access key id.
  final String accessKeyIdVar;

  /// Name of the masked env var holding the AWS secret access key.
  final String secretAccessKeyVar;

  /// Optional name of the masked env var holding the AWS session token (temporary credentials). When set, the proxy sends the real token as x-amz-security-token on re-signed requests and adds it to the signed header set if the client did not.
  final String? sessionTokenVar;
  const AwsPairConfig({
    required this.accessKeyIdVar,
    required this.secretAccessKeyVar,
    this.sessionTokenVar,
  });
}

class Sigv4Config {
  /// Policy for aws-chunked streaming uploads (x-amz-content-sha256: STREAMING-*): per-chunk signatures chain off the seed signature, so re-signing would require rewriting the body. Default "deny".
  final Sigv4Policy? streaming;

  /// Policy for presigned URLs (X-Amz-Algorithm/X-Amz-Signature in the query, no Authorization header): the signature lives in the URL itself. Default "deny".
  final Sigv4Policy? presigned;

  /// Policy for SigV4A (AWS4-ECDSA-P256-SHA256) asymmetric signatures: there is no shared-key HMAC to recompute. Default "deny".
  final Sigv4Policy? sigv4a;
  const Sigv4Config({this.streaming, this.presigned, this.sigv4a});
}

/// Map of command patterns to filesystem paths to ignore violations for. Use "*" to match all commands
typedef IgnoreViolationsConfig = Map<String, List<String>>;

class RipgrepConfig {
  /// The ripgrep command to execute
  final String command;

  /// Additional arguments to pass before ripgrep args
  final List<String>? args;

  /// Override argv[0] when spawning (for multicall binaries that dispatch on argv[0])
  final String? argv0;
  const RipgrepConfig({required this.command, this.args, this.argv0});
}

class GitConfig {
  /// Directories git should treat as safe (`safe.directory`) even though they're owned by a different user inside the sandbox. Use for the repo top-level when launching from a subdirectory. Does NOT grant write.
  final List<String> safeDirectories;
  const GitConfig({this.safeDirectories = const []});
}

class SeccompConfig {
  /// Path to the apply-seccomp binary
  final String? applyPath;

  /// Invoke apply-seccomp as a multicall binary that dispatches on the ARGV0 environment variable. When set, applyPath is used verbatim (no existence check) and the invocation inside bwrap is prefixed with ARGV0=<this value>. The caller is responsible for ensuring applyPath resolves inside the bwrap namespace and that the target binary implements the apply-seccomp interface when ARGV0 matches.
  final String? argv0;
  const SeccompConfig({this.applyPath, this.argv0});
}

class SrtWinConfig {
  /// Path to the srt-win binary. Pass the exported VENDORED_SRT_WIN_EXE constant to use the packaged vendor/srt-win/<arch>/srt-win.exe (see its WARNING: in a dev checkout that file may sit inside your sandbox write grant). The binary is spawned with the `--srt-win` argv[1] sentinel so a multicall dispatcher can route to srt-win's CLI.
  final String path;
  const SrtWinConfig({required this.path});
}

class WindowsConfig {
  /// Name for the dedicated sandbox user account that `srt-win install` creates and the sandboxed child runs as. Default: `srt-sandbox`. Install refuses if an account by this name already exists and srt-win did not create it (it will not rotate the password of an account it does not own). Must match what `srt-win install --sandbox-user` was run with.
  final String? sandboxUser;

  /// WFP sublayer GUID under which the filters were installed. Omit to use the srt-win compile-time default. Set this when filters were installed by enterprise tooling under a custom sublayer.
  final String? sublayerGuid;

  /// Deprecated alias for sublayerGuid.
  final String? wfpSublayerGuid;

  /// Inclusive [low, high] port range the JS mux proxy listeners bind inside. MUST match the range passed to `srt-win install --proxy-port-range` (default 60080–60089) — the WFP loopback permit only covers ports in that range.
  final (int, int)? proxyPortRange;

  /// How to locate/invoke the srt-win helper binary. `srtWin.path` is required to use the Windows sandbox — your own (multicall) binary, or the exported VENDORED_SRT_WIN_EXE constant for the packaged exe.
  final SrtWinConfig? srtWin;
  const WindowsConfig({
    this.sandboxUser,
    this.sublayerGuid,
    this.wfpSublayerGuid,
    this.proxyPortRange,
    this.srtWin,
  });
}

class SandboxRuntimeConfig {
  /// Network restrictions configuration
  final NetworkConfig network;

  /// Filesystem restrictions configuration
  final FilesystemConfig filesystem;

  /// Credential handling configuration. Only the explicitly declared files and environment variables are restricted.
  final CredentialsConfig? credentials;

  /// Optional configuration for ignoring specific violations
  final IgnoreViolationsConfig? ignoreViolations;

  /// Enable weaker nested sandbox mode (for Docker environments)
  final bool? enableWeakerNestedSandbox;

  /// Enable weaker network isolation to allow access to com.apple.trustd.agent (macOS only). This is needed for Go programs (gh, gcloud, terraform, kubectl, etc.) to verify TLS certificates when using httpProxyPort with a MITM proxy and custom CA. Enabling this opens a potential data exfiltration vector through the trustd service. Only enable if you need Go TLS verification.
  final bool? enableWeakerNetworkIsolation;

  /// Allow sending Apple Events and Launch Services open requests from the sandbox (macOS only). Needed for open, osascript, and anything that opens URLs or scripts other apps via AppleScript. This removes code-execution isolation: sandboxed commands can launch other applications unsandboxed with no user prompt (launched apps are not subject to the sandbox filesystem or network restrictions), and can script running apps subject to TCC automation consent. Default: false.
  final bool? allowAppleEvents;

  /// Custom ripgrep configuration (default: { command: "rg" })
  final RipgrepConfig? ripgrep;

  /// How deep below the working directory dangerous names are looked for on Linux (default: 3): a dangerous file down to this depth, and a dangerous directory, or the hooks and config of a repository, one level higher up. Higher values provide more protection but slower performance.
  final int? mandatoryDenySearchDepth;

  /// Allow pseudo-terminal (pty) operations (macOS only)
  final bool? allowPty;

  /// Custom seccomp binary paths (Linux only).
  final SeccompConfig? seccomp;

  /// Linux only: absolute path to the bwrap (bubblewrap) binary. When set, this path is used directly instead of resolving "bwrap" via PATH.
  final String? bwrapPath;

  /// Linux only: absolute path to the socat binary. When set, this path is used directly instead of resolving "socat" via PATH.
  final String? socatPath;

  /// macOS/Linux: absolute path to srt-proxy-agent.jar, the JVM agent injected via JAVA_TOOL_OPTIONS so Java tools honor the proxy. When set, used instead of looking under vendor/java-proxy-agent/. For consumers that bundle sandbox-runtime and ship the jar separately.
  final String? javaAgentJarPath;

  /// Windows-specific settings (WFP sublayer, proxy port range).
  final WindowsConfig? windows;

  /// Git configuration to inject via GIT_CONFIG_* env vars (cross-platform). `safeDirectories` marks paths as `safe.directory` without adding them to `filesystem.allowWrite`.
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
