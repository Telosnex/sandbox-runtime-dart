// Ported from sandbox-runtime src/sandbox/sandbox-manager.ts @ 24eb39e.
// ignore_for_file: non_constant_identifier_names, constant_identifier_names
// ignore_for_file: doc_directive_unknown, slash_for_doc_comments

import 'dart:async';
import 'dart:convert';

import 'package:path/path.dart' show dirname;

import '../node/abort.dart';
import '../node/child_process.dart' show NodeChildProcess;
import '../node/crypto.dart' show randomBytes;
import '../node/structured_clone.dart';
import '../node/errno.dart' show NodeError, NodeException;
import '../node/fs.dart' as fs;
import '../node/os.dart' show EOL;
import '../node/process.dart' as process;
import '../node/url.dart' show URL;
import '../utils/debug.dart';
import '../utils/ripgrep.dart' show RipgrepConfig;
import '../utils/platform.dart' show getPlatform, getWslVersion;
import '../utils/which.dart';
import 'body_substitution.dart' show GetBodySubstitutions;
import 'credential_aws_pairs.dart'
    show AwsPairRegistry, PlanSigv4, createSigv4Planner, registerAwsPairs;
import 'credential_mask_env.dart' show buildMaskedEnvVars;
import 'credential_mask_files.dart' show MaskedFileStore, buildMaskedFileBinds;
import 'credential_sentinel.dart' show SentinelRegistry;
import 'domain_pattern.dart'
    show
        ALLOWED_DOMAIN_ENTRY_MESSAGE,
        isValidAllowedDomainEntry,
        matchesDomainPattern,
        matchesDomainPatternWithPort,
        stripDomainPatternPort;
import 'emitted_connection.dart' show ByteBudget, assertTlsTerminationSupported;
import 'generate_seccomp_filter.dart' show getApplySeccompBinaryPathAsync;
import 'http_proxy.dart' show HttpProxyServerOptions, createHttpProxyServer;
import '../node/http.dart' as http;
import '../node/stream.dart' as stream;
import 'java_proxy_agent.dart' show getJavaProxyAgentJarPathAsync;
import 'linux_sandbox_utils.dart'
    show
        LinuxNetworkBridgeContext,
        LinuxSandboxParams,
        SandboxDependencyCheck,
        WorkingDirectoryChanged,
        checkLinuxDependencies,
        cleanupBwrapMountPoints,
        initializeLinuxNetworkBridge,
        linuxGetCwdMandatoryDenyPaths,
        wrapCommandWithSandboxLinux;
import 'linux_violation_monitor.dart'
    show
        LinuxViolationMonitor,
        LinuxViolationMonitorOptions,
        startLinuxSandboxViolationMonitor;
import 'listen_in_range.dart' show listenInRange;
import 'macos_sandbox_utils.dart'
    show
        MacOSSandboxParams,
        SandboxViolationEvent,
        startMacOSSandboxLogMonitor,
        wrapCommandWithSandboxMacOS;
import 'mitm_ca.dart'
    show
        CRL_PATH,
        MitmCA,
        certThumbprint,
        createMitmCA,
        disposeMitmCA,
        disposeMitmCASync;
import 'mux_proxy.dart'
    show MuxProxyOptions, MuxProxyServer, createMuxProxyServer;
import 'own_files.dart' show ownInstallWarning;
import 'parent_proxy.dart'
    show
        DirectLookup,
        ResolvedParentProxy,
        canonicalizeHost,
        isValidHost,
        redactUrl,
        resolveParentProxy;
import 'path_entries.dart'
    show
        PathListKind,
        hasNameReading,
        literalReadLists,
        literalWriteLists,
        reExposedBy,
        readRulesOf,
        samePathEntries,
        spelledOf,
        withOtherReadings,
        writeRootsOf;
import 'read_deny_glob.dart' show expandReadDenyGlobLinuxSteps;
import 'request_filter.dart' show FilterRequestCallback, MutateForwardedHeaders;
import 'resolved_address_guard.dart'
    show
        ResolvedAddressDeniedError,
        ResolvedAddressGuard,
        createResolvedAddressGuard,
        isResolvedAddressDenied;
import 'sandbox_config.dart'
    show
        CredentialEnvVarConfig,
        CredentialsConfig,
        FilesystemConfig,
        FilesystemPathEntry,
        FilesystemPathSpelling,
        GitConfig,
        IgnoreViolationsConfig,
        NetworkConfig,
        SandboxRuntimeConfig,
        SeccompConfig,
        WindowsConfig;
import 'sandbox_schemas.dart'
    show
        CredentialRestrictionConfig,
        FsReadRestrictionConfig,
        FsWriteRestrictionConfig,
        NetworkRestrictionConfig,
        SandboxAskCallback;
import 'sandbox_utils.dart'
    show
        GlobWalkListings,
        Steps,
        attributionKeyFor,
        containsGlobChars,
        decodeSandboxedCommand,
        encodeSandboxedCommand,
        GlobWalk,
        finish,
        finishInTurns,
        getDefaultWritePaths,
        globBaseDirIsRoot,
        globPatternBaseDir,
        normalizePathForSandbox,
        removeTrailingGlobSuffix,
        walkGlobPatternSteps,
        workingDirectory;
import '../node/generators.dart';
import 'socks_proxy.dart'
    show SocksProxyServerOptions, SocksProxyWrapper, createSocksProxyServer;
import 'sandbox_violation_store.dart'
    show
        SandboxViolationStore,
        sanitizeDenialReason,
        sanitizeUnregisteredCommandKey,
        shouldIgnoreViolation;
import 'windows_sandbox_utils.dart'
    show
        DEFAULT_WINDOWS_PROXY_PORT_RANGE,
        SrtWinSpawn,
        WindowsAclGrantOptions,
        WindowsAclStampOptions,
        WindowsBinShell,
        WindowsFsAccessSet,
        WindowsSandboxError,
        WindowsSandboxParams,
        checkWindowsDependencies,
        checkWindowsDependenciesAsync,
        ensurePersistentWindowsCa,
        expandWindowsFsPaths,
        getWindowsSandboxCaCert,
        getWindowsSandboxUserStatusAsync,
        grantWindowsAcl,
        parseWindowsBinShell,
        rankWindowsFsAccess,
        resolveSrtWin,
        restoreWindowsAcl,
        revokeWindowsAcl,
        stampWindowsAcl,
        verifyWindowsWfpEgress,
        wrapCommandWithSandboxWindows;

class _HostNetworkManagerContext {
  final int httpProxyPort;
  final int socksProxyPort;
  final LinuxNetworkBridgeContext? linuxBridge;

  const _HostNetworkManagerContext({
    required this.httpProxyPort,
    required this.socksProxyPort,
    required this.linuxBridge,
  });
}

// ============================================================================
// Private Module State
// ============================================================================

SandboxRuntimeConfig? _config;
/** How many times a configuration has been installed. A wrap tells by this
 *  as well as by the object: initialize() keeps the caller's own, which can
 *  be handed to it again. */
int _configInstalls = 0;
http.NodeHttpServer? _httpProxyServer;
SocksProxyWrapper? _socksProxyServer;
MuxProxyServer? _muxProxyServer;
_HostNetworkManagerContext? _managerContext;
Future<_HostNetworkManagerContext>? _initializationPromise;
bool _cleanupRegistered = false;
bool _ownInstallLogged = false;
void Function()? _logMonitorShutdown;
LinuxViolationMonitor? _linuxMonitor;
ResolvedParentProxy? _parentProxy;
/** Read live through {@link directLookup}, so a config update applies to the next dial. */
ResolvedAddressGuard _resolvedAddressGuard = createResolvedAddressGuard();
MitmCA? _mitmCA;
/**
 * Resolved path of the JVM proxy agent jar (see java-proxy-agent.ts); set
 * while a proxy is advertised to the sandbox, undefined if the jar is not
 * shipped/found (JVMs then just aren't proxy-aware, as before).
 */
String? _javaAgentJarPath;
// Per-session proxy auth token. Generated at proxy start, exported only into
// the sandbox child env, checked on every CONNECT/request — so a host process
// dialing 127.0.0.1:<proxyPort> can't reach the filter callback.
String? _proxyAuthToken;
// Windows: the config's resolved access set that was actually applied
// at initialize(). `undefined` means no stamp/grant was applied
// (gates running `acl restore`/`acl revoke` at reset()).
WindowsFsAccessSet? _windowsFsStampedSet;
// The sandbox user SID captured at initialize(). reset() uses this
// so a config change between init and reset can't strand ACEs
// under a different SID.
String? _windowsFsSbUserSid;
// The RAW config inputs that produced `windowsFsStampedSet`.
// updateConfig() compares these (not the resolved set) so it never
// re-expands globs — see `sameWindowsStampSet`.
_RawWindowsFsInputs? _windowsFsRawInputs;
// `verifyWindowsWfpEgress()` is once per PROCESS (it spawns a
// CreateProcessWithLogonW runner; first call may create the sandbox
// user's profile). The WFP fence is install-scoped, not config- or
// session-scoped — reset() does NOT clear this, so updateConfig()'s
// reset+reinit and the test suite's per-test reset() don't re-verify.
bool _windowsWfpVerified = false;
// Resolved once at initialize() (`resolveSrtWin` stats the disk).
// Captured so wrapWithSandboxArgv/reset() don't re-resolve per call
// and so reset()'s revoke/restore addresses the SAME binary the
// grants/stamps were applied with even if `config` mutated between.
SrtWinSpawn? _srtWinSpawn;
final _sandboxViolationStore = SandboxViolationStore();
// Per-session sentinel↔real-value map for masked credentials. Lives only in
// process memory; never written to disk or logged. Cleared on reset().
final _sentinelRegistry = SentinelRegistry();
// Per-session linked AWS credential pairs for SigV4 re-signing, keyed by
// the fake access key id. Same lifecycle and secrecy posture as the
// sentinel registry.
final _awsPairRegistry = AwsPairRegistry();
// Temp dir holding the sentinel-content fake files for masked credential
// files. Created lazily on first masked file; removed on reset().
final _maskedFileStore = MaskedFileStore();

// ============================================================================
// Private Helper Functions (not exported)
// ============================================================================

void _registerCleanup() {
  if (_cleanupRegistered) {
    return;
  }
  Future<void> cleanupHandler() => _reset().catchError((Object e) {
    logForDebugging('Cleanup failed in registerCleanup $e', level: 'error');
  });
  process.once('exit', () {
    unawaited(cleanupHandler());
    // On 'exit' reset() gets as far as its first await, so what it takes out
    // of the temp directory later than that goes here. After it, because on
    // Windows it starts by revoking a grant on the trust-bundle directory.
    // Only paths this process made and still holds: never a listing of the
    // temp directory, never a path out of the configuration.
    if (_mitmCA != null) disposeMitmCASync(_mitmCA!);
    _muxProxyServer?.removeBackendSocketSync();
    _maskedFileStore.dispose();
    // A bridge told to end removes its own socket, but not every time.
    final bridge = _managerContext?.linuxBridge;
    for (final path in [bridge?.httpSocketPath, bridge?.socksSocketPath]) {
      try {
        if (path != null && path.isNotEmpty) fs.rmSync(path, {'force': true});
      } catch (_) {
        // Best effort: an 'exit' handler must not throw.
      }
    }
  });
  process.once('SIGINT', cleanupHandler);
  process.once('SIGTERM', cleanupHandler);
  _cleanupRegistered = true;
}

/**
 * Attribution key to command text for every wrapped invocation, so each
 * producer can report (and ignoreViolations can match) the command an event
 * belongs to rather than the opaque key. Keys are held decoded because that
 * is the form the carriers deliver. Bounded FIFO: the violation store itself
 * only retains the last 100 events, so long-gone invocations need no entry.
 */
const _MAX_COMMAND_TEXTS = 1024;
final _commandTextsByKey = <String, String>{};

/** Exported for testing. */
void registerCommandText(String command, WrapWithSandboxOptions? options) {
  final key = decodeSandboxedCommand(
    encodeSandboxedCommand(attributionKeyFor(command, options?.commandId)),
  );
  final text = options?.commandText ?? command;
  _commandTextsByKey.remove(key);
  _commandTextsByKey[key] = text;
  while (_commandTextsByKey.length > _MAX_COMMAND_TEXTS) {
    final oldest = _commandTextsByKey.keys.firstOrNull;
    if (oldest == null) break;
    _commandTextsByKey.remove(oldest);
  }
}

/**
 * The command text for a decoded attribution key. Keys arrive over carriers
 * the sandboxed process can write (the observe socket's event field, the
 * macOS log tag, the proxy username), so only a key this process registered
 * carries the embedder's own text; anything else is untrusted bytes.
 * Exported for testing.
 */
String resolveCommandText(String decodedKey) {
  return _commandTextsByKey[decodedKey] ??
      sanitizeUnregisteredCommandKey(decodedKey);
}

/**
 * The shortest commandId a per-command allow list may be registered under:
 * 16 random bytes (128 bits) as unpadded base64url. The floor only turns away
 * what is too short to hold 128 bits: it cannot tell a random id from a
 * predictable one of the same length.
 */
const _MIN_NETWORK_LISTS_COMMAND_ID_LENGTH = 22;

/**
 * Attribution key to the network allow list registered for one invocation
 * (registerCommandNetworkLists), keyed the way commandTextsByKey is because
 * the proxy username delivers both. The embedder removes an entry when its
 * command is gone. Not bounded the way commandTextsByKey is: dropping the
 * oldest entry would silently take a list away from a running command.
 */
final _commandNetworkListsByKey = <String, ({List<String> allowedDomains})>{};

void _registerCommandNetworkLists(
  Object? commandId,
  ({List<String>? allowedDomains})? lists,
) {
  // The floor is measured on the key the map holds, not on the raw id, and
  // less U+FFFD: every unpaired surrogate becomes one, so it carries nothing.
  final key = commandId is String
      ? decodeSandboxedCommand(encodeSandboxedCommand(commandId))
      : '';
  // The id is not echoed in either message: it is what stands between a
  // sandboxed process and this list, and error text ends up in logs.
  if (key.replaceAll('\ufffd', '').length <
      _MIN_NETWORK_LISTS_COMMAND_ID_LENGTH) {
    throw NodeException(
      'registerCommandNetworkLists: commandId must be a string of at least '
      '$_MIN_NETWORK_LISTS_COMMAND_ID_LENGTH characters, unpaired '
      'surrogates not counted. The id is the '
      'only thing that binds a proxy connection to this allow list, and '
      'the sandboxed process chooses which id it presents, so it must be '
      'random (at least 128 bits, e.g. 16 random bytes as base64url) and '
      'never derived from the command text, a counter or the time.',
    );
  }
  final Object? allowedDomains = lists?.allowedDomains ?? const <String>[];
  if (allowedDomains is! List) {
    throw NodeException(
      'registerCommandNetworkLists: allowedDomains must be an array of strings.',
    );
  }
  for (final Object? entry in allowedDomains) {
    if (entry is! String || !isValidAllowedDomainEntry(entry)) {
      throw NodeException(
        'registerCommandNetworkLists: invalid allowedDomains entry '
        '${jsonEncode(entry)}. $ALLOWED_DOMAIN_ENTRY_MESSAGE',
      );
    }
  }
  _commandNetworkListsByKey[key] =
      // Copied, so the caller cannot change what was validated.
      (allowedDomains: [...allowedDomains.cast<String>()]);
  // An external HTTP proxy is handed no username, so no connection names an id.
  if (_config?.network.httpProxyPort != null) {
    logForDebugging(
      'registerCommandNetworkLists: network.httpProxyPort is set (an '
      'external proxy), so this list will never apply',
      level: 'warn',
    );
  }
}

void _unregisterCommandNetworkLists(Object? commandId) {
  if (commandId is! String) return;
  _commandNetworkListsByKey.remove(
    decodeSandboxedCommand(encodeSandboxedCommand(commandId)),
  );
}

/**
 * Record a proxy-side denial in the violation store so the model sees a
 * structured <sandbox_violations> block alongside the raw 403 / SOCKS
 * failure in stderr — parity with the macOS seatbelt log monitor and the
 * Linux seccomp observer. The proxy is the only component that knows the
 * destination host of a network deny, so neither of those can produce
 * this line. `encodedCommand` (from the proxy username) attributes it to
 * the invocation; without one the event is stored unattributed.
 */
void _recordProxyViolation(String line, String? encodedCommand) {
  final command = encodedCommand != null && encodedCommand.isNotEmpty
      ? resolveCommandText(decodeSandboxedCommand(encodedCommand))
      : null;
  // Same suppression the seatbelt / seccomp monitors apply, so a
  // configured ignoreViolations pattern silences the event no matter
  // which producer saw it.
  if (shouldIgnoreViolation(line, command, _config?.ignoreViolations)) {
    return;
  }
  _sandboxViolationStore.addViolation(
    SandboxViolationEvent(
      line: line,
      encodedCommand: encodedCommand,
      command: command,
      timestamp: DateTime.now(),
    ),
  );
}

void _recordOutboundDeny(
  String host,
  int port,
  String reason, [
  String? encodedCommand,
]) {
  _recordProxyViolation(
    'deny network-outbound $host:$port ($reason)',
    encodedCommand,
  );
}

/** Direct-dial `lookup` for the proxies: the current guard's, with a refusal recorded as a violation. */
final DirectLookup _directLookup = (port, [encodedCommand]) =>
    (hostname, options, callback) => _resolvedAddressGuard.lookupFor(port)(
      hostname,
      options,
      (err, address, [family]) {
        if (isResolvedAddressDenied(err)) {
          _recordOutboundDeny(
            hostname,
            port,
            (err as ResolvedAddressDeniedError).reason,
            encodedCommand,
          );
        }
        callback(err, address, family);
      },
    );

/**
 * The request URL as it should appear in a model-visible violation line:
 * origin + path, with any query string reduced to a `?…` marker (origin
 * carries no userinfo, so an embedded `name:pass@` is dropped too). Query
 * strings routinely carry credentials (api_key=, access_token=, signed
 * URLs) that the sandboxed client interpolated at runtime and that were
 * never in the model's context, so they must not enter the transcript via
 * the <sandbox_violations> block. The full URL still reaches the embedder's
 * filterRequest callback and its own debug logging.
 */
String _redactUrlForViolation(String url) {
  try {
    final u = URL(url);
    return '${u.origin}${u.pathname}${u.search.isNotEmpty ? '?…' : ''}';
  } catch (_) {
    // Not an absolute URL (shouldn't happen for proxy requests) — drop
    // anything after '?' rather than risk leaking it.
    final q = url.indexOf('?');
    return q == -1 ? url : '${url.substring(0, q)}?…';
  }
}

/** Whether an ask-callback answer is one of the two documented denials. */
bool _isDeclaredDenial(Object? answer) {
  return answer == false || (answer is Map && answer['allow'] == false);
}

/**
 * The reason an ask-callback answer gives for denying, sanitized, or
 * undefined when it gives none that can be shown. Only
 * `{ allow: false, reason }` supplies one: a reason on any other object was
 * not written as the explanation of a denial.
 */
String? _denialReasonOf(Object? answer) {
  if (answer is! Map) return null;
  final allow = answer['allow'];
  final reason = answer['reason'];
  if (allow != false || reason is! String) return null;
  final sanitized = sanitizeDenialReason(reason);
  return sanitized.isEmpty ? null : sanitized;
}

/** Own keys only: an entry can be spelled `constructor`. */
String _deniedDomainReason(String entry) {
  final reasons = _config?.network.deniedDomainReasons ?? const {};
  final own = reasons.containsKey(entry);
  return (own ? reasons[entry] : null) ?? 'host is on the deny list';
}

Future<bool> _filterNetworkRequest(
  int port,
  String host,
  SandboxAskCallback? sandboxAskCallback, [
  String? encodedCommand,
  void Function(String reason)? explain,
]) async {
  bool denied(String reason) {
    _recordOutboundDeny(host, port, reason, encodedCommand);
    explain?.call(reason);
    return false;
  }

  final config = _config;
  if (config == null) {
    logForDebugging('No config available, denying network request');
    return denied('sandbox policy unavailable');
  }

  // Reject hosts containing control characters before pattern matching.
  // `matchesDomainPattern` uses string suffix matching which is trivially
  // fooled by e.g. `evil.com\x00.allowed.com` — the null byte passes
  // `.endsWith()` but truncates at the libc DNS layer. The SOCKS path is the
  // main exposure (DOMAINNAME is unvalidated bytes); HTTP is protected by
  // llhttp/URL parsing, but we check here for defence in depth.
  if (!isValidHost(host)) {
    logForDebugging(
      'Denying malformed host: ${jsonEncode(host)}:$port',
      level: 'error',
    );
    return denied('malformed host');
  }

  // Canonicalize so string comparisons match what getaddrinfo() will dial.
  // Without this, inet_aton shorthand like `2852039166` (= 169.254.169.254)
  // or `127.1` slips past a denylist entry for the dotted-decimal form.
  final canonicalHost = canonicalizeHost(host) ?? host;

  // Check denied domains first
  for (final deniedDomain in config.network.deniedDomains) {
    if (matchesDomainPatternWithPort(canonicalHost, port, deniedDomain)) {
      logForDebugging('Denied by config rule: $host:$port');
      // The matched entry's own reason when the caller supplied one, so the
      // model reads why this destination is off-limits (and the sanctioned
      // alternative) instead of a generic deny; keyed by the exact entry.
      return denied(_deniedDomainReason(deniedDomain));
    }
  }

  // Check allowed domains
  for (final allowedDomain in config.network.allowedDomains) {
    if (matchesDomainPatternWithPort(canonicalHost, port, allowedDomain)) {
      logForDebugging('Allowed by config rule: $host:$port');
      return true;
    }
  }

  // strictAllowlist makes the configured allowlist deterministic enforcement:
  // neither a per-command allow list nor the callback below can widen it.
  if (config.network.strictAllowlist == true) {
    logForDebugging('No matching config rule, denying: $host:$port');
    return denied('host is not on the allow list');
  }

  // The allow list registered for the invocation the proxy username names.
  // Coming after both configured lists, it lifts the default deny for that
  // one command and never a configured deniedDomains entry. The username is
  // presented by the sandboxed client: see registerCommandNetworkLists.
  final perCommand = encodedCommand != null && encodedCommand.isNotEmpty
      ? _commandNetworkListsByKey[decodeSandboxedCommand(encodedCommand)]
      : null;
  for (final allowedDomain in perCommand?.allowedDomains ?? const <String>[]) {
    if (matchesDomainPatternWithPort(canonicalHost, port, allowedDomain)) {
      logForDebugging('Allowed by per-command rule: $host:$port');
      return true;
    }
  }

  if (sandboxAskCallback == null) {
    logForDebugging('No matching rule, denying: $host:$port');
    return denied('host is not on the allow list');
  }

  logForDebugging('No matching rule, asking user: $host:$port');
  try {
    // Held as unknown: a JavaScript caller is not bound by the declared type.
    final Object? answer = await sandboxAskCallback((host: host, port: port));
    // Only `true` allows: an object is how a callback denies with a reason,
    // and a truthiness test here would read every such denial as an allow.
    if (answer == true) {
      logForDebugging('User allowed: $host:$port');
      return true;
    }
    if (!_isDeclaredDenial(answer)) {
      logForDebugging(
        'Ask callback answered neither a boolean nor { allow: false, reason }; treating it as a denial: $host:$port',
        level: 'warn',
      );
    }
    logForDebugging('User denied: $host:$port');
    // The callback's own reason, when it gave one, says what to do instead.
    return denied(_denialReasonOf(answer) ?? 'user denied');
  } catch (error) {
    logForDebugging('Error in permission callback: $error', level: 'error');
    return denied('permission prompt failed');
  }
}

/**
 * Build the header-mutation callback that substitutes sentinel→real for
 * masked credentials. Returns undefined when no `credentials` block is
 * configured — wiring the seam at all is unnecessary then.
 *
 * Per-host gating happens inside the registry: each sentinel carries its
 * own injectHosts list and substitutes independently, so credential A's
 * sentinel cannot be laundered through credential B's allowed host. The
 * returned closure does not log header values; the registry holds the only
 * copy of the real value.
 */
MutateForwardedHeaders? _buildCredentialInjector() {
  if (_config?.credentials == null) return null;
  return (headers, destHost) {
    _sentinelRegistry.substituteInHeaders(
      headers,
      destHost,
      matchesDomainPattern,
    );
  };
}

/**
 * Body counterpart of {@link buildCredentialInjector}: per-destination
 * sentinel→real pairs for streaming substitution in request bodies, with
 * the same per-credential injectHosts gating applied inside the registry.
 */
GetBodySubstitutions? _buildBodyCredentialInjector() {
  if (_config?.credentials == null) return null;
  return (destHost) =>
      _sentinelRegistry.sentinelsForHost(destHost, matchesDomainPattern);
}

/**
 * Build the per-request SigV4 hook for the TLS-terminating proxy.
 * Returns undefined when no `credentials` block is configured. The hook
 * consults {@link awsPairRegistry} at request time, so pairs registered
 * later (wrapWithSandbox runs after the proxy starts) are picked up.
 */
PlanSigv4? _buildSigv4Planner() {
  if (_config?.credentials == null) return null;
  // Re-read the policies per request (not captured at proxy start) so an
  // updateConfig() that changes credentials.sigv4 takes effect without a
  // proxy restart, matching how the injector sees live registry state.
  return (method, requestTarget, headers, destHost) => createSigv4Planner(
    _awsPairRegistry,
    _config?.credentials?.sigv4,
    matchesDomainPattern,
  )(method, requestTarget, headers, destHost);
}

/**
 * Get the MITM proxy socket path for a given host, if configured.
 * Returns the socket path if the host matches any MITM domain pattern,
 * otherwise returns undefined.
 *
 * Matches the canonicalized hostname, like the allow/deny filter
 * (filterNetworkRequest) and the tlsTerminate exclusion below. This site
 * fails OPEN on a miss — a host that matches no MITM pattern is dialed
 * directly — so it must accept exactly the set of spellings the allowlist
 * accepts: otherwise `api.example.com.` (trailing-dot FQDN, same name to
 * DNS) passes the allowlist as `api.example.com` but misses every MITM
 * pattern and skips the MITM proxy entirely. The proxies already hand this
 * hook the canonical spelling; canonicalizing again here is defence in
 * depth for any other caller.
 */
String? _getMitmSocketPath(String host) {
  if (_config?.network.mitmProxy == null) {
    return null;
  }

  final mitmProxy = _config!.network.mitmProxy!;
  final socketPath = mitmProxy.socketPath;
  final domains = mitmProxy.domains;
  final canonicalHost = canonicalizeHost(host) ?? host;

  for (final pattern in domains) {
    if (matchesDomainPattern(canonicalHost, pattern)) {
      logForDebugging('Host $host matches MITM pattern $pattern');
      return socketPath;
    }
  }

  return null;
}

/**
 * Per-host TLS-termination opt-out from network.tlsTerminate.excludeDomains.
 * Only consulted by the HTTP proxy when tlsTerminate is enabled; exempted
 * hosts fall back to the opaque CONNECT tunnel (still allowlist-filtered),
 * so mTLS / cert-pinning clients can complete their own handshake.
 *
 * Matches the canonicalized hostname, like the allow/deny filter
 * (filterNetworkRequest) — otherwise a spelling the allowlist accepts after
 * canonicalization (`127.1`, a trailing-dot FQDN) would dodge the exclusion
 * and get terminated anyway.
 */
bool _shouldTerminateTLSForHost(String host) {
  final excludeDomains = _config?.network.tlsTerminate?.excludeDomains;
  if (excludeDomains == null || excludeDomains.isEmpty) return true;
  final canonicalHost = canonicalizeHost(host) ?? host;
  for (final pattern in excludeDomains) {
    if (!matchesDomainPattern(canonicalHost, pattern)) continue;
    logForDebugging(
      'Host $host matches tlsTerminate.excludeDomains pattern $pattern; skipping TLS termination',
    );
    // Masked-credential substitution only happens on the terminated path,
    // so a credential whose injectHosts cover this host can never be
    // injected here — the upstream gets the placeholder. Config validation
    // rejects the fully-contradictory spellings; this flags the partial
    // ones (e.g. default injectHosts = allowedDomains) at the moment they
    // actually bite.
    final masked = _sentinelRegistry.namesInjectableAt(
      canonicalHost,
      matchesDomainPattern,
    );
    if (masked.isNotEmpty) {
      logForDebugging(
        'tlsTerminate.excludeDomains: masked credential(s) ${masked.join(', ')} '
        'are configured for injection at $host, but its connections are '
        'not terminated, so the upstream will receive the placeholder',
        level: 'error',
      );
    }
    return false;
  }
  return true;
}

// Dart: the object literal upstream hands createHttpProxyServer.
class _HttpProxyServerOptions implements HttpProxyServerOptions {
  _HttpProxyServerOptions({
    required this.filterFn,
    this.getMitmSocketPath,
    this.mitmCA,
    this.shouldTerminateTLS,
    this.filterRequest,
    this.plaintextHeaderSet,
    this.stripResponseHeaders,
    this.refuseOpaqueTunnels,
    this.requireHostMatch,
    this.maxTerminatedTunnels,
    this.tlsHandshakeTimeoutMs,
    this.onFilterRequestDenied,
    this.mutateHeaders,
    this.mutateHeadersPlaintext,
    this.getBodySubstitutions,
    this.getBodySubstitutionsPlaintext,
    this.planSigv4,
    this.parentProxy,
    this.lookupFor,
    this.proxyAuthToken,
  });

  final FutureOr<bool> Function(
    int port,
    String host,
    stream.Duplex socket, [
    String? encodedCommand,
    void Function(String reason)? explain,
  ])
  filterFn;

  @override
  FutureOr<bool> filter(
    int port,
    String host,
    stream.Duplex socket, [
    String? encodedCommand,
    void Function(String reason)? explain,
  ]) => filterFn(port, host, socket, encodedCommand, explain);

  @override
  String? Function(String host)? getMitmSocketPath;
  @override
  final MitmCA? mitmCA;
  @override
  bool Function(String hostname, int port)? shouldTerminateTLS;
  @override
  final FilterRequestCallback? filterRequest;
  @override
  final bool? plaintextHeaderSet;
  @override
  final List<String>? stripResponseHeaders;
  @override
  final bool? refuseOpaqueTunnels;
  @override
  final bool? requireHostMatch;
  @override
  final int? maxTerminatedTunnels;
  @override
  final int? tlsHandshakeTimeoutMs;
  @override
  final void Function(
    ({String method, String url, String reason, String? encodedCommand}),
  )?
  onFilterRequestDenied;
  @override
  final MutateForwardedHeaders? mutateHeaders;
  @override
  final MutateForwardedHeaders? mutateHeadersPlaintext;
  @override
  final GetBodySubstitutions? getBodySubstitutions;
  @override
  final GetBodySubstitutions? getBodySubstitutionsPlaintext;
  @override
  final PlanSigv4? planSigv4;
  @override
  final ResolvedParentProxy? parentProxy;
  @override
  final DirectLookup? lookupFor;
  @override
  final String? proxyAuthToken;
  @override
  int? get maxSigv4ResignBodyBytes => null;
  @override
  Object? get tlsTerminateUpstreamCA => null;
  @override
  int? get maxHeaderSize => null;
  @override
  String? get denyHeader => null;
  @override
  bool? get requestTargetAsSpelled => null;
  @override
  bool? get requireAsciiHost => null;
  @override
  bool? get foldHopByHop => null;
  @override
  int? get maxBufferedRequestBody => null;
  @override
  int? get maxBufferedBytes => null;
  @override
  ByteBudget? get byteBudget => null;
}

// Dart: the object literal upstream hands createSocksProxyServer.
class _SocksProxyServerOptions implements SocksProxyServerOptions {
  _SocksProxyServerOptions({
    required this.filterFn,
    this.parentProxy,
    this.lookupFor,
    this.proxyAuthToken,
    this.refuseOpaqueTunnels,
    this.onTunnelRefused,
    this.probeUnauthenticated,
  });

  final FutureOr<bool> Function(int port, String host, [String? encodedCommand])
  filterFn;

  @override
  FutureOr<bool> filter(int port, String host, [String? encodedCommand]) =>
      filterFn(port, host, encodedCommand);

  @override
  final ResolvedParentProxy? parentProxy;
  @override
  final DirectLookup? lookupFor;
  @override
  final String? proxyAuthToken;
  @override
  final bool? refuseOpaqueTunnels;
  @override
  final void Function(int port, String host, String? encodedCommand)?
  onTunnelRefused;
  @override
  final Future<({String? deniedReason})> Function(int port, String host)?
  probeUnauthenticated;
}

Future<int> _startMuxProxyServer(
  SandboxAskCallback? sandboxAskCallback,
  (int, int)? portRange,
) async {
  final injectCredentials = _buildCredentialInjector();
  final injectBodyCredentials = _buildBodyCredentialInjector();
  _httpProxyServer = createHttpProxyServer(
    _HttpProxyServerOptions(
      filterFn: (port, host, socket, [encodedCommand, explain]) =>
          _filterNetworkRequest(
            port,
            host,
            sandboxAskCallback,
            encodedCommand,
            explain,
          ),
      getMitmSocketPath: _getMitmSocketPath,
      mitmCA: _mitmCA,
      // Dart: upstream's function takes the host alone; the port is not used.
      shouldTerminateTLS: (host, _) => _shouldTerminateTLSForHost(host),
      filterRequest: _config?.network.filterRequest,
      plaintextHeaderSet: _config?.network.allowPlaintextHeaderSet,
      stripResponseHeaders: _config?.network.stripResponseHeaders,
      refuseOpaqueTunnels: _config?.network.refuseOpaqueTunnels,
      requireHostMatch: _config?.network.requireHostMatch,
      maxTerminatedTunnels: _config?.network.tlsTerminate?.maxTunnels,
      tlsHandshakeTimeoutMs: _config?.network.tlsTerminate?.handshakeTimeoutMs,
      onFilterRequestDenied: (d) {
        _recordProxyViolation(
          'deny http-request ${d.method} ${_redactUrlForViolation(d.url)} (${d.reason})',
          d.encodedCommand,
        );
      },
      // TLS-terminated path always gets the injector; the plain-HTTP path
      // only when explicitly opted in. Without the opt-in, a sentinel sent
      // over plain HTTP reaches the upstream unchanged (fails closed).
      mutateHeaders: injectCredentials,
      mutateHeadersPlaintext: _config?.credentials?.allowPlaintextInject == true
          ? injectCredentials
          : null,
      getBodySubstitutions: injectBodyCredentials,
      getBodySubstitutionsPlaintext:
          _config?.credentials?.allowPlaintextInject == true
          ? injectBodyCredentials
          : null,
      // SigV4 re-signing is TLS-terminated-path only, like credential
      // injection: the real signature must not travel over plaintext.
      planSigv4: _buildSigv4Planner(),
      parentProxy: _parentProxy,
      lookupFor: _directLookup,
      proxyAuthToken: _proxyAuthToken,
    ),
  );

  _socksProxyServer = createSocksProxyServer(
    _SocksProxyServerOptions(
      filterFn: (port, host, [encodedCommand]) =>
          _filterNetworkRequest(port, host, sandboxAskCallback, encodedCommand),
      parentProxy: _parentProxy,
      lookupFor: _directLookup,
      proxyAuthToken: _proxyAuthToken,
      // A SOCKS tunnel is opaque, so the option that keeps opaque CONNECT
      // tunnels off the HTTP side must close this side of the port too.
      refuseOpaqueTunnels: _config?.network.refuseOpaqueTunnels,
      onTunnelRefused: (port, host, encodedCommand) {
        _recordProxyViolation(
          'deny socks-tunnel $host:$port (refuseOpaqueTunnels)',
          encodedCommand,
        );
      },
      probeUnauthenticated: (port, host) async {
        // Explicit deny rules only: an unauthenticated peer must never reach
        // the ask callback, and a merely off-list host gets the generic
        // cannot-authenticate refusal rather than a policy claim.
        final config = _config;
        if (config == null) return (deniedReason: null);
        final canonical = canonicalizeHost(host) ?? host;
        for (final entry in config.network.deniedDomains) {
          if (matchesDomainPatternWithPort(canonical, port, entry)) {
            final reason = _deniedDomainReason(entry);
            _recordOutboundDeny(host, port, reason);
            return (deniedReason: reason);
          }
        }
        return (deniedReason: null);
      },
    ),
  );

  _muxProxyServer = createMuxProxyServer(
    MuxProxyOptions(
      httpServer: _httpProxyServer!,
      handleSocksConnection: (s) => _socksProxyServer!.handleConnection(s),
      httpBackendPortRange: portRange,
    ),
  );

  final mux = _muxProxyServer!;
  // Backend first so the front-end never accepts a connection that would
  // dispatch to an unbound backend. On Windows the backend's port is
  // excluded when binding the front-end in the same WFP range.
  final backendPort = await mux.listenHttpBackend();
  await listenInRange(
    mux.server,
    (p) => mux.server.listen(p, '127.0.0.1'),
    portRange == null ? null : [portRange.$1, portRange.$2],
    backendPort != null ? {backendPort} : <int>{},
  );
  final muxPort = mux.getPort();
  if (muxPort == null) {
    throw NodeException('Failed to get mux proxy server port');
  }
  mux.unref();
  logForDebugging('Mux proxy (HTTP+SOCKS) listening on localhost:$muxPort');
  return muxPort;
}

// ============================================================================
// Public Module Functions (will be exported via namespace)
// ============================================================================

Future<void> _initialize(
  SandboxRuntimeConfig runtimeConfig, [
  SandboxAskCallback? sandboxAskCallback,
  bool enableLogMonitor = false,
]) async {
  try {
    await _initializeSteps(runtimeConfig, sandboxAskCallback, enableLogMonitor);
  } catch (error) {
    // Here, not at reset() or 'exit': a step can fail before the clean-up is
    // registered, and the next call makes a CA of its own.
    if (_mitmCA != null) disposeMitmCASync(_mitmCA!);
    _mitmCA = null;
    rethrow;
  }
}

Future<void> _initializeSteps(
  SandboxRuntimeConfig runtimeConfig,
  SandboxAskCallback? sandboxAskCallback,
  bool enableLogMonitor,
) async {
  // Return if already initializing
  if (_initializationPromise != null) {
    await _initializationPromise;
    return;
  }

  // Store config for use by other functions
  _config = runtimeConfig;
  _configInstalls++;

  // Resolve parent/upstream proxy from config or HTTP_PROXY env before we
  // start our own listeners (which will later shadow those vars in the child).
  _parentProxy = resolveParentProxy(runtimeConfig.network.parentProxy);
  if (_parentProxy != null) {
    logForDebugging(
      'Parent proxy configured: http=${redactUrl(_parentProxy!.httpUrl)} '
      'https=${redactUrl(_parentProxy!.httpsUrl)}',
    );
  }
  _resolvedAddressGuard = createResolvedAddressGuard(
    allowedDomains: runtimeConfig.network.allowedDomains,
    deniedDomains: runtimeConfig.network.deniedDomains,
    deniedResolvedAddresses: runtimeConfig.network.deniedResolvedAddresses,
  );

  // Load TLS-termination CA if configured. Throws on unreadable/non-PEM —
  // tlsTerminate is explicit opt-in, so a bad config is a hard error.
  if (runtimeConfig.network.tlsTerminate != null &&
      runtimeConfig.network.mitmProxy != null) {
    throw NodeException(
      'network.tlsTerminate and network.mitmProxy are mutually exclusive',
    );
  }
  // Before any CA, proxy or sandbox is set up: a runtime that cannot
  // terminate TLS in-process fails here, not on each tunnel.
  if (runtimeConfig.network.tlsTerminate != null) {
    assertTlsTerminationSupported();
  }
  // On Windows with tlsTerminate and no explicit caCertPath/caKeyPath,
  // defer CA creation until the Windows block below has resolved
  // srt-win and fetched user status — the persistent CA is
  // generated-if-absent under windowsStateDir()/ca and
  // trusted in the sandbox user's Root store, then loaded here.
  // Explicit paths (or non-Windows) go straight to createMitmCA.
  final tlsTerminate = runtimeConfig.network.tlsTerminate;
  final useWindowsPersistentCa =
      getPlatform() == 'windows' &&
      tlsTerminate != null &&
      (tlsTerminate.caCertPath ?? '').isEmpty &&
      (tlsTerminate.caKeyPath ?? '').isEmpty;
  _mitmCA = tlsTerminate != null && !useWindowsPersistentCa
      ? createMitmCA(
          caCertPath: tlsTerminate.caCertPath,
          caKeyPath: tlsTerminate.caKeyPath,
          extraCaCertPaths: tlsTerminate.extraCaCertPaths,
        )
      : null;

  // Check dependencies
  final deps = await _checkDependenciesAsync();
  if (deps.errors.isNotEmpty) {
    throw NodeException(
      'Sandbox dependencies not available: ${deps.errors.join(', ')}',
    );
  }

  // Start log monitor for macOS if enabled
  if (enableLogMonitor && getPlatform() == 'macos') {
    _logMonitorShutdown = startMacOSSandboxLogMonitor(
      _sandboxViolationStore.addViolation,
      _config!.ignoreViolations,
      resolveCommandText,
    );
    logForDebugging('Started macOS sandbox log monitor');
  }
  if (enableLogMonitor && getPlatform() == 'linux') {
    // The monitor compares paths the kernel reported, so its lists are
    // expanded the way the wrapper expands them (getFsWriteConfig folds in
    // the default write paths and drops the patterns, so only names are left;
    // normalizePathForSandbox resolves `~`, relative spellings and symlinks),
    // plus the built-in write denies the wrapper always applies.
    // It does not reproduce the wrapper's existence and boundary-symlink
    // filters, nor the ripgrep scan for nested dangerous paths; and it still
    // reports writes bwrap permits through `--dev`, `--proc` and the tmpfs
    // over each read-denied directory. Started once, so both lists are fixed
    // at the cwd and configuration of this call, and at the disk as it is
    // now: an entry with glob characters that becomes the name of a path
    // later is applied by the next wrap and stays unknown here.
    final monitoredWrites = _getFsWriteConfig();
    _linuxMonitor = startLinuxSandboxViolationMonitor(
      _sandboxViolationStore.addViolation,
      LinuxViolationMonitorOptions(
        // apply-seccomp's observer reports every write-intent syscall
        // (allowed or not). Only paths bwrap would actually refuse — outside
        // allowWrite or inside a denyWrite carve-out — go to the store. With
        // the policy on, the default write paths are listed in full rather
        // than as getFsWriteConfig() narrowed them: a home directory it leaves
        // out because it is read-denied sits under that deny's writable
        // tmpfs, so a write there is permitted and is not a violation.
        allowWritePaths: [
          ...writeRootsOf((
            allowOnly: monitoredWrites.allowOnly,
            literalAllowOnly: monitoredWrites.literalAllowOnly,
          )),
          ...(_config!.filesystem.disabled == true
              ? const <String>[]
              : getDefaultWritePaths()),
        ].map((p) => normalizePathForSandbox(p, literal: true)).toList(),
        denyWritePaths: [
          ...monitoredWrites.denyWithinAllow.map(
            (p) => normalizePathForSandbox(p, literal: true),
          ),
          ...(monitoredWrites.literalDenyWithinAllow ?? const <String>[]).map(
            (p) => normalizePathForSandbox(p, literal: true),
          ),
          // filesystem.disabled reaches the wrapper as `writeConfig ===
          // undefined`, which skips every bind and the built-in denies with
          // them, so the monitor must not judge by them either.
          ...(_config!.filesystem.disabled == true
              ? const <String>[]
              : linuxGetCwdMandatoryDenyPaths(_getAllowGitConfig())),
        ],
        ignoreViolations: _config!.ignoreViolations,
        resolveCommandText: resolveCommandText,
      ),
    );
    // Don't block initialization on listen() — wrap-time checks
    // fs.existsSync(observeSocketPath) and degrades gracefully.
    unawaited(_linuxMonitor!.ready);
    logForDebugging('Started Linux seccomp violation monitor');
  }

  // Register cleanup handlers first time
  _registerCleanup();

  // Windows: validate provisioning + filesystem config BEFORE any
  // sandboxed child can be spawned. Doing this at initialize() (not
  // wrap-time) means the host gets a single actionable error before
  // any per-exec work happens, instead of exit-15 on every command.
  if (getPlatform() == 'windows') {
    // Resolve once (stats disk); captured module-level for wrap/reset.
    _srtWinSpawn = resolveSrtWin(runtimeConfig.windows?.srtWin);
    final srtWin = _srtWinSpawn;
    final u = await getWindowsSandboxUserStatusAsync(srtWin: srtWin);
    if (!u.provisioned || !u.credPresent) {
      _config = null;
      throw WindowsSandboxError(
        'not_provisioned',
        'Windows sandbox user is not provisioned (user='
            '${u.provisioned}, cred=${u.credPresent}). Run `npx '
            'sandbox-runtime windows-install` (one UAC prompt) to '
            'provision it.',
      );
    }
    // Behavioral proof the WFP egress fence is active for the
    // sandbox user — BFE enumeration (`wfp status`) is admin-gated,
    // so this is the non-elevated readiness check. Fails closed: a
    // stale install (user provisioned but filters since removed)
    // throws here instead of running every exec with full egress.
    // After the user-status check so the not-provisioned message is
    // the actionable one. Once per process — the fence is install-
    // scoped, not session-scoped.
    if (!_windowsWfpVerified) {
      try {
        await verifyWindowsWfpEgress(
          proxyPortRange: runtimeConfig.windows?.proxyPortRange,
          srtWin: srtWin,
        );
      } catch (e) {
        _config = null;
        rethrow;
      }
      _windowsWfpVerified = true;
    }
    // Persistent-CA branch (see the deferral comment above).
    // `ensurePersistentWindowsCa` reconciles the registry thumb
    // itself (so initialize() after uninstall→reinstall repairs
    // trust) and may make `u.caCertThumb` stale — hence the
    // explicit-path thumb check below skips this branch.
    if (useWindowsPersistentCa) {
      try {
        final p = await ensurePersistentWindowsCa(status: u, srtWin: srtWin);
        _mitmCA = createMitmCA(
          caCertPem: p.certPem,
          caKeyPem: p.keyPem,
          caCertPath: p.certPath,
          caKeyPath: p.keyPath,
          extraCaCertPaths: tlsTerminate.extraCaCertPaths,
        );
      } catch (e) {
        _config = null;
        rethrow;
      }
    }
    // Explicit-path branch: schannel clients (System32 curl, IWR,
    // .NET, default-backend git) only trust what's in the sandbox
    // user's `CurrentUser\Root` — which `srt-win exec` does not (and
    // must not) write. Compare thumbprints so a stale install-time
    // CA doesn't pass the gate while schannel rejects the session's
    // proxy-minted leaves.
    if (tlsTerminate != null && _mitmCA != null && !useWindowsPersistentCa) {
      final installed = getWindowsSandboxCaCert(status: u);
      final sessionThumb = certThumbprint(_mitmCA!.certPem);
      if (installed == null) {
        _config = null;
        throw WindowsSandboxError(
          'trust_ca_not_installed',
          'tlsTerminate on Windows requires the sandbox to be '
              'installed with this CA (thumb=$sessionThumb): run '
              '`srt-win user trust-ca ${_mitmCA!.certPath}`. Per-exec '
              'installs into the sandbox user\'s Root store are not '
              'supported.',
        );
      }
      if (installed.thumb != sessionThumb) {
        _config = null;
        throw WindowsSandboxError(
          'trust_ca_thumbprint_mismatch',
          'tlsTerminate on Windows: the sandbox\'s installed CA '
              '(thumb=${installed.thumb}) doesn\'t match this '
              'session\'s CA (thumb=$sessionThumb). Run `srt-win '
              'user trust-ca ${_mitmCA!.certPath}` to update it.',
        );
      }
    }
    // Filesystem grants/denies — additive sandbox-user ACEs.
    try {
      var maskedFiles = <String>[];
      try {
        maskedFiles = _windowsMaskedFileDenies(
          _getCredentialRestrictions(
            runtimeConfig.credentials,
            runtimeConfig.network.allowedDomains,
          ),
        );
      } catch (_) {
        // onExtractNoMatch: "error" is thrown by every wrap, so nothing runs.
      }
      final acc = _computeWindowsFsAccessSet(runtimeConfig, maskedFiles);
      // The trust bundle the CA-trust env vars point at
      // (NODE_EXTRA_CA_CERTS etc.) must be readable by the
      // srt-sandbox child. It's written into the broker's %TEMP%,
      // which the sandbox user has no inherent rights on, so it
      // rides the same session-level `acl grant` read-set as the
      // working tree. Granted on the mkdtemp DIR (not the file)
      // so the (OI)(CI) ACE covers both the file open AND the
      // parent-directory list that cmd's `type`/`FindFirstFile`
      // does before opening. Mirrors the mac/linux
      // `ownAllowWithinDeny` in wrapWithSandbox: it is not ranked
      // against the config's lists, nor one of the config's grants.
      final grantRead = _mitmCA != null
          ? [...acc.grantRead, dirname(_mitmCA!.trustBundlePath)]
          : acc.grantRead;
      // `u` was fetched once above for the provisioning gate; the
      // same status carries the SID — don't re-spawn `srt-win user
      // status` here.
      if (u.sid == null || u.sid!.isEmpty) {
        throw NodeException(
          'sandbox user SID missing from `srt-win user status` '
          '(provisioned but in an inconsistent state)',
        );
      }
      final sb = u.sid!;
      // Record module-level state BEFORE the first acl call so the
      // catch's best-effort revoke/restore can address whatever
      // partially landed.
      _windowsFsSbUserSid = sb;
      // Grant FIRST so the sandbox user has working-tree access by
      // the time the deny stamp runs. The two are independent
      // refcounted state-DB sets keyed on the same holder PID.
      if (grantRead.isNotEmpty || acc.grantWrite.isNotEmpty) {
        grantWindowsAcl(
          WindowsAclGrantOptions(
            sandboxUserSid: sb,
            read: grantRead,
            write: acc.grantWrite,
            srtWin: srtWin,
          ),
        );
      }
      if (acc.denyRead.isNotEmpty || acc.denyWrite.isNotEmpty) {
        stampWindowsAcl(
          WindowsAclStampOptions(
            sandboxUserSid: sb,
            denyRead: acc.denyRead,
            denyWrite: acc.denyWrite,
            srtWin: srtWin,
          ),
        );
      }
      // Only record when something was actually applied — gates
      // running revoke/restore at reset(). Recorded AFTER success —
      // the catch below clears `config`, and a non-undefined
      // stampedSet would leave reset()/updateConfig() seeing state
      // that never landed.
      final anyApplied =
          grantRead.isNotEmpty ||
          acc.grantWrite.isNotEmpty ||
          acc.denyRead.isNotEmpty ||
          acc.denyWrite.isNotEmpty;
      if (anyApplied) {
        _windowsFsStampedSet = acc;
        logForDebugging(
          '[Sandbox Windows] fs applied: '
          '${acc.grantWrite.length} grantWrite, '
          '${grantRead.length} grantRead, '
          '${acc.denyRead.length} denyRead, '
          '${acc.denyWrite.length} denyWrite',
        );
      }
      _windowsFsRawInputs = _rawWindowsFsInputs(runtimeConfig);
    } catch (e) {
      // Best-effort release of whatever WAS applied before the
      // failure (exit-2 partial stamps/grants the resolvable
      // inputs; harmless if nothing was — no holds for this PID).
      if (_windowsFsSbUserSid != null && _windowsFsSbUserSid!.isNotEmpty) {
        revokeWindowsAcl(sandboxUserSid: _windowsFsSbUserSid!, srtWin: srtWin);
        restoreWindowsAcl(sandboxUserSid: _windowsFsSbUserSid!, srtWin: srtWin);
      }
      _windowsFsSbUserSid = null;
      _config = null;
      rethrow;
    }
  }

  // Initialize network infrastructure
  _initializationPromise = (() async {
    try {
      // On Windows the WFP loopback permit covers a fixed port
      // range, so the proxies must bind inside it. Other platforms
      // bake the actual ephemeral port into the sandbox profile, so
      // they keep using port 0.
      final (int, int)? portRange = getPlatform() == 'windows'
          ? (_config!.windows?.proxyPortRange ??
                DEFAULT_WINDOWS_PROXY_PORT_RANGE)
          : null;

      // The auth token is only set when this process owns the proxy; an
      // external proxy (_config!.network.httpProxyPort) handles its own auth,
      // and embedding our token in its URL would be wrong.
      _proxyAuthToken = _config!.network.httpProxyPort != null
          ? null
          : randomBytes(16).toString('hex');

      // The mux front-end serves both protocols on one port. Each side's
      // reported port is the external override if configured, else the mux
      // port — so the public _config!.network.{http,socks}ProxyPort contract
      // is unchanged. The mux is skipped only when BOTH are external.
      final needLocalProxy =
          _config!.network.httpProxyPort == null ||
          _config!.network.socksProxyPort == null;
      final muxPort = needLocalProxy
          ? await _startMuxProxyServer(sandboxAskCallback, portRange)
          : null;
      final httpProxyPort = _config!.network.httpProxyPort ?? muxPort!;
      final socksProxyPort = _config!.network.socksProxyPort ?? muxPort!;
      // JVMs read neither HTTPS_PROXY nor its credential; the agent bridges
      // both. Resolved once here, advertised via JAVA_TOOL_OPTIONS per command.
      // Async: the global-npm fallback spawns `npm root -g`.
      _javaAgentJarPath = await getJavaProxyAgentJarPathAsync(
        _config!.javaAgentJarPath,
      );
      // Leaves are minted lazily per-CONNECT (after this point), so setting
      // the CDP URL now means every leaf carries it. See MitmCA.crlUrl.
      // Windows-only: on Linux the child runs under bwrap --unshare-net and
      // reaches the proxy via a socat bridge on a fixed netns port, so a
      // host-namespace mux port would be unreachable — worse than no CDP,
      // since a Schannel-analog client (Java, OpenSSL with CRL_CHECK) then
      // hard-fails "CRL fetch error" instead of soft-passing "no CDP". macOS
      // has no in-tree Schannel-analog client. Also gated on `muxPort`: an
      // external `network.httpProxyPort` doesn't answer /srt.crl.
      if (_mitmCA != null && muxPort != null && getPlatform() == 'windows') {
        _mitmCA!.crlUrl = 'http://127.0.0.1:$muxPort$CRL_PATH';
      }
      if (_config!.network.httpProxyPort != null) {
        logForDebugging('Using external HTTP proxy on port $httpProxyPort');
      }
      if (_config!.network.socksProxyPort != null) {
        logForDebugging('Using external SOCKS proxy on port $socksProxyPort');
      }

      // Initialize platform-specific infrastructure
      LinuxNetworkBridgeContext? linuxBridge;
      if (getPlatform() == 'linux') {
        linuxBridge = await initializeLinuxNetworkBridge(
          httpProxyPort,
          socksProxyPort,
          _config!.socatPath,
        );
      }

      final context = _HostNetworkManagerContext(
        httpProxyPort: httpProxyPort,
        socksProxyPort: socksProxyPort,
        linuxBridge: linuxBridge,
      );
      _managerContext = context;
      logForDebugging('Network infrastructure initialized');
      return context;
    } catch (error) {
      // Clear state on error so initialization can be retried
      _initializationPromise = null;
      _managerContext = null;
      unawaited(
        _reset().catchError((Object e) {
          logForDebugging(
            'Cleanup failed in initializationPromise $e',
            level: 'error',
          );
        }),
      );
      rethrow;
    }
  })();

  await _initializationPromise;
}

bool _isSupportedPlatform() {
  final platform = getPlatform();
  if (platform == 'linux') {
    // WSL1 doesn't support bubblewrap
    return getWslVersion() != '1';
  }
  return platform == 'macos' || platform == 'windows';
}

bool _isSandboxingEnabled() {
  // Sandboxing is enabled if config has been set (via initialize())
  return _config != null;
}

/**
 * Platform-independent part of the dependency check. Returns either
 * a finished result (POSIX, unsupported platform, or a Windows
 * srt-win resolution failure) or the inputs for the Windows probe —
 * the only platform where the sync and async variants differ.
 */
({
  SandboxDependencyCheck? done,
  ({String? sublayerGuid, SrtWinSpawn srtWin})? windows,
})
_checkDependenciesCommon([RipgrepConfig? ripgrepConfig]) {
  if (!_isSupportedPlatform()) {
    return (
      done: const SandboxDependencyCheck(
        errors: ['Unsupported platform'],
        warnings: [],
      ),
      windows: null,
    );
  }

  final errors = <String>[];
  final warnings = <String>[];

  final platform = getPlatform();
  if (platform == 'linux') {
    // ripgrep is Linux-only: it's used by linuxGetMandatoryDenyPaths() to
    // expand glob deny-patterns to concrete paths for bwrap. macOS seatbelt
    // profiles take regex patterns directly, so rg is never invoked there.
    final rgToCheck =
        ripgrepConfig ??
        // Dart: sandbox_config.dart and ripgrep.dart each declare a RipgrepConfig.
        (_config?.ripgrep == null
            ? null
            : RipgrepConfig(
                command: _config!.ripgrep!.command,
                args: _config!.ripgrep!.args,
                argv0: _config!.ripgrep!.argv0,
              )) ??
        RipgrepConfig(command: 'rg');
    if (whichSync(rgToCheck.command) == null) {
      errors.add('ripgrep (${rgToCheck.command}) not found');
    }

    final linuxDeps = checkLinuxDependencies(
      seccompConfig: _config?.seccomp,
      bwrapPath: _config?.bwrapPath,
      socatPath: _config?.socatPath,
    );
    errors.addAll(linuxDeps.errors);
    warnings.addAll(linuxDeps.warnings);
  } else if (platform == 'windows') {
    SrtWinSpawn srtWin;
    try {
      srtWin = resolveSrtWin(_config?.windows?.srtWin);
    } catch (e) {
      errors.add(e is NodeException ? e.message : '$e');
      return (
        done: SandboxDependencyCheck(errors: errors, warnings: warnings),
        windows: null,
      );
    }
    return (
      done: null,
      windows: (
        sublayerGuid:
            _config?.windows?.sublayerGuid ?? _config?.windows?.wfpSublayerGuid,
        srtWin: srtWin,
      ),
    );
  }

  // The library itself writable from inside the sandbox: see own-files.ts.
  if (_config?.filesystem.disabled != true) {
    try {
      final writes = _getFsWriteConfig();
      final ownInstall = ownInstallWarning(
        writeRootsOf((
          allowOnly: writes.allowOnly,
          literalAllowOnly: writes.literalAllowOnly,
        )),
      );
      if (ownInstall != null) warnings.add(ownInstall);
    } catch (_) {
      // It only advises: whoever enforces a config says what is wrong with it.
    }
  }

  return (
    done: SandboxDependencyCheck(errors: errors, warnings: warnings),
    windows: null,
  );
}

/**
 * Check sandbox dependencies for the current platform
 * @param ripgrepConfig - Ripgrep command to check. If not provided, uses config from initialization or defaults to 'rg'
 * @returns { warnings, errors } - errors mean sandbox cannot run, warnings mean degraded functionality
 */
SandboxDependencyCheck _checkDependencies([RipgrepConfig? ripgrepConfig]) {
  final common = _checkDependenciesCommon(ripgrepConfig);
  if (common.done != null) return common.done!;
  return checkWindowsDependencies(
    sublayerGuid: common.windows!.sublayerGuid,
    srtWin: common.windows!.srtWin,
  );
}

/**
 * Async variant of {@link checkDependencies} — same result for the
 * same underlying state. On Windows the srt-win probes run via
 * `spawn` (never blocking the event loop) and concurrently; on other
 * platforms the checks are native and this simply wraps the sync
 * result. Windows callers should prefer this variant.
 */
Future<SandboxDependencyCheck> _checkDependenciesAsync([
  RipgrepConfig? ripgrepConfig,
]) async {
  // Linux: resolve apply-seccomp first so its global-npm fallback
  // (`npm root -g`) runs off the event loop; the sync check below then
  // hits the shared path cache.
  if (getPlatform() == 'linux' &&
      (_config?.seccomp?.argv0 == null || _config!.seccomp!.argv0!.isEmpty)) {
    await getApplySeccompBinaryPathAsync(_config?.seccomp?.applyPath);
  }
  final common = _checkDependenciesCommon(ripgrepConfig);
  if (common.done != null) return common.done!;
  return checkWindowsDependenciesAsync(
    sublayerGuid: common.windows!.sublayerGuid,
    srtWin: common.windows!.srtWin,
  );
}

/**
 * Build the read-deny / env-unset / env-set maps implied by the
 * `credentials` config.
 *
 * Only explicitly declared sources are restricted: `mode: 'deny'` file
 * entries join the read-deny set, `mode: 'deny'` env vars are unset, and
 * `mode: 'mask'` env vars are set to a fake value (whole-value sentinel,
 * the real value with extract-captured spans swapped for sentinels, or a
 * JWT-shaped fake for `decode: 'jwt'` / `maskClaims` entries) registered
 * in {@link sentinelRegistry} — see {@link buildMaskedEnvVars}.
 */
CredentialRestrictionConfig _getCredentialRestrictions(
  CredentialsConfig? credentials,
  List<String>? allowedDomains,
) {
  if (credentials == null) {
    return CredentialRestrictionConfig(
      denyReadPaths: [],
      unsetEnvVars: [],
      setEnvVars: {},
      maskedFileBinds: [],
      maskedFileStoreDir: null,
      degradeToDenyPaths: [],
    );
  }

  final denyReadPaths = _getCredentialDenyReadPaths(credentials);

  // Default injectHosts (= allowedDomains) is host-scoped: drop any
  // `:port` suffixes, otherwise the sentinel would carry an entry no bare
  // destination host can ever match and the credential would never inject.
  final defaultInjectHosts = [
    ...(allowedDomains ?? const <String>[]).map(stripDomainPatternPort).toSet(),
  ];

  final unsetEnvVars = <String>[];
  for (final v in credentials.envVars ?? const <CredentialEnvVarConfig>[]) {
    if (v.mode == 'deny') unsetEnvVars.add(v.name);
  }

  // Masked env vars: read the real value from the host environment,
  // register sentinel(s), and set the variable to the fake value inside
  // the sandbox. degradeToUnsetNames carries variables whose extract
  // pattern matched nothing with onExtractNoMatch: "deny" — merged into
  // unsetEnvVars below so the value is withheld rather than exposed.
  final maskedEnv = buildMaskedEnvVars(
    credentials.envVars ?? const [],
    defaultInjectHosts,
    _sentinelRegistry,
  );
  final setEnvVars = maskedEnv.setEnvVars;
  final degradeToUnsetNames = maskedEnv.degradeToUnsetNames;
  unsetEnvVars.addAll(degradeToUnsetNames);

  // Link masked AWS credentials into pairs so the proxy can re-sign
  // SigV4 requests (the signature is derived from the secret; header
  // substitution alone cannot fix it).
  registerAwsPairs(
    credentials.envVars ?? const [],
    credentials.awsPairs,
    defaultInjectHosts,
    setEnvVars,
    _awsPairRegistry,
  );

  // Masked files: read the real bytes on the host, register a sentinel,
  // write it to a fake file in the manager-owned temp dir. Missing/unreadable
  // entries are skipped (same posture as an unset masked env var).
  // degradeToDenyPaths carries paths whose extract pattern matched
  // nothing with onExtractNoMatch: "deny" — merged into denyReadPaths
  // below so both the read-deny config and the platform builders see
  // them, and carried separately so they stay literal on the way there.
  final files = credentials.files ?? const [];
  final maskedFiles = buildMaskedFileBinds(
    files,
    defaultInjectHosts,
    _sentinelRegistry,
    _maskedFileStore,
  );
  final maskedFileBinds = maskedFiles.binds;
  final degradeToDenyPaths = maskedFiles.degradeToDenyPaths;

  return CredentialRestrictionConfig(
    denyReadPaths: [
      ...{...denyReadPaths, ...degradeToDenyPaths},
    ],
    unsetEnvVars: [...unsetEnvVars.toSet()],
    setEnvVars: setEnvVars,
    // Dart: the schema holds records; credential-mask-files returns MaskedFileBind.
    maskedFileBinds: [
      for (final b in maskedFileBinds)
        (realPath: b.realPath, fakePath: b.fakePath),
    ],
    maskedFileStoreDir: _maskedFileStore.dirPath,
    degradeToDenyPaths: degradeToDenyPaths,
  );
}

/**
 * Pure (side-effect-free) chokepoint for credential file-deny
 * paths — `credentials.files` entries with `mode: 'deny'`. Any
 * code that needs the credential→denyRead contribution routes
 * through here so a comparison predicate can read it without
 * touching {@link sentinelRegistry}.
 */
List<String> _getCredentialDenyReadPaths(CredentialsConfig? credentials) {
  final files = credentials?.files ?? const [];
  return [...files.where((f) => f.mode == 'deny').map((f) => f.path).toSet()];
}

/**
 * The default write paths under a filesystem policy's read rules, for
 * getFsWriteConfig() and wrapWithSandbox() alike. Fed the entries as
 * configured, through the pure {@link getCredentialDenyReadPaths}: no glob
 * expansion and no credential masking, because getFsWriteConfig() is a
 * getter callers reach from permission checks and render paths. A mask entry
 * that degrades to a deny is a file and cannot cover a directory, so
 * leaving those out changes nothing. An entry with glob characters that is
 * also the name of a path counts as that name too. The credential denies are
 * judged apart, with no `allowRead`: they have no exceptions.
 */
List<String> _defaultWritePathsUnder({
  required List<FilesystemPathEntry> denyRead,
  required List<FilesystemPathEntry>? allowRead,
  required CredentialsConfig? credentials,
}) {
  final credentialRules = readRulesOf(
    [],
    null,
    _getCredentialDenyReadPaths(credentials),
  );
  final underCredentialDenies = getDefaultWritePaths(
    denyRead: credentialRules.denyRead,
    allowRead: credentialRules.allowRead,
  );
  final rules = readRulesOf(denyRead, allowRead, []);
  return getDefaultWritePaths(
    denyRead: rules.denyRead,
    allowRead: rules.allowRead,
  ).where((p) => underCredentialDenies.contains(p)).toList();
}

/**
 * The explicit `filesystem.denyRead` and the credential-derived deny paths,
 * each through {@link resolveReadPathEntries}. The single source of "what
 * files does this config want read-denied" on macOS and Linux, so a new
 * credential kind that contributes deny paths reaches both. The credential
 * ones are also returned apart, for the precedence the backends give them.
 */
Steps<({List<String> denyOnly, List<String>? credentialDenyOnly})>
_resolveReadDenies(
  List<FilesystemPathEntry>? denyRead,
  CredentialRestrictionConfig credentialRestrictions,
  Steps<List<String>> Function(String pattern, [String? anchor]) expandGlob,
) sync* {
  final listed = Box<List<String>>();
  yield* yieldStar(
    _resolveReadPathEntries('deny', denyRead ?? const [], expandGlob),
    listed,
  );
  final credentialDenyOnly = Box<List<String>>();
  yield* yieldStar(
    _resolveReadPathEntries(
      'deny',
      credentialRestrictions.denyReadPaths
          .map<FilesystemPathEntry>(FilesystemPathSpelling.new)
          .toList(),
      expandGlob,
      credentialRestrictions.degradeToDenyPaths,
    ),
    credentialDenyOnly,
  );
  yield Done((
    denyOnly: [
      ...{...listed.value, ...credentialDenyOnly.value},
    ],
    credentialDenyOnly: credentialDenyOnly.value.isNotEmpty
        ? credentialDenyOnly.value
        : null,
  ));
  return;
}

/// Strip a trailing `/**` from each read-path entry and, on Linux, replace
/// any remaining glob with what `expandGlob` returns for it (bubblewrap takes
/// concrete paths only). Other platforms match globs natively.
/// On Linux the entry's other readings are added (see `withOtherReadings`);
/// elsewhere the backend decides them. Entries the caller marked literal are
/// not in the result: they travel in the `literal…` lists.
///
/// `literalPaths` are the ones the library resolved itself (a masked
/// credential file that degraded to deny) — each names one file on disk, so
/// it is passed through whatever characters it contains. Expanded as a
/// pattern, a name holding `[` matches nothing and the deny is lost.
///
/// Each path once, where it first came up: every `**` pattern over one base
/// returns the directories it could not list, and the Linux wrapper looks at
/// every entry it is given.
Steps<List<String>> _resolveReadPathEntries(
  PathListKind kind,
  List<FilesystemPathEntry> paths,
  Steps<List<String>> Function(String pattern, [String? anchor]) expandGlob, [
  List<String> literalPaths = const [],
]) sync* {
  final literal = literalPaths.toSet();
  final resolved = <String>{};
  for (final p in spelledOf(paths)) {
    final stripped = removeTrailingGlobSuffix(p);
    if (getPlatform() == 'linux' &&
        !literal.contains(p) &&
        containsGlobChars(stripped)) {
      final found = Box<List<String>>();
      yield* yieldStar(withOtherReadings(p, stripped, kind, expandGlob), found);
      for (final f in found.value) {
        resolved.add(f);
      }
    } else {
      resolved.add(stripped);
    }
  }
  yield Done([...resolved]);
  return;
}

/// Strip a trailing `/**` and drop what is still a glob on Linux: bwrap needs
/// real paths. macOS subpath matching is recursive, so the strip is harmless
/// there and the filter never fires.
/// A glob that is also the name of a path that exists is kept, as that name.
/// Marked entries are not in the result, as in [resolveReadPathEntries].
List<String> _stripWriteGlobs(
  PathListKind kind,
  List<FilesystemPathEntry> paths,
) {
  return spelledOf(paths).map((p) => removeTrailingGlobSuffix(p)).where((p) {
    if (getPlatform() == 'linux' &&
        containsGlobChars(p) &&
        !hasNameReading(p, kind)) {
      logForDebugging('[Sandbox] Skipping glob write pattern on Linux: $p');
      return false;
    }
    return true;
  }).toList();
}

Steps<List<String>> _expandAllowReadGlob(
  String pattern, [
  String? anchor,
]) sync* {
  final walk = Box<GlobWalk>();
  yield* yieldStar(walkGlobPatternSteps(pattern, anchor: anchor), walk);
  final expanded = walk.value.matches;
  logForDebugging(
    '[Sandbox] Expanded allowRead glob pattern "$pattern" to ${expanded.length} paths on Linux',
  );
  yield Done(expanded);
  return;
}

/**
 * The read policy of the initialized config, for inspection and display.
 * On Linux, denyRead globs are collapsed to covering directory mounts against
 * this config's allowRead and {@link getFsWriteConfig}'s write roots, so
 * `denyOnly` is only sound alongside that write config and must not be handed
 * to wrapCommandWithSandboxLinux with a different one. Marked entries are
 * in the `literal…` lists, as spelled: pass the object on whole.
 */
FsReadRestrictionConfig _getFsReadConfig() {
  final config = _config;
  if (config == null || config.filesystem.disabled == true) {
    return FsReadRestrictionConfig(denyOnly: [], allowWithinDeny: []);
  }

  // Credential deny paths are unioned with the caller's denyRead — never
  // replacing it — so explicit filesystem restrictions always survive.
  final credentialRestrictions = _getCredentialRestrictions(
    config.credentials,
    config.network.allowedDomains,
  );
  // allowRead (re-allow within denied regions) is resolved first: the
  // denyRead glob expansion collapses against it.
  final allowPaths = finish(
    _resolveReadPathEntries(
      'allow',
      config.filesystem.allowRead ?? const [],
      _expandAllowReadGlob,
    ),
  );
  final reExposedPaths = reExposedBy(
    allowPaths,
    config.filesystem.allowRead,
    _getFsWriteConfig(),
  );
  final unlistableDenyDirs = <String>{};
  final GlobWalkListings listings = {};
  final denyPaths = finish(
    _resolveReadDenies(
      config.filesystem.denyRead,
      credentialRestrictions,
      (pattern, [anchor]) => expandReadDenyGlobLinuxSteps(
        pattern,
        reExposedPaths,
        unlistableDirs: unlistableDenyDirs,
        anchor: anchor,
        listings: listings,
      ),
    ),
  );

  final literals = literalReadLists(
    config.filesystem.denyRead,
    config.filesystem.allowRead,
  );
  return FsReadRestrictionConfig(
    denyOnly: denyPaths.denyOnly,
    credentialDenyOnly: denyPaths.credentialDenyOnly,
    allowWithinDeny: allowPaths,
    unlistableDenyDirs: [...unlistableDenyDirs],
    literalDenyOnly: literals['literalDenyOnly'],
    literalAllowWithinDeny: literals['literalAllowWithinDeny'],
  );
}

FsWriteRestrictionConfig _getFsWriteConfig() {
  final config = _config;
  if (config == null) {
    return FsWriteRestrictionConfig(
      allowOnly: getDefaultWritePaths(),
      denyWithinAllow: [],
    );
  }

  if (config.filesystem.disabled == true) {
    return FsWriteRestrictionConfig(allowOnly: ['/'], denyWithinAllow: []);
  }

  final allowPaths = _stripWriteGlobs('allow', config.filesystem.allowWrite);
  final denyPaths = _stripWriteGlobs('deny', config.filesystem.denyWrite);

  final allowOnly = [
    ..._defaultWritePathsUnder(
      denyRead: config.filesystem.denyRead,
      allowRead: config.filesystem.allowRead,
      credentials: config.credentials,
    ),
    ...allowPaths,
  ];

  final literals = literalWriteLists(
    config.filesystem.allowWrite,
    config.filesystem.denyWrite,
  );
  return FsWriteRestrictionConfig(
    allowOnly: allowOnly,
    denyWithinAllow: denyPaths,
    literalAllowOnly: literals['literalAllowOnly'],
    literalDenyWithinAllow: literals['literalDenyWithinAllow'],
  );
}

/**
 * Build the Windows file-access set (deny stamps + sandbox-user
 * grants) from `runtimeConfig`. Globs are expanded to concrete
 * paths (point-in-time — a path appearing after this returns is NOT
 * covered). Directory targets are accepted (the `(OI)(CI)` ACEs
 * cover the subtree).
 *
 * The sandbox user has no inherent rights on real-user-owned files,
 * so `allowWrite` (the working-tree roots) becomes a per-session
 * `MODIFY_NO_FDC` ALLOW ACE for `<sb-SID>`, `allowRead` a
 * `READ|EXECUTE` ALLOW ACE, and `denyRead`/`denyWrite` become an
 * explicit DENY ACE for `<sb-SID>` on the target plus a
 * `(OI)(CI) FILE_DELETE_CHILD` DENY on its parent.
 * {@link rankWindowsFsAccess} ranks the lists against each other.
 *
 * `maskedFiles`: see {@link windowsMaskedFileDenies}.
 */
WindowsFsAccessSet _computeWindowsFsAccessSet(
  SandboxRuntimeConfig c,
  List<String> maskedFiles,
) {
  final fs = c.filesystem;
  // filesystem.disabled bypasses ALL filesystem rule generation —
  // same as the macOS/Linux wrapWithSandbox path (readConfig /
  // writeConfig left undefined). On Windows this means no grant, and
  // no stamp but a masked file's; credential FILE denies are dropped
  // along with the rest (credential ENV: mode:'deny' is structural
  // under the fresh srt-sandbox env; mode:'mask' sentinels are passed
  // via the --env overlay).
  if (fs.disabled == true) {
    return WindowsFsAccessSet(
      grantRead: [],
      grantWrite: [],
      denyRead: [...maskedFiles],
      denyWrite: [],
    );
  }
  const expand = expandWindowsFsPaths;
  // `mode: 'deny'` — non-existent literals reach srt-win, which
  // creates a placeholder chain and stamps it (deny lands on the
  // exact target path). `mode: 'grant'` drops them (a grant on
  // nothing is meaningless).
  return rankWindowsFsAccess(
    allowRead: expand(fs.allowRead ?? const [], mode: 'grant'),
    allowWrite: expand(fs.allowWrite, mode: 'grant'),
    denyRead: expand(fs.denyRead, mode: 'deny'),
    denyWrite: expand(fs.denyWrite, mode: 'deny'),
    credentialDeny: [
      ...expand(
        _getCredentialDenyReadPaths(
          c.credentials,
        ).map<FilesystemPathEntry>(FilesystemPathSpelling.new).toList(),
        mode: 'deny',
      ),
      ...maskedFiles,
    ],
  );
}

/**
 * The `mode: "mask"` files, as credential denies: an ACL cannot redirect a
 * read, so on Windows, as on macOS, a masked file is unreadable. Each is a
 * file the library opened, so none is expanded, and `filesystem.disabled`
 * leaves them in force, as it leaves the masks on the other platforms.
 */
List<String> _windowsMaskedFileDenies(
  CredentialRestrictionConfig credentialRestrictions,
) {
  return [
    ...credentialRestrictions.maskedFileBinds.map((b) => b.realPath),
    ...credentialRestrictions.degradeToDenyPaths,
  ];
}

// Dart: the return type of rawWindowsFsInputs.
typedef _RawWindowsFsInputs = ({
  bool disabled,
  List<FilesystemPathEntry> denyRead,
  List<FilesystemPathEntry> denyWrite,
  List<FilesystemPathEntry> allowRead,
  List<FilesystemPathEntry> allowWrite,
  List<FilesystemPathEntry> credFiles,
});

/**
 * Snapshot the raw config fields that feed
 * {@link computeWindowsFsAccessSet}. Used by updateConfig() to
 * short-circuit the resolved-set diff (which re-runs glob
 * expansion) when nothing relevant changed.
 */
_RawWindowsFsInputs _rawWindowsFsInputs(SandboxRuntimeConfig c) {
  // Keyed exactly on what {@link computeWindowsFsAccessSet} reads of
  // the config. The masked files are not session-wide: each wrap
  // denies the ones the session has not stamped.
  // `network.allowedDomains` does NOT feed file-deny (only mask
  // injectHosts), so a network-only updateConfig hits the cache.
  return (
    disabled: c.filesystem.disabled ?? false,
    denyRead: [...c.filesystem.denyRead],
    denyWrite: [...c.filesystem.denyWrite],
    allowRead: [...(c.filesystem.allowRead ?? const [])],
    allowWrite: [...c.filesystem.allowWrite],
    credFiles: _getCredentialDenyReadPaths(
      c.credentials,
    ).map<FilesystemPathEntry>(FilesystemPathSpelling.new).toList(),
  );
}

bool _sameRawWindowsFsInputs(_RawWindowsFsInputs a, _RawWindowsFsInputs b) {
  return a.disabled == b.disabled &&
      samePathEntries(a.denyRead, b.denyRead) &&
      samePathEntries(a.denyWrite, b.denyWrite) &&
      samePathEntries(a.allowRead, b.allowRead) &&
      samePathEntries(a.allowWrite, b.allowWrite) &&
      samePathEntries(a.credFiles, b.credFiles);
}

/**
 * True when `newConfig`'s file-deny inputs match what was
 * stamped at initialize(). Compares raw inputs only (cheap,
 * order-insensitive); never re-expands globs — updateConfig is
 * warn-only on Windows and the resolved set wouldn't be used.
 */
bool _sameWindowsStampSet(SandboxRuntimeConfig newConfig) {
  return _windowsFsRawInputs != null &&
      _sameRawWindowsFsInputs(
        _windowsFsRawInputs!,
        _rawWindowsFsInputs(newConfig),
      );
}

NetworkRestrictionConfig _getNetworkRestrictionConfig() {
  final config = _config;
  if (config == null) {
    return NetworkRestrictionConfig();
  }

  // Preserve an explicitly-empty allowlist: consumers need to distinguish
  // "no network restriction configured" (absent) from "allowlist configured
  // with zero entries" (block-all / ask-only). Stripping the empty array
  // made a host app's restriction-status UI report an airgapped config as
  // unrestricted. deniedHosts keeps the strip — an empty denylist and an
  // absent one are semantically identical.
  final allowedHosts = config.network.allowedDomains;
  final deniedHosts = config.network.deniedDomains;

  return NetworkRestrictionConfig(
    allowedHosts: allowedHosts,
    deniedHosts: deniedHosts.isNotEmpty ? deniedHosts : null,
  );
}

List<String>? _getAllowUnixSockets() {
  return _config?.network.allowUnixSockets;
}

bool? _getAllowAllUnixSockets() {
  return _config?.network.allowAllUnixSockets;
}

bool? _getAllowLocalBinding() {
  return _config?.network.allowLocalBinding;
}

List<String>? _getAllowMachLookup() {
  return _config?.network.allowMachLookup;
}

Map<String, List<String>>? _getIgnoreViolations() {
  return _config?.ignoreViolations;
}

bool? _getEnableWeakerNestedSandbox() {
  return _config?.enableWeakerNestedSandbox;
}

bool? _getEnableWeakerNetworkIsolation() {
  return _config?.enableWeakerNetworkIsolation;
}

bool? _getAllowAppleEvents() {
  return _config?.allowAppleEvents;
}

RipgrepConfig _getRipgrepConfig() {
  return (_config?.ripgrep == null
          ? null
          : RipgrepConfig(
              command: _config!.ripgrep!.command,
              args: _config!.ripgrep!.args,
              argv0: _config!.ripgrep!.argv0,
            )) ??
      RipgrepConfig(command: 'rg');
}

int _getMandatoryDenySearchDepth() {
  return _config?.mandatoryDenySearchDepth ?? 3;
}

bool _getAllowGitConfig() {
  return _config?.filesystem.allowGitConfig ?? false;
}

/**
 * Union of session-level and per-call `git.safeDirectories`. Marks
 * paths as `safe.directory` (dubious-ownership bypass) WITHOUT
 * touching the write grant — the repo top-level for a subdirectory
 * launch must NOT go in `filesystem.allowWrite`.
 */
List<String> _getGitSafeDirectories([
  PartialSandboxRuntimeConfig? customConfig,
]) {
  return [
    ...(_config?.git?.safeDirectories ?? const []),
    ...(customConfig?.git?.safeDirectories ?? const []),
  ];
}

SeccompConfig? _getSeccompConfig() {
  return _config?.seccomp;
}

String? _getProxyAuthToken() {
  return _proxyAuthToken;
}

int? _getProxyPort() {
  return _managerContext?.httpProxyPort;
}

int? _getSocksProxyPort() {
  return _managerContext?.socksProxyPort;
}

String? _getLinuxHttpSocketPath() {
  return _managerContext?.linuxBridge?.httpSocketPath;
}

String? _getLinuxSocksSocketPath() {
  return _managerContext?.linuxBridge?.socksSocketPath;
}

/**
 * Wait for network initialization to complete if already in progress
 * Returns true if initialized successfully, false otherwise
 */
Future<bool> _waitForNetworkInitialization() async {
  if (_config == null) {
    return false;
  }
  if (_initializationPromise != null) {
    try {
      await _initializationPromise;
      return true;
    } catch (_) {
      return false;
    }
  }
  return _managerContext != null;
}

/**
 * Per-invocation options for {@link wrapWithSandbox} /
 * {@link wrapWithSandboxArgv} that aren't sandbox *policy* (that's
 * `customConfig`).
 */
class WrapWithSandboxOptions {
  /**
   * Opaque per-invocation correlation key. Violations observed while the
   * wrapped command runs (seatbelt log lines, seccomp events, proxy denies)
   * are stored under this key, so it must equal what you later pass to
   * `annotateStderrWithSandboxFailures` / `getViolationsForCommand`.
   * Defaults to `command`. Prefer a unique id (e.g. a tool-use id) over the
   * command text: keys are compared on their first 100 characters, so two
   * long commands sharing a prefix would otherwise cross-attribute, and a
   * rerun of the same text would inherit the earlier run's events.
   *
   * An id that a network allow list is registered under must also be
   * unguessable: see `registerCommandNetworkLists`.
   */
  final String? commandId;

  /**
   * The command this invocation *represents*, when that differs from the
   * string being wrapped (e.g. you wrap an assembled
   * `source <snapshot> && eval '<cmd>'` but the user-facing command is
   * `<cmd>`). Used for `ignoreViolations` command-pattern matching and
   * reported as the violation's `command`. Defaults to `command`.
   */
  final String? commandText;

  const WrapWithSandboxOptions({this.commandId, this.commandText});
}

/// TS `Partial<SandboxRuntimeConfig>`: every field of [SandboxRuntimeConfig], all optional.
class PartialSandboxRuntimeConfig {
  final NetworkConfig? network;
  final FilesystemConfig? filesystem;
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

  const PartialSandboxRuntimeConfig({
    this.network,
    this.filesystem,
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

/** A wrap that has started over this many times walks without giving the
 *  thread back. */
const _RESTARTS_IN_TURNS = 2;

/** In place of what a walk finds: the configuration was replaced under it. */
final Object _REPLACED = Object();

/** Whether a wrap is walking, and the ones waiting to, first come first. */
bool _walking = false;
final List<void Function()> _waitingToWalk = [];

/**
 * Resolves once no other wrap is walking, with what says that this one's walk
 * has ended; only the first call of it counts. Walks that take turns on one
 * thread end no sooner for it, while each keeps all it has listed until it
 * ends and has its turn before the event loop gets one: the memory and the
 * thread held would both grow with the wraps in flight.
 * Rejects with `signal`'s reason as soon as that is aborted during the wait.
 * Nothing else takes a wrap out of the line, reset() included.
 */
Future<void Function()> _waitToWalk([AbortSignal? signal]) async {
  if (_walking) {
    signal?.throwIfAborted();
    final completer = Completer<void>();
    late final void Function() go;
    late final void Function() leave;
    go = () {
      signal?.removeEventListener('abort', leave);
      completer.complete();
    };
    leave = () {
      _waitingToWalk.remove(go);
      completer.completeError(signal?.reason ?? AbortError());
    };
    _waitingToWalk.add(go);
    signal?.addEventListener('abort', leave, {'once': true});
    await completer.future;
  }
  _walking = true;
  var ended = false;
  return () {
    if (ended) return;
    ended = true;
    // Handed on while `walking` stays set, so that no newcomer gets in first.
    final next = _waitingToWalk.isNotEmpty ? _waitingToWalk.removeAt(0) : null;
    if (next != null) {
      next();
    } else {
      _walking = false;
    }
  };
}

Future<String> _wrapWithSandbox(
  String command, [
  String? binShell,
  PartialSandboxRuntimeConfig? customConfig,
  AbortSignal? abortSignal,
  WrapWithSandboxOptions? options,
]) async {
  return _wrapWithSandboxAgain(
    0,
    command,
    binShell,
    customConfig,
    abortSignal,
    options,
  );
}

/** {@link wrapWithSandbox}, having started over `restarts` times. */
Future<String> _wrapWithSandboxAgain(
  int restarts,
  String command, [
  String? binShell,
  PartialSandboxRuntimeConfig? customConfig,
  AbortSignal? abortSignal,
  WrapWithSandboxOptions? options,
]) async {
  // INVARIANT: an attempt waits before it reads anything, so that it goes by
  // the configuration, the working directory and the disk it finds afterwards.
  final walkEnded = await _waitToWalk(abortSignal);
  try {
    return await _wrapWithSandboxOnce(
      walkEnded,
      restarts,
      command,
      binShell,
      customConfig,
      abortSignal,
      options,
    );
  } finally {
    walkEnded();
  }
}

/** One attempt of {@link wrapWithSandboxAgain}, which calls `walkEnded` once
 *  it walks no more. */
Future<String> _wrapWithSandboxOnce(
  void Function() walkEnded,
  int restarts,
  String command, [
  String? binShell,
  PartialSandboxRuntimeConfig? customConfig,
  AbortSignal? abortSignal,
  WrapWithSandboxOptions? options,
]) async {
  final platform = getPlatform();
  final commandId = options?.commandId;
  registerCommandText(command, options);
  final startedWith = _config;
  final startedAt = _configInstalls;
  final startedIn = workingDirectory();
  bool movedOn() =>
      !identical(_config, startedWith) ||
      _configInstalls != startedAt ||
      workingDirectory() != startedIn;
  Future<String> startOver() {
    // The next attempt waits like any other wrap, behind the ones there are.
    walkEnded();
    return _wrapWithSandboxAgain(
      restarts + 1,
      command,
      binShell,
      customConfig,
      abortSignal,
      options,
    );
  }

  /** `steps`, left as soon as the host is seen to have moved on: what they
   *  would go on to find is for a wrap that starts over anyway. */
  Steps<Object?> whileCurrent<T>(Steps<T> steps) sync* {
    final iterator = steps.iterator;
    for (;;) {
      if (movedOn()) {
        yield Done(_REPLACED);
        return;
      }
      if (!iterator.moveNext()) throw StateError('Steps ended without Done');
      final step = iterator.current;
      if (step case Done<T>(:final value)) {
        yield Done(value);
        return;
      }
      yield Pause();
    }
  }

  FutureOr<Object?> walked<T>(Steps<T> steps) {
    if (restarts < _RESTARTS_IN_TURNS) {
      return finishInTurns(whileCurrent(steps), abortSignal);
    }
    abortSignal?.throwIfAborted();
    return finish(steps);
  }

  // filesystem.disabled bypasses ALL filesystem rule generation. Both
  // platform wrappers treat readConfig/writeConfig === undefined as "no
  // filesystem restrictions" (seatbelt emits `(allow file-write*)`; bwrap
  // skips the `--ro-bind / /` root and all path binds).
  //
  // Precedence: when a caller passes a per-call filesystem override at all,
  // its `disabled` (defaulting to false) wins outright. A global
  // disabled=true must not silently discard a per-call tightening that
  // omits the new key.
  final fsDisabled = customConfig?.filesystem != null
      ? (customConfig!.filesystem!.disabled ?? false)
      : (_config?.filesystem.disabled ?? false);

  // Credential env handling is independent of filesystem policy: unsetEnvVars /
  // setEnvVars must be applied even when fsDisabled (the credential file
  // deny-reads are dropped, but env scrubbing still happens).
  final credentialRestrictions = _getCredentialRestrictions(
    customConfig?.credentials ?? _config?.credentials,
    customConfig?.network?.allowedDomains ?? _config?.network.allowedDomains,
  );

  // Get configs - use custom if provided, otherwise fall back to main config
  // If neither exists, defaults to empty arrays (most restrictive)
  // Always include default system write paths (like /dev/null, /tmp/claude)
  FsWriteRestrictionConfig? writeConfig;
  FsReadRestrictionConfig? readConfig;
  if (!fsDisabled) {
    final userAllowWrite = _stripWriteGlobs(
      'allow',
      customConfig?.filesystem?.allowWrite ??
          _config?.filesystem.allowWrite ??
          const [],
    );
    final writeLiterals = literalWriteLists(
      customConfig?.filesystem?.allowWrite ?? _config?.filesystem.allowWrite,
      customConfig?.filesystem?.denyWrite ?? _config?.filesystem.denyWrite,
    );
    writeConfig = FsWriteRestrictionConfig(
      allowOnly: [
        ..._defaultWritePathsUnder(
          denyRead:
              customConfig?.filesystem?.denyRead ??
              _config?.filesystem.denyRead ??
              const [],
          allowRead:
              customConfig?.filesystem?.allowRead ??
              _config?.filesystem.allowRead,
          credentials: customConfig?.credentials ?? _config?.credentials,
        ),
        ...userAllowWrite,
      ],
      denyWithinAllow: _stripWriteGlobs(
        'deny',
        customConfig?.filesystem?.denyWrite ??
            _config?.filesystem.denyWrite ??
            const [],
      ),
      literalAllowOnly: writeLiterals['literalAllowOnly'],
      literalDenyWithinAllow: writeLiterals['literalDenyWithinAllow'],
    );
    // For a caller that never reads checkDependencies(), the CLI among them.
    if (!_ownInstallLogged) {
      _ownInstallLogged = true;
      try {
        final ownInstall = ownInstallWarning(
          writeRootsOf((
            allowOnly: writeConfig.allowOnly,
            literalAllowOnly: writeConfig.literalAllowOnly,
          )),
        );
        if (ownInstall != null) {
          logForDebugging(ownInstall, level: 'warn');
        }
      } catch (_) {
        // It only advises, as in checkDependenciesCommon().
      }
    }

    // Credential deny paths are unioned with the caller's denyRead — never
    // replacing it — so explicit filesystem restrictions always survive.
    // allowRead is resolved first: on Linux a denyRead glob's expansion is
    // collapsed against the paths that re-expose contents under a denied
    // directory (allowRead + allowWrite), so both must be final here.
    final expandedAllowReadResult = await walked(
      _resolveReadPathEntries(
        'allow',
        customConfig?.filesystem?.allowRead ??
            _config?.filesystem.allowRead ??
            const [],
        _expandAllowReadGlob,
      ),
    );
    if (identical(expandedAllowReadResult, _REPLACED)) return startOver();
    final expandedAllowRead = expandedAllowReadResult as List<String>;
    // The TLS-termination CA cert and the trust bundle the env vars point at
    // (NODE_EXTRA_CA_CERTS etc.) must be readable by the child, even if their
    // paths fall under a user-configured denyRead or credential entry.
    final ownAllowWithinDeny = <String>[];
    if (_mitmCA != null) {
      ownAllowWithinDeny.addAll([_mitmCA!.certPath, _mitmCA!.trustBundlePath]);
    }
    // Likewise the JVM proxy agent jar JAVA_TOOL_OPTIONS points at.
    if (_javaAgentJarPath != null && _javaAgentJarPath!.isNotEmpty) {
      ownAllowWithinDeny.add(_javaAgentJarPath!);
    }
    expandedAllowRead.addAll(ownAllowWithinDeny);
    final reExposedPaths = reExposedBy(
      expandedAllowRead,
      customConfig?.filesystem?.allowRead ?? _config?.filesystem.allowRead,
      writeConfig,
    );
    final unlistableDenyDirs = <String>{};
    final GlobWalkListings listings = {};
    final expandedDenyReadResult = await walked(
      _resolveReadDenies(
        customConfig?.filesystem?.denyRead ?? _config?.filesystem.denyRead,
        credentialRestrictions,
        (pattern, [anchor]) => expandReadDenyGlobLinuxSteps(
          pattern,
          reExposedPaths,
          unlistableDirs: unlistableDenyDirs,
          anchor: anchor,
          listings: listings,
        ),
      ),
    );
    // Emptied by hand: a runtime may keep what this function has named for as
    // long as it is suspended, which is until the scan below has ended.
    listings.clear();
    if (identical(expandedDenyReadResult, _REPLACED)) return startOver();
    final expandedDenyRead =
        expandedDenyReadResult
            as ({List<String> denyOnly, List<String>? credentialDenyOnly});
    final readLiterals = literalReadLists(
      customConfig?.filesystem?.denyRead ?? _config?.filesystem.denyRead,
      customConfig?.filesystem?.allowRead ?? _config?.filesystem.allowRead,
    );
    readConfig = FsReadRestrictionConfig(
      denyOnly: expandedDenyRead.denyOnly,
      credentialDenyOnly: expandedDenyRead.credentialDenyOnly,
      allowWithinDeny: expandedAllowRead,
      ownAllowWithinDeny: ownAllowWithinDeny.isNotEmpty
          ? ownAllowWithinDeny
          : null,
      unlistableDenyDirs: [...unlistableDenyDirs],
      literalDenyOnly: readLiterals['literalDenyOnly'],
      literalAllowWithinDeny: readLiterals['literalAllowWithinDeny'],
    );
  }
  // Nothing below walks, and what it waits for is not this thread.
  walkEnded();

  // Check if network config is specified - this determines if we need network restrictions
  // Network restriction is needed when:
  // 1. customConfig has network.allowedDomains defined (even if empty array = block all)
  // 2. OR config has network.allowedDomains defined (even if empty array = block all)
  // An empty allowedDomains array means "no domains allowed" = block all network access
  final hasNetworkConfig =
      customConfig?.network?.allowedDomains != null ||
      _config?.network.allowedDomains != null;

  // Network RESTRICTION is needed whenever network config is specified
  // This includes empty allowedDomains which means "block all network"
  final needsNetworkRestriction = hasNetworkConfig;

  // Network PROXY is needed whenever network config is specified
  // Even with empty allowedDomains, we route through proxy so that:
  // 1. updateConfig() can enable network access for already-running processes
  // 2. The proxy blocks all requests when allowlist is empty
  final needsNetworkProxy = hasNetworkConfig;

  // Wait for network initialization only if proxy is actually needed
  if (needsNetworkProxy) {
    await _waitForNetworkInitialization();
  }

  // INVARIANT: one wrap, one configuration. updateConfig() can run in any of
  // the turns above, and what was read before it must not be put together
  // with what is read after it: the write list of one configuration with the
  // allowGitConfig of another is a policy nobody chose. So the wrap starts
  // over. Nothing from here to the platform's wrapper awaits.
  //
  // And one working directory, which a relative entry is resolved against
  // wherever it is read: a `.` bound back from where the host has gone to,
  // over denies walked from where it was, uncovers what they matched.
  //
  // INVARIANT: what a wrap hands out was read from the disk after its
  // configuration was installed. A host that writes a file and then installs
  // a rule that denies it finds it denied by every wrap that goes by that
  // rule. So a wrap that starts over keeps nothing of what it has listed or
  // walked, the same rules included. A configuration installed after this
  // check is the next wrap's.
  //
  // An embedder can replace the configuration many times during one walk.
  // After RESTARTS_IN_TURNS the wrap walks without a turn of the event loop,
  // so no timer or I/O callback replaces it meanwhile. That holds the thread
  // for one walk, as every wrap did before the walk took turns. It is not a
  // proof that the wrap ends: a promise continuation, or anything at all
  // while the network is still being initialized, can replace it between the
  // walk and this check, and the wrap then starts over once more.
  if (movedOn()) return startOver();

  // Check custom config to allow pseudo-terminal (can be applied dynamically)
  final allowPty = customConfig?.allowPty ?? _config?.allowPty;

  final gitSafeDirectories = _getGitSafeDirectories(customConfig);

  switch (platform) {
    case 'macos':
      // macOS sandbox profile supports glob patterns directly, no ripgrep needed
      return wrapCommandWithSandboxMacOS(
        MacOSSandboxParams(
          command: command,
          commandId: commandId,
          needsNetworkRestriction: needsNetworkRestriction,
          // Only pass proxy ports if proxy is running (when there are domains to filter)
          httpProxyPort: needsNetworkProxy ? _getProxyPort() : null,
          socksProxyPort: needsNetworkProxy ? _getSocksProxyPort() : null,
          proxyAuthToken: needsNetworkProxy ? _proxyAuthToken : null,
          caCertPath: _mitmCA?.trustBundlePath,
          javaAgentJarPath: needsNetworkProxy ? _javaAgentJarPath : null,
          readConfig: readConfig,
          writeConfig: writeConfig,
          unsetEnvVars: credentialRestrictions.unsetEnvVars,
          setEnvVars: credentialRestrictions.setEnvVars,
          maskedFileBinds: credentialRestrictions.maskedFileBinds,
          degradeToDenyPaths: credentialRestrictions.degradeToDenyPaths,
          allowUnixSockets: _getAllowUnixSockets(),
          allowAllUnixSockets: _getAllowAllUnixSockets(),
          allowLocalBinding: _getAllowLocalBinding(),
          allowMachLookup: _getAllowMachLookup(),
          ignoreViolations: _getIgnoreViolations(),
          allowPty: allowPty,
          allowGitConfig: _getAllowGitConfig(),
          gitSafeDirectories: gitSafeDirectories,
          enableWeakerNetworkIsolation: _getEnableWeakerNetworkIsolation(),
          allowAppleEvents: _getAllowAppleEvents(),
          binShell: binShell,
        ),
      );

    case 'linux':
      return wrapCommandWithSandboxLinux(
        LinuxSandboxParams(
          command: command,
          commandId: commandId,
          needsNetworkRestriction: needsNetworkRestriction,
          // Only pass socket paths if proxy is running (when there are domains to filter)
          httpSocketPath: needsNetworkProxy ? _getLinuxHttpSocketPath() : null,
          socksSocketPath: needsNetworkProxy
              ? _getLinuxSocksSocketPath()
              : null,
          httpProxyPort: needsNetworkProxy
              ? _managerContext?.httpProxyPort
              : null,
          socksProxyPort: needsNetworkProxy
              ? _managerContext?.socksProxyPort
              : null,
          proxyAuthToken: needsNetworkProxy ? _proxyAuthToken : null,
          caCertPath: _mitmCA?.trustBundlePath,
          javaAgentJarPath: needsNetworkProxy ? _javaAgentJarPath : null,
          readConfig: readConfig,
          writeConfig: writeConfig,
          unsetEnvVars: credentialRestrictions.unsetEnvVars,
          setEnvVars: credentialRestrictions.setEnvVars,
          maskedFileBinds: credentialRestrictions.maskedFileBinds,
          maskedFileStoreDir: credentialRestrictions.maskedFileStoreDir,
          enableWeakerNestedSandbox: _getEnableWeakerNestedSandbox(),
          allowAllUnixSockets: _getAllowAllUnixSockets(),
          binShell: binShell,
          ripgrepConfig: _getRipgrepConfig(),
          mandatoryDenySearchDepth: _getMandatoryDenySearchDepth(),
          allowGitConfig: _getAllowGitConfig(),
          gitSafeDirectories: gitSafeDirectories,
          seccompConfig: _getSeccompConfig(),
          bwrapPath: _config?.bwrapPath,
          socatPath: _config?.socatPath,
          observeSocketPath: _linuxMonitor?.observeSocketPath,
          abortSignal: abortSignal,
        ),
      ).catchError((Object err) {
        // It awaits once more, for its scan: see the invariant above.
        if (err is WorkingDirectoryChanged) return startOver();
        throw err;
      });

    case 'windows':
      // Windows wraps to an argv array, not a shell string. Forcing
      // callers through wrapWithSandboxArgv() means they spawn with
      // {shell:false}, which is the security boundary that keeps the
      // user's command bytes off the HOST shell.
      throw NodeException(
        'wrapWithSandbox() returns a shell string and is not supported '
        'on Windows. Use SandboxManager.wrapWithSandboxArgv() and '
        'spawn the result with {shell: false}.',
      );

    default:
      // Unsupported platform - this should not happen since isSandboxingEnabled() checks platform support
      throw NodeException(
        'Sandbox configuration is not supported on platform: $platform',
      );
  }
}

/**
 * Wrap `command` for the sandbox and return a spawn descriptor:
 * `{ argv, env }`, suitable for
 * `spawn(argv[0], argv.slice(1), {shell: false, env})`.
 *
 * On Windows this is the ONLY supported wrap method (see
 * {@link wrapWithSandbox}); `env` is the broker process's spawn env
 * — the sandboxed child gets a fresh `srt-sandbox` profile env with
 * only the `--env` overlay baked into `argv` (see
 * {@link wrapCommandWithSandboxWindows}). On
 * macOS/Linux `argv` is `[binShell, '-c', <wrapWithSandbox result>]`
 * (proxy env is baked into that command) and `env` is the unchanged
 * `process.env`, so callers can spawn uniformly across platforms.
 *
 * @param cwd the working directory the caller will spawn the result
 *   with. On Windows the child's cwd is whatever the caller passes
 *   as the spawn `{cwd:}` option (there is no `--cwd` flag), and
 *   the `safe.directory` git-config injection derives from this — so
 *   pass the same value here as to `spawn({cwd})`. Defaults to
 *   `process.cwd()`. Currently unused on macOS/Linux.
 */
Future<({List<String> argv, Map<String, String?> env})> _wrapWithSandboxArgv(
  String command, [
  Object? binShell, // String | WindowsBinShell
  PartialSandboxRuntimeConfig? customConfig,
  AbortSignal? abortSignal,
  String? cwd,
  WrapWithSandboxOptions? options,
]) async {
  final platform = getPlatform();

  if (platform == 'windows') {
    final hasNetworkConfig =
        customConfig?.network?.allowedDomains != null ||
        _config?.network.allowedDomains != null;
    if (hasNetworkConfig) {
      await _waitForNetworkInitialization();
    }
    final credentialRestrictions = _getCredentialRestrictions(
      customConfig?.credentials ?? _config?.credentials,
      customConfig?.network?.allowedDomains ?? _config?.network.allowedDomains,
    );
    // Per-exec FILE denies (customConfig only — the session-level
    // config's denies were already stamped at initialize()).
    // Paths go through `expandWindowsFsPaths` — the SAME
    // chokepoint the session-level set uses (point-in-time glob
    // expand, normalize, missing→drop) — so a per-exec entry
    // resolves identically to its session-level equivalent.
    // macOS/Linux per-exec already reuses session-level expansion;
    // Windows now matches.
    //
    // The dedup against `windowsFsStampedSet` is an OPTIMIZATION,
    // not a correctness gate: re-stamping a session-held path
    // under the exec's distinct holder is refcount-safe but wastes
    // a SetSecurityInfo round-trip.
    //
    // filesystem.disabled bypasses ALL filesystem rule generation
    // — including credential-derived file denies — same ordering
    // as session-level `computeWindowsFsAccessSet` (credential
    // ENV: mode:'deny' is structural under the fresh srt-sandbox
    // env; mode:'mask' sentinels are passed via the --env
    // overlay). The masked files stay denied, as of this wrap: the
    // session has stamped the ones it found at initialize().
    // Per-exec allowRead/allowWrite throw — `srt-win exec` only
    // exposes `--deny-*`; per-exec grants are not implemented.
    final fsCfg = customConfig?.filesystem;
    final maskedFiles = _windowsMaskedFileDenies(credentialRestrictions);
    List<FilesystemPathEntry> rawRead = const [];
    List<FilesystemPathEntry> rawWrite = const [];
    List<String> rawCredential = const [];
    if (fsCfg?.disabled != true) {
      if ((fsCfg?.allowRead?.isNotEmpty ?? false) ||
          (fsCfg?.allowWrite.isNotEmpty ?? false)) {
        throw NodeException(
          'Per-exec filesystem.allowRead/allowWrite is not supported '
          'on Windows — `srt-win exec` only exposes per-exec '
          'denies. Set them at the session level (initialize()).',
        );
      }
      rawRead = fsCfg?.denyRead ?? const [];
      rawWrite = fsCfg?.denyWrite ?? const [];
      rawCredential = _getCredentialDenyReadPaths(customConfig?.credentials);
    }
    var perExecDenyRead = <String>[];
    var perExecDenyWrite = <String>[];
    // Skip on the dominant path (no per-exec fs deny, no credential
    // file).
    if (rawRead.isNotEmpty ||
        rawWrite.isNotEmpty ||
        rawCredential.isNotEmpty ||
        maskedFiles.isNotEmpty) {
      final sessRead = {...?_windowsFsStampedSet?.denyRead};
      final sessWrite = {...?_windowsFsStampedSet?.denyWrite};
      const expand = expandWindowsFsPaths;
      final ranked = rankWindowsFsAccess(
        allowRead: [],
        allowWrite: [],
        denyRead: expand(rawRead, mode: 'deny'),
        denyWrite: expand(rawWrite, mode: 'deny'),
        credentialDeny: [
          ...expand(
            rawCredential
                .map<FilesystemPathEntry>(FilesystemPathSpelling.new)
                .toList(),
            mode: 'deny',
          ),
          ...maskedFiles,
        ],
        held: _windowsFsStampedSet == null
            ? null
            : (
                grantRead: _windowsFsStampedSet!.grantRead,
                grantWrite: _windowsFsStampedSet!.grantWrite,
              ),
      );
      perExecDenyRead = ranked.denyRead
          .where((p) => !sessRead.contains(p))
          .toList();
      perExecDenyWrite = ranked.denyWrite
          .where((p) => !sessRead.contains(p) && !sessWrite.contains(p))
          .toList();
    }
    // Per-exec deny rides on argv (`acl stamp` reads stdin, but
    // exec's stdin belongs to the child). The CreateProcessW
    // length check lives in `wrapCommandWithSandboxWindows`
    // where the full argv (incl. shell + user command) is known.
    //
    // The `denyReadPaths` half of the SESSION-level credentials
    // is already unioned into the stamp set at initialize() time
    // via `computeWindowsFsAccessSet`.
    registerCommandText(command, options);
    return wrapCommandWithSandboxWindows(
      WindowsSandboxParams(
        command: command,
        commandId: options?.commandId,
        httpProxyPort: hasNetworkConfig ? _getProxyPort() : null,
        socksProxyPort: hasNetworkConfig ? _getSocksProxyPort() : null,
        proxyAuthToken: hasNetworkConfig ? _proxyAuthToken : null,
        // mode:'deny' env vars are structurally absent (fresh
        // srt-sandbox profile env). mode:'mask' sentinels are
        // passed via the --env overlay so the sandboxed child sees
        // the sentinel value, same as macOS/Linux.
        setEnvVars: credentialRestrictions.setEnvVars,
        denyRead: perExecDenyRead,
        denyWrite: perExecDenyWrite,
        // safe.directory: cwd + the resolved session-level write
        // grants + explicit git.safeDirectories — the working-tree
        // roots the sandbox user has MODIFY on plus any repo top-level
        // the caller marks as safe without granting write.
        cwd: cwd,
        allowWrite: _windowsFsStampedSet?.grantWrite,
        gitSafeDirectories: _getGitSafeDirectories(customConfig),
        caCertPath: _mitmCA?.trustBundlePath,
        binShell: parseWindowsBinShell(binShell),
        srtWin: customConfig?.windows?.srtWin != null
            ? resolveSrtWin(customConfig!.windows!.srtWin)
            : (_srtWinSpawn ?? resolveSrtWin(_config?.windows?.srtWin)),
      ),
    );
  }

  // macOS/Linux: delegate to the existing string wrapper, then put
  // the result behind `<shell> -c` so the caller's argv-spawn works.
  if (binShell is WindowsBinShell) {
    throw NodeException(
      'binShell object form is Windows-only; pass a shell path string '
      'on macOS/Linux',
    );
  }
  final wrapped = await _wrapWithSandbox(
    command,
    binShell as String?,
    customConfig,
    abortSignal,
    options,
  );
  final shell = binShell ?? '/bin/bash';
  return (argv: [shell, '-c', wrapped], env: process.env);
}

/**
 * Get the current sandbox configuration
 * @returns The current configuration, or undefined if not initialized
 */
SandboxRuntimeConfig? _getConfig() {
  return _config;
}

/**
 * Update the sandbox configuration in place.
 *
 * **Network/allowlist changes are a live swap**: the running
 * mux proxy reads `config.network.allowedDomains` /
 * `deniedDomains` per-request (via `filterNetworkRequest`), so
 * reassigning `config` here takes effect on the next connection
 * with no proxy rebind and no port change — on every platform,
 * including Windows. This is what lets a host enable/deny domains
 * for already-running sandboxed children.
 *
 * Filesystem changes (denyRead/denyWrite) are NOT applied live:
 * macOS bakes them into the seatbelt profile at wrap time, and
 * Linux/Windows bake them into the bwrap argv / DENY-ACE set at
 * wrap time. Call reset() + initialize() to apply a new
 * filesystem config.
 *
 * @param newConfig - The new configuration to use
 */
void _updateConfig(SandboxRuntimeConfig newConfig) {
  if (getPlatform() == 'windows' &&
      _config != null &&
      !_sameWindowsStampSet(newConfig)) {
    logForDebugging(
      '[Sandbox Windows] updateConfig: the resolved file-access set '
      '(filesystem.* ∪ credentials.files) changed but the ACL '
      'stamp/grant is session-wide — call reset() then initialize() '
      'to apply. The previously-applied set stays in effect.',
      level: 'warn',
    );
  }
  // Built before anything is swapped, so a malformed range leaves the
  // previous config fully in effect.
  final nextGuard = createResolvedAddressGuard(
    allowedDomains: newConfig.network.allowedDomains,
    deniedDomains: newConfig.network.deniedDomains,
    deniedResolvedAddresses: newConfig.network.deniedResolvedAddresses,
  );
  // Deep clone the config to avoid mutations. structuredClone cannot clone
  // functions, so pull filterRequest out, clone the rest, and put it back —
  // a function reference is immutable in the sense that matters here.
  // Dart: functions pass through structuredClone by reference.
  _config = structuredClone(newConfig);
  _configInstalls++;
  _resolvedAddressGuard = nextGuard;
  // Re-resolve parent proxy so hot-reload picks up changes. Note: the proxy
  // servers capture `parentProxy` by value at creation, so changes here take
  // effect only on re-initialize. This keeps the state consistent for the
  // next initialize() call.
  _parentProxy = resolveParentProxy(newConfig.network.parentProxy);
  logForDebugging('Sandbox configuration updated');
}

/**
 * Lightweight cleanup to call after each sandboxed command completes.
 *
 * On Linux, bwrap creates empty files on the host filesystem as mount points
 * when protecting non-existent deny paths (e.g. ~/.bashrc, ~/.gitconfig).
 * These persist after bwrap exits. This function removes them.
 *
 * Safe to call on any platform — it's a no-op on macOS.
 * Also called automatically by reset() and on process exit as safety nets.
 */
void _cleanupAfterCommand() {
  cleanupBwrapMountPoints();
}

/**
 * How long to wait for a bridge process to exit after SIGTERM before
 * escalating to SIGKILL.
 *
 * socat exits within ~10ms of SIGTERM; this is purely a safety margin.
 * Keep it well below bun's default 5s test/hook timeout: when a bridge's
 * `'exit'` event is missed entirely (a Linux-only Bun pidfd notification
 * bug, oven-sh/bun#30301), this timer is the only thing that lets `reset()`
 * make progress, and a 5000ms value here loses the race against the hook
 * timer by a couple of milliseconds — that race was the dominant CI flake.
 */
const _BRIDGE_EXIT_TIMEOUT_MS = 1500;

/**
 * SIGTERM a bridge process and resolve once it has exited.
 *
 * Returns immediately if the process has already exited (`.exitCode` /
 * `.signalCode` set) — registering `.once('exit')` after the event has
 * already been emitted produces a listener that never fires.
 *
 * Falls back to SIGKILL after {@link BRIDGE_EXIT_TIMEOUT_MS}.
 */
Future<void> _killBridgeProcess(NodeChildProcess proc, String label) {
  // Already exited → 'exit' already emitted → a fresh once('exit') would
  // never fire. Don't wait on it.
  if (proc.pid == null ||
      proc.pid == 0 ||
      proc.exitCode != null ||
      proc.signalCode != null) {
    return Future.value();
  }

  try {
    process.kill(proc.pid!, 'SIGTERM');
    logForDebugging('Sent SIGTERM to $label bridge process');
  } catch (err) {
    if (!(err is NodeError && err.code == 'ESRCH')) {
      logForDebugging('Error killing $label bridge: $err', level: 'error');
    }
    // ESRCH = process already gone; nothing to wait for either way.
    return Future.value();
  }

  final completer = Completer<void>();
  void resolve() => completer.complete();
  var settled = false;
  late final Timer timer;
  void done() {
    if (settled) return;
    settled = true;
    timer.cancel();
    resolve();
  }

  proc.once('exit', () {
    logForDebugging('$label bridge process exited');
    done();
  });
  timer = Timer(const Duration(milliseconds: _BRIDGE_EXIT_TIMEOUT_MS), () {
    // Re-check liveness — the 'exit' may have raced us.
    if (proc.exitCode == null && proc.signalCode == null) {
      logForDebugging(
        '$label bridge did not exit, forcing SIGKILL',
        level: 'warn',
      );
      try {
        if (proc.pid != null && proc.pid != 0) {
          process.kill(proc.pid!, 'SIGKILL');
        }
      } catch (_) {
        // Process may have already exited
      }
    }
    done();
  });
  // The bridge process is being torn down; this timer must not be the
  // only thing keeping the event loop alive.
  // Dart: a Timer cannot be unref'd.
  return completer.future;
}

/**
 * Forcibly close an http.Server, including any in-flight requests.
 *
 * Plain `server.close()` waits for every active request to finish.
 * The proxy may be mid-upstream-request when reset() runs (e.g. a test's
 * curl was killed by --max-time while the proxy was still dialing the
 * real example.com / api.github.com), and `dialDirect()` allows up to
 * 30s before giving up. Combined with a socat fork that hasn't yet seen
 * its unix-socket EOF, that leaves a fully-open inbound connection and
 * `server.close()` never calls back. `closeAllConnections()` (Node 18.2+,
 * also implemented in Bun) tears down those sockets so `close()` resolves
 * immediately.
 */
Future<void> _forceCloseHttpServer(http.NodeHttpServer server) {
  final completer = Completer<void>();
  // Must run *before* close(): in Bun, close() also detaches the
  // underlying handle, so a closeAllConnections() called afterwards
  // becomes a no-op and the close callback waits for the in-flight
  // request to drain — defeating the purpose. With closeAllConnections()
  // first, the connections are gone by the time close() runs and its
  // callback fires immediately (Bun reports "Server is not running.",
  // Node reports no error). Verified against both orderings.
  server.closeAllConnections();
  server.close(([Object? error]) {
    final message = error is NodeException ? error.message : '$error';
    if (error != null && message != 'Server is not running.') {
      logForDebugging(
        'Error closing HTTP proxy server: $message',
        level: 'error',
      );
    }
    completer.complete();
  });
  return completer.future;
}

Future<void> _reset() async {
  // Windows: release this session's sandbox-user ACEs. Best-effort
  // — log anomalies rather than throw, so teardown always
  // completes. Leftover ACEs are recoverable later via
  // `srt-win acl recover` (which sweeps by trustee SID).
  if (_windowsFsStampedSet != null &&
      _windowsFsSbUserSid != null &&
      _windowsFsSbUserSid!.isNotEmpty) {
    final sb = _windowsFsSbUserSid!;
    // Captured at initialize() — the SAME binary the grants/stamps
    // were applied with, immune to `config` mutation between.
    final srtWin = _srtWinSpawn;
    // 'restored'/'alreadyOriginal' are the pre- same-user-removal
    // srt-win's success vocabulary; 'revoked'/'stillHeld' are the
    // post-. Either is non-anomalous.
    final ok = {'revoked', 'stillHeld', 'restored', 'alreadyOriginal'};
    void log(String kind, ({String path, String status}) e) {
      if (!ok.contains(e.status)) {
        logForDebugging(
          "[Sandbox Windows] $kind: '${e.path}' ${e.status} — "
          'ACE may be left in place; resolve and run '
          '`srt-win acl recover` to clear',
          level: 'warn',
        );
      }
    }

    for (final e
        in revokeWindowsAcl(sandboxUserSid: sb, srtWin: srtWin) ?? const []) {
      log('grant revoke', (path: e.path, status: e.status));
    }
    for (final e
        in restoreWindowsAcl(sandboxUserSid: sb, srtWin: srtWin) ?? const []) {
      log('deny restore', (path: e.path, status: e.status));
    }
  }
  _windowsFsStampedSet = null;
  _windowsFsSbUserSid = null;
  _windowsFsRawInputs = null;
  _srtWinSpawn = null;
  // windowsWfpVerified is NOT cleared — per-process, not per-session.

  // Clean up any leftover bwrap mount points. Force past the
  // active-sandbox counter — reset() means the session is over.
  cleanupBwrapMountPoints(force: true);

  // Stop log monitor
  if (_logMonitorShutdown != null) {
    _logMonitorShutdown!();
    _logMonitorShutdown = null;
  }
  if (_linuxMonitor != null) {
    _linuxMonitor!.stop();
    _linuxMonitor = null;
  }

  if (_managerContext?.linuxBridge != null) {
    final bridge = _managerContext!.linuxBridge!;
    final httpSocketPath = bridge.httpSocketPath;
    final socksSocketPath = bridge.socksSocketPath;
    final httpBridgeProcess = bridge.httpBridgeProcess;
    final socksBridgeProcess = bridge.socksBridgeProcess;

    // Kill both bridges and wait for them to exit
    await Future.wait([
      _killBridgeProcess(httpBridgeProcess, 'HTTP'),
      _killBridgeProcess(socksBridgeProcess, 'SOCKS'),
    ]);

    // Clean up sockets
    if (httpSocketPath.isNotEmpty) {
      try {
        fs.rmSync(httpSocketPath, {'force': true});
        logForDebugging('Cleaned up HTTP socket');
      } catch (err) {
        logForDebugging('HTTP socket cleanup error: $err', level: 'error');
      }
    }

    if (socksSocketPath.isNotEmpty) {
      try {
        fs.rmSync(socksSocketPath, {'force': true});
        logForDebugging('Cleaned up SOCKS socket');
      } catch (err) {
        logForDebugging('SOCKS socket cleanup error: $err', level: 'error');
      }
    }
  }

  // Close servers in parallel (only if they exist, i.e., were started by us)
  final closePromises = <Future<void>>[];

  if (_mitmCA != null) {
    closePromises.add(disposeMitmCA(_mitmCA!));
  }

  if (_muxProxyServer != null) {
    closePromises.add(
      _muxProxyServer!.close().catchError((Object error) {
        logForDebugging(
          'Error closing mux proxy server: ${error is NodeException ? error.message : error}',
          level: 'error',
        );
      }),
    );
  }

  if (_httpProxyServer != null) {
    closePromises.add(_forceCloseHttpServer(_httpProxyServer!));
  }

  if (_socksProxyServer != null) {
    final socksClose = _socksProxyServer!.close().catchError((Object error) {
      logForDebugging(
        'Error closing SOCKS proxy server: ${error is NodeException ? error.message : error}',
        level: 'error',
      );
    });
    closePromises.add(socksClose);
  }

  // Wait for all servers to close
  await Future.wait(closePromises);

  // Clear references
  _muxProxyServer = null;
  _httpProxyServer = null;
  _proxyAuthToken = null;
  _socksProxyServer = null;
  _managerContext = null;
  _initializationPromise = null;
  _parentProxy = null;
  _resolvedAddressGuard = createResolvedAddressGuard();
  _mitmCA = null;
  _javaAgentJarPath = null;
  _sentinelRegistry.clear();
  _awsPairRegistry.clear();
  _commandTextsByKey.clear();
  _commandNetworkListsByKey.clear();
  _maskedFileStore.dispose();
}

SandboxViolationStore _getSandboxViolationStore() {
  return _sandboxViolationStore;
}

String _annotateStderrWithSandboxFailures(String command, String stderr) {
  if (_config == null) {
    return stderr;
  }

  final violations = _sandboxViolationStore.getViolationsForCommand(command);
  if (violations.isEmpty) {
    return stderr;
  }

  var annotated = stderr;
  annotated += '$EOL<sandbox_violations>$EOL';
  for (final violation in violations) {
    annotated += violation.line + EOL;
  }
  annotated += '</sandbox_violations>';

  return annotated;
}

/// Returns glob patterns from Edit/Read permission rules that are not
/// fully supported on Linux. Returns empty array on macOS or when
/// sandboxing is disabled.
///
/// Patterns ending with /** are excluded since they work as subpaths.
/// So are entries marked literal. An entry that is also the name of a path
/// that exists is still returned: what is returned must not depend on what
/// is on the disk, which a sandboxed command can change.
List<String> _getLinuxGlobPatternWarnings() {
  // Only warn on Linux/WSL (bubblewrap doesn't support globs)
  // macOS supports glob patterns via regex conversion
  final config = _config;
  if (getPlatform() != 'linux' ||
      config == null ||
      config.filesystem.disabled == true) {
    return [];
  }

  final globPatterns = <String>[];

  // Write paths take no globs at all on Linux: bubblewrap binds concrete
  // paths, and nothing expands them.
  final allPaths = [
    ...config.filesystem.allowWrite,
    ...config.filesystem.denyWrite,
  ];

  for (final entry in allPaths) {
    if (entry is! FilesystemPathSpelling) continue;
    final path = entry.path;
    // Strip trailing /** since that's just a subpath (directory and everything under it)
    final pathWithoutTrailingStar = removeTrailingGlobSuffix(path);

    // Only warn if there are still glob characters after removing trailing /**
    if (containsGlobChars(pathWithoutTrailingStar)) {
      globPatterns.add(path);
    }
  }

  // Read paths are expanded, so a glob there is supported — unless the
  // pattern has no literal directory below the root for the walk to start
  // from (a wildcard in its first path component, `/**/*.pem`), which
  // expands to nothing and leaves the entry unenforced.
  for (final entry in <Object>[
    ...<Object>{
      ...config.filesystem.denyRead.map<Object>(
        (e) => e is FilesystemPathSpelling ? e.path : e,
      ),
      // Joins the read denies, and is skipped like one of them.
      ..._getCredentialDenyReadPaths(config.credentials),
    },
    ...(config.filesystem.allowRead ?? const []).map<Object>(
      (e) => e is FilesystemPathSpelling ? e.path : e,
    ),
  ]) {
    if (entry is! String) continue;
    final path = entry;
    final baseDir = globPatternBaseDir(normalizePathForSandbox(path));
    if (containsGlobChars(removeTrailingGlobSuffix(path)) &&
        globBaseDirIsRoot(baseDir)) {
      globPatterns.add(path);
    }
  }

  return globPatterns;
}

// ============================================================================
// Public API Interface
// ============================================================================

/**
 * Interface for the sandbox manager API
 */
abstract interface class ISandboxManager {
  Future<void> initialize(
    SandboxRuntimeConfig runtimeConfig, [
    SandboxAskCallback? sandboxAskCallback,
    bool? enableLogMonitor,
  ]);
  bool isSupportedPlatform();
  bool isSandboxingEnabled();
  SandboxDependencyCheck checkDependencies([
    ({String command, List<String>? args})? ripgrepConfig,
  ]);
  Future<SandboxDependencyCheck> checkDependenciesAsync([
    ({String command, List<String>? args})? ripgrepConfig,
  ]);
  FsReadRestrictionConfig getFsReadConfig();
  FsWriteRestrictionConfig getFsWriteConfig();
  NetworkRestrictionConfig getNetworkRestrictionConfig();
  List<String>? getAllowUnixSockets();
  bool? getAllowLocalBinding();
  List<String>? getAllowMachLookup();
  Map<String, List<String>>? getIgnoreViolations();
  bool? getEnableWeakerNestedSandbox();
  int? getProxyPort();
  String? getProxyAuthToken();
  int? getSocksProxyPort();
  String? getLinuxHttpSocketPath();
  String? getLinuxSocksSocketPath();
  Future<bool> waitForNetworkInitialization();
  Future<String> wrapWithSandbox(
    String command, [
    String? binShell,
    PartialSandboxRuntimeConfig? customConfig,
    AbortSignal? abortSignal,
    WrapWithSandboxOptions? options,
  ]);
  Future<({List<String> argv, Map<String, String?> env})> wrapWithSandboxArgv(
    String command, [
    Object? binShell, // String | WindowsBinShell
    PartialSandboxRuntimeConfig? customConfig,
    AbortSignal? abortSignal,
    String? cwd,
    WrapWithSandboxOptions? options,
  ]);
  /**
   * Register the network allow list of one invocation, under the `commandId`
   * its wrap was given ({@link WrapWithSandboxOptions}). Entries are matched
   * and validated as `network.allowedDomains` entries are; an invalid one
   * throws. Registering an id again replaces its list.
   *
   * Order of evaluation for a connection: a configured `deniedDomains` match
   * denies; a configured `allowedDomains` match allows;
   * `network.strictAllowlist` denies; a match in the list registered for the
   * id the connection presents allows; then the ask callback decides if
   * there is one, and otherwise the connection is denied. So a per-command
   * entry never overrides a configured `deniedDomains` entry and is ignored
   * entirely under `strictAllowlist`. It also never enters `network.*`, so
   * the default `injectHosts` scope of a masked credential does not grow.
   *
   * The proxy reads the id from the proxy username, which the sandboxed
   * client presents, so the id is the ONLY thing binding a connection to an
   * allow list. It MUST be unguessable: at least 128 bits of randomness (16
   * random bytes as base64url, 22 characters; a shorter id throws), never a
   * counter, a timestamp or anything derived from the command. Presenting
   * another live invocation's id gets that invocation's allows: this is
   * attribution, not a boundary between concurrent commands of one session.
   *
   * Register just before spawning the wrapped command, and unregister when
   * the child exits or never started: a registration that outlives its
   * command widens the window in which its id is worth presenting.
   *
   * As with every attribution key, only the first 100 characters of an id
   * take part, and a list under an id whose encoded form does not fit in the
   * proxy username (possible only with non-ASCII ids) never applies. An
   * unpaired surrogate does not count towards the 22 characters.
   *
   * No list applies while `network.httpProxyPort` names an external proxy:
   * the wrap gives that proxy no username, so no connection carries an id.
   * Registering still succeeds, and every connection is decided as if no list
   * existed.
   */
  void registerCommandNetworkLists(
    String commandId,
    ({List<String>? allowedDomains}) lists,
  );
  /**
   * Remove the list registered for `commandId`. A no-op for an id that has
   * none. `reset()` removes them all.
   */
  void unregisterCommandNetworkLists(String commandId);
  /**
   * True when the network filter understands an ask callback's
   * `{ allow: false, reason }` answer (see {@link SandboxAskCallback}). Read
   * it before returning that object: releases up to v0.0.77 allow on any
   * truthy answer, so there the object would be read as an allow. Where this
   * is absent, deny with a plain `false`.
   */
  bool get askCallbackDenyReason;
  SandboxViolationStore getSandboxViolationStore();
  String annotateStderrWithSandboxFailures(String command, String stderr);
  List<String> getLinuxGlobPatternWarnings();
  SandboxRuntimeConfig? getConfig();
  MitmCA? getMitmCA();
  SentinelRegistry getSentinelRegistry();
  AwsPairRegistry getAwsPairRegistry();
  MaskedFileStore getMaskedFileStore();
  void updateConfig(SandboxRuntimeConfig newConfig);
  void cleanupAfterCommand();
  Future<void> reset();
}

// ============================================================================
// Export as Namespace with Interface
// ============================================================================

/**
 * Global sandbox manager that handles both network and filesystem restrictions
 * for this session. This runs outside of the sandbox, on the host machine.
 */
final ISandboxManager SandboxManager = _SandboxManager();

/// The object literal upstream exports as `SandboxManager`.
class _SandboxManager implements ISandboxManager {
  @override
  Future<void> initialize(
    SandboxRuntimeConfig runtimeConfig, [
    SandboxAskCallback? sandboxAskCallback,
    bool? enableLogMonitor,
  ]) =>
      _initialize(runtimeConfig, sandboxAskCallback, enableLogMonitor ?? false);

  @override
  bool isSupportedPlatform() => _isSupportedPlatform();

  @override
  bool isSandboxingEnabled() => _isSandboxingEnabled();

  @override
  SandboxDependencyCheck checkDependencies([
    ({String command, List<String>? args})? ripgrepConfig,
  ]) => _checkDependencies(
    ripgrepConfig == null
        ? null
        : RipgrepConfig(
            command: ripgrepConfig.command,
            args: ripgrepConfig.args,
          ),
  );

  @override
  Future<SandboxDependencyCheck> checkDependenciesAsync([
    ({String command, List<String>? args})? ripgrepConfig,
  ]) => _checkDependenciesAsync(
    ripgrepConfig == null
        ? null
        : RipgrepConfig(
            command: ripgrepConfig.command,
            args: ripgrepConfig.args,
          ),
  );

  @override
  FsReadRestrictionConfig getFsReadConfig() => _getFsReadConfig();

  @override
  FsWriteRestrictionConfig getFsWriteConfig() => _getFsWriteConfig();

  @override
  NetworkRestrictionConfig getNetworkRestrictionConfig() =>
      _getNetworkRestrictionConfig();

  @override
  List<String>? getAllowUnixSockets() => _getAllowUnixSockets();

  @override
  bool? getAllowLocalBinding() => _getAllowLocalBinding();

  @override
  List<String>? getAllowMachLookup() => _getAllowMachLookup();

  @override
  Map<String, List<String>>? getIgnoreViolations() => _getIgnoreViolations();

  @override
  bool? getEnableWeakerNestedSandbox() => _getEnableWeakerNestedSandbox();

  @override
  int? getProxyPort() => _getProxyPort();

  @override
  String? getProxyAuthToken() => _getProxyAuthToken();

  @override
  int? getSocksProxyPort() => _getSocksProxyPort();

  @override
  String? getLinuxHttpSocketPath() => _getLinuxHttpSocketPath();

  @override
  String? getLinuxSocksSocketPath() => _getLinuxSocksSocketPath();

  @override
  Future<bool> waitForNetworkInitialization() =>
      _waitForNetworkInitialization();

  @override
  Future<String> wrapWithSandbox(
    String command, [
    String? binShell,
    PartialSandboxRuntimeConfig? customConfig,
    AbortSignal? abortSignal,
    WrapWithSandboxOptions? options,
  ]) => _wrapWithSandbox(command, binShell, customConfig, abortSignal, options);

  @override
  Future<({List<String> argv, Map<String, String?> env})> wrapWithSandboxArgv(
    String command, [
    Object? binShell, // String | WindowsBinShell
    PartialSandboxRuntimeConfig? customConfig,
    AbortSignal? abortSignal,
    String? cwd,
    WrapWithSandboxOptions? options,
  ]) => _wrapWithSandboxArgv(
    command,
    binShell,
    customConfig,
    abortSignal,
    cwd,
    options,
  );

  @override
  void registerCommandNetworkLists(
    String commandId,
    ({List<String>? allowedDomains}) lists,
  ) => _registerCommandNetworkLists(commandId, lists);

  @override
  void unregisterCommandNetworkLists(String commandId) =>
      _unregisterCommandNetworkLists(commandId);

  @override
  bool get askCallbackDenyReason => true;

  @override
  void cleanupAfterCommand() => _cleanupAfterCommand();

  @override
  Future<void> reset() => _reset();

  @override
  MitmCA? getMitmCA() => _mitmCA;

  @override
  SentinelRegistry getSentinelRegistry() => _sentinelRegistry;

  @override
  AwsPairRegistry getAwsPairRegistry() => _awsPairRegistry;

  @override
  MaskedFileStore getMaskedFileStore() => _maskedFileStore;

  @override
  SandboxViolationStore getSandboxViolationStore() =>
      _getSandboxViolationStore();

  @override
  String annotateStderrWithSandboxFailures(String command, String stderr) =>
      _annotateStderrWithSandboxFailures(command, stderr);

  @override
  List<String> getLinuxGlobPatternWarnings() => _getLinuxGlobPatternWarnings();

  @override
  SandboxRuntimeConfig? getConfig() => _getConfig();

  @override
  void updateConfig(SandboxRuntimeConfig newConfig) => _updateConfig(newConfig);
}
