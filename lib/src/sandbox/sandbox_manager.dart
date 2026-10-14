// STUB: pending port of src/sandbox/sandbox-manager.ts @ 24eb39e.
// ignore_for_file: non_constant_identifier_names
// ignore_for_file: doc_directive_unknown, slash_for_doc_comments

import '../node/abort.dart';
import 'credential_aws_pairs.dart' show AwsPairRegistry;
import 'credential_mask_files.dart' show MaskedFileStore;
import 'credential_sentinel.dart' show SentinelRegistry;
import 'linux_sandbox_utils.dart' show SandboxDependencyCheck;
import 'mitm_ca.dart' show MitmCA;
import 'sandbox_config.dart'
    show
        CredentialsConfig,
        FilesystemConfig,
        GitConfig,
        IgnoreViolationsConfig,
        NetworkConfig,
        RipgrepConfig,
        SandboxRuntimeConfig,
        SeccompConfig,
        WindowsConfig;
import 'sandbox_schemas.dart'
    show
        FsReadRestrictionConfig,
        FsWriteRestrictionConfig,
        NetworkRestrictionConfig,
        SandboxAskCallback;
import 'sandbox_violation_store.dart' show SandboxViolationStore;

/** Exported for testing. */
void registerCommandText(String command, WrapWithSandboxOptions? options) =>
    throw UnimplementedError('pending port of src/sandbox/sandbox-manager.ts');

/**
 * The command text for a decoded attribution key. Keys arrive over carriers
 * the sandboxed process can write (the observe socket's event field, the
 * macOS log tag, the proxy username), so only a key this process registered
 * carries the embedder's own text; anything else is untrusted bytes.
 * Exported for testing.
 */
String resolveCommandText(String decodedKey) =>
    throw UnimplementedError('pending port of src/sandbox/sandbox-manager.ts');

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

/**
 * Global sandbox manager that handles both network and filesystem restrictions
 * for this session. This runs outside of the sandbox, on the host machine.
 */
final ISandboxManager SandboxManager = _SandboxManager();

class _SandboxManager implements ISandboxManager {
  @override
  Future<void> initialize(
    SandboxRuntimeConfig runtimeConfig, [
    SandboxAskCallback? sandboxAskCallback,
    bool? enableLogMonitor,
  ]) => throw UnimplementedError(
    'pending port of src/sandbox/sandbox-manager.ts',
  );

  @override
  bool isSupportedPlatform() => throw UnimplementedError(
    'pending port of src/sandbox/sandbox-manager.ts',
  );

  @override
  bool isSandboxingEnabled() => throw UnimplementedError(
    'pending port of src/sandbox/sandbox-manager.ts',
  );

  @override
  SandboxDependencyCheck checkDependencies([
    ({String command, List<String>? args})? ripgrepConfig,
  ]) => throw UnimplementedError(
    'pending port of src/sandbox/sandbox-manager.ts',
  );

  @override
  Future<SandboxDependencyCheck> checkDependenciesAsync([
    ({String command, List<String>? args})? ripgrepConfig,
  ]) => throw UnimplementedError(
    'pending port of src/sandbox/sandbox-manager.ts',
  );

  @override
  FsReadRestrictionConfig getFsReadConfig() => throw UnimplementedError(
    'pending port of src/sandbox/sandbox-manager.ts',
  );

  @override
  FsWriteRestrictionConfig getFsWriteConfig() => throw UnimplementedError(
    'pending port of src/sandbox/sandbox-manager.ts',
  );

  @override
  NetworkRestrictionConfig getNetworkRestrictionConfig() =>
      throw UnimplementedError(
        'pending port of src/sandbox/sandbox-manager.ts',
      );

  @override
  List<String>? getAllowUnixSockets() => throw UnimplementedError(
    'pending port of src/sandbox/sandbox-manager.ts',
  );

  @override
  bool? getAllowLocalBinding() => throw UnimplementedError(
    'pending port of src/sandbox/sandbox-manager.ts',
  );

  @override
  List<String>? getAllowMachLookup() => throw UnimplementedError(
    'pending port of src/sandbox/sandbox-manager.ts',
  );

  @override
  Map<String, List<String>>? getIgnoreViolations() => throw UnimplementedError(
    'pending port of src/sandbox/sandbox-manager.ts',
  );

  @override
  bool? getEnableWeakerNestedSandbox() => throw UnimplementedError(
    'pending port of src/sandbox/sandbox-manager.ts',
  );

  @override
  int? getProxyPort() => throw UnimplementedError(
    'pending port of src/sandbox/sandbox-manager.ts',
  );

  @override
  String? getProxyAuthToken() => throw UnimplementedError(
    'pending port of src/sandbox/sandbox-manager.ts',
  );

  @override
  int? getSocksProxyPort() => throw UnimplementedError(
    'pending port of src/sandbox/sandbox-manager.ts',
  );

  @override
  String? getLinuxHttpSocketPath() => throw UnimplementedError(
    'pending port of src/sandbox/sandbox-manager.ts',
  );

  @override
  String? getLinuxSocksSocketPath() => throw UnimplementedError(
    'pending port of src/sandbox/sandbox-manager.ts',
  );

  @override
  Future<bool> waitForNetworkInitialization() => throw UnimplementedError(
    'pending port of src/sandbox/sandbox-manager.ts',
  );

  @override
  Future<String> wrapWithSandbox(
    String command, [
    String? binShell,
    PartialSandboxRuntimeConfig? customConfig,
    AbortSignal? abortSignal,
    WrapWithSandboxOptions? options,
  ]) => throw UnimplementedError(
    'pending port of src/sandbox/sandbox-manager.ts',
  );

  @override
  Future<({List<String> argv, Map<String, String?> env})> wrapWithSandboxArgv(
    String command, [
    Object? binShell, // String | WindowsBinShell
    PartialSandboxRuntimeConfig? customConfig,
    AbortSignal? abortSignal,
    String? cwd,
    WrapWithSandboxOptions? options,
  ]) => throw UnimplementedError(
    'pending port of src/sandbox/sandbox-manager.ts',
  );

  @override
  void registerCommandNetworkLists(
    String commandId,
    ({List<String>? allowedDomains}) lists,
  ) => throw UnimplementedError(
    'pending port of src/sandbox/sandbox-manager.ts',
  );

  @override
  void unregisterCommandNetworkLists(String commandId) =>
      throw UnimplementedError(
        'pending port of src/sandbox/sandbox-manager.ts',
      );

  @override
  bool get askCallbackDenyReason => true;

  @override
  SandboxViolationStore getSandboxViolationStore() => throw UnimplementedError(
    'pending port of src/sandbox/sandbox-manager.ts',
  );

  @override
  String annotateStderrWithSandboxFailures(String command, String stderr) =>
      throw UnimplementedError(
        'pending port of src/sandbox/sandbox-manager.ts',
      );

  @override
  List<String> getLinuxGlobPatternWarnings() => throw UnimplementedError(
    'pending port of src/sandbox/sandbox-manager.ts',
  );

  @override
  SandboxRuntimeConfig? getConfig() => throw UnimplementedError(
    'pending port of src/sandbox/sandbox-manager.ts',
  );

  @override
  MitmCA? getMitmCA() => throw UnimplementedError(
    'pending port of src/sandbox/sandbox-manager.ts',
  );

  @override
  SentinelRegistry getSentinelRegistry() => throw UnimplementedError(
    'pending port of src/sandbox/sandbox-manager.ts',
  );

  @override
  AwsPairRegistry getAwsPairRegistry() => throw UnimplementedError(
    'pending port of src/sandbox/sandbox-manager.ts',
  );

  @override
  MaskedFileStore getMaskedFileStore() => throw UnimplementedError(
    'pending port of src/sandbox/sandbox-manager.ts',
  );

  @override
  void updateConfig(SandboxRuntimeConfig newConfig) => throw UnimplementedError(
    'pending port of src/sandbox/sandbox-manager.ts',
  );

  @override
  void cleanupAfterCommand() => throw UnimplementedError(
    'pending port of src/sandbox/sandbox-manager.ts',
  );

  @override
  Future<void> reset() => throw UnimplementedError(
    'pending port of src/sandbox/sandbox-manager.ts',
  );
}
