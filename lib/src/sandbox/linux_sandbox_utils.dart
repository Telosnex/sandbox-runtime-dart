// STUB: pending port of src/sandbox/linux-sandbox-utils.ts @ 24eb39e.
// ignore_for_file: slash_for_doc_comments, constant_identifier_names
// ignore_for_file: doc_directive_unknown

import '../node/abort.dart';
import '../node/child_process.dart' as child_process;
import 'sandbox_config.dart' show SeccompConfig;
import 'sandbox_schemas.dart'
    show FsReadRestrictionConfig, FsWriteRestrictionConfig;
import '../utils/ripgrep.dart' show RipgrepConfig;

class LinuxNetworkBridgeContext {
  final String httpSocketPath;
  final String socksSocketPath;
  final child_process.NodeChildProcess httpBridgeProcess;
  final child_process.NodeChildProcess socksBridgeProcess;
  final int httpProxyPort;
  final int socksProxyPort;

  const LinuxNetworkBridgeContext({
    required this.httpSocketPath,
    required this.socksSocketPath,
    required this.httpBridgeProcess,
    required this.socksBridgeProcess,
    required this.httpProxyPort,
    required this.socksProxyPort,
  });
}

class LinuxSandboxParams {
  final String command;

  /** Attribution key encoded for violation correlation; defaults to
   *  `command`. See MacOSSandboxParams.commandId. */
  final String? commandId;
  final bool needsNetworkRestriction;
  final String? httpSocketPath;
  final String? socksSocketPath;
  final int? httpProxyPort;
  final int? socksProxyPort;

  /** Per-session proxy auth token; embedded in proxy env URLs. */
  final String? proxyAuthToken;

  /** Path to the TLS-termination CA cert; injected as trust env vars. */
  final String? caCertPath;

  /** Path to the JVM proxy agent jar; injected via JAVA_TOOL_OPTIONS. */
  final String? javaAgentJarPath;
  final FsReadRestrictionConfig? readConfig;
  final FsWriteRestrictionConfig? writeConfig;

  /** Environment variable names to unset inside the sandbox (bwrap --unsetenv) */
  final List<String>? unsetEnvVars;

  /** Environment variables to set inside the sandbox (bwrap --setenv NAME VALUE) */
  final Map<String, String>? setEnvVars;

  /**
   * Whole-file credential masks: bind fakePath (sentinel content) over
   * realPath read-only so the sandbox reads the sentinel.
   */
  final List<({String realPath, String fakePath})>? maskedFileBinds;

  /**
   * Host directory holding the fake files. Ro-bound over itself so the
   * sandbox cannot write the bind sources even if allowWrite covers it.
   */
  final String? maskedFileStoreDir;
  final bool? enableWeakerNestedSandbox;
  final bool? allowAllUnixSockets;
  final String? binShell;
  final RipgrepConfig? ripgrepConfig;

  /** Maximum directory depth to search for dangerous files (default: 3) */
  final int? mandatoryDenySearchDepth;

  /** Allow writes to .git/config files (default: false) */
  final bool? allowGitConfig;

  /**
   * Directories to emit as `safe.directory` via `GIT_CONFIG_*` env
   * vars (see {@link buildPosixGitSafeDirEnv}). Under `--unshare-user`
   * the repo owner's uid is unmapped inside the sandbox, so git
   * refuses with "detected dubious ownership" without this.
   */
  final List<String>? gitSafeDirectories;

  /** Custom seccomp binary paths */
  final SeccompConfig? seccompConfig;

  /** Absolute path to the bwrap binary (default: resolve "bwrap" via PATH) */
  final String? bwrapPath;

  /** Absolute path to the socat binary (default: resolve "socat" via PATH) */
  final String? socatPath;

  /**
   * Filesystem unix socket bound by the Linux violation monitor. When set,
   * the socket is bind-mounted into the sandbox and apply-seccomp is told
   * (via SRT_OBSERVE_SOCK) to install a USER_NOTIF observation filter and
   * stream observed write-intent paths over that socket as newline JSON.
   */
  final String? observeSocketPath;

  /** Abort signal to cancel the ripgrep scan */
  final AbortSignal? abortSignal;

  const LinuxSandboxParams({
    required this.command,
    this.commandId,
    required this.needsNetworkRestriction,
    this.httpSocketPath,
    this.socksSocketPath,
    this.httpProxyPort,
    this.socksProxyPort,
    this.proxyAuthToken,
    this.caCertPath,
    this.javaAgentJarPath,
    this.readConfig,
    this.writeConfig,
    this.unsetEnvVars,
    this.setEnvVars,
    this.maskedFileBinds,
    this.maskedFileStoreDir,
    this.enableWeakerNestedSandbox,
    this.allowAllUnixSockets,
    this.binShell,
    this.ripgrepConfig,
    this.mandatoryDenySearchDepth,
    this.allowGitConfig,
    this.gitSafeDirectories,
    this.seccompConfig,
    this.bwrapPath,
    this.socatPath,
    this.observeSocketPath,
    this.abortSignal,
  });
}

/**
 * The part of the mandatory deny set that follows from the cwd alone: the
 * dangerous files and directories resolved against it, plus `.git/hooks` and
 * (unless the caller allows git config) `.git/config`.
 * {@link linuxGetMandatoryDenyPaths} adds the nested matches its ripgrep scan
 * finds on top of these. Split out so a consumer that must not scan — the
 * violation monitor, which needs the same denies to judge a write bwrap
 * refuses — reads the same definition rather than a copy of it.
 */
List<String> linuxGetCwdMandatoryDenyPaths([bool allowGitConfig = false]) =>
    throw UnimplementedError(
      'pending port of src/sandbox/linux-sandbox-utils.ts',
    );

/**
 * The directories below `cwd`, down to `maxDepth`, that ripgrep said it could
 * not read, that this process cannot read either, and whose mode is this
 * user's to change. What is in one is not known, so the caller denies it whole.
 * Exported for testing.
 */
List<String> unreadableDirectories(String stderr, String cwd, int maxDepth) =>
    throw UnimplementedError(
      'pending port of src/sandbox/linux-sandbox-utils.ts',
    );

const int CAP_SETFCAP = 31;

/**
 * Whether this process holds `cap` in its bounding or inheritable set (Linux).
 *
 * bwrap is reached by execve, and for a euid-0 caller the kernel recomputes
 * the new permitted set from the bounding and inheritable sets, discarding
 * what the caller itself had permitted. Those two sets are therefore what
 * decides which capabilities bwrap holds when it writes its uid map; CapPrm
 * and CapEff do not, and for any process itself reached by exec as root they
 * merely repeat the union.
 */
bool processHasBoundingCapability(int cap) => throw UnimplementedError(
  'pending port of src/sandbox/linux-sandbox-utils.ts',
);

/**
 * The capability set an execve gives a euid-0 caller's child, parsed out of a
 * `/proc/<pid>/status`: CapBnd unioned with CapInh. `undefined` when either
 * line is absent. CapPrm and CapEff are deliberately not consulted — see
 * processHasBoundingCapability.
 */
BigInt? boundingCapabilitiesFromStatus(String status) =>
    throw UnimplementedError(
      'pending port of src/sandbox/linux-sandbox-utils.ts',
    );

/**
 * The bwrap capability list. Always `--cap-drop ALL`, which for a non-root
 * caller is bwrap's default anyway. `--cap-add CAP_SETFCAP` for the whole
 * bwrap invocation — the outer shell and the two socat relays hold it too —
 * when the caller is uid 0, the seccomp helper is in use and the capability
 * survives into bwrap: the helper's nested user namespace maps uid 0, which
 * Linux 5.12 and the distribution kernels that backported it allow only from
 * a creator holding CAP_SETFCAP. Under the helper a uid-0 caller's command
 * therefore has a full set inside that nested namespace, which is
 * identity-mapped to the caller's uid 0, and the filesystem policy there
 * rests on the nested namespace's mount copies being locked. Without the
 * helper (`allowAllUnixSockets`, or no usable helper binary) the command runs
 * in bwrap's own namespaces and `--cap-drop ALL` is what stops it unmounting
 * a deny.
 *
 * Pure: `hasSetfcap` is decided by the caller, which is also where the
 * missing-capability case is reported once per process.
 */
List<String> capabilityArgs({
  required int? euid,
  required bool hasSetfcap,
  required bool usesSeccompHelper,
}) => throw UnimplementedError(
  'pending port of src/sandbox/linux-sandbox-utils.ts',
);

const String CAP_SETFCAP_MISSING_MESSAGE =
    "running as uid 0 without CAP_SETFCAP in this process's capability bounding set - on "
    'kernels that enforce the CAP_SETFCAP requirement for mapping uid 0 into a user namespace '
    '(Linux 5.12 and distribution backports) every sandboxed command fails while writing a uid '
    'map ("Operation not permitted"). Grant CAP_SETFCAP to this process, or run as a non-root user';

/** Why a bubblewrap profile could not be run. */
typedef LinuxSandboxProfileErrorCode = String;

/** More arguments than bubblewrap parses, on the line or through a file. */
/** A mount path holds a NUL byte, which no carrier of arguments can hold. */
/**
 * No unnamed file could be opened to carry the mounts: passing (this
 * process is out of descriptors) or lasting (no directory on this host
 * takes one). The error on `.cause` names each directory tried and what it
 * said.
 */
/** The line does not fit one shell argument even with the mounts in a file. */

/**
 * Thrown when a Linux bubblewrap profile cannot be run on this host: what the
 * configuration expands to, with the mandatory denies of the working
 * directory, is past a limit, or, for `command_too_long` and `nul_in_path`,
 * what the caller passed in is. The command was not run and no
 * profile file stays open, so do not run the per-command cleanup
 * (`cleanupAfterCommand()`, `cleanupBwrapMountPoints()`) for a wrap that
 * threw: it would release a second time, and a sandbox still running would
 * lose its mount points. Branch on `.code`, never on `.message`, which
 * carries the sizes of the moment. Other wrap-time failures (a shell that is
 * not on PATH, a bridge socket that is gone) are plain Errors.
 */
class LinuxSandboxProfileError extends Error {
  LinuxSandboxProfileError(this.code, this.message, [this.cause])
    : name = 'LinuxSandboxProfileError';

  final LinuxSandboxProfileErrorCode code;
  final Object? cause;
  String message;
  String name;

  @override
  String toString() => 'LinuxSandboxProfileError: $message';
}

/**
 * Thrown by the wrap when the host changed its working directory while the
 * mandatory denies were looked for. Nothing has been handed out or left on
 * the host by then. `SandboxManager` starts the wrap over.
 */
class WorkingDirectoryChanged extends Error {
  WorkingDirectoryChanged()
    : message =
          'The working directory changed while the command was being wrapped',
      name = 'WorkingDirectoryChanged';

  String message;
  String name;

  @override
  String toString() => 'WorkingDirectoryChanged: $message';
}

/**
 * Clean up mount point files created by bwrap for non-existent deny paths.
 *
 * When protecting non-existent deny paths, bwrap creates empty files on the
 * host filesystem as mount points for --ro-bind. These files persist after
 * bwrap exits. This function removes them.
 *
 * This should be called after each sandboxed command completes to prevent
 * ghost dotfiles (e.g. .bashrc, .gitconfig) from appearing in the working
 * directory. It is also called automatically on process exit as a safety net.
 *
 * Each call decrements the active-sandbox counter that was incremented by
 * wrapCommandWithSandboxLinux(). File deletion is deferred until the counter
 * reaches zero. Deleting a mount point file on the host while another bwrap
 * instance is still running detaches that instance's bind mount (the dentry
 * is unhashed, so path lookup no longer finds the mount) and the deny rule
 * stops applying inside that sandbox.
 *
 * Pass `{ force: true }` to delete unconditionally — used by the process-exit
 * handler and reset() where deferral is not meaningful.
 *
 * Also closes the `--args` profiles the wraps of this batch opened.
 */
void cleanupBwrapMountPoints({bool force = false}) => throw UnimplementedError(
  'pending port of src/sandbox/linux-sandbox-utils.ts',
);

/**
 * Detailed status of Linux sandbox dependencies
 */
class LinuxDependencyStatus {
  final bool hasBwrap;
  final bool hasSocat;
  final bool hasSeccompApply;

  const LinuxDependencyStatus({
    required this.hasBwrap,
    required this.hasSocat,
    required this.hasSeccompApply,
  });
}

/**
 * Result of checking sandbox dependencies
 */
class SandboxDependencyCheck {
  final List<String> warnings;
  final List<String> errors;

  const SandboxDependencyCheck({required this.warnings, required this.errors});
}

/**
 * Options for Linux dependency checks. Explicit binary paths, when set,
 * are checked directly instead of resolving via PATH.
 */
class LinuxDependencyOptions {
  final SeccompConfig? seccompConfig;
  final String? bwrapPath;
  final String? socatPath;

  const LinuxDependencyOptions({
    this.seccompConfig,
    this.bwrapPath,
    this.socatPath,
  });
}

/**
 * Get detailed status of Linux sandbox dependencies
 */
LinuxDependencyStatus getLinuxDependencyStatus([
  LinuxDependencyOptions? opts,
]) => throw UnimplementedError(
  'pending port of src/sandbox/linux-sandbox-utils.ts',
);

/**
 * Check sandbox dependencies and return structured result
 */
SandboxDependencyCheck checkLinuxDependencies([LinuxDependencyOptions? opts]) =>
    throw UnimplementedError(
      'pending port of src/sandbox/linux-sandbox-utils.ts',
    );

/**
 * The oldest bubblewrap on which everything this library does holds. Mount
 * plans start on 0.4.0 and later, but before 0.5.0 `ensure_file()` takes
 * only a regular file as a file bind's mount point, so a mask on a fifo,
 * socket or device node blocks or fails.
 */
const String OLDEST_FULLY_SUPPORTED_BWRAP_VERSION = '0.5.0';

/**
 * Predict, then confirm. The prediction — uid 0 with no CAP_SETFCAP to hand
 * to bwrap — is exact about the capability but not about the kernel, so ask
 * bubblewrap itself before failing the caller's initialize(). An error, not a
 * warning: if it holds, every sandboxed command fails.
 *
 * `bwrap === null` skips the probe: a missing or unusable bubblewrap is
 * already its own dependency error, and a second one about capabilities would
 * only misdirect.
 */
String? uid0SandboxError({
  required int? euid,
  required bool hasSetfcap,
  required String? bwrap,
}) => throw UnimplementedError(
  'pending port of src/sandbox/linux-sandbox-utils.ts',
);

/**
 * Initialize the Linux network bridge for sandbox networking
 *
 * ARCHITECTURE NOTE:
 * Linux network sandboxing uses bwrap --unshare-net which creates a completely isolated
 * network namespace with NO network access. To enable network access, we:
 *
 * 1. Host side: Run socat bridges that listen on Unix sockets and forward to host proxy servers
 *    - HTTP bridge: Unix socket -> host HTTP proxy (for HTTP/HTTPS traffic)
 *    - SOCKS bridge: Unix socket -> host SOCKS5 proxy (for SSH/git traffic)
 *
 * 2. Sandbox side: Bind the Unix sockets into the isolated namespace and run socat listeners
 *    - HTTP listener on port 3128 -> HTTP Unix socket -> host HTTP proxy
 *    - SOCKS listener on port 1080 -> SOCKS Unix socket -> host SOCKS5 proxy
 *
 * 3. Configure environment:
 *    - HTTP_PROXY=http://localhost:3128 for HTTP/HTTPS tools
 *    - GIT_SSH_COMMAND with socat for SSH through SOCKS5
 *
 * LIMITATION: Unlike macOS sandbox which can enforce domain-based allowlists at the kernel level,
 * Linux's --unshare-net provides only all-or-nothing network isolation. Domain filtering happens
 * at the host proxy level, not the sandbox boundary. This means network restrictions on Linux
 * depend on the proxy's filtering capabilities.
 *
 * DEPENDENCIES: Requires bwrap (bubblewrap) and socat
 */
Future<LinuxNetworkBridgeContext> initializeLinuxNetworkBridge(
  int httpProxyPort,
  int socksProxyPort, [
  String? socatPath,
]) => throw UnimplementedError(
  'pending port of src/sandbox/linux-sandbox-utils.ts',
);

/**
 * Wrap a command with sandbox restrictions on Linux
 *
 * UNIX SOCKET BLOCKING (APPLY-SECCOMP):
 * This implementation uses a custom apply-seccomp binary to block Unix domain socket
 * creation for user commands while allowing network infrastructure:
 *
 * The two stages are described in README.md, "Unix Socket Restrictions
 * (Linux)".
 *
 * This solves the conflict between:
 * - Security: Blocking arbitrary Unix socket creation in user commands
 * - Functionality: Network sandboxing requires socat to call socket(AF_UNIX, ...) for bridge connections
 *
 * The seccomp-bpf filter blocks socket(AF_UNIX, ...) syscalls, preventing:
 * - Creating new Unix domain socket file descriptors
 *
 * It also blocks socket(AF_VSOCK, ...): the network namespace does not fence
 * VM sockets, so one would reach out of the sandbox past the proxies.
 *
 * Security limitations:
 * - Does NOT block operations (bind, connect, sendto, etc.) on inherited Unix socket FDs
 * - Does NOT prevent passing Unix socket FDs via SCM_RIGHTS
 * - For most sandboxing use cases, blocking socket creation is sufficient
 *
 * The filter allows:
 * - All TCP/UDP sockets (AF_INET, AF_INET6) for normal network operations
 * - All other syscalls
 *
 * PLATFORM NOTE:
 * The allowUnixSockets configuration is not path-based on Linux (unlike macOS)
 * because seccomp-bpf cannot inspect user-space memory to read socket paths.
 *
 * Requirements for seccomp filtering:
 * - Pre-built apply-seccomp binaries are included for x64 and ARM64
 * - Pre-generated BPF filters are included for x64 and ARM64
 * - Other architectures are not currently supported (no apply-seccomp binary available)
 * - To use sandboxing without Unix socket blocking on unsupported architectures,
 *   set allowAllUnixSockets: true in your configuration
 * Dependencies are checked by checkLinuxDependencies() before enabling the sandbox.
 *
 * CALLER OBLIGATION: the euid and capability decisions behind the returned
 * string are made here, in the process that builds it, so the string must be
 * run by a process with the same euid and the same capability bounding and
 * inheritable sets.
 */
Future<String> wrapCommandWithSandboxLinux(LinuxSandboxParams params) =>
    throw UnimplementedError(
      'pending port of src/sandbox/linux-sandbox-utils.ts',
    );
