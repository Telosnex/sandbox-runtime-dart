// Ported from sandbox-runtime src/sandbox/mxc-sandbox-utils.ts @ 0bbebed.
// ignore_for_file: doc_directive_unknown, dangling_library_doc_comments, curly_braces_in_flow_control_structures, prefer_adjacent_string_concatenation, overridden_fields
// ignore_for_file: constant_identifier_names, slash_for_doc_comments, unused_element
/**
 * MXC BaseContainer backend for Windows, chosen by the caller with
 * `windows.backend: 'mxc'`.
 *
 * On hosts whose Windows build supports MXC's **BaseContainer** tier,
 * sandboxed commands start through the `@microsoft/mxc-sdk` Node API,
 * in this process: the OS applies filesystem and network policy in its
 * own elevated context, with no install step, no UAC, no ACL stamping,
 * and policy lifetime bound to the container. MXC's AppContainer tiers
 * are never used: srt-win's WFP fence is mandatory and fail-closed,
 * where MXC's AppContainer network enforcement is cooperative.
 *
 * The SDK starts the process itself, so this backend has no argv form:
 * callers use `SandboxManager.spawnSandboxed()`, and
 * `wrapWithSandboxArgv()` refuses.
 *
 * `network.tlsTerminate` is not supported here: Schannel clients in a
 * BaseContainer do not trust the MITM CA.
 *
 * ── Fail closed ──────────────────────────────────────────────────────
 *
 * Every spawn first runs the SDK's request-aware `probe()` on the exact
 * request it is about to start. The probe runs MXC's own tier detector,
 * the same code that picks the tier at spawn time. Anything other than
 * a clean `base-container` answer that supports every restriction in
 * the request (denied paths, the host proxy, clipboard and input
 * injection blocking) refuses the spawn. Nothing retries with a weaker
 * request and nothing falls back to srt-win.
 *
 * Residual risk: tier selection runs again inside `spawn()`. If the
 * machine changed between the two calls, MXC could pick an AppContainer
 * tier rather than fail. The calls are milliseconds apart.
 *
 * ── Policy mapping ───────────────────────────────────────────────────
 *
 * srt's cross-platform contract: writes are an ALLOW-list
 * (`filesystem.allowWrite`), reads are a DENY-list
 * (`filesystem.denyRead`, readable everywhere else). BaseContainer is
 * default-deny in both directions, so:
 *
 *   - reads:  `readonlyPaths: [<system drive root>, cwd, ...allowRead]`
 *     restores read-everywhere, then `deniedPaths: denyRead ∪
 *     credential-file denies` carves the deny-list out.
 *     Only the system drive is granted: other fixed drives are
 *     unreadable unless listed in allowRead.
 *   - writes: `readwritePaths: [...allowWrite, %TEMP%]`. %TEMP% is
 *     granted for parity with macOS/Linux (TMPDIR is always writable).
 *     cwd is NOT auto-granted, as on every other platform.
 *   - MXC resolves overlapping entries by path specificity, whatever
 *     the list order: a grant beneath a denied path is accessible and
 *     the rest of the deny stays denied, which is srt's ranking (a
 *     grant beneath a deny outranks it). So the lists go as they are.
 *   - denyWrite: mapped into `deniedPaths` too, which over-denies
 *     (BaseContainer has no write-only deny, so reads on those paths
 *     are lost as well).
 *   - network: `egress.default: 'deny'`; with a proxy configured,
 *     `ingress.default: 'allow'` + `ingress.hostLoopback: 'allow'` and
 *     `runtimeConfig.networkProxy` naming the proxy port as the only
 *     way out (MXC 1.0's host proxy without a peer identity). srt's
 *     proxy does the domain filtering exactly as on macOS/Linux.
 *   - UI: on for every command (see {@link buildMxcRequest}), with
 *     clipboard and input injection blocked.
 */

import 'package:path/path.dart' as path;

import '../node/stream.dart' as stream;
import '../node/process.dart' as process;
import '../node/errno.dart' show errorMessage;
import '../node/fs.dart' as fs;
import '../utils/debug.dart';
import 'sandbox_utils.dart';
import 'windows_sandbox_utils.dart';

const _MXC_PKG = '@microsoft/mxc-sdk';
const _MXC_V1 = '$_MXC_PKG/v1';

// ────────────────────────────────────────────────────────────────────────
// The SDK surface srt uses. `@microsoft/mxc-sdk` is an optional peer
// dependency that only installs on Node 24+, so srt cannot compile
// against its types; these mirror the subset of `@microsoft/mxc-sdk/v1`
// (`ContainerRequest`, `ProbeOutput`, `MxcProcess`) srt reads and
// writes. Keep them in step with the pinned SDK major.
// ────────────────────────────────────────────────────────────────────────

/** Mirrors the subset of the SDK's v1 `ContainerRequest` srt sends. */
class MxcRequest {
  /** One command line, handed to the OS verbatim. */
  final String command;
  final ({
    List<String> readwritePaths,
    List<String> readonlyPaths,
    List<String> deniedPaths,
  })
  filesystem;
  final ({
    ({String defaultAction}) egress,
    ({String defaultAction, String hostLoopback}) ingress,
    ({String networkProxy})? runtimeConfig,
  })
  network;
  final ({bool disable, String clipboard, bool allowInputInjection}) ui;
  /** Milliseconds; omitted = no timeout. */
  final int? timeoutMs;
  final String workingDirectory;
  final Map<String, String> environment;
  /** Always false: the child gets exactly `environment`. */
  final bool inheritDefaultEnvironment;
  const MxcRequest({
    required this.command,
    required this.filesystem,
    required this.network,
    required this.ui,
    this.timeoutMs,
    required this.workingDirectory,
    required this.environment,
    required this.inheritDefaultEnvironment,
  });
}

/** Mirrors the SDK's `UiCapabilitySupport` fields srt checks. */
class MxcUiCapabilities {
  final bool canBlockClipboardRead;
  final bool canBlockClipboardWrite;
  final bool canBlockInputInjection;
  const MxcUiCapabilities({
    required this.canBlockClipboardRead,
    required this.canBlockClipboardWrite,
    required this.canBlockInputInjection,
  });
}

/** Mirrors the SDK's `ProbeOutput` fields srt checks. */
class MxcProbeOutput {
  final String? tier;
  final bool? needsDaclAugmentation;
  final List<String> warnings;
  final String? error;
  final ({
    bool baseContainerSupportsDenyPaths,
    bool baseContainerSupportsIngressHostLoopbackAllow,
    bool baseContainerSupportsIdentitylessLoopbackProxy,
    MxcUiCapabilities uiCapabilities,
  })
  probes;
  const MxcProbeOutput({
    this.tier,
    this.needsDaclAugmentation,
    required this.warnings,
    this.error,
    required this.probes,
  });
}

/** Mirrors the SDK's `MxcProcess` members srt uses. */
abstract interface class MxcProcessHandle {
  int get id;
  stream.Writable? get standardInput;
  stream.Readable? get standardOutput;
  stream.Readable? get standardError;
  Future<({int exitCode, bool timedOut})> wait();
  void kill();
  void dispose();
}

/** The two SDK entry points srt calls. */
abstract interface class MxcSdk {
  MxcProbeOutput probe(MxcRequest request);
  Future<MxcProcessHandle> spawn(MxcRequest request);
}

// ────────────────────────────────────────────────────────────────────────
// Loading the SDK
// ────────────────────────────────────────────────────────────────────────

/** Whether `@microsoft/mxc-sdk` resolves from here, without loading it. */
bool isMxcSdkInstalled() => false;

/** Why `windows.backend: 'mxc'` cannot load the SDK. */
const MXC_SDK_MISSING =
    '$_MXC_PKG is not installed (pass windowsMxcSdk to initialize())';

/**
 * Load `@microsoft/mxc-sdk/v1`.
 *
 * @throws {WindowsSandboxError} `backend_unsupported` when the package
 * is missing or does not export `probe` and `spawn`.
 */
Future<MxcSdk> Function() loadMxcSdk = _loadMxcSdk;
Future<MxcSdk> _loadMxcSdk() async {
  // A variable specifier keeps bundlers and tsc from resolving an
  // optional dependency that is usually absent.
  throw WindowsSandboxError(
    'backend_unsupported',
    "windows.backend is 'mxc' but $MXC_SDK_MISSING",
  );
}

/**
 * The SDK a session uses: the embedder's when it passed one, otherwise
 * the installed package. An injected SDK is used as given, and the
 * package is not resolved.
 *
 * @throws {WindowsSandboxError} `backend_unsupported` when the injected
 * object lacks `probe` or `spawn`, or from {@link loadMxcSdk}.
 */
Future<MxcSdk> resolveMxcSdk([Object? injected = _notInjected]) async {
  if (identical(injected, _notInjected)) return loadMxcSdk();
  if (injected is! MxcSdk) {
    throw WindowsSandboxError(
      'backend_unsupported',
      "windows.backend is 'mxc' but windowsMxcSdk does not have probe() and spawn()",
    );
  }
  // The two functions, bound, so a later change to the caller's object
  // changes nothing here and methods keep their receiver.
  return _BoundMxcSdk(injected.probe, injected.spawn);
}

const _notInjected = Object();

class _BoundMxcSdk implements MxcSdk {
  final MxcProbeOutput Function(MxcRequest) _probe;
  final Future<MxcProcessHandle> Function(MxcRequest) _spawn;
  _BoundMxcSdk(this._probe, this._spawn);
  @override
  MxcProbeOutput probe(MxcRequest request) => _probe(request);
  @override
  Future<MxcProcessHandle> spawn(MxcRequest request) => _spawn(request);
}

// ────────────────────────────────────────────────────────────────────────
// Probe & spawn
// ────────────────────────────────────────────────────────────────────────

class WindowsBackendSelection {
  /// Allowed values: 'srt-win', 'mxc'.
  final String backend;
  const WindowsBackendSelection({required this.backend});
}

/**
 * Every reason the probe's answer cannot enforce `request` exactly.
 * Empty means the request is safe to spawn.
 */
List<String> mxcProbeRefusals(MxcRequest request, MxcProbeOutput probe) {
  if (probe.error != null) return ['the probe failed: ${probe.error}'];
  final reasons = <String>[];
  if (probe.tier != 'base-container')
    reasons.add(
      "this host offers MXC tier '${probe.tier ?? 'none'}'; BaseContainer is required",
    );
  if (probe.needsDaclAugmentation == true)
    reasons.add('the tier needs host ACL changes (DACL augmentation)');
  final facts = probe.probes;
  if (request.filesystem.deniedPaths.isNotEmpty &&
      !facts.baseContainerSupportsDenyPaths)
    reasons.add('BaseContainer cannot enforce denied paths on this host');
  if (request.network.runtimeConfig != null) {
    if (!facts.baseContainerSupportsIdentitylessLoopbackProxy)
      reasons.add('BaseContainer cannot confine egress to the host proxy');
    if (!facts.baseContainerSupportsIngressHostLoopbackAllow)
      reasons.add('BaseContainer cannot allow host loopback for the proxy');
  }
  final ui = facts.uiCapabilities;
  if (!ui.canBlockClipboardRead || !ui.canBlockClipboardWrite)
    reasons.add('this host cannot block clipboard access');
  if (!ui.canBlockInputInjection)
    reasons.add('this host cannot block input injection');
  return reasons;
}

/**
 * Probe `request`, refusing anything {@link mxcProbeRefusals} reports.
 *
 * @throws {WindowsSandboxError} `backend_unsupported`.
 */
MxcProbeOutput assertMxcCanEnforce(MxcSdk sdk, MxcRequest request) {
  final MxcProbeOutput probe;
  try {
    probe = sdk.probe(request);
  } catch (e) {
    throw WindowsSandboxError(
      'backend_unsupported',
      "windows.backend is 'mxc' but the probe failed: ${errorMessage(e)}",
    );
  }
  final reasons = mxcProbeRefusals(request, probe);
  if (reasons.isNotEmpty)
    throw WindowsSandboxError(
      'backend_unsupported',
      "windows.backend is 'mxc' but ${reasons.join('; ')}",
    );
  for (final warning in probe.warnings) {
    logForDebugging('[Sandbox Windows] mxc probe: $warning');
  }
  return probe;
}

/**
 * Check, once at `initialize()`, that this host can run the session's
 * policy on BaseContainer. `request` is the session policy compiled by
 * {@link buildMxcRequest}.
 *
 * @throws {WindowsSandboxError} `backend_unsupported`.
 */
void verifyMxcBackend(MxcSdk sdk, MxcRequest request) {
  assertMxcCanEnforce(sdk, request);
}

/**
 * Start `request` after {@link assertMxcCanEnforce} accepts it. The
 * probe runs on every spawn, so a command whose per-command policy the
 * host cannot enforce never starts.
 */
Future<MxcProcessHandle> spawnMxcRequest(MxcSdk sdk, MxcRequest request) async {
  assertMxcCanEnforce(sdk, request);
  logForDebugging(
    '[Sandbox Windows] mxc spawn: ${request.filesystem.readwritePaths.length} write, ${request.filesystem.deniedPaths.length} denied paths',
  );
  return sdk.spawn(request);
}

// ────────────────────────────────────────────────────────────────────────
// Command-line assembly
// ────────────────────────────────────────────────────────────────────────

/**
 * MSVCRT/CreateProcess argument quoting: no quotes for safe tokens;
 * otherwise wrap in `"…"`, doubling backslashes that precede a `"` or
 * the closing quote and escaping each `"` as `\"`.
 */
String joinWindowsCommandLine(List<String> argv) =>
    argv.map(_quoteWindowsArg).join(' ');

/**
 * Build the ONE command line MXC hands verbatim to the OS as
 * `lpCommandLine`. The string must therefore be exactly what the
 * CHILD parses:
 *
 *   - cmd.exe does NOT use MSVCRT escaping: the payload after `/c`
 *     gets ONE outer quote pair for `/s` to strip, contents verbatim
 *     (quotes and metachars untouched: they are the user's tool
 *     inside the sandbox). This mirrors srt-win's `build_cmdline`.
 *   - pwsh/powershell/bash are CRT programs that argv-parse their
 *     command line MSVCRT-style, so the payload is a regular quoted
 *     argv element.
 */
String buildShellCommandLine(WindowsBinShell sh, String command) {
  final base = path.windows.basename(sh.exe).toLowerCase();
  if (base == 'cmd' || base == 'cmd.exe')
    return '${joinWindowsCommandLine([sh.exe, ...sh.args])} "$command"';
  return joinWindowsCommandLine([sh.exe, ...sh.args, command]);
}

String _quoteWindowsArg(String arg) {
  if (arg.isNotEmpty && !RegExp(r'[ \t\n\v"]').hasMatch(arg)) return arg;
  var out = '"';
  var backslashes = 0;
  for (final ch in arg.split('')) {
    if (ch == r'\') {
      backslashes++;
      continue;
    }
    if (ch == '"') {
      // 2n+1: escape the backslashes AND the quote.
      out += r'\' * (backslashes * 2 + 1) + '"';
    } else {
      out += r'\' * backslashes + ch;
    }
    backslashes = 0;
  }
  // 2n before the closing quote so it isn't escaped.
  out += r'\' * (backslashes * 2) + '"';
  return out;
}

// ────────────────────────────────────────────────────────────────────────
// Policy → request
// ────────────────────────────────────────────────────────────────────────

/**
 * Inputs to {@link buildMxcRequest}: the same information the srt-win
 * wrap receives, in srt's own semantics. The mapping to MXC's
 * allow-list model happens inside.
 */
class MxcSandboxParams {
  final String command;
  /** Attribution key for the proxy and violation store; see WrapWithSandboxOptions. */
  final String? commandId;
  /** Proxy port: the ONE loopback listener the child may reach. */
  final int? httpProxyPort;
  final int? socksProxyPort;
  final String? proxyAuthToken;
  /** `mode:'mask'` sentinels; the child inherits no other env. */
  final Map<String, String>? setEnvVars;
  /** srt read deny-list (expanded, concrete paths). */
  final List<String>? denyRead;
  /** srt write deny-list (expanded): over-denied to full deny. */
  final List<String>? denyWrite;
  /** srt read allow-list, on top of the system-drive grant. */
  final List<String>? allowRead;
  /** srt write allow-list (expanded). */
  final List<String>? allowWrite;
  final String? cwd;
  final List<String>? gitSafeDirectories;
  final WindowsBinShell? binShell;
  final int? timeoutMs;
  /** The caller's variables for the child, laid over every other layer. */
  final Map<String, String>? env;
  const MxcSandboxParams({
    required this.command,
    this.commandId,
    this.httpProxyPort,
    this.socksProxyPort,
    this.proxyAuthToken,
    this.setEnvVars,
    this.denyRead,
    this.denyWrite,
    this.allowRead,
    this.allowWrite,
    this.cwd,
    this.gitSafeDirectories,
    this.binShell,
    this.timeoutMs,
    this.env,
  });
}

/** Compile srt semantics into an SDK v1 container request. */
MxcRequest buildMxcRequest(MxcSandboxParams p) {
  final systemDrive = '${process.env['SystemDrive'] ?? 'C:'}\\';
  final workingDirectory = p.cwd ?? process.cwd();
  // The host's temp folder stays writable by its full path. It is not
  // the child's %TEMP%: see CHILD_BASE_ENV_VARS.
  final temp = process.env['TEMP'] ?? process.env['TMP'];
  final sh = p.binShell ?? parseWindowsBinShell(null);
  final hasProxy = p.httpProxyPort != null;
  // The proxy username carries the command's attribution key, as on
  // srt-win, so per-command network lists and violations reach it.
  final encodedCommand = encodeSandboxedCommand(
    attributionKeyFor(p.command, p.commandId),
  );
  final proxyUser = proxyUsernameFor(encodedCommand);
  final proxyEnv = generateProxyEnvVars(
    p.httpProxyPort,
    p.socksProxyPort,
    null,
    p.proxyAuthToken,
    null,
    encodedCommand,
  );
  final readwritePaths = <String>[...?p.allowWrite, if (temp != null) temp];
  // TELOSNEX DEVIATION (PORT_WORKLOG.md, "Deviations from upstream"):
  // upstream sends every denyWrite path as a denied path, which also
  // takes reads away. On MXC, a read-only path beneath a write grant
  // blocks writes, renames into it and deletes, and keeps reads (tested
  // on Windows 11 26H2, 2026-11-14). A read-only path that does not
  // exist does not stop its creation, so only an existing path becomes
  // read-only, and only outside every denyRead; any other denyWrite path
  // stays denied, as upstream sends it.
  final readDenied = coveringWindowsPath([...?p.denyRead]);
  final writeDeniedReadable = [
    for (final d in p.denyWrite ?? const <String>[])
      if (readDenied(d) == null && fs.existsSync(d)) d,
  ];
  final deniedPaths = <String>[
    ...?p.denyRead,
    for (final d in p.denyWrite ?? const <String>[])
      if (!writeDeniedReadable.contains(d)) d,
  ];
  // MXC lets the most specific entry win. A read-only entry at or
  // beneath a write grant would make that subtree read-only, so it is
  // left out when the write grant is what governs it (no deny between
  // the two; beneath such a deny the read grant is what re-opens reads).
  // The working directory is added for reading only outside every deny:
  // beneath one it would override the deny.
  final writable = coveringWindowsPath(readwritePaths);
  final denied = coveringWindowsPath(deniedPaths);
  bool governedByWrite(String r) {
    final w = writable(r);
    if (w == null) return false;
    final under = coveringWindowsPath([w]);
    return !deniedPaths.any(
      (d) => coveringWindowsPath([d])(r) != null && under(d) != null,
    );
  }

  final readonlyPaths =
      [
          systemDrive,
          if (denied(workingDirectory) == null) workingDirectory,
          ...?p.allowRead,
        ].where((r) => !governedByWrite(r)).toList()
        // TELOSNEX DEVIATION: see deniedPaths. Beneath a write grant on
        // purpose: the most specific entry makes the path read-only.
        ..addAll(writeDeniedReadable);
  return MxcRequest(
    command: buildShellCommandLine(sh, p.command),
    filesystem: (
      readonlyPaths: readonlyPaths,
      readwritePaths: readwritePaths,
      deniedPaths: deniedPaths,
    ),
    network: (
      egress: (defaultAction: 'deny'),
      // MXC 1.0 refuses a host proxy unless ingress.default is 'allow',
      // and one without a peer identity also needs hostLoopback 'allow'
      // (resolved on its own, not inherited). On Windows 11 25H2 (build
      // 26200.9711) this still admitted nothing inbound, from loopback
      // or the LAN, and blocked outbound to other loopback ports; MXC
      // documents no guarantee of that. Without a proxy both are denied.
      ingress: (
        defaultAction: hasProxy ? 'allow' : 'deny',
        hostLoopback: hasProxy ? 'allow' : 'deny',
      ),
      runtimeConfig: hasProxy
          ? (
              networkProxy:
                  'http://${p.proxyAuthToken != null && p.proxyAuthToken!.isNotEmpty ? '${Uri.encodeComponent(proxyUser)}:${p.proxyAuthToken}@' : ''}127.0.0.1:${p.httpProxyPort}',
            )
          : null,
    ),
    // UI stays on for every command. With it off, any program that loads
    // user32 or gdi32 (PowerShell, git, node, whoami, tasklist and most
    // other tools) fails at startup with 0xC0000142, and children
    // inherit the container's setting, so it can't be chosen per shell.
    // The cost: a sandboxed program can open a window on the desktop.
    // Clipboard and input injection stay blocked.
    ui: (disable: false, clipboard: 'none', allowInputInjection: false),
    timeoutMs: p.timeoutMs != null && p.timeoutMs! > 0 ? p.timeoutMs : null,
    workingDirectory: workingDirectory,
    environment: _buildChildEnv(p, proxyEnv),
    inheritDefaultEnvironment: false,
  );
}

/**
 * Host variables copied into the child's environment. The child gets
 * exactly the environment srt builds (`inheritDefaultEnvironment` is
 * off): the user's profile environment can hold secrets, so it is
 * never layered underneath. This is the set ordinary Windows programs
 * expect to find; MXC refuses to start a child without LOCALAPPDATA.
 *
 * MXC replaces TEMP, TMP and LOCALAPPDATA with a per-command folder of
 * its own (under `AppData\Local\Packages\sandbox.{GUID}\AC`), deleted
 * when the command ends; the values sent here only have to be present.
 */
const _CHILD_BASE_ENV_VARS = [
  'ALLUSERSPROFILE',
  'APPDATA',
  'CommonProgramFiles',
  'CommonProgramFiles(Arm)',
  'CommonProgramFiles(x86)',
  'CommonProgramW6432',
  'COMPUTERNAME',
  'ComSpec',
  'HOMEDRIVE',
  'HOMEPATH',
  'LOCALAPPDATA',
  'NUMBER_OF_PROCESSORS',
  'OS',
  'PATH',
  'PATHEXT',
  'PROCESSOR_ARCHITECTURE',
  'PROCESSOR_IDENTIFIER',
  'PROCESSOR_LEVEL',
  'PROCESSOR_REVISION',
  'ProgramData',
  'ProgramFiles',
  'ProgramFiles(Arm)',
  'ProgramFiles(x86)',
  'ProgramW6432',
  'PUBLIC',
  'SystemDrive',
  'SystemRoot',
  'TEMP',
  'TMP',
  'USERDOMAIN',
  'USERNAME',
  'USERPROFILE',
  'windir',
];

/**
 * The child's environment. Precedence matches srt-win: host base vars,
 * then mask sentinels, then the generated proxy set (so a caller
 * masking HTTPS_PROXY cannot break the sandbox's own plumbing), then
 * GIT_CONFIG_* last so its COUNT composition wins, then the caller's
 * `env` over all of it, as the `--env` pairs a caller adds after
 * srt-win's own are. The caller keeps sandbox-runtime's names (PATH,
 * the proxy variables, GIT_CONFIG_*) and masked names off it.
 */
Map<String, String> _buildChildEnv(MxcSandboxParams p, List<String> proxyEnv) {
  // Same two deletions as srt-win, same reasons: TMPDIR is POSIX-only
  // and breaks msys2 tools; NO_PROXY would send localhost DIRECT into
  // the container's egress block (only the proxy port is reachable).
  final envList = proxyEnv
      .where(
        (e) =>
            !e.startsWith('TMPDIR=') &&
            !e.startsWith('NO_PROXY=') &&
            !e.startsWith('no_proxy='),
      )
      .toList();
  final gitCfg = buildGitConfigEnv(
    safeDirs: [
      p.cwd ?? process.cwd(),
      ...?p.allowWrite,
      ...?p.gitSafeDirectories,
    ],
    schannelCa: false,
    baseEnv: p.setEnvVars,
  );
  final base = <String, String>{};
  for (final k in _CHILD_BASE_ENV_VARS) {
    final v = process.env[k];
    if (v != null) base[k] = v;
  }
  // Node's built-in clients read the proxy variables only with
  // NODE_USE_ENV_PROXY set, as srt-win sets it; first, so a caller's
  // value wins.
  return mergeWindowsEnv([
    base,
    p.httpProxyPort != null && p.httpProxyPort != 0
        ? {'NODE_USE_ENV_PROXY': '1'}
        : {},
    p.setEnvVars ?? {},
    envListToObject(envList),
    gitCfg,
    p.env ?? {},
  ]).cast<String, String>();
}
