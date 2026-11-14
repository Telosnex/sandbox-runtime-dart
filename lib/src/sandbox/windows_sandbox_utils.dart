// Ported from sandbox-runtime src/sandbox/windows-sandbox-utils.ts @ 0bbebed.
// ignore_for_file: doc_directive_unknown, dangling_library_doc_comments, prefer_adjacent_string_concatenation, overridden_fields
// Windows is not supported by this port (PORT_WORKLOG.md); pure helpers are ported, the rest throws.
// ignore_for_file: constant_identifier_names, non_constant_identifier_names, slash_for_doc_comments
// ignore_for_file: unused_element, unused_element_parameter, prefer_is_empty, curly_braces_in_flow_control_structures
// ignore_for_file: prefer_interpolation_to_compose_strings

import 'dart:convert';

import '../node/abort.dart' show AbortSignal;

import 'dart:io' show File, Platform;

import 'package:path/path.dart' as path;

import '../node/fs.dart' as fs;
import '../node/errno.dart' show NodeError, errorMessage;
import '../node/process.dart' as process;
import '../utils/debug.dart';
import 'sandbox_config.dart'
    show FilesystemPathEntry, FilesystemPathSpelling, SrtWinConfig;
import 'linux_sandbox_utils.dart' show SandboxDependencyCheck;
import 'path_entries.dart' show literalReadings;
import 'sandbox_utils.dart'
    show
        generateProxyEnvVars,
        encodeSandboxedCommand,
        attributionKeyFor,
        buildGitConfigEnv,
        normalizePathForSandbox,
        containsGlobCharsWin,
        expandGlobPattern,
        isAtOrUnder,
        isUncPath,
        markedLiteralPath,
        normalizeCaseForComparison,
        stripExtendedPathPrefix;

// Kept on this module's surface for out-of-tree importers; the
// implementations live in sandbox-utils.ts.
export 'sandbox_utils.dart'
    show
        containsGlobCharsWin,
        stripExtendedPathPrefix,
        buildGitConfigEnv,
        isUncPath;

/**
 * Windows sandbox backend.
 *
 * Network isolation is enforced by `srt-win.exe` — a Rust helper that
 * provisions a dedicated `srt-sandbox` local user account, installs a
 * machine-wide WFP filter set keyed on that account's SID, and
 * provides an `exec` subcommand that spawns the target via a two-hop
 * launch (broker → `CreateProcessWithLogonW(runner)` → runner →
 * restricted-token child) under `srt-sandbox`. The sandboxed child
 * reaches the host only via the JS mux proxy, which the caller
 * passes in via `--env`.
 *
 * The separate-user account structurally closes the surrogate-spawn
 * class (schtasks, `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`, BITS,
 * RunAs="Interactive User" COM): the child's token carries a
 * different user SID, so it cannot reach real-user processes, tasks
 * register under `srt-sandbox`, and the user-SID WFP filter fences
 * `srt-sandbox` egress regardless of how the child was spawned.
 *
 * This module is a thin wrapper around the `srt-win` CLI; all status
 * comes from live enumeration. There is no marker file.
 *
 * Filesystem rules (`denyRead`/`denyWrite`/`allowRead`/`allowWrite`)
 * are enforced via additive explicit ACEs for `<sb-SID>` — see
 * {@link grantWindowsAcl} / {@link stampWindowsAcl}.
 */

// ────────────────────────────────────────────────────────────────────

// ────────────────────────────────────────────────────────────────────
// Errors
// ────────────────────────────────────────────────────────────────────

/**
 * Stable machine-readable code carried on every
 * {@link WindowsSandboxError}. Consumers branch on `.code` instead of
 * prose-matching `.message` (message text is diagnostic and may change
 * between releases).
 */
/** `windows.srtWin.path` unset, or the configured/packaged exe is missing. */
/** `spawnSync(srt-win)` itself failed (ENOENT, EACCES). */
/** `srt-win` was killed by the spawn timeout (generic; see `install_timeout`). */
/** The caller aborted a run of `srt-win` (see `signal`). */
/** A JSON-emitting `srt-win` subcommand exited non-zero. */
/** `srt-win` stdout was not valid JSON. */
/** {@link parseWindowsBinShell} rejected the `binShell` value. */
/** {@link verifyWindowsWfpEgress} could not bind a probe listener. */
/** `srt-win wfp verify` produced no parseable result (timeout/kill). */
/** `srt-win wfp verify` proved direct egress SUCCEEDED (fence absent). */
/** `srt-win wfp verify` was neither `blocked` nor `connected`. */
/**
   * The installed loopback mode is not the one this session asks for
   * with `network.allowLocalBinding` (`srt-win` exit 19).
   */
/** `srt-win` predates `--allow-loopback`; `network.allowLocalBinding` needs a newer one. */
/** `srt-win user trust-ca` exited non-zero. */
/** `tlsTerminate` requested but no CA is installed for the sandbox user. */
/** Installed CA thumbprint ≠ session CA thumbprint. */
/** `srt-win install` exit 12 — WFP filter install failed. */
/** `srt-win install` exit 14 — sandbox-user provisioning failed. */
/** `srt-win install` exit 13 — different config under this sublayer. */
/** `srt-win install` exit 17 — ambient write-deny stamping failed. */
/** `srt-win install` was killed by the spawn timeout (UAC left open). */
/** `srt-win install` failed with an unmapped exit code. */
/** `srt-win uninstall` exited non-zero (not UAC-cancel). */
/** `srt-win acl stamp` exited non-zero. */
/** `srt-win acl grant` exited non-zero. */
/**
   * A profile read grant is recorded and cannot be relied on (unfinished,
   * older exclusion list, another profile, unreadable record). An ABSENT
   * grant is not an error.
   */
/**
   * `srt-win profile grant` did not complete. From an install: the
   * account and the filters are installed, the grant is not.
   */
/** `srt-win profile forget` could not remove the whole grant. */
/**
   * A path the session would grant — `filesystem.allowRead`, or a
   * write root (`allowWrite`) — is, contains, or lies inside a path
   * the profile read grant excludes. Nothing is granted.
   */
/** `srt-win exec` argv would exceed CreateProcessW's 32 767-char limit. */
/** Sandbox user account / credential not present — run install. */
/**
   * The sandbox is installed, by a release whose setup version is not
   * the one this `srt-win` requires — re-run the install. Nothing is
   * granted or run until then.
   */
/**
   * Working directory is on a mapped network drive; the sandbox
   * cannot start (per-user drive mappings don't exist under the
   * sandbox logon). `srt-win exec` exit **16**; parsed from its
   * stderr JSON by {@link parseWindowsSandboxError}, which carries
   * the failing root on `.drive` ({@link MappedDriveCwdError}).
   */
/**
   * The Secondary Logon service (`seclogon`) is disabled or absent; `srt-win`
   * launch subcommands exit **18** ({@link SeclogonDisabledError}).
   */
/**
   * The named `windows.backend` cannot run this configuration on this
   * host. Nothing falls back; the caller decides what to try next.
   */
/// Allowed values: srt_win_not_found, spawn_failed, srt_win_timeout, srt_win_cancelled, srt_win_nonzero, srt_win_bad_json, bin_shell_invalid, wfp_verify_bind_failed, wfp_verify_unparseable, wfp_fence_inactive, wfp_verify_inconclusive, wfp_loopback_mismatch, srt_win_too_old, trust_ca_failed, trust_ca_not_installed, trust_ca_thumbprint_mismatch, install_wfp_failed, install_user_failed, install_config_conflict, install_ambient_failed, install_timeout, install_failed, uninstall_failed, acl_stamp_failed, acl_grant_failed, profile_grant_outdated, profile_grant_failed, profile_forget_failed, kept_grants_in_use, srt_win_outdated, profile_grant_blocked_by_session, profile_operation_in_progress, session_ended, profile_exclusion_read_grant, argv_too_long, not_provisioned, reinstall_required, mapped_drive_cwd, seclogon_disabled, backend_unsupported.
typedef WindowsSandboxErrorCode = String;

/**
 * Error thrown by the Windows sandbox backend. Carries a stable
 * {@link WindowsSandboxErrorCode} on `.code` so callers can branch
 * without prose-matching `.message`. `instanceof WindowsSandboxError`
 * narrows `.code` to the union.
 *
 * `.subcommand` is set on errors thrown from the `srt-win` spawn
 * chokepoint (`spawn_failed`, `srt_win_timeout`, `srt_win_nonzero`,
 * `srt_win_bad_json`) to the first CLI arg (e.g. `'install'`,
 * `'wfp'`) so a consumer can distinguish install-spawn-failed from
 * probe-spawn-failed without prose-matching. Unset elsewhere.
 */
class WindowsSandboxError extends Error {
  final WindowsSandboxErrorCode code;
  final String message;
  final String? subcommand;
  final String name = 'WindowsSandboxError';

  WindowsSandboxError(this.code, this.message, [this.subcommand]);
}

// ────────────────────────────────────────────────────────────────────
// Types
// ────────────────────────────────────────────────────────────────────

const (int, int) DEFAULT_WINDOWS_PROXY_PORT_RANGE = (60080, 60089);

/**
 * The one loopback port that stays blocked for the sandbox account with
 * `network.allowLocalBinding`, so the fence check has a connect that must
 * be refused. `srt-win` owns it (`LOOPBACK_PROBE_PORT` in `wfp.rs`).
 */
const WINDOWS_LOOPBACK_PROBE_PORT = 1;

/** What `network.allowLocalBinding` opens on Windows, in plain words. */
const WINDOWS_ALLOW_LOOPBACK_EFFECT =
    'Loopback is open: sandboxed commands can connect to every TCP and ' +
    'UDP port on localhost (127.0.0.0/8 and ::1; port ' +
    '$WINDOWS_LOOPBACK_PROBE_PORT alone stays blocked, so the sandbox ' +
    'can check its own fence). Every service listening ' +
    'on localhost is reachable from them, and any local forwarder (a DNS ' +
    'stub, a SOCKS or HTTP proxy, a VPN or security agent, a tunnel) ' +
    'reachable there gives them a way off the machine that the network ' +
    'restrictions do not cover.';

/**
 * `cannot-read` is the graceful-degrade state when BFE enumeration
 * is access-denied (it is admin-gated). The non-elevated readiness
 * check is {@link verifyWindowsWfpEgress}, not this enum.
 *
 * `loopback-mismatch` (elevated callers only): the filters' loopback
 * mode is not the one the install recorded; re-install.
 */
/// Allowed values: 'absent', 'installed', 'loopback-mismatch', 'cannot-read'.
typedef WindowsWfpStatus = String;

class WindowsWfpStatusResult {
  final WindowsWfpStatus state;
  /** Live filter count from BFE enum; `0` on `cannot-read`. */
  final int filters;
  /** `[low, high]` for the loopback PERMIT, when known. */
  final (int, int)? portRange;
  /**
   * Whether the installed filter set opens loopback — see
   * {@link WINDOWS_ALLOW_LOOPBACK_EFFECT}.
   */
  final bool allowLoopback;
  /** Sandbox-user SID read from the first user-keyed filter tag. */
  final String? userSid;
  /**
   * Populated only on `cannot-read` (BFE enumeration is admin-gated;
   * a non-elevated caller can't read it). The non-elevated readiness
   * check is {@link verifyWindowsWfpEgress}, not this enum.
   */
  final String? hint;

  const WindowsWfpStatusResult({
    required this.state,
    required this.filters,
    this.portRange,
    this.allowLoopback = false,
    this.userSid,
    this.hint,
  });
}

/**
 * Result of one connect attempt by `srt-win wfp verify`. `connected`
 * and `refused` both mean the connect got past the filters;
 * `unreachable` and `error` say nothing about the fence.
 */
/// Allowed values: blocked, connected, refused, unreachable, skipped, error.
typedef WindowsWfpProbeOutcome = String;

/**
 * A gap {@link verifyWindowsWfpEgress} observed that the filter set
 * does not close. `anonymous-egress` is expected on every machine with
 * an off-loopback address: no filter is keyed on the anonymous token.
 */
/// Allowed values: anonymous-egress, anonymous-loopback, deny-only-user-sid,
/// lowered-integrity-unprobed.
typedef WindowsWfpResidual = String;

/**
 * Result of `srt-win wfp verify` on success (exit 0); anything else
 * throws. `plain` is `blocked`. A lowered-integrity attempt may be
 * `error` (not set up), and the rest anything: see `residuals`.
 */
class WindowsWfpVerifyResult {
  final String target;
  /** Runner's stderr (carries one diagnostic line per attempt). */
  final String stderr;
  /**
   * One per attempt. `anonymous`, `lowIntegrity` and `untrustedIntegrity`
   * go to an off-loopback target, the rest to the loopback one: the
   * listener, or with loopback open {@link WINDOWS_LOOPBACK_PROBE_PORT}.
   */
  final ({
    WindowsWfpProbeOutcome plain,
    WindowsWfpProbeOutcome anonymous,
    WindowsWfpProbeOutcome anonymousLoopback,
    WindowsWfpProbeOutcome denyOnly,
    WindowsWfpProbeOutcome lowIntegrity,
    WindowsWfpProbeOutcome lowIntegrityLoopback,
    WindowsWfpProbeOutcome untrustedIntegrity,
    WindowsWfpProbeOutcome untrustedIntegrityLoopback,
    WindowsWfpProbeOutcome? openLoopback,
  })
  probes;
  /** With loopback open: own token, to the loopback listener. */
  /** Gaps the probe found open: NOT a clean pass when non-empty. */
  final List<WindowsWfpResidual> residuals;
  /**
   * Warnings for residuals, skipped attempts and open loopback;
   * `initialize()` logs them.
   */
  final List<String> warnings;

  const WindowsWfpVerifyResult({
    required this.target,
    required this.stderr,
    required this.probes,
    required this.residuals,
    required this.warnings,
  });
}

/**
 * Readiness of the Secondary Logon service every launch goes through. `ok`
 * covers a stopped Manual service (the launch demand-starts it);
 * `cannot-read` is not proof of a problem.
 */
/// Allowed values: ok, disabled, missing, cannot-read.
typedef WindowsSeclogonState = String;

/**
 * State of the `srt-sandbox` local account that `srt-win install`
 * provisions. The sandboxed child runs **as** this account.
 */
class WindowsSandboxUserStatus {
  /** The `srt-sandbox` local account exists. */
  final bool provisioned;
  /** `S-1-5-21-…` of `srt-sandbox`, when provisioned. */
  final String? sid;
  /** The `sandbox-runtime-users` local group exists. */
  final bool groupExists;
  /** `S-1-5-21-…` of `sandbox-runtime-users`, when it exists. */
  final String? groupSid;
  final bool inBuiltinUsers;
  final bool inSandboxGroup;
  final bool hiddenFromLogon;
  /**
   * The credential blob (`HKLM\SOFTWARE\sandbox-runtime\Cred`) is
   * present, decryptable, and readable by THIS process. False when
   * not yet written, or when called from inside the sandbox (the
   * Cred key carries an explicit DENY for `sandbox-runtime-users` —
   * machine-scope DPAPI alone is not a confidentiality boundary).
   */
  final bool credPresent;
  /** Setup marker schema version, when the marker row exists. */
  final int? markerVersion;
  /**
   * The setup version this `srt-win` requires; it launches nothing
   * while {@link markerVersion} differs. Absent from an `srt-win` that
   * does not report it.
   */
  final int? setupVersion;
  /**
   * The calling (real) user's SID — the broker's identity, surfaced
   * for diagnostics. The DENY-ACE trustee is `srt-sandbox`'s SID
   * ({@link sid}), not this. Always present.
   */
  final String realUserSid;
  /**
   * SHA-1 thumbprint of the install-time CA, when one was
   * installed via `srt-win user trust-ca`. Uppercase hex.
   */
  final String? caCertThumb;
  /** PEM-encoded install-time CA certificate, when present. */
  final String? caCertPem;
  /** Secondary Logon readiness. Absent when `srt-win` predates the field. */
  final WindowsSeclogonState? seclogon;
  /**
   * Set when write grants kept between sessions exist (`present`) or
   * cannot be ruled out (`unknown`); `srt-win` then refuses to run a
   * command under the ordinary token.
   */
  final ({String state, List<String> roots, String? reason})? persistentGrants;
  /**
   * Set when a profile read grant is recorded (`present`) or cannot
   * be ruled out (`unknown`). Whether it is current is {@link
   * getWindowsProfileReadStatus}'s to say.
   */
  final ({String state, String? reason})? profileGrant;
  /**
   * What `srt-win` says it does, by name (see
   * {@link WINDOWS_SRT_WIN_CAPABILITIES}); empty from one that does
   * not say.
   */
  final List<String> capabilities;
  /**
   * SID of the user who owns the interactive session this process
   * runs in, when `srt-win` can tell.
   */
  final String? sessionUserSid;

  const WindowsSandboxUserStatus({
    required this.provisioned,
    this.sid,
    required this.groupExists,
    this.groupSid,
    required this.inBuiltinUsers,
    required this.inSandboxGroup,
    required this.hiddenFromLogon,
    required this.credPresent,
    this.markerVersion,
    this.setupVersion,
    required this.realUserSid,
    this.caCertThumb,
    this.caCertPem,
    this.seclogon,
    this.persistentGrants,
    this.profileGrant,
    this.capabilities = const [],
    this.sessionUserSid,
  });
}

/**
 * Inner shell to run `command` under, inside the sandbox: the
 * executable to spawn and the flag argv placed between it and the
 * user's command string. `exe` MUST originate from trusted host
 * configuration (user settings / install detection), NEVER from
 * workspace or repository content — the inner shell runs INSIDE the
 * sandbox so an unexpected path is not a sandbox-escape vector, but
 * it would still be an arbitrary-exec footgun if sourced from
 * untrusted input.
 *
 * Construct via {@link parseWindowsBinShell} — it is the SOLE
 * normalizer and the only place validation lives.
 */
class WindowsBinShell {
  /** Shell executable to spawn (absolute path when caller-supplied). */
  final String exe;
  /** Argv placed between `exe` and the user's command string. */
  final List<String> args;

  const WindowsBinShell({required this.exe, required this.args});
}

const List<String> _PWSH_FLAGS = ['-NoProfile', '-Command'];

/**
 * Sole normalizer from the cross-platform `binShell?: string |
 * WindowsBinShell` surface ({@link SandboxManager.wrapWithSandboxArgv})
 * to a spawnable `{exe, args}` pair. All validation lives here —
 * {@link wrapCommandWithSandboxWindows} consumes the result verbatim.
 *
 * String form: bare token (`'cmd'|'pwsh'|'powershell'`) resolves to
 * the default install; absolute path to `bash.exe`/`sh.exe`/
 * `pwsh.exe`/`powershell.exe`/`cmd.exe` keeps the caller's path with
 * the matching flag shape. Object form: `exe` must be absolute; `args`
 * pass through unchanged. Throws on anything else — no silent
 * fallback to cmd.exe.
 *
 * Uses `path.win32` explicitly so the function (and its unit test)
 * is platform-independent.
 */
WindowsBinShell parseWindowsBinShell([Object? raw]) {
  final systemRoot = process.env['SystemRoot'] ?? 'C:\\Windows';
  final cmdDefault = WindowsBinShell(
    exe: path.windows.join(systemRoot, 'System32', 'cmd.exe'),
    args: ['/d', '/s', '/c'],
  );
  if (raw == null) return cmdDefault;
  if (raw is WindowsBinShell) {
    if (!path.windows.isAbsolute(raw.exe)) {
      throw WindowsSandboxError(
        'bin_shell_invalid',
        'binShell.exe must be an absolute path ' +
            '(got ${jsonEncode(raw.exe)})',
      );
    }
    // Dart: `args` is a typed List, so upstream's Array.isArray check cannot fail.
    return raw;
  }
  raw as String;
  final rawBase = path.windows.basename(raw);
  final base = rawBase.toLowerCase();
  final isAbs = path.windows.isAbsolute(raw);
  // A relative path with a directory component (`bin\bash.exe`) is
  // neither a token nor a resolved install — never silently degrade.
  if (!isAbs && raw != rawBase) {
    throw WindowsSandboxError(
      'bin_shell_invalid',
      'binShell string must be a bare token or an absolute path ' +
          '(got ${jsonEncode(raw)})',
    );
  }
  switch (base) {
    case 'bash':
    case 'bash.exe':
    case 'sh':
    case 'sh.exe':
      // Bare 'bash' is ambiguous (WSL vs Git Bash) — require the
      // resolved install path.
      if (!isAbs) {
        throw WindowsSandboxError(
          'bin_shell_invalid',
          'binShell bash path must be absolute ' +
              '(got ${jsonEncode(raw)}); pass the resolved Git Bash ' +
              'install path',
        );
      }
      return WindowsBinShell(exe: raw, args: ['-c']);
    case 'pwsh':
    case 'pwsh.exe':
      return WindowsBinShell(exe: isAbs ? raw : 'pwsh.exe', args: _PWSH_FLAGS);
    case 'powershell':
    case 'powershell.exe':
      return WindowsBinShell(
        exe: isAbs
            ? raw
            : path.windows.join(
                systemRoot,
                'System32',
                'WindowsPowerShell',
                'v1.0',
                'powershell.exe',
              ),
        args: _PWSH_FLAGS,
      );
    case 'cmd':
    case 'cmd.exe':
      return isAbs
          ? WindowsBinShell(exe: raw, args: cmdDefault.args)
          : cmdDefault;
    default:
      throw WindowsSandboxError(
        'bin_shell_invalid',
        'unrecognised binShell ${jsonEncode(raw)}: expected ' +
            "'cmd' | 'powershell' | 'pwsh' or an absolute path to " +
            'bash.exe/sh.exe/pwsh.exe/powershell.exe',
      );
  }
}

class WindowsSandboxParams {
  final String command;
  /** Attribution key encoded for violation correlation; defaults to
   *  `command`. See MacOSSandboxParams.commandId. */
  final String? commandId;
  /**
   * JS HTTP proxy port — fed to `generateProxyEnvVars` for the env
   * overlay. With the in-process proxy this is the mux front-end
   * port (same as `socksProxyPort`).
   */
  final int? httpProxyPort;
  /**
   * JS SOCKS proxy port — fed to `generateProxyEnvVars` for the env
   * overlay. With the in-process proxy this is the mux front-end
   * port (same as `httpProxyPort`).
   */
  final int? socksProxyPort;
  /** Per-session proxy auth token; embedded in proxy env URLs. */
  final String? proxyAuthToken;
  /**
   * The session's `network.allowLocalBinding`. `srt-win exec` launches
   * nothing (exit 19) unless the install recorded the same mode. When
   * true, with a proxy, `no_proxy` names the loopback hosts.
   */
  final bool? allowLoopback;
  /**
   * `mode: 'mask'` credential env vars — sentinel values the
   * sandboxed child should see in place of the real credentials.
   * Threaded through the `--env` overlay so the runner forwards
   * them into the child's fresh profile env (the broker's own
   * environment never reaches the child, so an `env -u`-style
   * scrub is structurally moot — there is no `unsetEnvVars`).
   * Applied BEFORE the proxy assignments so the sandbox's own
   * proxy plumbing survives even if a caller masks one of those
   * names — same precedence as macOS/Linux.
   */
  final Map<String, String>? setEnvVars;
  /**
   * Per-exec read-deny paths, applied via an additive
   * `(D;OICI;FA;;;<sb-SID>)` ACE under the `srt-win exec`
   * process's own PID and released after the child exits. Same
   * disk-first chokepoint as the session-level
   * {@link stampWindowsAcl}; same fail-closed semantics (exec
   * fails if any path cannot be stamped).
   *
   * Normalized concrete paths — globs expanded by the caller via
   * {@link expandWindowsFsPaths}, the same as session-level.
   * `srt-win exec`'s `canonicalize_ace_targets` hard-fails on a
   * glob (it never expands), so a `*`/`?` reaching this field is
   * a caller bug.
   */
  final List<String>? denyRead;
  /**
   * Paths the session is granted (read or write) that lie beneath a
   * {@link denyRead} path — see {@link windowsGrantsBeneathDenies}.
   */
  final List<String>? denyReadExcept;
  /**
   * The process whose session this command belongs to, as `srt-win`
   * recorded it. Without it `srt-win exec` records itself until the command
   * has exited (one more acquisition of its lock).
   */
  final int? heldBy;
  /** Per-exec write-deny paths — see {@link denyRead}. */
  final List<String>? denyWrite;
  /**
   * Working directory the child starts in. Fed to
   * {@link buildGitConfigEnv} as a `safe.directory` entry so git
   * inside the sandbox accepts the real-user-owned working tree.
   * Default: `process.cwd()`.
   *
   * `srt-win exec` has no `--cwd` flag — the child's working
   * directory is whatever the caller passes as the spawn `{cwd:}`
   * option (broker `current_dir()` → runner `lpCurrentDirectory` →
   * child inherits). This field must match that spawn option so
   * `safe.directory` covers where git actually runs.
   */
  final String? cwd;
  /**
   * Session-level write-granted paths (the resolved
   * `filesystem.allowWrite` set). Each becomes a `safe.directory`
   * entry — see {@link buildGitConfigEnv}.
   */
  final List<String>? allowWrite;
  /**
   * Explicit `safe.directory` entries (from
   * `SandboxRuntimeConfig.git.safeDirectories`). Unioned with
   * {@link cwd} and {@link allowWrite} into the `safe.directory` set
   * — see {@link buildGitConfigEnv}. Use for the repo top-level when
   * launching from a subdirectory: the top-level must NOT go in
   * `allowWrite`, but git's dubious-ownership check keys on it.
   */
  final List<String>? gitSafeDirectories;
  /**
   * Path to the TLS-termination trust bundle (the MITM CA + system
   * roots) — fed to {@link generateProxyEnvVars} so the child's
   * `NODE_EXTRA_CA_CERTS` / `CURL_CA_BUNDLE` / `SSL_CERT_FILE` /
   * etc. point at it. Backslashes are normalised to forward slashes
   * before emission so the value survives msys2 env conversion AND
   * is accepted by native tools.
   *
   * The env-var layer covers OpenSSL-backed clients (msys2 curl,
   * openssl-backed git, node, python, cargo). Schannel/.NET clients
   * that read the Windows certificate store exclusively (System32
   * `curl.exe`, `Invoke-WebRequest`, Go-built tools) trust via the
   * separate `srt-win user trust-ca` / {@link windowsTrustCa}
   * install-time write into the sandbox user's `CurrentUser\Root`.
   *
   * The caller is responsible for the sandbox user having read
   * access to this path — `sandbox-manager.ts`'s `initialize()`
   * pushes it into the session's `acl grant` read-set alongside the
   * working-tree grants.
   */
  final String? caCertPath;
  /**
   * Suppress srt-win's informational stderr (progress lines,
   * per-exec-deny summary, seclogon-job note). Actual errors still
   * print. Default `true` — the host surfaces sandbox diagnostics
   * via its own debug log, not the child's stderr stream.
   */
  final bool? quiet;
  /**
   * Resolved `srt-win` spawn descriptor — from
   * {@link resolveSrtWin}. Omitting it throws (there is no implicit
   * vendor fallback); direct callers must resolve a path first.
   */
  final SrtWinSpawn? srtWin;
  /**
   * The session's write roots. Each is passed as `--write-root`, which
   * puts the root's capability SID in the child token; without it the
   * child cannot write the root.
   */
  final List<String>? writeRoots;
  /**
   * Inner shell. Defaults to `parseWindowsBinShell(undefined)`
   * (System32 cmd.exe). The child's post-`args` content is
   * **passthrough** — `&` chains, `"…"`/`'…'` quotes exactly as
   * written. The security boundary is at the OUTER spawn (this argv
   * is spawned with `shell:false`); the inner shell runs INSIDE the
   * sandbox so its metachars are the user's tool. Construct via
   * {@link parseWindowsBinShell}.
   */
  final WindowsBinShell? binShell;

  const WindowsSandboxParams({
    required this.command,
    this.commandId,
    this.httpProxyPort,
    this.socksProxyPort,
    this.proxyAuthToken,
    this.allowLoopback,
    this.setEnvVars,
    this.denyRead,
    this.denyReadExcept,
    this.heldBy,
    this.denyWrite,
    this.cwd,
    this.allowWrite,
    this.gitSafeDirectories,
    this.caCertPath,
    this.quiet,
    this.srtWin,
    this.writeRoots,
    this.binShell,
  });
}

// ────────────────────────────────────────────────────────────────────
// Binary resolution
// ────────────────────────────────────────────────────────────────────

String repoRoot() {
  // src/sandbox/windows-sandbox-utils.ts → repo root (compiled: dist/sandbox/…)
  // Dart: the package root, from the package config (as child_process.dart finds the spawn helper).
  final cfg = Platform.packageConfig;
  if (cfg == null)
    throw StateError('no package config: cannot locate the package root');
  final cfgUri = cfg.startsWith('file:') ? Uri.parse(cfg) : Uri.file(cfg);
  final config = jsonDecode(File.fromUri(cfgUri).readAsStringSync()) as Map;
  for (final e in config['packages'] as List) {
    if ((e as Map)['name'] == 'sandbox_runtime') {
      return path.normalize(
        cfgUri.resolve(e['rootUri'] as String).toFilePath(),
      );
    }
  }
  throw StateError('sandbox_runtime not in the package config');
}

const Map<String, String> nodeArchToDir = {'x64': 'x64', 'arm64': 'arm64'};

/**
 * The srt-win binary packaged with this module
 * (`vendor/srt-win/<arch>/srt-win.exe`, arch from `process.arch`).
 * Pass explicitly as `windows.srtWin.path` if you want the vendored
 * exe — {@link resolveSrtWin} never falls back to it implicitly.
 *
 * WARNING: in a dev checkout this file may live inside your sandbox
 * write grant — a sandboxed process could overwrite it; prefer a
 * binary outside any grant (e.g. your own signed executable).
 */
final String VENDORED_SRT_WIN_EXE = path.join(
  repoRoot(),
  'vendor',
  'srt-win',
  nodeArchToDir[process.arch] ?? process.arch,
  'srt-win.exe',
);

/**
 * Locate a built `srt-win.exe` for development/CI. Checks, in order:
 *   1. `<root>/vendor/srt-win/{arch}/srt-win.exe` (prebuilt —
 *      {@link VENDORED_SRT_WIN_EXE}).
 *   2. `<root>/vendor/srt-win-src/target/release/srt-win.exe` (local
 *      `cargo build --release`).
 *
 * `<root>` is {@link repoRoot} — `__dirname/../..`, which resolves to the
 * repo root from `src/sandbox/` and `dist/sandbox/` alike, and to the
 * package root when installed under `node_modules`.
 *
 * This is an explicit helper — nothing calls it as an ambient
 * default. Production callers set `windows.srtWin.path` (their own
 * binary, or {@link VENDORED_SRT_WIN_EXE}); see {@link resolveSrtWin}.
 *
 * @throws if neither candidate exists.
 */
String getSrtWinPath() =>
    throw UnsupportedError('Windows is not supported by this port');

/**
 * `argv[1]` sentinel a multicall embedder's dispatcher matches
 * against to route into `srt_win::run_from_args`. Mirrors the Rust
 * `srt_win::SRT_WIN_DISPATCH_ARG1`; the two MUST stay in sync.
 * `run_from_args` strips it before clap, so the standalone binary
 * accepts it harmlessly.
 */
const String SRT_WIN_DISPATCH_ARG1 = '--srt-win';

/**
 * Resolved `srt-win` spawn descriptor — the executable to load plus
 * the leading arguments that carry the dispatch sentinel. Threaded
 * to every spawn site so {@link resolveSrtWin} runs once (at
 * `initialize()`) instead of re-`stat`ing on every helper call.
 */
class SrtWinSpawn {
  final String exe;
  final List<String> prependArgs;

  const SrtWinSpawn({required this.exe, required this.prependArgs});
}

/**
 * Resolve the `srt-win` spawn target from config. `cfg.path` is
 * required and used verbatim; {@link SRT_WIN_DISPATCH_ARG1} is
 * prepended so a multicall dispatcher routes on `argv[1]` (the
 * standalone binary strips it harmlessly).
 *
 * The path must be explicit because the packaged exe lives under
 * the package root, which in a dev checkout sits inside the
 * working-tree write grant (a planted `srt-win.exe` there would be
 * spawned as the broker). Callers that want the packaged binary
 * pass {@link VENDORED_SRT_WIN_EXE}.
 *
 * @throws if `cfg.path` is unset or names a missing file.
 */
SrtWinSpawn resolveSrtWin([SrtWinConfig? cfg]) =>
    throw UnsupportedError('Windows is not supported by this port');

// ────────────────────────────────────────────────────────────────────
// Internal: spawn helpers
// ────────────────────────────────────────────────────────────────────

class _RunResult {
  final int? status;
  final String? signal;
  final String stdout;
  final String stderr;

  const _RunResult({
    required this.status,
    required this.signal,
    required this.stdout,
    required this.stderr,
  });
}

class _RunOpts {
  final int? timeoutMs;
  final String? stdin;
  final SrtWinSpawn? srtWin;

  const _RunOpts({this.timeoutMs, this.stdin, this.srtWin});
}

_RunResult _runSrtWin(List<String> args, [_RunOpts opts = const _RunOpts()]) =>
    throw UnsupportedError('Windows is not supported by this port');

/**
 * `srt-win`'s exit code when its lock is held by a `profile grant` or
 * `profile forget`: the caller is told after about three seconds.
 */
const SRT_WIN_EXIT_PROFILE_BUSY = 25;

/**
 * `srt-win exec`'s exit code when the session a command was started
 * for (`heldBy`) ended while the command ran: the command and
 * everything it started were terminated.
 */
const SRT_WIN_EXIT_SESSION_ENDED = 26;

/** `srt-win`'s exit code for "nothing was removed: sandbox sessions or commands are running". */
const SRT_WIN_EXIT_HELD_BY_OTHERS = 22;

/** `srt-win profile grant`'s exit code for "nothing was changed: sandbox sessions or commands are running". */
const SRT_WIN_EXIT_GRANT_BLOCKED = 24;

/** One row of `srt-win`'s `{"held_by": […]}`, said as what it is. */
String _describeWindowsHolder(Map<String, Object?> h) {
  final who = 'process ${h.containsKey('pid') ? h['pid'] : 'undefined'}';
  final at = '${h.containsKey('path') ? h['path'] : 'undefined'}';
  switch (h['kind']) {
    case 'profile':
      return '$who is a sandbox session or command';
    case 'kept_root':
      return '$who runs on the kept write grant on $at';
    case 'grant':
      return '$who holds a session grant on $at';
    case 'deny':
    case 'deny_fdc':
    case 'deny_delete':
    case 'deny_satisfied':
      return '$who holds a session deny on $at';
    default:
      return '$who holds ${h.containsKey('kind') ? h['kind'] : 'undefined'} on $at';
  }
}

String _describeWindowsHolders(String stdout) {
  var held = <Map<String, Object?>>[];
  try {
    final parsed = jsonDecode(stdout);
    if (parsed is Map && parsed['held_by'] is List)
      held = (parsed['held_by'] as List).cast<Map<String, Object?>>();
  } catch (_) {
    // The exit code says it; the list is for the message only.
  }
  final said = held.take(8).map(_describeWindowsHolder).toList();
  if (held.length > said.length) said.add('${held.length - said.length} more');
  return said.join('; ');
}

/**
 * The one mapping of `srt-win`'s refusals beside other sandbox activity:
 * 25 (a profile operation runs), 22 (nothing removed), 24 (grant unchanged).
 */
void _throwIfRefusedBesideOthers(
  List<String> args,
  int? status,
  String stdout,
) {
  if (status == SRT_WIN_EXIT_PROFILE_BUSY)
    throw WindowsSandboxError(
      'profile_operation_in_progress',
      'The read grant on your user profile is being written or removed ' +
          'right now (srt-win profile grant / profile forget). Nothing in the ' +
          'sandbox can start until that is done; try again when it has ' +
          'finished.',
      args[0],
    );
  if (status != SRT_WIN_EXIT_HELD_BY_OTHERS &&
      status != SRT_WIN_EXIT_GRANT_BLOCKED)
    return;
  final what = _describeWindowsHolders(stdout);
  final who = what.isNotEmpty ? ' ($what)' : '';
  if (status == SRT_WIN_EXIT_GRANT_BLOCKED)
    throw WindowsSandboxError(
      'profile_grant_blocked_by_session',
      'The read grant on your user profile was not changed: sandbox ' +
          'sessions or commands are running$who, and the grant is written ' +
          'only while none is, so that no session sees it change. What was ' +
          'granted before is as it was. End them and run it again.',
      args[0],
    );
  throw WindowsSandboxError(
    'kept_grants_in_use',
    'srt-win ${args.take(2).join(' ')} removed nothing: sandbox ' +
        'sessions or commands are running$who, and what they run on is ' +
        'not taken from under them. End them and run it again.',
    args[0],
  );
}

/**
 * Async twin of {@link runSrtWin}: same signature, same result shape,
 * but the event loop stays live. Prefer it for any call reachable
 * from a UI/render path — the sync variant `spawnSync`-blocks, which
 * on Windows can be seconds when Defender cold-scans `srt-win.exe`.
 */
Future<_RunResult> _runSrtWinAsync(
  List<String> args, [
  _RunOpts opts = const _RunOpts(),
]) => throw UnsupportedError('Windows is not supported by this port');

T _parseSrtWinJson<T>(List<String> args, _RunResult r) {
  if (r.status != 0) {
    throw WindowsSandboxError(
      'srt_win_nonzero',
      'srt-win ${args.join(' ')} exited ${r.status}: ${r.stderr.isNotEmpty ? r.stderr : r.stdout}',
      args[0],
    );
  }
  try {
    return jsonDecode(r.stdout) as T;
  } catch (e) {
    throw WindowsSandboxError(
      'srt_win_bad_json',
      'srt-win ${args.join(' ')}: unparseable JSON output ' +
          '${jsonEncode(r.stdout)}: ${errorMessage(e)}',
      args[0],
    );
  }
}

T _runSrtWinJson<T>(List<String> args, [_RunOpts? opts]) =>
    _parseSrtWinJson<T>(args, _runSrtWin(args, opts ?? const _RunOpts()));

Future<T> _runSrtWinJsonAsync<T>(List<String> args, [_RunOpts? opts]) async =>
    _parseSrtWinJson<T>(
      args,
      await _runSrtWinAsync(args, opts ?? const _RunOpts()),
    );

/**
 * As {@link runSrtWinJson} but parses stdout BEFORE checking the
 * exit code, so a non-zero exit with the per-path JSON intact
 * still surfaces every entry. For best-effort teardown helpers
 * (`acl restore`/`acl revoke`).
 */
({bool ok, T json, String stderr}) _runSrtWinJsonAllowFail<T>(
  List<String> args,
  _RunOpts opts,
) => throw UnsupportedError('Windows is not supported by this port');

// ────────────────────────────────────────────────────────────────────
// Status / install API
// ────────────────────────────────────────────────────────────────────

/** Shape of `srt-win wfp status` (and `srt-win status .wfp`) stdout. */
typedef _RawWfpStatus = Map<String, dynamic>;

List<String> _wfpStatusArgs([String? sublayerGuid]) {
  final args = ['wfp', 'status'];
  if (sublayerGuid != null && sublayerGuid.isNotEmpty)
    args.addAll(['--sublayer-guid', sublayerGuid]);
  return args;
}

WindowsWfpStatusResult _mapWfpStatus(_RawWfpStatus raw) {
  final portRange = raw['port_range'] as List?;
  final userSid = raw['user_sid'] as String?;
  final hint = raw['hint'] as String?;
  return WindowsWfpStatusResult(
    state: raw['state'] as WindowsWfpStatus,
    filters: raw['filters'] as int,
    allowLoopback: raw['allow_loopback'] == true,
    portRange: portRange != null
        ? (portRange[0] as int, portRange[1] as int)
        : null,
    userSid: userSid != null && userSid.isNotEmpty ? userSid : null,
    hint: hint != null && hint.isNotEmpty ? hint : null,
  );
}

/** Shape of `srt-win user status` (and `srt-win status .user`) stdout. */
typedef _RawUserStatus = Map<String, dynamic>;

/**
 * Behaviours of `srt-win` this library relies on and asks for by
 * name. `srt-win` lists what it does as `capabilities` in `user
 * status` and `profile status`.
 */
const WINDOWS_SRT_WIN_CAPABILITIES = (
  /**
   * A read deny handed to `srt-win` is also written on every recorded
   * path of the profile read grant beneath it that carries an allow
   * of its own.
   */
  profileDenyExpansion: 'profile-deny-expansion',
  /**
   * Sessions are recorded as holders of the kept grants they run on,
   * and `acl forget` / `profile forget` take
   * `--unless-held-by-others`.
   */
  keptGrantHolders: 'kept-grant-holders',
  /**
   * `acl grant` itself refuses a path that reaches an exclusion
   * recorded with the profile read grant.
   */
  profileSessionGrantCheck: 'profile-session-grant-check',
  /**
   * That expansion leaves out the recorded paths the session allows
   * more specifically: the grants of the same `acl grant` call, and
   * the ones a command names with `--deny-read-except`.
   */
  readDenyExcept: 'read-deny-except',
  /**
   * A session under the write-restricted token is recorded as a
   * holder of the profile read grant from its start, and `exec` is
   * told which session holds for it (`--held-by`) or holds for itself.
   */
  execHolder: 'exec-holder',
  /**
   * `profile retry-stale` tries again to revoke what the last run could
   * not, and `profile status` says which operation wrote the record and
   * whether it is this profile's.
   */
  profileRetryStale: 'profile-retry-stale',
);

/**
 * The first capability this library needs that `capabilities` (as
 * `srt-win` reported them) does not list.
 */
String? missingWindowsSrtWinCapability(List<String> capabilities) {
  return [
    WINDOWS_SRT_WIN_CAPABILITIES.profileDenyExpansion,
    WINDOWS_SRT_WIN_CAPABILITIES.keptGrantHolders,
    WINDOWS_SRT_WIN_CAPABILITIES.profileSessionGrantCheck,
    WINDOWS_SRT_WIN_CAPABILITIES.readDenyExcept,
    WINDOWS_SRT_WIN_CAPABILITIES.execHolder,
    WINDOWS_SRT_WIN_CAPABILITIES.profileRetryStale,
  ].where((c) => !capabilities.contains(c)).firstOrNull;
}

List<String> _capabilityList(Object? v) =>
    v is List ? v.whereType<String>().toList() : [];
/** The typed error for an `srt-win` that lacks a behaviour by name. */
WindowsSandboxError windowsSrtWinOutdatedError(String capability, String why) =>
    WindowsSandboxError(
      'srt_win_outdated',
      'The srt-win in use is older than this library: it does not report ' +
          "the capability '$capability', which $why. Update srt-win (the " +
          'one shipped with the program embedding this library, or the ' +
          "package's own) to a build that matches the library. Nothing was " +
          'granted.',
    );
const _SECLOGON_STATES = ['ok', 'disabled', 'missing', 'cannot-read'];

WindowsSandboxUserStatus _mapUserStatus(_RawUserStatus raw) {
  final user = raw['user'] as Map<String, dynamic>;
  final sid = user['sid'] as String?;
  final groupSid = user['group_sid'] as String?;
  final markerVersion = raw['marker_version'];
  final caCertThumb = raw['ca_cert_thumb'] as String?;
  final caCertPem = raw['ca_cert_pem'] as String?;
  return WindowsSandboxUserStatus(
    provisioned: user['exists'] as bool,
    sid: sid != null && sid.isNotEmpty ? sid : null,
    groupExists: user['group_exists'] as bool,
    groupSid: groupSid != null && groupSid.isNotEmpty ? groupSid : null,
    inBuiltinUsers: user['in_builtin_users'] as bool,
    inSandboxGroup: user['in_sandbox_group'] as bool,
    hiddenFromLogon: user['hidden_from_logon'] as bool,
    credPresent: raw['cred_present'] as bool,
    markerVersion: markerVersion is num ? markerVersion.toInt() : null,
    setupVersion: raw['setup_version'] is num
        ? (raw['setup_version'] as num).toInt()
        : null,
    realUserSid: raw['real_user_sid'] as String,
    caCertThumb: caCertThumb != null && caCertThumb.isNotEmpty
        ? caCertThumb
        : null,
    caCertPem: caCertPem != null && caCertPem.isNotEmpty ? caCertPem : null,
    seclogon: _SECLOGON_STATES.contains(raw['seclogon'])
        ? raw['seclogon'] as String
        : null,
    // Anything but an explicit "none" counts: a state this code does
    // not know must not read as "no grants".
    persistentGrants:
        raw['persistent_grants'] != null &&
            raw['persistent_grants']['state'] != 'none'
        ? (
            state: raw['persistent_grants']['state'] == 'present'
                ? 'present'
                : 'unknown',
            roots:
                (raw['persistent_grants']['roots'] as List?)?.cast<String>() ??
                <String>[],
            reason:
                (raw['persistent_grants']['reason'] as String?)?.isNotEmpty ==
                    true
                ? raw['persistent_grants']['reason'] as String
                : null,
          )
        : null,
    sessionUserSid: (raw['session_user_sid'] as String?)?.isNotEmpty == true
        ? raw['session_user_sid'] as String
        : null,
    capabilities: _capabilityList(raw['capabilities']),
    // As above: only an explicit "none" is no grant.
    profileGrant:
        raw['profile_grant'] != null && raw['profile_grant']['state'] != 'none'
        ? (
            state: raw['profile_grant']['state'] == 'present'
                ? 'present'
                : 'unknown',
            reason:
                (raw['profile_grant']['reason'] as String?)?.isNotEmpty == true
                ? raw['profile_grant']['reason'] as String
                : null,
          )
        : null,
  );
}

/** User-facing text for a disabled/absent Secondary Logon service. */
String _seclogonDisabledMessage(String state) => state == 'missing'
    ? 'The Windows Secondary Logon service (seclogon) is not present ' +
          'on this machine; the sandbox cannot start without it.'
    : 'The Windows Secondary Logon service (seclogon) is disabled; an ' +
          'administrator must set its startup type to Manual (`sc.exe ' +
          'config seclogon start= demand`). The sandbox cannot start ' +
          'without it.';
/** `srt-win` exit code for a `seclogon_disabled` launch failure. */
const _SRT_WIN_EXIT_SECLOGON_DISABLED = 18;
/**
 * The typed `seclogon_disabled` error for an `srt-win` launch result, if it
 * is one. Gated on the exit code first: the child's own stderr could match.
 */
SeclogonDisabledError? _seclogonDisabledFrom(
  ({int? status, String stderr}) r,
  String subcommand,
) {
  if (r.status != _SRT_WIN_EXIT_SECLOGON_DISABLED) return null;
  final e = _parseSrtWinLaunchError(r.stderr, subcommand);
  return e is SeclogonDisabledError ? e : null;
}

/** Combined result of `srt-win status` — see {@link checkWindowsSandboxStatus}. */
class WindowsSandboxStatus {
  final WindowsSandboxUserStatus user;
  final WindowsWfpStatusResult wfp;

  const WindowsSandboxStatus({required this.user, required this.wfp});
}

/**
 * Query sandbox-user provisioning state AND the WFP filter set in a
 * single `srt-win status` spawn — the same objects
 * {@link getWindowsSandboxUserStatus} and {@link getWindowsWfpStatus}
 * return, without paying two subprocess round-trips. Does not require
 * elevation (WFP degrades to `cannot-read` for a non-elevated caller;
 * see {@link WindowsWfpStatusResult.hint}).
 */
WindowsSandboxStatus checkWindowsSandboxStatus({
  String? sublayerGuid,
  SrtWinSpawn? srtWin,
}) => throw UnsupportedError('Windows is not supported by this port');

/** Async twin of {@link checkWindowsSandboxStatus}. */
Future<WindowsSandboxStatus> checkWindowsSandboxStatusAsync({
  String? sublayerGuid,
  SrtWinSpawn? srtWin,
}) async => throw UnsupportedError('Windows is not supported by this port');

/**
 * Query the WFP filter set under the given sublayer via live BFE
 * enumeration. `installed` means at least one srt-win-tagged
 * `block-user` filter is present. Detection is **tag-based**
 * (providerData JSON); filters installed by other tooling without the
 * tag are not counted.
 *
 * BFE enumeration is admin-gated — a non-elevated caller gets
 * `state:"cannot-read"` with a `hint` (not an error). The
 * non-elevated readiness check is {@link verifyWindowsWfpEgress}.
 *
 * Prefer {@link getWindowsWfpStatusAsync}; this variant
 * `spawnSync`-blocks the event loop.
 */
WindowsWfpStatusResult getWindowsWfpStatus({
  String? sublayerGuid,
  SrtWinSpawn? srtWin,
}) => throw UnsupportedError('Windows is not supported by this port');

/** Async twin of {@link getWindowsWfpStatus}. */
Future<WindowsWfpStatusResult> getWindowsWfpStatusAsync({
  String? sublayerGuid,
  SrtWinSpawn? srtWin,
}) async => throw UnsupportedError('Windows is not supported by this port');

typedef _RawWfpVerify = Map<String, dynamic>;

/**
 * The options of the install a session expects. A suggested install
 * command names only the ones that are not the defaults.
 */
class WindowsInstallContext {
  final String? sublayerGuid;
  final (int, int)? proxyPortRange;
  final String? sandboxUser;
  final bool? allowLoopback;
  const WindowsInstallContext({
    this.sublayerGuid,
    this.proxyPortRange,
    this.sandboxUser,
    this.allowLoopback,
  });
}

/**
 * Install flags for `ctx`. `force` only when the install replaces a
 * set that is in place with another configuration: it refuses that
 * without `--force` (exit 13), and needs none otherwise.
 */
String _windowsInstallFlags(WindowsInstallContext ctx, bool force) {
  final (lo, hi) = ctx.proxyPortRange ?? DEFAULT_WINDOWS_PROXY_PORT_RANGE;
  final (defLo, defHi) = DEFAULT_WINDOWS_PROXY_PORT_RANGE;
  return ((ctx.sublayerGuid?.isNotEmpty ?? false)
          ? ' --sublayer-guid ${ctx.sublayerGuid}'
          : '') +
      (lo != defLo || hi != defHi ? ' --proxy-port-range $lo-$hi' : '') +
      (ctx.sandboxUser != null &&
              ctx.sandboxUser!.isNotEmpty &&
              ctx.sandboxUser != 'srt-sandbox'
          ? ' --sandbox-user ${ctx.sandboxUser}'
          : '') +
      (ctx.allowLoopback == true ? ' --allow-loopback' : '') +
      (force ? ' --force' : '');
}

/** The install command, as error messages print it. */
const WINDOWS_INSTALL_COMMAND =
    'npx @anthropic-ai/sandbox-runtime windows-install';
String _windowsInstallCommand(WindowsInstallContext ctx, bool force) =>
    WINDOWS_INSTALL_COMMAND + _windowsInstallFlags(ctx, force);
/**
 * Whether a failed `srt-win` run is an `srt-win` that predates
 * `--allow-loopback` rejecting the argument.
 */
bool _rejectsAllowLoopback(({String stderr}) r) =>
    RegExp("unexpected argument '--allow-loopback'").hasMatch(r.stderr);
WindowsSandboxError _srtWinTooOld(String stderr) => WindowsSandboxError(
  'srt_win_too_old',
  'srt-win is too old for network.allowLocalBinding: it does not know ' +
      '`--allow-loopback`. Update srt-win (and re-run the install with ' +
      'it), or unset network.allowLocalBinding. (${stderr.trim()})',
);
const _WFP_RESIDUAL_TEXT = <WindowsWfpResidual, String>{
  'anonymous-egress':
      'a connect to an off-loopback destination made while impersonating ' +
      'the anonymous token is not blocked (no filter is keyed on that ' +
      'token; a sandboxed process that puts it on a thread before ' +
      'creating a socket is not fenced)',
  'anonymous-loopback':
      'a connect to a loopback destination made while impersonating the ' +
      'anonymous token is not blocked (local listeners outside the proxy ' +
      'port range are reachable that way)',
  'deny-only-user-sid':
      'a connect made under a copy of the sandbox token whose user SID is ' +
      'deny-only is not blocked (the filters cannot match that token)',
  'lowered-integrity-unprobed':
      'a lowered-integrity copy of the sandbox token could not be set up on ' +
      'this machine, so no connect under it was observed',
};
bool _isWfpResidual(String s) => _WFP_RESIDUAL_TEXT.containsKey(s);

/**
 * Behavioral proof that the WFP egress fence is active for the
 * sandbox user. Binds a local listener on an ephemeral loopback port
 * outside the WFP loopback-permit range, then spawns `srt-win
 * runner` as the sandbox user (via `CreateProcessWithLogonW`) to
 * attempt a direct TCP connect to it. The WFP block-user filter
 * fires at `ALE_AUTH_CONNECT` — before any packet leaves — so an
 * active fence yields WSAEACCES immediately and a missing fence lets
 * the connect through (the kernel completes the handshake against
 * the listening socket's backlog; no event-loop tick required, so
 * the synchronous `runSrtWin` is safe). Does not require elevation
 * and does not depend on any external host.
 *
 * `initialize()` calls this once per session, so a stale install
 * (sandbox user provisioned but filters since removed) fails closed
 * at session start instead of running every exec with full egress.
 *
 * @param opts.target overrides the probe target (skips the local
 *   listener bind).
 * @param opts.proxyPortRange the WFP loopback-permit range the
 *   listener must avoid. Default
 *   {@link DEFAULT_WINDOWS_PROXY_PORT_RANGE}.
 * @throws on any outcome other than `blocked` (exit 0).
 */
Future<WindowsWfpVerifyResult> verifyWindowsWfpEgress({
  String? target,
  (int, int)? proxyPortRange,
  bool? allowLoopback,
  bool? anonymousEgress,
  String? sublayerGuid,
  String? sandboxUser,
  List<String>? writeRoots,
  SrtWinSpawn? srtWin,
}) async => throw UnsupportedError('Windows is not supported by this port');

/**
 * Query the sandbox user account's provisioning state. Each field
 * is independently observed so a half-provisioned install (e.g.
 * user exists but credential file missing) is distinguishable.
 * Does not require elevation.
 *
 * Prefer {@link getWindowsSandboxUserStatusAsync}; this variant
 * `spawnSync`-blocks the event loop.
 */
WindowsSandboxUserStatus getWindowsSandboxUserStatus({SrtWinSpawn? srtWin}) =>
    throw UnsupportedError('Windows is not supported by this port');

/** Async twin of {@link getWindowsSandboxUserStatus}. */
Future<WindowsSandboxUserStatus> getWindowsSandboxUserStatusAsync({
  SrtWinSpawn? srtWin,
}) async => throw UnsupportedError('Windows is not supported by this port');

/**
 * Read back the persistent MITM CA the sandbox was installed with
 * (via `srt-win user trust-ca` / {@link windowsTrustCa}).
 * Returns `null` when no CA was installed. The PEM is what `srt-win
 * user status` reconstructs from the DER recorded in the registry.
 *
 * On Windows, `tlsTerminate` requires this CA to be present in the
 * sandbox user's `CurrentUser\Root` (schannel-level trust is an
 * install-time concern, not per-session); the host calls this from
 * `initialize()` to fail early with an actionable message when it
 * isn't.
 *
 * @param status pass an already-fetched
 *   {@link getWindowsSandboxUserStatus} result to avoid a second
 *   `srt-win user status` spawn.
 */
({String pem, String thumb})? getWindowsSandboxCaCert({
  WindowsSandboxUserStatus? status,
  SrtWinSpawn? srtWin,
}) => throw UnsupportedError('Windows is not supported by this port');

/**
 * Install (or replace) the MITM CA in the **sandbox user's**
 * `CurrentUser\Root` and record it in the registry (so
 * {@link getWindowsSandboxCaCert} surfaces its thumbprint + PEM).
 * Thin wrapper around `srt-win user trust-ca <path>`. Does NOT
 * require elevation. Persistent until {@link uninstallWindowsSandbox}
 * deletes the sandbox user's profile.
 *
 * The CA has a separate lifecycle from {@link installWindowsSandbox}
 * — install provisions the account/filters and never touches the CA;
 * call this AFTER install when `tlsTerminate` will be used.
 *
 * @throws when the sandbox user is not provisioned, the file is not a
 *   parseable X.509 certificate, or the registry write into the
 *   sandbox user's hive fails.
 */
void windowsTrustCa(String caCertPath, {SrtWinSpawn? srtWin}) =>
    throw UnsupportedError('Windows is not supported by this port');

/** Async twin of {@link windowsTrustCa} — identical argv and errors. */
Future<void> windowsTrustCaAsync(
  String caCertPath, {
  SrtWinSpawn? srtWin,
}) async => throw UnsupportedError('Windows is not supported by this port');

void _checkTrustCaResult(String caCertPath, _RunResult r) {
  logForDebugging(
    '[Sandbox Windows] user trust-ca exit=${r.status}: ${r.stderr.isNotEmpty ? r.stderr : r.stdout}',
  );
  if (r.status != 0) {
    throw WindowsSandboxError(
      'trust_ca_failed',
      "srt-win user trust-ca '$caCertPath' failed (exit " +
          '${r.status}): ${r.stderr.isNotEmpty ? r.stderr : r.stdout}',
    );
  }
}

/**
 * The machine-wide state directory `%ProgramData%\sandbox-runtime`,
 * mirroring `srt-win`'s `state_db::machine_store_dir()` exactly.
 * Since the registry move it hosts only the managed CA key material
 * (`ca\`), which must stay on the filesystem because the broker's
 * unelevated generate-if-absent self-heal rewrites it; the
 * credential, marker, and CA record live in
 * `HKLM\SOFTWARE\sandbox-runtime`. Created and ACL'd by the
 * elevated `srt-win install`: Administrators own it, BUILTIN\Users
 * have modify, and the sandbox group carries an explicit
 * `(OI)(CI)` DENY.
 */
String windowsStateDir() {
  final programData = process.env['ProgramData'];
  if (programData == null || programData.isEmpty)
    throw Exception('ProgramData is not set');
  return path.windows.join(programData, 'sandbox-runtime');
}

/** Result of {@link ensurePersistentWindowsCa}. */
class WindowsPersistentCa {
  /**
   * PEM certificate — pass to `createMitmCA({caCertPem, caKeyPem})` so
   * the caller doesn't re-read from disk.
   */
  final String certPem;
  /** PEM private key — see {@link certPem}. */
  final String keyPem;
  /**
   * `cert.pem` on disk (derived from `ca.json`; exists so
   * {@link windowsTrustCa} and diagnostic tooling have a path).
   */
  final String certPath;
  /** `key.pem` on disk (derived from `ca.json`). */
  final String keyPath;
  /** Uppercase-hex SHA-1 (matches `srt-win user status` `caCertThumb`). */
  final String thumbprint;
  /**
   * `true` when this call generated a fresh CA (first run, `force`, or
   * the on-disk pair was invalid/expiring); `false` when the existing
   * on-disk pair was reused.
   */
  final bool generated;
  /**
   * `true` when this call wrote the CA into the sandbox user's
   * `CurrentUser\Root` (via {@link windowsTrustCa}) — always on
   * `generated`, and on reuse when the sandbox user's installed
   * thumbprint didn't already match. Callers holding a
   * {@link WindowsSandboxUserStatus} fetched before this call should
   * treat its `caCertThumb` as stale when `trusted` is true.
   */
  final bool trusted;

  const WindowsPersistentCa({
    required this.certPem,
    required this.keyPem,
    required this.certPath,
    required this.keyPath,
    required this.thumbprint,
    required this.generated,
    required this.trusted,
  });
}

/**
 * Generate-if-absent a persistent MITM CA under
 * `{windowsStateDir()}\ca\` and ensure it is trusted in
 * the sandbox user's `CurrentUser\Root`. Idempotent and unelevated:
 * a second call with a valid on-disk pair returns it with
 * `generated: false`. On the machine store the `ca\` subdir is
 * user-writable by design (BUILTIN\Users modify, inherited from the
 * install-ACL'd store), so this self-heal keeps working without
 * admin rights for every user of the machine.
 *
 * **Storage.** The pair lives in a single `ca.json = {certPem,
 * keyPem}` written atomically (tmp+rename) and re-read after every
 * write, so it is always a matched pair and concurrent brokers
 * converge on whichever rename landed last. `cert.pem`/`key.pem` are
 * derived copies for diagnostic tooling; `ca.json` is the source of
 * truth.
 *
 * **Key custody is broker-side.** The MITM proxy runs as the real
 * user, so the sandbox user never needs to read the key. The `ca/`
 * subdirectory inherits the machine store's `(OI)(CI)` DACL, which
 * carries an explicit `sandbox-runtime-users` DENY (see
 * {@link windowsStateDir}), so `ca.json`/`key.pem` are unreadable
 * from inside the sandbox with no per-file ACL work here. The key
 * IS readable (and replaceable) by other REAL local users — an
 * accepted trade-off of the shared store: the sandbox account is
 * network-confined by SID-keyed WFP filters regardless of who
 * spawns it. The certificate reaches the sandboxed child via the
 * schannel registry write ({@link windowsTrustCa}) and the
 * trust-bundle env vars — never via these files.
 *
 * `SandboxManager.initialize()` calls this on Windows when
 * `tlsTerminate` is enabled without an explicit
 * `caCertPath`/`caKeyPath`, then feeds the returned PEMs to
 * `createMitmCA` — so an embedder gets a stable CA across restarts
 * without orchestrating generation, storage, or trust itself. Explicit
 * paths in config bypass this entirely.
 *
 * @param opts.force regenerate even if a valid pair is on disk.
 * @param opts.status pass an already-fetched
 *   {@link getWindowsSandboxUserStatus} result to skip the
 *   provisioning check and avoid re-spawning `srt-win user status`
 *   for the trust reconcile.
 * @param opts.dir override the CA directory (tests). Default
 *   `windowsStateDir()/ca`.
 * @param opts.regenerateWithinDays regenerate if `notAfter` is within
 *   this many days. Default 30.
 * @throws when the sandbox user is not provisioned (run
 *   {@link installWindowsSandbox} first), or the CA directory cannot
 *   be created.
 */
Future<WindowsPersistentCa> ensurePersistentWindowsCa({
  bool? force,
  WindowsSandboxUserStatus? status,
  String? dir,
  int? regenerateWithinDays,
  SrtWinSpawn? srtWin,
}) async => throw UnsupportedError('Windows is not supported by this port');

class WindowsInstallOptions {
  /** WFP sublayer GUID. Omit for srt-win's compile-time default. */
  final String? sublayerGuid;
  /**
   * Loopback PERMIT port range. Must match what
   * `SandboxRuntimeConfig.windows.proxyPortRange` will be set to.
   * Default {@link DEFAULT_WINDOWS_PROXY_PORT_RANGE}.
   */
  final (int, int)? proxyPortRange;
  /**
   * Open loopback ({@link WINDOWS_ALLOW_LOOPBACK_EFFECT}); must match
   * `network.allowLocalBinding`. Take it only from a source the machine's
   * user or administrator controls, never from a project's own files.
   */
  final bool? allowLoopback;
  /**
   * Name for the sandbox user account (created if absent, adopted
   * if it already exists as a local user). Default `srt-sandbox`.
   */
  final String? sandboxUser;
  /**
   * Replace an existing install whose configuration differs
   * (different port range, loopback mode or sandbox-user name under
   * the same sublayer). Without this, install refuses with "already
   * installed with different config" rather than silently
   * overwriting.
   */
  final bool? force;
  /**
   * How long to wait for the self-elevating install subprocess.
   * Defaults to {@link INSTALL_TIMEOUT_MS}.
   */
  final int? timeoutMs;
  /**
   * Leave the profile read grant unapplied.
   */
  final bool? skipProfileGrant;
  /**
   * Paths inside the profile to keep unreadable in addition to the
   * built-in exclusions — {@link WindowsProfileGrantOptions.exclude}.
   */
  final List<String>? profileExclude;
  /**
   * Directories (or files) inside the profile to make readable in
   * addition to the built-in list — {@link WindowsProfileGrantOptions.include}.
   */
  final List<String>? profileInclude;
  /**
   * How long the profile read grant may take. Default 30 minutes; the
   * first grant touches every file under the granted directories.
   */
  final int? profileGrantTimeoutMs;
  /**
   * Called with each progress line of the profile read grant (a count
   * of top-level items done). The synchronous install delivers the
   * lines only when the grant has finished.
   */
  final void Function(String line)? onProfileGrantProgress;
  /**
   * Called once, right before the profile read grant is applied (not
   * when it is skipped), with {@link windowsProfileGrantNotice} for
   * the profile about to be granted: one line to show the user.
   */
  final void Function(String notice)? onProfileGrantStart;
  /** Resolved `srt-win` spawn descriptor — from {@link resolveSrtWin}. */
  final SrtWinSpawn? srtWin;

  const WindowsInstallOptions({
    this.sublayerGuid,
    this.proxyPortRange,
    this.allowLoopback,
    this.sandboxUser,
    this.force,
    this.timeoutMs,
    this.skipProfileGrant,
    this.profileExclude,
    this.profileInclude,
    this.profileGrantTimeoutMs,
    this.onProfileGrantProgress,
    this.onProfileGrantStart,
    this.srtWin,
  });
}

/**
 * What an install did about the profile read grant.
 */
sealed class WindowsInstallProfileGrant {
  const WindowsInstallProfileGrant();
}

class WindowsInstallProfileGrantApplied extends WindowsInstallProfileGrant {
  final bool applied = true;
  /** SID of the user whose profile was granted. */
  final String userSid;
  final WindowsProfileGrantResult result;
  const WindowsInstallProfileGrantApplied({
    required this.userSid,
    required this.result,
  });
}

class WindowsInstallProfileGrantSkipped extends WindowsInstallProfileGrant {
  final bool applied = false;
  /**
   * Why not. Sessions still run; they read nothing in the profile
   * until the grant is applied.
   */
  final String reason;
  const WindowsInstallProfileGrantSkipped({required this.reason});
}

class WindowsInstallResult {
  /** Post-install WFP state. */
  final WindowsWfpStatusResult wfp;
  /** Post-install sandbox-user state. */
  final WindowsSandboxUserStatus user;
  /** The profile read grant; absent when the install was cancelled. */
  final WindowsInstallProfileGrant? profileGrant;
  /**
   * `true` if the user dismissed the UAC prompt. Not an error —
   * the install simply didn't happen. Re-run when the user is
   * ready to grant elevation.
   */
  final bool? cancelled;

  const WindowsInstallResult({
    required this.wfp,
    required this.user,
    this.profileGrant,
    this.cancelled,
  });
}

/**
 * Default spawn budget for the self-elevating install/uninstall. The Windows
 * UAC consent dialog auto-dismisses after ~2 minutes, so anything shorter
 * risks killing the subprocess while a legitimate approval is still pending
 * (elevation is not retracted when the parent dies, so a late approval after
 * we have timed out would half-complete).
 */
const int _INSTALL_TIMEOUT_MS = 120000;

/** Effective spawn budget for the self-elevating install/uninstall. */
int _installTimeoutMs({int? timeoutMs}) {
  return timeoutMs ?? _INSTALL_TIMEOUT_MS;
}

List<String> _installArgs(WindowsInstallOptions opts) {
  final args = ['install'];
  if (opts.sublayerGuid != null && opts.sublayerGuid!.isNotEmpty)
    args.addAll(['--sublayer-guid', opts.sublayerGuid!]);
  if (opts.proxyPortRange != null) {
    args.addAll([
      '--proxy-port-range',
      '${opts.proxyPortRange!.$1}-${opts.proxyPortRange!.$2}',
    ]);
  }
  if (opts.allowLoopback == true) args.add('--allow-loopback');
  if (opts.sandboxUser != null && opts.sandboxUser!.isNotEmpty)
    args.addAll(['--sandbox-user', opts.sandboxUser!]);
  if (opts.force == true) args.add('--force');
  return args;
}

/**
 * Re-throw a `srt_win_timeout` from the install spawn as the more
 * specific `install_timeout` (the UAC prompt is the usual cause).
 * Shared by the sync and async install variants.
 */
Never _remapInstallTimeout(Object e) {
  if (e is WindowsSandboxError && e.code == 'srt_win_timeout') {
    throw WindowsSandboxError(
      'install_timeout',
      'srt-win install timed out — the UAC prompt may still be open. ' +
          'Re-run when ready to grant elevation. (${e.message})',
    );
  }
  throw e;
}

// srt-win install exit-code contract:
//   0  ok
//   10 user cancelled UAC elevation
//   12 WFP install failed
//   13 already installed with different config (use --force)
//   14 sandbox-user provisioning failed
//   17 ambient write-deny stamping failed
//   1  other error (stderr has detail)
// Throws on any failure code; the caller reads back state on 0/10.
void _throwOnInstallFailure(_RunResult r) {
  logForDebugging(
    '[Sandbox Windows] install exit=${r.status}: ${r.stderr.isNotEmpty ? r.stderr : r.stdout}',
  );
  if (r.status == 0 || r.status == 10) return;
  final out = r.stderr.isNotEmpty ? r.stderr : r.stdout;
  switch (r.status) {
    case 12:
      throw WindowsSandboxError(
        'install_wfp_failed',
        'srt-win install: WFP filter install failed: $out',
      );
    case 14:
      throw WindowsSandboxError(
        'install_user_failed',
        'srt-win install: sandbox user provisioning failed: $out',
      );
    case 13:
      throw WindowsSandboxError(
        'install_config_conflict',
        'srt-win install: filters already exist under this sublayer with ' +
            'a different port range or sandbox-user name. Pass ' +
            '{force: true} to replace, or pick a different sublayerGuid. ' +
            'Output: $out',
      );
    case 17:
      throw WindowsSandboxError(
        'install_ambient_failed',
        'srt-win install: ambient write-deny stamping failed (stock ' +
            'world-writable system dirs could not be deny-stamped for the ' +
            'sandbox user): $out',
      );
    default:
      throw WindowsSandboxError(
        'install_failed',
        'srt-win install failed (exit ${r.status}): $out',
      );
  }
}

/**
 * One-shot install: provisions the `srt-sandbox` user account and
 * installs the user-SID-keyed WFP filter set — all in a single
 * self-elevating process (one UAC prompt). Idempotent; re-running
 * rotates the sandbox user's password.
 *
 * Network for the calling user is **not disrupted**: the filters key
 * on the `srt-sandbox` user's SID, so the broker, services, and
 * every other principal fall through to default-permit. No logout
 * is required.
 *
 * Returns the post-call WFP + sandbox-user state. If the user
 * cancels the UAC prompt this returns `{cancelled: true, …}` rather
 * than throwing — cancellation is a user choice, not an error.
 *
 * Prefer {@link installWindowsSandboxAsync}; this variant
 * `spawnSync`-blocks the event loop for the full UAC-prompt wait
 * (up to `timeoutMs`).
 *
 * @throws on user/WFP creation failure, or if filters already exist
 *   under `sublayerGuid` with a different port range and `force` is
 *   not set.
 */
WindowsInstallResult installWindowsSandbox({
  String? sublayerGuid,
  (int, int)? proxyPortRange,
  bool? allowLoopback,
  String? sandboxUser,
  bool? force,
  int? timeoutMs,
  bool? skipProfileGrant,
  List<String>? profileExclude,
  List<String>? profileInclude,
  int? profileGrantTimeoutMs,
  void Function(String line)? onProfileGrantProgress,
  void Function(String notice)? onProfileGrantStart,
  SrtWinSpawn? srtWin,
}) => throw UnsupportedError('Windows is not supported by this port');

/**
 * Async twin of {@link installWindowsSandbox}. Same options, same
 * return type, same throw semantics. The UAC prompt is still modal,
 * but the event loop stays live — spinners keep painting and timers
 * keep firing.
 */
Future<WindowsInstallResult> installWindowsSandboxAsync({
  String? sublayerGuid,
  (int, int)? proxyPortRange,
  bool? allowLoopback,
  String? sandboxUser,
  bool? force,
  int? timeoutMs,
  bool? skipProfileGrant,
  List<String>? profileExclude,
  List<String>? profileInclude,
  int? profileGrantTimeoutMs,
  void Function(String line)? onProfileGrantProgress,
  void Function(String notice)? onProfileGrantStart,
  SrtWinSpawn? srtWin,
}) async => throw UnsupportedError('Windows is not supported by this port');

/** LocalSystem, LocalService, NetworkService: accounts no one runs sessions as. */
const _WINDOWS_SERVICE_ACCOUNT_SIDS = {'S-1-5-18', 'S-1-5-19', 'S-1-5-20'};

/**
 * Why an install leaves the profile read grant unapplied (`undefined`: it
 * applies it): asked to skip, a service account, or not running as the
 * owner of the interactive session, whose profile it would open instead.
 */
String? windowsProfileGrantSkipReason(
  WindowsSandboxUserStatus user, {
  bool? skipProfileGrant,
}) {
  if (skipProfileGrant == true) return 'skipProfileGrant was set';
  const how =
      'run the install, or grantWindowsProfileRead() (`srt-win profile ' +
      'grant`), as the user whose sessions are to read their profile';
  if (_WINDOWS_SERVICE_ACCOUNT_SIDS.contains(user.realUserSid))
    return 'the install ran as the service account ${user.realUserSid}, which ' +
        'runs no sessions; $how';
  if (user.sessionUserSid == null)
    return 'the owner of the session this install ran in could not be ' +
        'determined, so it is not known whose profile ${user.realUserSid} ' +
        'is; $how';
  if (user.sessionUserSid!.toUpperCase() != user.realUserSid.toUpperCase())
    return 'the install ran as ${user.realUserSid} in a session that belongs ' +
        'to ${user.sessionUserSid}; granting would open the installing ' +
        "account's profile, not the session owner's; $how";
  return null;
}

WindowsInstallProfileGrant? _installProfileGrantSkip(
  WindowsInstallOptions opts,
  WindowsSandboxUserStatus user,
) {
  final reason = windowsProfileGrantSkipReason(
    user,
    skipProfileGrant: opts.skipProfileGrant,
  );
  return reason == null
      ? null
      : WindowsInstallProfileGrantSkipped(reason: reason);
}

/**
 * What the profile read grant is about to do, in one line, for the person
 * at the keyboard.
 */
String windowsProfileGrantNotice(String profileDir) =>
    'Making the tool directories of $profileDir readable to sandboxed ' +
    'commands on this machine: where per-user tools install themselves ' +
    '(AppData\\Local\\Programs, AppData\\Roaming\\npm, go, .nuget, ' +
    '.cargo and the like) and package-manager configuration that can ' +
    'hold feed tokens (.npmrc, pip.ini, NuGet.Config, Maven settings.xml, ' +
    'gradle.properties, .gitconfig). Documents, Desktop, Downloads and ' +
    'the rest of the profile are not readable unless added (the names ' +
    'inside some AppData folders can be listed); credential ' +
    'stores (SSH and GPG keys, cloud and browser sign-ins, password ' +
    'managers, registry hives) are denied. Skip with --skip-profile-grant ' +
    '(skipProfileGrant); undo with `srt-win profile forget` ' +
    '(forgetWindowsProfileRead()).';
WindowsProfileGrantOptions _installProfileGrantOptions(
  WindowsInstallOptions opts,
  SrtWinSpawn srtWin,
) => WindowsProfileGrantOptions(
  exclude: opts.profileExclude,
  include: opts.profileInclude,
  timeoutMs: opts.profileGrantTimeoutMs,
  onProgress: opts.onProfileGrantProgress,
  srtWin: srtWin,
);
/**
 * The account and the filters are installed and the profile read grant
 * is not: its own error, so the caller does not take the whole install
 * for failed.
 */
Never _throwInstallProfileGrantFailure(Object e) {
  final cause = e;
  // Refused beside other sandbox activity: nothing was written, and a
  // grant made before is still the current one.
  if (cause is WindowsSandboxError &&
      (cause.code == 'profile_grant_blocked_by_session' ||
          cause.code == 'profile_operation_in_progress'))
    throw WindowsSandboxError(
      cause.code,
      'The Windows sandbox is installed. ${cause.message}',
      'profile',
    );
  final timedOut =
      cause is WindowsSandboxError && cause.code == 'srt_win_timeout';
  throw WindowsSandboxError(
    'profile_grant_failed',
    'The Windows sandbox is installed, but the read grant on your user ' +
        "profile ${timedOut ? 'did not finish in time' : 'could not be applied'}" +
        ': ${errorMessage(cause)}\nNo session starts until it is complete. Run the ' +
        'install again, or grantWindowsProfileRead(), to finish it; ' +
        'forgetWindowsProfileRead() removes what was written.',
    'profile',
  );
}

/**
 * Remove the WFP filter set under `sublayerGuid` and the
 * `srt-sandbox` account, its credential file, and the setup marker
 * (one UAC prompt). Idempotent.
 *
 * @returns `{cancelled: true}` if the user dismissed UAC.
 */
({bool? cancelled}) uninstallWindowsSandbox({
  String? sublayerGuid,
  bool? keepUser,
  int? timeoutMs,
  SrtWinSpawn? srtWin,
}) => throw UnsupportedError('Windows is not supported by this port');

/**
 * Resolve any Windows filesystem-config path list — `allowRead`/
 * `allowWrite` grants and `denyRead`/`denyWrite` stamps — to
 * concrete paths via the single platform-aware
 * {@link normalizePathForSandbox} chokepoint (Linux/macOS parity:
 * point-in-time expansion at session initialize, not per-exec).
 * Glob patterns are expanded; non-glob paths are normalized and
 * returned 1:1. Directory targets are accepted — the additive
 * sandbox-user ACE carries `(OI)(CI)` so it covers the subtree.
 *
 * Missing literal paths are dropped for `mode: 'grant'` (a grant on
 * nothing is meaningless) but PASSED THROUGH for `mode: 'deny'` —
 * `srt-win acl stamp` materializes a placeholder chain (mkdirs each
 * missing intermediate + creates an empty leaf) and stamps every
 * created component, so the deny lands on the exact target path
 * and the sandbox user cannot create/write/delete it. A trailing
 * `/` or `\` on the raw input means "the target is a directory":
 * the placeholder leaf is created as an empty directory instead of
 * an empty file, so a later `mkdirSync({recursive: true})` on the
 * real path succeeds. Glob results (existing-by-construction) drop
 * on a stat miss regardless of mode: a glob is inherently "match
 * existing".
 *
 * **UNC exception:** a `\\server\share\…` **literal** passes through
 * raw in BOTH modes (no existence probe — see {@link isUncPath});
 * `srt-win` soft-drops a missing UNC deny target rather than
 * materializing a placeholder chain on an SMB share. A UNC **glob**
 * still walks the share (user-trusted).
 *
 * `[` and `]` are characters of a name here, but the walk that expands a
 * glob reads them as a character class. So a glob beneath a directory with
 * brackets in its name is also expanded beneath that directory taken as the
 * name it is (see path-entries.ts). A UNC glob is not: finding the directory
 * would probe the share.
 *
 * An entry marked `{ path, literal: true }` is a literal whatever it holds.
 * One that holds `*` or `?` is skipped: no Win32 name has them, and
 * `srt-win` refuses the characters outright.
 */
List<String> expandWindowsFsPaths(
  List<FilesystemPathEntry> patterns, {

  /// 'grant' or 'deny'.
  String? mode,
}) {
  final out = <String>{};
  for (final entry in patterns) {
    final marked = entry is! FilesystemPathSpelling;
    final raw = marked ? markedLiteralPath(entry) : entry.path;
    final norm = normalizePathForSandbox(raw, literal: marked);
    if (marked && containsGlobCharsWin(norm)) {
      logForDebugging(
        '[Sandbox Windows] Skipping a literal path that no file can have: $norm',
        level: 'warn',
      );
      continue;
    }
    final isGlob = !marked && containsGlobCharsWin(norm);
    // UNC literal: pass raw (no stat) — see {@link isUncPath}. A
    // UNC glob falls through to expandGlobPattern below.
    if (isUncPath(norm) && !isGlob) {
      out.add(norm);
      continue;
    }
    final candidates = isGlob
        ? [
            ...expandGlobPattern(norm, caseInsensitive: true),
            ...literalReadings(
              raw,
              mode == 'deny' ? 'deny' : 'allow',
              isPattern: containsGlobCharsWin,
            ).expand(
              (reading) => reading.glob
                  ? expandGlobPattern(
                      reading.path,
                      caseInsensitive: true,
                      anchor: reading.anchor,
                    )
                  : <String>[],
            ),
          ]
        : [norm];
    for (final c in candidates) {
      // statSync({throwIfNoEntry: false}): only a missing entry is undefined.
      fs.Stats? st;
      try {
        st = fs.statSync(c);
      } on NodeError catch (err) {
        if (err.code != 'ENOENT') rethrow;
      }
      if (st == null) {
        // normalizePathForSandbox (path.resolve) strips the
        // trailing separator (the dir-leaf signal — see doc);
        // re-apply it from the raw input.
        if (mode == 'deny' && !isGlob) {
          out.add(
            RegExp(r'[\\/]$').hasMatch(raw) && !RegExp(r'[\\/]$').hasMatch(c)
                ? c + '\\'
                : c,
          );
        }
        continue;
      }
      out.add(c);
    }
  }
  return [...out];
}

/**
 * `p` for comparison with another path, as the object `srt-win` opens for it:
 * links, junctions, 8.3 names and the case on disk are resolved by the same
 * final-path lookup the helper makes. On top of that, lower case, `/`
 * separators and none at the end. A path that cannot be opened is compared as
 * spelled, and so is a UNC path, which is never probed (see
 * {@link isUncPath}).
 */
String _windowsPathKey(String p) {
  var resolved = p;
  if (!isUncPath(p)) {
    try {
      // The final-path lookup itself, which also resolves 8.3 names and the
      // case on disk.
      // eslint-disable-next-line no-restricted-properties
      resolved = fs.realpathSync(p);
    } catch (_) {
      // Not there, so nothing lies beneath it either.
    }
  }
  return normalizeCaseForComparison(
    path.windows
        .normalize(stripExtendedPathPrefix(resolved))
        .replaceAll(r'\', '/')
        .replaceAll(RegExp(r'/+$'), ''),
  );
}

/** The one of `dirs` that a path is, or lies beneath. */
String? Function(String) coveringWindowsPath(List<String> dirs) {
  final keys = dirs.map(_windowsPathKey).toList();
  return (p) {
    if (keys.length == 0) return null;
    final key = _windowsPathKey(p);
    final covering = keys.indexWhere((dir) => isAtOrUnder(key, dir));
    return covering < 0 ? null : dirs[covering];
  };
}

/** What `srt-win` is handed: see {@link rankWindowsFsAccess}. */
class WindowsFsAccessSet {
  final List<String> grantRead;
  final List<String> grantWrite;
  final List<String> denyRead;
  final List<String> denyWrite;

  const WindowsFsAccessSet({
    required this.grantRead,
    required this.grantWrite,
    required this.denyRead,
    required this.denyWrite,
  });
}

/**
 * Ranks the lists against each other, as on the other platforms, and returns
 * the grants and stamps that say so. Takes concrete paths
 * ({@link expandWindowsFsPaths}).
 *
 * The ACEs set on an object come before the ones it inherits, so beneath a
 * DENY on a directory an ALLOW set further down is the one that counts. That
 * is the rank of `allowRead` over `denyRead`. The other two ranks are the
 * opposite one, so `srt-win` is handed no such ALLOW for them:
 *
 * - `denyWrite` over `allowWrite`: a write grant at or beneath a write deny
 *   is a read grant.
 * - `credentialDeny` (`credentials.files`) over `allowRead` and `allowWrite`:
 *   a grant at or beneath a credential deny is left out. The caller adds the
 *   grants for the library's own files to the result, so they are the only
 *   exceptions.
 *
 * `held` are grants that are on disk already: the session's, when one command
 * brings denies of its own. They cannot be taken back for one command, so
 * each gets the deny at its own path, where `srt-win` puts DENY first.
 */
WindowsFsAccessSet rankWindowsFsAccess({
  required List<String> allowRead,
  required List<String> allowWrite,
  required List<String> denyRead,
  required List<String> denyWrite,
  required List<String> credentialDeny,
  ({List<String> grantRead, List<String> grantWrite})? held,
}) {
  final credentialDenyOver = coveringWindowsPath(credentialDeny);
  final writeDenyOver = coveringWindowsPath(denyWrite);
  final grantRead = <String>{};
  final grantWrite = <String>{};
  void rank(String list, String p) {
    final credentialDeny = credentialDenyOver(p);
    final writeDeny = list == 'allowWrite' ? writeDenyOver(p) : null;
    if (credentialDeny == null && writeDeny == null) {
      final grants = list == 'allowRead' ? grantRead : grantWrite;
      grants.add(p);
      return;
    }
    if (credentialDeny == null) grantRead.add(p);
    logForDebugging(
      '[Sandbox Windows] $list $p is at or beneath ' +
          (credentialDeny != null
              ? 'the credential file entry $credentialDeny: not granted'
              : 'denyWrite $writeDeny: granted read only'),
      level: 'warn',
    );
  }

  for (final p in allowRead) rank('allowRead', p);
  for (final p in allowWrite) rank('allowWrite', p);
  final heldRead = held?.grantRead ?? <String>[];
  final heldWrite = held?.grantWrite ?? <String>[];
  return WindowsFsAccessSet(
    grantRead: [...grantRead],
    grantWrite: [...grantWrite],
    denyRead: [
      ...{
        ...denyRead,
        ...credentialDeny,
        ...[
          ...heldRead,
          ...heldWrite,
        ].where((p) => credentialDenyOver(p) != null),
      },
    ],
    denyWrite: [
      ...{...denyWrite, ...heldWrite.where((p) => writeDenyOver(p) != null)},
    ],
  );
}

/**
 * {@link WindowsSandboxError} narrowed to `mapped_drive_cwd`,
 * carrying the `DRIVE_REMOTE` root that made the launch fail
 * (`Z:\` for a mapped letter, `\\server\share\` for a raw UNC cwd).
 */
class MappedDriveCwdError extends WindowsSandboxError {
  @override
  final WindowsSandboxErrorCode code = 'mapped_drive_cwd';
  final String? drive;

  MappedDriveCwdError(String message, {this.drive, String subcommand = 'exec'})
    : super('mapped_drive_cwd', message, subcommand);
}

/** {@link WindowsSandboxError} narrowed to `seclogon_disabled`. */
class SeclogonDisabledError extends WindowsSandboxError {
  @override
  final WindowsSandboxErrorCode code = 'seclogon_disabled';

  /// 'disabled' or 'missing'.
  final String state;
  SeclogonDisabledError(
    String message, {
    required this.state,
    String subcommand = 'exec',
  }) : super('seclogon_disabled', message, subcommand);
}

/**
 * Parse a structured `srt-win exec` error from its stderr. `exec`
 * emits typed launch failures as a single JSON line
 * `{"code":…,"message":…}` alongside a distinct exit code —
 * `mapped_drive_cwd` is exit **16**. Embedders that spawn the
 * `{argv, env}` from {@link wrapCommandWithSandboxWindows} call
 * this on non-zero exit to surface an actionable
 * {@link WindowsSandboxError} instead of a bare status.
 *
 * Returns `undefined` when no typed-error line is present (the
 * common case: exit status is the child's own). Gate on the
 * `srt-win` exit code before calling — the sandboxed child's own
 * stderr is pumped through unchanged, so a child that happened to
 * print a matching JSON line would parse here too.
 */
WindowsSandboxError? parseWindowsSandboxError(String stderr) =>
    _parseSrtWinLaunchError(stderr, 'exec');

/** {@link parseWindowsSandboxError} for any runner-launching subcommand. */
WindowsSandboxError? _parseSrtWinLaunchError(String stderr, String subcommand) {
  for (final line in stderr.split(RegExp(r'\r?\n'))) {
    final t = line.trim();
    if (!t.startsWith('{') || !t.contains('"code"')) continue;
    try {
      final j = jsonDecode(t) as Map<String, dynamic>;
      // Exit 25: the command needed the lock a profile grant or forget
      // is holding.
      if (j['code'] == 'profile_operation_in_progress')
        return WindowsSandboxError(
          'profile_operation_in_progress',
          j['message'] as String? ?? 'a profile grant or forget is in progress',
          'exec',
        );
      // Exit 26: the process named with `heldBy` ended while the
      // command ran, and the command was terminated with it.
      if (j['code'] == 'session_ended')
        return WindowsSandboxError(
          'session_ended',
          j['message'] as String? ??
              'the session that started this command ended; the command was terminated',
          'exec',
        );
      if (j['code'] == 'mapped_drive_cwd') {
        // The canonical class carries `code`/`subcommand`; `drive`
        // is this one code's extra payload, attached as a plain
        // property rather than forking the class.
        return MappedDriveCwdError(
          j['message'] as String? ?? 'mapped/network-drive working directory',
          drive: j['drive'] as String?,
          subcommand: subcommand,
        );
      }
      // Exit 19: the installed loopback mode is not the one the
      // command was wrapped for; nothing was launched.
      if (j['code'] == 'wfp_loopback_mismatch')
        return WindowsSandboxError(
          'wfp_loopback_mismatch',
          j['message'] as String? ??
              "the installed loopback mode is not this session's",
          'exec',
        );
      if (j['code'] == 'seclogon_disabled') {
        final state = j['state'] == 'missing' ? 'missing' : 'disabled';
        return SeclogonDisabledError(
          j['message'] as String? ?? _seclogonDisabledMessage(state),
          state: state,
          subcommand: subcommand,
        );
      }
    } catch (_) {
      // not our line
    }
  }
  return null;
}

class WindowsAclStampOptions {
  /** Paths the sandboxed child must not read. */
  final List<String> denyRead;
  /** Paths the sandboxed child must not write (read stays allowed). */
  final List<String> denyWrite;
  /** SID of the dedicated sandbox user — {@link WindowsSandboxUserStatus.sid}. */
  final String sandboxUserSid;
  /** Long-lived host PID the holds are tied to. Default: this process. */
  final int? holderPid;
  /** Resolved `srt-win` spawn descriptor — from {@link resolveSrtWin}. */
  final SrtWinSpawn? srtWin;

  const WindowsAclStampOptions({
    required this.denyRead,
    required this.denyWrite,
    required this.sandboxUserSid,
    this.holderPid,
    this.srtWin,
  });
}

/**
 * Apply the file-deny ACE set for one host session: an additive
 * `(D;OICI;mask;;;<sb-SID>)` on the target plus a
 * `(D;OICI;FILE_DELETE_CHILD;;;<sb-SID>)` on the parent — no
 * PROTECTED rewrite, no SD snapshot. Idempotent and refcounted via
 * srt-win's `working_aces` table.
 *
 * Inputs are passed verbatim to `srt-win` (which canonicalizes and
 * rejects globs). Callers that accept globs should pre-expand via
 * {@link expandWindowsFsPaths}.
 *
 * @throws on exit ≠ 0 — including exit 2 (one or more inputs
 *   skipped). srt-win stamps the resolvable inputs before exiting
 *   2, so on throw the caller should call {@link restoreWindowsAcl}
 *   to release whatever WAS stamped.
 */
void stampWindowsAcl(WindowsAclStampOptions opts) =>
    throw UnsupportedError('Windows is not supported by this port');

/**
 * Per-path outcome from `srt-win acl restore --json` /
 * `revoke --json`. The status set is intentionally loose: the
 * pre-/post- same-user-removal `srt-win` builds emit different
 * vocabularies for `restore` (`restored`/`leftChanged`/… vs
 * `revoked`/`stillHeld`/…). Callers (`reset()`) only log these,
 * so the union is whatever the binary on PATH says.
 */
class WindowsAclAceOutcome {
  final String path;
  final String status;

  const WindowsAclAceOutcome({required this.path, required this.status});
}

/**
 * Release this holder's deny ACEs and remove the sandbox-user ACE
 * on any path whose refcount falls to zero. Best-effort (does not
 * throw on per-path anomalies); returns per-path outcomes for the
 * caller to surface. Returns `undefined` only when `srt-win`
 * itself failed (no JSON to parse).
 */
List<WindowsAclAceOutcome>? restoreWindowsAcl({
  required String sandboxUserSid,
  int? holderPid,
  SrtWinSpawn? srtWin,
}) => throw UnsupportedError('Windows is not supported by this port');

class WindowsAclGrantOptions {
  /** Paths to grant `MODIFY_NO_FDC` on (the working tree, `allowWrite`). */
  final List<String> write;
  /** Paths to grant `FILE_GENERIC_READ|EXECUTE` on (`allowRead`). */
  final List<String> read;
  /** SID of the dedicated sandbox user — {@link WindowsSandboxUserStatus.sid}. */
  final String sandboxUserSid;
  /** Long-lived host PID the holds are tied to. Default: this process. */
  final int? holderPid;
  /** Resolved `srt-win` spawn descriptor — from {@link resolveSrtWin}. */
  final List<String>? allowProfileExclusions;
  final SrtWinSpawn? srtWin;

  const WindowsAclGrantOptions({
    required this.write,
    required this.read,
    required this.sandboxUserSid,
    this.holderPid,
    this.allowProfileExclusions,
    this.srtWin,
  });
}

/**
 * Apply per-session additive `(OI)(CI)` ALLOW ACEs for the sandbox
 * user on each path. The sandbox user has no inherent rights on
 * real-user-owned files; this is what makes the working tree (and
 * explicit `allowRead`/`allowWrite` paths) reachable from the
 * child. Idempotent and refcounted via srt-win's `working_aces`
 * table.
 *
 * @throws on exit ≠ 0. On throw the caller should call
 *   {@link revokeWindowsAcl} to release whatever WAS granted.
 */
void grantWindowsAcl(WindowsAclGrantOptions opts) =>
    throw UnsupportedError('Windows is not supported by this port');

/**
 * Release this holder's grants and remove the sandbox-user ACE on
 * any path whose refcount falls to zero. Best-effort (does not
 * throw); logs anomalies.
 */
List<WindowsAclAceOutcome>? revokeWindowsAcl({
  required String sandboxUserSid,
  int? holderPid,
  SrtWinSpawn? srtWin,
}) => throw UnsupportedError('Windows is not supported by this port');

/**
 * Session start under the write-restricted token: one `srt-win acl
 * grant --persistent`. Grants on the `write` roots are KEPT at session
 * end; `srt-win acl forget` removes them.
 */
Future<void> grantWindowsAclPersistent(
  WindowsAclGrantOptions opts, {
  required List<String> denyRead,
  required List<String> denyWrite,
}) async => throw UnsupportedError('Windows is not supported by this port');

class WindowsAclRevokeResult {
  /**
   * True only when `srt-win acl revoke` exited 0, its output parsed,
   * and every per-path outcome shows the grant released.
   */
  final bool complete;
  final List<WindowsAclAceOutcome>? outcomes;
  /**
   * Paths whose outcome does not show the grant released — the grant
   * may still be on disk there. Empty when `complete`, and also when
   * the revoke reported no outcomes at all.
   */
  final List<String> pending;
  /** srt-win's stderr, or the error that stopped the revoke. */
  final String? detail;

  const WindowsAclRevokeResult({
    required this.complete,
    this.outcomes,
    required this.pending,
    this.detail,
  });
}

/**
 * {@link revokeWindowsAcl} that also reports whether the revoke
 * completed; gate {@link restoreWindowsAcl} on `complete`.
 */
WindowsAclRevokeResult revokeWindowsAclChecked({
  required String sandboxUserSid,
  int? holderPid,
  SrtWinSpawn? srtWin,
}) => throw UnsupportedError('Windows is not supported by this port');

/**
 * What `srt-win profile status` reports. Only `current` is a grant a
 * session may rely on: complete, made with this `srt-win`'s exclusion
 * list, for the profile directory that is there now.
 */
/// Allowed values: none, current, outdated, incomplete, unknown.
typedef WindowsProfileGrantState = String;

/** One path the grant wrote on, as `srt-win` recorded it. */
class WindowsProfileGrantPath {
  /** Canonical (`\\?\`-prefixed) path. */
  final String path;
  /**
   * `container`: listable, children granted one by one. `granted`: a
   * directory readable with everything below it. `file`: a single
   * readable file. `denied`: an exclusion.
   */
  final String kind;

  const WindowsProfileGrantPath({required this.path, required this.kind});
}

class WindowsProfileGrantStatus {
  final WindowsProfileGrantState state;
  /** Why the state is not `current`, when `srt-win` says. */
  final String? reason;
  /** The profile directory the grant was made for. */
  final String? profile;
  /** The list version of this `srt-win`, and the one the grant was made with. */
  final int? listVersion;
  final int? recordedListVersion;
  /** Which operation last wrote the record, when `srt-win` says. */
  final String? lastOperation;
  /** The record was made for the profile directory that is there now. */
  final bool sameProfile;
  /**
   * What `srt-win` says it does, by name (see
   * {@link WINDOWS_SRT_WIN_CAPABILITIES}); empty from one that does
   * not say.
   */
  final List<String> capabilities;
  /**
   * What the last run of the grant left as it found it, as {@link
   * WindowsProfileGrantResult} reports it: objects in the profile
   * this user may not change.
   */
  final List<WindowsProfileGrantItem> notGranted;
  final List<WindowsProfileGrantItem> selfClosed;
  final List<WindowsProfileGrantItem> unverifiable;
  final List<WindowsProfileGrantItem> unprotected;
  final List<WindowsProfileGrantItem> staleAllow;
  /**
   * Configuration files granted by name that were replaced since (a save
   * by write-and-rename): unreadable to sandboxed commands, and their
   * variables are not in `env`, until the grant runs again.
   */
  final List<String> replacedFiles;
  /** Exclusions added to the built-in list when the grant was made, relative to the profile. */
  final List<String> extraExclusions;
  /**
   * Inclusions added to the built-in list when the grant was made,
   * relative to the profile: directories (or files) readable besides
   * the per-user tool directories the library lists.
   */
  final List<String> extraInclusions;
  /**
   * Every PROTECTED path the grant keeps unreadable, absolute, existing or
   * not; `*` stands for one name, a trailing `*` for a prefix. A session may
   * not grant a path that is one, lies inside one, or lies above one.
   */
  final List<String> exclusions;
  /**
   * The UNGRANTED-ONLY directories, in the same form (the user's
   * temporary directory): not readable through the grant, and not
   * denied.
   */
  final List<String> ungrantedOnly;
  /**
   * Every inclusion the grant was made with, absolute: the built-in
   * list of per-user tool directories and what was added, each readable
   * but for the exclusions inside it. Empty from an srt-win that does
   * not report them.
   */
  final List<String> inclusions;
  final ({int containers, int granted, int files, int denied}) counts;
  /**
   * Configuration-file variables for a sandboxed command — see
   * {@link windowsProfileReadEnv}. Empty unless `current`.
   */
  final Map<String, String> env;
  /** Every recorded path; only when asked for. */
  final List<WindowsProfileGrantPath>? paths;

  const WindowsProfileGrantStatus({
    required this.state,
    this.reason,
    this.profile,
    this.listVersion,
    this.recordedListVersion,
    this.lastOperation,
    required this.sameProfile,
    required this.capabilities,
    required this.notGranted,
    required this.selfClosed,
    required this.unverifiable,
    required this.unprotected,
    required this.staleAllow,
    required this.replacedFiles,
    required this.extraExclusions,
    required this.extraInclusions,
    required this.exclusions,
    required this.ungrantedOnly,
    required this.inclusions,
    required this.counts,
    required this.env,
    this.paths,
  });
}

/**
 * The variables {@link windowsProfileReadEnv} can return; any other name
 * `srt-win` reports is dropped. `RUSTUP_HOME` and `CARGO_HOME` name
 * directories, which stay read-only to the sandboxed command.
 */
const WINDOWS_PROFILE_READ_ENV_VARS = [
  'NPM_CONFIG_USERCONFIG',
  'GIT_CONFIG_GLOBAL',
  'PIP_CONFIG_FILE',
  'MAVEN_ARGS',
  'RUSTUP_HOME',
  'CARGO_HOME',
];

/**
 * The list versions between which every change only narrows the grant:
 * the only ones `initialize()` moves a grant across by itself. A new list
 * version that only narrows raises `to`; one that widens anything raises
 * `from` to it as well, so that widening is applied only by a run the user
 * asked for.
 */
const WINDOWS_PROFILE_NARROWING_LIST_VERSIONS = (from: 3, to: 4);

/**
 * Whether `initialize()` brings this grant up to date by itself: an
 * older list on the same profile, or a grant that was cut short, which
 * finishes what its caller started. Not a forget that was cut short,
 * another profile, or a record newer than this `srt-win`.
 */
bool windowsProfileGrantRefreshable(WindowsProfileGrantStatus status) {
  final list = status.listVersion, recorded = status.recordedListVersion;
  final (:from, :to) = WINDOWS_PROFILE_NARROWING_LIST_VERSIONS;
  if (list == null || recorded == null || !status.sameProfile) return false;
  if (recorded < from || recorded > list || list > to) return false;
  if (status.state == 'outdated') return recorded < list;
  return status.state == 'incomplete' && status.lastOperation == 'grant';
}

/**
 * The recorded profile read grant (`srt-win profile status`): whether one
 * exists and is current, and with `paths` every path it wrote on. Throws
 * `profile_operation_in_progress` while a grant or forget is running.
 * Blocks the event loop: prefer {@link getWindowsProfileReadStatusAsync}.
 */
WindowsProfileGrantStatus getWindowsProfileReadStatus({
  bool? paths,
  SrtWinSpawn? srtWin,
}) => throw UnsupportedError('Windows is not supported by this port');

/** Async twin of {@link getWindowsProfileReadStatus}: the event loop stays live. */
Future<WindowsProfileGrantStatus> getWindowsProfileReadStatusAsync({
  bool? paths,
  SrtWinSpawn? srtWin,
}) async => throw UnsupportedError('Windows is not supported by this port');

class WindowsProfileGrantOptions {
  /**
   * Abort the run: the child is killed and the promise rejects with
   * `srt_win_cancelled`. The grant stays recorded as incomplete.
   */
  final AbortSignal? signal;
  /**
   * Paths inside the profile to keep unreadable in addition to the
   * built-in list (absolute, or relative to the profile): for example
   * the embedding program's own configuration directory.
   */
  final List<String>? exclude;
  /**
   * Make `exclude` the whole added list, dropping the entries earlier
   * runs recorded. Without it a run only ever adds.
   */
  final bool? replaceExclusions;
  /**
   * Directories (or files) inside the profile to make readable in
   * addition to the built-in list of per-user tool directories
   * (absolute, or relative to the profile): a toolchain kept somewhere
   * the list does not name, say. A protected path, anything inside
   * one, and the temporary directory or anything in it are refused
   * (`profile_grant_failed`); a directory above a protected path is
   * granted child by child. An inclusion recorded by an earlier run is
   * checked again on every run, since the built-in exclusions may have
   * grown: one that conflicts fails the run the same way until a run
   * with `replaceInclusions: true` drops it.
   */
  final List<String>? include;
  /**
   * Make `include` the whole added list, dropping the entries earlier
   * runs recorded. Without it a run only ever adds.
   */
  final bool? replaceInclusions;
  /**
   * Kill `srt-win` after this long. Default 30 minutes: the first run
   * touches every file under the granted directories.
   */
  final int? timeoutMs;
  /** Called with each progress line `srt-win` writes (a count of top-level items done). */
  final void Function(String line)? onProgress;
  /** Resolved `srt-win` spawn descriptor — from {@link resolveSrtWin}. */
  final SrtWinSpawn? srtWin;

  const WindowsProfileGrantOptions({
    this.signal,
    this.exclude,
    this.replaceExclusions,
    this.include,
    this.replaceInclusions,
    this.timeoutMs,
    this.onProgress,
    this.srtWin,
  });
}

/** One path `srt-win profile grant` skipped or could not write. */
class WindowsProfileGrantItem {
  final String path;
  final String reason;
  /**
   * On an `unverifiable` item: whether YOU can open the object for reading
   * (`'unknown'`: not tried). One you can read without seeing its access
   * list is to be taken as readable to sandboxed commands as well.
   */
  final Object? callerReads;
  /**
   * On an `unverifiable` item: why it could not be examined —
   * `acl_unreadable`, `account_unknown` (the sandbox account's
   * identity is not known), `not_local`, `probe_failed`.
   */
  final String? cause;
  /**
   * Set where an entry THIS PRODUCT wrote makes the path readable and could
   * not be removed: `true` if the path is on the exclusion list now (among
   * `unprotected`), `false` if it merely left the grant (`staleAllow`).
   */
  final bool? protectedExclusion;
  /**
   * With `protectedExclusion`: `explicit` — the entry is on the
   * object, which you may not change; `inherited` — a copy handed down
   * from a directory above, which could not be taken off the object.
   */
  final String? entry;

  const WindowsProfileGrantItem({
    required this.path,
    required this.reason,
    this.callerReads,
    this.cause,
    this.protectedExclusion,
    this.entry,
  });
}

class WindowsProfileGrantResult {
  final String profile;
  final int containers;
  final int granted;
  final int files;
  final int denied;
  /** Excluded directories that did not exist and were created empty. */
  final int placeholders;
  /** Empty directories an earlier run created that left the grant, removed. */
  final int placeholdersRemoved;
  /** DACLs written by this run; 0 on a refresh that found nothing new. */
  final int writes;
  final int unchanged;
  /** Recorded paths that left the grant and had their entry removed. */
  final int removed;
  /** Junctions, symbolic links, cloud placeholders: nothing is written on or through them. */
  final List<WindowsProfileGrantItem> skipped;
  /**
   * Paths that were to be granted and whose access list this user may not
   * change. They stay unreadable to sandboxed commands.
   */
  final List<WindowsProfileGrantItem> notGranted;
  /**
   * Excluded paths whose deny could not be written, and whose own
   * access list gives the sandbox account no read.
   */
  final List<WindowsProfileGrantItem> selfClosed;
  /**
   * Excluded paths whose deny could not be written and whose access
   * list this user may not even read (and so cannot use either).
   */
  final List<WindowsProfileGrantItem> unverifiable;
  /**
   * Excluded paths whose deny could not be written and whose own
   * access list lets the sandbox account read them — as it did before
   * the grant, which neither opened them nor can close them.
   */
  final List<WindowsProfileGrantItem> unprotected;
  /**
   * Paths that have left the grant and may still carry the allow of an
   * earlier run, which could not be removed: readable through the
   * grant's own entry until it is. Includes those on a volume that
   * cannot be reached now. They stay recorded and are retried.
   */
  final List<WindowsProfileGrantItem> staleAllow;
  /**
   * Write roots kept from earlier sessions whose grant this run removed
   * because it reached an exclusion (the root is one, lies inside one,
   * or lies above one). A session that asks for such a root is refused.
   */
  final List<WindowsProfileGrantItem> forgottenRoots;
  final int elapsedMs;

  const WindowsProfileGrantResult({
    required this.profile,
    required this.containers,
    required this.granted,
    required this.files,
    required this.denied,
    required this.placeholders,
    required this.placeholdersRemoved,
    required this.writes,
    required this.unchanged,
    required this.removed,
    required this.skipped,
    required this.notGranted,
    required this.selfClosed,
    required this.unverifiable,
    required this.unprotected,
    required this.staleAllow,
    required this.forgottenRoots,
    required this.elapsedMs,
  });
}

/**
 * Write or refresh the profile read grant (`srt-win profile grant`), as
 * the user of this process, unelevated. Runs only while no sandbox session
 * or command is running (`profile_grant_blocked_by_session`).
 */
Future<WindowsProfileGrantResult> grantWindowsProfileRead([
  WindowsProfileGrantOptions opts = const WindowsProfileGrantOptions(),
]) async => throw UnsupportedError('Windows is not supported by this port');

/**
 * Try again to revoke what the last run of the grant could not, on the
 * paths it noted alone (`srt-win profile retry-stale`). Bounded, as a
 * session is starting: only if a retry is due, on local paths, and
 * keeping no starting session out. Returns how many cleared; what is
 * left stays recorded and reported by the status.
 */
Future<({int cleared})> retryWindowsProfileStale({
  required SrtWinSpawn srtWin,
}) async => throw UnsupportedError('Windows is not supported by this port');

/**
 * Remove the profile read grant (`srt-win profile forget`). Synchronous:
 * blocks for as long as the removal takes; with an event loop use
 * {@link forgetWindowsProfileReadAsync}. Throws `profile_forget_failed`.
 */
WindowsProfileForgetResult forgetWindowsProfileRead({
  int? timeoutMs,
  SrtWinSpawn? srtWin,
}) => throw UnsupportedError('Windows is not supported by this port');

/** {@link forgetWindowsProfileRead} without blocking the event loop. */
Future<WindowsProfileForgetResult> forgetWindowsProfileReadAsync({
  int? timeoutMs,
  SrtWinSpawn? srtWin,
}) async => throw UnsupportedError('Windows is not supported by this port');

/** What `srt-win profile forget` could not establish. */
class WindowsProfileForgetResult {
  /**
   * Paths on a volume that cannot be reached, with nothing recorded that
   * could find them when it returns. No longer recorded, and NOT known
   * to be clear: if the volume comes back they may still hold the entry.
   */
  final List<WindowsProfileGrantItem> deferred;

  const WindowsProfileForgetResult({required this.deferred});
}

/** How a path a session wants to grant stands to a profile exclusion. */
class WindowsProfileExclusionConflict {
  /** The path as the session configuration resolved it. */
  final String path;
  /** The exclusion, as the grant recorded it. */
  final String exclusion;
  /** Which list the exclusion is on. */
  final String kind;
  /** What the session would have granted on the path. */
  final String access;
  /**
   * `equal`: the path is the excluded one. `inside`: it lies beneath
   * an excluded directory (protected only). `above`: an excluded path
   * lies beneath it.
   */
  final String relation;
  /**
   * Set on an `above` conflict with a wildcard exclusion when the path
   * could not be examined for what the exclusion covers beneath it —
   * access denied, an I/O error, a path on a share — with the reason.
   */
  final String? unexamined;

  const WindowsProfileExclusionConflict({
    required this.path,
    required this.exclusion,
    required this.kind,
    required this.access,
    required this.relation,
    this.unexamined,
  });
}

/**
 * The paths among `paths` a session must not grant while the profile read
 * grant exists, with the exclusion each collides with. Paths are resolved
 * first; fails closed on a path that exists and cannot be listed.
 */
List<WindowsProfileExclusionConflict> windowsProfileExclusionConflicts(
  List<String> paths,
  ({List<String> exclusions, List<String> ungrantedOnly}) grant, {
  List<String>? override,
  bool? write,
}) => throw UnsupportedError('Windows is not supported by this port');

/**
 * Variables an embedder may set so a tool reads the real user's files in
 * place. Empty unless the grant is current; never one `env` already holds.
 * The library sets none of them itself.
 */
Map<String, String> windowsProfileReadEnv(
  WindowsProfileGrantStatus status, [
  Map<String, String?> env = const {},
]) {
  if (status.state != 'current') return {};
  final supplied = env.entries
      .where((e) => e.value != null)
      .map((e) => e.key.toUpperCase())
      .toSet();
  final out = <String, String>{};
  for (final name in WINDOWS_PROFILE_READ_ENV_VARS) {
    final v = status.env[name];
    if (v != null && !supplied.contains(name)) out[name] = v;
  }
  return out;
}

// ────────────────────────────────────────────────────────────────────
// Wrap
// ────────────────────────────────────────────────────────────────────

/**
 * `no_proxy` for a sandboxed child with `network.allowLocalBinding`:
 * the loopback hosts, so proxy-aware clients connect to local servers
 * directly. Otherwise `no_proxy` is not set at all.
 */
const WINDOWS_LOOPBACK_NO_PROXY = 'localhost,127.0.0.1,::1';

/**
 * Build the spawn descriptor for running `command` inside the Windows
 * sandbox: an `argv` array plus the `env` to spawn it with.
 *
 * Caller MUST spawn the result with `{shell: false}` — that is the
 * security boundary that keeps untrusted bytes off the host's shell
 * (the inner `cmd.exe /c` runs INSIDE the sandbox; see
 * `vendor/srt-win-src/src/launch.rs` `build_cmdline` for the passthrough
 * rationale) — AND with the returned `env`.
 *
 * Proxy configuration is single-sourced by {@link generateProxyEnvVars}
 * (the same canonical builder used on macOS/Linux). `srt-win exec`
 * takes no `--http-proxy` / `--socks-proxy` flags and synthesizes no
 * proxy env. The two-hop runner starts with the SANDBOX user's
 * profile env (`USERPROFILE`/`TEMP` isolated) and overlays exactly
 * what we pass as `--env` — built here from the broker's `PATH` plus
 * the generated proxy set.
 */
({List<String> argv, Map<String, String?> env}) wrapCommandWithSandboxWindows(
  WindowsSandboxParams p,
) {
  final (:exe, :prependArgs) = (
    exe: (p.srtWin ?? resolveSrtWin()).exe,
    prependArgs: (p.srtWin ?? resolveSrtWin()).prependArgs,
  );
  // Generated proxy + CA-trust env. Single-sourced here so the
  // same object feeds (a) the spawn env merge below and (b) the
  // explicit `--env` overlay for the runner.
  //
  // The CA trust-bundle path is emitted with forward slashes:
  // msys2's POSIX-path conversion leaves `C:/…` alone and every
  // tool we set the var for (curl, git, node, python, …) accepts
  // forward slashes on Windows; backslashes would be mangled if
  // the value passes through a bash command line. Schannel-level
  // trust comes from the registry write `srt-win user trust-ca`
  // did at install time; the env-var layer here covers the
  // OpenSSL-backed tools.
  final generated = envListToObject(
    generateProxyEnvVars(
      p.httpProxyPort,
      p.socksProxyPort,
      p.caCertPath?.replaceAll('\\', '/'),
      p.proxyAuthToken,
      null,
      encodeSandboxedCommand(attributionKeyFor(p.command, p.commandId)),
    ),
  );
  // TMPDIR is a POSIX path meant for the macOS/Linux FS sandbox — it
  // serves no purpose on Windows and breaks msys2 tools (mktemp etc.).
  generated.remove('TMPDIR');
  // NO_PROXY=localhost,127.0.0.1,… is correct on POSIX where seatbelt/
  // bwrap allow direct loopback: a NO_PROXY match makes the client
  // connect directly and it works. On Windows the WFP fence blocks
  // ALL direct connects from the sandbox user — including loopback
  // outside the proxy-port PERMIT range — so NO_PROXY makes clients
  // bypass the proxy and hit the fence; every localhost/127.0.0.1
  // request fails. Consumers currently work around with
  // `curl --noproxy ""`. Drop NO_PROXY here so localhost goes through
  // the proxy (which connects on the child's behalf, from the broker's
  // SID, and is not fenced).
  generated.remove('NO_PROXY');
  generated.remove('no_proxy');
  // With loopback open the fence permits direct loopback connects, so the
  // loopback hosts (only: private networks are still fenced) skip the proxy.
  if (p.allowLoopback == true &&
      ((p.httpProxyPort ?? 0) != 0 || (p.socksProxyPort ?? 0) != 0))
    generated['no_proxy'] = WINDOWS_LOOPBACK_NO_PROXY;

  // GIT_CONFIG_* set — safe.directory (dubious-ownership) + the
  // schannel CA knobs. Composed against setEnvVars so a caller
  // that already emits GIT_CONFIG_COUNT keeps its entries.
  final gitCfg = buildGitConfigEnv(
    safeDirs: [
      p.cwd ?? process.cwd(),
      ...(p.allowWrite ?? []),
      ...(p.gitSafeDirectories ?? []),
    ],
    schannelCa: p.caCertPath != null,
    baseEnv: p.setEnvVars,
  );

  final argv = <String>[exe, ...prependArgs, 'exec'];
  if (p.quiet != false) argv.add('--quiet');
  if (p.heldBy != null) argv.addAll(['--held-by', '${p.heldBy}']);
  argv.add('--write-restricted-token');
  for (final r in p.writeRoots ?? <String>[]) argv.addAll(['--write-root', r]);
  if (p.allowLoopback == true) argv.add('--allow-loopback');
  for (final d in p.denyRead ?? <String>[]) argv.addAll(['--deny-read', d]);
  for (final a in p.denyReadExcept ?? <String>[])
    argv.addAll(['--deny-read-except', a]);
  for (final d in p.denyWrite ?? <String>[]) argv.addAll(['--deny-write', d]);
  // The two-hop runner starts with the SANDBOX user's profile env
  // (USERPROFILE/TEMP isolated) and overlays exactly what we pass as
  // `--env`. The broker does NOT enumerate its own env — the overlay
  // is built here from the broker's PATH, the mode:'mask' sentinel
  // set, the generated proxy set, and the GIT_CONFIG_* set.
  // Sentinels precede `generated` so a caller masking e.g.
  // `HTTPS_PROXY` cannot break the sandbox's own proxy plumbing —
  // same precedence as the macOS/Linux `env -u … VAR=…
  // sandbox-exec` order. `gitCfg` is last so its GIT_CONFIG_COUNT
  // (which composes against setEnvVars) wins.
  // Merged ignoring case, as Windows reads names: a caller's
  // `Https_Proxy` is the same variable as ours. Node's built-in clients
  // read the proxy variables only with NODE_USE_ENV_PROXY set; it sits in
  // the first layer, so a caller's value, in any case, wins.
  final overlay = mergeWindowsEnv([
    {
      'PATH': process.env['PATH'],
      'PATHEXT': process.env['PATHEXT'],
      if ((p.httpProxyPort ?? 0) != 0) 'NODE_USE_ENV_PROXY': '1',
    },
    p.setEnvVars ?? {},
    generated,
    gitCfg,
  ]);
  for (final MapEntry(key: k, value: v) in overlay.entries) {
    if (v != null) argv.addAll(['--env', '$k=$v']);
  }
  argv.add('--');

  // Inner shell: `{exe, args}` from parseWindowsBinShell — the SOLE
  // normalizer. `p.command` lands as a single argv element; srt-win's
  // `build_cmdline` MSVCRT-quotes it (or wraps in one outer "…" for
  // cmd /s) so the inner shell receives it intact. See launch.rs.
  final sh = p.binShell ?? parseWindowsBinShell(null);
  argv.addAll([sh.exe, ...sh.args, p.command]);

  // CreateProcessW's lpCommandLine is capped at 32 767 WCHARs.
  // Node's `shell:false` spawn builds it by MSVCRT-quoting each
  // argv element and joining with spaces; ~30 000 leaves headroom
  // for the quote overhead the estimate doesn't model.
  final cmdlineEstimate = argv.fold<int>(0, (n, a) => n + a.length + 3);
  if (cmdlineEstimate > 30000) {
    throw WindowsSandboxError(
      'argv_too_long',
      'Windows sandbox argv is ~$cmdlineEstimate chars ' +
          '(CreateProcessW limit is 32 767). Besides the command itself it ' +
          'carries ${p.denyRead?.length ?? 0} per-command read denies, ' +
          '${p.denyReadExcept?.length ?? 0} session grants beneath them, ' +
          '${p.denyWrite?.length ?? 0} write denies and ' +
          '${p.writeRoots?.length ?? 0} write roots; the command was not ' +
          'run with fewer.',
    );
  }

  // The two-hop runner starts with a FRESH `srt-sandbox` profile
  // env (`lpEnvironment = NULL` + `LOGON_WITH_PROFILE`), so the
  // broker process's environment never reaches the child. The
  // returned `env` is the spawn env for the broker (srt-win)
  // process only; the child sees the `--env` overlay built into
  // `argv` above (PATH/PATHEXT + mode:'mask' sentinels + proxy).
  final env = <String, String?>{...process.env, ...generated};
  return (argv: argv, env: env);
}

/**
 * The one spelling each proxy variable has in a sandboxed command's
 * environment. Must match `PROXY_NAME_SPELLING` in launch.rs.
 */
const _WINDOWS_PROXY_NAME_SPELLING = [
  'http_proxy',
  'https_proxy',
  'ftp_proxy',
  'all_proxy',
  'no_proxy',
  'grpc_proxy',
  'RSYNC_PROXY',
];

/**
 * Merge environment layers ignoring case, as Windows reads names: a later
 * layer's entry replaces an earlier one, name and value; an `undefined`
 * value sets nothing. Two names that differ only by case in one block make
 * .NET's `Process.Start` throw.
 */
Map<String, String?> mergeWindowsEnv(List<Map<String, String?>> layers) {
  final byName = <String, (String, String?)>{};
  for (final layer in layers) {
    for (final MapEntry(key: name, value: value) in layer.entries) {
      if (value == null) continue;
      final folded = name.toUpperCase();
      final spelling =
          _WINDOWS_PROXY_NAME_SPELLING
              .where((n) => n.toUpperCase() == folded)
              .firstOrNull ??
          name;
      byName[folded] = (spelling, value);
    }
  }
  return {for (final (name, value) in byName.values) name: value};
}

/**
 * Parse a list of `KEY=VALUE` strings (as produced by
 * {@link generateProxyEnvVars}) into an object. Splits on the FIRST
 * `=` only, so values containing `=` survive intact. Shared with the
 * MXC backend's child-environment assembly.
 */
Map<String, String?> envListToObject(List<String> list) {
  final out = <String, String?>{};
  for (final entry in list) {
    final eq = entry.indexOf('=');
    if (eq == -1) continue;
    out[entry.substring(0, eq)] = entry.substring(eq + 1);
  }
  return out;
}

// ────────────────────────────────────────────────────────────────────
// Dependency / readiness check
// ────────────────────────────────────────────────────────────────────

/**
 * Install instructions, surfaced verbatim in error messages.
 */
String windowsInstallInstructions(String? sublayerGuid) {
  final sl = sublayerGuid != null && sublayerGuid.isNotEmpty
      ? ' --sublayer-guid $sublayerGuid'
      : '';
  return 'Windows sandbox needs a one-time install (one UAC prompt):\n' +
      '  npx sandbox-runtime windows-install\n' +
      '  — or call installWindowsSandbox(), or run ' +
      '`srt-win.exe install$sl` directly.\n' +
      'No logout is needed: the WFP filter keys on the dedicated ' +
      "`srt-sandbox` user's SID, so your network is unaffected.";
}

/// Dart: stands in for JavaScript's `PromiseSettledResult<T>`.
class _PromiseSettledResult<T> {
  final String status;
  final T? value;
  final Object? reason;

  const _PromiseSettledResult.fulfilled(T this.value)
    : status = 'fulfilled',
      reason = null;
  const _PromiseSettledResult.rejected(this.reason)
    : status = 'rejected',
      value = null;
}

_PromiseSettledResult<T> _settle<T>(T Function() fn) {
  try {
    return _PromiseSettledResult<T>.fulfilled(fn());
  } catch (e) {
    return _PromiseSettledResult<T>.rejected(e);
  }
}

/**
 * Interpret the two probe results into a {@link SandboxDependencyCheck}.
 * Shared by the sync and async `checkWindowsDependencies*` variants so
 * both produce byte-identical `errors[]` for the same underlying state.
 *
 * `getWfp` is lazy: the sync caller's thunk spawns `wfp status` on
 * demand (preserving the short-circuit — no second spawn when
 * `user status` already failed); the async caller has already run
 * both probes concurrently and its thunk returns the settled result.
 */
SandboxDependencyCheck _interpretDependencyProbes(
  String? sublayerGuid,
  _PromiseSettledResult<WindowsSandboxUserStatus> user,
  _PromiseSettledResult<WindowsWfpStatusResult> Function() getWfp,
) {
  final errors = <String>[];
  final warnings = <String>[];

  // 2. Sandbox user provisioned + credential readable.
  if (user.status == 'rejected') {
    errors.add('srt-win user status failed: ${errorMessage(user.reason)}');
    return SandboxDependencyCheck(errors: errors, warnings: warnings);
  }
  final us = user.value!;
  if (!us.provisioned || !us.credPresent) {
    errors.add(
      'Sandbox user is not provisioned (user=${us.provisioned}, ' +
          'cred=${us.credPresent}). ' +
          windowsInstallInstructions(sublayerGuid),
    );
  }

  // 3. WFP filters installed under the sublayer. BFE enumeration is
  // admin-gated; `cannot-read` is informational only — the
  // BEHAVIORAL check (`verifyWindowsWfpEgress`) runs at
  // `initialize()` and is what actually fails closed.
  final wfp = getWfp();
  if (wfp.status == 'rejected') {
    errors.add('srt-win wfp status failed: ${errorMessage(wfp.reason)}');
    return SandboxDependencyCheck(errors: errors, warnings: warnings);
  }
  final ws = wfp.value!;
  if (ws.state == 'cannot-read') {
    logForDebugging(
      '[Sandbox Windows] wfp status cannot-read (non-elevated): ${ws.hint ?? 'undefined'}',
    );
  } else if (ws.state != 'installed') {
    // 'absent'. If the user is also not-provisioned, the user-state
    // error above already gave the right instruction; don't repeat.
    if (us.provisioned && us.credPresent) {
      errors.add(
        'WFP filters not installed under sublayer ' +
            "${sublayerGuid ?? '(default)'}. " +
            windowsInstallInstructions(sublayerGuid),
      );
    }
  } else if (ws.portRange != null) {
    logForDebugging(
      '[Sandbox Windows] WFP installed: ${ws.filters} filters, ' +
          'proxy port range ${ws.portRange!.$1}-${ws.portRange!.$2}',
    );
  }

  return SandboxDependencyCheck(errors: errors, warnings: warnings);
}

/**
 * Check the Windows backend is ready to sandbox. Errors block
 * `initialize()`; warnings are informational.
 *
 * Prefer {@link checkWindowsDependenciesAsync}; this variant
 * `spawnSync`-blocks the event loop on two `srt-win.exe` spawns
 * (Windows Defender cold-scan can add seconds).
 */
SandboxDependencyCheck checkWindowsDependencies({
  String? sublayerGuid,
  (int, int)? proxyPortRange,
  String? sandboxUser,
  bool? allowLoopback,
  SrtWinSpawn? srtWin,
}) => throw UnsupportedError('Windows is not supported by this port');

/**
 * Async twin of {@link checkWindowsDependencies}. Same result for the
 * same underlying state; runs the two `srt-win` probes concurrently
 * and never blocks the event loop.
 */
Future<SandboxDependencyCheck> checkWindowsDependenciesAsync({
  String? sublayerGuid,
  (int, int)? proxyPortRange,
  String? sandboxUser,
  bool? allowLoopback,
  SrtWinSpawn? srtWin,
}) async => throw UnsupportedError('Windows is not supported by this port');
