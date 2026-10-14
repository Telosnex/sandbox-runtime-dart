// STUB: pending port of src/sandbox/linux-violation-monitor.ts @ 24eb39e.
// ignore_for_file: slash_for_doc_comments

import 'macos_sandbox_utils.dart';
import 'sandbox_config.dart';

class LinuxViolationMonitorOptions {
  const LinuxViolationMonitorOptions({
    required this.allowWritePaths,
    required this.denyWritePaths,
    this.ignoreViolations,
    required this.resolveCommandText,
  });

  /**
   * Paths bwrap mounts read-write. apply-seccomp's USER_NOTIF observer
   * reports every write-intent syscall (allowed or not, since the BPF filter
   * cannot see the mount table); a path is treated as a violation only when
   * it is *not* under any of these prefixes, or when it falls under
   * [denyWritePaths].
   */
  final List<String> allowWritePaths;
  /** Paths bwrap re-mounts read-only inside an allowWrite region. */
  final List<String> denyWritePaths;
  final IgnoreViolationsConfig? ignoreViolations;
  /** Map a decoded attribution key to the command text it represents, before
   *  ignoreViolations matching and before the event's `command` is set. Only
   *  the manager holds the registry that can do that, so it is required
   *  rather than defaulted: a caller with no registry passes
   *  `sanitizeUnregisteredCommandKey`, which treats the key as the untrusted
   *  bytes it arrived as. */
  final String Function(String decodedKey) resolveCommandText;
}

class LinuxViolationMonitor {
  const LinuxViolationMonitor({
    required this.observeSocketPath,
    required this.ready,
    required this.stop,
  });

  /** Filesystem unix-socket path the listener is bound to. Bind-mount this
   *  into each bwrap sandbox and pass it to apply-seccomp via
   *  SRT_OBSERVE_SOCK. `undefined` if listen() failed (the caller should
   *  proceed without observation). */
  final String? observeSocketPath;
  /** Resolves once the listener is bound, or on listen failure. */
  final Future<void> ready;
  final void Function() stop;
}

/**
 * Linux equivalent of [startMacOSSandboxLogMonitor]. Creates a single
 * filesystem unix-socket listener; each `apply-seccomp` instance's outer stub
 * connects to it and writes one JSON line per observed write-intent syscall.
 * The supervise loop lives inside `apply-seccomp` itself (the parent that
 * already waitpid()s the workload), so there is no separate supervisor binary.
 *
 * Unlike Seatbelt's `log stream`, the kernel reports *attempts* here, not
 * denials, so this function intersects each path against the configured
 * allow/deny set before forwarding it as a violation.
 *
 * The reported path is read out of the (untrusted) sandboxed process's memory
 * with process_vm_readv and is therefore ATTACKER-CONTROLLED and racy. bwrap's
 * mount table is the only enforcement boundary; the violation events emitted
 * here are diagnostic hints and must never gate a policy decision.
 *
 * The transport is a *filesystem* unix socket because bwrap runs with
 * `--unshare-net` (abstract sockets are net-namespace-scoped) and bwrap closes
 * inherited fds. Filesystem sockets survive across net + user + mount
 * namespaces as long as the path is bind-mounted into the sandbox.
 */
LinuxViolationMonitor startLinuxSandboxViolationMonitor(
  SandboxViolationCallback callback,
  LinuxViolationMonitorOptions opts,
) {
  throw UnimplementedError(
    'pending port of src/sandbox/linux-violation-monitor.ts',
  );
}
