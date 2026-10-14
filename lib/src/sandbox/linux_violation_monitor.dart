// Ported from sandbox-runtime src/sandbox/linux-violation-monitor.ts @ 24eb39e.
// ignore_for_file: slash_for_doc_comments

import 'dart:convert';
import 'dart:async';
import 'dart:io';
import 'dart:math' as math;

import 'package:path/path.dart' as path;

import '../node/buffer.dart' show Buffer;
import '../node/errno.dart' show NodeException;
import '../node/net.dart';
import '../utils/debug.dart';
import 'macos_sandbox_utils.dart';
import 'sandbox_config.dart';
import 'sandbox_utils.dart';
import 'sandbox_violation_store.dart';

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
  LinuxViolationMonitor({
    required String? Function() observeSocketPath,
    required this.ready,
    required this.stop,
  }) : _observeSocketPath = observeSocketPath;
  /** Filesystem unix-socket path the listener is bound to. Bind-mount this
   *  into each bwrap sandbox and pass it to apply-seccomp via
   *  SRT_OBSERVE_SOCK. `undefined` if listen() failed (the caller should
   *  proceed without observation). */
  // Upstream exposes this as a getter: listen() failure clears it later.
  String? get observeSocketPath => _observeSocketPath();
  final String? Function() _observeSocketPath;
  /** Resolves once the listener is bound, or on listen failure. */
  final Future<void> ready;
  final void Function() stop;
}

class _ObserveEvent {
  _ObserveEvent(Map<String, dynamic> json)
    : nr = json['nr'] as int?,
      syscall = json['syscall'] as String?,
      pid = json['pid'] as int?,
      path = json['path'] as String?,
      encodedCommand = json['encodedCommand'] as String?,
      observeInitError = json['observe_init_error'] as String?;
  final int? nr;
  final String? syscall;
  final int? pid;
  final String? path;
  final String? encodedCommand;
  final String? observeInitError;
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
  final allowWritePaths = opts.allowWritePaths;
  final denyWritePaths = opts.denyWritePaths;
  final ignoreViolations = opts.ignoreViolations;
  final resolveCommandText = opts.resolveCommandText;
  // sun_path is 108 bytes; mkdtemp under tmpdir() keeps us well under.
  final sockDir = Directory.systemTemp.createTempSync('srt-obs-').path;
  final rand = math.Random.secure();
  final sockPath = path.join(
    sockDir,
    's${List<int>.generate(4, (_) => rand.nextInt(256)).map((x) => x.toRadixString(16).padLeft(2, '0')).join()}.sock',
  );
  bool underPrefix(String p, String prefix) =>
      p == prefix || p.startsWith(prefix.endsWith('/') ? prefix : '$prefix/');
  /** A write attempt is a violation iff bwrap would refuse it: outside every
   *  allowWrite prefix, or back inside a denyWrite carve-out. */
  bool isDenied(String p) {
    if (denyWritePaths.any((d) => underPrefix(p, d))) return true;
    return !allowWritePaths.any((a) => underPrefix(p, a));
  }

  void handleEvent(_ObserveEvent ev, String? encodedCommand) {
    if (ev.observeInitError != null && ev.observeInitError!.isNotEmpty) {
      logForDebugging(
        '[Sandbox Linux Monitor] observe filter not installed: ${ev.observeInitError}',
      );
      return;
    }
    if (ev.path == null) return;
    // Only resolved absolute paths are classifiable. Anything else means
    // resolution failed upstream (or an old producer): this channel is
    // best-effort telemetry, so drop rather than guess.
    if (!ev.path!.startsWith('/')) return;
    // apply-seccomp resolves relative paths against the tracee's cwd/dirfd
    // before emitting, so events arrive absolute; the joined form may still
    // contain ./ and ../ segments. Collapse them ONCE, here: the policy check,
    // the ignoreViolations match and the recorded line must all speak of the
    // same path, or a `..` detour suppresses a record it did not match, or
    // hides which file was written.
    final observedPath = path.posix.normalize(ev.path!);
    if (!isDenied(observedPath)) return;
    String? command;
    if (encodedCommand != null && encodedCommand.isNotEmpty) {
      try {
        command = resolveCommandText(decodeSandboxedCommand(encodedCommand));
      } catch (_) {
        /* ignore */
      }
    }
    if (shouldIgnoreViolation(observedPath, command, ignoreViolations)) return;
    final violation = SandboxViolationEvent(
      line: 'deny ${ev.syscall ?? 'syscall'} $observedPath',
      command: command,
      encodedCommand: encodedCommand,
      timestamp: DateTime.now(),
    );
    callback(violation);
  }

  final readyCompleter = Completer<void>();
  void resolveReady() {
    if (!readyCompleter.isCompleted) readyCompleter.complete();
  }

  String? observeSocketPath = sockPath;

  final NodeServer server = createServer((NodeSocket conn) {
    String? encodedCommand;
    // Upstream reads lines with node:readline createInterface({input: conn});
    // no readline shim exists, so the same line splitting is done here and
    // rl.close() becomes `closed = true`.
    var closed = false;
    final decoder = Utf8Decoder(allowMalformed: true);
    var pending = '';
    void onLine(String raw) {
      if (raw.isEmpty) return;
      _ObserveEvent ev;
      try {
        ev = _ObserveEvent(jsonDecode(raw) as Map<String, dynamic>);
      } catch (_) {
        return;
      }
      // The socket is writable from inside the sandbox, so the attribution
      // field is attacker-chosen bytes of attacker-chosen length. One longer
      // than a carrier this process mints can hold attributes nothing: drop
      // it and keep the violation itself, unattributed.
      final attribution =
          ev.encodedCommand != null &&
              Buffer.byteLength(ev.encodedCommand!) <= MAX_ENCODED_COMMAND_BYTES
          ? ev.encodedCommand
          : null;
      // First line from each apply-seccomp instance is the encodedCommand
      // header; subsequent lines may also carry it but the header is
      // authoritative for this connection.
      if (attribution != null &&
          attribution.isNotEmpty &&
          encodedCommand == null) {
        encodedCommand = attribution;
      }
      handleEvent(ev, encodedCommand ?? attribution);
    }

    conn.on('data', (Object? data) {
      if (closed) return;
      pending += decoder.convert(data! as List<int>);
      var i = pending.indexOf('\n');
      while (i >= 0 && !closed) {
        var raw = pending.substring(0, i);
        if (raw.endsWith('\r')) raw = raw.substring(0, raw.length - 1);
        pending = pending.substring(i + 1);
        onLine(raw);
        i = pending.indexOf('\n');
      }
    });
    conn.on('end', () {
      // readline emits a final unterminated line on input end.
      if (!closed && pending.isNotEmpty) {
        final raw = pending;
        pending = '';
        onLine(raw);
      }
    });
    conn.on('error', (Object? _) => closed = true);
    conn.on('close', ([Object? _]) => closed = true);
  });

  server.on('error', (Object? err) {
    final message = err is NodeException ? err.message : '$err';
    logForDebugging(
      '[Sandbox Linux Monitor] listen failed: $message - violation monitoring disabled',
      level: 'warn',
    );
    observeSocketPath = null;
    resolveReady();
  });
  server.listen(sockPath, () => resolveReady());

  final sockets = <NodeSocket>{};
  server.on('connection', (NodeSocket s) {
    sockets.add(s);
    s.on('close', ([Object? _]) => sockets.remove(s));
  });

  void stop() {
    logForDebugging('[Sandbox Linux Monitor] stopping');
    for (final s in sockets.toList()) {
      s.destroy();
    }
    server.close();
    try {
      // No node:fs rmSync shim yet: rmSync(sockDir, {recursive, force}).
      Directory(sockDir).deleteSync(recursive: true);
    } catch (_) {
      /* best effort */
    }
  }

  return LinuxViolationMonitor(
    observeSocketPath: () => observeSocketPath,
    ready: readyCompleter.future,
    stop: stop,
  );
}
