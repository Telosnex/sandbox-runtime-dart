// Ported from sandbox-runtime test/helpers/bwrap-namespace.ts @ 0bbebed.
import 'dart:io';

bool _probe(List<String> extraArgs) {
  final result = Process.runSync('bwrap', [
    '--unshare-pid',
    '--unshare-user',
    ...extraArgs,
    '--cap-drop',
    'ALL',
    '--ro-bind',
    '/',
    '/',
    '--proc',
    '/proc',
    'true',
  ], runInShell: false);
  return result.exitCode == 0;
}

bool? _probed;
bool? _probedWithNetwork;

/**
 * Whether bwrap here can run the same namespace/proc surface the wrapped
 * commands use (--unshare-pid/--unshare-user/--proc). A bare --ro-bind probe
 * passes on hosts where mounting a fresh /proc in the new PID namespace
 * still EPERMs, turning a live arm into a false red. No --unshare-net: the
 * suites pass needsNetworkRestriction: false, so the commands under test
 * never create a netns and the probe must not require one — a
 * netns-restricted host would otherwise silently skip the arm.
 *
 * Lazy and memoised: it spawns a process, which nothing that merely imports
 * a test helper should pay for.
 */
bool bwrapCanNamespace() => _probed ??= _probe([]);

/**
 * The same probe with --unshare-net added, for the suites whose wrap does
 * restrict the network: that wrap creates a network namespace, which a host
 * can refuse while still granting the PID and user namespaces above. Kept
 * apart from [bwrapCanNamespace] so the suites that never create one
 * are not skipped along with these.
 */
bool bwrapCanNamespaceNetwork() =>
    _probedWithNetwork ??= _probe(['--unshare-net']);
