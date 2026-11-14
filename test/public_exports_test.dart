// Ported from sandbox-runtime test/public-exports.test.ts @ 0bbebed.
// ignore_for_file: constant_identifier_names, slash_for_doc_comments

import 'package:sandbox_runtime/sandbox_runtime.dart';
import 'package:test/test.dart';

/**
 * Every value src/index.ts re-exports, sorted. src/index.ts is what
 * package.json points `main` and `types` at, and almost all of it is reached
 * only by embedders: the test tree imports two of these names through the
 * barrel and everything else straight from its implementation module, so a
 * removal here breaks the published surface without reddening anything.
 * Pinning the list makes a removal edit this array in the same commit, which
 * is the signal a review wants.
 *
 * Runtime values only. `export type` is erased before this can see it, so a
 * removed type still passes; catching that needs a declaration snapshot or an
 * API report, neither of which the package builds.
 */
const PUBLIC_VALUE_EXPORTS = [
  'CredentialsConfigSchema',
  'DEFAULT_WINDOWS_PROXY_PORT_RANGE',
  'FilesystemConfigSchema',
  'GitConfigSchema',
  'IgnoreViolationsConfigSchema',
  'LinuxSandboxProfileError',
  'NetworkConfigSchema',
  'RipgrepConfigSchema',
  'SRT_WIN_DISPATCH_ARG1',
  'SandboxInitializeConflictError',
  'SandboxManager',
  'SandboxRuntimeConfigSchema',
  'SandboxViolationStore',
  'SrtWinConfigSchema',
  'VENDORED_SRT_WIN_EXE',
  'WINDOWS_ALLOW_LOOPBACK_EFFECT',
  'WINDOWS_LOOPBACK_PROBE_PORT',
  'WINDOWS_PROFILE_READ_ENV_VARS',
  'WindowsConfigSchema',
  'WindowsSandboxError',
  'buildGitConfigEnv',
  'certThumbprint',
  'checkWindowsDependenciesAsync',
  'checkWindowsSandboxStatus',
  'checkWindowsSandboxStatusAsync',
  'ensurePersistentWindowsCa',
  'expandWindowsFsPaths',
  'forgetWindowsProfileRead',
  'forgetWindowsProfileReadAsync',
  'generateCa',
  'getDefaultWritePaths',
  'getSrtWinPath',
  'getWindowsProfileReadStatus',
  'getWindowsProfileReadStatusAsync',
  'getWindowsSandboxCaCert',
  'getWindowsSandboxUserStatus',
  'getWindowsSandboxUserStatusAsync',
  'getWindowsWfpStatus',
  'getWindowsWfpStatusAsync',
  'getWslVersion',
  'grantWindowsAcl',
  'grantWindowsProfileRead',
  'installWindowsSandbox',
  'installWindowsSandboxAsync',
  'isUncPath',
  'parseWindowsBinShell',
  'parseWindowsSandboxError',
  'realPathOf',
  'resolveSrtWin',
  'restoreWindowsAcl',
  'revokeWindowsAcl',
  'revokeWindowsAclChecked',
  'stampWindowsAcl',
  'uninstallWindowsSandbox',
  'validateCaPair',
  'verifyWindowsWfpEgress',
  'windowsInstallInstructions',
  'windowsProfileExclusionConflicts',
  'windowsProfileGrantNotice',
  'windowsProfileGrantSkipReason',
  'windowsProfileReadEnv',
  'windowsStateDir',
  'windowsTrustCa',
  'windowsTrustCaAsync',
  'writeRootsOf',
];

// Dart: there is no `Object.keys(srt)` on a library; this map is the barrel's
// runtime values, written out, so each name is checked to resolve at compile time.
final Map<String, Object? Function()> srt = {
  'CredentialsConfigSchema': () => CredentialsConfigSchema,
  'DEFAULT_WINDOWS_PROXY_PORT_RANGE': () => DEFAULT_WINDOWS_PROXY_PORT_RANGE,
  'FilesystemConfigSchema': () => FilesystemConfigSchema,
  'GitConfigSchema': () => GitConfigSchema,
  'IgnoreViolationsConfigSchema': () => IgnoreViolationsConfigSchema,
  'LinuxSandboxProfileError': () => LinuxSandboxProfileError,
  'NetworkConfigSchema': () => NetworkConfigSchema,
  'RipgrepConfigSchema': () => RipgrepConfigSchema,
  'SRT_WIN_DISPATCH_ARG1': () => SRT_WIN_DISPATCH_ARG1,
  'SandboxInitializeConflictError': () => SandboxInitializeConflictError,
  'SandboxManager': () => SandboxManager,
  'SandboxRuntimeConfigSchema': () => SandboxRuntimeConfigSchema,
  'SandboxViolationStore': () => SandboxViolationStore,
  'SrtWinConfigSchema': () => SrtWinConfigSchema,
  'VENDORED_SRT_WIN_EXE': () => VENDORED_SRT_WIN_EXE,
  'WINDOWS_ALLOW_LOOPBACK_EFFECT': () => WINDOWS_ALLOW_LOOPBACK_EFFECT,
  'WINDOWS_LOOPBACK_PROBE_PORT': () => WINDOWS_LOOPBACK_PROBE_PORT,
  'WINDOWS_PROFILE_READ_ENV_VARS': () => WINDOWS_PROFILE_READ_ENV_VARS,
  'WindowsConfigSchema': () => WindowsConfigSchema,
  'WindowsSandboxError': () => WindowsSandboxError,
  'buildGitConfigEnv': () => buildGitConfigEnv,
  'certThumbprint': () => certThumbprint,
  'checkWindowsDependenciesAsync': () => checkWindowsDependenciesAsync,
  'checkWindowsSandboxStatus': () => checkWindowsSandboxStatus,
  'checkWindowsSandboxStatusAsync': () => checkWindowsSandboxStatusAsync,
  'ensurePersistentWindowsCa': () => ensurePersistentWindowsCa,
  'expandWindowsFsPaths': () => expandWindowsFsPaths,
  'forgetWindowsProfileRead': () => forgetWindowsProfileRead,
  'forgetWindowsProfileReadAsync': () => forgetWindowsProfileReadAsync,
  'generateCa': () => generateCa,
  'getDefaultWritePaths': () => getDefaultWritePaths,
  'getSrtWinPath': () => getSrtWinPath,
  'getWindowsProfileReadStatus': () => getWindowsProfileReadStatus,
  'getWindowsProfileReadStatusAsync': () => getWindowsProfileReadStatusAsync,
  'getWindowsSandboxCaCert': () => getWindowsSandboxCaCert,
  'getWindowsSandboxUserStatus': () => getWindowsSandboxUserStatus,
  'getWindowsSandboxUserStatusAsync': () => getWindowsSandboxUserStatusAsync,
  'getWindowsWfpStatus': () => getWindowsWfpStatus,
  'getWindowsWfpStatusAsync': () => getWindowsWfpStatusAsync,
  'getWslVersion': () => getWslVersion,
  'grantWindowsAcl': () => grantWindowsAcl,
  'grantWindowsProfileRead': () => grantWindowsProfileRead,
  'installWindowsSandbox': () => installWindowsSandbox,
  'installWindowsSandboxAsync': () => installWindowsSandboxAsync,
  'isUncPath': () => isUncPath,
  'parseWindowsBinShell': () => parseWindowsBinShell,
  'parseWindowsSandboxError': () => parseWindowsSandboxError,
  'realPathOf': () => realPathOf,
  'resolveSrtWin': () => resolveSrtWin,
  'restoreWindowsAcl': () => restoreWindowsAcl,
  'revokeWindowsAcl': () => revokeWindowsAcl,
  'revokeWindowsAclChecked': () => revokeWindowsAclChecked,
  'stampWindowsAcl': () => stampWindowsAcl,
  'uninstallWindowsSandbox': () => uninstallWindowsSandbox,
  'validateCaPair': () => validateCaPair,
  'verifyWindowsWfpEgress': () => verifyWindowsWfpEgress,
  'windowsInstallInstructions': () => windowsInstallInstructions,
  'windowsProfileExclusionConflicts': () => windowsProfileExclusionConflicts,
  'windowsProfileGrantNotice': () => windowsProfileGrantNotice,
  'windowsProfileGrantSkipReason': () => windowsProfileGrantSkipReason,
  'windowsProfileReadEnv': () => windowsProfileReadEnv,
  'windowsStateDir': () => windowsStateDir,
  'windowsTrustCa': () => windowsTrustCa,
  'windowsTrustCaAsync': () => windowsTrustCaAsync,
  'writeRootsOf': () => writeRootsOf,
};

void main() {
  group('package entry point', () {
    test('exports exactly the checked-in list of values', () {
      expect(srt.keys.toList()..sort(), PUBLIC_VALUE_EXPORTS);
    });

    test('binds every listed name', () {
      for (final name in PUBLIC_VALUE_EXPORTS) {
        expect(srt[name]!(), isNotNull);
      }
    });
  });
}
