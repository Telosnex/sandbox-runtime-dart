// Port of the WHATWG `structuredClone` for the values this package clones.
//
// Dart has no reflection, so beyond Map/List/Set/primitives every class that
// must be cloned is listed here by hand. Config classes whose fields are all
// final Strings/bools/ints/records are immutable and returned as-is; classes
// that hold a List or Map are rebuilt with copied collections.
//
// One divergence from the platform function: `structuredClone` throws
// DataCloneError on functions. Upstream's updateConfig works around that by
// pulling `filterRequest` out and putting the reference back; here functions
// pass through by reference, which is what that workaround produces.

import '../sandbox/sandbox_config.dart';

/// Node's global `structuredClone(value)`: a deep copy of [value].
///
/// Throws [ArgumentError] (standing in for DataCloneError) for an object of
/// a class this file doesn't know.
T structuredClone<T>(T value) => _clone(value) as T;

List<E>? _l<E>(List<E>? v) => v == null ? null : List<E>.of(v);

Object? _clone(Object? v) {
  switch (v) {
    case null || String() || num() || bool() || Function() || Record():
      return v;
    case DateTime():
      return DateTime.fromMicrosecondsSinceEpoch(
        v.microsecondsSinceEpoch,
        isUtc: v.isUtc,
      );
    case Map<String, List<String>>():
      return {for (final e in v.entries) e.key: List<String>.of(e.value)};
    case Map<String, String>():
      return Map<String, String>.of(v);
    case Map<String, Object?>():
      return <String, Object?>{
        for (final e in v.entries) e.key: _clone(e.value),
      };
    // Other element types come back as Map<Object?, Object?> / List<Object?>.
    case Map():
      return {for (final e in v.entries) _clone(e.key): _clone(e.value)};
    case List<String>():
      return List<String>.of(v);
    case List<FilesystemPathEntry>():
      return List<FilesystemPathEntry>.of(v);
    case List():
      return [for (final e in v) _clone(e)];
    case Set<String>():
      return Set<String>.of(v);
    case Set():
      return {for (final e in v) _clone(e)};
    // Immutable: every field is a final String/bool/int/record.
    case FilesystemPathEntry() ||
        ParentProxyConfig() ||
        AwsPairConfig() ||
        Sigv4Config() ||
        SeccompConfig() ||
        SrtWinConfig() ||
        WindowsConfig():
      return v;
    case MitmProxyConfig():
      return MitmProxyConfig(socketPath: v.socketPath, domains: [...v.domains]);
    case TlsTerminateConfig():
      return TlsTerminateConfig(
        caCertPath: v.caCertPath,
        caKeyPath: v.caKeyPath,
        excludeDomains: _l(v.excludeDomains),
        extraCaCertPaths: _l(v.extraCaCertPaths),
        maxTunnels: v.maxTunnels,
        handshakeTimeoutMs: v.handshakeTimeoutMs,
      );
    case NetworkConfig():
      return NetworkConfig(
        allowedDomains: [...v.allowedDomains],
        deniedDomains: [...v.deniedDomains],
        deniedDomainReasons: v.deniedDomainReasons == null
            ? null
            : Map.of(v.deniedDomainReasons!),
        strictAllowlist: v.strictAllowlist,
        deniedResolvedAddresses: _l(v.deniedResolvedAddresses),
        allowUnixSockets: _l(v.allowUnixSockets),
        allowAllUnixSockets: v.allowAllUnixSockets,
        allowLocalBinding: v.allowLocalBinding,
        allowMachLookup: _l(v.allowMachLookup),
        httpProxyPort: v.httpProxyPort,
        socksProxyPort: v.socksProxyPort,
        mitmProxy: structuredClone(v.mitmProxy),
        filterRequest: v.filterRequest,
        allowPlaintextHeaderSet: v.allowPlaintextHeaderSet,
        stripResponseHeaders: _l(v.stripResponseHeaders),
        refuseOpaqueTunnels: v.refuseOpaqueTunnels,
        requireHostMatch: v.requireHostMatch,
        tlsTerminate: structuredClone(v.tlsTerminate),
        parentProxy: v.parentProxy,
        ambiguousRequestTarget: v.ambiguousRequestTarget,
      );
    case FilesystemConfig():
      return FilesystemConfig(
        disabled: v.disabled,
        denyRead: [...v.denyRead],
        allowRead: _l(v.allowRead),
        allowWrite: [...v.allowWrite],
        denyWrite: [...v.denyWrite],
        allowGitConfig: v.allowGitConfig,
      );
    case CredentialFileConfig():
      return CredentialFileConfig(
        path: v.path,
        mode: v.mode,
        extract: v.extract,
        onExtractNoMatch: v.onExtractNoMatch,
        decode: v.decode,
        maskClaims: _l(v.maskClaims),
        maskDuplicates: v.maskDuplicates,
        injectHosts: _l(v.injectHosts),
      );
    case CredentialEnvVarConfig():
      return CredentialEnvVarConfig(
        name: v.name,
        mode: v.mode,
        extract: v.extract,
        onExtractNoMatch: v.onExtractNoMatch,
        decode: v.decode,
        maskClaims: _l(v.maskClaims),
        injectHosts: _l(v.injectHosts),
      );
    case CredentialsConfig():
      return CredentialsConfig(
        files: v.files?.map(structuredClone).toList(),
        envVars: v.envVars?.map(structuredClone).toList(),
        allowPlaintextInject: v.allowPlaintextInject,
        awsPairs: _l(v.awsPairs),
        sigv4: v.sigv4,
      );
    case RipgrepConfig():
      return RipgrepConfig(
        command: v.command,
        args: _l(v.args),
        argv0: v.argv0,
      );
    case GitConfig():
      return GitConfig(safeDirectories: [...v.safeDirectories]);
    case SandboxRuntimeConfig():
      return SandboxRuntimeConfig(
        network: structuredClone(v.network),
        filesystem: structuredClone(v.filesystem),
        credentials: structuredClone(v.credentials),
        ignoreViolations: structuredClone(v.ignoreViolations),
        enableWeakerNestedSandbox: v.enableWeakerNestedSandbox,
        enableWeakerNetworkIsolation: v.enableWeakerNetworkIsolation,
        allowAppleEvents: v.allowAppleEvents,
        ripgrep: structuredClone(v.ripgrep),
        mandatoryDenySearchDepth: v.mandatoryDenySearchDepth,
        allowPty: v.allowPty,
        allowNestedUserNamespaces: v.allowNestedUserNamespaces,
        seccomp: v.seccomp,
        bwrapPath: v.bwrapPath,
        socatPath: v.socatPath,
        javaAgentJarPath: v.javaAgentJarPath,
        windows: v.windows,
        git: structuredClone(v.git),
      );
    default:
      throw ArgumentError.value(v, 'value', 'could not be cloned');
  }
}
