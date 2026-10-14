// Ported from sandbox-runtime src/index.ts @ 24eb39e.
// Library exports
export 'sandbox/sandbox_manager.dart' show SandboxManager;
export 'sandbox/sandbox_manager.dart' show WrapWithSandboxOptions;
export 'sandbox/sandbox_violation_store.dart' show SandboxViolationStore;
// Configuration types and schemas
export 'sandbox/sandbox_config.dart'
    show
        SandboxRuntimeConfig,
        NetworkConfig,
        FilesystemConfig,
        FilesystemPathEntry,
        CredentialsConfig,
        CredentialFileConfig,
        CredentialEnvVarConfig,
        CredentialMode,
        IgnoreViolationsConfig;
export 'sandbox/sandbox_config.dart'
    show
        SandboxRuntimeConfigSchema,
        NetworkConfigSchema,
        FilesystemConfigSchema,
        CredentialsConfigSchema,
        IgnoreViolationsConfigSchema,
        RipgrepConfigSchema;
// Schema types and utilities
export 'sandbox/sandbox_schemas.dart'
    show
        SandboxAskCallback,
        FsReadRestrictionConfig,
        FsWriteRestrictionConfig,
        CredentialRestrictionConfig,
        NetworkRestrictionConfig,
        NetworkHostPattern;
// Per-request filter
export 'sandbox/request_filter.dart'
    show
        FilterRequestCallback,
        RequestDecision,
        RequestInfo,
        MutateForwardedHeaders;
// Platform-specific utilities
export 'sandbox/macos_sandbox_utils.dart' show SandboxViolationEvent;
export 'sandbox/linux_sandbox_utils.dart'
    show
        SandboxDependencyCheck,
        LinuxSandboxProfileError,
        LinuxSandboxProfileErrorCode;
// Windows install/status API
export 'sandbox/windows_sandbox_utils.dart'
    show
        WindowsSandboxError,
        getSrtWinPath,
        resolveSrtWin,
        VENDORED_SRT_WIN_EXE,
        checkWindowsSandboxStatus,
        checkWindowsSandboxStatusAsync,
        getWindowsWfpStatus,
        getWindowsWfpStatusAsync,
        verifyWindowsWfpEgress,
        getWindowsSandboxUserStatus,
        getWindowsSandboxUserStatusAsync,
        getWindowsSandboxCaCert,
        windowsTrustCa,
        windowsTrustCaAsync,
        ensurePersistentWindowsCa,
        windowsStateDir,
        installWindowsSandbox,
        installWindowsSandboxAsync,
        checkWindowsDependenciesAsync,
        uninstallWindowsSandbox,
        windowsInstallInstructions,
        stampWindowsAcl,
        restoreWindowsAcl,
        grantWindowsAcl,
        revokeWindowsAcl,
        expandWindowsFsPaths,
        buildGitConfigEnv,
        parseWindowsBinShell,
        parseWindowsSandboxError,
        isUncPath,
        DEFAULT_WINDOWS_PROXY_PORT_RANGE,
        SRT_WIN_DISPATCH_ARG1;
export 'sandbox/windows_sandbox_utils.dart'
    show
        WindowsSandboxErrorCode,
        WindowsSandboxStatus,
        WindowsBinShell,
        MappedDriveCwdError,
        WindowsInstallOptions,
        WindowsInstallResult,
        WindowsWfpStatus,
        WindowsAclStampOptions,
        WindowsAclGrantOptions,
        WindowsAclAceOutcome,
        WindowsWfpStatusResult,
        WindowsWfpVerifyResult,
        WindowsSandboxUserStatus,
        WindowsPersistentCa,
        SrtWinSpawn;
// TLS-termination CA generation/validation (mitm-ca.ts). Embedders that
// manage CA persistence themselves (rather than relying on the Windows
// persistent-CA default) use these to generate and validate a pair.
export 'sandbox/mitm_ca.dart' show generateCa, validateCaPair, certThumbprint;
export 'sandbox/mitm_ca.dart' show GeneratedCa, CaPairValidation;
export 'sandbox/sandbox_config.dart'
    show WindowsConfig, SrtWinConfig, GitConfig;
export 'sandbox/sandbox_config.dart'
    show WindowsConfigSchema, SrtWinConfigSchema, GitConfigSchema;
// Utility functions
export 'sandbox/sandbox_utils.dart' show getDefaultWritePaths;
export 'sandbox/path_entries.dart' show writeRootsOf;
// Where the library takes a path to be: for a caller that judges paths itself.
export 'utils/real_path.dart' show realPathOf;
// Platform utilities
export 'utils/platform.dart' show getWslVersion, Platform;
