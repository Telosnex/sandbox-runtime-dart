// Node process values reproduced for the ported files. Overrides let tests
// model upstream tests which temporarily replace process.platform/env/cwd.
import 'dart:io';

String? _platformOverride;
Map<String, String>? _envOverride;
String? _cwdOverride;

/// The Node `process.platform` spelling for the current Dart host.
String get platform =>
    _platformOverride ??
    (Platform.isMacOS
        ? 'darwin'
        : Platform.isLinux
        ? 'linux'
        : Platform.isWindows
        ? 'win32'
        : Platform.operatingSystem);

/// Node's live `process.env` map, unless a test has supplied an override.
Map<String, String> get env => _envOverride ?? Platform.environment;

/// Node's `process.cwd()` value, unless a test has supplied an override.
String cwd() => _cwdOverride ?? Directory.current.path;

/// Override `process.platform` in tests; pass null to use the host value.
void setPlatformForTesting(String? value) => _platformOverride = value;

/// Override `process.env` in tests; pass null to use the host environment.
void setEnvForTesting(Map<String, String>? value) => _envOverride = value;

/// Override `process.cwd()` in tests; pass null to use `Directory.current`.
void setCwdForTesting(String? value) => _cwdOverride = value;
