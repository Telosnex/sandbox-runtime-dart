// STUB: pending port of src/utils/config-loader.ts @ 24eb39e.
// ignore_for_file: slash_for_doc_comments

import '../sandbox/sandbox_config.dart' show SandboxRuntimeConfig;

/**
 * Parse and validate sandbox configuration from a string
 * Used for parsing config from control fd (JSON lines protocol)
 */
SandboxRuntimeConfig? loadConfigFromString(String content) =>
    throw UnimplementedError('pending port of src/utils/config-loader.ts');

/**
 * Why a settings file did not yield a config. Only `missing` is a reason to
 * run with the built-in defaults; the rest name a file whose rules would be
 * silently dropped by doing so. `reason` is a printable sentence naming the
 * path — key paths and validator messages, never the file's values.
 */
sealed class LoadConfigResult {
  const LoadConfigResult();

  String get kind;
}

class LoadConfigResultOk extends LoadConfigResult {
  @override
  final String kind;
  final SandboxRuntimeConfig config;
  const LoadConfigResultOk({required this.config}) : kind = 'ok';
}

class LoadConfigResultMissing extends LoadConfigResult {
  @override
  final String kind;
  const LoadConfigResultMissing() : kind = 'missing';
}

class LoadConfigResultEmpty extends LoadConfigResult {
  @override
  final String kind;
  const LoadConfigResultEmpty() : kind = 'empty';
}

class LoadConfigResultUnreadable extends LoadConfigResult {
  @override
  final String kind;
  final String reason;
  const LoadConfigResultUnreadable({required this.reason})
    : kind = 'unreadable';
}

class LoadConfigResultInvalid extends LoadConfigResult {
  @override
  final String kind;
  final String reason;
  const LoadConfigResultInvalid({required this.reason}) : kind = 'invalid';
}

/**
 * Load and validate sandbox configuration from a file.
 */
LoadConfigResult loadConfig(String filePath) =>
    throw UnimplementedError('pending port of src/utils/config-loader.ts');
