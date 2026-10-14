// Ported from sandbox-runtime src/utils/config-loader.ts @ 24eb39e.
// ignore_for_file: slash_for_doc_comments

import 'dart:convert';
import 'dart:io';

import '../sandbox/sandbox_config.dart' show SandboxRuntimeConfig;
import '../sandbox/sandbox_config.dart' show SandboxRuntimeConfigSchema;

/**
 * Parse and validate sandbox configuration from a string
 * Used for parsing config from control fd (JSON lines protocol)
 */
SandboxRuntimeConfig? loadConfigFromString(String content) {
  if (content.trim().isEmpty) return null;
  try {
    final parsed = jsonDecode(content);
    final result = SandboxRuntimeConfigSchema.safeParse(parsed);
    if (!result.success) return null;
    return result.data;
  } catch (_) {
    return null;
  }
}

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
LoadConfigResult loadConfig(String filePath) {
  late String content;
  try {
    content = File(filePath).readAsStringSync(encoding: utf8);
  } on FileSystemException catch (error) {
    final code = error.osError?.errorCode;
    // dart:io exposes errno, whereas Node exposes its symbolic code.
    if (code == 2 || code == 3) return const LoadConfigResultMissing();
    return LoadConfigResultUnreadable(
      reason:
          '$filePath could not be read (${error.osError?.message ?? error.message}).',
    );
  } catch (error) {
    return LoadConfigResultUnreadable(
      reason: '$filePath could not be read ($error).',
    );
  }

  if (content.trim().isEmpty) return const LoadConfigResultEmpty();
  Object? parsed;
  try {
    parsed = jsonDecode(content);
  } on FormatException catch (error) {
    return LoadConfigResultInvalid(
      reason: '$filePath is not valid JSON: ${error.message}',
    );
  }
  final result = SandboxRuntimeConfigSchema.safeParse(parsed);
  if (!result.success) {
    final issues = result.error.issues
        .map(
          (issue) =>
              '${issue.path.join('.').isEmpty ? '(root)' : issue.path.join('.')}: ${issue.message}',
        )
        .join('; ');
    return LoadConfigResultInvalid(
      reason: '$filePath does not hold a valid config — $issues',
    );
  }
  return LoadConfigResultOk(config: result.data);
}
