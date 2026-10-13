// Ported from sandbox-runtime src/sandbox/java-proxy-agent.ts @ 24eb39e.
// ignore_for_file: constant_identifier_names, non_constant_identifier_names
// ignore_for_file: curly_braces_in_flow_control_structures, slash_for_doc_comments

import 'dart:isolate';

import 'package:path/path.dart' as path;

import '../node/fs_exists.dart' as fs;
import '../utils/debug.dart';
import 'generate_seccomp_filter.dart' show getGlobalNpmPathsAsync;

///
/// JVM proxy agent: makes Java tools inside the sandbox honour the proxy.
///
/// The JVM ignores HTTPS_PROXY/NO_PROXY — proxy selection is driven by the
/// `https.proxyHost` family of system properties, and the credential the
/// proxy requires can only be supplied through `java.net.Authenticator`,
/// which needs code running inside the JVM. Env vars alone can't do that,
/// so gRPC-Java (Bazel's remote cache), Gradle, Maven, etc. either dial the
/// target directly (no route out of the sandbox) or hit the proxy without
/// the token and get a 407.
///
/// The fix is a tiny `-javaagent` (source in vendor/java-proxy-agent-src,
/// built into vendor/java-proxy-agent/srt-proxy-agent.jar by the release
/// workflow) that, at JVM start-up, translates the proxy env vars into
/// system properties and installs an Authenticator for the proxy endpoint.
/// This module locates that jar — same lookup shape as the apply-seccomp
/// binary — and builds the JAVA_TOOL_OPTIONS value that points every JVM in
/// the sandbox at it. The env var carries only the jar path; the credential
/// stays in HTTPS_PROXY, which the agent reads itself, so the JVM's "Picked
/// up JAVA_TOOL_OPTIONS: …" stderr line leaks nothing.
///
const String JAVA_PROXY_AGENT_JAR_NAME = 'srt-proxy-agent.jar';

final Map<String, String?> _jarPathCache = <String, String?>{};

///
/// Locate srt-proxy-agent.jar. Order:
/// 0. explicit path (config `javaAgentJarPath`) — used if it exists,
/// 1. vendor/java-proxy-agent/ next to this module (bundled),
/// 2. ../../vendor/java-proxy-agent/ (package root — normal npm install),
/// 3. ../vendor/java-proxy-agent/ (dist/vendor — some bundlers),
/// 4. a global npm install of the package (native builds without vendor/).
/// Returns null when nothing is found; callers then leave JAVA_TOOL_OPTIONS
/// alone (JVMs are simply not proxy-aware, as before) rather than failing.
///
/// The global-npm fallback resolves `npm root -g` without blocking the event
/// loop.
///
Future<String?> getJavaProxyAgentJarPathAsync([String? explicitPath]) async {
  final key = explicitPath ?? '';
  if (_jarPathCache.containsKey(key)) return _jarPathCache[key];
  final found =
      await _findLocalJar(explicitPath) ??
      _findGlobalJar(await getGlobalNpmPathsAsync());
  _jarPathCache[key] = found;
  return found;
}

final String _JAR_REL_PATH = path.join(
  'vendor',
  'java-proxy-agent',
  JAVA_PROXY_AGENT_JAR_NAME,
);

/// Steps 0–3 of the lookup; null means try the global npm install.
Future<String?> _findLocalJar([String? explicitPath]) async {
  if (explicitPath != null && explicitPath.isNotEmpty) {
    if (fs.existsSync(explicitPath)) return explicitPath;
    logForDebugging(
      '[java-proxy-agent] javaAgentJarPath not found: $explicitPath',
      level: 'warn',
    );
  }
  final moduleUri = await Isolate.resolvePackageUri(
    Uri.parse('package:sandbox_runtime/src/sandbox/java_proxy_agent.dart'),
  );
  if (moduleUri == null) return null;
  final baseDir = path.dirname(moduleUri.toFilePath());
  final candidates = [
    path.join(baseDir, _JAR_REL_PATH),
    path.join(baseDir, '..', '..', '..', _JAR_REL_PATH),
    path.join(baseDir, '..', '..', _JAR_REL_PATH),
  ];
  for (final candidate in candidates) {
    if (fs.existsSync(candidate)) return candidate;
  }
  return null;
}

/// Step 4 of the lookup: a global npm install of the package.
String? _findGlobalJar(List<String> globalBases) {
  for (final base in globalBases) {
    final candidate = path.join(base, _JAR_REL_PATH);
    if (fs.existsSync(candidate)) return candidate;
  }
  logForDebugging(
    '[java-proxy-agent] $JAVA_PROXY_AGENT_JAR_NAME not found; JVMs in the '
    'sandbox will not be pointed at the proxy (run `npm run build:java-agent`)',
    level: 'warn',
  );
  return null;
}

///
/// Compose the JAVA_TOOL_OPTIONS value for a sandboxed child.
///
/// `-javaagent:<jar>` is prepended when a jar path is given; `flags` are
/// appended (e.g. macOS's -Djava.net.preferIPv4Stack=true). The parent's
/// own JAVA_TOOL_OPTIONS is preserved unless that var is on the
/// credential-deny list, in which case it is dropped so the deny holds.
/// Flags already present in the inherited value are not duplicated.
/// Returns null when there is nothing to set.
///
String? buildJavaToolOptions({
  String? agentJarPath,
  List<String>? flags,
  List<String>? unsetEnvVars,
  String? inherited,
}) {
  final denied = (unsetEnvVars ?? const <String>[]).contains(
    'JAVA_TOOL_OPTIONS',
  );
  final inheritedValue = denied ? '' : (inherited ?? '');
  final parts = <String>[];
  if (agentJarPath != null && agentJarPath.isNotEmpty) {
    parts.add(_javaAgentFlag(agentJarPath));
  }
  if (inheritedValue.isNotEmpty) parts.add(inheritedValue);
  for (final flag in flags ?? const <String>[]) {
    if (!inheritedValue.contains(flag) && !parts.contains(flag))
      parts.add(flag);
  }
  return parts.isNotEmpty ? parts.join(' ') : null;
}

///
/// The JVM tokenizes JAVA_TOOL_OPTIONS on whitespace but honours double
/// quotes, so a jar path containing whitespace is wrapped in them.
///
String _javaAgentFlag(String jarPath) {
  final flag = '-javaagent:$jarPath';
  return RegExp(r'\s').hasMatch(jarPath) ? '"$flag"' : flag;
}
