// Ported from sandbox-runtime test/helpers/emitted-connections.ts @ 0bbebed.
import 'package:test/test.dart';
import 'package:sandbox_runtime/src/sandbox/emitted_connection.dart'
    show servesEmittedConnections;
import 'package:sandbox_runtime/src/node/console.dart' as console;

/// Whether this runtime's http.Server serves a connection handed to it with
/// emit('connection'): Node and Bun >= 1.4 do, and such a server has a
/// 'connection' listener of its own. TLS termination in this process and a
/// handed listening socket both need it; without it a proxy given a CA
/// refuses to start, and the descriptor forms of srt-proxy cannot serve.
final canServeEmittedConnections = servesEmittedConnections();

/// `describe` and `test` for cases that run a proxy configured to terminate
/// TLS: skipped where this runtime cannot (Bun before 1.4), where such a
/// proxy refuses to start. The reason is logged once below.
void describeWithTls(String description, void Function() body) {
  _warned;
  return group(
    description,
    body,
    skip: canServeEmittedConnections ? null : 'TLS termination unavailable',
  );
}

void testWithTls(String description, void Function() body, {Object? tags}) {
  _warned;
  return test(
    description,
    body,
    tags: tags,
    skip: canServeEmittedConnections ? null : 'TLS termination unavailable',
  );
}

// Dart has no top-level statements: the warning runs once, on first use of
// describeWithTls or testWithTls.
final bool _warned = _warnUnsupported();
bool _warnUnsupported() {
  if (!canServeEmittedConnections) {
    console.warn(
      'TLS termination tests are skipped: tlsTerminate needs Node, or Bun 1.4 or later, and this is Bun null',
    );
  }
  return true;
}
