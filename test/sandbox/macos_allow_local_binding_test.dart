// Ported from sandbox-runtime test/sandbox/macos-allow-local-binding.test.ts @ 24eb39e.
import 'dart:io';

import 'package:test/test.dart';
import '../../lib/src/sandbox/macos_sandbox_utils.dart';

ProcessResult runInSandbox(String pythonCode, bool allowLocalBinding) {
  final command = 'python3 -c "$pythonCode"';
  final wrappedCommand = wrapCommandWithSandboxMacOS(
    MacOSSandboxParams(
      command: command,
      needsNetworkRestriction: true,
      allowLocalBinding: allowLocalBinding,
      readConfig: null,
      writeConfig: null,
    ),
  );
  return Process.runSync(
    '/bin/sh',
    ['-c', wrappedCommand],
    stdoutEncoding: const SystemEncoding(),
    stderrEncoding: const SystemEncoding(),
  );
}

// Python one-liners for socket bind tests
// AF_INET bind
String bindIPv4(String addr) =>
    "import socket; s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(('${addr}', 0)); print('BOUND'); s.close()";

// AF_INET6 dual-stack bind (IPV6_V6ONLY=0, same as Java ServerSocketChannel.open())
String bindIPv6DualStack(String addr) =>
    "import socket; s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0); s.bind(('${addr}', 0)); print('BOUND'); s.close()";

// Outbound TCP connect to a public IP (Seatbelt check, not reachability — settimeout
// keeps the success path bounded; the deny path is an immediate EPERM at connect()).
String connectTCP(String addr, int port) =>
    "import socket; s = socket.socket(); s.settimeout(3); s.connect(('${addr}', ${port})); print('CONNECTED')";

// Outbound UDP sendto a public IP (DNS-exfil shape, #88).
String sendUDP(String addr, int port) =>
    "import socket; s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(3); s.sendto(b'x', ('${addr}', ${port})); print('SENT')";

// Bind a loopback listener and connect to it from a sibling AF_INET socket
// in the same sandboxed process.
const loopbackIPC = '''
import socket, threading
srv = socket.socket()
srv.bind(('127.0.0.1', 0)); srv.listen(1)
port = srv.getsockname()[1]
def serve():
    c, _ = srv.accept(); c.send(b'HI'); c.close()
threading.Thread(target=serve, daemon=True).start()
cli = socket.socket(); cli.settimeout(3)
cli.connect(('127.0.0.1', port))
print('IPC', cli.recv(2).decode())
''';

void main() {
  group('macOS Seatbelt allowLocalBinding', () {
    group('when allowLocalBinding is true', () {
      test('should allow AF_INET bind to 127.0.0.1', () {
        final result = runInSandbox(bindIPv4('127.0.0.1'), true);

        expect(result.exitCode, 0);
        expect(result.stdout, contains('BOUND'));
      });

      test('should allow AF_INET6 dual-stack bind to ::ffff:127.0.0.1', () {
        // This is the case that breaks Java/Gradle: an IPv6 dual-stack socket
        // binding to 127.0.0.1, which the kernel represents as ::ffff:127.0.0.1
        final result = runInSandbox(
          bindIPv6DualStack('::ffff:127.0.0.1'),
          true,
        );

        expect(result.exitCode, 0);
        expect(result.stdout, contains('BOUND'));
      });

      test('should allow AF_INET6 bind to ::1', () {
        final result = runInSandbox(bindIPv6DualStack('::1'), true);

        expect(result.exitCode, 0);
        expect(result.stdout, contains('BOUND'));
      });

      test('should allow connect to a self-bound 127.0.0.1 listener', () {
        final result = runInSandbox(loopbackIPC, true);

        expect(result.exitCode, 0);
        expect(result.stdout, contains('IPC HI'));
      });

      test('should still block outbound TCP to a non-loopback host (#225)', () {
        final result = runInSandbox(connectTCP('1.1.1.1', 443), true);

        expect(result.exitCode, isNot(0));
        expect(result.stderr, contains('Operation not permitted'));
      });

      test('should still block outbound UDP to a non-loopback host (#88)', () {
        final result = runInSandbox(sendUDP('1.1.1.1', 53), true);

        expect(result.exitCode, isNot(0));
        expect(result.stderr, contains('Operation not permitted'));
      });
    });

    group('when allowLocalBinding is false', () {
      test('should block AF_INET bind to 127.0.0.1', () {
        final result = runInSandbox(bindIPv4('127.0.0.1'), false);

        expect(result.exitCode, isNot(0));
      });

      test('should block AF_INET6 dual-stack bind to ::ffff:127.0.0.1', () {
        final result = runInSandbox(
          bindIPv6DualStack('::ffff:127.0.0.1'),
          false,
        );

        expect(result.exitCode, isNot(0));
      });
    });
  }, skip: Platform.isMacOS ? false : 'requires macOS Seatbelt');
}
