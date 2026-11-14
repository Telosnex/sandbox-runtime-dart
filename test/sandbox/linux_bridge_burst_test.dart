// Ported from sandbox-runtime test/sandbox/linux-bridge-burst.test.ts @ 0bbebed.
// ignore_for_file: constant_identifier_names, slash_for_doc_comments
import 'package:test/test.dart';
import 'package:sandbox_runtime/src/sandbox/linux_sandbox_utils.dart';
import 'package:sandbox_runtime/src/sandbox/sandbox_manager.dart';
import 'package:sandbox_runtime/src/sandbox/sandbox_config.dart';
import 'package:sandbox_runtime/src/utils/shell_quote.dart';
import '../helpers/platform.dart';
import '../helpers/bwrap_namespace.dart';
import '../helpers/spawn.dart';

/**
 * What is timed is connect(2) alone. A handshake the listener's queue has room
 * for the kernel finishes by itself, however busy the host and however slowly
 * the listener accepts. One it has no room for it drops, and the client sends
 * again after a second.
 */
const BURST = '''
import os, selectors, socket, time, urllib.parse
for name in ('HTTP_PROXY', 'FTP_PROXY'):
    to = urllib.parse.urlparse(os.environ[name])
    waiting = selectors.DefaultSelector()
    began = time.monotonic()
    for _ in range(64):
        s = socket.socket()
        s.setblocking(False)
        s.connect_ex((to.hostname, to.port))
        waiting.register(s, selectors.EVENT_WRITE)
    made, late = [], 0
    while len(made) < 64 and time.monotonic() - began < 20:
        for key, _ in waiting.select(1):
            waiting.unregister(key.fileobj)
            if key.fileobj.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR) == 0:
                made.append(key.fileobj)
                late += time.monotonic() - began > 0.9
    print('%s made=%d late=%d' % (name, len(made), late))
    for s in made:
        s.close()
''';

void main() {
  group('the bridges inside the Linux sandbox', () {
    setUpAll(() async {
      expect(checkLinuxDependencies().errors, []);
      await SandboxManager.reset();
    });
    tearDownAll(() async {
      await SandboxManager.reset();
    });
    test(
      'take 64 connections made at once, each at its first try',
      () async {
        await SandboxManager.initialize(
          SandboxRuntimeConfig(
            network: NetworkConfig(allowedDomains: [], deniedDomains: []),
            filesystem: FilesystemConfig(
              denyRead: [],
              allowWrite: [],
              denyWrite: [],
            ),
          ),
        );
        final r = await spawnAsync(
          await SandboxManager.wrapWithSandbox(quote(['python3', '-c', BURST])),
          const RunOpts(shell: true, encoding: 'utf8', timeout: 60000),
        );
        expect(
          r.stdout,
          'HTTP_PROXY made=64 late=0\nFTP_PROXY made=64 late=0\n',
        );
      },
      skip: isLinux && bwrapCanNamespaceNetwork()
          ? false
          : 'bwrap cannot namespace network',
      timeout: const Timeout(Duration(milliseconds: 70000)),
    );
  }, skip: isLinux ? false : 'not Linux');
}
