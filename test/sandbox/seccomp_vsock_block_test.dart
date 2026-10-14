// Ported from sandbox-runtime test/sandbox/seccomp-vsock-block.test.ts @ 24eb39e.
// ignore_for_file: constant_identifier_names, non_constant_identifier_names, slash_for_doc_comments
import 'package:sandbox_runtime/src/node/child_process.dart' show spawnSync;
import 'package:sandbox_runtime/src/sandbox/generate_seccomp_filter.dart';
import 'package:sandbox_runtime/src/sandbox/linux_sandbox_utils.dart';
import 'package:sandbox_runtime/src/sandbox/sandbox_config.dart';
import 'package:sandbox_runtime/src/sandbox/sandbox_manager.dart';
import 'package:sandbox_runtime/src/sandbox/sandbox_schemas.dart'
    show FsWriteRestrictionConfig;
import 'package:sandbox_runtime/src/utils/shell_quote.dart' show quote;
import 'package:test/test.dart';

import '../helpers/bwrap_namespace.dart';
import '../helpers/platform.dart';
import '../helpers/spawn.dart';

/**
 * Every vsock assertion is on the errno. seccomp answers before the kernel
 * looks at the family, so under the filter the result is EPERM whether or not
 * the host has a vsock transport. Without the rule the kernel answers with a
 * socket, ENODEV or EAFNOSUPPORT, unless a container runtime's own seccomp
 * profile already refuses the family.
 */

// Prints `<label>=OK` or `<label>=<errno name>` for each socket() attempt.
const ATTEMPT = [
  'import errno, socket',
  'def attempt(label, family, kind):',
  '    try:',
  '        socket.socket(family, kind).close()',
  '        print(label + "=OK")',
  '    except OSError as e:',
  '        print(label + "=" + errno.errorcode.get(e.errno, str(e.errno)))',
];

final VSOCK_ATTEMPTS = [
  ...ATTEMPT,
  'attempt("STREAM", socket.AF_VSOCK, socket.SOCK_STREAM)',
  'attempt("DGRAM", socket.AF_VSOCK, socket.SOCK_DGRAM)',
  'attempt("SEQPACKET", socket.AF_VSOCK, socket.SOCK_SEQPACKET)',
].join('\n');

const VSOCK_REFUSED = 'STREAM=EPERM\nDGRAM=EPERM\nSEQPACKET=EPERM\n';

void main() {
  group('apply-seccomp refuses AF_VSOCK sockets', skip: isLinux ? false : 'Linux only', () {
    late String applySeccomp;

    underFilter(String script) => spawnSync(
      applySeccomp,
      ['python3', '-c', script],
      {'encoding': 'utf8', 'timeout': 10000},
    );

    setUpAll(() {
      applySeccomp = getApplySeccompBinaryPath()!;
      expect(applySeccomp, isNotEmpty);
    });

    test('answers EPERM for every socket type', () {
      final r = underFilter(VSOCK_ATTEMPTS);
      expect(r.stdout as String, contains(VSOCK_REFUSED));
      expect(r.status, 0);
    });

    test('answers EPERM when the upper half of the domain register is set', () {
      // The kernel reads the domain as a 32-bit int, so a raw syscall that sets
      // bits above it still asks for AF_VSOCK. The rule has to mask them off.
      final r = underFilter(
        [
          'import ctypes, errno, platform, socket',
          'nr = {"x86_64": 41, "aarch64": 198}[platform.machine()]',
          'libc = ctypes.CDLL(None, use_errno=True)',
          'domain = ctypes.c_ulong(socket.AF_VSOCK | (1 << 32) | (1 << 63))',
          'fd = libc.syscall(ctypes.c_long(nr), domain, ctypes.c_ulong(1), ctypes.c_ulong(0))',
          'print("fd=%d errno=%s" % (fd, errno.errorcode.get(ctypes.get_errno())))',
        ].join('\n'),
      );
      expect(r.stdout as String, contains('fd=-1 errno=EPERM'));
      expect(r.status, 0);
    });

    test('leaves other socket families alone', () {
      final r = underFilter(
        [
          ...ATTEMPT,
          'attempt("INET", socket.AF_INET, socket.SOCK_STREAM)',
          'attempt("INET_DGRAM", socket.AF_INET, socket.SOCK_DGRAM)',
          'attempt("INET6", socket.AF_INET6, socket.SOCK_STREAM)',
          'attempt("NETLINK", socket.AF_NETLINK, socket.SOCK_RAW)',
          'attempt("BELOW", socket.AF_VSOCK - 1, socket.SOCK_STREAM)',
          'attempt("ABOVE", socket.AF_VSOCK + 1, socket.SOCK_STREAM)',
        ].join('\n'),
      );
      final stdout = r.stdout as String;
      expect(stdout, contains('INET=OK'));
      expect(stdout, contains('INET_DGRAM=OK'));
      expect(stdout, contains('NETLINK=OK'));
      // A host with IPv6 turned off answers EAFNOSUPPORT here by itself.
      expect(stdout, isNot(contains('INET6=EPERM')));
      // AF_VSOCK's neighbours, NFC and KCM: the kernel refuses a stream socket of
      // either with another errno, so EPERM would mean the rule matches too much.
      expect(stdout, isNot(contains('BELOW=EPERM')));
      expect(stdout, isNot(contains('ABOVE=EPERM')));
      expect(r.status, 0);
    });
  });

  group('AF_VSOCK in the full Linux sandbox', skip: isLinux ? false : 'Linux only', () {
    setUpAll(() async {
      expect(checkLinuxDependencies().errors, isEmpty);
      await SandboxManager.reset();
    });

    tearDownAll(() async {
      await SandboxManager.reset();
    });

    // Dart: fails on the VM: apply-seccomp cannot write /proc/self/setgroups inside bwrap's userns (environment)
    test(
      'is refused when the network is not restricted',
      () async {
        final wrapped = await wrapCommandWithSandboxLinux(
          LinuxSandboxParams(
            command: quote(['python3', '-c', VSOCK_ATTEMPTS]),
            needsNetworkRestriction: false,
            writeConfig: FsWriteRestrictionConfig(
              allowOnly: ['/tmp'],
              denyWithinAllow: [],
            ),
          ),
        );

        final r = await spawnAsync(
          wrapped,
          const RunOpts(shell: true, encoding: 'utf8', timeout: 15000),
        );
        expect(r.stdout, contains(VSOCK_REFUSED));
        expect(r.status, 0);
      },
    );

    // Dart: fails on the VM: apply-seccomp cannot write /proc/self/setgroups inside bwrap's userns (environment)
    test(
      'is refused in a network-restricted sandbox whose proxies still answer',
      () async {
        // Nothing is allowed, so no request leaves the host: the HTTP proxy's 403
        // and the SOCKS proxy's method selection show the command reaches both.
        await SandboxManager.initialize(
          const SandboxRuntimeConfig(
            network: NetworkConfig(allowedDomains: [], deniedDomains: []),
            filesystem: FilesystemConfig(
              denyRead: [],
              allowWrite: [],
              denyWrite: [],
            ),
          ),
        );

        final script = [
          VSOCK_ATTEMPTS,
          'import os, urllib.error, urllib.parse, urllib.request',
          'try:',
          '    urllib.request.urlopen("http://denied.example/", timeout=10)',
          'except urllib.error.HTTPError as e:',
          '    print("HTTP=%d" % e.code)',
          'socks = urllib.parse.urlparse(os.environ["FTP_PROXY"])',
          'conn = socket.create_connection((socks.hostname, socks.port), timeout=10)',
          'conn.sendall(bytes([5, 1, 2]))',
          'print("SOCKS=" + conn.recv(2).hex())',
        ].join('\n');
        final wrapped = await SandboxManager.wrapWithSandbox(
          quote(['python3', '-c', script]),
        );
        expect(wrapped, contains('--unshare-net'));

        final r = await spawnAsync(
          wrapped,
          const RunOpts(shell: true, encoding: 'utf8', timeout: 30000),
        );
        expect(r.stdout, contains(VSOCK_REFUSED));
        expect(r.stdout, contains('HTTP=403'));
        // VER=5 and a method: the SOCKS proxy's own reply to the greeting.
        expect(
          r.stdout,
          matches(RegExp(r'^SOCKS=05[0-9a-f]{2}$', multiLine: true)),
        );
        expect(r.status, 0);
      },
      skip: !isLinux || !bwrapCanNamespaceNetwork()
          ? 'bwrap cannot namespace network'
          : null,
      timeout: const Timeout(Duration(milliseconds: 40000)),
    );
  });
}
