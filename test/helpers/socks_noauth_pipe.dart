// Ported from sandbox-runtime test/helpers/socks-noauth-pipe.ts @ 24eb39e.
/**
 * Minimal no-auth SOCKS5 CONNECT pipe for tests: connects to the proxy,
 * offers ONLY the no-auth method (like BSD `nc -X 5`), issues CONNECT for
 * the given destination, then pipes stdin/stdout to the socket. Used as an
 * ssh ProxyCommand so the ssh-refusal end-to-end tests do not depend on
 * which netcat flavor the host ships (GNU/nmap variants lack `-X`).
 *
 * Usage: bun socks-noauth-pipe.ts <proxyPort> <destHost> <destPort>
 */
import 'dart:async';
import 'dart:io';

Future<void> main(List<String> args) async {
  final proxyPort = args.isEmpty ? null : args[0];
  final destHost = args.length < 2 ? null : args[1];
  final destPort = args.length < 3 ? null : args[2];
  if (proxyPort == null || destHost == null || destPort == null) return;
  final sock = await Socket.connect('127.0.0.1', int.parse(proxyPort));
  sock.add([5, 1, 0]);
  var stage = 'method';
  var buf = <int>[];
  sock.listen(
    (chunk) {
      if (stage == 'pipe') {
        stdout.add(chunk);
        return;
      }
      buf.addAll(chunk);
      if (stage == 'method' && buf.length >= 2) {
        if (buf[0] != 5 || buf[1] != 0) exit(1);
        buf = buf.sublist(2);
        final host = destHost.codeUnits;
        final port = int.parse(destPort);
        sock.add([
          5,
          1,
          0,
          3,
          host.length,
          ...host,
          (port >> 8) & 255,
          port & 255,
        ]);
        stage = 'reply';
      }
      if (stage == 'reply' && buf.length >= 10) {
        if (buf[1] != 0) exit(1);
        final rest = buf.sublist(10);
        stage = 'pipe';
        if (rest.isNotEmpty) stdout.add(rest);
        stdin.listen(sock.add);
      }
    },
    onDone: () async {
      stdout.close();
      await stdin.drain<void>();
      exit(0);
    },
    onError: (_) => exit(1),
  );
  stdin.listen(sock.add);
}
