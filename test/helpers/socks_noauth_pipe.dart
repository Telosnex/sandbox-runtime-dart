// Ported from sandbox-runtime test/helpers/socks-noauth-pipe.ts @ 0bbebed.
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
  StreamSubscription<List<int>>? toSock;
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
        toSock = stdin.listen(sock.add);
      }
    },
    /**
     * The proxy refuses by writing banner + DISCONNECT and closing straight
     * away, but ssh only reads that DISCONNECT after it has written its own
     * identification/KEXINIT into our stdin. Exiting as soon as the socket
     * closes therefore races ssh's write: when ssh loses (busy CI runner) it
     * gets EPIPE and dies with "Broken pipe" instead of reporting the reason.
     * So on socket close, signal EOF to ssh once everything forwarded has been
     * flushed, then keep draining stdin and exit only when ssh closes it — with
     * a fallback timer so a client that never closes cannot wedge the test.
     */
    onDone: () {
      stdout.close().catchError((_) => exit(0));
      Timer(const Duration(milliseconds: 5000), () => exit(0));
      // Dart's stdin is single-subscription: the forwarding subscription is
      // redirected to discard instead of unpiped and re-listened.
      final sub = toSock;
      if (sub == null) {
        stdin.listen((_) {}, onDone: () => exit(0), onError: (_) => exit(0));
      } else {
        sub.onData((_) {});
        sub.onDone(() => exit(0));
        sub.onError((_) => exit(0));
      }
    },
    onError: (_) => exit(1),
  );
}
