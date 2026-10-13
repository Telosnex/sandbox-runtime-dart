// Ported from sandbox-runtime test/sandbox/mux-proxy.test.ts @ 24eb39e.
import 'package:test/test.dart';

const _httpSocketGap =
    'Blocked on the HTTP/socket shim: Node net first-byte peek/unshift, '
    'duplex socket piping and lifecycle, and HTTP backend Unix-socket '
    'listen/connect are not implemented.';

void main() {
  group('mux-proxy first-byte dispatch', () {
    test(
      'routes 0x05 (SOCKS5 greeting) to the SOCKS handler with byte 0 intact',
      () {},
      skip: _httpSocketGap,
    );

    test(
      'routes 0x04 (SOCKS4) to the SOCKS handler',
      () {},
      skip: _httpSocketGap,
    );

    test(
      'routes an absolute-URI GET to the HTTP backend',
      () {},
      skip: _httpSocketGap,
    );

    test(
      'routes CONNECT to the HTTP backend connect handler',
      () {},
      skip: _httpSocketGap,
    );

    test(
      'routes a TLS ClientHello first byte (0x16) to HTTP, not SOCKS',
      () {},
      skip: _httpSocketGap,
    );

    test(
      'destroys a connect-then-stall client after firstByteTimeoutMs',
      () {},
      skip: _httpSocketGap,
    );

    test(
      'handles connect-then-immediate-close without dispatching',
      () {},
      skip: _httpSocketGap,
    );

    test(
      'removeBackendSocketSync removes the backend socket file, and close() still works',
      () {},
      skip: _httpSocketGap,
    );
  });
}
