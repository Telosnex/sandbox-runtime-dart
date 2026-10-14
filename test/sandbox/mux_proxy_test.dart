// Ported from sandbox-runtime test/sandbox/mux-proxy.test.ts @ 24eb39e.
import 'package:test/test.dart';

void main() {
  group('mux-proxy first-byte dispatch', () {
    test(
      'routes 0x05 (SOCKS5 greeting) to the SOCKS handler with byte 0 intact',
      () {
        // const greeting = Buffer.from([0x05, 0x01, 0x00])
        // const reply = await send(greeting)
        // expect(reply).toEqual(Buffer.from([0x05, 0x00]))
        // // The handler must see the FULL greeting including the peeked 0x05.
        // expect(Buffer.concat(socksHits)).toEqual(greeting)
      },
      skip: 'pending port: src/sandbox/mux-proxy.ts',
    );

    test('routes 0x04 (SOCKS4) to the SOCKS handler', () {
      // const req = Buffer.from([
      //   0x04, 0x01, 0x00, 0x50, 0x7f, 0x00, 0x00, 0x01, 0x00,
      // ])
      // await send(req)
      // expect(Buffer.concat(socksHits)[0]).toBe(0x04)
    }, skip: 'pending port: src/sandbox/mux-proxy.ts');

    test('routes an absolute-URI GET to the HTTP backend', () {
      // const reply = await send(
      //   Buffer.from(
      //     'GET http://x/ HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n',
      //   ),
      // )
      // const text = reply.toString()
      // expect(text).toContain('HTTP/1.1 200')
      // expect(text).toContain('http-request:GET:http://x/')
      // expect(socksHits.length).toBe(0)
    }, skip: 'pending port: src/sandbox/mux-proxy.ts');

    test('routes CONNECT to the HTTP backend connect handler', () {
      // const reply = await send(
      //   Buffer.from('CONNECT x:443 HTTP/1.1\r\nHost: x:443\r\n\r\n'),
      // )
      // const text = reply.toString()
      // expect(text).toContain('200 Connection Established')
      // expect(text).toContain('http-connect:x:443')
    }, skip: 'pending port: src/sandbox/mux-proxy.ts');

    test('routes a TLS ClientHello first byte (0x16) to HTTP, not SOCKS', () {
      // // Not a valid HTTP request — the backend will 400 it — but the point
      // // is it must NOT be treated as SOCKS.
      // await send(Buffer.from([0x16, 0x03, 0x01, 0x00, 0x05])).catch(() => {})
      // expect(socksHits.length).toBe(0)
    }, skip: 'pending port: src/sandbox/mux-proxy.ts');

    test('destroys a connect-then-stall client after firstByteTimeoutMs', () {
      // const start = Date.now()
      // await new Promise<void>(resolve => {
      //   const c = connect(port, '127.0.0.1')
      //   // Send nothing; wait for the server to drop us.
      //   c.on('close', () => resolve())
      //   c.on('error', () => {}) // ECONNRESET is fine
      // })
      // const elapsed = Date.now() - start
      // expect(elapsed).toBeGreaterThanOrEqual(450)
      // expect(elapsed).toBeLessThan(2000)
      // expect(socksHits.length).toBe(0)
    }, skip: 'pending port: src/sandbox/mux-proxy.ts');

    test('handles connect-then-immediate-close without dispatching', () {
      // await new Promise<void>(resolve => {
      //   const c = connect(port, '127.0.0.1', () => c.end())
      //   c.on('close', () => resolve())
      //   c.on('error', () => {})
      // })
      // expect(socksHits.length).toBe(0)
    }, skip: 'pending port: src/sandbox/mux-proxy.ts');

    test(
      'removeBackendSocketSync removes the backend socket file, and close() still works',
      () {
        // const address = httpStub.address() // a path, or on Windows a port
        // if (typeof address === 'string') expect(existsSync(address)).toBe(true)
        // mux.removeBackendSocketSync()
        // if (typeof address === 'string') expect(existsSync(address)).toBe(false)
      },
      skip: 'pending port: src/sandbox/mux-proxy.ts',
    );
  });
}
