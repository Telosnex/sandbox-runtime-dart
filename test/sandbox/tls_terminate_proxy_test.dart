// Ported from sandbox-runtime test/sandbox/tls-terminate-proxy.test.ts @ 0bbebed.
// ignore_for_file: constant_identifier_names, non_constant_identifier_names, no_leading_underscores_for_local_identifiers, slash_for_doc_comments
import 'dart:async';
import 'dart:convert';
import 'dart:io' show Directory, HttpClient;

import 'package:sandbox_runtime/src/node/buffer.dart' show Buffer;
import 'package:sandbox_runtime/src/node/child_process.dart' show spawn;
import 'package:sandbox_runtime/src/node/forge.dart' show forge;
import 'package:sandbox_runtime/src/node/fs.dart'
    show mkdtempSync, readFileSync, rmSync, writeFileSync;
import 'package:sandbox_runtime/src/node/http.dart' as http;
import 'package:sandbox_runtime/src/node/https.dart' as https;
import 'package:sandbox_runtime/src/node/net.dart' show NodeAddress;
import 'package:sandbox_runtime/src/node/os.dart' show tmpdir;
import 'package:sandbox_runtime/src/node/path.dart' show join;
import 'package:sandbox_runtime/src/node/tls.dart' as tls;
import 'package:sandbox_runtime/src/node/url.dart' show URL;
import 'package:sandbox_runtime/src/sandbox/http_proxy.dart'
    show HttpProxyServerOptions, createHttpProxyServer;
import 'package:sandbox_runtime/src/sandbox/mitm_ca.dart'
    show MitmCA, createMitmCA, disposeMitmCA, randomSerial;
import 'package:sandbox_runtime/src/sandbox/mitm_leaf.dart' show mintLeafCert;
import 'package:sandbox_runtime/src/sandbox/request_filter.dart'
    show FilterRequestCallback, RequestDecision;
import 'package:test/test.dart';

// Every case here runs a proxy configured to terminate TLS, so each is
// skipped where this runtime cannot terminate it in-process.
import '../helpers/emitted_connections.dart' show SERVES_EMITTED_CONNECTIONS;

// Committed test-only CA — see test/fixtures/tls-terminate/README.md.
final FIXTURE_DIR = join(
  Directory.current.path, // import.meta.dir, '..'
  'test',
  'fixtures',
  'tls-terminate',
);
final CA_CERT = join(FIXTURE_DIR, 'ca.crt');
final CA_KEY = join(FIXTURE_DIR, 'ca.key');
final CA_PEM = readFileSync(CA_CERT, 'utf8') as String;

// Dart: the object literal upstream hands createHttpProxyServer; every
// option not named here is absent (null).
class _HttpOptions implements HttpProxyServerOptions {
  _HttpOptions({
    this.filter_,
    this.mitmCA,
    this.tlsTerminateUpstreamCA,
    this.shouldTerminateTLS,
    this.filterRequest,
  });
  final bool Function()? filter_;
  @override
  final MitmCA? mitmCA;
  @override
  final dynamic tlsTerminateUpstreamCA;
  @override
  bool Function(String hostname, int port)? shouldTerminateTLS;
  @override
  final FilterRequestCallback? filterRequest;
  @override
  FutureOr<bool> filter(
    int port,
    String host,
    dynamic socket, [
    String? encodedCommand,
    void Function(String reason)? explain,
  ]) => filter_?.call() ?? true;
  @override
  dynamic noSuchMethod(Invocation invocation) => null;
}

// Drive the proxy with curl so we exercise a real CONNECT-through-proxy
// client. (Bun's https.request ignores createConnection, so an in-process
// client would bypass the proxy.)
void main() {
  // Dart: upstream's describeWithTls, spelled as group so the title audit sees it.
  group(
    'tls-terminate-proxy: end-to-end through createHttpProxyServer',
    skip: SERVES_EMITTED_CONNECTIONS ? null : 'TLS termination unavailable',
    () {
      final ca = createMitmCA(caCertPath: CA_CERT, caKeyPath: CA_KEY);

      // Upstream HTTPS server. Uses a leaf cert for 127.0.0.1 signed by the
      // fixture CA; the proxy's outbound https.request trusts it via
      // tlsTerminateUpstreamCA. Leaf-only — Bun's TLS client mis-verifies when
      // the root CA is appended to the server chain.
      late http.NodeHttpServer upstream;
      late int upstreamPort;
      late http.NodeHttpServer proxy;
      late int proxyPort;

      setUpAll(() async {
        final upCert = mintLeafCert(ca, '127.0.0.1');
        final upLeafOnly = RegExp(
          r'-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----\r?\n?',
        ).firstMatch(upCert.certPem)!.group(0)!;
        upstream = https.createServer(
          {'cert': upLeafOnly, 'key': upCert.keyPem},
          (http.IncomingMessage req, http.ServerResponse res) {
            var body = '';
            req.on(
              'data',
              (Object? c) => body += Buffer.from(c as List<int>).toString(),
            );
            req.on('end', () {
              res.writeHead(200, {
                'content-type': 'application/json',
                'x-upstream': 'ok',
              });
              res.end(
                jsonEncode({
                  'echoed': body,
                  'path': req.url,
                  'method': req.method,
                  'host': req.headers['host'],
                }),
              );
            });
          },
        );
        await (() {
          final r = Completer<void>();
          upstream.listen(0, '127.0.0.1', () => r.complete());
          return r.future;
        })();
        upstreamPort = (upstream.address() as NodeAddress).port;

        proxy = createHttpProxyServer(
          _HttpOptions(
            filter_: () => true,
            mitmCA: ca,
            tlsTerminateUpstreamCA: CA_PEM,
          ),
        );
        await (() {
          final r = Completer<void>();
          proxy.listen(0, '127.0.0.1', () => r.complete());
          return r.future;
        })();
        proxyPort = (proxy.address() as NodeAddress).port;
      });

      tearDownAll(() async {
        await (() {
          final r = Completer<void>();
          proxy.close(() => r.complete());
          return r.future;
        })();
        await (() {
          final r = Completer<void>();
          upstream.close(() => r.complete());
          return r.future;
        })();
      });

      test(
        'terminates client TLS, forwards request, pipes response back',
        () async {
          final r = await curlViaProxy(
            proxyPort,
            'https://127.0.0.1:$upstreamPort/hello?a=1',
            method: 'POST',
            body: 'hi-from-client',
          );
          expect(r.exit, 0);
          expect(r.status, 200);
          expect(r.headers['x-upstream'], 'ok');
          final parsed = jsonDecode(r.body) as Map<String, dynamic>;
          expect(parsed['echoed'], 'hi-from-client');
          expect(parsed['path'], '/hello?a=1');
          expect(parsed['method'], 'POST');
          expect(parsed['host'], '127.0.0.1:$upstreamPort');
          // The client saw a leaf cert issued by our fixture CA — proves termination
          // happened (curl verified the chain via --cacert).
          expect(r.stderr, matches(RegExp(r'issuer:.*srt-test-ca')));
        },
      );

      test('GET works (no body)', () async {
        final r = await curlViaProxy(
          proxyPort,
          'https://127.0.0.1:$upstreamPort/ping',
        );
        expect(r.exit, 0);
        expect(r.status, 200);
        expect((jsonDecode(r.body) as Map<String, dynamic>)['path'], '/ping');
      });

      test('serves the empty CRL at GET /srt.crl (Schannel revocation)', () async {
        // CryptoAPI fetches the leaf's cRLDistributionPoints URL as an
        // origin-form GET over plain HTTP with no Proxy-Authorization, so this
        // route sits before both the auth check and the absolute-URI parse.
        // eslint-disable-next-line eslint-plugin-n/no-unsupported-features/node-builtins -- bun:test runtime has stable fetch
        // Dart: no fetch() global in the shims; dart:io's HttpClient stands in.
        final client = HttpClient();
        final req = await client.getUrl(
          Uri.parse('http://127.0.0.1:$proxyPort/srt.crl'),
        );
        final res = await req.close();
        expect(res.statusCode, 200);
        expect(res.headers.value('content-type'), 'application/pkix-crl');
        final body = Buffer.concat(await res.toList());
        client.close();
        expect(body.toUint8List(), equals(ca.crlDer));
      });

      test(
        'absolute-form request-target is normalized (filterRequest + upstream)',
        () async {
          // RFC 7230 §5.3.2 absolute-form. Some clients send this inside CONNECT
          // tunnels; without normalization the host concat produced a malformed
          // hostname like `example.comhttps`.
          final seen = <String>[];
          final p = createHttpProxyServer(
            _HttpOptions(
              filter_: () => true,
              filterRequest: (r, [info]) async {
                seen.add(r.url);
                return const RequestDecision(action: 'allow');
              },
              mitmCA: ca,
              tlsTerminateUpstreamCA: CA_PEM,
            ),
          );
          await (() {
            final r = Completer<void>();
            p.listen(0, '127.0.0.1', () => r.complete());
            return r.future;
          })();
          final port = (p.address() as NodeAddress).port;
          try {
            final r = await curlViaProxy(
              port,
              'https://127.0.0.1:$upstreamPort/abs?x=1',
              requestTarget: 'https://127.0.0.1:$upstreamPort/abs?x=1',
            );
            expect(r.exit, 0);
            expect(r.status, 200);
            expect(
              (jsonDecode(r.body) as Map<String, dynamic>)['path'],
              '/abs?x=1',
            );
            expect(seen, equals(['https://127.0.0.1:$upstreamPort/abs?x=1']));
            expect(URL(seen[0]).hostname, '127.0.0.1');
          } finally {
            await (() {
              final r = Completer<void>();
              p.close(() => r.complete());
              return r.future;
            })();
          }
        },
      );

      test(
        'upstream connect failure → 502 from the terminating proxy',
        () async {
          // Proves we are NOT an opaque tunnel: a tunnel would surface a TLS/TCP
          // error to the client (curl exit 35/56); the terminating proxy speaks
          // HTTP and returns 502 over the established TLS session.
          final r = await curlViaProxy(proxyPort, 'https://127.0.0.1:1/');
          expect(r.exit, 0);
          expect(r.status, 502);
        },
      );

      test('domain filter still gates termination (CONNECT 403)', () async {
        final blocked = createHttpProxyServer(
          _HttpOptions(filter_: () => false, mitmCA: ca),
        );
        await (() {
          final r = Completer<void>();
          blocked.listen(0, '127.0.0.1', () => r.complete());
          return r.future;
        })();
        final port = (blocked.address() as NodeAddress).port;
        try {
          final r = await curlViaProxy(
            port,
            'https://127.0.0.1:$upstreamPort/',
          );
          // curl: 56 = "Failure when receiving data from the peer" / proxy CONNECT refused
          expect(r.exit, isNot(0));
          expect(r.stderr, matches(RegExp(r'403')));
        } finally {
          await (() {
            final r = Completer<void>();
            blocked.close(() => r.complete());
            return r.future;
          })();
        }
      });

      test(
        'without mitmCA, CONNECT is still an opaque tunnel (regression)',
        () async {
          final tunnelProxy = createHttpProxyServer(
            _HttpOptions(filter_: () => true),
          );
          await (() {
            final r = Completer<void>();
            tunnelProxy.listen(0, '127.0.0.1', () => r.complete());
            return r.future;
          })();
          final port = (tunnelProxy.address() as NodeAddress).port;
          try {
            final r = await curlViaProxy(
              port,
              'https://127.0.0.1:$upstreamPort/tunnel',
            );
            expect(r.exit, 0);
            expect(r.status, 200);
            expect(
              (jsonDecode(r.body) as Map<String, dynamic>)['path'],
              '/tunnel',
            );
          } finally {
            await (() {
              final r = Completer<void>();
              tunnelProxy.close(() => r.complete());
              return r.future;
            })();
          }
        },
      );
    },
  );

  // Regression: same end-to-end path with an SRT-generated ephemeral CA
  // (createMitmCA({})). #259 introduced ephemeral CAs; the leaf-minting AKI
  // extension turned out to encode the SKI as a hex string (rather than raw
  // bytes) for forge-created CAs, breaking chain verification — caught only
  // when testing against a non-fixture CA.
  group(
    'tls-terminate-proxy: end-to-end with ephemeral CA',
    skip: SERVES_EMITTED_CONNECTIONS ? null : 'TLS termination unavailable',
    () {
      test('curl trusts the ephemeral-CA-signed leaf and round-trips', () async {
        final ca = createMitmCA();
        // Upstream uses the FIXTURE CA (same as the other describe) so the
        // proxy's outbound `ca:` value is identical across the file — Bun's
        // https.request caches the first `ca:` process-wide. The regression
        // under test is the client-facing leaf (ephemeral CA → curl), which is
        // covered by mitmCA below + curl --cacert pointing at the ephemeral CA.
        final fixtureCA = createMitmCA(caCertPath: CA_CERT, caKeyPath: CA_KEY);
        final upCert = mintLeafCert(fixtureCA, '127.0.0.1');
        final upLeafOnly = RegExp(
          r'-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----\r?\n?',
        ).firstMatch(upCert.certPem)!.group(0)!;
        final upstream = https.createServer(
          {'cert': upLeafOnly, 'key': upCert.keyPem},
          (http.IncomingMessage req, http.ServerResponse res) {
            var body = '';
            req.on(
              'data',
              (Object? c) => body += Buffer.from(c as List<int>).toString(),
            );
            req.on('end', () {
              res.writeHead(200, {'x-upstream': 'ok'});
              res.end(jsonEncode({'echoed': body, 'path': req.url}));
            });
          },
        );
        await (() {
          final r = Completer<void>();
          upstream.listen(0, '127.0.0.1', () => r.complete());
          return r.future;
        })();
        final upstreamPort = (upstream.address() as NodeAddress).port;

        final proxy = createHttpProxyServer(
          _HttpOptions(
            filter_: () => true,
            mitmCA: ca,
            tlsTerminateUpstreamCA: CA_PEM,
          ),
        );
        await (() {
          final r = Completer<void>();
          proxy.listen(0, '127.0.0.1', () => r.complete());
          return r.future;
        })();
        final proxyPort = (proxy.address() as NodeAddress).port;

        try {
          final r = await curlViaProxy(
            proxyPort,
            'https://127.0.0.1:$upstreamPort/hello?a=1',
            method: 'POST',
            body: 'from-ephemeral',
            cacert: ca.certPath,
          );
          expect(r.exit, 0);
          expect(r.status, 200);
          expect(r.headers['x-upstream'], 'ok');
          final parsed = jsonDecode(r.body) as Map<String, dynamic>;
          expect(parsed['echoed'], 'from-ephemeral');
          expect(parsed['path'], '/hello?a=1');
          expect(
            r.stderr,
            matches(RegExp(r'issuer:.*sandbox-runtime ephemeral CA')),
          );
        } finally {
          await (() {
            final r = Completer<void>();
            proxy.close(() => r.complete());
            return r.future;
          })();
          await (() {
            final r = Completer<void>();
            upstream.close(() => r.complete());
            return r.future;
          })();
          await disposeMitmCA(ca);
        }
      });
    },
  );

  // Per-host termination opt-out (`shouldTerminateTLS`). The scenario it
  // exists for is an mTLS upstream: only the in-sandbox client holds the
  // client certificate, and it pins the real upstream CA, so the connection
  // can only work if the proxy does NOT re-originate it. The upstream here
  // requires and verifies a client cert (`rejectUnauthorized: true`) signed
  // by the fixture CA, while the proxy MITMs with a *different* (ephemeral)
  // CA — the same shape as srt's ephemeral CA vs a real upstream's PKI.
  group(
    'tls-terminate-proxy: per-host termination opt-out (mTLS upstream)',
    skip: SERVES_EMITTED_CONNECTIONS ? null : 'TLS termination unavailable',
    () {
      // "Real" PKI the upstream + client belong to (fixture CA).
      final realCA = createMitmCA(caCertPath: CA_CERT, caKeyPath: CA_KEY);
      // The proxy's MITM CA — deliberately a different CA.
      final proxyCA = createMitmCA();

      late http.NodeHttpServer upstream;
      late int upstreamPort;
      late String tmpDir;
      late String clientCertPath;
      late String clientKeyPath;

      setUpAll(() async {
        final upCert = mintLeafCert(realCA, '127.0.0.1');
        final upLeafOnly = RegExp(
          r'-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----\r?\n?',
        ).firstMatch(upCert.certPem)!.group(0)!;
        upstream = https.createServer(
          {
            'cert': upLeafOnly,
            'key': upCert.keyPem,
            // True mTLS: the handshake fails unless the peer presents a cert
            // chaining to the fixture CA.
            'requestCert': true,
            'rejectUnauthorized': true,
            'ca': CA_PEM,
          },
          (http.IncomingMessage req, http.ServerResponse res) {
            // With rejectUnauthorized: true this handler only runs after the
            // client presented a cert that verified against `ca` — reaching it
            // at all is the mTLS proof. Echo the client CN too where the
            // runtime supports it (Bun's server-side TLSSocket has no
            // getPeerCertificate).
            final tlsSocket = req.socket as tls.TLSSocket;
            // Dart: getPeerCertificate() is a dart:io X509Certificate; its `subject` is the DN text, so the CN is cut out of it.
            final clientCN = RegExp(r'CN=([^,/]+)')
                .firstMatch(tlsSocket.getPeerCertificate()?.subject ?? '')
                ?.group(1);
            res.writeHead(200, {'content-type': 'application/json'});
            res.end(jsonEncode({'path': req.url, 'clientCN': clientCN}));
          },
        );
        await (() {
          final r = Completer<void>();
          upstream.listen(0, '127.0.0.1', () => r.complete());
          return r.future;
        })();
        upstreamPort = (upstream.address() as NodeAddress).port;

        // Client cert for curl. mintLeafCert only sets EKU serverAuth, which
        // OpenSSL rejects for client authentication, so mint one here.
        final client = mintClientCert(realCA, 'srt-test-client');
        tmpDir = mkdtempSync(join(tmpdir(), 'srt-mtls-test-'));
        clientCertPath = join(tmpDir, 'client.crt');
        clientKeyPath = join(tmpDir, 'client.key');
        writeFileSync(clientCertPath, client.certPem);
        writeFileSync(clientKeyPath, client.keyPem);
      });

      tearDownAll(() async {
        await (() {
          final r = Completer<void>();
          upstream.close(() => r.complete());
          return r.future;
        })();
        await disposeMitmCA(proxyCA);
        rmSync(tmpDir, {'recursive': true, 'force': true});
      });

      String url() => 'https://127.0.0.1:$upstreamPort/mtls';

      test(
        'terminating proxy cannot reach an mTLS upstream (502): it has no client cert to present',
        () async {
          final proxy = createHttpProxyServer(
            _HttpOptions(
              filter_: () => true,
              mitmCA: proxyCA,
              tlsTerminateUpstreamCA: CA_PEM,
            ),
          );
          await (() {
            final r = Completer<void>();
            proxy.listen(0, '127.0.0.1', () => r.complete());
            return r.future;
          })();
          final port = (proxy.address() as NodeAddress).port;
          try {
            // The client cooperates as much as possible: it trusts the MITM CA
            // and offers its client cert. Still fails — the cert is presented to
            // the proxy's listener (which never asks for it), not to the
            // upstream, and the proxy's own outbound leg has no client cert.
            final r = await curlViaProxy(
              port,
              url(),
              cacert: proxyCA.certPath,
              clientCertPath: clientCertPath,
              clientKeyPath: clientKeyPath,
            );
            expect(r.status, 502);
          } finally {
            await (() {
              final r = Completer<void>();
              proxy.close(() => r.complete());
              return r.future;
            })();
          }
        },
      );

      test(
        'a client that pins the real upstream CA rejects the MITM leaf outright',
        () async {
          final proxy = createHttpProxyServer(
            _HttpOptions(
              filter_: () => true,
              mitmCA: proxyCA,
              tlsTerminateUpstreamCA: CA_PEM,
            ),
          );
          await (() {
            final r = Completer<void>();
            proxy.listen(0, '127.0.0.1', () => r.complete());
            return r.future;
          })();
          final port = (proxy.address() as NodeAddress).port;
          try {
            // --cacert is the REAL upstream CA, not the MITM CA: the leaf the
            // proxy mints does not chain to it, so the handshake dies inside the
            // CONNECT tunnel (curl 60). This is what cert-pinning clients hit.
            final r = await curlViaProxy(
              port,
              url(),
              clientCertPath: clientCertPath,
              clientKeyPath: clientKeyPath,
            );
            expect(r.exit, isNot(0));
            expect(
              r.stderr,
              matches(RegExp(r'certificate|issuer', caseSensitive: false)),
            );
          } finally {
            await (() {
              final r = Completer<void>();
              proxy.close(() => r.complete());
              return r.future;
            })();
          }
        },
      );

      test(
        'shouldTerminateTLS=false: opaque tunnel, client completes mTLS end-to-end',
        () async {
          final seen = <(String, int)>[];
          final proxy = createHttpProxyServer(
            _HttpOptions(
              filter_: () => true,
              mitmCA: proxyCA,
              tlsTerminateUpstreamCA: CA_PEM,
              shouldTerminateTLS: (hostname, port) {
                seen.add((hostname, port));
                return false;
              },
            ),
          );
          await (() {
            final r = Completer<void>();
            proxy.listen(0, '127.0.0.1', () => r.complete());
            return r.future;
          })();
          final port = (proxy.address() as NodeAddress).port;
          try {
            // Same pinning client, same client cert — now it works: the tunnel is
            // opaque, so curl handshakes with the real upstream, verifies it
            // against the real CA, and presents its client cert to it.
            final r = await curlViaProxy(
              port,
              url(),
              clientCertPath: clientCertPath,
              clientKeyPath: clientKeyPath,
            );
            expect(r.exit, 0);
            expect(r.status, 200);
            final parsed = jsonDecode(r.body) as Map<String, dynamic>;
            expect(parsed['path'], '/mtls');
            // Node reports the verified client cert's CN; Bun's server-side
            // TLSSocket has no getPeerCertificate, so it reports null there.
            if (parsed['clientCN'] != null) {
              expect(parsed['clientCN'], 'srt-test-client');
            }
            // The cert curl saw was the upstream's real one, not a MITM leaf.
            expect(r.stderr, matches(RegExp(r'issuer:.*srt-test-ca')));
            expect(
              r.stderr,
              isNot(matches(RegExp(r'sandbox-runtime ephemeral CA'))),
            );
            expect(seen, contains(('127.0.0.1', upstreamPort)));
          } finally {
            await (() {
              final r = Completer<void>();
              proxy.close(() => r.complete());
              return r.future;
            })();
          }
        },
      );

      test(
        'shouldTerminateTLS=false without a client cert still fails: the upstream really demands mTLS',
        () async {
          // Negative control for the test above — proves the 200 there can only
          // come from curl's client cert being presented and verified end-to-end.
          final proxy = createHttpProxyServer(
            _HttpOptions(
              filter_: () => true,
              mitmCA: proxyCA,
              tlsTerminateUpstreamCA: CA_PEM,
              shouldTerminateTLS: (hostname, port) => false,
            ),
          );
          await (() {
            final r = Completer<void>();
            proxy.listen(0, '127.0.0.1', () => r.complete());
            return r.future;
          })();
          final port = (proxy.address() as NodeAddress).port;
          try {
            final r = await curlViaProxy(port, url());
            // The upstream aborts the handshake inside the opaque tunnel, so curl
            // fails at the TLS layer. (`r.status` would still read 200 here — the
            // proxy's own "200 Connection Established" is the only header block —
            // so the exit code is the meaningful assertion.)
            expect(r.exit, isNot(0));
            expect(r.body, '');
          } finally {
            await (() {
              final r = Completer<void>();
              proxy.close(() => r.complete());
              return r.future;
            })();
          }
        },
      );

      test(
        'shouldTerminateTLS=true keeps terminating (explicit default)',
        () async {
          final proxy = createHttpProxyServer(
            _HttpOptions(
              filter_: () => true,
              mitmCA: proxyCA,
              tlsTerminateUpstreamCA: CA_PEM,
              shouldTerminateTLS: (hostname, port) => true,
            ),
          );
          await (() {
            final r = Completer<void>();
            proxy.listen(0, '127.0.0.1', () => r.complete());
            return r.future;
          })();
          final port = (proxy.address() as NodeAddress).port;
          try {
            final r = await curlViaProxy(
              port,
              url(),
              cacert: proxyCA.certPath,
              clientCertPath: clientCertPath,
              clientKeyPath: clientKeyPath,
            );
            expect(r.status, 502);
          } finally {
            await (() {
              final r = Completer<void>();
              proxy.close(() => r.complete());
              return r.future;
            })();
          }
        },
      );
    },
  );

  group(
    'tls-terminate-proxy: extraCaCertPaths lets the client verify an excluded host with a site-local root',
    skip: SERVES_EMITTED_CONNECTIONS ? null : 'TLS termination unavailable',
    () {
      // The "site-local" PKI: the fixture CA plays the role of an internal root
      // (e.g. an internal mTLS CA) that is in no public root store. The
      // upstream's leaf chains to it.
      final realCA = createMitmCA(caCertPath: CA_CERT, caKeyPath: CA_KEY);

      late http.NodeHttpServer upstream;
      late int upstreamPort;

      setUpAll(() async {
        final upCert = mintLeafCert(realCA, '127.0.0.1');
        final upLeafOnly = RegExp(
          r'-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----\r?\n?',
        ).firstMatch(upCert.certPem)!.group(0)!;
        upstream = https.createServer(
          {'cert': upLeafOnly, 'key': upCert.keyPem},
          (http.IncomingMessage _req, http.ServerResponse res) {
            res.writeHead(200, {'content-type': 'text/plain'});
            res.end('site-local ok');
          },
        );
        await (() {
          final r = Completer<void>();
          upstream.listen(0, '127.0.0.1', () => r.complete());
          return r.future;
        })();
        upstreamPort = (upstream.address() as NodeAddress).port;
      });

      tearDownAll(() async {
        await (() {
          final r = Completer<void>();
          upstream.close(() => r.complete());
          return r.future;
        })();
        await disposeMitmCA(realCA);
      });

      String url() => 'https://127.0.0.1:$upstreamPort/extra-ca';

      // This is the regression the field exists for: SRT points the sandboxed
      // child's trust env vars (GIT_SSL_CAINFO, SSL_CERT_FILE, ...) at the trust
      // bundle, REPLACING the tool's own CA config. For an excluded
      // (passthrough) host the child does its own handshake against the real
      // certificate, so unless the site-local root is *in the bundle* the host
      // can never be verified from inside the sandbox.
      test(
        'without extraCaCertPaths the bundle cannot verify the upstream (negative control)',
        () async {
          final mitmCA = createMitmCA();
          final proxy = createHttpProxyServer(
            _HttpOptions(
              filter_: () => true,
              mitmCA: mitmCA,
              shouldTerminateTLS: (_, _) => false,
            ),
          );
          await (() {
            final r = Completer<void>();
            proxy.listen(0, '127.0.0.1', () => r.complete());
            return r.future;
          })();
          final port = (proxy.address() as NodeAddress).port;
          try {
            final r = await curlViaProxy(
              port,
              url(),
              cacert: mitmCA.trustBundlePath,
            );
            expect(r.exit, isNot(0));
            expect(
              r.stderr,
              matches(RegExp(r'certificate|issuer', caseSensitive: false)),
            );
          } finally {
            await (() {
              final r = Completer<void>();
              proxy.close(() => r.complete());
              return r.future;
            })();
            await disposeMitmCA(mitmCA);
          }
        },
      );

      test(
        'with extraCaCertPaths the bundle verifies the real upstream through the opaque tunnel',
        () async {
          final mitmCA = createMitmCA(extraCaCertPaths: [CA_CERT]);
          final proxy = createHttpProxyServer(
            _HttpOptions(
              filter_: () => true,
              mitmCA: mitmCA,
              shouldTerminateTLS: (_, _) => false,
            ),
          );
          await (() {
            final r = Completer<void>();
            proxy.listen(0, '127.0.0.1', () => r.complete());
            return r.future;
          })();
          final port = (proxy.address() as NodeAddress).port;
          try {
            final r = await curlViaProxy(
              port,
              url(),
              cacert: mitmCA.trustBundlePath,
            );
            expect(r.exit, 0);
            expect(r.status, 200);
            expect(r.body, 'site-local ok');
            // curl saw the upstream's REAL certificate, not a MITM leaf.
            expect(r.stderr, matches(RegExp(r'issuer:.*srt-test-ca')));
            expect(
              r.stderr,
              isNot(matches(RegExp(r'sandbox-runtime ephemeral CA'))),
            );
          } finally {
            await (() {
              final r = Completer<void>();
              proxy.close(() => r.complete());
              return r.future;
            })();
            await disposeMitmCA(mitmCA);
          }
        },
      );

      test(
        'terminated hosts still verify against the same bundle (MITM CA is first)',
        () async {
          final mitmCA = createMitmCA(extraCaCertPaths: [CA_CERT]);
          final proxy = createHttpProxyServer(
            _HttpOptions(
              filter_: () => true,
              mitmCA: mitmCA,
              tlsTerminateUpstreamCA: CA_PEM,
            ),
          );
          await (() {
            final r = Completer<void>();
            proxy.listen(0, '127.0.0.1', () => r.complete());
            return r.future;
          })();
          final port = (proxy.address() as NodeAddress).port;
          try {
            final r = await curlViaProxy(
              port,
              url(),
              cacert: mitmCA.trustBundlePath,
            );
            expect(r.exit, 0);
            expect(r.status, 200);
            // On the terminated path curl saw the proxy-minted leaf.
            expect(r.stderr, matches(RegExp(r'sandbox-runtime ephemeral CA')));
          } finally {
            await (() {
              final r = Completer<void>();
              proxy.close(() => r.complete());
              return r.future;
            })();
            await disposeMitmCA(mitmCA);
          }
        },
      );
    },
  );
}

/**
 * Mint a clientAuth leaf signed by `ca` for the mTLS tests. Test-only:
 * the production minter (mintLeafCert) is for server-side MITM leaves and
 * intentionally only carries EKU serverAuth.
 */
({String certPem, String keyPem}) mintClientCert(MitmCA ca, String cn) {
  final pki = forge.pki;
  final md = forge.md;
  final keys = pki.rsa.generateKeyPair(2048);
  final cert = pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = randomSerial();
  final notBefore = DateTime.now().subtract(Duration(days: 1));
  final notAfter = DateTime.now().add(Duration(days: 30));
  cert.validity.notBefore = notBefore;
  cert.validity.notAfter = notAfter;
  cert.setSubject([
    {'name': 'commonName', 'value': cn},
  ]);
  cert.setIssuer(ca.cert.subject.attributes);
  cert.setExtensions([
    {'name': 'basicConstraints', 'cA': false, 'critical': true},
    {'name': 'keyUsage', 'critical': true, 'digitalSignature': true},
    {'name': 'extKeyUsage', 'clientAuth': true},
    {'name': 'subjectKeyIdentifier'},
  ]);
  cert.sign(ca.key, md.sha256.create());
  return (
    certPem: pki.certificateToPem(cert),
    keyPem: pki.privateKeyToPem(keys.privateKey),
  );
}

typedef CurlResult = ({
  int exit,
  int status,
  Map<String, String> headers,
  String body,
  String stderr,
});

Future<CurlResult> curlViaProxy(
  int proxyPort,
  String url, {
  String? method,
  String? body,
  String? cacert,
  String? requestTarget,
  /** Client certificate + key, for mTLS upstreams. */
  String? clientCertPath,
  String? clientKeyPath,
}) async {
  final args = [
    '-sS',
    '-v', // TLS issuer line goes to stderr
    '--proxy',
    'http://127.0.0.1:$proxyPort',
    // An empty list overrides NO_PROXY, which would send curl around
    // the proxy under test for 127.0.0.1.
    '--noproxy',
    '',
    '--cacert',
    cacert ?? CA_CERT,
    '--max-time',
    '10',
    '-D',
    '-', // dump response headers to stdout before body
    '-X',
    method ?? 'GET',
  ];
  if (body != null) args.addAll(['--data-binary', body]);
  if (clientCertPath != null && clientCertPath.isNotEmpty) {
    args.addAll(['--cert', clientCertPath]);
  }
  if (clientKeyPath != null && clientKeyPath.isNotEmpty) {
    args.addAll(['--key', clientKeyPath]);
  }
  if (requestTarget != null && requestTarget.isNotEmpty) {
    args.addAll(['--request-target', requestTarget]);
  }
  args.add(url);

  // Async spawn so the in-process proxy/upstream can service the request.
  final child = spawn('curl', args);
  var out = '';
  var stderr = '';
  // Dart: child.stdout/stderr are byte Streams; decode them and signal 'end' through onDone.
  final stdoutEnd = Completer<void>();
  final stderrEnd = Completer<void>();
  child.stdout!
      .transform(utf8.decoder)
      .listen((c) => out += c, onDone: () => stdoutEnd.complete());
  child.stderr!
      .transform(utf8.decoder)
      .listen((c) => stderr += c, onDone: () => stderrEnd.complete());
  // Drain both streams to 'end' before reading the exit code — Bun's
  // ChildProcess 'close' can fire before all 'data' events are delivered.
  // Dart: listen for 'close' first; it can fire before the streams end, and
  // a late listener would wait forever.
  final exitCompleter = Completer<int>();
  child.on('close', (int? code) => exitCompleter.complete(code ?? 1));
  await Future.wait([stdoutEnd.future, stderrEnd.future]);
  final exit = await exitCompleter.future;

  // -D - prints headers (possibly multiple blocks: CONNECT response, then the
  // real response) followed by body. Take the LAST header block.
  final sep = out.lastIndexOf('\r\n\r\n');
  final headerPart = sep >= 0 ? out.substring(0, sep) : '';
  final bodyText = sep >= 0 ? out.substring(sep + 4) : out;
  final blocks = headerPart.split(RegExp(r'\r\n\r\n'));
  final lastHdr = blocks.isNotEmpty ? blocks[blocks.length - 1] : '';
  final lines = lastHdr.split('\r\n');
  final statusLine = lines.isNotEmpty ? lines.removeAt(0) : '';
  final m = RegExp(r'HTTP/[\d.]+ (\d+)').firstMatch(statusLine);
  final status = m != null ? int.parse(m.group(1)!) : 0;
  final headers = <String, String>{};
  for (final line in lines) {
    final i = line.indexOf(':');
    if (i > 0) {
      headers[line.substring(0, i).toLowerCase()] = line
          .substring(i + 1)
          .trim();
    }
  }
  return (
    exit: exit,
    status: status,
    headers: headers,
    body: bodyText,
    stderr: stderr,
  );
}
