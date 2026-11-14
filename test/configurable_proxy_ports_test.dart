// Ported from sandbox-runtime test/configurable-proxy-ports.test.ts @ 0bbebed.
// ignore_for_file: constant_identifier_names, non_constant_identifier_names, slash_for_doc_comments
import 'dart:async';

import 'package:sandbox_runtime/src/node/console.dart' as console;
import 'package:sandbox_runtime/src/node/http.dart' as http;
import 'package:sandbox_runtime/src/node/net.dart' as net;
import 'package:sandbox_runtime/src/node/url.dart' show URL;
import 'package:sandbox_runtime/src/sandbox/sandbox_config.dart';
import 'package:sandbox_runtime/src/sandbox/sandbox_manager.dart';
import 'package:test/test.dart';

import 'helpers/platform.dart' show isLinux;
import 'helpers/spawn.dart' show RunOpts, spawnAsync;

/**
 * Integration tests for configurable proxy ports feature
 * Tests that external proxy ports can be specified in config,
 * and that the library skips starting proxies when external ports are provided
 */
void main() {
  group('Configurable Proxy Ports Integration Tests', () {
    tearDownAll(() async {
      // Always reset after tests
      await SandboxManager.reset();
    });

    group('External HTTP proxy + local SOCKS', () {
      test(
        'should use external HTTP proxy when httpProxyPort is provided',
        () async {
          final config = SandboxRuntimeConfig(
            network: NetworkConfig(
              allowedDomains: ['example.com'],
              deniedDomains: [],
              httpProxyPort: 8888, // External HTTP proxy
              // socksProxyPort not specified - should start locally
            ),
            filesystem: FilesystemConfig(
              denyRead: [],
              allowWrite: [],
              denyWrite: [],
            ),
          );

          await SandboxManager.initialize(config);

          // Verify HTTP proxy port matches what was configured
          final httpProxyPort = SandboxManager.getProxyPort();
          expect(httpProxyPort, 8888);

          // SOCKS proxy should have been started locally with dynamic port
          final socksProxyPort = SandboxManager.getSocksProxyPort();
          expect(socksProxyPort, isNotNull);
          expect(socksProxyPort, isNot(8888));
          expect(socksProxyPort, greaterThan(0));

          await SandboxManager.reset();
        },
      );
    });

    group('External SOCKS proxy + local HTTP', () {
      test(
        'should use external SOCKS proxy when socksProxyPort is provided',
        () async {
          final config = SandboxRuntimeConfig(
            network: NetworkConfig(
              allowedDomains: ['example.com'],
              deniedDomains: [],
              // httpProxyPort not specified - should start locally
              socksProxyPort: 1080, // External SOCKS proxy
            ),
            filesystem: FilesystemConfig(
              denyRead: [],
              allowWrite: [],
              denyWrite: [],
            ),
          );

          await SandboxManager.initialize(config);

          // Verify SOCKS proxy port matches what was configured
          final socksProxyPort = SandboxManager.getSocksProxyPort();
          expect(socksProxyPort, 1080);

          // HTTP proxy should have been started locally with dynamic port
          final httpProxyPort = SandboxManager.getProxyPort();
          expect(httpProxyPort, isNotNull);
          expect(httpProxyPort, isNot(1080));
          expect(httpProxyPort, greaterThan(0));

          await SandboxManager.reset();
        },
      );
    });

    group('Both external proxies', () {
      test(
        'should use both external proxies when both ports are provided',
        () async {
          final config = SandboxRuntimeConfig(
            network: NetworkConfig(
              allowedDomains: ['example.com'],
              deniedDomains: [],
              httpProxyPort: 9090, // External HTTP proxy
              socksProxyPort: 9091, // External SOCKS proxy
            ),
            filesystem: FilesystemConfig(
              denyRead: [],
              allowWrite: [],
              denyWrite: [],
            ),
          );

          await SandboxManager.initialize(config);

          // Verify both proxy ports match what was configured
          final httpProxyPort = SandboxManager.getProxyPort();
          expect(httpProxyPort, 9090);

          final socksProxyPort = SandboxManager.getSocksProxyPort();
          expect(socksProxyPort, 9091);

          await SandboxManager.reset();
        },
      );
    });

    group('Both local proxies (baseline)', () {
      test(
        'should start both proxies locally when no ports are configured',
        () async {
          final config = SandboxRuntimeConfig(
            network: NetworkConfig(
              allowedDomains: ['example.com'],
              deniedDomains: [],
              // No httpProxyPort or socksProxyPort - both should start locally
            ),
            filesystem: FilesystemConfig(
              denyRead: [],
              allowWrite: [],
              denyWrite: [],
            ),
          );

          await SandboxManager.initialize(config);

          // Both proxies should have been started locally with dynamic ports
          final httpProxyPort = SandboxManager.getProxyPort();
          expect(httpProxyPort, isNotNull);
          expect(httpProxyPort, greaterThan(0));
          expect(httpProxyPort, lessThan(65536));

          final socksProxyPort = SandboxManager.getSocksProxyPort();
          expect(socksProxyPort, isNotNull);
          expect(socksProxyPort, greaterThan(0));
          expect(socksProxyPort, lessThan(65536));

          // Both protocols are now served by the mux on a single port.
          expect(httpProxyPort, socksProxyPort);

          await SandboxManager.reset();
        },
      );
    });

    group('Multiple initialize/reset cycles', () {
      test(
        'should handle multiple initialize and reset cycles with different configs',
        () async {
          // First: both local
          final config1 = SandboxRuntimeConfig(
            network: NetworkConfig(
              allowedDomains: ['example.com'],
              deniedDomains: [],
            ),
            filesystem: FilesystemConfig(
              denyRead: [],
              allowWrite: [],
              denyWrite: [],
            ),
          );

          await SandboxManager.initialize(config1);
          final httpPort1 = SandboxManager.getProxyPort();
          final socksPort1 = SandboxManager.getSocksProxyPort();
          expect(httpPort1, isNotNull);
          expect(socksPort1, isNotNull);
          await SandboxManager.reset();

          // Second: both external
          final config2 = SandboxRuntimeConfig(
            network: NetworkConfig(
              allowedDomains: ['example.com'],
              deniedDomains: [],
              httpProxyPort: 7777,
              socksProxyPort: 7778,
            ),
            filesystem: FilesystemConfig(
              denyRead: [],
              allowWrite: [],
              denyWrite: [],
            ),
          );

          await SandboxManager.initialize(config2);
          expect(SandboxManager.getProxyPort(), 7777);
          expect(SandboxManager.getSocksProxyPort(), 7778);
          await SandboxManager.reset();

          // Third: mixed (external HTTP, local SOCKS)
          final config3 = SandboxRuntimeConfig(
            network: NetworkConfig(
              allowedDomains: ['example.com'],
              deniedDomains: [],
              httpProxyPort: 6666,
            ),
            filesystem: FilesystemConfig(
              denyRead: [],
              allowWrite: [],
              denyWrite: [],
            ),
          );

          await SandboxManager.initialize(config3);
          expect(SandboxManager.getProxyPort(), 6666);
          final socksPort3 = SandboxManager.getSocksProxyPort();
          expect(socksPort3, isNotNull);
          expect(socksPort3, isNot(6666));
          await SandboxManager.reset();
        },
      );
    });

    group('Port validation', () {
      test('should accept valid port numbers (1-65535)', () async {
        final config = SandboxRuntimeConfig(
          network: NetworkConfig(
            allowedDomains: ['example.com'],
            deniedDomains: [],
            httpProxyPort: 1,
            socksProxyPort: 65535,
          ),
          filesystem: FilesystemConfig(
            denyRead: [],
            allowWrite: [],
            denyWrite: [],
          ),
        );

        await SandboxManager.initialize(config);
        expect(SandboxManager.getProxyPort(), 1);
        expect(SandboxManager.getSocksProxyPort(), 65535);
        await SandboxManager.reset();
      });

      test('should accept standard proxy ports', () async {
        final config = SandboxRuntimeConfig(
          network: NetworkConfig(
            allowedDomains: ['example.com'],
            deniedDomains: [],
            httpProxyPort: 3128, // Standard HTTP proxy port
            socksProxyPort: 1080, // Standard SOCKS proxy port
          ),
          filesystem: FilesystemConfig(
            denyRead: [],
            allowWrite: [],
            denyWrite: [],
          ),
        );

        await SandboxManager.initialize(config);
        expect(SandboxManager.getProxyPort(), 3128);
        expect(SandboxManager.getSocksProxyPort(), 1080);
        await SandboxManager.reset();
      });
    });

    group('Idempotent initialization', () {
      test(
        'should handle calling initialize multiple times without reset',
        () async {
          final config = SandboxRuntimeConfig(
            network: NetworkConfig(
              allowedDomains: ['example.com'],
              deniedDomains: [],
              httpProxyPort: 5555,
              socksProxyPort: 5556,
            ),
            filesystem: FilesystemConfig(
              denyRead: [],
              allowWrite: [],
              denyWrite: [],
            ),
          );

          // Initialize once
          await SandboxManager.initialize(config);
          final httpPort1 = SandboxManager.getProxyPort();
          final socksPort1 = SandboxManager.getSocksProxyPort();

          // Initialize again without reset (should be idempotent)
          await SandboxManager.initialize(config);
          final httpPort2 = SandboxManager.getProxyPort();
          final socksPort2 = SandboxManager.getSocksProxyPort();

          // Should return the same ports
          expect(httpPort2, httpPort1);
          expect(socksPort2, socksPort1);
          expect(httpPort2, 5555);
          expect(socksPort2, 5556);

          await SandboxManager.reset();
        },
      );
    });

    group('End-to-end: External proxy actually handles requests', () {
      test(
        'should route requests through external allow-all proxy, bypassing SRT filtering',
        skip: isLinux ? null : 'Linux only',
        () async {
          // Create a simple HTTP CONNECT proxy that allows ALL connections (no filtering)
          http.NodeHttpServer? externalProxyServer;
          int? externalProxyPort;

          try {
            externalProxyServer = http.createServer();

            // Handle HTTP CONNECT method for HTTPS tunneling
            externalProxyServer.on('connect', (
              http.IncomingMessage req,
              net.NodeSocket clientSocket,
              List<int> head,
            ) {
              final url = URL('http://${req.url}');
              final port = url.port;
              final hostname = url.hostname;

              // Connect to target (allow everything - no filtering)
              late final net.NodeSocket serverSocket;
              serverSocket = net.connect(
                {'port': int.tryParse(port) ?? 80, 'host': hostname},
                () {
                  clientSocket.write(
                    'HTTP/1.1 200 Connection Established\r\n\r\n',
                  );
                  serverSocket.write(head);
                  serverSocket.pipe(clientSocket);
                  clientSocket.pipe(serverSocket);
                },
              );

              serverSocket.on('error', (_) {
                clientSocket.end();
              });

              clientSocket.on('error', (_) {
                serverSocket.end();
              });
            });

            // Handle regular HTTP requests
            externalProxyServer.on('request', (
              http.IncomingMessage req,
              http.ServerResponse res,
            ) {
              final url = URL(req.url!);
              final options = {
                'hostname': url.hostname,
                'port': url.port == '' ? 80 : url.port,
                'path': url.pathname + url.search,
                'method': req.method,
                'headers': req.headers,
              };

              final proxyReq = http.request(options, (
                http.IncomingMessage proxyRes,
              ) {
                res.writeHead(proxyRes.statusCode!, proxyRes.headers);
                proxyRes.pipe(res);
              });

              proxyReq.on('error', (_) {
                res.writeHead(502);
                res.end('Bad Gateway');
              });

              req.pipe(proxyReq);
            });

            // Start the external proxy on a random port
            await () {
              final completer = Completer<void>();
              externalProxyServer!.listen(0, '127.0.0.1', () {
                final addr = externalProxyServer!.address();
                if (addr != null && addr is net.NodeAddress) {
                  externalProxyPort = addr.port;
                  console.log(
                    'External allow-all proxy started on port $externalProxyPort',
                  );
                  completer.complete();
                } else {
                  completer.completeError(
                    Exception('Failed to get proxy address'),
                  );
                }
              });
              externalProxyServer.on('error', (Object e) {
                if (!completer.isCompleted) completer.completeError(e);
              });
              return completer.future;
            }();

            // Initialize SandboxManager with restrictive config but external proxy
            final config = SandboxRuntimeConfig(
              network: NetworkConfig(
                allowedDomains: ['example.com'], // Only allow example.com
                deniedDomains: [],
                httpProxyPort:
                    externalProxyPort, // Use our allow-all external proxy
              ),
              filesystem: FilesystemConfig(
                denyRead: [],
                allowWrite: [],
                denyWrite: [],
              ),
            );

            await SandboxManager.initialize(config);

            // Verify the external proxy port is being used
            expect(SandboxManager.getProxyPort(), externalProxyPort);

            // Try to access example.com (in allowlist)
            // This verifies that requests are routed through the external proxy
            final command = await SandboxManager.wrapWithSandbox(
              'curl -s --max-time 5 http://example.com',
            );

            final result = await spawnAsync(
              command,
              const RunOpts(shell: true, encoding: 'utf8', timeout: 10000),
            );

            // The request should succeed
            expect(result.status, 0);

            // Should NOT contain SRT's block message
            final output =
                (result.stderr.isNotEmpty ? result.stderr : result.stdout)
                    .toLowerCase();
            expect(output, isNot(contains('blocked by network allowlist')));

            console.log(
              '✓ Request to example.com succeeded through external proxy',
            );
            console.log(
              '✓ This verifies SRT used the external proxy on the configured port',
            );
          } finally {
            // Clean up
            await SandboxManager.reset();

            if (externalProxyServer != null) {
              await () {
                final completer = Completer<void>();
                externalProxyServer!.close(() {
                  console.log('External proxy server closed');
                  completer.complete();
                });
                return completer.future;
              }();
            }
          }
        },
      );
    });
  });
}
