// Ported from sandbox-runtime test/sandbox/proxy-env-vars.test.ts @ 24eb39e.
// ignore_for_file: constant_identifier_names, non_constant_identifier_names, slash_for_doc_comments
import 'dart:async';
import 'dart:convert';

import 'package:sandbox_runtime/src/node/http.dart' as http;
import 'package:sandbox_runtime/src/node/net.dart' as net;
import 'package:sandbox_runtime/src/node/process.dart' as process;
import 'package:sandbox_runtime/src/sandbox/sandbox_config.dart';
import 'package:sandbox_runtime/src/sandbox/sandbox_manager.dart';
import 'package:sandbox_runtime/src/sandbox/sandbox_utils.dart'
    show CA_TRUST_VARS, generateProxyEnvVars;
import 'package:test/test.dart';

import '../helpers/platform.dart' show isLinux, isWindows;
import '../helpers/spawn.dart' show RunOpts, spawnAsync;

void main() {
  group('generateProxyEnvVars', () {
    test('sets CLOUDSDK_PROXY_TYPE to http (gcloud rejects "https")', () {
      // gcloud's proxy/type only accepts http, http_no_tunnel, socks4, socks5.
      // Our local proxy is an HTTP CONNECT proxy regardless of the traffic it
      // tunnels, so the value must be "http" — see issue #151.
      final env = generateProxyEnvVars(3128, 1080);

      expect(env, contains('CLOUDSDK_PROXY_TYPE=http'));
      expect(env, contains('CLOUDSDK_PROXY_ADDRESS=localhost'));
      expect(env, contains('CLOUDSDK_PROXY_PORT=3128'));
      expect(env, isNot(contains('CLOUDSDK_PROXY_TYPE=https')));
    });

    test('omits CLOUDSDK_PROXY_* when no HTTP proxy port is configured', () {
      final env = generateProxyEnvVars(null, 1080);

      expect(env.any((v) => v.startsWith('CLOUDSDK_PROXY_')), false);
    });

    group('GRPC_PROXY', () {
      const grpcNames = ['GRPC_PROXY', 'grpc_proxy'];

      test('advertises the HTTP CONNECT proxy, and never SOCKS alongside it', () {
        // gRPC C-core rejects socks5h:// ("scheme not supported in proxy URI"),
        // ignores the var, and resolves directly via c-ares — which the sandbox
        // blocks. It must get an http:// URL, and must not also get a socks one:
        // two values for the same var in the child env is a coin flip.
        final env = generateProxyEnvVars(3128, 1080);

        for (final name in grpcNames) {
          expect(env, contains('$name=http://localhost:3128'));
          expect(env.where((v) => v.startsWith('$name=')), hasLength(1));
        }
      });

      test('carries proxy credentials in the URL', () {
        final env = generateProxyEnvVars(3128, 1080, null, 'tok');

        for (final name in grpcNames) {
          expect(env, contains('$name=http://srt:tok@localhost:3128'));
        }
      });

      test('is emitted when only an HTTP proxy port is configured', () {
        // The value does not depend on the SOCKS port, and a gRPC client in an
        // HTTP-only sandbox needs it just as much.
        final env = generateProxyEnvVars(3128, null);

        for (final name in grpcNames) {
          expect(env, contains('$name=http://localhost:3128'));
        }
      });

      test('falls back to SOCKS when no HTTP proxy port is configured', () {
        final env = generateProxyEnvVars(null, 1080);

        for (final name in grpcNames) {
          expect(env, contains('$name=socks5h://localhost:1080'));
        }
      });
    });

    group('caCertPath', () {
      test('sets all trust env vars to the CA path when provided', () {
        final env = generateProxyEnvVars(3128, 1080, '/etc/srt/ca.crt');
        for (final v in CA_TRUST_VARS) {
          expect(env, contains('$v=/etc/srt/ca.crt'));
        }
      });

      test('sets trust env vars even when no proxy ports are configured', () {
        // tlsTerminate implies network restriction in practice, but the env-var
        // helper should not couple the two.
        final env = generateProxyEnvVars(null, null, '/etc/srt/ca.crt');
        for (final v in CA_TRUST_VARS) {
          expect(env, contains('$v=/etc/srt/ca.crt'));
        }
      });

      test('omits trust env vars when caCertPath is not provided', () {
        final env = generateProxyEnvVars(3128, 1080);
        for (final v in CA_TRUST_VARS) {
          expect(env.any((e) => e.startsWith('$v=')), false);
        }
      });
    });

    group('NO_PROXY', () {
      test('does not exclude .local hostnames from the proxy', () {
        // Under network restriction the child has no usable resolver, so a
        // NO_PROXY match on *.local makes clients attempt direct getaddrinfo()
        // and fail before any request is sent. .local must go through the
        // proxy so the parent resolves it (e.g. k8s *.svc.cluster.local).
        final env = generateProxyEnvVars(3128, 1080);
        for (final name in ['NO_PROXY', 'no_proxy']) {
          final entry = env.where((e) => e.startsWith('$name=')).firstOrNull;
          expect(entry, isNotNull);
          final tokens = entry!.substring(name.length + 1).split(',');
          expect(tokens, isNot(contains('.local')));
          expect(tokens, isNot(contains('*.local')));
        }
      });

      test(
        'sandboxed curl to a .local hostname reaches the parent proxy',
        () async {
          http.NodeHttpServer? proxy;
          final received = <String>[];
          try {
            proxy = http.createServer((
              http.IncomingMessage req,
              http.ServerResponse res,
            ) {
              received.add(req.url ?? '');
              res.writeHead(200);
              res.end('ok');
            });
            proxy.on('connect', (
              http.IncomingMessage req,
              net.NodeSocket sock,
            ) {
              received.add(req.url ?? '');
              sock.end('HTTP/1.1 200 OK\r\n\r\n');
            });
            final proxyPort = await () {
              final completer = Completer<int>();
              proxy!.on('error', completer.completeError);
              proxy.listen(
                0,
                '127.0.0.1',
                () => completer.complete(
                  (proxy!.address()! as net.NodeAddress).port,
                ),
              );
              return completer.future;
            }();

            final config = SandboxRuntimeConfig(
              network: NetworkConfig(
                allowedDomains: ['srt-test.local'],
                deniedDomains: [],
                httpProxyPort: proxyPort,
              ),
              filesystem: FilesystemConfig(
                denyRead: [],
                allowWrite: [],
                denyWrite: [],
              ),
            );
            await SandboxManager.initialize(config);
            expect(SandboxManager.getProxyPort(), proxyPort);

            final wrapped = await SandboxManager.wrapWithSandbox(
              'curl -s --max-time 5 http://srt-test.local:8080/',
            );
            final result = await spawnAsync(
              wrapped,
              const RunOpts(shell: true, encoding: 'utf8', timeout: 10000),
            );

            expect(result.status, 0);
            // Plain HTTP via proxy → absolute-form request line.
            expect(received, contains('http://srt-test.local:8080/'));
          } finally {
            await SandboxManager.reset();
            if (proxy != null) {
              final closed = Completer<void>();
              proxy.close(() => closed.complete());
              await closed.future;
            }
          }
        },
        skip: isLinux ? null : 'requires Linux',
      );
    });

    group('GIT_SSH_COMMAND', () {
      const MUX_OFF = 'ssh -o ControlMaster=no -o ControlPath=none';
      const NC_SOCKS =
          "$MUX_OFF -o ProxyCommand='nc -X 5 -x localhost:1080 %h %p'";

      /** The ssh variables `generateProxyEnvVars` emits on `os`, by name. */
      Map<String, String> sshVars(String os, [List<Object?> args = const []]) {
        // Dart: spyOn(platform, 'getPlatform') is process.setPlatformForTesting.
        process.setPlatformForTesting(
          const {'macos': 'darwin', 'linux': 'linux', 'windows': 'win32'}[os],
        );
        try {
          return Map<String, String>.fromEntries(
            (Function.apply(generateProxyEnvVars, args) as List<String>)
                .where(
                  (v) => RegExp(
                    r'^(GIT_SSH_COMMAND|SRT_SSH_PROXY_COMMAND)=',
                  ).hasMatch(v),
                )
                .map(
                  (v) => MapEntry(
                    v.substring(0, v.indexOf('=')),
                    v.substring(v.indexOf('=') + 1),
                  ),
                ),
          );
        } finally {
          process.setPlatformForTesting(null);
        }
      }

      test(
        'macOS, one port for both protocols and a token: an authenticated CONNECT, the credential in a variable of its own',
        () {
          for (final (encodedCommand, user) in [
            (null, 'srt'),
            ('Zm9v+/8=', 'srt.Zm9v+/8='),
          ]) {
            final basic = base64.encode(utf8.encode('$user:tok'));
            final vars = sshVars('macos', [
              3128,
              3128,
              null,
              'tok',
              false,
              encodedCommand,
            ]);
            expect(vars, {
              'SRT_SSH_PROXY_COMMAND':
                  r'LC_ALL=C; no() { printf "sandbox proxy: %s\n" "$*" >&2; exit 1; }; '
                      r'case $1 in ""|*[!A-Za-z0-9._:-]*) no bad host;; *:*) set -- "[$1]" "$2";; esac; ' +
                  r'case $2 in ""|*[!0-9]*) no bad port;; esac; '
                      r'exec 3<&0; ' +
                  r'{ printf "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Basic ' +
                  basic +
                  r'\r\n\r\n" "$1:$2" "$1:$2"; exec /bin/cat <&3; } | '
                      r'/usr/bin/nc 127.0.0.1 3128 | ' +
                  r'{ read -r v why; while read -r v; do case $v in ""|?) break;; esac; done; '
                      r'case $why in "200 "*) exec /bin/cat;; esac; ' +
                  r'why=${why%?}; no "$1:$2: ${why:-no answer}"; } & '
                      r'exec >&-; wait $!',
              'GIT_SSH_COMMAND':
                  MUX_OFF +
                  r''' -o ProxyCommand="/bin/sh -c 'eval \"\${SRT_SSH_PROXY_COMMAND:?unset, but GIT_SSH_COMMAND needs it}\"' sh '%h' %p"''',
            });
            // What ends up in arguments names neither the token nor its encoding.
            expect(vars['GIT_SSH_COMMAND'], isNot(contains('tok')));
            expect(vars['GIT_SSH_COMMAND'], isNot(contains(basic)));
          }
        },
      );

      test(
        'macOS without a token, with a SOCKS port of its own, or without an HTTP port: nc over SOCKS, as before',
        () {
          final cases = <List<Object?>>[
            [1080, 1080],
            [3128, 1080],
            [3128, 1080, null, 'tok'],
            [null, 1080, null, 'tok'],
          ];
          for (final args in cases) {
            expect(sshVars('macos', args), {'GIT_SSH_COMMAND': NC_SOCKS});
          }
        },
      );

      // The ports and the token are the manager's own, on any host: what macOS
      // would be given for them follows from those three alone.
      test(
        'macOS: ssh leaves nc over SOCKS only for the listener nc cannot use, the one of the library',
        () async {
          for (final (httpProxyPort, socksProxyPort) in <(int?, int?)>[
            (null, null),
            (null, 41080),
            (43128, null),
            (43128, 41080),
          ]) {
            try {
              await SandboxManager.initialize(
                SandboxRuntimeConfig(
                  network: NetworkConfig(
                    allowedDomains: ['example.com'],
                    deniedDomains: [],
                    httpProxyPort: httpProxyPort,
                    socksProxyPort: socksProxyPort,
                  ),
                  filesystem: FilesystemConfig(
                    denyRead: [],
                    allowWrite: [],
                    denyWrite: [],
                  ),
                ),
              );
              final socks = SandboxManager.getSocksProxyPort()!;
              final vars = sshVars('macos', [
                SandboxManager.getProxyPort(),
                socks,
                null,
                SandboxManager.getProxyAuthToken(),
              ]);
              if (httpProxyPort == null && socksProxyPort == null) {
                expect(
                  vars['SRT_SSH_PROXY_COMMAND'],
                  contains('| /usr/bin/nc 127.0.0.1 $socks |'),
                );
                expect(
                  vars['GIT_SSH_COMMAND'],
                  contains('SRT_SSH_PROXY_COMMAND'),
                );
              } else {
                expect(socks, socksProxyPort ?? socks);
                expect(vars, {
                  'GIT_SSH_COMMAND':
                      "$MUX_OFF -o ProxyCommand='nc -X 5 -x localhost:$socks %h %p'",
                });
              }
            } finally {
              await SandboxManager.reset();
            }
          }
        },
        skip: isWindows ? 'Windows not supported by this port' : null,
      );

      test('Linux: socat, unchanged', () {
        expect(sshVars('linux', [3128, 1080]), {
          'GIT_SSH_COMMAND':
              "$MUX_OFF -o ProxyCommand='socat - PROXY:localhost:%h:%p,proxyport=3128'",
        });
        expect(sshVars('linux', [3128, 1080, null, 'tok', false, 'Zm9v']), {
          'GIT_SSH_COMMAND':
              "$MUX_OFF -o ProxyCommand='socat - PROXY:localhost:%h:%p,proxyport=3128,proxyauth=srt.Zm9v:tok'",
        });
        expect(sshVars('linux', [null, 1080, null, 'tok']), {});
      });

      test('Windows, and no SOCKS port: not set', () {
        expect(sshVars('windows', [3128, 3128, null, 'tok']), {});
        expect(sshVars('macos', [3128, null, null, 'tok']), {});
      });
    });
  });
}
