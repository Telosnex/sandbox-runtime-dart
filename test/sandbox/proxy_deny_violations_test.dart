// Ported from sandbox-runtime test/sandbox/proxy-deny-violations.test.ts @ 24eb39e.
// ignore_for_file: constant_identifier_names, no_leading_underscores_for_local_identifiers
import 'dart:async';
import 'dart:typed_data';

import 'package:sandbox_runtime/src/node/buffer.dart';
import 'package:sandbox_runtime/src/node/events.dart' show once;
import 'package:sandbox_runtime/src/node/http.dart' show NodeHttpServer;
import 'package:sandbox_runtime/src/node/net.dart'
    show NodeAddress, NodeSocket, connect;
import 'package:sandbox_runtime/src/node/stream.dart' show Duplex;
import 'package:sandbox_runtime/src/node/url.dart' show URL;
import 'package:sandbox_runtime/src/sandbox/http_proxy.dart';
import 'package:sandbox_runtime/src/sandbox/request_filter.dart'
    show FilterRequestCallback, RequestDecision;
import 'package:sandbox_runtime/src/sandbox/sandbox_utils.dart';
import 'package:test/test.dart';

typedef _Filter =
    FutureOr<bool> Function(
      int port,
      String host,
      Duplex socket, [
      String? encodedCommand,
      void Function(String reason)? explain,
    ]);

// Dart: `createHttpProxyServer({...})` takes an options object; this carries
// only the fields upstream names here, every other option is absent (null).
class _Options implements HttpProxyServerOptions {
  _Options({
    required _Filter filter,
    this.filterRequest,
    this.onFilterRequestDenied,
    this.proxyAuthToken,
    this.denyHeader,
  }) : _filter = filter;

  final _Filter _filter;
  @override
  final FilterRequestCallback? filterRequest;
  @override
  final void Function(
    ({String method, String url, String reason, String? encodedCommand}),
  )?
  onFilterRequestDenied;
  @override
  final String? proxyAuthToken;
  @override
  final String? denyHeader;
  @override
  FutureOr<bool> filter(
    int port,
    String host,
    Duplex socket, [
    String? encodedCommand,
    void Function(String reason)? explain,
  ]) => _filter(port, host, socket, encodedCommand, explain);
  @override
  dynamic noSuchMethod(Invocation invocation) => null;
}

void main() {
  group('proxyUsernameFor / encodedCommandFromProxyUser', () {
    test('bare "srt" when there is no encodedCommand', () {
      expect(proxyUsernameFor(null), 'srt');
      expect(proxyUsernameFor(''), 'srt');
    });

    test('appends the encodedCommand as a suffix', () {
      expect(proxyUsernameFor('Zm9v'), 'srt.Zm9v');
    });

    test(
      'falls back to bare "srt" when the username would exceed the RFC 1929 255-byte limit',
      () {
        // 100 CJK code units → 300 UTF-8 bytes → 400 base64 chars.
        final enc = encodeSandboxedCommand('漢' * 100);
        expect(Buffer.byteLength('srt.$enc'), greaterThan(255));
        expect(proxyUsernameFor(enc), 'srt');
      },
    );

    test('returns undefined for bare "srt" and unrecognized usernames', () {
      expect(encodedCommandFromProxyUser('srt'), isNull);
      expect(encodedCommandFromProxyUser('srt.'), isNull);
      expect(encodedCommandFromProxyUser('alice'), isNull);
      expect(encodedCommandFromProxyUser(''), isNull);
      expect(encodedCommandFromProxyUser(null), isNull);
    });

    test(
      'round-trips encodeSandboxedCommand for commands containing +/= b64 chars',
      () {
        final cmd = 'curl https://example.com/?q=a+b';
        final enc = encodeSandboxedCommand(cmd);
        expect(enc, matches(RegExp(r'[+/=]')));
        expect(encodedCommandFromProxyUser(proxyUsernameFor(enc)), enc);
      },
    );
  });

  group('generateProxyEnvVars encodedCommand', () {
    const TOKEN = 'tok123';

    test(
      'embeds the percent-encoded encodedCommand in HTTP/SOCKS proxy URLs',
      () {
        final enc = encodeSandboxedCommand('curl https://example.com/');
        final env = generateProxyEnvVars(3128, 1080, null, TOKEN, false, enc);

        final expectedUser = 'srt.${Uri.encodeComponent(enc)}';
        expect(
          env,
          contains('HTTP_PROXY=http://$expectedUser:$TOKEN@localhost:3128'),
        );
        expect(
          env,
          contains('FTP_PROXY=socks5h://$expectedUser:$TOKEN@localhost:1080'),
        );
      },
    );

    test('round-trips through URL userinfo parsing', () {
      // This is the critical encoding gotcha: clients URL-decode the userinfo
      // before building the Basic header / RFC 1929 frame, so the proxy must
      // see the raw base64 — including +/= — and recover the same encodedCommand
      // that getViolationsForCommand() will key on.
      final cmd = 'curl https://example.com/?q=a+b';
      final enc = encodeSandboxedCommand(cmd);
      final env = generateProxyEnvVars(3128, 1080, null, TOKEN, false, enc);

      final httpProxy = env
          .firstWhere((e) => e.startsWith('HTTP_PROXY='))
          .substring('HTTP_PROXY='.length);
      final url = URL(httpProxy);
      // URL.username is still pct-encoded; clients decode before sending Basic.
      final decodedUser = Uri.decodeComponent(url.username);
      expect(encodedCommandFromProxyUser(decodedUser), enc);
    });

    test('still uses bare "srt" when no encodedCommand is supplied', () {
      final env = generateProxyEnvVars(3128, 1080, null, TOKEN);
      expect(env, contains('HTTP_PROXY=http://srt:$TOKEN@localhost:3128'));
    });
  });

  group('HTTP proxy threads encodedCommand from Basic auth to filter()', () {
    NodeHttpServer? proxy;

    tearDown(() {
      proxy?.close();
      proxy = null;
    });

    Future<String> sendConnect(
      int proxyPort,
      String user,
      String token,
      String target,
    ) async {
      final sock = connect(proxyPort, '127.0.0.1');
      await once(sock, 'connect');
      final basic = Buffer.from('$user:$token').toString('base64');
      sock.write(
        'CONNECT $target HTTP/1.1\r\n'
        'Host: $target\r\n'
        'Proxy-Authorization: Basic $basic\r\n\r\n',
      );
      final chunks = <Uint8List>[];
      sock.on('data', (Uint8List d) => chunks.add(d));
      await once(sock, 'close');
      return Buffer.concat(chunks).toString('utf8');
    }

    test(
      'passes the encodedCommand suffix to filter() and 403s on deny',
      () async {
        const TOKEN = 'sekrit';
        final seen = <String?>[];
        proxy = createHttpProxyServer(
          _Options(
            filter: (_port, _host, _socket, [encodedCommand, explain]) {
              seen.add(encodedCommand);
              return false;
            },
            proxyAuthToken: TOKEN,
          ),
        );
        proxy!.listen(0, '127.0.0.1');
        await once(proxy!, 'listening');
        final port = (proxy!.address() as NodeAddress).port;

        final enc = encodeSandboxedCommand('curl https://blocked.test/');
        final resp = await sendConnect(
          port,
          'srt.$enc',
          TOKEN,
          'blocked.test:443',
        );

        expect(resp, contains('HTTP/1.1 403'));
        expect(seen, equals([enc]));
      },
    );

    test(
      'answers a refused CONNECT with the reason filter() gave as the status phrase: cleaned and cut as a violation line is, and ASCII',
      // Dart: explain takes a String, so the `Object` case ("a caller no type binds") throws a TypeError in the filter and the proxy answers 500, not the upstream phrase.
      tags: ['pending'],
      () async {
        final cases = <(Object?, String)>[
          ('use an https:// remote', 'use an https:// remote'),
          (
            'a\r\nX-Injected: 1\r\n\r\nb\x00\x1b[31m\x7f\x9fc',
            'a X-Injected: 1 b [31m c',
          ),
          // What a violation line is cleaned of besides the controls.
          ('a\u2028b\u2029c\u202ed\u200be\u{e0041}f <g>', 'a b c d e f g'),
          ('x' * 501, 'x' * 500),
          // Cut between characters, not inside one.
          ('${'x' * 499}\u{1f600}', 'x' * 499),
          ('caf\u00e9 \u2014 \u{1f600}!', 'caf? ? ?!'),
          // From a caller no type binds.
          (Object, 'function Object() { [native code] }'),
          (null, 'Forbidden'),
        ];
        final reasons = cases.map((c) => c.$1).toList();
        proxy = createHttpProxyServer(
          _Options(
            filter: (_port, _host, _socket, [_encodedCommand, explain]) {
              final reason = reasons.isEmpty ? null : reasons.removeAt(0);
              if (reason != null) (explain as dynamic)?.call(reason);
              return false;
            },
            proxyAuthToken: 'sekrit',
            denyHeader: 'X-Deny',
          ),
        );
        proxy!.listen(0, '127.0.0.1');
        await once(proxy!, 'listening');
        final port = (proxy!.address() as NodeAddress).port;

        for (final (_, phrase) in cases) {
          expect(
            await sendConnect(port, 'srt', 'sekrit', 'blocked.test:22'),
            'HTTP/1.1 403 $phrase\r\n'
            'Content-Type: text/plain\r\n'
            'X-Deny: host_not_allowed\r\n'
            '\r\n'
            'Connection blocked by network allowlist',
          );
        }
      },
    );

    test('still authenticates and passes undefined for bare "srt"', () async {
      const TOKEN = 'sekrit';
      final seen = <String?>[];
      proxy = createHttpProxyServer(
        _Options(
          filter: (_port, _host, _socket, [encodedCommand, explain]) {
            seen.add(encodedCommand);
            return false;
          },
          proxyAuthToken: TOKEN,
        ),
      );
      proxy!.listen(0, '127.0.0.1');
      await once(proxy!, 'listening');
      final port = (proxy!.address() as NodeAddress).port;

      final resp = await sendConnect(port, 'srt', TOKEN, 'blocked.test:443');

      expect(resp, contains('HTTP/1.1 403'));
      expect(seen, equals([null]));
    });

    test('407s on wrong token regardless of username', () async {
      final seen = <Object?>[];
      proxy = createHttpProxyServer(
        _Options(
          filter: (_port, _host, _socket, [ec, explain]) {
            seen.add(ec);
            return true;
          },
          proxyAuthToken: 'right',
        ),
      );
      proxy!.listen(0, '127.0.0.1');
      await once(proxy!, 'listening');
      final port = (proxy!.address() as NodeAddress).port;

      final resp = await sendConnect(port, 'srt.Zm9v', 'wrong', 'x.test:443');

      expect(resp, contains('HTTP/1.1 407'));
      expect(seen, equals([]));
    });

    test(
      'threads encodedCommand to onFilterRequestDenied on plain-HTTP filterRequest deny',
      () async {
        const TOKEN = 'sekrit';
        final denied =
            <
              ({
                String method,
                String url,
                String reason,
                String? encodedCommand,
              })
            >[];
        proxy = createHttpProxyServer(
          _Options(
            filter: (_port, _host, _socket, [encodedCommand, explain]) => true,
            filterRequest: (request, [info]) async =>
                const RequestDecision(action: 'deny', reason: 'policy says no'),
            onFilterRequestDenied: (info) => denied.add(info),
            proxyAuthToken: TOKEN,
          ),
        );
        proxy!.listen(0, '127.0.0.1');
        await once(proxy!, 'listening');
        final port = (proxy!.address() as NodeAddress).port;

        final enc = encodeSandboxedCommand('curl http://blocked.test/x');
        final sock = connect(port, '127.0.0.1');
        await once(sock, 'connect');
        final basic = Buffer.from('srt.$enc:$TOKEN').toString('base64');
        sock.write(
          'GET http://blocked.test/x HTTP/1.1\r\n'
          'Host: blocked.test\r\n'
          'Proxy-Authorization: Basic $basic\r\n'
          'Connection: close\r\n\r\n',
        );
        final chunks = <Uint8List>[];
        sock.on('data', (Uint8List d) => chunks.add(d));
        await once(sock, 'close');
        final resp = Buffer.concat(chunks).toString('utf8');

        expect(resp, contains('HTTP/1.1 403'));
        expect(
          denied,
          equals([
            (
              method: 'GET',
              url: 'http://blocked.test/x',
              reason: 'policy says no',
              encodedCommand: enc,
            ),
          ]),
        );
      },
    );

    test(
      'uses the default policy reason when filterRequest denies without one',
      () async {
        const TOKEN = 'sekrit';
        final reasons = <String>[];
        proxy = createHttpProxyServer(
          _Options(
            filter: (_port, _host, _socket, [encodedCommand, explain]) => true,
            filterRequest: (request, [info]) async =>
                const RequestDecision(action: 'deny'),
            onFilterRequestDenied: (info) => reasons.add(info.reason),
            proxyAuthToken: TOKEN,
          ),
        );
        proxy!.listen(0, '127.0.0.1');
        await once(proxy!, 'listening');
        final port = (proxy!.address() as NodeAddress).port;

        final sock = connect(port, '127.0.0.1');
        await once(sock, 'connect');
        final basic = Buffer.from('srt:$TOKEN').toString('base64');
        sock.write(
          'GET http://blocked.test/y HTTP/1.1\r\n'
          'Host: blocked.test\r\n'
          'Proxy-Authorization: Basic $basic\r\n'
          'Connection: close\r\n\r\n',
        );
        // Consume the response: a socket nobody reads never reaches 'end', so it
        // never emits 'close' (Node, and Bun from 1.4).
        sock.resume();
        await once(sock, 'close');

        expect(reasons, equals(['denied by sandbox policy']));
      },
    );
  });
}
