// Ported from sandbox-runtime test/sandbox/parent-proxy.test.ts @ 24eb39e.

import 'package:test/test.dart';

import 'package:sandbox_runtime/src/node/net.dart' show connect;
import 'package:sandbox_runtime/src/node/process.dart' as process;
import 'package:sandbox_runtime/src/node/url.dart' show URL;
import 'package:sandbox_runtime/src/sandbox/parent_proxy.dart';
import 'package:sandbox_runtime/src/sandbox/sandbox_config.dart'
    show ParentProxyConfig;

void main() {
  group('parent-proxy: resolveParentProxy', () {
    final saved = <String, String?>{};
    final vars = [
      'HTTP_PROXY',
      'http_proxy',
      'HTTPS_PROXY',
      'https_proxy',
      'NO_PROXY',
      'no_proxy',
    ];

    setUp(() {
      for (final v in vars) {
        saved[v] = process.env[v];
        process.env.remove(v);
      }
    });
    tearDown(() {
      for (final v in vars) {
        if (saved[v] == null) {
          process.env.remove(v);
        } else {
          process.env[v] = saved[v]!;
        }
      }
    });

    test('returns undefined when nothing is set', () {
      expect(resolveParentProxy(null), isNull);
    });

    test('explicit config takes precedence over env', () {
      process.env['HTTP_PROXY'] = 'http://env-proxy:8080';
      final r = resolveParentProxy(
        const ParentProxyConfig(http: 'http://cfg-proxy:3128'),
      );
      expect(r?.httpUrl?.href, 'http://cfg-proxy:3128/');
    });

    test('falls back to HTTP_PROXY env', () {
      process.env['HTTP_PROXY'] = 'http://env-proxy:8080';
      final r = resolveParentProxy(null);
      expect(r?.httpUrl?.hostname, 'env-proxy');
      // HTTPS falls back to HTTP when HTTPS_PROXY unset
      expect(r?.httpsUrl?.hostname, 'env-proxy');
    });

    test('lowercase env vars are honoured', () {
      process.env['http_proxy'] = 'http://lower:8080';
      final r = resolveParentProxy(null);
      expect(r?.httpUrl?.hostname, 'lower');
    });

    test('HTTPS_PROXY distinct from HTTP_PROXY', () {
      process.env['HTTP_PROXY'] = 'http://plain:8080';
      process.env['HTTPS_PROXY'] = 'http://secure:8443';
      final r = resolveParentProxy(null);
      expect(r?.httpUrl?.hostname, 'plain');
      expect(r?.httpsUrl?.hostname, 'secure');
    });
  });

  group('parent-proxy: NO_PROXY matching', () {
    ResolvedParentProxy mk(String noProxy) => resolveParentProxy(
      ParentProxyConfig(http: 'http://p:1', noProxy: noProxy),
    )!;

    test('exact hostname match', () {
      final r = mk('example.com');
      expect(shouldBypassParentProxy(r, 'example.com'), true);
      expect(shouldBypassParentProxy(r, 'other.com'), false);
    });

    test('bare hostname also matches subdomains (golang semantics)', () {
      final r = mk('example.com');
      expect(shouldBypassParentProxy(r, 'api.example.com'), true);
    });

    test('leading-dot suffix match', () {
      final r = mk('.example.com');
      expect(shouldBypassParentProxy(r, 'api.example.com'), true);
      expect(shouldBypassParentProxy(r, 'example.com'), true);
      expect(shouldBypassParentProxy(r, 'notexample.com'), false);
    });

    test('wildcard *. prefix is normalised to leading-dot', () {
      final r = mk('*.local');
      expect(shouldBypassParentProxy(r, 'foo.local'), true);
    });

    test('wildcard * matches everything', () {
      final r = mk('*');
      expect(shouldBypassParentProxy(r, 'anything.com'), true);
    });

    test('CIDR v4 match', () {
      final r = mk('10.0.0.0/8,192.168.0.0/16');
      expect(shouldBypassParentProxy(r, '10.1.2.3'), true);
      expect(shouldBypassParentProxy(r, '192.168.99.1'), true);
      expect(shouldBypassParentProxy(r, '172.16.0.1'), false);
      expect(shouldBypassParentProxy(r, '11.0.0.1'), false);
    });

    test('CIDR v4 /32 exact', () {
      final r = mk('1.2.3.4/32');
      expect(shouldBypassParentProxy(r, '1.2.3.4'), true);
      expect(shouldBypassParentProxy(r, '1.2.3.5'), false);
    });

    test('CIDR v6 match', () {
      final r = mk('fe80::/10');
      expect(shouldBypassParentProxy(r, 'fe80::1'), true);
      expect(shouldBypassParentProxy(r, '2001:db8::1'), false);
    });

    test('link-local CIDR', () {
      final r = mk('169.254.0.0/16');
      expect(shouldBypassParentProxy(r, '169.254.169.254'), true);
    });

    test('localhost always bypasses regardless of NO_PROXY', () {
      final r = mk('');
      expect(shouldBypassParentProxy(r, 'localhost'), true);
      expect(shouldBypassParentProxy(r, '127.0.0.1'), true);
      expect(shouldBypassParentProxy(r, '::1'), true);
    });

    test('full 127/8 and v4-mapped loopback bypass', () {
      final r = mk('');
      expect(shouldBypassParentProxy(r, '127.0.0.2'), true);
      expect(shouldBypassParentProxy(r, '127.255.255.254'), true);
      expect(shouldBypassParentProxy(r, '::ffff:127.0.0.1'), true);
    });

    test('bracketed IPv6 host is handled', () {
      final r = mk('');
      expect(shouldBypassParentProxy(r, '[::1]'), true);
    });

    test('case-insensitive hostname matching', () {
      final r = mk('Example.COM');
      expect(shouldBypassParentProxy(r, 'EXAMPLE.com'), true);
    });

    test('port suffix in NO_PROXY entry is stripped', () {
      final r = mk('example.com:8080');
      expect(shouldBypassParentProxy(r, 'example.com'), true);
    });

    test('IPv6 literal in NO_PROXY is not mangled by port-stripping', () {
      final r = mk('fe80::1');
      expect(shouldBypassParentProxy(r, 'fe80::1'), true);
    });

    test('a zoned IPv6 entry is its unzoned range and never throws', () {
      final r = mk('fe80::1%eth0,fe80::%eth1/10,10.0.0.0/8');
      expect(shouldBypassParentProxy(r, 'fe80::1'), true);
      expect(shouldBypassParentProxy(r, 'fe80::2'), true);
      expect(shouldBypassParentProxy(r, '10.1.1.1'), true);
      expect(shouldBypassParentProxy(r, '8.8.8.8'), false);
    });

    test(
      'an IPv4-mapped entry matches exactly its IPv4 address, not every IPv4 host',
      () {
        final r = mk('::ffff:10.0.0.1,::ffff:192.168.0.0/112');
        expect(shouldBypassParentProxy(r, '10.0.0.1'), true);
        expect(shouldBypassParentProxy(r, '192.168.4.4'), true);
        expect(shouldBypassParentProxy(r, '10.0.0.2'), false);
        expect(shouldBypassParentProxy(r, '8.8.8.8'), false);
      },
    );

    test('empty CIDR suffix does not become match-all', () {
      final r = mk('10.0.0.0/');
      // Malformed — should be ignored, not treated as /0
      expect(shouldBypassParentProxy(r, '8.8.8.8'), false);
    });

    test('malformed CIDR is ignored', () {
      final r = mk('10.0.0.0/999,not-an-ip/24');
      expect(shouldBypassParentProxy(r, '10.0.0.1'), false);
    });

    test('comma-separated list with whitespace', () {
      final r = mk(' foo.com , bar.com ,  10.0.0.0/8 ');
      expect(shouldBypassParentProxy(r, 'foo.com'), true);
      expect(shouldBypassParentProxy(r, 'bar.com'), true);
      expect(shouldBypassParentProxy(r, '10.1.1.1'), true);
      expect(shouldBypassParentProxy(r, 'baz.com'), false);
    });
  });

  group('parent-proxy: selectParentProxyUrl', () {
    test('picks https proxy for https, http for http', () {
      final r = resolveParentProxy(
        const ParentProxyConfig(
          http: 'http://plain:1',
          https: 'http://secure:2',
        ),
      )!;
      expect(selectParentProxyUrl(r, isHttps: true)?.hostname, 'secure');
      expect(selectParentProxyUrl(r, isHttps: false)?.hostname, 'plain');
    });

    test('falls back when only one is set', () {
      final r = resolveParentProxy(
        const ParentProxyConfig(http: 'http://only:1'),
      )!;
      expect(selectParentProxyUrl(r, isHttps: true)?.hostname, 'only');
    });
  });

  group('parent-proxy: openConnectTunnel validation', () {
    Future<String> rejectMsg(Future<Object?> p) => p.then(
      (_) => 'resolved',
      onError: (Object e) =>
          e is Error ? e.toString() : (e as dynamic).message as String,
    );

    test('rejects CRLF in destHost', () async {
      final msg = await rejectMsg(
        openConnectTunnel(
          ConnectTunnelOptions(
            dial: () => connect(1, '127.0.0.1'),
            readyEvent: 'connect',
            destHost: 'evil\r\nX-Injected: yes',
            destPort: 443,
          ),
        ),
      );
      expect(msg, matches(RegExp(r'Invalid destination host')));
    });

    test('rejects request-smuggling payload in destHost', () async {
      final msg = await rejectMsg(
        openConnectTunnel(
          ConnectTunnelOptions(
            dial: () => connect(1, '127.0.0.1'),
            readyEvent: 'connect',
            destHost:
                'a\r\n\r\nCONNECT internal:8080 HTTP/1.1\r\nX: .allowed.com',
            destPort: 443,
          ),
        ),
      );
      expect(msg, matches(RegExp(r'Invalid destination host')));
    });

    test('rejects invalid port', () async {
      final msg = await rejectMsg(
        openConnectTunnel(
          ConnectTunnelOptions(
            dial: () => connect(1, '127.0.0.1'),
            readyEvent: 'connect',
            destHost: 'example.com',
            destPort: 99999,
          ),
        ),
      );
      expect(msg, matches(RegExp(r'Invalid destination port')));
    });

    test('accepts plain hostname (fails on dial, not validation)', () async {
      final msg = await rejectMsg(
        openConnectTunnel(
          ConnectTunnelOptions(
            dial: () => connect(1, '127.0.0.1'),
            readyEvent: 'connect',
            destHost: 'registry.npmjs.org',
            destPort: 443,
            timeoutMs: 500,
          ),
        ),
      );
      expect(msg, isNot(matches(RegExp(r'Invalid destination'))));
    });

    test('accepts IPv6 literal (fails on dial, not validation)', () async {
      final msg = await rejectMsg(
        openConnectTunnel(
          ConnectTunnelOptions(
            dial: () => connect(1, '127.0.0.1'),
            readyEvent: 'connect',
            destHost: 'fe80::1',
            destPort: 443,
            timeoutMs: 500,
          ),
        ),
      );
      expect(msg, isNot(matches(RegExp(r'Invalid destination'))));
    });
  });

  group('parent-proxy: utilities', () {
    test('stripBrackets removes IPv6 brackets', () {
      expect(stripBrackets('[::1]'), '::1');
      expect(stripBrackets('[fe80::1]'), 'fe80::1');
      expect(stripBrackets('example.com'), 'example.com');
      expect(stripBrackets('127.0.0.1'), '127.0.0.1');
    });

    test('redactUrl hides userinfo', () {
      expect(
        redactUrl(URL('http://user:secret@proxy:3128')),
        'http://***:***@proxy:3128/',
      );
      expect(redactUrl(URL('http://proxy:3128')), 'http://proxy:3128/');
      expect(redactUrl(null), '-');
    });

    test('stripHopByHop removes proxy and connection headers', () {
      final out = stripHopByHop({
        'host': 'example.com',
        'proxy-authorization': 'Basic secret',
        'proxy-connection': 'keep-alive',
        'connection': 'close',
        'transfer-encoding': 'chunked',
        'x-custom': 'keep-me',
      });
      expect(out, {'host': 'example.com', 'x-custom': 'keep-me'});
    });

    test('stripHopByHop strips headers named in Connection', () {
      final out = stripHopByHop({
        'host': 'example.com',
        'connection': 'x-foo, x-bar',
        'x-foo': 'drop',
        'x-bar': 'drop',
        'x-keep': 'keep',
      });
      expect(out, {'host': 'example.com', 'x-keep': 'keep'});
    });

    test('stripHopByHop preserves content-length (end-to-end header)', () {
      final out = stripHopByHop({
        'content-length': '42',
        'transfer-encoding': 'chunked',
        'x-keep': 'keep',
      });
      expect(out, {'content-length': '42', 'x-keep': 'keep'});
    });

    test('isValidHost rejects null bytes (DNS-truncation bypass)', () {
      expect(isValidHost('evil.com\x00.allowed.com'), false);
    });

    test('isValidHost rejects CRLF', () {
      expect(isValidHost('a\r\nInjected: x'), false);
      expect(isValidHost('a\nInjected: x'), false);
    });

    test('isValidHost rejects IPv6 zone-ID allowlist bypass', () {
      // This payload passes net.isIP() === 6, passes .endsWith('.github.com'),
      // and connects to 127.0.0.1 when the OS discards the bogus scope.
      expect(isValidHost('::ffff:127.0.0.1%x.github.com'), false);
      expect(isValidHost('fe80::1%eth0'), false);
      expect(isValidHost('[fe80::1%eth0]'), false);
    });

    test('isValidHost accepts underscore (real-world DNS records)', () {
      expect(isValidHost('_dmarc.example.com'), true);
      expect(isValidHost('_acme-challenge.example.com'), true);
    });

    test('isValidHost accepts DNS names and IPs', () {
      expect(isValidHost('registry.npmjs.org'), true);
      expect(isValidHost('sub-domain.example.co.uk'), true);
      expect(isValidHost('192.168.1.1'), true);
      expect(isValidHost('::1'), true);
      expect(isValidHost('[::1]'), true);
      expect(isValidHost('fe80::1'), true);
    });

    test('isValidHost rejects empty and overlong', () {
      expect(isValidHost(''), false);
      expect(isValidHost('a' * 256), false);
    });
  });

  group('parent-proxy: resolveParentProxy URL normalisation', () {
    test('accepts schemeless host:port like curl', () {
      final r = resolveParentProxy(
        const ParentProxyConfig(http: 'proxy.corp:3128'),
      );
      expect(r?.httpUrl?.hostname, 'proxy.corp');
      expect(r?.httpUrl?.port, '3128');
    });

    test('rejects non-http(s) schemes', () {
      final r = resolveParentProxy(
        const ParentProxyConfig(http: 'socks5://proxy:1080'),
      );
      expect(r?.httpUrl, isNull);
    });
  });

  group('parent-proxy: selectParentProxyUrl curl semantics', () {
    test('plain HTTP returns undefined when only HTTPS_PROXY set', () {
      final r = resolveParentProxy(
        const ParentProxyConfig(https: 'http://secure:1'),
      )!;
      expect(selectParentProxyUrl(r, isHttps: false), isNull);
      expect(selectParentProxyUrl(r, isHttps: true)?.hostname, 'secure');
    });
  });

  group('parent-proxy: canonicalizeHost', () {
    test('normalizes inet_aton shorthand (denylist evasion guard)', () {
      expect(canonicalizeHost('127.1'), '127.0.0.1');
      expect(canonicalizeHost('2130706433'), '127.0.0.1');
      expect(canonicalizeHost('0x7f.0.0.1'), '127.0.0.1');
      // AWS metadata as decimal
      expect(canonicalizeHost('2852039166'), '169.254.169.254');
    });

    test('normalizes IPv6 forms', () {
      expect(canonicalizeHost('0:0:0:0:0:0:0:1'), '::1');
      expect(canonicalizeHost('[::1]'), '::1');
    });

    test(
      'spells an IPv4-mapped IPv6 literal as the IPv4 address it connects to',
      () {
        expect(canonicalizeHost('::ffff:127.0.0.1'), '127.0.0.1');
        expect(canonicalizeHost('[::FFFF:A9FE:A9FE]'), '169.254.169.254');
        expect(canonicalizeHost('0:0:0:0:0:ffff:7f00:1'), '127.0.0.1');
        // Other IPv4-embedding forms are different destinations; left as IPv6.
        expect(canonicalizeHost('::ffff:0:7f00:1'), '::ffff:0:7f00:1');
        expect(canonicalizeHost('64:ff9b::7f00:1'), '64:ff9b::7f00:1');
      },
    );

    test('strips trailing dot and lowercases', () {
      expect(canonicalizeHost('Example.COM.'), 'example.com');
    });

    test('passes through ordinary hostnames', () {
      expect(canonicalizeHost('registry.npmjs.org'), 'registry.npmjs.org');
    });

    test('returns undefined for garbage', () {
      expect(canonicalizeHost('not a host'), isNull);
    });
  });
}
