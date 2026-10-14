// Node `whatwgUrlHostname` shim goldens generated with Node v22.16.0.
import 'package:sandbox_runtime/src/node/url.dart';
import 'package:test/test.dart';

void main() {
  group('URL', () {
    test('parses WHATWG URL fields', () {
      final url = URL('https://user:pass@example.test:8443/a?q=1#frag');
      expect(url.protocol, 'https:');
      expect(url.username, 'user');
      expect(url.password, 'pass');
      expect(url.hostname, 'example.test');
      expect(url.port, '8443');
      expect(url.pathname, '/a');
      expect(url.search, '?q=1');
      expect(url.hash, '#frag');
      expect(url.origin, 'https://example.test:8443');
      expect(url.searchParams.get('q'), '1');
    });

    test('resolves a relative reference against its base', () {
      expect(
        URL('../b', 'https://example.test/a/c').href,
        'https://example.test/b',
      );
    });
  });

  group('whatwgUrlHostname', () {
    test('normalizes IPv4 inet_aton forms', () {
      expect(whatwgUrlHostname('127.1'), '127.0.0.1');
      expect(whatwgUrlHostname('2130706433'), '127.0.0.1');
      expect(whatwgUrlHostname('0x7f.1'), '127.0.0.1');
      expect(whatwgUrlHostname('0177.0.0.1'), '127.0.0.1');
      expect(whatwgUrlHostname('1.2.3'), '1.2.0.3');
    });

    test('lowercases domains and preserves a trailing dot', () {
      expect(whatwgUrlHostname('EXAMPLE.COM.'), 'example.com.');
      expect(whatwgUrlHostname('example.com:80'), 'example.com');
    });

    test('percent-decodes host bytes before IDNA processing', () {
      expect(whatwgUrlHostname('%65xample.com'), 'example.com');
      expect(whatwgUrlHostname('example%2ecom'), 'example.com');
      expect(whatwgUrlHostname('b%C3%BCcher.example'), 'xn--bcher-kva.example');
      expect(whatwgUrlHostname('a。com'), 'a.com');
    });

    test('encodes supported IDNA labels with Punycode', () {
      expect(whatwgUrlHostname('bücher.example'), 'xn--bcher-kva.example');
      expect(whatwgUrlHostname('faß.de'), 'xn--fa-hia.de');
      expect(
        whatwgUrlHostname('xn--bcher-kva.example'),
        'xn--bcher-kva.example',
      );
      expect(
        whatwgUrlHostname('xn--BCHER-KVA.example'),
        'xn--bcher-kva.example',
      );
    });

    test('compresses IPv6 and omits the URL port from hostname', () {
      expect(whatwgUrlHostname('[2001:0db8::1]:8443'), '[2001:db8::1]');
      expect(whatwgUrlHostname('[::ffff:192.0.2.1]'), '[::ffff:c000:201]');
      expect(whatwgUrlHostname('[0:0:0:0:0:0:0:1]'), '[::1]');
    });

    test('rejects invalid IPv4, IPv6, percent escapes, and ports', () {
      for (final host in [
        '08.0.0.1',
        '1.2.3.256',
        '4294967296',
        'xn--.com',
        'bad host',
        'example%2f.com',
        'example%FF.com',
        'example.com:65536',
        '[fe80::1%25en0]',
        '[2001:db8::1',
      ]) {
        expect(
          () => whatwgUrlHostname(host),
          throwsA(isA<FormatException>()),
          reason: host,
        );
      }
    });

    test(
      'fails closed for IDNA input outside its supported Unicode subset',
      () {
        expect(
          () => whatwgUrlHostname('例.example'),
          throwsA(isA<FormatException>()),
        );
        expect(
          () => whatwgUrlHostname('e\u0301.example'),
          throwsA(isA<FormatException>()),
        );
      },
    );
  });

  group('URL parser matches Node', () {
    test('serializes and exposes fields', () {
      String row(String s) {
        final u = URL(s);
        return [
          u.href,
          u.host,
          u.port,
          u.pathname,
          u.search,
          u.hash,
          u.origin,
        ].join(' | ');
      }

      expect(
        row('http://A.com'),
        'http://a.com/ | a.com |  | / |  |  | http://a.com',
      );
      expect(
        row('https://u:p@[::1]:443/a/../b?x=1 y#f g'),
        'https://u:p@[::1]/b?x=1%20y#f%20g | [::1] |  | /b | ?x=1%20y | #f%20g | https://[::1]',
      );
      expect(
        row('HTTP://x:8080'),
        'http://x:8080/ | x:8080 | 8080 | / |  |  | http://x:8080',
      );
      expect(row('foo:bar baz'), 'foo:bar baz |  |  | bar baz |  |  | null');
      expect(
        row('http://0x7f.1/'),
        'http://127.0.0.1/ | 127.0.0.1 |  | / |  |  | http://127.0.0.1',
      );
      expect(URL('http://a@b@c/').username, 'a%40b');
      expect(URL(r'http://ex.com\p\q').pathname, '/p/q');
      expect(URL("http://a/'q?'").href, "http://a/'q?%27");
      expect(URL('file:///C:/x/../y').href, 'file:///C:/y');
      expect(URL('../x?y', 'http://h/a/b/c').href, 'http://h/a/x?y');
      expect(URL('//o/p', 'https://h/').href, 'https://o/p');
    });

    test('setters', () {
      final u = URL('http://user:pw@h:81/')
        ..username = '***'
        ..password = '***'
        ..port = '80'
        ..pathname = 'a b'
        ..search = 'q=1'
        ..hash = 'z'
        ..protocol = 'https'
        ..hostname = 'NEW';
      expect(u.href, 'https://***:***@new/a%20b?q=1#z');
    });

    test('rejects invalid input', () {
      for (final bad in [
        'nope',
        'http://',
        'http://a:99999',
        'http://[::1',
        'http://a b/',
      ]) {
        expect(URL.canParse(bad), isFalse, reason: bad);
        expect(() => URL(bad), throwsFormatException, reason: bad);
      }
    });

    test('fileURLToPath', () {
      expect(fileURLToPath('file:///a/b%20c', windows: false), '/a/b c');
      expect(
        () => fileURLToPath('file:///a%2fb', windows: false),
        throwsArgumentError,
      );
      expect(
        () => fileURLToPath('file://h/a', windows: false),
        throwsArgumentError,
      );
      expect(
        () => fileURLToPath('http://h/a', windows: false),
        throwsArgumentError,
      );
      expect(fileURLToPath('file:///C:/a/b', windows: true), r'C:\a\b');
      expect(
        fileURLToPath('file://srv/share/x', windows: true),
        r'\\srv\share\x',
      );
      expect(
        () => fileURLToPath('file:///a', windows: true),
        throwsArgumentError,
      );
    });
  });
}
