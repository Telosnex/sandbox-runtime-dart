// Node `whatwgUrlHostname` shim goldens generated with Node v22.16.0.
import 'package:sandbox_runtime/src/node/url.dart';
import 'package:test/test.dart';

void main() {
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
}
