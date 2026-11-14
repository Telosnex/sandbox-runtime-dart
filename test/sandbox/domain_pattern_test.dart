// Ported from sandbox-runtime test/sandbox/domain-pattern.test.ts @ 0bbebed.
import 'package:sandbox_runtime/src/sandbox/domain_pattern.dart';
import 'package:test/test.dart';

void main() {
  group('matchesDomainPattern', () {
    test('exact match is case-insensitive', () {
      expect(
        matchesDomainPattern('API.Example.com', 'api.example.com'),
        isTrue,
      );
    });

    test('wildcard matches strict subdomains only', () {
      expect(matchesDomainPattern('a.example.com', '*.example.com'), isTrue);
      expect(matchesDomainPattern('a.b.example.com', '*.example.com'), isTrue);
      expect(matchesDomainPattern('example.com', '*.example.com'), isFalse);
      expect(matchesDomainPattern('notexample.com', '*.example.com'), isFalse);
    });
  });

  // Generic "is this pattern fully covered by that pattern list" predicate.
  // Used for injectHosts ⊆ allowedDomains and, since tlsTerminate
  // excludeDomains, for "could this injectHost ever be injected".
  group('isInjectHostCoveredByAllowedDomains', () {
    test('exact host covered by an exact entry or a wildcard', () {
      expect(
        isInjectHostCoveredByAllowedDomains('api.example.com', [
          'api.example.com',
        ]),
        isTrue,
      );
      expect(
        isInjectHostCoveredByAllowedDomains('api.example.com', [
          '*.example.com',
        ]),
        isTrue,
      );
      expect(
        isInjectHostCoveredByAllowedDomains('api.example.com', ['example.com']),
        isFalse,
      );
    });

    test('a wildcard is never covered by exact entries', () {
      expect(
        isInjectHostCoveredByAllowedDomains('*.example.com', [
          'api.example.com',
          'b.example.com',
        ]),
        isFalse,
      );
    });

    test('a wildcard is covered by an equal or ancestor wildcard only', () {
      expect(
        isInjectHostCoveredByAllowedDomains('*.api.example.com', [
          '*.example.com',
        ]),
        isTrue,
      );
      expect(
        isInjectHostCoveredByAllowedDomains('*.example.com', [
          '*.api.example.com',
        ]),
        isFalse,
      );
    });

    test('ignores :port suffixes on allowedDomains entries', () {
      expect(
        isInjectHostCoveredByAllowedDomains('api.example.com', [
          'api.example.com:443',
        ]),
        isTrue,
      );
      expect(
        isInjectHostCoveredByAllowedDomains('*.api.example.com', [
          '*.example.com:8443',
        ]),
        isTrue,
      );
    });
  });

  group('splitDomainPatternPort', () {
    test('splits a numeric port suffix', () {
      expect(splitDomainPatternPort('example.com:443'), (
        hostPattern: 'example.com',
        port: 443,
      ));
      expect(splitDomainPatternPort('*.example.com:8080'), (
        hostPattern: '*.example.com',
        port: 8080,
      ));
      expect(splitDomainPatternPort('*:22'), (hostPattern: '*', port: 22));
    });

    test('no suffix, or a non-port suffix, is left whole', () {
      expect(splitDomainPatternPort('example.com'), (
        hostPattern: 'example.com',
        port: null,
      ));
      for (final s in [
        'example.com:0',
        'example.com:65536',
        'example.com:99999999',
        'example.com:0443',
        'example.com:abc',
        'example.com:443.allowed.com',
        'example.com:',
      ]) {
        expect(splitDomainPatternPort(s), (hostPattern: s, port: null));
      }
    });
  });

  group('splitDomainPatternPort — IPv6 literals', () {
    test(
      'bracketed literal, with and without port; host is bare + canonical',
      () {
        expect(splitDomainPatternPort('[::1]'), (
          hostPattern: '::1',
          port: null,
        ));
        expect(splitDomainPatternPort('[::1]:443'), (
          hostPattern: '::1',
          port: 443,
        ));
        // Canonical compression so it compares equal to canonicalizeHost(dest).
        expect(splitDomainPatternPort('[2001:0db8:0000::0001]:8443'), (
          hostPattern: '2001:db8::1',
          port: 8443,
        ));
        expect(splitDomainPatternPort('[fd00:ec2::254]'), (
          hostPattern: 'fd00:ec2::254',
          port: null,
        ));
        // A zone id is meaningless for matching (a request can never carry one)
        // and is dropped, so the entry matches the address on any interface.
        expect(splitDomainPatternPort('[fe80::1%en0]:22'), (
          hostPattern: 'fe80::1',
          port: 22,
        ));
        expect(splitDomainPatternPort('fe80::1%en0'), (
          hostPattern: 'fe80::1',
          port: null,
        ));
      },
    );

    test(
      'unbracketed multi-colon is never split (no hextet mistaken for a port)',
      () {
        // The pre-fix behaviour parsed this as host "fd00:ec2:" + port 254.
        expect(splitDomainPatternPort('fd00:ec2::254'), (
          hostPattern: 'fd00:ec2::254',
          port: null,
        ));
        expect(splitDomainPatternPort('::1'), (hostPattern: '::1', port: null));
        // Not an address at all: left whole for validation to reject.
        expect(splitDomainPatternPort('example.com:80:443'), (
          hostPattern: 'example.com:80:443',
          port: null,
        ));
      },
    );

    test('malformed bracket forms are left whole', () {
      for (final s in [
        '[::1',
        '[::1]junk',
        '[::1]:',
        '[::1]:0',
        '[::1]:65536',
      ]) {
        expect(splitDomainPatternPort(s), (hostPattern: s, port: null));
      }
    });
  });

  group('matchesDomainPatternWithPort — IPv6 literals', () {
    // filterNetworkRequest matches against canonicalizeHost(dest): bare,
    // lowercase, compressed. These are the strings the matcher really sees.
    test('bracketed deny entry matches the canonical destination', () {
      expect(matchesDomainPatternWithPort('::1', 443, '[::1]:443'), isTrue);
      expect(matchesDomainPatternWithPort('::1', 80, '[::1]:443'), isFalse);
      expect(matchesDomainPatternWithPort('::1', 80, '[::1]'), isTrue);
      expect(
        matchesDomainPatternWithPort('fd00:ec2::254', 80, '[fd00:ec2::254]'),
        isTrue,
      );
      expect(
        matchesDomainPatternWithPort(
          '2001:db8::1',
          8443,
          '[2001:DB8:0:0::1]:8443',
        ),
        isTrue,
      );
    });

    test(
      'unbracketed entry still matches its own canonical form on every port (fails closed for deny lists)',
      () {
        expect(
          matchesDomainPatternWithPort('fd00:ec2::254', 254, 'fd00:ec2::254'),
          isTrue,
        );
        expect(
          matchesDomainPatternWithPort('fd00:ec2::254', 80, 'fd00:ec2::254'),
          isTrue,
        );
      },
    );
  });

  group('matchesDomainPatternWithPort', () {
    test('entry without port matches any port', () {
      expect(
        matchesDomainPatternWithPort('example.com', 22, 'example.com'),
        isTrue,
      );
      expect(
        matchesDomainPatternWithPort('a.example.com', 65535, '*.example.com'),
        isTrue,
      );
    });

    test('entry with port matches only that port', () {
      expect(
        matchesDomainPatternWithPort('example.com', 443, 'example.com:443'),
        isTrue,
      );
      expect(
        matchesDomainPatternWithPort('example.com', 80, 'example.com:443'),
        isFalse,
      );
      expect(
        matchesDomainPatternWithPort(
          'a.example.com',
          8443,
          '*.example.com:8443',
        ),
        isTrue,
      );
      expect(
        matchesDomainPatternWithPort(
          'a.example.com',
          443,
          '*.example.com:8443',
        ),
        isFalse,
      );
    });

    test('bare "*" with port (deniedDomains)', () {
      expect(matchesDomainPatternWithPort('anything.test', 22, '*:22'), isTrue);
      expect(
        matchesDomainPatternWithPort('anything.test', 23, '*:22'),
        isFalse,
      );
    });
  });
}
