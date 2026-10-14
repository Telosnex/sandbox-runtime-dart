// Ported from sandbox-runtime test/sandbox/resolved-address-guard.test.ts @ 24eb39e.
// ignore_for_file: constant_identifier_names, non_constant_identifier_names, slash_for_doc_comments
import 'dart:async';
import 'dart:io';

import 'package:sandbox_runtime/src/node/dns.dart' as dns;
import 'package:sandbox_runtime/src/node/errno.dart';
import 'package:sandbox_runtime/src/sandbox/address.dart';
import 'package:sandbox_runtime/src/sandbox/resolved_address_guard.dart'
    as guard;
import 'package:sandbox_runtime/src/sandbox/sandbox_config.dart';
import 'package:path/path.dart' as path;
import 'package:test/test.dart';

final FIXTURE_DIR = path.join(
  Directory.current.path, // import.meta.dir, '..'
  'test',
  'fixtures',
  'tls-terminate',
);
final CA_CERT = path.join(FIXTURE_DIR, 'ca.crt');
final CA_KEY = path.join(FIXTURE_DIR, 'ca.key');
final CA_PEM = File(CA_CERT).readAsStringSync();

/**
 * The domain allowlist matches by name; these tests pin what happens when a
 * permitted name resolves somewhere the allowlist never meant — loopback,
 * link-local, or an embedder-listed private range — and that explicit IP
 * literals and the reserved `localhost` names are left alone.
 */

/** Resolver stub: answers from a fixed table (ENOTFOUND otherwise) on a later tick, as dns.lookup does. */
({guard.Resolver resolve, List<String> calls}) fakeResolver(
  Map<String, List<String>> table,
) {
  final calls = <String>[];
  void resolve(
    String hostname,
    dns.LookupAllOptions options,
    void Function(dns.NodeLookupError? err, List<dns.LookupAddress> addresses)
    callback,
  ) {
    calls.add(hostname);
    final addrs = table[hostname];
    scheduleMicrotask(() {
      if (addrs == null) {
        callback(
          dns.NodeLookupError('ENOTFOUND', 'getaddrinfo ENOTFOUND $hostname'),
          const <dns.LookupAddress>[],
        );
        return;
      }
      callback(
        null,
        addrs
            .map(
              (address) => dns.LookupAddress(
                address: address,
                family: address.contains(':') ? 6 : 4,
              ),
            )
            .toList(),
      );
    });
  }

  return (resolve: resolve, calls: calls);
}

Future<List<dns.LookupAddress>> lookupAll(
  guard.ResolvedAddressGuard guard,
  String hostname, {
  int port = 443,
}) {
  final completer = Completer<List<dns.LookupAddress>>();
  guard.lookupFor(port)(hostname, dns.LookupAllOptions(), (
    dns.NodeLookupError? err,
    dns.LookupResult? address, [
    int? family,
  ]) {
    if (err != null) {
      completer.completeError(err as Object);
    } else if (address is dns.LookupResultAll) {
      completer.complete(address.addresses);
    } else {
      completer.completeError(
        StateError('Expected all-address lookup result, got $address'),
      );
    }
  });
  return completer.future;
}

typedef Denial = ({String host, int port, String reason});

/** What the manager does: the guard's lookup for the port, recording refusals. */
// Pending port: src/sandbox/parent-proxy.ts (DirectLookup).
// function recordingLookupFor(
//   guard: ResolvedAddressGuard,
//   denials: Denial[],
// ): DirectLookup {
//   return port => (hostname, options, callback) =>
//     guard.lookupFor(port)(hostname, options, (err, address, family) => {
//       if (isResolvedAddressDenied(err)) {
//         denials.push({ host: hostname, port, reason: err.reason })
//       }
//       callback(err, address, family)
//     })

void main() {
  group('address: parseAddressRange', () {
    test('accepts IPv4/IPv6 literals and CIDR ranges', () {
      expect(parseAddressRange('10.0.0.0/8'), (
        address: '10.0.0.0',
        prefix: 8,
        family: 'ipv4',
      ));
      expect(parseAddressRange('192.0.2.7'), (
        address: '192.0.2.7',
        prefix: 32,
        family: 'ipv4',
      ));
      expect(parseAddressRange('fc00::/7'), (
        address: 'fc00::',
        prefix: 7,
        family: 'ipv6',
      ));
      expect(parseAddressRange('::1')?.prefix, 128);
    });

    test(
      'stores an IPv4-mapped IPv6 entry as the IPv4 rule and drops a zone id',
      () {
        expect(parseAddressRange('::ffff:10.0.0.1'), (
          address: '10.0.0.1',
          prefix: 32,
          family: 'ipv4',
        ));
        expect(parseAddressRange('::FFFF:A00:0/104'), (
          address: '10.0.0.0',
          prefix: 8,
          family: 'ipv4',
        ));
        expect(parseAddressRange('::ffff:0:0/96'), (
          address: '0.0.0.0',
          prefix: 0,
          family: 'ipv4',
        ));
        expect(parseAddressRange('fe80::1%en0'), (
          address: 'fe80::1',
          prefix: 128,
          family: 'ipv6',
        ));
        expect(parseAddressRange('fe80::%eth0/10')?.address, 'fe80::');
      },
    );

    test(
      'rejects hostnames, bad prefixes, bracketed IPv6 and a mapped range wider than /96',
      () {
        for (final bad in [
          'example.com',
          '10.0.0.0/33',
          '10.0.0.0/',
          '10.0.0.0/x',
          'fc00::/129',
          '[::1]',
          '::ffff:10.0.0.0/95',
          '',
          '300.1.1.1',
        ]) {
          expect(parseAddressRange(bad), isNull);
        }
      },
    );
  });

  /** This host's interface addresses as the guard sees them in these tests. */
  const HOST_ADDRESSES = ['192.168.7.23', '2001:db8:7::23', '127.0.0.1', '::1'];
  List<String> localAddresses() => HOST_ADDRESSES;

  group('address: embeddedIPv4', () {
    test(
      'extracts the IPv4 address from the transition forms that carry one',
      () {
        const cases = <(String, String?)>[
          ('::ffff:127.0.0.1', '127.0.0.1'), // IPv4-mapped
          ('::FFFF:7F00:1', '127.0.0.1'),
          ('::7f00:1', '127.0.0.1'), // IPv4-compatible
          ('::169.254.169.254', '169.254.169.254'),
          ('::ffff:0:a9fe:a9fe', '169.254.169.254'), // IPv4-translated
          ('64:ff9b::7f00:1', '127.0.0.1'), // NAT64 well-known prefix
          ('64:ff9b::8.8.8.8', '8.8.8.8'),
          (
            '64:ff9b:1::a00:5',
            null,
          ), // local-use prefix: layout ambiguous, not decoded
          ('64:ff9b:1:0:5d:b8d8:7f00:0', null),
          ('2002:c0a8:717::1', '192.168.7.23'), // 6to4
          ('2002:7f00:1:5::9%en0', '127.0.0.1'),
          ('::1', '0.0.0.1'),
          ('64:ff9b:0:1::7f00:1', null), // not one of the forms
          ('2001:db8::7f00:1', null),
          ('fe80::7f00:1', null),
          ('127.0.0.1', null),
          ('not-an-address', null),
        ];
        for (final (address, v4) in cases) {
          expect([address, embeddedIPv4(address)], [address, v4]);
        }
      },
    );
  });

  group('resolved-address-guard: permits', () {
    final testGuard = guard.createResolvedAddressGuard(
      localAddresses: localAddresses,
    );

    test(
      'denies the built-in set for a hostname, including v4-mapped forms',
      () {
        for (final address in [
          '127.0.0.1',
          '127.255.255.254',
          '::1',
          '::ffff:127.0.0.1',
          '::ffff:7f00:1',
          '0:0:0:0:0:FFFF:7F00:0001',
          '0.0.0.0',
          '169.254.169.254',
          '::ffff:169.254.169.254',
          '224.0.0.1',
          '239.255.255.250',
          '255.255.255.255',
          '100.100.100.200',
          '168.63.129.16',
          '192.0.0.192',
          '::',
          'fe80::1',
          'fe80::1%en0',
          'fe80::1%1',
          '::1%lo0',
          'FE80::ABCD',
          'febf::1',
          'ff02::1',
          'fd00:ec2::254',
          'fd00:ec2::23',
          'fd20:ce::254',
          'fd00:c1::a9fe:a9fe',
          'fd00:42::42',
          'fd00:a9fe:a9fe::1',
          'fd00:100::100:200',
        ]) {
          expect(testGuard.permits('api.example.com', address, 443), isFalse);
        }
      },
    );

    test("denies this host's own interface addresses, read at lookup time", () {
      expect(
        testGuard.permits('api.example.com', '192.168.7.23', 443),
        isFalse,
      );
      expect(
        testGuard.permits('api.example.com', '::ffff:192.168.7.23', 443),
        isFalse,
      );
      expect(
        testGuard.permits('api.example.com', '2001:DB8:7:0::23', 443),
        isFalse,
      );
      expect(testGuard.permits('api.example.com', '192.168.7.24', 443), isTrue);
      var current = <String>['10.9.8.7'];
      final live = guard.createResolvedAddressGuard(
        localAddresses: () => current,
      );
      expect(live.permits('api.example.com', '10.9.8.7', 443), isFalse);
      current = [];
      expect(live.permits('api.example.com', '10.9.8.7', 443), isTrue);
      // A carve-out for the LAN address wins, like any other.
      final carved = guard.createResolvedAddressGuard(
        localAddresses: localAddresses,
        allowedDomains: ['192.168.7.23'],
      );
      expect(carved.permits('nas.example.com', '192.168.7.23', 443), isTrue);
    });

    test(
      'judges an IPv6 answer that embeds an IPv4 address as that address too',
      () {
        for (final address in [
          '64:ff9b::7f00:1', // NAT64 to loopback
          '64:ff9b::a9fe:a9fe', // NAT64 to the link-local metadata endpoint
          '64:ff9b::c0a8:717', // NAT64 to this host's own 192.168.7.23
          '2002:7f00:1::1', // 6to4
          '2002:c0a8:717:1::2',
          '::7f00:1', // IPv4-compatible
          '::ffff:0:7f00:1', // IPv4-translated
        ]) {
          expect(
            [address, testGuard.permits('api.example.com', address, 443)],
            [address, false],
          );
        }
        // The same forms carrying a public address are left alone, as is an
        // ordinary IPv6 address whose low bits merely look like one.
        for (final address in [
          '64:ff9b::c000:20a',
          '2002:c000:20a::1',
          '2001:db8::7f00:1',
          '64:ff9b:0:1::7f00:1',
          '64:ff9b:1::7f00:1', // local-use prefix — not decoded, so not treated as loopback
        ]) {
          expect(
            [address, testGuard.permits('api.example.com', address, 443)],
            [address, true],
          );
        }
        // The carried IPv4 binds embedder deny rules — and only denials: it does
        // not inherit an allow-list carve-out, so a name cannot reach a denied
        // address by resolving to a carried form of an allow-listed one.
        final g = guard.createResolvedAddressGuard(
          localAddresses: localAddresses,
          deniedResolvedAddresses: ['10.0.0.0/8'],
          allowedDomains: ['10.0.0.9'],
        );
        expect(
          g.permits('intranet.example.com', '64:ff9b::a00:5', 443),
          isFalse,
        );
        expect(
          g.permits('intranet.example.com', '64:ff9b::a00:9', 443),
          isFalse,
        );
        expect(g.permits('intranet.example.com', '10.0.0.9', 443), isTrue);
        expect(
          g.permits('intranet.example.com', '64:ff9b::ac10:1', 443),
          isTrue,
        );
        expect(g.permits('localhost', '64:ff9b::7f00:1', 443), isFalse);
        // `::1` is loopback; its IPv4-compatible form `0.0.0.1` must not let it
        // ride a carve-out for `0.0.0.1`, and a real mapped carve-out still holds.
        final h = guard.createResolvedAddressGuard(
          localAddresses: localAddresses,
          allowedDomains: ['0.0.0.1:3000', '127.0.0.1:3000'],
        );
        expect(h.permits('svc.example.com', '::1', 3000), isFalse);
        expect(h.permits('svc.example.com', '0.0.0.1', 3000), isTrue);
        expect(h.permits('svc.example.com', '::ffff:127.0.0.1', 3000), isTrue);
      },
    );

    test(
      'permits public and (by default) private-use addresses for a hostname',
      () {
        for (final address in [
          '192.0.2.10',
          '198.51.100.1',
          '2001:db8::1',
          '10.0.0.5',
          '172.16.0.1',
          '192.168.1.1',
          'fd00::1',
          'fd20:ce::1',
          '100.64.0.1',
          '192.0.0.8',
        ]) {
          expect(testGuard.permits('api.example.com', address, 443), isTrue);
        }
      },
    );

    test('never re-judges an IP-literal destination', () {
      expect(testGuard.permits('127.0.0.1', '127.0.0.1', 443), isTrue);
      expect(testGuard.permits('::1', '::1', 443), isTrue);
      expect(
        testGuard.permits('169.254.169.254', '169.254.169.254', 443),
        isTrue,
      );
    });

    test('lets localhost names resolve to loopback and nothing else', () {
      expect(testGuard.permits('localhost', '127.0.0.1', 443), isTrue);
      expect(testGuard.permits('localhost', '::1', 443), isTrue);
      expect(testGuard.permits('localhost', '::ffff:127.0.0.1', 443), isTrue);
      expect(testGuard.permits('LOCALHOST.', '127.0.0.1', 443), isTrue);
      expect(testGuard.permits('app.dev.localhost', '127.0.0.1', 443), isTrue);
      expect(testGuard.permits('localhost', '169.254.169.254', 443), isFalse);
      expect(testGuard.permits('app.localhost', '192.0.2.1', 443), isFalse);
      expect(testGuard.permits('app.localhost', '10.0.0.5', 443), isFalse);
      expect(testGuard.permits('notlocalhost', '127.0.0.1', 443), isFalse);
      expect(
        testGuard.permits('localhost.example.com', '127.0.0.1', 443),
        isFalse,
      );
    });

    test(
      'applies embedder-configured denied ranges (and their v4-mapped twins)',
      () {
        final g = guard.createResolvedAddressGuard(
          localAddresses: localAddresses,
          deniedResolvedAddresses: ['10.0.0.0/8', '192.168.0.0/16', 'fc00::/7'],
        );
        expect(g.permits('intranet.example.com', '10.1.2.3', 443), isFalse);
        expect(
          g.permits('intranet.example.com', '::ffff:10.1.2.3', 443),
          isFalse,
        );
        expect(g.permits('intranet.example.com', '192.168.1.1', 443), isFalse);
        expect(g.permits('intranet.example.com', 'fd12:3456::1', 443), isFalse);
        expect(g.permits('intranet.example.com', '172.16.0.1', 443), isTrue);
        expect(g.permits('intranet.example.com', '192.0.2.10', 443), isTrue);
        // Built-ins still apply alongside the extras.
        expect(g.permits('intranet.example.com', '127.0.0.1', 443), isFalse);
      },
    );

    test(
      'allowed carve-outs win over the denied set, per port when given one',
      () {
        final g = guard.createResolvedAddressGuard(
          localAddresses: localAddresses,
          allowedDomains: ['127.0.0.1', '[::1]:3000'],
        );
        expect(g.permits('myapp.test', '127.0.0.1', 443), isTrue);
        expect(g.permits('myapp.test', '127.0.0.2', 443), isFalse);
        expect(g.permits('myapp.test', '::1', 3000), isTrue);
        expect(g.permits('myapp.test', '::1', 443), isFalse);
      },
    );

    test(
      'an IPv4-mapped literal in either list binds exactly its IPv4 address',
      () {
        final g = guard.createResolvedAddressGuard(
          localAddresses: localAddresses,
          allowedDomains: ['[::ffff:127.0.0.1]:3000'],
          deniedResolvedAddresses: ['::ffff:10.0.0.1'],
          deniedDomains: ['[::ffff:10.0.0.2]'],
        );
        expect(g.permits('myapp.test', '127.0.0.1', 3000), isTrue);
        expect(g.permits('myapp.test', '127.0.0.1', 3001), isFalse);
        expect(g.permits('myapp.test', '169.254.169.254', 3000), isFalse);
        expect(g.permits('myapp.test', '127.0.0.2', 3000), isFalse);
        expect(g.permits('api.example.com', '10.0.0.1', 443), isFalse);
        expect(g.permits('api.example.com', '::ffff:10.0.0.2', 443), isFalse);
        expect(g.permits('api.example.com', '10.0.0.3', 443), isTrue);
        expect(g.permits('api.example.com', '192.0.2.1', 443), isTrue);
      },
    );

    test('port-qualified denied rules apply to that port only', () {
      final g = guard.createResolvedAddressGuard(
        localAddresses: localAddresses,
        deniedDomains: ['10.0.0.5:22'],
        deniedResolvedAddresses: ['10.9.0.0/16'],
      );
      expect(g.permits('git.example.com', '10.0.0.5', 22), isFalse);
      expect(g.permits('git.example.com', '10.0.0.5', 443), isTrue);
      expect(g.permits('git.example.com', '10.9.1.1', 443), isFalse);
    });

    test('throws on a malformed entry (schema validates first)', () {
      expect(
        () => guard.createResolvedAddressGuard(
          deniedResolvedAddresses: ['nope/8'],
        ),
        throwsA(
          isA<NodeException>().having(
            (error) => error.message,
            'message',
            contains('Invalid IP address or CIDR range'),
          ),
        ),
      );
      expect(
        () => guard.createResolvedAddressGuard(
          deniedResolvedAddresses: ['[::1]'],
        ),
        throwsA(isA<NodeException>()),
      );
    });

    test("by default reads the machine's real interface addresses", () {
      final real = guard.createResolvedAddressGuard();
      for (final address in guard.localInterfaceAddresses()) {
        expect(real.permits('api.example.com', address, 443), isFalse);
      }
    });
  });

  group('resolved-address-guard: lookup', () {
    test(
      'fails with ResolvedAddressDeniedError when every address is denied',
      () async {
        final resolve = fakeResolver({
          'evil.example.com': ['127.0.0.1', '::1'],
        });
        final testGuard = guard.createResolvedAddressGuard(
          resolve: resolve.resolve,
        );
        final err = await lookupAll(
          testGuard,
          'evil.example.com',
        ).then<Object>((value) => value, onError: (Object error) => error);
        expect(err, isA<guard.ResolvedAddressDeniedError>());
        expect(guard.isResolvedAddressDenied(err), isTrue);
        final denied = err as guard.ResolvedAddressDeniedError;
        expect(denied.code, 'ERR_SRT_RESOLVED_ADDRESS_DENIED');
        expect(denied.reason, 'resolved to a loopback address');
        expect(denied.addresses, ['127.0.0.1', '::1']);
        expect(denied.message, isNot(contains('127.0.0.1')));
        expect(denied.hostname, 'evil.example.com');
      },
    );

    test(
      'names the class of the refused addresses, never the addresses',
      () async {
        final resolve = fakeResolver({
          'meta.example.com': ['169.254.169.254', 'fd20:ce::254'],
          'lan.example.com': ['192.168.7.23'],
          'db.example.com': ['10.1.2.3'],
          'ssh.example.com': ['192.0.2.5'],
          'app.localhost': ['192.0.2.9'],
        });
        final testGuard = guard.createResolvedAddressGuard(
          resolve: resolve.resolve,
          localAddresses: localAddresses,
          deniedResolvedAddresses: ['10.0.0.0/8'],
          deniedDomains: ['192.0.2.5:22'],
        );
        Future<String> reasonFor(String hostname, [int port = 443]) =>
            lookupAll(testGuard, hostname, port: port).then(
              (_) => 'permitted',
              onError: (Object error) =>
                  (error as guard.ResolvedAddressDeniedError).reason,
            );
        expect(
          await reasonFor('meta.example.com'),
          'resolved to a link-local address / a cloud metadata address',
        );
        expect(
          await reasonFor('lan.example.com'),
          "resolved to one of this host's addresses",
        );
        expect(
          await reasonFor('db.example.com'),
          'resolved to a listed address',
        );
        expect(
          await reasonFor('ssh.example.com', 22),
          'resolved to a deny-listed address',
        );
        expect(await reasonFor('ssh.example.com', 443), 'permitted');
        expect(
          await reasonFor('app.localhost'),
          'resolved to a non-loopback address',
        );
      },
    );

    test('returns only the surviving addresses, in resolver order', () async {
      final resolve = fakeResolver({
        'mixed.example.com': ['169.254.169.254', '2001:db8::5', '192.0.2.10'],
      });
      final testGuard = guard.createResolvedAddressGuard(
        resolve: resolve.resolve,
        localAddresses: localAddresses,
      );
      expect(
        (await lookupAll(testGuard, 'mixed.example.com'))
            .map(
              (address) => (address: address.address, family: address.family),
            )
            .toList(),
        [
          (address: '2001:db8::5', family: 6),
          (address: '192.0.2.10', family: 4),
        ],
      );
    });

    test('supports the single-address callback form', () async {
      final resolve = fakeResolver({
        'mixed.example.com': ['127.0.0.1', '192.0.2.10'],
      });
      final testGuard = guard.createResolvedAddressGuard(
        resolve: resolve.resolve,
        localAddresses: localAddresses,
      );
      final completer = Completer<(String, int?)>();
      testGuard.lookupFor(443)('mixed.example.com', dns.LookupOptions(), (
        dns.NodeLookupError? err,
        dns.LookupResult? result, [
        int? family,
      ]) {
        if (err != null) {
          completer.completeError(err as Object);
        } else if (result is dns.LookupResultAddress) {
          completer.complete((result.address, family));
        } else {
          completer.completeError(
            StateError('Expected single-address lookup result'),
          );
        }
      });
      expect(await completer.future, ('192.0.2.10', 4));
    });

    test('never filters an IP-literal destination', () async {
      final resolve = fakeResolver({
        '127.0.0.1': ['127.0.0.1'],
      });
      final testGuard = guard.createResolvedAddressGuard(
        resolve: resolve.resolve,
      );
      expect(
        (await lookupAll(testGuard, '127.0.0.1'))
            .map(
              (address) => (address: address.address, family: address.family),
            )
            .toList(),
        [(address: '127.0.0.1', family: 4)],
      );
    });

    test('an empty answer without an error surfaces as ENOTFOUND', () async {
      final testGuard = guard.createResolvedAddressGuard(
        resolve: fakeResolver({'empty.example.com': []}).resolve,
      );
      try {
        await lookupAll(testGuard, 'empty.example.com');
        fail('Expected an ENOTFOUND error');
      } catch (error) {
        expect((error as dns.NodeLookupError).code, 'ENOTFOUND');
      }
    });

    test('propagates resolver errors unchanged', () async {
      final testGuard = guard.createResolvedAddressGuard(
        resolve: fakeResolver({}).resolve,
      );
      try {
        await lookupAll(testGuard, 'nx.example.com');
        fail('Expected an ENOTFOUND error');
      } catch (error) {
        expect((error as dns.NodeLookupError).code, 'ENOTFOUND');
        expect(guard.isResolvedAddressDenied(error), isFalse);
      }
    });
  });

  group('resolved-address-guard: config schema', () {
    final Map<String, Object?> base = {
      'network': {
        'allowedDomains': ['*.example.com'],
        'deniedDomains': [],
      },
      'filesystem': {'denyRead': [], 'allowWrite': [], 'denyWrite': []},
    };

    test('accepts deniedResolvedAddresses', () {
      final result = SandboxRuntimeConfigSchema.safeParse({
        ...base,
        'network': {
          ...base['network'] as Map<String, Object?>,
          'deniedResolvedAddresses': ['10.0.0.0/8', 'fc00::/7', '192.0.2.1'],
        },
      });
      expect(result.success, isTrue);
    });

    test('rejects a malformed range with a pointed message', () {
      final result = SandboxRuntimeConfigSchema.safeParse({
        ...base,
        'network': {
          ...base['network'] as Map<String, Object?>,
          'deniedResolvedAddresses': ['10.0.0.0/33'],
        },
      });
      expect(result.success, isFalse);
      if (!result.success) {
        expect(
          result.error.issues.first.message,
          contains('Invalid IP address or CIDR range'),
        );
      }
    });

    test(
      'reads the IP literals of the allow/deny lists with the same precedence as for names',
      () {
        // A name may reach exactly what an allow-listed literal already permits,
        // nothing wider; a deny-listed literal is refused by name too.
        final g = guard.createResolvedAddressGuard(
          localAddresses: localAddresses,
          allowedDomains: ['*.example.com', 'myapp.test', '127.0.0.1:3000'],
          deniedDomains: ['10.0.0.5', '[fd00::7]:22', '*:25'],
        );
        expect(g.permits('myapp.test', '127.0.0.1', 3000), isTrue);
        expect(g.permits('myapp.test', '127.0.0.1', 5432), isFalse);
        expect(g.permits('evil.example.com', '127.0.0.1', 3000), isTrue);
        expect(g.permits('evil.example.com', '127.0.0.2', 3000), isFalse);
        expect(g.permits('intranet.example.com', '10.0.0.5', 443), isFalse);
        expect(g.permits('intranet.example.com', 'fd00::7', 22), isFalse);
        expect(g.permits('intranet.example.com', 'fd00::7', 443), isTrue);
      },
    );

    test(
      'a deny-listed literal wins over an allow-listed one and over the localhost rule',
      () {
        final g = guard.createResolvedAddressGuard(
          localAddresses: localAddresses,
          allowedDomains: ['myapp.test', '127.0.0.1', '10.0.0.5', 'localhost'],
          deniedDomains: ['127.0.0.1:6379', '10.0.0.5:22', '[::1]:6379'],
        );
        expect(g.permits('myapp.test', '127.0.0.1', 3000), isTrue);
        expect(g.permits('myapp.test', '127.0.0.1', 6379), isFalse);
        expect(g.permits('git.corp.example', '10.0.0.5', 443), isTrue);
        expect(g.permits('git.corp.example', '10.0.0.5', 22), isFalse);
        expect(g.permits('localhost', '127.0.0.1', 8080), isTrue);
        expect(g.permits('localhost', '127.0.0.1', 6379), isFalse);
        expect(g.permits('app.localhost', '::1', 6379), isFalse);
        // And the other way round: a bare deny-listed literal beats a port-scoped allow.
        final h = guard.createResolvedAddressGuard(
          localAddresses: localAddresses,
          allowedDomains: ['myapp.test', '127.0.0.1:3000'],
          deniedDomains: ['127.0.0.1'],
        );
        expect(h.permits('myapp.test', '127.0.0.1', 3000), isFalse);
        // A zone id on a list entry is meaningless for matching and is dropped, so
        // the entry means the same address here as it does for a literal request.
        final z = guard.createResolvedAddressGuard(
          localAddresses: localAddresses,
          allowedDomains: ['myapp.test'],
          deniedDomains: ['[2001:db8::1%eth0]'],
        );
        expect(z.permits('myapp.test', '2001:db8::1', 443), isFalse);
        expect(z.permits('myapp.test', '2001:db8::2', 443), isTrue);
      },
    );
  });

  // ---------------------------------------------------------------------------
  // Proxy-level: the guard's lookup wired into the real HTTP / SOCKS servers.
  // A local HTTP server on 127.0.0.1 stands in for "whatever is listening on
  // loopback"; the fake resolver points allow-listed names at it.
  // ---------------------------------------------------------------------------
  group('resolved-address-guard: through the proxy servers', () {
    // Upstream setup, kept as written until src/sandbox/http-proxy.ts and src/sandbox/socks-proxy.ts are ported.
    // let upstream: HttpServer
    // let upstreamPort: number
    // let upstreamHits: string[]
    // let denials: Denial[]
    // const closers: Array<() => Promise<unknown> | unknown> = []

    // beforeEach(async () => {
    //   upstreamHits = []
    //   denials = []
    //   upstream = createHttpServer((req, res) => {
    //     let body = ''
    //     req.setEncoding('utf8').on('data', c => (body += c))
    //     req.on('end', () => {
    //       upstreamHits.push(
    //         `${req.method} ${req.url} host=${req.headers.host}` +
    //           (body ? ` body=${body}` : ''),
    //       )
    //       res.writeHead(200, { 'Content-Type': 'text/plain' })
    //       res.end('upstream-ok')
    //     })
    //   })
    //   upstream.listen(0, '127.0.0.1')
    //   await once(upstream, 'listening')
    //   upstreamPort = (upstream.address() as { port: number }).port
    // })

    // afterEach(async () => {
    //   for (const c of closers.splice(0)) await c()
    //   upstream.close()
    // })

    // const resolve = fakeResolver({
    //   'rebind.example.com': ['127.0.0.1'],
    //   'metadata.example.com': ['169.254.169.254'],
    //   'intranet.example.com': ['127.0.0.1'],
    //   'devbox.example.com': ['127.0.0.1'],
    //   localhost: ['127.0.0.1'],
    // })

    // async function startHttpProxy(
    //   guard = createResolvedAddressGuard({ resolve }),
    // ): Promise<number> {
    //   const proxy = createHttpProxyServer({
    //     filter: () => true,
    //     lookupFor: recordingLookupFor(guard, denials),
    //   })
    //   proxy.listen(0, '127.0.0.1')
    //   await once(proxy, 'listening')
    //   closers.push(
    //     () =>
    //       new Promise(r => {
    //         proxy.closeAllConnections?.()
    //         proxy.close(() => r(undefined))
    //       }),
    //   )
    //   return (proxy.address() as { port: number }).port
    // }

    // /** One request over a raw socket; resolves once the response is complete (Content-Length) or the socket closes. */
    // async function rawExchange(
    //   proxyPort: number,
    //   payload: string,
    // ): Promise<string> {
    //   const sock = connect({ host: '127.0.0.1', port: proxyPort })
    //   await once(sock, 'connect')
    //   sock.write(payload)
    //   let buf = ''
    //   await new Promise<void>(resolve => {
    //     sock.on('data', d => {
    //       buf += d.toString('latin1')
    //       const headEnd = buf.indexOf('\r\n\r\n')
    //       if (headEnd === -1) return
    //       const length = /content-length: (\d+)/i.exec(buf.slice(0, headEnd))
    //       if (length && buf.length - headEnd - 4 >= Number(length[1])) resolve()
    //     })
    //     sock.on('end', resolve)
    //     sock.on('close', resolve)
    //   })
    //   sock.destroy()
    //   return buf
    // }

    test(
      'plain HTTP: allow-listed name resolving to loopback is refused with 403, upstream untouched',
      () async {
        // const proxyPort = await startHttpProxy()
        // const resp = await rawExchange(
        //   proxyPort,
        //   `GET http://rebind.example.com:${upstreamPort}/secret HTTP/1.1\r\n` +
        //     `Host: rebind.example.com:${upstreamPort}\r\nConnection: close\r\n\r\n`,
        // )
        // expect(resp.startsWith('HTTP/1.1 403')).toBe(true)
        // expect(resp).toContain('X-Proxy-Error: blocked-by-sandbox-runtime')
        // expect(resp).toContain(
        //   'Connection to rebind.example.com blocked: resolved to a loopback address',
        // )
        // expect(upstreamHits).toEqual([])
        // expect(denials).toEqual([
        //   {
        //     host: 'rebind.example.com',
        //     port: upstreamPort,
        //     reason: 'resolved to a loopback address',
        //   },
        // ])
      },
      skip: 'pending port: src/sandbox/http-proxy.ts',
    );

    test('plain HTTP: an allow-listed IP literal is still dialed', () async {
      // const proxyPort = await startHttpProxy()
      // const resp = await rawExchange(
      //   proxyPort,
      //   `GET http://127.0.0.1:${upstreamPort}/ok HTTP/1.1\r\n` +
      //     `Host: 127.0.0.1:${upstreamPort}\r\nConnection: close\r\n\r\n`,
      // )
      // expect(resp.startsWith('HTTP/1.1 200')).toBe(true)
      // expect(resp).toContain('upstream-ok')
      // expect(denials).toEqual([])
    }, skip: 'pending port: src/sandbox/http-proxy.ts');

    test('plain HTTP: "localhost" may resolve to loopback', () async {
      // const proxyPort = await startHttpProxy()
      // const resp = await rawExchange(
      //   proxyPort,
      //   `GET http://localhost:${upstreamPort}/ok HTTP/1.1\r\n` +
      //     `Host: localhost:${upstreamPort}\r\nConnection: close\r\n\r\n`,
      // )
      // expect(resp.startsWith('HTTP/1.1 200')).toBe(true)
      // expect(upstreamHits).toEqual([`GET /ok host=localhost:${upstreamPort}`])
    }, skip: 'pending port: src/sandbox/http-proxy.ts');

    test(
      'plain HTTP: a permitted resolution dials the resolved address with the Host header preserved',
      () async {
        // const proxyPort = await startHttpProxy(
        //   createResolvedAddressGuard({
        //     resolve,
        //     allowedDomains: [`127.0.0.1:${upstreamPort}`],
        //   }),
        // )
        // const resp = await rawExchange(
        //   proxyPort,
        //   `GET http://devbox.example.com:${upstreamPort}/app HTTP/1.1\r\n` +
        //     `Host: devbox.example.com:${upstreamPort}\r\nConnection: close\r\n\r\n`,
        // )
        // expect(resp.startsWith('HTTP/1.1 200')).toBe(true)
        // expect(upstreamHits).toEqual([
        //   `GET /app host=devbox.example.com:${upstreamPort}`,
        // ])
        // expect(resolve.calls).toContain('devbox.example.com')
      },
      skip: 'pending port: src/sandbox/http-proxy.ts',
    );

    test(
      'plain HTTP: a permitted resolution forwards a streamed request body intact, exactly once',
      () async {
        // const proxyPort = await startHttpProxy(
        //   createResolvedAddressGuard({
        //     resolve,
        //     allowedDomains: [`127.0.0.1:${upstreamPort}`],
        //   }),
        // )
        // // Chunked from the client, so the proxy re-frames the upstream body.
        // const body = '{"password":"hunter2"}'
        // const resp = await rawExchange(
        //   proxyPort,
        //   `POST http://devbox.example.com:${upstreamPort}/submit HTTP/1.1\r\n` +
        //     `Host: devbox.example.com:${upstreamPort}\r\n` +
        //     `Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n` +
        //     `${body.length.toString(16)}\r\n${body}\r\n0\r\n\r\n`,
        // )
        // expect(resp.startsWith('HTTP/1.1 200')).toBe(true)
        // expect(upstreamHits).toEqual([
        //   `POST /submit host=devbox.example.com:${upstreamPort} body=${body}`,
        // ])
      },
      skip: 'pending port: src/sandbox/http-proxy.ts',
    );

    test('plain HTTP: an embedder-configured range is refused too', () async {
      // const proxyPort = await startHttpProxy(
      //   createResolvedAddressGuard({
      //     resolve: fakeResolver({ 'intranet.example.com': ['10.20.30.40'] }),
      //     deniedResolvedAddresses: ['10.0.0.0/8'],
      //   }),
      // )
      // const resp = await rawExchange(
      //   proxyPort,
      //   `GET http://intranet.example.com/ HTTP/1.1\r\nHost: intranet.example.com\r\nConnection: close\r\n\r\n`,
      // )
      // expect(resp.startsWith('HTTP/1.1 403')).toBe(true)
      // expect(denials[0]?.reason).toBe('resolved to a listed address')
    }, skip: 'pending port: src/sandbox/http-proxy.ts');

    test(
      'CONNECT: allow-listed name resolving to loopback gets 403 instead of a tunnel',
      () async {
        // const proxyPort = await startHttpProxy()
        // const resp = await rawExchange(
        //   proxyPort,
        //   `CONNECT rebind.example.com:${upstreamPort} HTTP/1.1\r\nHost: rebind.example.com:${upstreamPort}\r\n\r\n`,
        // )
        // // The class is the status phrase too: few clients show the body.
        // expect(resp).toStartWith('HTTP/1.1 403 resolved to a loopback address\r\n')
        // expect(resp).toContain('X-Proxy-Error: blocked-by-sandbox-runtime')
        // expect(resp).toEndWith(
        //   '\r\n\r\nConnection to rebind.example.com blocked: resolved to a loopback address',
        // )
        // expect(resp).not.toContain('127.0.0.1')
        // expect(denials.map(d => `${d.host}:${d.port}`)).toEqual([
        //   `rebind.example.com:${upstreamPort}`,
        // ])
      },
      skip: 'pending port: src/sandbox/http-proxy.ts',
    );

    test('CONNECT: link-local (metadata-style) resolution is refused', () async {
      // const proxyPort = await startHttpProxy()
      // const resp = await rawExchange(
      //   proxyPort,
      //   `CONNECT metadata.example.com:80 HTTP/1.1\r\nHost: metadata.example.com:80\r\n\r\n`,
      // )
      // expect(resp.startsWith('HTTP/1.1 403')).toBe(true)
      // expect(denials[0]?.reason).toBe('resolved to a link-local address')
    }, skip: 'pending port: src/sandbox/http-proxy.ts');

    test('CONNECT: an allow-listed IP literal still tunnels', () async {
      // const proxyPort = await startHttpProxy()
      // const sock = connect({ host: '127.0.0.1', port: proxyPort })
      // await once(sock, 'connect')
      // sock.write(
      //   `CONNECT 127.0.0.1:${upstreamPort} HTTP/1.1\r\nHost: 127.0.0.1:${upstreamPort}\r\n\r\n`,
      // )
      // const [first] = (await once(sock, 'data')) as [Buffer]
      // expect(first.toString()).toContain('200 Connection Established')
      // sock.write(
      //   `GET /tunnelled HTTP/1.1\r\nHost: 127.0.0.1:${upstreamPort}\r\nConnection: close\r\n\r\n`,
      // )
      // let buf = ''
      // sock.on('data', d => (buf += d.toString()))
      // await once(sock, 'close')
      // expect(buf).toContain('upstream-ok')
      // expect(denials).toEqual([])
    }, skip: 'pending port: src/sandbox/http-proxy.ts');

    // // --- SOCKS -------------------------------------------------------------

    // async function startSocks(
    //   guard = createResolvedAddressGuard({ resolve }),
    // ): Promise<number> {
    //   const wrapper = createSocksProxyServer({
    //     filter: () => true,
    //     lookupFor: recordingLookupFor(guard, denials),
    //   })
    //   const tcp: TcpServer = createTcpServer((s: Socket) =>
    //     wrapper.handleConnection(s),
    //   )
    //   tcp.listen(0, '127.0.0.1')
    //   await once(tcp, 'listening')
    //   closers.push(async () => {
    //     await wrapper.close()
    //     tcp.close()
    //   })
    //   return (tcp.address() as { port: number }).port
    // }

    // /** No-auth greeting, then CONNECT; resolves with the reply's REP byte. */
    // async function socksConnect(
    //   socksPort: number,
    //   dest:
    //     | { type: 'domain'; host: string; port: number }
    //     | { type: 'ipv4'; host: string; port: number },
    // ): Promise<{ rep: number; sock: Socket }> {
    //   const sock = connect({ host: '127.0.0.1', port: socksPort })
    //   await once(sock, 'connect')
    //   sock.write(Buffer.from([0x05, 0x01, 0x00]))
    //   const [method] = (await once(sock, 'data')) as [Buffer]
    //   expect([...method]).toEqual([0x05, 0x00])
    //   const portBytes = Buffer.from([(dest.port >> 8) & 0xff, dest.port & 0xff])
    //   const addr =
    //     dest.type === 'domain'
    //       ? Buffer.concat([
    //           Buffer.from([0x03, dest.host.length]),
    //           Buffer.from(dest.host, 'utf8'),
    //         ])
    //       : Buffer.from([0x01, ...dest.host.split('.').map(Number)])
    //   sock.write(
    //     Buffer.concat([Buffer.from([0x05, 0x01, 0x00]), addr, portBytes]),
    //   )
    //   const [reply] = (await once(sock, 'data')) as [Buffer]
    //   return { rep: reply[1]!, sock }
    // }

    test(
      'SOCKS: allow-listed name resolving to loopback gets "not allowed by ruleset"',
      () async {
        // const socksPort = await startSocks()
        // const { rep, sock } = await socksConnect(socksPort, {
        //   type: 'domain',
        //   host: 'rebind.example.com',
        //   port: upstreamPort,
        // })
        // sock.destroy()
        // expect(rep).toBe(0x02)
        // expect(denials).toEqual([
        //   {
        //     host: 'rebind.example.com',
        //     port: upstreamPort,
        //     reason: 'resolved to a loopback address',
        //   },
        // ])
      },
      skip: 'pending port: src/sandbox/socks-proxy.ts',
    );

    test('SOCKS: an IP-literal destination is still granted', () async {
      // const socksPort = await startSocks()
      // const { rep, sock } = await socksConnect(socksPort, {
      //   type: 'ipv4',
      //   host: '127.0.0.1',
      //   port: upstreamPort,
      // })
      // expect(rep).toBe(0x00)
      // sock.write(
      //   `GET /via-socks HTTP/1.1\r\nHost: 127.0.0.1:${upstreamPort}\r\nConnection: close\r\n\r\n`,
      // )
      // let buf = ''
      // sock.on('data', d => (buf += d.toString()))
      // await once(sock, 'close')
      // expect(buf).toContain('upstream-ok')
      // expect(denials).toEqual([])
    }, skip: 'pending port: src/sandbox/socks-proxy.ts');

    test(
      'SOCKS: a permitted resolution is dialed at the resolved address',
      () async {
        // const socksPort = await startSocks(
        //   createResolvedAddressGuard({ resolve, allowedDomains: ['127.0.0.1'] }),
        // )
        // const { rep, sock } = await socksConnect(socksPort, {
        //   type: 'domain',
        //   host: 'devbox.example.com',
        //   port: upstreamPort,
        // })
        // expect(rep).toBe(0x00)
        // sock.write(
        //   `GET /via-socks-name HTTP/1.1\r\nHost: devbox.example.com\r\nConnection: close\r\n\r\n`,
        // )
        // let buf = ''
        // sock.on('data', d => (buf += d.toString()))
        // await once(sock, 'close')
        // expect(buf).toContain('upstream-ok')
        // expect(upstreamHits).toEqual([
        //   'GET /via-socks-name host=devbox.example.com',
        // ])
      },
      skip: 'pending port: src/sandbox/socks-proxy.ts',
    );
  });

  // ---------------------------------------------------------------------------
  // TLS-terminated leg: the upstream is dialed through the same lookup and the
  // request made to the vetted address, with the hostname in Host and SNI.
  // Driven with curl (a real CONNECT-through-proxy client). The positive case
  // relies on the runtime verifying the upstream certificate against
  // `servername` rather than the address — true for Node and Bun >= 1.3.11.
  // ---------------------------------------------------------------------------
  group('resolved-address-guard: TLS-terminated upstream leg', () {
    // Upstream setup, kept as written until src/sandbox/tls-terminate-proxy.ts are ported.
    // // Every case runs a TLS-terminating proxy: skipped where none can run.
    // const it = testWithTls
    // const ca = createMitmCA({ caCertPath: CA_CERT, caKeyPath: CA_KEY })
    // const UP_HOST = 'devbox.example.com'
    // let upstream: ReturnType<typeof createHttpsServer>
    // let upstreamPort: number
    // let upstreamHits: string[]
    // let denials: Denial[]
    // const closers: Array<() => Promise<unknown>> = []

    // beforeEach(async () => {
    //   upstreamHits = []
    //   denials = []
    //   // Leaf for the HOSTNAME, served on 127.0.0.1: a request that reaches it
    //   // verified proves the upstream leg dialed the resolved address while
    //   // keeping SNI/verification on the name.
    //   const leaf = mintLeafCert(ca, UP_HOST)
    //   const leafOnly = leaf.certPem.match(
    //     /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----\r?\n?/,
    //   )![0]
    //   upstream = createHttpsServer(
    //     { cert: leafOnly, key: leaf.keyPem },
    //     (req, res) => {
    //       let body = ''
    //       req.setEncoding('utf8').on('data', c => (body += c))
    //       req.on('end', () => {
    //         upstreamHits.push(
    //           `${req.method} ${req.url}` + (body ? ` body=${body}` : ''),
    //         )
    //         res.writeHead(200, { 'x-upstream-host': String(req.headers.host) })
    //         res.end('tls-upstream-ok')
    //       })
    //     },
    //   )
    //   await new Promise<void>(r => upstream.listen(0, '127.0.0.1', () => r()))
    //   upstreamPort = (upstream.address() as AddressInfo).port
    //   closers.push(() => new Promise(r => upstream.close(() => r(undefined))))
    // })

    // afterEach(async () => {
    //   for (const c of closers.splice(0)) await c()
    // })

    // async function startTerminatingProxy(
    //   guard: ResolvedAddressGuard,
    // ): Promise<number> {
    //   const proxy = createHttpProxyServer({
    //     filter: () => true,
    //     mitmCA: ca,
    //     tlsTerminateUpstreamCA: CA_PEM,
    //     lookupFor: recordingLookupFor(guard, denials),
    //   })
    //   await new Promise<void>(r => proxy.listen(0, '127.0.0.1', () => r()))
    //   closers.push(
    //     () =>
    //       new Promise(r => {
    //         proxy.closeAllConnections?.()
    //         proxy.close(() => r(undefined))
    //       }),
    //   )
    //   return (proxy.address() as AddressInfo).port
    // }

    // async function curl(
    //   proxyPort: number,
    //   url: string,
    //   data?: string,
    // ): Promise<{ exit: number; out: string }> {
    //   const child = spawn('curl', [
    //     '-sS',
    //     '--proxy',
    //     `http://127.0.0.1:${proxyPort}`,
    //     // An empty list overrides NO_PROXY, which would send curl around
    //     // the proxy under test for 127.0.0.1.
    //     '--noproxy',
    //     '',
    //     '--cacert',
    //     CA_CERT,
    //     '--max-time',
    //     '10',
    //     '-D',
    //     '-',
    //     ...(data === undefined ? [] : ['--data-binary', data]),
    //     url,
    //   ])
    //   let out = ''
    //   child.stdout.setEncoding('utf8').on('data', c => (out += c))
    //   child.stderr.resume()
    //   await new Promise<void>(r => child.stdout.once('end', () => r()))
    //   const exit = await new Promise<number>(r =>
    //     child.on('close', code => r(code ?? 1)),
    //   )
    //   return { exit, out }
    // }

    test(
      'hostname resolving to loopback: 403 inside the terminated session, upstream untouched',
      () async {
        // const proxyPort = await startTerminatingProxy(
        //   createResolvedAddressGuard({
        //     resolve: fakeResolver({ [UP_HOST]: ['127.0.0.1'] }),
        //   }),
        // )
        // const r = await curl(proxyPort, `https://${UP_HOST}:${upstreamPort}/secret`)
        // expect(r.out).toContain('HTTP/1.1 403')
        // expect(r.out.toLowerCase()).toContain(
        //   'x-proxy-error: blocked-by-sandbox-runtime',
        // )
        // expect(r.out).not.toContain('tls-upstream-ok')
        // expect(denials).toEqual([
        //   {
        //     host: UP_HOST,
        //     port: upstreamPort,
        //     reason: 'resolved to a loopback address',
        //   },
        // ])
      },
      skip: 'pending port: src/sandbox/tls-terminate-proxy.ts',
    );

    test(
      'non-TLS bytes after the sniff path already answered 200: denied dial closes the tunnel and records the violation',
      () async {
        // const proxyPort = await startTerminatingProxy(
        //   createResolvedAddressGuard({
        //     resolve: fakeResolver({ [UP_HOST]: ['127.0.0.1'] }),
        //   }),
        // )
        // const sock = connect({ host: '127.0.0.1', port: proxyPort })
        // await once(sock, 'connect')
        // sock.write(
        //   `CONNECT ${UP_HOST}:${upstreamPort} HTTP/1.1\r\nHost: ${UP_HOST}:${upstreamPort}\r\n\r\n`,
        // )
        // let buf = ''
        // sock.on('data', d => {
        //   buf += d.toString('latin1')
        //   if (buf.includes('Connection Established') && !buf.includes('sent')) {
        //     buf += 'sent'
        //     sock.write('SSH-2.0-OpenSSH_9.7\r\n')
        //   }
        // })
        // await Promise.race([
        //   once(sock, 'close'),
        //   new Promise(r => setTimeout(r, 3000)),
        // ])
        // expect(buf.startsWith('HTTP/1.1 200')).toBe(true)
        // expect(buf).not.toContain('403') // a status line now would land inside the tunnel
        // expect(sock.destroyed || sock.readableEnded).toBe(true)
        // expect(denials).toEqual([
        //   {
        //     host: UP_HOST,
        //     port: upstreamPort,
        //     reason: 'resolved to a loopback address',
        //   },
        // ])
        // sock.destroy()
      },
      skip: 'pending port: src/sandbox/tls-terminate-proxy.ts',
    );

    test(
      'permitted resolution: dials the resolved address, verifies the certificate against the name',
      () async {
        // const resolve = fakeResolver({ [UP_HOST]: ['127.0.0.1'] })
        // const proxyPort = await startTerminatingProxy(
        //   createResolvedAddressGuard({
        //     resolve,
        //     allowedDomains: [`127.0.0.1:${upstreamPort}`],
        //   }),
        // )
        // const r = await curl(proxyPort, `https://${UP_HOST}:${upstreamPort}/app`)
        // expect(r.exit).toBe(0)
        // expect(r.out).toContain('HTTP/1.1 200')
        // expect(r.out).toContain('tls-upstream-ok')
        // expect(r.out).toContain(`x-upstream-host: ${UP_HOST}:${upstreamPort}`)
        // expect(resolve.calls).toContain(UP_HOST)
        // expect(denials).toEqual([])
      },
      skip: 'pending port: src/sandbox/tls-terminate-proxy.ts',
    );

    test(
      'permitted resolution: a request body reaches the upstream intact, exactly once',
      () async {
        // const proxyPort = await startTerminatingProxy(
        //   createResolvedAddressGuard({
        //     resolve: fakeResolver({ [UP_HOST]: ['127.0.0.1'] }),
        //     allowedDomains: [`127.0.0.1:${upstreamPort}`],
        //   }),
        // )
        // const body = 'command=ls-refs'
        // const r = await curl(
        //   proxyPort,
        //   `https://${UP_HOST}:${upstreamPort}/upload`,
        //   body,
        // )
        // expect(r.exit).toBe(0)
        // expect(r.out).toContain('HTTP/1.1 200')
        // expect(upstreamHits).toEqual([`POST /upload body=${body}`])
      },
      skip: 'pending port: src/sandbox/tls-terminate-proxy.ts',
    );
  });
}
