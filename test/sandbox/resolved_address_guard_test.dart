// Ported from sandbox-runtime test/sandbox/resolved-address-guard.test.ts @ 0bbebed.
// ignore_for_file: constant_identifier_names, non_constant_identifier_names, slash_for_doc_comments
import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:sandbox_runtime/src/node/dns.dart' as dns;
import 'package:sandbox_runtime/src/node/errno.dart';
import 'package:sandbox_runtime/src/node/events.dart' as events;
import 'package:sandbox_runtime/src/node/http.dart' as http;
import 'package:sandbox_runtime/src/node/https.dart' as https;
import 'package:sandbox_runtime/src/node/net.dart' as net;
import 'package:sandbox_runtime/src/sandbox/http_proxy.dart';
import 'package:sandbox_runtime/src/sandbox/mitm_ca.dart';
import 'package:sandbox_runtime/src/sandbox/mitm_leaf.dart';
import 'package:sandbox_runtime/src/sandbox/parent_proxy.dart'
    show DirectLookup;
import 'package:sandbox_runtime/src/sandbox/socks_proxy.dart';
import 'package:sandbox_runtime/src/sandbox/address.dart';
import 'package:sandbox_runtime/src/sandbox/resolved_address_guard.dart'
    as guard;
import 'package:sandbox_runtime/src/sandbox/sandbox_config.dart';
import 'package:path/path.dart' as path;
import 'package:test/test.dart';

import '../helpers/emitted_connections.dart' show canServeEmittedConnections;

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

// Dart: upstream's `const it = testWithTls`, which `test` cannot alias.
final Object _tlsSkip = canServeEmittedConnections
    ? false
    : 'TLS termination unavailable';

typedef Denial = ({String host, int port, String reason});

/** What the manager does: the guard's lookup for the port, recording refusals. */
DirectLookup recordingLookupFor(
  guard.ResolvedAddressGuard g,
  List<Denial> denials,
) {
  return (port, [encodedCommand]) =>
      (hostname, options, callback) =>
          g.lookupFor(port)(hostname, options, (err, address, [family]) {
            if (guard.isResolvedAddressDenied(err)) {
              denials.add((
                host: hostname,
                port: port,
                reason: (err as guard.ResolvedAddressDeniedError).reason,
              ));
            }
            callback(err, address, family);
          });
}

// Dart: the object literals upstream hands createHttpProxyServer /
// createSocksProxyServer; every option not named here is absent (null).
class _HttpOptions implements HttpProxyServerOptions {
  _HttpOptions({this.lookupFor, this.mitmCA, this.tlsTerminateUpstreamCA});
  @override
  final DirectLookup? lookupFor;
  @override
  final MitmCA? mitmCA;
  @override
  final dynamic tlsTerminateUpstreamCA;
  @override
  FutureOr<bool> filter(
    int port,
    String host,
    dynamic socket, [
    String? encodedCommand,
    void Function(String reason)? explain,
  ]) => true;
  @override
  dynamic noSuchMethod(Invocation invocation) => null;
}

class _SocksOptions implements SocksProxyServerOptions {
  _SocksOptions({this.lookupFor});
  @override
  final DirectLookup? lookupFor;
  @override
  FutureOr<bool> filter(int port, String host, [String? encodedCommand]) =>
      true;
  @override
  dynamic noSuchMethod(Invocation invocation) => null;
}

String _utf8(Object? d) => d is String ? d : utf8.decode(d as List<int>);
String _latin1(Object? d) => d is String ? d : latin1.decode(d as List<int>);

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
    late http.NodeHttpServer upstream;
    late int upstreamPort;
    late List<String> upstreamHits;
    late List<Denial> denials;
    final closers = <Future<void> Function()>[];

    setUp(() async {
      upstreamHits = [];
      denials = [];
      upstream = http.createServer((
        http.IncomingMessage req,
        http.ServerResponse res,
      ) {
        var body = '';
        req.setEncoding('utf8').on('data', (Object? c) => body += _utf8(c));
        req.on('end', () {
          upstreamHits.add(
            '${req.method} ${req.url} host=${req.headers['host']}${body.isNotEmpty ? ' body=$body' : ''}',
          );
          res.writeHead(200, {'Content-Type': 'text/plain'});
          res.end('upstream-ok');
        });
      });
      upstream.listen(0, '127.0.0.1');
      await events.once(upstream, 'listening');
      upstreamPort = (upstream.address() as net.NodeAddress).port;
    });

    tearDown(() async {
      for (final c in closers.toList().reversed) {
        await c();
      }
      closers.clear();
      upstream.close();
    });

    final resolve = fakeResolver({
      'rebind.example.com': ['127.0.0.1'],
      'metadata.example.com': ['169.254.169.254'],
      'intranet.example.com': ['127.0.0.1'],
      'devbox.example.com': ['127.0.0.1'],
      'localhost': ['127.0.0.1'],
    });

    Future<int> startHttpProxy([guard.ResolvedAddressGuard? g]) async {
      g ??= guard.createResolvedAddressGuard(resolve: resolve.resolve);
      final proxy = createHttpProxyServer(
        _HttpOptions(lookupFor: recordingLookupFor(g, denials)),
      );
      proxy.listen(0, '127.0.0.1');
      await events.once(proxy, 'listening');
      closers.add(() {
        final done = Completer<void>();
        proxy.closeAllConnections();
        proxy.close(() => done.complete());
        return done.future;
      });
      return (proxy.address() as net.NodeAddress).port;
    }

    /** One request over a raw socket; resolves once the response is complete (Content-Length) or the socket closes. */
    Future<String> rawExchange(int proxyPort, String payload) async {
      final sock = net.connect({'host': '127.0.0.1', 'port': proxyPort});
      await events.once(sock, 'connect');
      sock.write(payload);
      var buf = '';
      final done = Completer<void>();
      void resolveDone() {
        if (!done.isCompleted) done.complete();
      }

      sock.on('data', (Object? d) {
        buf += _latin1(d);
        final headEnd = buf.indexOf('\r\n\r\n');
        if (headEnd == -1) return;
        final length = RegExp(
          r'content-length: (\d+)',
          caseSensitive: false,
        ).firstMatch(buf.substring(0, headEnd));
        if (length != null &&
            buf.length - headEnd - 4 >= int.parse(length.group(1)!)) {
          resolveDone();
        }
      });
      sock.on('end', resolveDone);
      sock.on('close', resolveDone);
      await done.future;
      sock.destroy();
      return buf;
    }

    test(
      'plain HTTP: allow-listed name resolving to loopback is refused with 403, upstream untouched',
      () async {
        final proxyPort = await startHttpProxy();
        final resp = await rawExchange(
          proxyPort,
          'GET http://rebind.example.com:$upstreamPort/secret HTTP/1.1\r\n'
          'Host: rebind.example.com:$upstreamPort\r\nConnection: close\r\n\r\n',
        );
        expect(resp.startsWith('HTTP/1.1 403'), isTrue);
        expect(resp, contains('X-Proxy-Error: blocked-by-sandbox-runtime'));
        expect(
          resp,
          contains(
            'Connection to rebind.example.com blocked: resolved to a loopback address',
          ),
        );
        expect(upstreamHits, isEmpty);
        expect(denials, [
          (
            host: 'rebind.example.com',
            port: upstreamPort,
            reason: 'resolved to a loopback address',
          ),
        ]);
      },
    );

    test('plain HTTP: an allow-listed IP literal is still dialed', () async {
      final proxyPort = await startHttpProxy();
      final resp = await rawExchange(
        proxyPort,
        'GET http://127.0.0.1:$upstreamPort/ok HTTP/1.1\r\n'
        'Host: 127.0.0.1:$upstreamPort\r\nConnection: close\r\n\r\n',
      );
      expect(resp.startsWith('HTTP/1.1 200'), isTrue);
      expect(resp, contains('upstream-ok'));
      expect(denials, isEmpty);
    });

    test('plain HTTP: "localhost" may resolve to loopback', () async {
      final proxyPort = await startHttpProxy();
      final resp = await rawExchange(
        proxyPort,
        'GET http://localhost:$upstreamPort/ok HTTP/1.1\r\n'
        'Host: localhost:$upstreamPort\r\nConnection: close\r\n\r\n',
      );
      expect(resp.startsWith('HTTP/1.1 200'), isTrue);
      expect(upstreamHits, ['GET /ok host=localhost:$upstreamPort']);
    });

    test(
      'plain HTTP: a permitted resolution dials the resolved address with the Host header preserved',
      () async {
        final proxyPort = await startHttpProxy(
          guard.createResolvedAddressGuard(
            resolve: resolve.resolve,
            allowedDomains: ['127.0.0.1:$upstreamPort'],
          ),
        );
        final resp = await rawExchange(
          proxyPort,
          'GET http://devbox.example.com:$upstreamPort/app HTTP/1.1\r\n'
          'Host: devbox.example.com:$upstreamPort\r\nConnection: close\r\n\r\n',
        );
        expect(resp.startsWith('HTTP/1.1 200'), isTrue);
        expect(upstreamHits, [
          'GET /app host=devbox.example.com:$upstreamPort',
        ]);
        expect(resolve.calls, contains('devbox.example.com'));
      },
    );

    test(
      'plain HTTP: a permitted resolution forwards a streamed request body intact, exactly once',
      () async {
        final proxyPort = await startHttpProxy(
          guard.createResolvedAddressGuard(
            resolve: resolve.resolve,
            allowedDomains: ['127.0.0.1:$upstreamPort'],
          ),
        );
        // Chunked from the client, so the proxy re-frames the upstream body.
        const body = '{"password":"hunter2"}';
        final resp = await rawExchange(
          proxyPort,
          'POST http://devbox.example.com:$upstreamPort/submit HTTP/1.1\r\n'
          'Host: devbox.example.com:$upstreamPort\r\n'
          'Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n'
          '${body.length.toRadixString(16)}\r\n$body\r\n0\r\n\r\n',
        );
        expect(resp.startsWith('HTTP/1.1 200'), isTrue);
        expect(upstreamHits, [
          'POST /submit host=devbox.example.com:$upstreamPort body=$body',
        ]);
      },
    );

    test('plain HTTP: an embedder-configured range is refused too', () async {
      final proxyPort = await startHttpProxy(
        guard.createResolvedAddressGuard(
          resolve: fakeResolver({
            'intranet.example.com': ['10.20.30.40'],
          }).resolve,
          deniedResolvedAddresses: ['10.0.0.0/8'],
        ),
      );
      final resp = await rawExchange(
        proxyPort,
        'GET http://intranet.example.com/ HTTP/1.1\r\nHost: intranet.example.com\r\nConnection: close\r\n\r\n',
      );
      expect(resp.startsWith('HTTP/1.1 403'), isTrue);
      expect(
        denials.isEmpty ? null : denials[0].reason,
        'resolved to a listed address',
      );
    });

    test(
      'CONNECT: allow-listed name resolving to loopback gets 403 instead of a tunnel',
      () async {
        final proxyPort = await startHttpProxy();
        final resp = await rawExchange(
          proxyPort,
          'CONNECT rebind.example.com:$upstreamPort HTTP/1.1\r\nHost: rebind.example.com:$upstreamPort\r\n\r\n',
        );
        // The class is the status phrase too: few clients show the body.
        expect(
          resp,
          startsWith('HTTP/1.1 403 resolved to a loopback address\r\n'),
        );
        expect(resp, contains('X-Proxy-Error: blocked-by-sandbox-runtime'));
        expect(
          resp,
          endsWith(
            '\r\n\r\nConnection to rebind.example.com blocked: resolved to a loopback address',
          ),
        );
        expect(resp, isNot(contains('127.0.0.1')));
        expect(denials.map((d) => '${d.host}:${d.port}').toList(), [
          'rebind.example.com:$upstreamPort',
        ]);
      },
    );

    test('CONNECT: link-local (metadata-style) resolution is refused', () async {
      final proxyPort = await startHttpProxy();
      final resp = await rawExchange(
        proxyPort,
        'CONNECT metadata.example.com:80 HTTP/1.1\r\nHost: metadata.example.com:80\r\n\r\n',
      );
      expect(resp.startsWith('HTTP/1.1 403'), isTrue);
      expect(
        denials.isEmpty ? null : denials[0].reason,
        'resolved to a link-local address',
      );
    });

    test('CONNECT: an allow-listed IP literal still tunnels', () async {
      final proxyPort = await startHttpProxy();
      final sock = net.connect({'host': '127.0.0.1', 'port': proxyPort});
      await events.once(sock, 'connect');
      sock.write(
        'CONNECT 127.0.0.1:$upstreamPort HTTP/1.1\r\nHost: 127.0.0.1:$upstreamPort\r\n\r\n',
      );
      final first = await events.once(sock, 'data');
      expect(_utf8(first[0]), contains('200 Connection Established'));
      sock.write(
        'GET /tunnelled HTTP/1.1\r\nHost: 127.0.0.1:$upstreamPort\r\nConnection: close\r\n\r\n',
      );
      var buf = '';
      sock.on('data', (Object? d) => buf += _utf8(d));
      await events.once(sock, 'close');
      expect(buf, contains('upstream-ok'));
      expect(denials, isEmpty);
    });

    // --- SOCKS -------------------------------------------------------------

    Future<int> startSocks([guard.ResolvedAddressGuard? g]) async {
      g ??= guard.createResolvedAddressGuard(resolve: resolve.resolve);
      final wrapper = createSocksProxyServer(
        _SocksOptions(lookupFor: recordingLookupFor(g, denials)),
      );
      final tcp = net.createServer((net.NodeSocket s) {
        wrapper.handleConnection(s);
      });
      tcp.listen(0, '127.0.0.1');
      await events.once(tcp, 'listening');
      closers.add(() async {
        await wrapper.close();
        tcp.close();
      });
      return (tcp.address() as net.NodeAddress).port;
    }

    /** No-auth greeting, then CONNECT; resolves with the reply's REP byte. */
    Future<({int rep, net.NodeSocket sock})> socksConnect(
      int socksPort,
      ({String type, String host, int port}) dest,
    ) async {
      final sock = net.connect({'host': '127.0.0.1', 'port': socksPort});
      await events.once(sock, 'connect');
      sock.write(Uint8List.fromList([0x05, 0x01, 0x00]));
      final method = await events.once(sock, 'data');
      expect(List<int>.from(method[0] as List<int>), [0x05, 0x00]);
      final portBytes = [(dest.port >> 8) & 0xff, dest.port & 0xff];
      final addr = dest.type == 'domain'
          ? [0x03, dest.host.length, ...utf8.encode(dest.host)]
          : [0x01, ...dest.host.split('.').map(int.parse)];
      sock.write(Uint8List.fromList([0x05, 0x01, 0x00, ...addr, ...portBytes]));
      final reply = await events.once(sock, 'data');
      return (rep: (reply[0] as List<int>)[1], sock: sock);
    }

    test(
      'SOCKS: allow-listed name resolving to loopback gets "not allowed by ruleset"',
      () async {
        final socksPort = await startSocks();
        final r = await socksConnect(socksPort, (
          type: 'domain',
          host: 'rebind.example.com',
          port: upstreamPort,
        ));
        r.sock.destroy();
        expect(r.rep, 0x02);
        expect(denials, [
          (
            host: 'rebind.example.com',
            port: upstreamPort,
            reason: 'resolved to a loopback address',
          ),
        ]);
      },
    );

    test('SOCKS: an IP-literal destination is still granted', () async {
      final socksPort = await startSocks();
      final r = await socksConnect(socksPort, (
        type: 'ipv4',
        host: '127.0.0.1',
        port: upstreamPort,
      ));
      expect(r.rep, 0x00);
      r.sock.write(
        'GET /via-socks HTTP/1.1\r\nHost: 127.0.0.1:$upstreamPort\r\nConnection: close\r\n\r\n',
      );
      var buf = '';
      r.sock.on('data', (Object? d) => buf += _utf8(d));
      await events.once(r.sock, 'close');
      expect(buf, contains('upstream-ok'));
      expect(denials, isEmpty);
    });

    test(
      'SOCKS: a permitted resolution is dialed at the resolved address',
      () async {
        final socksPort = await startSocks(
          guard.createResolvedAddressGuard(
            resolve: resolve.resolve,
            allowedDomains: ['127.0.0.1'],
          ),
        );
        final r = await socksConnect(socksPort, (
          type: 'domain',
          host: 'devbox.example.com',
          port: upstreamPort,
        ));
        expect(r.rep, 0x00);
        r.sock.write(
          'GET /via-socks-name HTTP/1.1\r\nHost: devbox.example.com\r\nConnection: close\r\n\r\n',
        );
        var buf = '';
        r.sock.on('data', (Object? d) => buf += _utf8(d));
        await events.once(r.sock, 'close');
        expect(buf, contains('upstream-ok'));
        expect(upstreamHits, ['GET /via-socks-name host=devbox.example.com']);
      },
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
    // Every case runs a TLS-terminating proxy: skipped where none can run.
    final ca = createMitmCA(caCertPath: CA_CERT, caKeyPath: CA_KEY);
    const UP_HOST = 'devbox.example.com';
    late https.Server upstream;
    late int upstreamPort;
    late List<String> upstreamHits;
    late List<Denial> denials;
    final closers = <Future<void> Function()>[];

    setUp(() async {
      upstreamHits = [];
      denials = [];
      // Leaf for the HOSTNAME, served on 127.0.0.1: a request that reaches it
      // verified proves the upstream leg dialed the resolved address while
      // keeping SNI/verification on the name.
      final leaf = mintLeafCert(ca, UP_HOST);
      final leafOnly = RegExp(
        r'-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----\r?\n?',
      ).firstMatch(leaf.certPem)!.group(0)!;
      upstream = https.createServer({'cert': leafOnly, 'key': leaf.keyPem}, (
        http.IncomingMessage req,
        http.ServerResponse res,
      ) {
        var body = '';
        req.setEncoding('utf8').on('data', (Object? c) => body += _utf8(c));
        req.on('end', () {
          upstreamHits.add(
            '${req.method} ${req.url}${body.isNotEmpty ? ' body=$body' : ''}',
          );
          res.writeHead(200, {'x-upstream-host': '${req.headers['host']}'});
          res.end('tls-upstream-ok');
        });
      });
      final listening = Completer<void>();
      upstream.listen(0, '127.0.0.1', () => listening.complete());
      await listening.future;
      upstreamPort = (upstream.address() as net.NodeAddress).port;
      closers.add(() {
        final done = Completer<void>();
        upstream.close(() => done.complete());
        return done.future;
      });
    });

    tearDown(() async {
      for (final c in closers.toList().reversed) {
        await c();
      }
      closers.clear();
    });

    Future<int> startTerminatingProxy(guard.ResolvedAddressGuard g) async {
      final proxy = createHttpProxyServer(
        _HttpOptions(
          mitmCA: ca,
          tlsTerminateUpstreamCA: CA_PEM,
          lookupFor: recordingLookupFor(g, denials),
        ),
      );
      final listening = Completer<void>();
      proxy.listen(0, '127.0.0.1', () => listening.complete());
      await listening.future;
      closers.add(() {
        final done = Completer<void>();
        proxy.closeAllConnections();
        proxy.close(() => done.complete());
        return done.future;
      });
      return (proxy.address() as net.NodeAddress).port;
    }

    Future<({int exit, String out})> curl(
      int proxyPort,
      String url, [
      String? data,
    ]) async {
      final child = await Process.start('curl', [
        '-sS',
        '--proxy',
        'http://127.0.0.1:$proxyPort',
        // An empty list overrides NO_PROXY, which would send curl around
        // the proxy under test for 127.0.0.1.
        '--noproxy',
        '',
        '--cacert',
        CA_CERT,
        '--max-time',
        '10',
        '-D',
        '-',
        if (data != null) ...['--data-binary', data],
        url,
      ]);
      child.stderr.drain<void>();
      final out = await utf8.decodeStream(child.stdout);
      final exit = await child.exitCode;
      return (exit: exit, out: out);
    }

    test(
      'hostname resolving to loopback: 403 inside the terminated session, upstream untouched',
      () async {
        final proxyPort = await startTerminatingProxy(
          guard.createResolvedAddressGuard(
            resolve: fakeResolver({
              UP_HOST: ['127.0.0.1'],
            }).resolve,
          ),
        );
        final r = await curl(
          proxyPort,
          'https://$UP_HOST:$upstreamPort/secret',
        );
        expect(r.out, contains('HTTP/1.1 403'));
        expect(
          r.out.toLowerCase(),
          contains('x-proxy-error: blocked-by-sandbox-runtime'),
        );
        expect(r.out, isNot(contains('tls-upstream-ok')));
        expect(denials, [
          (
            host: UP_HOST,
            port: upstreamPort,
            reason: 'resolved to a loopback address',
          ),
        ]);
      },
      skip: _tlsSkip,
    );

    test(
      'non-TLS bytes after the sniff path already answered 200: denied dial closes the tunnel and records the violation',
      () async {
        final proxyPort = await startTerminatingProxy(
          guard.createResolvedAddressGuard(
            resolve: fakeResolver({
              UP_HOST: ['127.0.0.1'],
            }).resolve,
          ),
        );
        final sock = net.connect({'host': '127.0.0.1', 'port': proxyPort});
        await events.once(sock, 'connect');
        sock.write(
          'CONNECT $UP_HOST:$upstreamPort HTTP/1.1\r\nHost: $UP_HOST:$upstreamPort\r\n\r\n',
        );
        var buf = '';
        sock.on('data', (Object? d) {
          buf += _latin1(d);
          if (buf.contains('Connection Established') && !buf.contains('sent')) {
            buf += 'sent';
            sock.write('SSH-2.0-OpenSSH_9.7\r\n');
          }
        });
        await Future.any([
          events.once(sock, 'close'),
          Future<void>.delayed(const Duration(milliseconds: 3000)),
        ]);
        expect(buf.startsWith('HTTP/1.1 200'), isTrue);
        expect(
          buf,
          isNot(contains('403')),
        ); // a status line now would land inside the tunnel
        expect(sock.destroyed || sock.readableEnded, isTrue);
        expect(denials, [
          (
            host: UP_HOST,
            port: upstreamPort,
            reason: 'resolved to a loopback address',
          ),
        ]);
        sock.destroy();
      },
      skip: _tlsSkip,
    );

    test(
      'permitted resolution: dials the resolved address, verifies the certificate against the name',
      () async {
        final resolve = fakeResolver({
          UP_HOST: ['127.0.0.1'],
        });
        final proxyPort = await startTerminatingProxy(
          guard.createResolvedAddressGuard(
            resolve: resolve.resolve,
            allowedDomains: ['127.0.0.1:$upstreamPort'],
          ),
        );
        final r = await curl(proxyPort, 'https://$UP_HOST:$upstreamPort/app');
        expect(r.exit, 0);
        expect(r.out, contains('HTTP/1.1 200'));
        expect(r.out, contains('tls-upstream-ok'));
        expect(r.out, contains('x-upstream-host: $UP_HOST:$upstreamPort'));
        expect(resolve.calls, contains(UP_HOST));
        expect(denials, isEmpty);
      },
      skip: _tlsSkip,
    );

    test(
      'permitted resolution: a request body reaches the upstream intact, exactly once',
      () async {
        final proxyPort = await startTerminatingProxy(
          guard.createResolvedAddressGuard(
            resolve: fakeResolver({
              UP_HOST: ['127.0.0.1'],
            }).resolve,
            allowedDomains: ['127.0.0.1:$upstreamPort'],
          ),
        );
        const body = 'command=ls-refs';
        final r = await curl(
          proxyPort,
          'https://$UP_HOST:$upstreamPort/upload',
          body,
        );
        expect(r.exit, 0);
        expect(r.out, contains('HTTP/1.1 200'));
        expect(upstreamHits, ['POST /upload body=$body']);
      },
      skip: _tlsSkip,
    );
  });
}
