// Ported from sandbox-runtime src/sandbox/resolved-address-guard.ts @ 24eb39e.
// ignore_for_file: constant_identifier_names, dangling_library_doc_comments
// ignore_for_file: slash_for_doc_comments
// ignore_for_file: non_constant_identifier_names

import 'dart:convert';

import '../node/dns.dart' as dns;
import '../node/errno.dart';
import '../node/net.dart' as net;
import '../node/os.dart' as os;
import '../utils/debug.dart';
import 'address.dart';
import 'domain_pattern.dart' as domain_pattern;

/**
 * Resolved-address guard for hostname destinations.
 *
 * The domain allowlist decides by name, but whoever controls a permitted
 * name's DNS records (or any label under a permitted wildcard) decides what
 * that name resolves to. Without a check on the resolved address, an
 * allow-listed name can be pointed at the loopback interface, a link-local
 * address, or address space the embedder considers private, and the proxy
 * will dial it. This module wraps `dns.lookup` so a direct dial resolves
 * once, drops denied addresses, and connects to a surviving one — the
 * address that passed the check is the address dialed, with no second
 * resolution in between.
 *
 * Scope: hostnames only. An IP literal on the allowlist is an explicit
 * choice and is never re-judged here; conversely, a name may resolve to a
 * denied address only when that address (and port) is itself allow-listed,
 * so reaching it by name grants nothing the literal entry did not — and an
 * IP literal on the deny list is refused by name too, allowlist or not. The
 * reserved loopback names (`localhost` and anything under `.localhost`,
 * RFC 6761) resolve to loopback — that is what allow-listing them asks for —
 * or to an allow-listed literal, and to nothing else. Connections routed
 * through a parent proxy or a MITM socket are not resolved locally at all;
 * that hop resolves the name and is responsible for its own address policy.
 */

/**
 * Cloud instance-metadata / platform endpoints that live outside link-local
 * space, so `169.254.0.0/16` / `fe80::/10` do not cover them. Single
 * addresses (or a provider-reserved block), so nothing else is caught.
 */
const List<String> CLOUD_METADATA_ADDRESSES = [
  '100.100.100.200', // Alibaba Cloud
  '168.63.129.16', // Azure WireServer / host agent endpoint
  '192.0.0.192', // Oracle Cloud Infrastructure Classic
  'fd00:ec2::/32', // AWS IPv6 service block: IMDS ::254, EKS Pod Identity ::23, DNS, NTP
  'fd20:ce::254', // Google Cloud, IPv6-only instances
  'fd00:c1::a9fe:a9fe', // Oracle Cloud Infrastructure IPv6
  'fd00:42::42', // Scaleway IPv6
  'fd00:a9fe:a9fe::1', // Akamai / Linode IPv6
  'fd00:100::100:200', // Alibaba Cloud IPv6
];

/**
 * Destinations an allow-listed hostname may not resolve to, grouped by the
 * class a refusal reports. Addresses assigned to this host's own interfaces
 * are denied too (see [localInterfaceAddresses]), since a service
 * bound to 0.0.0.0 answers on those exactly as on loopback. Private-use
 * ranges (RFC 1918, ULA, CGNAT) are deliberately absent: allow-listing an
 * intranet hostname is legitimate, so those are opt-in via
 * `network.deniedResolvedAddresses`. IPv4 rules also bind the IPv6 forms
 * that carry an IPv4 address (see [embeddedIPv4]).
 */
const List<(String, List<String>)> DENIED_CLASSES = [
  ('a loopback address', LOOPBACK_RANGES),
  (
    'an unspecified address',
    ['0.0.0.0/8', '::'],
  ), // connects to the local host on common stacks
  (
    'a link-local address',
    ['169.254.0.0/16', 'fe80::/10'],
  ), // incl. most instance-metadata endpoints
  ('a multicast address', ['224.0.0.0/4', 'ff00::/8']),
  ('the broadcast address', ['255.255.255.255']),
  ('a cloud metadata address', CLOUD_METADATA_ADDRESSES),
];

/** Refusal classes in priority order, so a multi-address reason reads the same however the resolver ordered its answer. */
final List<String> REASON_ORDER = [
  'a deny-listed address',
  ...DENIED_CLASSES.map((entry) => entry.$1),
  'a listed address',
  "one of this host's addresses",
  'a non-loopback address',
  'an unparsable address',
];

/** Unicast addresses currently assigned to this host's network interfaces. */
List<String> localInterfaceAddresses() {
  late Map<String, List<os.NetworkInterfaceAddress>?> byInterface;
  try {
    byInterface = os.networkInterfaces();
  } catch (error) {
    if (error is UnimplementedError) rethrow;
    // Interface enumeration is unavailable in some restricted environments;
    // the fixed denied set still applies.
    return [];
  }
  return byInterface.values
      .expand((addresses) => addresses ?? const <os.NetworkInterfaceAddress>[])
      .map((address) => address.address)
      .toList();
}

class ResolvedAddressDeniedError extends dns.NodeLookupError {
  /**
   * @param reason parenthetical for the violation line and the client, e.g.
   *   `resolved to a loopback address` — the class, never the address, which
   *   the sandboxed client should not learn from a refusal.
   * @param addresses the refused addresses, for operator logs.
   */
  ResolvedAddressDeniedError(this.hostname, this.reason, this.addresses)
    : super(
        'ERR_SRT_RESOLVED_ADDRESS_DENIED',
        'Connection to $hostname blocked: $reason',
      );

  final String hostname;
  final String reason;
  final List<String> addresses;
  final String name = 'ResolvedAddressDeniedError';

  @override
  String toString() => '$name: $message';
}

bool isResolvedAddressDenied(Object? err) => err is ResolvedAddressDeniedError;

typedef Resolver =
    void Function(
      String hostname,
      dns.LookupAllOptions options,
      void Function(dns.NodeLookupError? err, List<dns.LookupAddress> addresses)
      callback,
    );

/** An IP literal or CIDR range, optionally restricted to one destination port. */
sealed class _AddressRule {
  const _AddressRule();
}

class _UnscopedAddressRule extends _AddressRule {
  const _UnscopedAddressRule(this.range);
  final String range;
}

class _PortScopedAddressRule extends _AddressRule {
  const _PortScopedAddressRule(this.range, this.port);
  final String range;
  final int? port;
}

/**
 * The guard reads the same three lists the name filter does, in the same
 * order of precedence: an IP literal in `deniedDomains` is refused however
 * it is reached; an IP literal in `allowedDomains` (with its `:port`) is
 * what a name MAY resolve to even though the address is otherwise denied —
 * so a name reaches nothing the literal entry does not already permit; and
 * `deniedResolvedAddresses` extends the built-in denied set.
 */
class ResolvedAddressGuardOptions {
  const ResolvedAddressGuardOptions({
    this.allowedDomains,
    this.deniedDomains,
    this.deniedResolvedAddresses,
    this.resolve,
    this.localAddresses,
  });

  final List<String>? allowedDomains;
  final List<String>? deniedDomains;
  /** IPs / CIDRs denied in addition to the built-in DENIED_CLASSES and this host's own addresses. */
  final List<String>? deniedResolvedAddresses;
  /** Name resolver; defaults to `dns.lookup`. Test seam. */
  final Resolver? resolve;
  /** This host's interface addresses; defaults to [localInterfaceAddresses], read per lookup. Test seam. */
  final List<String> Function()? localAddresses;
}

abstract class ResolvedAddressGuard {
  /**
   * Whether a connection to `hostname:port` may use resolved `address`.
   * Always true when `hostname` is itself an IP literal.
   */
  bool permits(String hostname, String address, int port);

  /**
   * `lookup` for a `net.connect` to `port` (see `dialDirect`): resolves via
   * the configured resolver, removes addresses `permits` rejects, and fails
   * with [ResolvedAddressDeniedError] when none remain.
   */
  net.LookupFunction lookupFor(int port);
}

/** Port-scoped BlockLists: `anyPort` plus one list per port-qualified rule. */
class _RuleSet {
  _RuleSet({required this.anyPort, required this.byPort});

  final net.BlockList anyPort;
  final Map<int, net.BlockList> byPort;
}

_RuleSet _buildRuleSet(List<_AddressRule> rules) {
  final set = _RuleSet(anyPort: net.BlockList(), byPort: {});
  for (final rule in rules) {
    final String range;
    final int? port;
    if (rule is _UnscopedAddressRule) {
      range = rule.range;
      port = null;
    } else {
      final scoped = rule as _PortScopedAddressRule;
      range = scoped.range;
      port = scoped.port;
    }
    net.BlockList? list = port == null ? set.anyPort : set.byPort[port];
    if (list == null) set.byPort[port!] = list = net.BlockList();
    if (!addRange(list, range)) {
      throw NodeException(
        'Invalid IP address or CIDR range: ${_jsonString(range)}',
      );
    }
  }
  return set;
}

String _jsonString(String value) => jsonEncode(value);

_RuleSet _addressRuleSet(List<({String range, int? port})> rules) =>
    _buildRuleSet([
      for (final rule in rules) _PortScopedAddressRule(rule.range, rule.port),
    ]);

_RuleSet _rangeRuleSet(List<String> ranges) =>
    _buildRuleSet([for (final range in ranges) _UnscopedAddressRule(range)]);

bool _inRuleSet(_RuleSet set, String address, int port) {
  final forPort = set.byPort[port];
  return addressInSet(set.anyPort, address) ||
      (forPort != null && addressInSet(forPort, address));
}

ResolvedAddressGuard createResolvedAddressGuard({
  List<String>? allowedDomains,
  List<String>? deniedDomains,
  List<String>? deniedResolvedAddresses,
  Resolver? resolve,
  List<String> Function()? localAddresses,
}) {
  final opts = ResolvedAddressGuardOptions(
    allowedDomains: allowedDomains,
    deniedDomains: deniedDomains,
    deniedResolvedAddresses: deniedResolvedAddresses,
    resolve: resolve,
    localAddresses: localAddresses,
  );
  final refused = _addressRuleSet(
    domain_pattern.ipLiteralRules(opts.deniedDomains ?? const <String>[]),
  );
  final allowed = _addressRuleSet(
    domain_pattern.ipLiteralRules(opts.allowedDomains ?? const <String>[]),
  );
  final denied = <(String, _RuleSet)>[
    ...DENIED_CLASSES.map((entry) => (entry.$1, _rangeRuleSet(entry.$2))),
    (
      'a listed address',
      _rangeRuleSet(opts.deniedResolvedAddresses ?? const <String>[]),
    ),
  ];
  final Resolver resolver = opts.resolve ?? _dnsLookupAll;

  /** This host's addresses right now; a malformed entry from the seam is skipped. */
  net.BlockList localSet() {
    final list = net.BlockList();
    for (final address in (opts.localAddresses ?? localInterfaceAddresses)()) {
      addRange(list, address);
    }
    return list;
  }

  /** Why `hostname:port` may not use resolved `address`, or undefined if it may. */
  String? denial(
    String hostname,
    String address,
    int port,
    net.BlockList local,
  ) {
    if (net.isIP(hostname) != 0) return null;
    if (net.isIP(address) == 0) return 'an unparsable address';
    // A NAT64 / 6to4 / IPv4-compatible answer is delivered to the IPv4
    // address it carries, so every deny is applied to that address too. The
    // carried form only ADDS denials: it never earns an allow-list carve-out
    // (that would let `::1`, whose IPv4-compatible form is `0.0.0.1`, ride a
    // carve-out for `0.0.0.1`) and does not stand in for the address in the
    // localhost rule. An IPv4-mapped answer needs no decode here — BlockList
    // matches it against the IPv4 rules in either spelling.
    final v4 = embeddedIPv4(address);
    bool denies(_RuleSet set) =>
        _inRuleSet(set, address, port) ||
        (v4 != null && _inRuleSet(set, v4, port));
    if (denies(refused)) return 'a deny-listed address';
    if (_inRuleSet(allowed, address, port)) return null;
    if (isLoopbackName(hostname)) {
      return isLoopbackAddress(address) ? null : 'a non-loopback address';
    }
    for (final (reason, set) in denied) {
      if (denies(set)) return reason;
    }
    if (addressInSet(local, address) ||
        (v4 != null && addressInSet(local, v4))) {
      return "one of this host's addresses";
    }
    return null;
  }

  net.LookupFunction lookupFor(int port) => (hostname, options, callback) {
    final allOptions = _allOptions(options);
    resolver(hostname, allOptions, (err, addresses) {
      if (err != null) {
        callback(err, null);
        return;
      }
      final local = localSet();
      final kept = <dns.LookupAddress>[];
      final dropped = <String>[];
      final whys = <String>{};
      for (final address in addresses) {
        final why = denial(hostname, address.address, port, local);
        if (why == null) {
          kept.add(address);
        } else {
          dropped.add(address.address);
          whys.add(why);
        }
      }
      // Order the classes by the built-in priority, not by the order the
      // resolver happened to return the addresses, so the reason (which
      // `ignoreViolations` matches by substring) is stable.
      final classes = REASON_ORDER.where(whys.contains).toList();
      if (dropped.isNotEmpty) {
        logForDebugging(
          'Denied address(es) for $hostname:$port: ${dropped.join(', ')} (${classes.join('; ')})',
        );
      }
      final dns.LookupAddress? first = kept.isEmpty ? null : kept.first;
      if (first == null) {
        // An empty answer without an error is possible from some resolvers.
        final Object none = dropped.isNotEmpty
            ? ResolvedAddressDeniedError(
                hostname,
                'resolved to ${classes.join(' / ')}',
                dropped,
              )
            : dns.NodeLookupError(
                'ENOTFOUND',
                'getaddrinfo ENOTFOUND $hostname',
              );
        callback(none as dns.NodeLookupError, null);
        return;
      }
      if (_lookupAllOptions(options)) {
        callback(null, dns.LookupResultAll(kept));
      } else {
        callback(null, dns.LookupResultAddress(first.address), first.family);
      }
    });
  };

  return _ResolvedAddressGuard(denial, localSet, lookupFor);
}

class _ResolvedAddressGuard extends ResolvedAddressGuard {
  _ResolvedAddressGuard(this._denial, this._localSet, this._lookupFor);

  final String? Function(String, String, int, net.BlockList) _denial;
  final net.BlockList Function() _localSet;
  final net.LookupFunction Function(int) _lookupFor;

  @override
  bool permits(String hostname, String address, int port) =>
      _denial(hostname, address, port, _localSet()) == null;

  @override
  net.LookupFunction lookupFor(int port) => _lookupFor(port);
}

// Node's `net.LookupFunction` receives the union `number | LookupOptions`.
// The all-address DNS request is created here while retaining the supplied
// family and resolver-order options. A map is accepted at this shim boundary
// for callers that have not yet selected a concrete options representation.
dns.LookupAllOptions _allOptions(dns.LookupOptions options) =>
    dns.LookupAllOptions(
      family: options.family,
      hints: options.hints,
      verbatim: options.verbatim,
      order: options.order,
    );

bool _lookupAllOptions(dns.LookupOptions options) => options.all == true;

void _dnsLookupAll(
  String hostname,
  dns.LookupAllOptions options,
  void Function(dns.NodeLookupError? err, List<dns.LookupAddress> addresses)
  callback,
) {
  dns.lookup(hostname, options, (err, result, [family]) {
    if (err != null) {
      callback(err, const <dns.LookupAddress>[]);
    } else if (result is dns.LookupResultAll) {
      callback(null, result.addresses);
    } else {
      throw StateError('dns.lookup all:true returned a single address');
    }
  });
}
