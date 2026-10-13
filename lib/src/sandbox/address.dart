// Ported from sandbox-runtime src/sandbox/address.ts @ 24eb39e.
// ignore_for_file: slash_for_doc_comments, dangling_library_doc_comments,
// ignore_for_file: constant_identifier_names, non_constant_identifier_names
// ignore_for_file: library_private_types_in_public_api

/**
 * IP-literal / CIDR helpers over `net.BlockList`, shared by the
 * resolved-address guard, the parent-proxy NO_PROXY matcher and config
 * validation.
 */

import 'dart:convert';

import '../node/errno.dart';
import '../node/net.dart' as net;

/** Loopback in both families (BlockList matches IPv4-mapped forms against the IPv4 rule). */
const List<String> LOOPBACK_RANGES = ['127.0.0.0/8', '::1'];

typedef _AddressFamily = String;

// Dart has no string-literal union type; this is the same `'ipv4' | 'ipv6'`
// pair the Node BlockList API accepts.
_AddressFamily? _ipFamily(String address) {
  final fam = net.isIP(address);
  return fam == 4
      ? 'ipv4'
      : fam == 6
      ? 'ipv6'
      : null;
}

typedef _AddressRange = ({String address, int prefix, _AddressFamily family});

/**
 * Parse an IP literal or CIDR range (`10.0.0.0/8`, `fc00::/7`, `::1`) into
 * the one form rules are stored in: an IPv4-mapped IPv6 entry becomes the
 * IPv4 rule it stands for (`::ffff:10.0.0.0/104` → `10.0.0.0/8`) and a zone
 * id is dropped, since matching treats both spellings alike and some
 * runtimes mis-evaluate or refuse the IPv6 ones. Undefined for anything
 * else; IPv6 is unbracketed.
 */
_AddressRange? parseAddressRange(String entry) {
  final slash = entry.indexOf('/');
  final address = _stripZone(slash == -1 ? entry : entry.substring(0, slash));
  final family = _ipFamily(address);
  if (family == null) return null;
  final max = family == 'ipv6' ? 128 : 32;
  var prefix = max;
  if (slash != -1) {
    final raw = entry.substring(slash + 1);
    if (!RegExp(r'^\d{1,3}$').hasMatch(raw)) return null;
    final number = int.parse(raw);
    if (number > max) return null;
    prefix = number;
  }
  final mapped = family == 'ipv6' ? mappedIPv4(address) : null;
  if (mapped != null) {
    return prefix < 96
        ? null
        : (address: mapped, prefix: prefix - 96, family: 'ipv4');
  }
  return (address: address, prefix: prefix, family: family);
}

/** Add an IP literal or CIDR range to `list`; false (list untouched) if malformed or refused by the runtime. */
bool addRange(net.BlockList list, String entry) {
  final range = parseAddressRange(entry);
  if (range == null) return false;
  try {
    list.addSubnet(range.address, range.prefix, range.family);
  } catch (_) {
    return false;
  }
  return true;
}

/**
 * Build a BlockList from IP/CIDR entries. Throws on a malformed entry — the
 * config schema validates first, so a throw here means a caller bypassed it.
 */
net.BlockList _buildAddressSet(List<String> entries) {
  final list = net.BlockList();
  for (final entry in entries) {
    if (!addRange(list, entry)) {
      throw NodeException(
        'Invalid IP address or CIDR range: ${_jsonString(entry)}',
      );
    }
  }
  return list;
}

String _jsonString(String value) {
  // JSON.stringify(entry) is used only in the validation error message.
  return jsonEncode(value);
}

/**
 * BlockList membership for an address string of either family. IPv4 rules
 * also match the IPv4-mapped IPv6 spelling (BlockList does that itself);
 * an IPv6 zone id (`fe80::1%en0`) is dropped first because a zoned address
 * is a non-match on some runtimes.
 */
bool addressInSet(net.BlockList list, String address) {
  final addr = _stripZone(address);
  final family = _ipFamily(addr);
  return family != null && list.check(addr, family);
}

/** Drop an IPv6 zone id (`fe80::1%en0` → `fe80::1`). */
String _stripZone(String address) {
  final pct = address.indexOf('%');
  return pct == -1 ? address : address.substring(0, pct);
}

/** The eight 16-bit groups of an IPv6 literal (zone dropped), or undefined. */
List<int>? _ipv6Groups(String address) {
  final host = _stripZone(address);
  final bytes = net.ipv6Bytes(host);
  if (bytes == null || bytes.length != 16) return null;
  return List<int>.generate(
    8,
    (index) => (bytes[index * 2] << 8) | bytes[index * 2 + 1],
  );
}

String _dottedQuad(int hi, int lo) =>
    '${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}';

/** The IPv4 address of an IPv4-mapped IPv6 literal (`::ffff:a.b.c.d`), or undefined. */
String? mappedIPv4(String address) {
  // Cheap reject before the URL parse: a mapped form always spells `ffff`.
  if (!RegExp('ffff', caseSensitive: false).hasMatch(address)) return null;
  final g = _ipv6Groups(address);
  return g != null && g.take(5).every((x) => x == 0) && g[5] == 0xffff
      ? _dottedQuad(g[6], g[7])
      : null;
}

/**
 * The IPv4 address an IPv6 address carries in one of the forms a network
 * delivers to that IPv4 destination: IPv4-mapped and IPv4-compatible
 * (`::ffff:0:0/96`, `::/96`), IPv4-translated (`::ffff:0:0:0/96`), the NAT64
 * well-known prefix (`64:ff9b::/96`) and 6to4 (`2002::/16`). Undefined for
 * anything else — including the local-use NAT64 prefix `64:ff9b:1::/48` and
 * network-specific prefixes, whose layout (RFC 6052 §2.2 allows /32…/96)
 * cannot be told from the address, so the embedded IPv4 could be anywhere;
 * an embedder on such a network lists the prefix's translations of the
 * ranges it denies.
 */
String? embeddedIPv4(String address) {
  if (net.isIP(address) != 6) return null;
  final g = _ipv6Groups(address);
  if (g == null) return null;
  bool zero(int from, int to) => g.sublist(from, to).every((x) => x == 0);
  if (g[0] == 0x2002) return _dottedQuad(g[1], g[2]);
  final low = _dottedQuad(g[6], g[7]);
  if (g[0] == 0x64 && g[1] == 0xff9b && zero(2, 6)) return low; // NAT64 /96
  if (zero(0, 5) && (g[5] == 0 || g[5] == 0xffff)) return low;
  if (zero(0, 4) && g[4] == 0xffff && g[5] == 0) return low;
  return null;
}

final net.BlockList _LOOPBACK = _buildAddressSet(LOOPBACK_RANGES);

/** True for an IPv4/IPv6 loopback literal (including v4-mapped forms). */
bool isLoopbackAddress(String address) => addressInSet(_LOOPBACK, address);

/** `localhost` and names under `.localhost` (RFC 6761 §6.3). */
bool isLoopbackName(String hostname) {
  final h = hostname.toLowerCase().replaceFirst(RegExp(r'\.$'), '');
  return h == 'localhost' || h.endsWith('.localhost');
}
