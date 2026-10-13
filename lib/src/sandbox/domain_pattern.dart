// Ported from sandbox-runtime src/sandbox/domain-pattern.ts @ 24eb39e.
// ignore_for_file: constant_identifier_names
// ignore_for_file: dangling_library_doc_comments, slash_for_doc_comments
// ignore_for_file: doc_directive_unknown

import '../node/net.dart' as net;
import 'parent_proxy.dart' show canonicalizeHost, stripBrackets;

/**
 * Domain-pattern matching shared between runtime host filtering
 * (sandbox-manager) and config-time validation (sandbox-config).
 * Lives in its own module so the schema can import it without pulling
 * in sandbox-manager (which imports the schema — circular).
 *
 * The validity check for a list entry lives here too, so the manager can
 * apply it to lists registered at run time without loading the schema module.
 */

/** Drop an IPv6 zone id from an IP-literal entry; matching ignores zones. */
String _dropZone(String host) {
  final pct = host.indexOf('%');
  return pct == -1 ? host : host.substring(0, pct);
}

/**
 * Split an optional `:port` suffix off a domain pattern.
 *
 * `api.github.com:443` → `{ hostPattern: 'api.github.com', port: 443 }`
 * `api.github.com`     → `{ hostPattern: 'api.github.com', port: undefined }`
 * `[::1]:443`          → `{ hostPattern: '::1', port: 443 }`
 * `[2001:db8::1]`      → `{ hostPattern: '2001:db8::1', port: undefined }`
 *
 * Only a strictly-numeric suffix in 1–65535 (no leading zeros) counts as a
 * port, so a smuggled host suffix like `evil.com:443.allowed.com` is left
 * whole (and then fails host validation on the remaining `:`).
 *
 * IPv6 literals must be bracketed (RFC 3986 / RFC 5952 §6: `[addr]` or
 * `[addr]:port`); the returned hostPattern is the bare, canonically
 * compressed address so it compares equal to what {@link canonicalizeHost}
 * yields for a destination. An *unbracketed* string with two or more colons
 * is ambiguous (`::1:443` is itself a valid address) — it is returned whole
 * with no port, never split, so a trailing hextet can't be mistaken for a
 * port and silently narrow the entry. The config schema rejects that form;
 * this fallback only matters for embedders passing config programmatically.
 */
({String hostPattern, int? port}) splitDomainPatternPort(String pattern) {
  if (pattern.startsWith('[')) {
    final close = pattern.indexOf(']');
    if (close == -1) return (hostPattern: pattern, port: null);
    final inner = _dropZone(pattern.substring(1, close));
    final host = canonicalizeHost(inner) ?? inner;
    final rest = pattern.substring(close + 1);
    if (rest.isEmpty) return (hostPattern: host, port: null);
    final port = _parsePortSuffix(
      rest.startsWith(':') ? rest.substring(1) : '',
    );
    // `[::1]junk` / `[::1]:0` — leave whole so validation rejects it.
    return port == null
        ? (hostPattern: pattern, port: null)
        : (hostPattern: host, port: port);
  }
  final idx = pattern.lastIndexOf(':');
  if (idx == -1) return (hostPattern: pattern, port: null);
  if (pattern.indexOf(':') != idx) {
    // ≥2 colons, no brackets: an IPv6 literal (or garbage). Never split.
    final host = _dropZone(pattern);
    return (hostPattern: canonicalizeHost(host) ?? host, port: null);
  }
  final port = _parsePortSuffix(pattern.substring(idx + 1));
  if (port == null) return (hostPattern: pattern, port: null);
  return (hostPattern: pattern.substring(0, idx), port: port);
}

int? _parsePortSuffix(String suffix) {
  if (!RegExp(r'^[1-9][0-9]{0,4}$').hasMatch(suffix)) return null;
  final port = int.parse(suffix);
  return port > 65535 ? null : port;
}

/**
 * Host-only pattern check (e.g., "example.com", "*.npmjs.org"). Rejects
 * protocols, paths, ports, and overly broad wildcards.
 */
bool isValidDomainPattern(String val) {
  // A bare IPv6 literal as produced by splitDomainPatternPort for a
  // bracketed entry (`[::1]`, `[2001:db8::1]:443` -> `::1`, `2001:db8::1`).
  // Whether the *raw* entry was bracketed is enforced separately
  // (hasValidIpv6Bracketing) before the split.
  if (net.isIP(val) == 6) return true;

  // Reject protocols, paths, ports, etc.
  if (val.contains('://') || val.contains('/') || val.contains(':')) {
    return false;
  }

  // Allow localhost
  if (val == 'localhost') return true;

  // Allow wildcard domains like *.example.com
  if (val.startsWith('*.')) {
    final domain = val.substring(2);
    // After the *. there must be a valid domain with at least one more dot
    // e.g., *.example.com is valid, *.com is not (too broad)
    if (!domain.contains('.') ||
        domain.startsWith('.') ||
        domain.endsWith('.')) {
      return false;
    }
    // Count dots - must have at least 2 parts after the wildcard (e.g., example.com)
    final parts = domain.split('.');
    return parts.length >= 2 && parts.every((p) => p.isNotEmpty);
  }

  // Reject any other use of wildcards (e.g., *, *., etc.)
  if (val.contains('*')) return false;

  // Regular domains must have at least one dot and only valid characters
  return val.contains('.') && !val.startsWith('.') && !val.endsWith('.');
}

const String DOMAIN_PATTERN_MESSAGE =
    'Invalid domain pattern. Must be a valid domain (e.g., "example.com"), a wildcard (e.g., "*.example.com"), or a bracketed IPv6 literal (e.g., "[::1]", "[2001:db8::1]:443"). Overly broad patterns like "*.com" or "*" are not allowed for security reasons.';

/**
 * Raw-entry rule applied before the port split: an entry with two or more
 * colons is an IPv6 literal and must use RFC 3986 brackets (`[::1]`,
 * `[::1]:443`). Unbracketed it is ambiguous (`2001:db8::1:443` is itself a
 * valid 8-hextet address), so reject it and make the user say which they
 * mean, rather than accept an entry that can silently match the wrong thing.
 */
bool hasValidIpv6Bracketing(String val) {
  final first = val.indexOf(':');
  final multiColon = first != -1 && val.indexOf(':', first + 1) != -1;
  return !multiColon || val.startsWith('[');
}

/**
 * The check an allow-list entry gets: a domain pattern with an optional
 * `:port` suffix.
 */
bool isValidAllowedDomainEntry(String val) =>
    hasValidIpv6Bracketing(val) &&
    isValidDomainPattern(splitDomainPatternPort(val).hostPattern);

const String ALLOWED_DOMAIN_ENTRY_MESSAGE =
    '$DOMAIN_PATTERN_MESSAGE An optional ":port" suffix (1-65535) restricts the entry to that port.';

/**
 * The IP-literal entries of an allow/deny list as `{ range, port? }` rules
 * for the resolved-address check: an address the list names explicitly is
 * judged the same way when a hostname resolves to it.
 */
List<({String range, int? port})> ipLiteralRules(List<String> entries) =>
    entries
        .map(splitDomainPatternPort)
        .where((parts) => net.isIP(parts.hostPattern) != 0)
        .map((parts) => (range: parts.hostPattern, port: parts.port))
        .toList();

/** Drop a `:port` suffix, if any (see [splitDomainPatternPort]). */
String stripDomainPatternPort(String pattern) =>
    splitDomainPatternPort(pattern).hostPattern;

/**
 * Match a hostname against a domain pattern.
 *
 * Patterns:
 *   - `*` matches everything (deny-all; the schema only accepts this in
 *     deniedDomains).
 *   - `*.example.com` matches any strict subdomain of example.com.
 *   - anything else matches exactly (case-insensitive).
 *
 * Wildcard suffix matching is refused for IP literals so an IPv6 zone-ID
 * payload like `::ffff:1.2.3.4%x.allowed.com` cannot pass `.endsWith()`
 * while the OS connects to the bare IP. isValidHost already rejects `%`,
 * but we refuse here too for defence in depth.
 */
bool matchesDomainPattern(String hostname, String pattern) {
  final h = hostname.toLowerCase();
  if (pattern == '*') return true;
  if (pattern.startsWith('*.')) {
    if (net.isIP(stripBrackets(h)) != 0) return false;
    final baseDomain = pattern.substring(2).toLowerCase();
    return h.endsWith('.$baseDomain');
  }
  return h == pattern.toLowerCase();
}

/**
 * {@link matchesDomainPattern} with an optional `:port` suffix on the
 * pattern (`example.com:443`, `*.example.com:8443`, `*:22`). A pattern
 * without a port matches every port; a pattern with one matches only when
 * the destination port is equal.
 */
bool matchesDomainPatternWithPort(String hostname, int port, String pattern) {
  final parts = splitDomainPatternPort(pattern);
  if (parts.port != null && parts.port != port) return false;
  return matchesDomainPattern(hostname, parts.hostPattern);
}

/**
 * Decide whether a per-credential `injectHosts` entry is reachable via
 * `network.allowedDomains` — every concrete host it could match must be
 * allowed by at least one entry.
 */
bool isInjectHostCoveredByAllowedDomains(
  String injectHost,
  List<String> allowedDomains,
) {
  final allowedHosts = allowedDomains.map(stripDomainPatternPort).toList();
  if (!injectHost.startsWith('*.')) {
    return allowedHosts.any((p) => matchesDomainPattern(injectHost, p));
  }
  final injectBase = injectHost.substring(2).toLowerCase();
  return allowedHosts.any((p) {
    if (!p.startsWith('*.')) return false;
    final allowedBase = p.substring(2).toLowerCase();
    return injectBase == allowedBase || injectBase.endsWith('.$allowedBase');
  });
}
