// STUB: pending port of src/sandbox/domain-pattern.ts @ 24eb39e.
// ignore_for_file: constant_identifier_names
// ignore_for_file: dangling_library_doc_comments, slash_for_doc_comments

/**
 * Split an optional `:port` suffix off a domain pattern.
 *
 * Returns the host pattern and the optional 1–65535 port. IPv6 literals are
 * bracketed in raw entries and are returned unbracketed.
 */
({String hostPattern, int? port}) splitDomainPatternPort(String pattern) =>
    throw UnimplementedError('pending port of src/sandbox/domain-pattern.ts');

/**
 * Host-only pattern check (e.g., "example.com", "*.npmjs.org"). Rejects
 * protocols, paths, ports, and overly broad wildcards.
 */
bool isValidDomainPattern(String val) =>
    throw UnimplementedError('pending port of src/sandbox/domain-pattern.ts');

const String DOMAIN_PATTERN_MESSAGE =
    'Invalid domain pattern. Must be a valid domain (e.g., "example.com"), a wildcard (e.g., "*.example.com"), or a bracketed IPv6 literal (e.g., "[::1]", "[2001:db8::1]:443"). Overly broad patterns like "*.com" or "*" are not allowed for security reasons.';

/**
 * Raw-entry rule applied before the port split: an entry with two or more
 * colons is an IPv6 literal and must use RFC 3986 brackets.
 */
bool hasValidIpv6Bracketing(String val) =>
    throw UnimplementedError('pending port of src/sandbox/domain-pattern.ts');

/**
 * The check an allow-list entry gets: a domain pattern with an optional
 * `:port` suffix.
 */
bool isValidAllowedDomainEntry(String val) =>
    throw UnimplementedError('pending port of src/sandbox/domain-pattern.ts');

const String ALLOWED_DOMAIN_ENTRY_MESSAGE =
    '$DOMAIN_PATTERN_MESSAGE An optional ":port" suffix (1-65535) restricts the entry to that port.';

/** Drop a `:port` suffix, if any (see [splitDomainPatternPort]). */
String stripDomainPatternPort(String pattern) =>
    throw UnimplementedError('pending port of src/sandbox/domain-pattern.ts');

/**
 * Decide whether a per-credential `injectHosts` entry is reachable via
 * `network.allowedDomains` — every concrete host it could match must be
 * allowed by at least one entry.
 */
bool isInjectHostCoveredByAllowedDomains(
  String injectHost,
  List<String> allowedDomains,
) => throw UnimplementedError('pending port of src/sandbox/domain-pattern.ts');
