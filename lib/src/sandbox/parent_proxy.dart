// PARTIAL: ported stripBrackets, canonicalizeHost; pending port of the rest of src/sandbox/parent-proxy.ts @ 24eb39e.
// ignore_for_file: slash_for_doc_comments

import '../node/net.dart' as net;
import '../node/url.dart' as url;
import 'address.dart' show mappedIPv4;

/** Remove surrounding square brackets from an IPv6 literal. */
String stripBrackets(String host) => host.startsWith('[') && host.endsWith(']')
    ? host.substring(1, host.length - 1)
    : host;

/**
 * Canonicalize a host string via the WHATWG URL parser so that string
 * comparisons in the allowlist agree with what `net.connect()`/`getaddrinfo()`
 * will actually dial. This normalizes:
 *   - inet_aton shorthand (`127.1` → `127.0.0.1`, `2130706433` → `127.0.0.1`)
 *   - hex/octal octets (`0x7f.0.0.1` → `127.0.0.1`)
 *   - IPv6 compression (`0:0:0:0:0:0:0:1` → `::1`)
 *   - trailing dots, case, brackets
 *
 * Returns undefined if the input is not a valid URL host.
 */
String? canonicalizeHost(String h) {
  try {
    final bare = stripBrackets(h);
    // WHATWG URL rejects zone IDs and most garbage; it normalizes inet_aton
    // forms and IPv6 compression. It does NOT strip trailing dots or IPv6
    // brackets from the output, so we do that ourselves.
    final bracketed = net.isIP(bare) == 6 ? '[$bare]' : bare;
    final out = stripBrackets(url.whatwgUrlHostname(bracketed));
    // An IPv4-mapped literal connects to that IPv4 address, so it is spelled
    // as one: allow/deny entries and requests then compare equal.
    return net.isIP(out) == 6
        ? (mappedIPv4(out) ?? out)
        : out.replaceFirst(RegExp(r'\.$'), '');
  } catch (_) {
    return null;
  }
}
