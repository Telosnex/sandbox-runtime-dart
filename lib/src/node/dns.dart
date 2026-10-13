// Node-compatible subset of `node:dns` used by resolved-address-guard.
import 'dart:async';
import 'dart:io';

import 'net.dart' as net;

/// A Node `dns.LookupAddress` record.
class LookupAddress {
  const LookupAddress({required this.address, required this.family});

  final String address;
  final int family;
}

/// Options for `dns.lookup` with Node's `all: true` callback shape.
///
/// The guard always requests all records. Family is 0 (any), 4 (IPv4), or 6
/// (IPv6); resolver order is left verbatim unless [order] requests a family
/// preference, matching Node's current default.
class LookupAllOptions {
  const LookupAllOptions({
    this.family = 0,
    this.hints = 0,
    this.verbatim = true,
    this.order = 'verbatim',
  });

  final int family;
  final int hints;
  final bool verbatim;
  final String order;
  final bool all = true;
}

/// Node-style asynchronous `dns.lookup` for the all-address overload.
///
/// The callback receives `(error, LookupAddress[])`. Node errors retain their
/// `code`; Dart's resolver does not expose getaddrinfo's code, so unresolved
/// names are surfaced as the Node `ENOTFOUND` error rather than guessed as a
/// successful empty answer.
void lookup(String hostname, LookupAllOptions options, Function callback) {
  final literalFamily = net.isIP(hostname);
  final family = options.family == 0 ? literalFamily : options.family;
  if (options.family != 0 && options.family != 4 && options.family != 6) {
    scheduleMicrotask(() {
      Function.apply(callback, [
        _lookupError('EINVAL', hostname),
        <LookupAddress>[],
      ]);
    });
    return;
  }
  if (literalFamily != 0 && family != 0 && family != literalFamily) {
    scheduleMicrotask(() {
      Function.apply(callback, [
        _lookupError('ENOTFOUND', hostname),
        <LookupAddress>[],
      ]);
    });
    return;
  }

  final type = family == 4
      ? InternetAddressType.IPv4
      : family == 6
      ? InternetAddressType.IPv6
      : InternetAddressType.any;
  InternetAddress.lookup(hostname, type: type).then<void>((results) {
    var addresses = results
        .map(
          (address) => LookupAddress(
            address: address.address,
            family: address.type == InternetAddressType.IPv4 ? 4 : 6,
          ),
        )
        .where((address) =>
            options.family == 0 || address.family == options.family)
        .toList();
    if (options.order == 'ipv4first' || !options.verbatim) {
      addresses = [
        ...addresses.where((address) => address.family == 4),
        ...addresses.where((address) => address.family == 6),
      ];
    } else if (options.order == 'ipv6first') {
      addresses = [
        ...addresses.where((address) => address.family == 6),
        ...addresses.where((address) => address.family == 4),
      ];
    }
    if (addresses.isEmpty) {
      Function.apply(callback, [
        _lookupError('ENOTFOUND', hostname),
        <LookupAddress>[],
      ]);
      return;
    }
    Function.apply(callback, [null, addresses]);
  }, onError: (Object error, StackTrace stack) {
    final code = _codeForLookupError(error);
    Function.apply(callback, [_lookupError(code, hostname), <LookupAddress>[]]);
  });
}

NodeLookupError _lookupError(String code, String hostname) =>
    NodeLookupError(code, 'getaddrinfo $code $hostname');

String _codeForLookupError(Object error) {
  final text = error.toString();
  for (final code in const [
    'EAI_AGAIN',
    'EAI_ADDRFAMILY',
    'EAI_NODATA',
    'EAI_FAIL',
    'ENOTFOUND',
  ]) {
    if (text.contains(code)) return code;
  }
  return 'ENOTFOUND';
}

/// A DNS error carrying Node's stable `err.code` field.
class NodeLookupError extends Error {
  NodeLookupError(this.code, this.message);

  final String code;
  final String message;

  @override
  String toString() => 'Error: $message';
}
