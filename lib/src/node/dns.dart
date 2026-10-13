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

/// Options accepted by Node's `dns.lookup` / `net.LookupFunction`.
///
/// Family is 0 (any), 4 (IPv4), or 6 (IPv6). Node also accepts the strings
/// `IPv4` / `IPv6` at net boundaries; those are normalized when constructed.
class LookupOptions {
  LookupOptions({
    Object? family,
    this.hints,
    this.all,
    this.verbatim,
    this.order,
  }) : family = _normalizeFamily(family);

  final int? family;
  final int? hints;
  final bool? all;
  final bool? verbatim;
  final String? order;
}

/// Options for `dns.lookup` with Node's all-address callback shape.
class LookupAllOptions extends LookupOptions {
  LookupAllOptions({Object? family, int? hints, bool? verbatim, String? order})
    : super(
        family: family,
        hints: hints,
        all: true,
        verbatim: verbatim,
        order: order,
      );

  @override
  bool get all => true;
}

sealed class LookupResult {
  const LookupResult();
}

class LookupResultAddress extends LookupResult {
  const LookupResultAddress(this.address);
  final String address;
}

class LookupResultAll extends LookupResult {
  const LookupResultAll(this.addresses);
  final List<LookupAddress> addresses;
}

/// Node-style asynchronous `dns.lookup` for the all-address overload.
///
/// The callback receives a [LookupResultAll] when `all` is true, or a
/// [LookupResultAddress] and family otherwise. Node errors retain their
/// `code`; Dart's resolver does not expose getaddrinfo's code, so unresolved
/// names are surfaced as the Node `ENOTFOUND` error rather than guessed as a
/// successful empty answer.
void lookup(String hostname, LookupOptions options, Function callback) {
  final literalFamily = net.isIP(hostname);
  final familyOption = options.family ?? 0;
  // Node passes IP literals through regardless of the requested family.
  final family = literalFamily != 0 ? literalFamily : familyOption;
  if (familyOption != 0 && familyOption != 4 && familyOption != 6) {
    scheduleMicrotask(() {
      Function.apply(callback, [_lookupError('EINVAL', hostname), null]);
    });
    return;
  }
  final type = family == 4
      ? InternetAddressType.IPv4
      : family == 6
      ? InternetAddressType.IPv6
      : InternetAddressType.any;
  InternetAddress.lookup(hostname, type: type).then<void>(
    (results) {
      var addresses = results
          .map(
            (address) => LookupAddress(
              address: address.address,
              family: address.type == InternetAddressType.IPv4 ? 4 : 6,
            ),
          )
          .where(
            (address) =>
                literalFamily != 0 ||
                familyOption == 0 ||
                address.family == familyOption,
          )
          .toList();
      if (options.order == 'ipv4first' || options.verbatim == false) {
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
        Function.apply(callback, [_lookupError('ENOTFOUND', hostname), null]);
        return;
      }
      if (options.all == true) {
        Function.apply(callback, [null, LookupResultAll(addresses)]);
      } else {
        final first = addresses.first;
        Function.apply(callback, [
          null,
          LookupResultAddress(first.address),
          first.family,
        ]);
      }
    },
    onError: (Object error, StackTrace stack) {
      final code = _codeForLookupError(error);
      Function.apply(callback, [_lookupError(code, hostname), null]);
    },
  );
}

int? _normalizeFamily(Object? family) {
  if (family == null) return null;
  if (family is int) return family;
  if (family == 'IPv4') return 4;
  if (family == 'IPv6') return 6;
  return -1;
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
