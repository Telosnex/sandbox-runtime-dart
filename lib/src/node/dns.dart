// Node-compatible subset of `node:dns` used by resolved-address-guard.
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
  LookupAllOptions({super.family, super.hints, super.verbatim, super.order})
    : super(all: true);

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
void lookup(
  String hostname,
  LookupOptions options,
  void Function(NodeLookupError? err, LookupResult? address, [int? family])
  callback,
) {
  final literalFamily = net.isIP(hostname);
  final familyOption = options.family ?? 0;
  if (familyOption != 0 && familyOption != 4 && familyOption != 6) {
    throw NodeLookupError(
      'ERR_INVALID_ARG_VALUE',
      "The property 'options.family' must be one of: 0, 4, 6. Received $familyOption",
    );
  }
  if (options.order != null &&
      !const ['verbatim', 'ipv4first', 'ipv6first'].contains(options.order)) {
    throw NodeLookupError(
      'ERR_INVALID_ARG_VALUE',
      "The property 'options.order' must be one of: 'verbatim', 'ipv4first', 'ipv6first'. Received '${options.order}'",
    );
  }
  if (options.hints != null && options.hints != 0) {
    throw UnimplementedError(
      'dns.lookup hints are not reproduced by dart:io InternetAddress.lookup',
    );
  }
  // Node passes IP literals through regardless of the requested family.
  final family = literalFamily != 0 ? literalFamily : familyOption;
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
      if (options.order == 'ipv4first' ||
          (options.order != 'ipv6first' &&
              options.order != 'verbatim' &&
              options.verbatim == false)) {
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
        callback(_lookupError('ENOTFOUND', hostname), null);
        return;
      }
      if (options.all == true) {
        callback(null, LookupResultAll(addresses));
      } else {
        final first = addresses.first;
        callback(null, LookupResultAddress(first.address), first.family);
      }
    },
    onError: (Object error, StackTrace stack) {
      final code = _codeForLookupError(error);
      callback(_lookupError(code, hostname), null);
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
