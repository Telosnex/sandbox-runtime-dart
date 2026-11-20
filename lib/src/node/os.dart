// Node `os` compatibility: homedir, tmpdir and networkInterfaces.
// No upstream counterpart.
import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'process.dart' as process;

/// Node's `os.endianness()`: 'BE' or 'LE' for this CPU.
String endianness() => Endian.host == Endian.little ? 'LE' : 'BE';

/// Node's `os.EOL`.
final String eol = Platform.isWindows ? '\r\n' : '\n';

String homedir() {
  final env = process.env;
  // As libuv's uv_os_homedir: a set variable wins even when it is empty
  // (Node then returns ''); only an unset one falls back.
  if (process.platform == 'win32') {
    final profile = env['USERPROFILE'];
    if (profile != null) return profile;
    final drive = env['HOMEDRIVE'] ?? '';
    final homePath = env['HOMEPATH'] ?? '';
    if (drive.isNotEmpty || homePath.isNotEmpty) return '$drive$homePath';
  } else {
    final home = env['HOME'];
    if (home != null) return home;
  }
  // Dart exposes the OS account home when the corresponding environment key
  // is absent, as Node's native os.homedir() does.
  final fallback =
      Platform.environment['HOME'] ?? Platform.environment['USERPROFILE'];
  if (fallback != null && fallback.isNotEmpty) return fallback;
  throw UnsupportedError(
    'os.homedir requires a HOME/USERPROFILE environment value or a passwd lookup',
  );
}

/// Node's `os.tmpdir()` order of environment-variable preference.
String tmpdir() {
  final env = process.env;
  final keys = process.platform == 'win32'
      ? const ['TEMP', 'TMP']
      : const ['TMPDIR', 'TMP', 'TEMP'];
  for (final key in keys) {
    final candidate = env[key];
    if (candidate != null && candidate.isNotEmpty) {
      return candidate.replaceFirst(RegExp(r'[\\/]+$'), '');
    }
  }
  if (process.platform == 'win32') {
    final systemRoot = env['SystemRoot'] ?? env['SYSTEMROOT'] ?? r'C:\Windows';
    return '$systemRoot\\Temp';
  }
  return '/tmp';
}

// `dart:io` lists network interfaces asynchronously; Node's
// `os.networkInterfaces()` is synchronous, so POSIX getifaddrs keeps that
// boundary.

/// The `address` field consumed from Node's network-interface records.
class NetworkInterfaceAddress {
  const NetworkInterfaceAddress(this.address);

  final String address;
}

/// Node `os.networkInterfaces()` address map (only the fields needed by the
/// guard are materialized). An interface with no addresses has a null value,
/// as in Node's API.
Map<String, List<NetworkInterfaceAddress>?> networkInterfaces() {
  if (Platform.isWindows) return _windowsNetworkInterfaces();
  if (!Platform.isMacOS && !Platform.isLinux) {
    throw UnimplementedError(
      'os.networkInterfaces requires POSIX getifaddrs on this platform',
    );
  }
  final library = DynamicLibrary.process();
  final getifaddrs = library.lookupFunction<_GetifaddrsNative, _GetifaddrsDart>(
    'getifaddrs',
  );
  final freeifaddrs = library
      .lookupFunction<_FreeifaddrsNative, _FreeifaddrsDart>('freeifaddrs');
  final result = calloc<Pointer<_Ifaddrs>>();
  try {
    if (getifaddrs(result) != 0) {
      throw StateError('getifaddrs failed');
    }
    final interfaces = <String, List<NetworkInterfaceAddress>?>{};
    var current = result.value;
    while (current != nullptr) {
      final entry = current.ref;
      final name = entry.name == nullptr ? '' : entry.name.toDartString();
      interfaces.putIfAbsent(name, () => <NetworkInterfaceAddress>[]);
      final address = entry.address;
      if (address != nullptr) {
        final family = Platform.isMacOS
            ? (address.cast<Uint8>() + 1).value
            : address.cast<Uint16>().value;
        final ipv4 = family == 2;
        final ipv6 = Platform.isMacOS ? family == 30 : family == 10;
        if (ipv4 || ipv6) {
          final bytes = address.cast<Uint8>();
          final rawAddress = ipv4
              ? List<int>.generate(4, (index) => (bytes + 4 + index).value)
              : List<int>.generate(16, (index) => (bytes + 8 + index).value);
          final textual = InternetAddress.fromRawAddress(
            Uint8List.fromList(rawAddress),
            type: ipv4 ? InternetAddressType.IPv4 : InternetAddressType.IPv6,
          ).address;
          interfaces[name]!.add(NetworkInterfaceAddress(textual));
        }
      }
      current = entry.next;
    }
    return interfaces;
  } finally {
    if (result.value != nullptr) freeifaddrs(result.value);
    calloc.free(result);
  }
}

final class _Ifaddrs extends Struct {
  external Pointer<_Ifaddrs> next;
  external Pointer<Utf8> name;
  @Uint32()
  external int flags;
  external Pointer<Void> address;
  external Pointer<Void> netmask;
  external Pointer<Void> destinationOrBroadcast;
  external Pointer<Void> data;
}

typedef _GetifaddrsNative = Int32 Function(Pointer<Pointer<_Ifaddrs>> ifap);
typedef _GetifaddrsDart = int Function(Pointer<Pointer<_Ifaddrs>> ifap);
typedef _FreeifaddrsNative = Void Function(Pointer<_Ifaddrs> ifa);
typedef _FreeifaddrsDart = void Function(Pointer<_Ifaddrs> ifa);

/// Windows: GetAdaptersAddresses, as libuv's uv_interface_addresses. Keys are
/// the adapters' friendly names, as Node's are.
Map<String, List<NetworkInterfaceAddress>?> _windowsNetworkInterfaces() {
  final iphlpapi = DynamicLibrary.open('iphlpapi.dll');
  final getAdaptersAddresses = iphlpapi
      .lookupFunction<
        Uint32 Function(
          Uint32,
          Uint32,
          Pointer<Void>,
          Pointer<Uint8>,
          Pointer<Uint32>,
        ),
        int Function(int, int, Pointer<Void>, Pointer<Uint8>, Pointer<Uint32>)
      >('GetAdaptersAddresses');
  // AF_UNSPEC; skip anycast, multicast and DNS servers.
  const family = 0, flags = 0x2 | 0x4 | 0x8;
  const errorBufferOverflow = 111;
  final size = calloc<Uint32>()..value = 16 * 1024;
  try {
    for (var attempt = 0; attempt < 3; attempt++) {
      final buffer = calloc<Uint8>(size.value);
      try {
        final status = getAdaptersAddresses(
          family,
          flags,
          nullptr,
          buffer,
          size,
        );
        if (status == errorBufferOverflow) continue;
        if (status != 0) {
          throw StateError('GetAdaptersAddresses failed: $status');
        }
        return _readAdapters(buffer);
      } finally {
        calloc.free(buffer);
      }
    }
    throw StateError('GetAdaptersAddresses: the adapter list kept growing');
  } finally {
    calloc.free(size);
  }
}

/// Reads IP_ADAPTER_ADDRESSES_LH records (64-bit layout): Next at 8,
/// FirstUnicastAddress at 24, FriendlyName at 72. Each
/// IP_ADAPTER_UNICAST_ADDRESS_LH has Next at 8 and the sockaddr pointer at 16.
Map<String, List<NetworkInterfaceAddress>?> _readAdapters(
  Pointer<Uint8> first,
) {
  Pointer<Uint8> pointerAt(Pointer<Uint8> base, int offset) =>
      Pointer<Uint8>.fromAddress((base + offset).cast<IntPtr>().value);
  final interfaces = <String, List<NetworkInterfaceAddress>?>{};
  for (
    var adapter = first;
    adapter != nullptr;
    adapter = pointerAt(adapter, 8)
  ) {
    final friendly = pointerAt(adapter, 72);
    final name = friendly == nullptr
        ? ''
        : friendly.cast<Utf16>().toDartString();
    final addresses = interfaces.putIfAbsent(
      name,
      () => <NetworkInterfaceAddress>[],
    )!;
    for (
      var unicast = pointerAt(adapter, 24);
      unicast != nullptr;
      unicast = pointerAt(unicast, 8)
    ) {
      final sockaddr = pointerAt(unicast, 16);
      if (sockaddr == nullptr) continue;
      final family = sockaddr.cast<Uint16>().value;
      // AF_INET 2, AF_INET6 23.
      final ipv4 = family == 2;
      if (!ipv4 && family != 23) continue;
      final raw = ipv4
          ? List<int>.generate(4, (i) => (sockaddr + 4 + i).value)
          : List<int>.generate(16, (i) => (sockaddr + 8 + i).value);
      addresses.add(
        NetworkInterfaceAddress(
          InternetAddress.fromRawAddress(
            Uint8List.fromList(raw),
            type: ipv4 ? InternetAddressType.IPv4 : InternetAddressType.IPv6,
          ).address,
        ),
      );
    }
  }
  return interfaces;
}
