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
final String EOL = Platform.isWindows ? '\r\n' : '\n';

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
