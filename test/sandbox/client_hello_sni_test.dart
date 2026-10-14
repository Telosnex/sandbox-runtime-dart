// Ported from sandbox-runtime test/sandbox/client-hello-sni.test.ts @ 24eb39e.
// ignore_for_file: constant_identifier_names, non_constant_identifier_names, slash_for_doc_comments
import 'dart:async';
import 'dart:typed_data';

import 'package:sandbox_runtime/src/node/buffer.dart' show Buffer;
import 'package:sandbox_runtime/src/node/net.dart'
    show NodeAddress, NodeSocket, createServer;
import 'package:sandbox_runtime/src/node/tls.dart' as tls;
import 'package:sandbox_runtime/src/sandbox/tls_terminate_proxy.dart'
    show ServerName, ServerNameName, serverNameFromClientHello;
import 'package:test/test.dart';

// Dart: a Buffer is a `List<int>`; the Uint8List below is what the function takes.
Uint8List _bytes(Iterable<int> b) => Uint8List.fromList(b.toList());

Uint8List u16(int n) => _bytes([n >> 8, n & 0xff]);
Uint8List u24(int n) => _bytes([n >> 16, (n >> 8) & 0xff, n & 0xff]);

Uint8List concat(List<List<int>> l) => Buffer.concat(l).toUint8List();

// Dart: stands for the anonymous `{ type, name }` entry type.
typedef SniEntry = ({int type, Uint8List name});

/** A server_name extension (type 0) with the given raw list entries. */
Uint8List sniExtension(List<SniEntry> entries) {
  final list = concat(
    entries
        .map(
          (e) => concat([
            _bytes([e.type]),
            u16(e.name.length),
            e.name,
          ]),
        )
        .toList(),
  );
  final body = concat([u16(list.length), list]);
  return concat([u16(0), u16(body.length), body]);
}

Uint8List otherExtension(int type, int len) =>
    concat([u16(type), u16(len), Uint8List(len)..fillRange(0, len, 0x41)]);

/**
 * A TLS record carrying a ClientHello with these extensions (none when
 * undefined). `recordCut` keeps only that many bytes of the handshake in
 * the record, as when the ClientHello continues in a second record.
 */
Uint8List clientHello(List<Uint8List>? extensions, [int? recordCut]) {
  final body = concat([
    u16(0x0303),
    Uint8List(32)..fillRange(0, 32, 7), // random
    _bytes([0]), // session_id
    u16(2),
    u16(0x1301), // cipher_suites
    _bytes([1, 0]), // compression_methods
    ...(extensions == null
        ? []
        : [u16(concat(extensions).length), ...extensions]),
  ]);
  final handshake = concat([
    _bytes([1]),
    u24(body.length),
    body,
  ]);
  final inRecord = recordCut == null
      ? handshake
      : Uint8List.sublistView(handshake, 0, recordCut);
  return concat([
    _bytes([0x16, 3, 1]),
    u16(inRecord.length),
    inRecord,
  ]);
}

Uint8List name(String s) => Buffer.from(s, 'latin1').toUint8List();

// Dart: toEqual on a `{ kind, name? }` object.
Matcher _isServerName(String kind, [String? n]) => predicate<ServerName>(
  (v) =>
      v.kind == kind &&
      (n == null ? v is! ServerNameName : (v as ServerNameName).name == n),
  'is $kind${n == null ? '' : ' $n'}',
);

void main() {
  group('serverNameFromClientHello', () {
    test('a plain name, lower-cased, among other extensions', () {
      expect(
        serverNameFromClientHello(
          clientHello([
            otherExtension(10, 4),
            sniExtension([(type: 0, name: name('API.Example.com'))]),
            otherExtension(16, 11),
          ]),
        ),
        _isServerName('name', 'api.example.com'),
      );
    });

    test('no server_name extension, or no extensions at all: absent', () {
      expect(
        serverNameFromClientHello(clientHello([otherExtension(10, 4)])),
        _isServerName('absent'),
      );
      expect(
        serverNameFromClientHello(clientHello(null)),
        _isServerName('absent'),
      );
    });

    for (final (what, n) in [
      ('an underscore', 'x_front.example'),
      ('a trailing dot', 'api.example.com.'),
      ('an empty label', 'api..example.com'),
      ('non-ASCII', 'bücher.example'),
      ('a zero-length name', ''),
      ('a name past 253 bytes', '${'a.' * 127}ab'),
      ('a label past 63 bytes', '${'a' * 64}.example'),
      ('a space', 'api example.com'),
    ]) {
      test('$what: unreadable', () {
        expect(
          serverNameFromClientHello(
            clientHello([
              sniExtension([(type: 0, name: name(n))]),
            ]),
          ),
          _isServerName('unreadable'),
        );
      });
    }

    test(
      'two names, a first name of another type, or two server_name extensions: unreadable',
      () {
        final a = (type: 0, name: name('a.example'));
        final b = (type: 0, name: name('b.example'));
        for (final extensions in [
          [
            sniExtension([a, b]),
          ],
          [
            sniExtension([(type: 1, name: name('a.example'))]),
          ],
          [
            sniExtension([a]),
            sniExtension([b]),
          ],
        ]) {
          expect(
            serverNameFromClientHello(clientHello(extensions)),
            _isServerName('unreadable'),
          );
        }
      },
    );

    test(
      'a ClientHello split across records: the name if it is in the first, else unreadable',
      () {
        final extensions = [
          sniExtension([(type: 0, name: name('a.example'))]),
          otherExtension(21, 400),
        ];
        final whole = clientHello(extensions).length - 5;
        // Cut inside the padding after the name: the name is read.
        expect(
          serverNameFromClientHello(clientHello(extensions, whole - 100)),
          _isServerName('name', 'a.example'),
        );
        // The name after the cut: it may be there, so unreadable, not absent.
        final late = [
          otherExtension(21, 400),
          sniExtension([(type: 0, name: name('a.example'))]),
        ];
        expect(
          serverNameFromClientHello(
            clientHello(late, clientHello(late).length - 5 - 20),
          ),
          _isServerName('unreadable'),
        );
        // Cut before the extensions start.
        expect(
          serverNameFromClientHello(clientHello(extensions, 30)),
          _isServerName('unreadable'),
        );
      },
    );

    test('a truncated record, garbage, or not a ClientHello: unreadable', () {
      final hello = clientHello([
        sniExtension([(type: 0, name: name('a.example'))]),
      ]);
      expect(
        serverNameFromClientHello(Uint8List.sublistView(hello, 0, 20)),
        _isServerName('unreadable'),
      );
      expect(
        serverNameFromClientHello(
          Buffer.from('GET / HTTP/1.1\r\n\r\n').toUint8List(),
        ),
        _isServerName('unreadable'),
      );
      final serverHello = Uint8List.fromList(hello);
      serverHello[5] = 2;
      expect(
        serverNameFromClientHello(serverHello),
        _isServerName('unreadable'),
      );
    });
  });

  group("a real ClientHello from this runtime's TLS client", () {
    final servers = <void Function()>[];
    tearDown(() {
      while (servers.isNotEmpty) {
        servers.removeLast()();
      }
    });

    test('its server name is read', () async {
      final firstCompleter = Completer<Uint8List>();
      final first = await (() {
        final server = createServer((NodeSocket sock) {
          sock.once('data', (d) {
            firstCompleter.complete(
              Uint8List.fromList((d as List).cast<int>()),
            );
            sock.destroy();
          });
        });
        servers.add(() => server.close());
        server.listen(0, '127.0.0.1', () {
          final t = tls.connect({
            'port': (server.address() as NodeAddress).port,
            'host': '127.0.0.1',
            'servername': 'api.example.com',
          });
          t.on('error', () {});
        });
        return firstCompleter.future;
      })();
      expect(
        serverNameFromClientHello(first),
        _isServerName('name', 'api.example.com'),
      );
    });
  });
}
