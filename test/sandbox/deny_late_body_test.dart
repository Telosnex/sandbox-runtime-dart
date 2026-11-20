// Ported from sandbox-runtime test/sandbox/deny-late-body.test.ts @ 0bbebed.
// ignore_for_file: constant_identifier_names, non_constant_identifier_names
import 'dart:async';

import 'package:sandbox_runtime/src/node/net.dart' as net;
import 'package:sandbox_runtime/src/node/tls.dart' as tls;
import 'package:sandbox_runtime/src/sandbox/http_proxy.dart';
import 'package:sandbox_runtime/src/sandbox/mitm_ca.dart';
import 'package:sandbox_runtime/src/sandbox/request_filter.dart'
    show FilterRequestCallback, RequestDecision;
import 'package:test/test.dart';

// Every case here runs a proxy configured to terminate TLS, so each is
// skipped where this runtime cannot terminate it in-process.
import '../helpers/emitted_connections.dart' show canServeEmittedConnections;

// Dart: upstream's `describeWithTls as describe`, which `group` cannot alias.
final Object? _tlsSkip = canServeEmittedConnections
    ? null
    : 'TLS termination unavailable';

// Dart: the object literal upstream hands createHttpProxyServer; every
// option not named here is absent (null).
class _HttpOptions implements HttpProxyServerOptions {
  _HttpOptions({this.mitmCA, this.filterRequest});
  @override
  final MitmCA? mitmCA;
  @override
  final FilterRequestCallback? filterRequest;
  @override
  FutureOr<bool> filter(
    int port,
    String host,
    dynamic socket, [
    String? encodedCommand,
    void Function(String reason)? explain,
  ]) => true;
  @override
  dynamic noSuchMethod(Invocation invocation) => null;
}

void main() {
  final cleanup = <void Function()>[];
  tearDown(() {
    while (cleanup.isNotEmpty) {
      cleanup.removeLast()();
    }
  });

  group('a body that keeps arriving after a deny', skip: _tlsSkip, () {
    // The deny cancels the stream filterRequest's Request reads the body
    // from; the rest of the upload must not be fed into it.
    test('the client gets the whole 403, and the proxy no error', () async {
      final ca = generateCa();
      final proxy = createHttpProxyServer(
        _HttpOptions(
          filterRequest: (_, [_]) async => const RequestDecision(
            action: 'deny',
            reason: 'denied for the test',
          ),
          mitmCA: createMitmCA(caCertPem: ca.certPem, caKeyPem: ca.keyPem),
        ),
      );
      final listening = Completer<void>();
      proxy.listen(0, '127.0.0.1', () => listening.complete());
      await listening.future;
      cleanup.add(() => proxy.close());
      final port = (proxy.address() as net.NodeAddress).port;
      final raw = await () {
        final resolve = Completer<String>();
        late final net.NodeSocket c;
        c = net.connect({'port': port, 'host': '127.0.0.1'}, () {
          c.write('CONNECT 127.0.0.1:9 HTTP/1.1\r\nHost: 127.0.0.1:9\r\n\r\n');
        });
        c.on('error', (_) {
          if (!resolve.isCompleted) resolve.complete('');
        });
        c.once('data', (_) {
          final t = tls.connect({
            'socket': c,
            'ca': ca.certPem,
            'checkServerIdentity': (Object? a, Object? b) => null,
          });
          var out = '';
          void done() {
            if (!resolve.isCompleted) resolve.complete(out);
          }

          t.on('secureConnect', () {
            t.write(
              'POST /x HTTP/1.1\r\nHost: 127.0.0.1:9\r\nContent-Length: 200000\r\n\r\n'
              '${'a' * 1000}',
            );
            // The rest of the body, after the deny is out.
            for (var i = 1; i <= 20; i++) {
              Timer(Duration(milliseconds: i * 10), () {
                if (!t.destroyed) t.write('b' * 9950);
              });
            }
          });
          t.on(
            'data',
            (Object? d) => out += String.fromCharCodes(d as List<int>),
          );
          t.on('close', (_) => done());
          t.on('error', (_) => done());
        });
        return resolve.future;
      }();
      expect(raw, startsWith('HTTP/1.1 403'));
      expect(raw, contains('denied for the test'));
    });
  });
}
