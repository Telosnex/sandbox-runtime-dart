// Throughput bench: 64 MB down/up through (a) direct TLS, (b) the
// TLS-terminating proxy, (c) the plain CONNECT tunnel. Run from repo root:
//   dart run tool/bench/proxy_throughput.dart [MB]
import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:sandbox_runtime/src/node/fs.dart' show readFileSync;
import 'package:sandbox_runtime/src/node/http.dart' as http;
import 'package:sandbox_runtime/src/node/https.dart' as https;
import 'package:sandbox_runtime/src/node/net.dart' as net;
import 'package:sandbox_runtime/src/sandbox/http_proxy.dart';
import 'package:sandbox_runtime/src/sandbox/mitm_ca.dart';
import 'package:sandbox_runtime/src/sandbox/mitm_leaf.dart';
import 'package:sandbox_runtime/src/sandbox/request_filter.dart';
import 'package:sandbox_runtime/src/sandbox/sandbox_config.dart';

int mutated = 0;

class _Opts implements HttpProxyServerOptions {
  _Opts(this.mitmCA, this.tlsTerminateUpstreamCA);
  @override
  MutateForwardedHeaders? get mutateHeaders => (h, d) {
    mutated++;
  };
  @override
  final MitmCA? mitmCA;
  @override
  final dynamic tlsTerminateUpstreamCA;
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

Future<net.NodeServer> _startProxy(MitmCA? ca, String caPem) async {
  final proxy = createHttpProxyServer(_Opts(ca, ca == null ? null : caPem));
  final c = Completer<void>();
  proxy.listen(0, '127.0.0.1', () => c.complete());
  await c.future;
  return proxy;
}

Future<void> main(List<String> args) async {
  final mb = args.isNotEmpty ? int.parse(args[0]) : 64;
  final total = mb * 1024 * 1024;
  const dir = 'test/fixtures/tls-terminate';
  final caPem = readFileSync('$dir/ca.crt', 'utf8') as String;
  final ca = createMitmCA(caCertPath: '$dir/ca.crt', caKeyPath: '$dir/ca.key');
  final leaf = mintLeafCert(ca, '127.0.0.1');
  final leafOnly = RegExp(
    r'-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----\r?\n?',
  ).firstMatch(leaf.certPem)![0]!;

  final sctx = SecurityContext()
    ..useCertificateChainBytes(leafOnly.codeUnits)
    ..usePrivateKeyBytes(leaf.keyPem.codeUnits);
  final block = Uint8List(64 * 1024)..fillRange(0, 64 * 1024, 0x61);
  final shimOrigin = args.contains('--shim-origin');
  late final int originPort;
  if (shimOrigin) {
    // Origin served by the node shims (as the test suites do).
    final srv = https.createServer({'cert': leafOnly, 'key': leaf.keyPem}, (
      http.IncomingMessage req,
      http.ServerResponse res,
    ) {
      if (req.method == 'GET') {
        res.writeHead(200, {'content-length': '$total'});
        var n = 0;
        void pump() {
          while (n < total) {
            n += block.length;
            if (!res.write(block)) {
              res.once('drain', (Object? _) => pump());
              return;
            }
          }
          res.end();
        }

        pump();
      } else {
        var n = 0;
        req.on('data', (Object? c) => n += (c as Uint8List).length);
        req.on('end', () => res.end('$n'));
      }
    });
    final l = Completer<void>();
    srv.listen(0, '127.0.0.1', () => l.complete());
    await l.future;
    originPort = (srv.address() as net.NodeAddress).port;
  }
  final origin = shimOrigin
      ? null
      : await HttpServer.bindSecure('127.0.0.1', 0, sctx);
  if (!shimOrigin) originPort = origin!.port;
  origin?.listen((req) async {
    if (req.method == 'GET') {
      req.response.contentLength = total;
      for (var n = 0; n < total; n += block.length) {
        req.response.add(block);
        if ((n >> 16) % 16 == 0) await req.response.flush();
      }
      await req.response.close();
    } else {
      var n = 0;
      await for (final c in req) {
        n += c.length;
      }
      req.response.write('$n');
      await req.response.close();
    }
  });

  final term = await _startProxy(ca, caPem);
  final plain = await _startProxy(null, caPem);
  final tctx = SecurityContext(withTrustedRoots: false)
    ..setTrustedCertificatesBytes(caPem.codeUnits);

  Future<void> run(String name, int? proxyPort) async {
    final client = HttpClient(context: tctx);
    if (proxyPort != null) {
      client.findProxy = (_) => 'PROXY 127.0.0.1:$proxyPort';
    }
    final url = Uri.parse('https://127.0.0.1:${originPort}/x');
    var sw = Stopwatch()..start();
    final r = await (await client.getUrl(url)).close();
    var n = 0;
    await for (final c in r) {
      n += c.length;
    }
    final down = mb / (sw.elapsedMicroseconds / 1e6);
    if (n != total) throw StateError('down got $n');
    sw = Stopwatch()..start();
    final q = await client.putUrl(url);
    q.contentLength = total;
    for (var i = 0; i < total; i += block.length) {
      q.add(block);
      if ((i >> 16) % 16 == 0) await q.flush();
    }
    final resp = await q.close();
    final body = await resp.transform(const SystemEncoding().decoder).join();
    final up = mb / (sw.elapsedMicroseconds / 1e6);
    if (body != '$total') throw StateError('up got $body');
    print(
      '${name.padRight(12)} down ${down.toStringAsFixed(1)} MB/s   up ${up.toStringAsFixed(1)} MB/s',
    );
    client.close(force: true);
  }

  await run('direct', null);
  await run(
    'terminated',
    term.address() is net.NodeAddress
        ? (term.address() as net.NodeAddress).port
        : 0,
  );
  await run('plain-tunnel', (plain.address() as net.NodeAddress).port);
  print('terminated requests seen by proxy: $mutated');
  exit(0);
}
