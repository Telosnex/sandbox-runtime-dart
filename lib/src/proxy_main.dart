// Ported from sandbox-runtime src/proxy-main.ts @ 24eb39e.
// Standalone entry for the proxy-only mode: `srt-proxy <flags>`.
import 'proxy_cli.dart' show runProxyCli;

// Dart: the entry runs from bin/srt_proxy.dart, which passes its arguments
// (Node's process.argv.slice(2)) here.
void main(List<String> argv) {
  runProxyCli(argv);
}
