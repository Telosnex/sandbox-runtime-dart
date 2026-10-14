// The `srt` executable (upstream package.json "bin": { "srt": "dist/cli.js" }).
import 'package:sandbox_runtime/src/cli.dart' as cli;

Future<void> main(List<String> argv) => cli.main(argv);
