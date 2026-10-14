// Ported from sandbox-runtime test/helpers/captured-warnings.ts @ 24eb39e.
import '../../lib/src/node/console.dart' as console;
import '../../lib/src/node/process.dart' as process;

/**
 * Run `fn` with debug logging on and console.warn/error captured, and return
 * what it produced beside the warnings it logged. The library routes its
 * warnings through the debug logger, so SRT_DEBUG has to be set for any of
 * them to be emitted at all; it is restored to whatever it was, unset
 * included.
 */
Future<({T result, List<String> warnings})> withCapturedWarnings<T>(
  Future<T> Function() fn,
) async {
  final warnings = <String>[];
  final savedDebug = process.env['SRT_DEBUG'];
  process.env['SRT_DEBUG'] = '1';
  final oldWarn = console.warn;
  final oldError = console.error;
  console.warn =
      ([Object? first, Object? second, Object? third, Object? fourth]) {
        warnings.add(
          [
            first,
            second,
            third,
            fourth,
          ].where((e) => e != null).map((e) => e.toString()).join(' '),
        );
      };
  console.error =
      ([Object? first, Object? second, Object? third, Object? fourth]) {};
  try {
    return (result: await fn(), warnings: warnings);
  } finally {
    console.warn = oldWarn;
    console.error = oldError;
    if (savedDebug == null) {
      process.env.remove('SRT_DEBUG');
    } else {
      process.env['SRT_DEBUG'] = savedDebug;
    }
  }
}
