// Ported from sandbox-runtime test/helpers/platform.ts @ 24eb39e.

import 'package:sandbox_runtime/src/utils/platform.dart';

final platform = getPlatform();

final isLinux = platform == 'linux';
final isMacOS = platform == 'macos';
final isWindows = platform == 'windows';
final isSupportedPlatform = isLinux || isMacOS || isWindows;
