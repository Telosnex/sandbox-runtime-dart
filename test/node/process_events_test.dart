import 'dart:async';

import 'package:sandbox_runtime/src/node/process.dart' as process;
import 'package:test/test.dart';

void main() {
  test('error events register and dispatch', () async {
    final seen = <Object>[];
    void h(Object e, StackTrace s) => seen.add(e);
    process.on('unhandledRejection', h);
    process.on('uncaughtException', h);
    process.runWithProcessErrorHandlers(() {
      Future<void>.error('boom');
    });
    await Future<void>.delayed(const Duration(milliseconds: 20));
    expect(seen, ['boom', 'boom']);
    process.off('unhandledRejection', h);
    process.off('uncaughtException', h);
    expect(process.listenerCount('uncaughtException'), 0);
  });
}
