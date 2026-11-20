import 'dart:io' as io;

import 'package:sandbox_runtime/sandbox_runtime.dart';

Future<void> main() async {
  if (!io.Platform.isMacOS && !io.Platform.isLinux) {
    io.stderr.writeln('This example requires macOS or Linux.');
    io.exitCode = 1;
    return;
  }

  // Do not grant network access or add writable paths for this command.
  final policy = SandboxRuntimeConfigSchema.safeParse({
    'network': {'allowedDomains': [], 'deniedDomains': []},
    'filesystem': {'denyRead': [], 'allowWrite': [], 'denyWrite': []},
  });
  if (!policy.success) {
    throw StateError('Invalid sandbox policy: ${policy.error.issues}');
  }

  final int status;
  try {
    await SandboxManager.initialize(policy.data);
    final (:argv, :env) = await SandboxManager.wrapWithSandboxArgv(
      'printf "Hello from inside the sandbox!\\n"',
    );
    final result = await io.Process.run(
      argv.first,
      argv.skip(1).toList(),
      environment: {
        for (final entry in env.entries)
          if (entry.value != null) entry.key: entry.value!,
      },
      includeParentEnvironment: false,
    );
    io.stdout.write(result.stdout);
    io.stderr.write(result.stderr);
    status = result.exitCode;
  } finally {
    await SandboxManager.reset();
  }

  // The runtime installs process-signal listeners. Exit after cleanup and
  // flushing output so this one-shot program does not keep listening.
  await io.stdout.flush();
  await io.stderr.flush();
  io.exit(status);
}
