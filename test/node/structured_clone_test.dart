import 'package:test/test.dart';
import 'package:sandbox_runtime/src/node/structured_clone.dart';
import 'package:sandbox_runtime/src/sandbox/sandbox_config.dart';

void main() {
  test('deep-copies nested collections', () {
    final src = <String, Object?>{
      'a': [
        1,
        {
          'b': <String>{'x'},
        },
      ],
      'n': null,
    };
    final c = structuredClone(src);
    expect(c, equals(src));
    ((c['a'] as List)[1] as Map)['b'].add('y');
    expect(((src['a'] as List)[1] as Map)['b'], {'x'});
  });

  test('copies SandboxRuntimeConfig without sharing mutable lists', () {
    final src = SandboxRuntimeConfig(
      network: NetworkConfig(allowedDomains: ['a.com'], deniedDomains: []),
      filesystem: FilesystemConfig(
        denyRead: [const FilesystemPathSpelling('/x')],
        allowWrite: [],
        denyWrite: [],
      ),
      credentials: CredentialsConfig(
        envVars: [
          CredentialEnvVarConfig(name: 'T', mode: 'mask', injectHosts: ['h']),
        ],
      ),
      ignoreViolations: {
        '*': ['/tmp'],
      },
      git: GitConfig(safeDirectories: ['/r']),
    );
    final c = structuredClone(src);
    expect(identical(c, src), isFalse);
    c.network.allowedDomains.add('b.com');
    c.filesystem.denyRead.clear();
    c.credentials!.envVars![0].injectHosts!.add('z');
    c.ignoreViolations!['*']!.add('/y');
    c.git!.safeDirectories.add('/s');
    expect(src.network.allowedDomains, ['a.com']);
    expect(src.filesystem.denyRead, hasLength(1));
    expect(src.credentials!.envVars![0].injectHosts, ['h']);
    expect(src.ignoreViolations!['*'], ['/tmp']);
    expect(src.git!.safeDirectories, ['/r']);
  });

  test('throws on unknown classes', () {
    expect(() => structuredClone(Object()), throwsArgumentError);
  });
}
