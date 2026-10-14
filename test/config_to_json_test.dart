import 'dart:convert';

import 'package:sandbox_runtime/src/sandbox/sandbox_config.dart';
import 'package:test/test.dart';

void main() {
  test('jsonEncode of a full config round-trips through the schema', () {
    final config = {
      'network': {
        'allowedDomains': ['a.com', '*.b.org:443'],
        'deniedDomains': ['evil.com'],
        'deniedDomainReasons': {'evil.com': 'no'},
        'strictAllowlist': true,
        'allowLocalBinding': false,
        'httpProxyPort': 8080,
        'mitmProxy': {
          'socketPath': '/tmp/s',
          'domains': ['x.com'],
        },
        'parentProxy': {'http': 'http://p:1'},
      },
      'filesystem': {
        'denyRead': [
          '~/x',
          {'path': '/a*', 'literal': true},
        ],
        'allowWrite': ['.'],
        'denyWrite': [],
        'allowGitConfig': true,
      },
      'ignoreViolations': {
        '*': ['/tmp'],
      },
      'mandatoryDenySearchDepth': 2,
      'ripgrep': {
        'command': 'rg',
        'args': ['-j1'],
      },
      'windows': {
        'proxyPortRange': [60080, 60089],
        'srtWin': {'path': 'x.exe'},
      },
      'git': {
        'safeDirectories': ['/r'],
      },
    };
    final parsed = SandboxRuntimeConfigSchema.safeParse(config);
    expect(parsed.success, isTrue);
    final encoded = jsonEncode(parsed.data);
    expect(jsonDecode(encoded), config);
    final again = SandboxRuntimeConfigSchema.safeParse(jsonDecode(encoded));
    expect(again.success, isTrue);
    expect(jsonEncode(again.data), encoded);
  });
}
