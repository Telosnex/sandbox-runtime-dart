// Ported from sandbox-runtime test/config-validation.test.ts @ 24eb39e.

import 'dart:convert';

import 'package:test/test.dart';
import 'package:sandbox_runtime/src/sandbox/sandbox_config.dart';
import 'package:sandbox_runtime/src/node/process.dart' as process;
import 'package:sandbox_runtime/src/utils/platform.dart';

Map<String, Object?> _config({
  Map<String, Object?>? network,
  Map<String, Object?>? filesystem,
  Map<String, Object?>? other,
}) => {
  'network':
      network ?? {'allowedDomains': <String>[], 'deniedDomains': <String>[]},
  'filesystem':
      filesystem ??
      {
        'denyRead': <Object>[],
        'allowWrite': <Object>[],
        'denyWrite': <Object>[],
      },
  ...?other,
};

Map<String, Object?> _credentialConfig(
  Map<String, Object?> credentials, {
  bool tlsTerminate = false,
  List<String> allowedDomains = const [],
}) => _config(
  network: {
    'allowedDomains': allowedDomains,
    'deniedDomains': <String>[],
    if (tlsTerminate) 'tlsTerminate': <String, Object?>{},
  },
  other: {'credentials': credentials},
);

void _expectResult(Object? input, bool success) {
  final result = SandboxRuntimeConfigSchema.safeParse(input);
  expect(result.success, success);
  if (!success) expect(result.error.issues, isNotEmpty);
}

List<FilesystemPathEntry>? _filesystemEntries(
  FilesystemConfig config,
  String name,
) => switch (name) {
  'denyRead' => config.denyRead,
  'allowRead' => config.allowRead,
  'allowWrite' => config.allowWrite,
  'denyWrite' => config.denyWrite,
  _ => throw ArgumentError.value(name, 'name'),
};

void _testEach<T>(
  Iterable<T> values,
  String title,
  void Function(dynamic) body, {
  String? skip,
}) {
  for (final row in values) {
    final value = row is List && row.length == 1 ? row.first : row;
    final rendered = title
        .replaceAll('%s', '$value')
        .replaceAll('%j', jsonEncode(value));
    test(rendered, () => body(value), skip: skip);
  }
}

void _testEachArgs(
  Iterable<List<Object?>> rows,
  String title,
  void Function(Object? first, Object? second) body,
) {
  for (final row in rows) {
    final name = title.replaceAll('%s', '${row.first}');
    test(name, () => body(row[0], row[1]));
  }
}

void main() {
  group('Config Validation', () {
    test('should validate a valid minimal config', () {
      _expectResult(_config(), true);
    });

    test(
      'should validate a config with valid domains',
      () => _expectResult(
        _config(
          network: {
            'allowedDomains': ['example.com', '*.github.com', 'localhost'],
            'deniedDomains': ['evil.com'],
          },
        ),
        true,
      ),
    );

    test(
      'should reject invalid domain patterns',
      () => _expectResult(
        _config(
          network: {
            'allowedDomains': ['not-a-domain'],
            'deniedDomains': <String>[],
          },
        ),
        false,
      ),
    );

    test(
      'should reject domain with protocol',
      () => _expectResult(
        _config(
          network: {
            'allowedDomains': ['https://example.com'],
            'deniedDomains': <String>[],
          },
        ),
        false,
      ),
    );

    test('should reject empty filesystem paths', () {
      _expectResult(
        _config(
          filesystem: {
            'denyRead': [''],
            'allowWrite': <Object>[],
            'denyWrite': <Object>[],
          },
        ),
        false,
      );
    });

    test(
      'should validate config with optional fields',
      () => _expectResult(
        _config(
          network: {
            'allowedDomains': ['example.com'],
            'deniedDomains': <String>[],
            'allowUnixSockets': ['/var/run/docker.sock'],
            'allowAllUnixSockets': false,
            'allowLocalBinding': true,
          },
          filesystem: {
            'denyRead': ['/etc/shadow'],
            'allowWrite': ['/tmp'],
            'denyWrite': ['/etc'],
          },
          other: {
            'ignoreViolations': {
              '*': ['/usr/bin'],
              'git push': ['/usr/bin/nc'],
            },
            'enableWeakerNestedSandbox': true,
            'enableWeakerNetworkIsolation': false,
          },
        ),
        true,
      ),
    );

    test('should reject missing required fields', () {
      _expectResult({
        'network': {'allowedDomains': <String>[]},
        'filesystem': {'denyRead': <String>[]},
      }, false);
    });

    test('should validate wildcard domains correctly', () {
      for (final domain in ['*.example.com', '*.github.io', '*.co.uk']) {
        _expectResult(
          _config(
            network: {
              'allowedDomains': [domain],
              'deniedDomains': <String>[],
            },
          ),
          true,
        );
      }
      for (final domain in ['*example.com', '*.com', '*.']) {
        _expectResult(
          _config(
            network: {
              'allowedDomains': [domain],
              'deniedDomains': <String>[],
            },
          ),
          false,
        );
      }
    });

    test('should accept ":port" suffixes on allowed/denied domains', () {
      for (final host in [
        'example.com:443',
        '[::1]',
        '[::1]:443',
        '[2001:db8::1]:8443',
        '*.example.com:8080',
        'localhost:3000',
        'example.com:65535',
        'example.com:1',
      ]) {
        _expectResult(
          _config(
            network: {
              'allowedDomains': [host],
              'deniedDomains': <String>[],
            },
          ),
          true,
        );
      }
      _expectResult(
        _config(
          network: {
            'allowedDomains': <String>[],
            'deniedDomains': ['*:22'],
          },
        ),
        true,
      );
      for (final host in [
        'example.com:0',
        'example.com:65536',
        'example.com:0443',
        'example.com:abc',
        'example.com:80:443',
        'example.com:',
        '*:22',
        '::1',
        'fd00:ec2::254',
        '2001:db8::1:443',
        '[::1',
        '[::1]:0',
        '[not-an-ip]',
      ]) {
        _expectResult(
          _config(
            network: {
              'allowedDomains': [host],
              'deniedDomains': <String>[],
            },
          ),
          false,
        );
      }
    });

    test('should validate config with enableWeakerNetworkIsolation', () {
      final result = SandboxRuntimeConfigSchema.safeParse(
        _config(other: {'enableWeakerNetworkIsolation': true}),
      );
      expect(result.success, isTrue);
      expect(result.data.enableWeakerNetworkIsolation, isTrue);
    });

    test('should validate config with allowAppleEvents', () {
      final result = SandboxRuntimeConfigSchema.safeParse(
        _config(other: {'allowAppleEvents': true}),
      );
      expect(result.success, isTrue);
      expect(result.data.allowAppleEvents, isTrue);
    });

    test('should validate config with custom ripgrep command', () {
      final result = SandboxRuntimeConfigSchema.safeParse(
        _config(
          other: {
            'ripgrep': {'command': '/usr/local/bin/rg'},
          },
        ),
      );
      expect(result.success, isTrue);
      expect(result.data.ripgrep?.command, '/usr/local/bin/rg');
    });

    test('should validate config with custom ripgrep command and args', () {
      final result = SandboxRuntimeConfigSchema.safeParse(
        _config(
          other: {
            'ripgrep': {
              'command': 'claude',
              'args': ['--ripgrep'],
            },
          },
        ),
      );
      expect(result.success, isTrue);
      expect(result.data.ripgrep?.command, 'claude');
      expect(result.data.ripgrep?.args, ['--ripgrep']);
    });

    test('should accept valid allowMachLookup entries', () {
      _expectResult(
        _config(
          network: {
            'allowedDomains': <String>[],
            'deniedDomains': <String>[],
            'allowMachLookup': ['com.example.*', '*'],
          },
        ),
        true,
      );
    });

    _testEach(
      ['com.*.foo', 'com.example.**'],
      'should reject allowMachLookup entry with non-trailing wildcard: %s',
      (entry) => _expectResult(
        _config(
          network: {
            'allowedDomains': <String>[],
            'deniedDomains': <String>[],
            'allowMachLookup': [entry],
          },
        ),
        false,
      ),
    );

    test('should use default ripgrep command when not specified', () {
      final result = SandboxRuntimeConfigSchema.safeParse(_config());
      expect(result.success, isTrue);
      expect(result.data.ripgrep, isNull);
    });

    group('deny globs with a trailing separator', () {
      tearDown(() => process.setPlatformForTesting(null));

      _testEach(
        [
          ['/data/*/'],
          ['/data/**/'],
          ['/data/?/'],
        ],
        'rejects denyRead %s',
        (path) => _expectResult(
          _config(
            filesystem: {
              'denyRead': [path],
              'allowWrite': <Object>[],
              'denyWrite': <Object>[],
            },
          ),
          false,
        ),
      );
      if (getPlatform() != 'windows') {
        test('rejects denyRead /data/[ab]/', () {
          process.setPlatformForTesting('linux');
          final result = SandboxRuntimeConfigSchema.safeParse(
            _config(
              filesystem: {
                'denyRead': ['/data/[ab]/'],
                'allowWrite': <Object>[],
                'denyWrite': <Object>[],
              },
            ),
          );
          expect(result.success, isFalse);
        });
      }
      test(
        'rejects a slashed denyWrite glob, naming the spelling to use',
        () => _expectResult(
          _config(
            filesystem: {
              'denyRead': <Object>[],
              'allowWrite': <Object>[],
              'denyWrite': ['/data/*/'],
            },
          ),
          false,
        ),
      );
      test(
        'rejects a slashed glob on a mode "deny" credential file',
        () => _expectResult(
          _config(
            other: {
              'credentials': {
                'files': [
                  {'path': '~/.aws/*/', 'mode': 'deny'},
                ],
              },
            },
          ),
          false,
        ),
      );
      if (getPlatform() != 'windows') {
        test(
          'points a deny inside a folder named like a pattern at the spelling read both ways',
          () {
            process.setPlatformForTesting('linux');
            final result = SandboxRuntimeConfigSchema.safeParse(
              _config(
                filesystem: {
                  'denyRead': <Object>[],
                  'allowWrite': <Object>[],
                  'denyWrite': ['/work/[WIP] project/keep/'],
                },
              ),
            );
            expect(result.success, isFalse);
            expect(
              result.error.issues.first.message,
              contains('can match no path'),
            );
          },
        );
      }
      test('accepts the slash-free glob spellings it points at', () {
        _expectResult(
          _config(
            filesystem: {
              'denyRead': ['/data/*'],
              'allowWrite': <Object>[],
              'denyWrite': <Object>[],
            },
          ),
          true,
        );
      });
      test('leaves trailing-slash literals and allow globs alone', () {
        _expectResult(
          _config(
            filesystem: {
              'denyRead': [
                const {'path': '/data/*/', 'literal': true},
              ],
              'allowRead': ['/data/*/'],
              'allowWrite': <Object>[],
              'denyWrite': <Object>[],
            },
          ),
          true,
        );
      });
      test('accepts relative slashed globs, which normalisation strips', () {
        _expectResult(
          _config(
            filesystem: {
              'denyRead': ['build/*/'],
              'allowWrite': <Object>[],
              'denyWrite': <Object>[],
            },
          ),
          true,
        );
      });
      test('accepts a slashed deny glob when filesystem.disabled', () {
        _expectResult(
          _config(
            filesystem: {
              'disabled': true,
              'denyRead': ['/data/*/'],
              'allowWrite': <Object>[],
              'denyWrite': <Object>[],
            },
          ),
          true,
        );
      });
      test(
        'Windows: accepts a bracketed literal keeping its directory marker',
        () {
          process.setPlatformForTesting('win32');
          _expectResult(
            _config(
              filesystem: {
                'denyRead': ['C:\\data\\[WIP]\\'],
                'allowWrite': <Object>[],
                'denyWrite': <Object>[],
              },
            ),
            true,
          );
          if (getPlatform() != 'windows') return;
        },
      );
      _testEach(
        [
          ['C:\\data\\*\\'],
          ['C:/data/*/'],
        ],
        'Windows: rejects the slashed glob %s',
        (path) {
          process.setPlatformForTesting('win32');
          _expectResult(
            _config(
              filesystem: {
                'denyRead': [path],
                'allowWrite': <Object>[],
                'denyWrite': <Object>[],
              },
            ),
            false,
          );
        },
      );
      test(
        'POSIX: rejects a bracketed glob, where [ and ] are metacharacters',
        () {
          process.setPlatformForTesting('linux');
          _expectResult(
            _config(
              filesystem: {
                'denyRead': ['/data/[WIP]/'],
                'allowWrite': <Object>[],
                'denyWrite': <Object>[],
              },
            ),
            false,
          );
        },
      );
    });

    group('path entries marked literal', () {
      _testEach(
        ['denyRead', 'allowRead', 'allowWrite', 'denyWrite'],
        '%s takes a path marked literal beside a string',
        (list) {
          final listName = list as String;
          final fs = <String, Object?>{
            'denyRead': <Object>[],
            'allowWrite': <Object>[],
            'denyWrite': <Object>[],
          };
          fs[listName] = [
            '/work/plain',
            const {'path': '/work/*.env', 'literal': true},
          ];
          final result = SandboxRuntimeConfigSchema.safeParse(
            _config(filesystem: fs),
          );
          expect(result.success, isTrue);
          final entries = _filesystemEntries(result.data.filesystem, listName);
          expect(entries, hasLength(2));
          expect(entries![0], isA<FilesystemPathSpelling>());
          expect((entries[0] as FilesystemPathSpelling).path, '/work/plain');
          expect(entries[1], isA<FilesystemPathLiteral>());
          expect((entries[1] as FilesystemPathLiteral).path, '/work/*.env');
        },
      );
      _testEach(
        ['denyRead', 'allowRead', 'allowWrite', 'denyWrite'],
        '%s takes ~ and relative spellings marked literal',
        (list) {
          final listName = list as String;
          for (final path in [
            '~/notes (draft?)',
            './build*',
            '[WIP] project',
          ]) {
            final result = SandboxRuntimeConfigSchema.safeParse(
              _config(
                filesystem: {
                  'denyRead': <Object>[],
                  'allowWrite': <Object>[],
                  'denyWrite': <Object>[],
                  listName: [
                    <String, Object?>{'path': path, 'literal': true},
                  ],
                },
              ),
            );
            expect(result.success, isTrue);
          }
        },
      );
      final invalidEntries = <List<Object?>>[
        [
          'no mark',
          {'path': '/work/x'},
        ],
        [
          'a mark that is false',
          {'path': '/work/x', 'literal': false},
        ],
        [
          'a mark that is a string',
          {'path': '/work/x', 'literal': 'true'},
        ],
        [
          'a mark that is a number',
          {'path': '/work/x', 'literal': 1},
        ],
        [
          'no path',
          {'literal': true},
        ],
        [
          'a path that is not a string',
          {
            'path': ['/work/x'],
            'literal': true,
          },
        ],
        ['a number', 42],
        ['null', null],
        [
          'a list',
          ['/work/x'],
        ],
      ];
      _testEachArgs(invalidEntries, 'refuses an entry with %s', (what, entry) {
        for (final list in [
          'denyRead',
          'allowRead',
          'allowWrite',
          'denyWrite',
        ]) {
          final result = SandboxRuntimeConfigSchema.safeParse(
            _config(
              filesystem: {
                'denyRead': <Object>[],
                'allowWrite': <Object>[],
                'denyWrite': <Object>[],
                list: [entry],
              },
            ),
          );
          expect(result.success, isFalse);
          expect(result.error.issues[0].path.take(3).toList(), [
            'filesystem',
            list,
            0,
          ]);
        }
      });
      test('says what an entry may be when it is neither', () {
        final result = SandboxRuntimeConfigSchema.safeParse(
          _config(
            filesystem: {
              'denyRead': [
                {'path': '/work/x', 'literal': false},
              ],
              'allowWrite': <Object>[],
              'denyWrite': <Object>[],
            },
          ),
        );
        expect(result.success, isFalse);
        expect(
          result.error.issues.first.message,
          'Expected a path, or { "path": "<path>", "literal": true }',
        );
      });
      test('refuses a key it does not know, rather than ignore it', () {
        final result = SandboxRuntimeConfigSchema.safeParse(
          _config(
            filesystem: {
              'denyRead': [
                {'path': '/work/x', 'literal': true, 'recursive': true},
              ],
              'allowWrite': <Object>[],
              'denyWrite': <Object>[],
            },
          ),
        );
        expect(result.success, isFalse);
      });
      test('refuses an empty path, marked or not, with the same message', () {
        for (final entry in [
          '',
          const {'path': '', 'literal': true},
        ]) {
          final result = SandboxRuntimeConfigSchema.safeParse(
            _config(
              filesystem: {
                'denyRead': <Object>[],
                'allowWrite': [entry],
                'denyWrite': <Object>[],
              },
            ),
          );
          expect(result.success, isFalse);
          expect(result.error.issues.first.message, 'Path cannot be empty');
        }
      });
      test(
        'takes a separator at the end of a marked deny, which is no glob',
        () {
          final result = SandboxRuntimeConfigSchema.safeParse(
            _config(
              filesystem: {
                'denyRead': [
                  const {'path': '/data/*/', 'literal': true},
                ],
                'allowWrite': <Object>[],
                'denyWrite': <Object>[],
              },
            ),
          );
          expect(result.success, isTrue);
        },
      );
      test('does not take the mark on a credential file', () {
        _expectResult(
          _config(
            other: {
              'credentials': {
                'files': [
                  {
                    'path': const {'path': '~/.netrc', 'literal': true},
                    'mode': 'deny',
                  },
                ],
              },
            },
          ),
          false,
        );
      });
    });

    group('bwrapPath / socatPath', () {
      test('accepts absolute paths', () {
        _expectResult(
          _config(
            other: {
              'bwrapPath': '/usr/bin/bwrap',
              'socatPath': '/usr/bin/socat',
            },
          ),
          true,
        );
      });
      test('rejects relative bwrapPath', () {
        _expectResult(_config(other: {'bwrapPath': 'bwrap'}), false);
      });
      test('rejects relative socatPath', () {
        _expectResult(_config(other: {'socatPath': 'socat'}), false);
      });
      test('rejects empty bwrapPath', () {
        _expectResult(_config(other: {'bwrapPath': ''}), false);
      });
    });

    group('credentials', () {
      test('is optional — config without it validates and stays undefined', () {
        final result = SandboxRuntimeConfigSchema.safeParse(_config());
        expect(result.success, isTrue);
        expect(result.data.credentials, isNull);
      });
      test('accepts file and env var entries with deny mode', () {
        _expectResult(
          _config(
            other: {
              'credentials': {
                'files': [
                  {'path': '~/.netrc', 'mode': 'deny'},
                ],
                'envVars': [
                  {'name': 'GITHUB_TOKEN', 'mode': 'deny'},
                ],
              },
            },
          ),
          true,
        );
      });
      test('rejects mode "allow" — no longer a valid mode', () {
        _expectResult(
          _config(
            other: {
              'credentials': {
                'files': [
                  {'path': '~/.netrc', 'mode': 'allow'},
                ],
              },
            },
          ),
          false,
        );
      });
      test('accepts an empty credentials object', () {
        _expectResult(_config(other: {'credentials': {}}), true);
      });
      test('accepts mode "mask" for files when tlsTerminate is enabled', () {
        _expectResult(
          _config(
            network: {
              'allowedDomains': <String>[],
              'deniedDomains': <String>[],
              'tlsTerminate': {},
            },
            other: {
              'credentials': {
                'files': [
                  {'path': '~/.config/gh/token', 'mode': 'mask'},
                ],
              },
            },
          ),
          true,
        );
      });
      test('rejects mode "mask" for files without tlsTerminate', () {
        final result = SandboxRuntimeConfigSchema.safeParse(
          _config(
            other: {
              'credentials': {
                'files': [
                  {'path': '~/.config/gh/token', 'mode': 'mask'},
                ],
              },
            },
          ),
        );
        expect(result.success, isFalse);
        expect(
          result.error.issues.map((issue) => issue.message).join('\n'),
          contains('tlsTerminate'),
        );
      });
      test('injectHosts covered by a port-scoped allowedDomains entry', () {
        final ok = SandboxRuntimeConfigSchema.safeParse(
          _config(
            network: {
              'allowedDomains': ['api.github.com:443'],
              'deniedDomains': <String>[],
              'tlsTerminate': {},
            },
            other: {
              'credentials': {
                'files': [
                  {
                    'path': '~/.config/gh/token',
                    'mode': 'mask',
                    'injectHosts': ['api.github.com'],
                  },
                ],
              },
            },
          ),
        );
        expect(ok.success, isTrue);
        final bad = SandboxRuntimeConfigSchema.safeParse(
          _config(
            network: {
              'allowedDomains': ['api.github.com:443'],
              'deniedDomains': <String>[],
              'tlsTerminate': {},
            },
            other: {
              'credentials': {
                'files': [
                  {
                    'path': '~/.config/gh/token',
                    'mode': 'mask',
                    'injectHosts': ['api.github.com:443'],
                  },
                ],
              },
            },
          ),
        );
        expect(bad.success, isFalse);
      });
      test(
        'accepts a masked file with per-entry injectHosts',
        () => _expectResult(
          _config(
            network: {
              'allowedDomains': ['api.github.com'],
              'deniedDomains': <String>[],
              'tlsTerminate': {},
            },
            other: {
              'credentials': {
                'files': [
                  {
                    'path': '~/.config/gh/token',
                    'mode': 'mask',
                    'injectHosts': ['api.github.com'],
                  },
                ],
              },
            },
          ),
          true,
        ),
      );
      test(
        'rejects a masked file whose per-entry injectHosts is explicitly empty',
        () {
          final result = SandboxRuntimeConfigSchema.safeParse(
            _config(
              network: {
                'allowedDomains': <String>[],
                'deniedDomains': <String>[],
                'tlsTerminate': {},
              },
              other: {
                'credentials': {
                  'files': [
                    {
                      'path': '~/.config/gh/token',
                      'mode': 'mask',
                      'injectHosts': [],
                    },
                  ],
                },
              },
            ),
          );
          expect(result.success, isFalse);
          expect(
            result.error.issues.map((issue) => issue.message).join('\n'),
            contains('masked but never injected'),
          );
        },
      );
      test(
        'rejects per-entry file injectHosts not reachable via allowedDomains',
        () => _expectResult(
          _config(
            network: {
              'allowedDomains': <String>[],
              'deniedDomains': <String>[],
              'tlsTerminate': {},
            },
            other: {
              'credentials': {
                'files': [
                  {
                    'path': '~/.config/gh/token',
                    'mode': 'mask',
                    'injectHosts': ['registry.npmjs.org'],
                  },
                ],
              },
            },
          ),
          false,
        ),
      );
      test('accepts a masked file with an extract regex', () {
        _expectResult(
          _config(
            network: {
              'allowedDomains': <String>[],
              'deniedDomains': <String>[],
              'tlsTerminate': {},
            },
            other: {
              'credentials': {
                'files': [
                  {
                    'path': '~/.config/gh/hosts.yml',
                    'mode': 'mask',
                    'extract': 'oauth_token:\\s*(\\S+)',
                  },
                ],
              },
            },
          ),
          true,
        );
      });
      test('rejects an extract value that is not a valid regex', () {
        final result = SandboxRuntimeConfigSchema.safeParse(
          _config(
            network: {
              'allowedDomains': <String>[],
              'deniedDomains': <String>[],
              'tlsTerminate': {},
            },
            other: {
              'credentials': {
                'files': [
                  {
                    'path': '~/.config/gh/hosts.yml',
                    'mode': 'mask',
                    'extract': '(',
                  },
                ],
              },
            },
          ),
        );
        expect(result.success, isFalse);
        expect(
          result.error.issues.map((issue) => issue.message).join('\n'),
          contains('not a valid regular expression'),
        );
      });
      test('rejects an extract regex with no capturing group', () {
        _expectResult(
          _config(
            network: {
              'allowedDomains': <String>[],
              'deniedDomains': <String>[],
              'tlsTerminate': {},
            },
            other: {
              'credentials': {
                'files': [
                  {
                    'path': '~/.config/gh/hosts.yml',
                    'mode': 'mask',
                    'extract': 'token\\s*\\S+',
                  },
                ],
              },
            },
          ),
          false,
        );
      });
      test(
        'a non-capturing group does not satisfy the extract group requirement',
        () {
          _expectResult(
            _credentialConfig({
              'files': [
                {
                  'path': '~/.netrc',
                  'mode': 'mask',
                  'extract': r'password (?:\S+)',
                },
              ],
            }, tlsTerminate: true),
            false,
          );
        },
      );
      test('extract on a deny-mode entry is accepted (ignored)', () {
        _expectResult(
          _credentialConfig({
            'files': [
              {
                'path': '~/.netrc',
                'mode': 'deny',
                'extract': r'password (\S+)',
              },
            ],
          }),
          true,
        );
      });
      test('accepts a masked file with decode "jwt" and no extract', () {
        _expectResult(
          _credentialConfig({
            'files': [
              {
                'path': '~/.config/app/credentials',
                'mode': 'mask',
                'decode': 'jwt',
              },
            ],
          }, tlsTerminate: true),
          true,
        );
      });
      test('accepts decode combined with an explicit extract pattern', () {
        _expectResult(
          _credentialConfig({
            'files': [
              {
                'path': '~/.config/app/credentials',
                'mode': 'mask',
                'extract': r'id_token:\s*(\S+)',
                'decode': 'jwt',
              },
            ],
          }, tlsTerminate: true),
          true,
        );
      });
      test('rejects an unknown decode encoding', () {
        final result = SandboxRuntimeConfigSchema.safeParse(
          _credentialConfig({
            'files': [
              {
                'path': '~/.config/app/credentials',
                'mode': 'mask',
                'decode': 'base64',
              },
            ],
          }),
        );
        expect(result.success, isFalse);
        expect(
          result.error.issues.any(
            (issue) => issue.path.join('.') == 'credentials.files.0.decode',
          ),
          isTrue,
        );
      });
      test('decode on a deny-mode entry is accepted (ignored)', () {
        _expectResult(
          _credentialConfig({
            'files': [
              {
                'path': '~/.config/app/credentials',
                'mode': 'deny',
                'decode': 'jwt',
              },
            ],
          }),
          true,
        );
      });
      test('accepts maskClaims alongside decode "jwt"', () {
        final result = SandboxRuntimeConfigSchema.safeParse(
          _config(
            network: {
              'allowedDomains': <String>[],
              'deniedDomains': <String>[],
              'tlsTerminate': {},
            },
            other: {
              'credentials': {
                'files': [
                  {
                    'path': '~/.config/app/credentials',
                    'mode': 'mask',
                    'decode': 'jwt',
                    'maskClaims': ['access_token'],
                  },
                ],
              },
            },
          ),
        );
        expect(result.success, isTrue);
        expect(result.data.credentials?.files?.first.maskClaims, [
          'access_token',
        ]);
      });
      test('rejects maskClaims without decode', () {
        final result = SandboxRuntimeConfigSchema.safeParse(
          _config(
            network: {
              'allowedDomains': <String>[],
              'deniedDomains': <String>[],
              'tlsTerminate': {},
            },
            other: {
              'credentials': {
                'files': [
                  {
                    'path': '~/.config/app/credentials',
                    'mode': 'mask',
                    'maskClaims': ['access_token'],
                  },
                ],
              },
            },
          ),
        );
        expect(result.success, isFalse);
        expect(
          result.error.issues.map((issue) => issue.message).join('\n'),
          contains('requires decode'),
        );
      });
      test('rejects an explicitly empty maskClaims', () {
        _expectResult(
          _config(
            network: {
              'allowedDomains': <String>[],
              'deniedDomains': <String>[],
              'tlsTerminate': {},
            },
            other: {
              'credentials': {
                'files': [
                  {
                    'path': '~/.config/app/credentials',
                    'mode': 'mask',
                    'decode': 'jwt',
                    'maskClaims': [],
                  },
                ],
              },
            },
          ),
          false,
        );
      });
      test('rejects an empty string in maskClaims', () {
        _expectResult(
          _credentialConfig({
            'files': [
              {
                'path': '~/.config/app/credentials',
                'mode': 'mask',
                'decode': 'jwt',
                'maskClaims': [''],
              },
            ],
          }, tlsTerminate: true),
          false,
        );
      });
      test(
        'maskClaims with decode on a deny-mode entry is accepted (ignored)',
        () {
          _expectResult(
            _credentialConfig({
              'files': [
                {
                  'path': '~/.config/app/credentials',
                  'mode': 'deny',
                  'decode': 'jwt',
                  'maskClaims': ['api_key'],
                },
              ],
            }),
            true,
          );
        },
      );
      _testEach(
        ['warn', 'deny', 'error'],
        'accepts onExtractNoMatch: "%s"',
        (mode) => _expectResult(
          _credentialConfig({
            'files': [
              {
                'path': '~/.netrc',
                'mode': 'mask',
                'extract': r'password (\S+)',
                'onExtractNoMatch': mode,
              },
            ],
          }, tlsTerminate: true),
          true,
        ),
      );
      test('rejects an invalid onExtractNoMatch value', () {
        _expectResult(
          _credentialConfig({
            'files': [
              {
                'path': '~/.netrc',
                'mode': 'mask',
                'extract': r'password (\S+)',
                'onExtractNoMatch': 'ignore',
              },
            ],
          }, tlsTerminate: true),
          false,
        );
      });
      test('accepts maskDuplicates alongside extract', () {
        _expectResult(
          _credentialConfig({
            'files': [
              {
                'path': '~/.netrc',
                'mode': 'mask',
                'extract': r'password (\S+)',
                'maskDuplicates': true,
              },
            ],
          }, tlsTerminate: true),
          true,
        );
      });
      test('maskDuplicates without extract is accepted (ignored)', () {
        _expectResult(
          _credentialConfig({
            'files': [
              {'path': '~/.netrc', 'mode': 'mask', 'maskDuplicates': true},
            ],
          }, tlsTerminate: true),
          true,
        );
      });
      test('maskDuplicates on a deny-mode entry is accepted (ignored)', () {
        _expectResult(
          _credentialConfig({
            'files': [
              {'path': '~/.netrc', 'mode': 'deny', 'maskDuplicates': true},
            ],
          }),
          true,
        );
      });
      test('rejects a non-boolean maskDuplicates', () {
        _expectResult(
          _credentialConfig({
            'files': [
              {
                'path': '~/.netrc',
                'mode': 'mask',
                'extract': r'password (\S+)',
                'maskDuplicates': 'true',
              },
            ],
          }, tlsTerminate: true),
          false,
        );
      });
      test('accepts a masked env var with an extract regex', () {
        _expectResult(
          _credentialConfig({
            'envVars': [
              {'name': 'GH_TOKEN', 'mode': 'mask', 'extract': r'token=(\S+)'},
            ],
          }, tlsTerminate: true),
          true,
        );
      });
      test('rejects an env extract value that is not a valid regex', () {
        final result = SandboxRuntimeConfigSchema.safeParse(
          _credentialConfig({
            'envVars': [
              {'name': 'GH_TOKEN', 'mode': 'mask', 'extract': '('},
            ],
          }, tlsTerminate: true),
        );
        expect(result.success, isFalse);
        expect(
          result.error.issues.map((issue) => issue.message).join('\n'),
          contains('not a valid regular expression'),
        );
      });
      test('rejects an env extract regex with no capturing group', () {
        _expectResult(
          _credentialConfig({
            'envVars': [
              {'name': 'GH_TOKEN', 'mode': 'mask', 'extract': r'token=\S+'},
            ],
          }, tlsTerminate: true),
          false,
        );
      });
      test('extract on a deny-mode env var is accepted (ignored)', () {
        _expectResult(
          _credentialConfig({
            'envVars': [
              {'name': 'GH_TOKEN', 'mode': 'deny', 'extract': r'token=(\S+)'},
            ],
          }),
          true,
        );
      });
      _testEach(
        ['warn', 'deny', 'error'],
        'accepts onExtractNoMatch: "%s" on an env var',
        (mode) => _expectResult(
          _credentialConfig({
            'envVars': [
              {
                'name': 'GH_TOKEN',
                'mode': 'mask',
                'extract': r'token=(\S+)',
                'onExtractNoMatch': mode,
              },
            ],
          }, tlsTerminate: true),
          true,
        ),
      );
      test('rejects an invalid onExtractNoMatch value on an env var', () {
        _expectResult(
          _credentialConfig({
            'envVars': [
              {
                'name': 'GH_TOKEN',
                'mode': 'mask',
                'extract': r'token=(\S+)',
                'onExtractNoMatch': 'ignore',
              },
            ],
          }, tlsTerminate: true),
          false,
        );
      });
      test('rejects mode "mask" on a directory path (trailing slash)', () {
        final result = SandboxRuntimeConfigSchema.safeParse(
          _credentialConfig({
            'files': [
              {'path': '~/.config/gh/', 'mode': 'mask'},
            ],
          }, tlsTerminate: true),
        );
        expect(result.success, isFalse);
        expect(
          result.error.issues.map((issue) => issue.message).join('\n'),
          contains('not a directory'),
        );
      });
      test('accepts mode "mask" for env vars when tlsTerminate is enabled', () {
        _expectResult(
          _credentialConfig({
            'envVars': [
              {'name': 'GH_TOKEN', 'mode': 'mask'},
            ],
          }, tlsTerminate: true),
          true,
        );
      });
      test('rejects mode "mask" for env vars without tlsTerminate', () {
        final result = SandboxRuntimeConfigSchema.safeParse(
          _credentialConfig({
            'envVars': [
              {'name': 'GH_TOKEN', 'mode': 'mask'},
            ],
          }),
        );
        expect(result.success, isFalse);
        expect(
          result.error.issues.map((issue) => issue.message).join('\n'),
          contains('tlsTerminate'),
        );
      });
      test('allowPlaintextInject permits mask without tlsTerminate', () {
        _expectResult(
          _credentialConfig({
            'allowPlaintextInject': true,
            'envVars': [
              {'name': 'GH_TOKEN', 'mode': 'mask'},
            ],
          }),
          true,
        );
      });
      test(
        'accepts a masked env var with no injectHosts (defaults to allowedDomains)',
        () {
          _expectResult(
            _credentialConfig({
              'envVars': [
                {'name': 'GH_TOKEN', 'mode': 'mask'},
              ],
            }, tlsTerminate: true),
            true,
          );
        },
      );
      test(
        'rejects a masked env var whose per-entry injectHosts is explicitly empty',
        () {
          final result = SandboxRuntimeConfigSchema.safeParse(
            _credentialConfig({
              'envVars': [
                {'name': 'GH_TOKEN', 'mode': 'mask', 'injectHosts': []},
              ],
            }, tlsTerminate: true),
          );
          expect(result.success, isFalse);
          expect(
            result.error.issues.map((issue) => issue.message).join('\n'),
            contains('masked but never injected'),
          );
        },
      );
      test('rejects block-level credentials.injectHosts (removed key)', () {
        _expectResult(
          _credentialConfig({
            'injectHosts': ['api.github.com'],
          }),
          false,
        );
      });
      test(
        'accepts a masked env var with per-entry injectHosts',
        () => _expectResult(
          _credentialConfig(
            {
              'envVars': [
                {
                  'name': 'GH_TOKEN',
                  'mode': 'mask',
                  'injectHosts': ['api.github.com'],
                },
              ],
            },
            tlsTerminate: true,
            allowedDomains: ['api.github.com'],
          ),
          true,
        ),
      );
      test(
        'rejects per-entry injectHosts not reachable via allowedDomains',
        () => _expectResult(
          _credentialConfig(
            {
              'envVars': [
                {
                  'name': 'GH_TOKEN',
                  'mode': 'mask',
                  'injectHosts': ['registry.npmjs.org'],
                },
              ],
            },
            tlsTerminate: true,
            allowedDomains: ['api.github.com'],
          ),
          false,
        ),
      );
      test(
        'rejects overly-broad wildcards in per-entry injectHosts',
        () => _expectResult(
          _credentialConfig(
            {
              'envVars': [
                {
                  'name': 'GH_TOKEN',
                  'mode': 'mask',
                  'injectHosts': ['*'],
                },
              ],
            },
            tlsTerminate: true,
            allowedDomains: ['api.github.com'],
          ),
          false,
        ),
      );
      test('injectHosts on a deny-mode entry is accepted (ignored)', () {
        _expectResult(
          _credentialConfig(
            {
              'envVars': [
                {
                  'name': 'GH_TOKEN',
                  'mode': 'deny',
                  'injectHosts': ['api.github.com'],
                },
              ],
            },
            allowedDomains: ['api.github.com'],
          ),
          true,
        );
      });
      test('accepts a masked env var with decode "jwt"', () {
        _expectResult(
          _credentialConfig({
            'envVars': [
              {'name': 'GH_TOKEN', 'mode': 'mask', 'decode': 'jwt'},
            ],
          }, tlsTerminate: true),
          true,
        );
      });
      test('rejects an unknown decode encoding on an env var entry', () {
        _expectResult(
          _credentialConfig({
            'envVars': [
              {'name': 'GH_TOKEN', 'mode': 'mask', 'decode': 'base64'},
            ],
          }, tlsTerminate: true),
          false,
        );
      });
      test('decode on a deny-mode env var entry is accepted (ignored)', () {
        _expectResult(
          _credentialConfig({
            'envVars': [
              {'name': 'GH_TOKEN', 'mode': 'deny', 'decode': 'jwt'},
            ],
          }),
          true,
        );
      });
      test('accepts maskClaims alongside decode "jwt" on an env var', () {
        _expectResult(
          _credentialConfig({
            'envVars': [
              {
                'name': 'GH_TOKEN',
                'mode': 'mask',
                'decode': 'jwt',
                'maskClaims': ['access_token'],
              },
            ],
          }, tlsTerminate: true),
          true,
        );
      });
      test('rejects maskClaims without decode on an env var', () {
        final result = SandboxRuntimeConfigSchema.safeParse(
          _credentialConfig({
            'envVars': [
              {
                'name': 'GH_TOKEN',
                'mode': 'mask',
                'maskClaims': ['access_token'],
              },
            ],
          }, tlsTerminate: true),
        );
        expect(result.success, isFalse);
        expect(
          result.error.issues.map((issue) => issue.message).join('\n'),
          contains('requires decode'),
        );
      });
      test('rejects an explicitly empty maskClaims on an env var', () {
        _expectResult(
          _credentialConfig({
            'envVars': [
              {
                'name': 'GH_TOKEN',
                'mode': 'mask',
                'decode': 'jwt',
                'maskClaims': [],
              },
            ],
          }, tlsTerminate: true),
          false,
        );
      });
      test('rejects an empty string in maskClaims on an env var', () {
        _expectResult(
          _credentialConfig({
            'envVars': [
              {
                'name': 'GH_TOKEN',
                'mode': 'mask',
                'decode': 'jwt',
                'maskClaims': [''],
              },
            ],
          }, tlsTerminate: true),
          false,
        );
      });
      test(
        'maskClaims with decode on a deny-mode env var entry is accepted (ignored)',
        () {
          _expectResult(
            _credentialConfig({
              'envVars': [
                {
                  'name': 'GH_TOKEN',
                  'mode': 'deny',
                  'decode': 'jwt',
                  'maskClaims': ['access_token'],
                },
              ],
            }),
            true,
          );
        },
      );
      test(
        'accepts per-entry injectHosts that are a subset of allowedDomains',
        () => _expectResult(
          _credentialConfig(
            {
              'envVars': [
                {
                  'name': 'GH_TOKEN',
                  'mode': 'mask',
                  'injectHosts': ['api.github.com', 'npmjs.org'],
                },
              ],
            },
            tlsTerminate: true,
            allowedDomains: ['api.github.com', 'npmjs.org'],
          ),
          true,
        ),
      );
      test(
        'accepts an exact injectHost covered by a wildcard allowedDomain',
        () => _expectResult(
          _credentialConfig(
            {
              'envVars': [
                {
                  'name': 'GH_TOKEN',
                  'mode': 'mask',
                  'injectHosts': ['api.github.com'],
                },
              ],
            },
            tlsTerminate: true,
            allowedDomains: ['*.github.com'],
          ),
          true,
        ),
      );
      test(
        'accepts a wildcard injectHost covered by a broader allowed wildcard',
        () => _expectResult(
          _credentialConfig(
            {
              'envVars': [
                {
                  'name': 'GH_TOKEN',
                  'mode': 'mask',
                  'injectHosts': ['*.api.github.com'],
                },
              ],
            },
            tlsTerminate: true,
            allowedDomains: ['*.github.com'],
          ),
          true,
        ),
      );
      test(
        'rejects a wildcard injectHost not covered by an exact allowedDomain',
        () => _expectResult(
          _credentialConfig(
            {
              'envVars': [
                {
                  'name': 'GH_TOKEN',
                  'mode': 'mask',
                  'injectHosts': ['*.github.com'],
                },
              ],
            },
            tlsTerminate: true,
            allowedDomains: ['api.github.com'],
          ),
          false,
        ),
      );
      test(
        'rejects an exact injectHost not covered by an unrelated wildcard',
        () => _expectResult(
          _credentialConfig(
            {
              'envVars': [
                {
                  'name': 'GH_TOKEN',
                  'mode': 'mask',
                  'injectHosts': ['api.github.com'],
                },
              ],
            },
            tlsTerminate: true,
            allowedDomains: ['*.npmjs.org'],
          ),
          false,
        ),
      );
      test('rejects unknown modes', () {
        _expectResult(
          _config(
            other: {
              'credentials': {
                'files': [
                  {'path': '~/.netrc', 'mode': 'invalid'},
                ],
              },
            },
          ),
          false,
        );
      });
      test('rejects empty file paths', () {
        _expectResult(
          _config(
            other: {
              'credentials': {
                'files': [
                  {'path': '', 'mode': 'deny'},
                ],
              },
            },
          ),
          false,
        );
      });
      _testEach(
        ['', 'FOO=BAR', 'FOO BAR', '--bind', '-u', '1FOO', 'FOO.BAR'],
        'rejects invalid env var name: %j',
        (name) => _expectResult(
          _config(
            other: {
              'credentials': {
                'envVars': [
                  {'name': name, 'mode': 'deny'},
                ],
              },
            },
          ),
          false,
        ),
      );
      _testEach(
        ['_FOO', 'FOO_BAR2'],
        'accepts valid env var name: %j',
        (name) => _expectResult(
          _config(
            other: {
              'credentials': {
                'envVars': [
                  {'name': name, 'mode': 'deny'},
                ],
              },
            },
          ),
          true,
        ),
      );
    });

    group('network.tlsTerminate', () {
      test('is optional — config without it validates', () {
        _expectResult(_config(), true);
      });
      test('accepts caCertPath + caKeyPath', () {
        _expectResult(
          _config(
            network: {
              'allowedDomains': <String>[],
              'deniedDomains': <String>[],
              'tlsTerminate': {
                'caCertPath': '/tmp/ca.crt',
                'caKeyPath': '/tmp/ca.key',
              },
            },
          ),
          true,
        );
      });
      test('rejects when caKeyPath is missing', () {
        _expectResult(
          _config(
            network: {
              'allowedDomains': <String>[],
              'deniedDomains': <String>[],
              'tlsTerminate': {'caCertPath': '/tmp/ca.crt'},
            },
          ),
          false,
        );
      });
      test('rejects empty caCertPath', () {
        _expectResult(
          _config(
            network: {
              'allowedDomains': <String>[],
              'deniedDomains': <String>[],
              'tlsTerminate': {'caCertPath': '', 'caKeyPath': '/tmp/ca.key'},
            },
          ),
          false,
        );
      });
      group('excludeDomains', () {
        test(
          'accepts exact and wildcard patterns',
          () => _expectResult(
            _config(
              network: {
                'allowedDomains': <String>[],
                'deniedDomains': <String>[],
                'tlsTerminate': {
                  'excludeDomains': [
                    'api.example.com',
                    '*.internal.example.com',
                  ],
                },
              },
            ),
            true,
          ),
        );
        test(
          'rejects invalid domain patterns',
          () => _expectResult(
            _config(
              network: {
                'allowedDomains': <String>[],
                'deniedDomains': <String>[],
                'tlsTerminate': {
                  'excludeDomains': ['*'],
                },
              },
            ),
            false,
          ),
        );
        test(
          'rejects a bare "*" (would silently disable termination)',
          () => _expectResult(
            _config(
              network: {
                'allowedDomains': <String>[],
                'deniedDomains': <String>[],
                'tlsTerminate': {
                  'excludeDomains': ['*'],
                },
              },
            ),
            false,
          ),
        );
        test(
          'rejects a masked credential whose explicit injectHosts entry is fully covered by excludeDomains',
          () {
            final result = SandboxRuntimeConfigSchema.safeParse(
              _config(
                network: {
                  'allowedDomains': ['api.github.com'],
                  'deniedDomains': <String>[],
                  'tlsTerminate': {
                    'excludeDomains': ['api.github.com'],
                  },
                },
                other: {
                  'credentials': {
                    'envVars': [
                      {
                        'name': 'GH_TOKEN',
                        'mode': 'mask',
                        'injectHosts': ['api.github.com'],
                      },
                    ],
                  },
                },
              ),
            );
            expect(result.success, isFalse);
            expect(
              result.error.issues.map((issue) => issue.message).join('\n'),
              contains('entirely covered'),
            );
          },
        );
        test(
          'accepts an explicit wildcard injectHosts that merely overlaps excludeDomains',
          () {
            final result = SandboxRuntimeConfigSchema.safeParse(
              _config(
                network: {
                  'allowedDomains': ['*.github.com'],
                  'deniedDomains': <String>[],
                  'tlsTerminate': {
                    'excludeDomains': ['api.github.com'],
                  },
                },
                other: {
                  'credentials': {
                    'envVars': [
                      {
                        'name': 'GH_TOKEN',
                        'mode': 'mask',
                        'injectHosts': ['*.github.com'],
                      },
                    ],
                  },
                },
              ),
            );
            expect(result.success, isTrue);
          },
        );
        test(
          'rejects a masked credential with default injectHosts when excludeDomains covers every allowed domain',
          () {
            final result = SandboxRuntimeConfigSchema.safeParse(
              _config(
                network: {
                  'allowedDomains': ['api.github.com'],
                  'deniedDomains': <String>[],
                  'tlsTerminate': {
                    'excludeDomains': ['api.github.com'],
                  },
                },
                other: {
                  'credentials': {
                    'envVars': [
                      {'name': 'GH_TOKEN', 'mode': 'mask'},
                    ],
                  },
                },
              ),
            );
            expect(result.success, isFalse);
            expect(
              result.error.issues.map((issue) => issue.message).join('\n'),
              contains('covers every allowed domain'),
            );
          },
        );
        test(
          'a masked credential with default (absent) injectHosts coexists with a partial excludeDomains',
          () {
            final result = SandboxRuntimeConfigSchema.safeParse(
              _config(
                network: {
                  'allowedDomains': ['api.github.com', 'registry.npmjs.org'],
                  'deniedDomains': <String>[],
                  'tlsTerminate': {
                    'excludeDomains': ['api.github.com'],
                  },
                },
                other: {
                  'credentials': {
                    'envVars': [
                      {'name': 'GH_TOKEN', 'mode': 'mask'},
                    ],
                  },
                },
              ),
            );
            expect(result.success, isTrue);
          },
        );
        test(
          'explicit injectHosts disjoint from excludeDomains is accepted',
          () {
            final result = SandboxRuntimeConfigSchema.safeParse(
              _config(
                network: {
                  'allowedDomains': ['api.github.com', 'registry.npmjs.org'],
                  'deniedDomains': <String>[],
                  'tlsTerminate': {
                    'excludeDomains': ['api.github.com'],
                  },
                },
                other: {
                  'credentials': {
                    'envVars': [
                      {
                        'name': 'GH_TOKEN',
                        'mode': 'mask',
                        'injectHosts': ['registry.npmjs.org'],
                      },
                    ],
                  },
                },
              ),
            );
            expect(result.success, isTrue);
          },
        );
      });
      group('extraCaCertPaths', () {
        test('accepts a list of paths and round-trips it', () {
          final result = SandboxRuntimeConfigSchema.safeParse(
            _config(
              network: {
                'allowedDomains': <String>[],
                'deniedDomains': <String>[],
                'tlsTerminate': {
                  'extraCaCertPaths': ['/tmp/internal-ca.pem'],
                },
              },
            ),
          );
          expect(result.success, isTrue);
          expect(result.data.network.tlsTerminate?.extraCaCertPaths, [
            '/tmp/internal-ca.pem',
          ]);
        });
        test('is optional', () {
          final result = SandboxRuntimeConfigSchema.safeParse(
            _config(
              network: {
                'allowedDomains': <String>[],
                'deniedDomains': <String>[],
                'tlsTerminate': {},
              },
            ),
          );
          expect(result.success, isTrue);
          expect(result.data.network.tlsTerminate?.extraCaCertPaths, isNull);
        });
        test('rejects an empty path', () {
          _expectResult(
            _config(
              network: {
                'allowedDomains': <String>[],
                'deniedDomains': <String>[],
                'tlsTerminate': {
                  'extraCaCertPaths': [''],
                },
              },
            ),
            false,
          );
        });
      });
      group('maxTunnels and handshakeTimeoutMs', () {
        test('are optional and round-trip when given', () {
          final result = SandboxRuntimeConfigSchema.safeParse(
            _config(
              network: {
                'allowedDomains': <String>[],
                'deniedDomains': <String>[],
                'tlsTerminate': {'maxTunnels': 4, 'handshakeTimeoutMs': 200},
              },
            ),
          );
          expect(result.success, isTrue);
          expect(result.data.network.tlsTerminate?.maxTunnels, 4);
          expect(result.data.network.tlsTerminate?.handshakeTimeoutMs, 200);
        });
        test('accept their bounds', () {
          _expectResult(
            _config(
              network: {
                'allowedDomains': <String>[],
                'deniedDomains': <String>[],
                'tlsTerminate': {'maxTunnels': 1, 'handshakeTimeoutMs': 100},
              },
            ),
            true,
          );
        });
        test('reject a value that is not a positive integer in range', () {
          _expectResult(
            _config(
              network: {
                'allowedDomains': <String>[],
                'deniedDomains': <String>[],
                'tlsTerminate': {'maxTunnels': 0},
              },
            ),
            false,
          );
        });
      });
    });
  });
}
