// Ported from sandbox-runtime test/config-validation.test.ts @ 24eb39e.
import 'dart:convert';

import 'package:test/test.dart';

import 'package:sandbox_runtime/src/node/process.dart' as process;
import 'package:sandbox_runtime/src/sandbox/sandbox_config.dart';

import 'helpers/platform.dart';

void main() {
  group('Config Validation', () {
    test('should validate a valid minimal config', () {
      final config = {
        'network': {'allowedDomains': [], 'deniedDomains': []},
        'filesystem': {'denyRead': [], 'allowWrite': [], 'denyWrite': []},
      };

      final result = SandboxRuntimeConfigSchema.safeParse(config);
      expect(result.success, isTrue);
    });

    test('should validate a config with valid domains', () {
      final config = {
        'network': {
          'allowedDomains': ['example.com', '*.github.com', 'localhost'],
          'deniedDomains': ['evil.com'],
        },
        'filesystem': {'denyRead': [], 'allowWrite': [], 'denyWrite': []},
      };

      final result = SandboxRuntimeConfigSchema.safeParse(config);
      expect(result.success, isTrue);
    });

    test('should reject invalid domain patterns', () {
      final config = {
        'network': {
          'allowedDomains': ['not-a-domain'],
          'deniedDomains': [],
        },
        'filesystem': {'denyRead': [], 'allowWrite': [], 'denyWrite': []},
      };

      final result = SandboxRuntimeConfigSchema.safeParse(config);
      expect(result.success, isFalse);
    });

    test('should reject domain with protocol', () {
      final config = {
        'network': {
          'allowedDomains': ['https://example.com'],
          'deniedDomains': [],
        },
        'filesystem': {'denyRead': [], 'allowWrite': [], 'denyWrite': []},
      };

      final result = SandboxRuntimeConfigSchema.safeParse(config);
      expect(result.success, isFalse);
    });

    test('should reject empty filesystem paths', () {
      final config = {
        'network': {'allowedDomains': [], 'deniedDomains': []},
        'filesystem': {
          'denyRead': [''],
          'allowWrite': [],
          'denyWrite': [],
        },
      };

      final result = SandboxRuntimeConfigSchema.safeParse(config);
      expect(result.success, isFalse);
    });

    test('should validate config with optional fields', () {
      final config = {
        'network': {
          'allowedDomains': ['example.com'],
          'deniedDomains': [],
          'allowUnixSockets': ['/var/run/docker.sock'],
          'allowAllUnixSockets': false,
          'allowLocalBinding': true,
        },
        'filesystem': {
          'denyRead': ['/etc/shadow'],
          'allowWrite': ['/tmp'],
          'denyWrite': ['/etc'],
        },
        'ignoreViolations': {
          '*': ['/usr/bin'],
          'git push': ['/usr/bin/nc'],
        },
        'enableWeakerNestedSandbox': true,
        'enableWeakerNetworkIsolation': false,
      };

      final result = SandboxRuntimeConfigSchema.safeParse(config);
      expect(result.success, isTrue);
    });

    test('should reject missing required fields', () {
      final config = {
        'network': {'allowedDomains': []},
        'filesystem': {'denyRead': []},
      };

      final result = SandboxRuntimeConfigSchema.safeParse(config);
      expect(result.success, isFalse);
    });

    test('should validate wildcard domains correctly', () {
      final validWildcards = ['*.example.com', '*.github.io', '*.co.uk'];

      final invalidWildcards = [
        '*example.com', // Missing dot after asterisk
        '*.com', // No subdomain
        '*.', // Invalid format
      ];

      for (final domain in validWildcards) {
        final config = {
          'network': {
            'allowedDomains': [domain],
            'deniedDomains': [],
          },
          'filesystem': {'denyRead': [], 'allowWrite': [], 'denyWrite': []},
        };
        final result = SandboxRuntimeConfigSchema.safeParse(config);
        expect(result.success, isTrue);
      }

      for (final domain in invalidWildcards) {
        final config = {
          'network': {
            'allowedDomains': [domain],
            'deniedDomains': [],
          },
          'filesystem': {'denyRead': [], 'allowWrite': [], 'denyWrite': []},
        };
        final result = SandboxRuntimeConfigSchema.safeParse(config);
        expect(result.success, isFalse);
      }
    });

    test('should accept ":port" suffixes on allowed/denied domains', () {
      final valid = [
        'example.com:443',
        '[::1]',
        '[::1]:443',
        '[2001:db8::1]:8443',
        '*.example.com:8080',
        'localhost:3000',
        'example.com:65535',
        'example.com:1',
      ];
      for (final domain in valid) {
        final result = SandboxRuntimeConfigSchema.safeParse({
          'network': {
            'allowedDomains': [domain],
            'deniedDomains': [],
          },
          'filesystem': {'denyRead': [], 'allowWrite': [], 'denyWrite': []},
        });
        expect(result.success, isTrue);
      }

      // deniedDomains additionally accepts a bare "*" with a port.
      final denyOnly = SandboxRuntimeConfigSchema.safeParse({
        'network': {
          'allowedDomains': [],
          'deniedDomains': ['*:22'],
        },
        'filesystem': {'denyRead': [], 'allowWrite': [], 'denyWrite': []},
      });
      expect(denyOnly.success, isTrue);

      final invalid = [
        'example.com:0', // port out of range → suffix not a port → ":" in host
        'example.com:65536',
        'example.com:0443', // leading zero
        'example.com:abc',
        'example.com:80:443',
        'example.com:', // empty suffix
        '*:22', // "*" is deny-only, still rejected in allowedDomains
        '::1', // IPv6 literals must be bracketed
        'fd00:ec2::254',
        '2001:db8::1:443', // ambiguous — is 443 a port or the last hextet?
        '[::1', // unterminated bracket
        '[::1]:0',
        '[not-an-ip]',
      ];
      for (final domain in invalid) {
        final result = SandboxRuntimeConfigSchema.safeParse({
          'network': {
            'allowedDomains': [domain],
            'deniedDomains': [],
          },
          'filesystem': {'denyRead': [], 'allowWrite': [], 'denyWrite': []},
        });
        expect(result.success, isFalse);
      }
    });

    test('should validate config with enableWeakerNetworkIsolation', () {
      final config = {
        'network': {
          'allowedDomains': ['example.com'],
          'deniedDomains': [],
        },
        'filesystem': {'denyRead': [], 'allowWrite': [], 'denyWrite': []},
        'enableWeakerNetworkIsolation': true,
      };

      final result = SandboxRuntimeConfigSchema.safeParse(config);
      expect(result.success, isTrue);
      if (result.success) {
        expect(result.data.enableWeakerNetworkIsolation, isTrue);
      }
    });

    test('should validate config with allowAppleEvents', () {
      final config = {
        'network': {
          'allowedDomains': ['example.com'],
          'deniedDomains': [],
        },
        'filesystem': {'denyRead': [], 'allowWrite': [], 'denyWrite': []},
        'allowAppleEvents': true,
      };

      final result = SandboxRuntimeConfigSchema.safeParse(config);
      expect(result.success, isTrue);
      if (result.success) {
        expect(result.data.allowAppleEvents, isTrue);
      }
    });

    test('should validate config with custom ripgrep command', () {
      final config = {
        'network': {'allowedDomains': [], 'deniedDomains': []},
        'filesystem': {'denyRead': [], 'allowWrite': [], 'denyWrite': []},
        'ripgrep': {'command': '/usr/local/bin/rg'},
      };

      final result = SandboxRuntimeConfigSchema.safeParse(config);
      expect(result.success, isTrue);
      if (result.success) {
        expect(result.data.ripgrep?.command, '/usr/local/bin/rg');
      }
    });

    test('should validate config with custom ripgrep command and args', () {
      final config = {
        'network': {'allowedDomains': [], 'deniedDomains': []},
        'filesystem': {'denyRead': [], 'allowWrite': [], 'denyWrite': []},
        'ripgrep': {
          'command': 'claude',
          'args': ['--ripgrep'],
        },
      };

      final result = SandboxRuntimeConfigSchema.safeParse(config);
      expect(result.success, isTrue);
      if (result.success) {
        expect(result.data.ripgrep?.command, 'claude');
        expect(result.data.ripgrep?.args, ['--ripgrep']);
      }
    });

    test('should accept valid allowMachLookup entries', () {
      final config = {
        'network': {
          'allowedDomains': [],
          'deniedDomains': [],
          'allowMachLookup': [
            '2BUA8C4S2C.com.1password.*',
            'com.apple.CoreSimulator.CoreSimulatorService',
            '*',
          ],
        },
        'filesystem': {'denyRead': [], 'allowWrite': [], 'denyWrite': []},
      };

      final result = SandboxRuntimeConfigSchema.safeParse(config);
      expect(result.success, isTrue);
    });

    for (final entry in ['com.*.foo', 'com.example.**']) {
      test(
        'should reject allowMachLookup entry with non-trailing wildcard: $entry',
        () {
          final config = {
            'network': {
              'allowedDomains': [],
              'deniedDomains': [],
              'allowMachLookup': [entry],
            },
            'filesystem': {'denyRead': [], 'allowWrite': [], 'denyWrite': []},
          };

          final result = SandboxRuntimeConfigSchema.safeParse(config);
          expect(result.success, isFalse);
        },
      );
    }

    test('should use default ripgrep command when not specified', () {
      final config = {
        'network': {'allowedDomains': [], 'deniedDomains': []},
        'filesystem': {'denyRead': [], 'allowWrite': [], 'denyWrite': []},
      };

      final result = SandboxRuntimeConfigSchema.safeParse(config);
      expect(result.success, isTrue);
      if (result.success) {
        expect(result.data.ripgrep, isNull);
      }
    });

    group('deny globs with a trailing separator', () {
      final base = {
        'network': {'allowedDomains': [], 'deniedDomains': []},
        'filesystem': {'denyRead': [], 'allowWrite': [], 'denyWrite': []},
      };

      // spyOn(platform, 'getPlatform') becomes a process.platform override:
      // getPlatform() reads it.

      tearDown(() {
        process.setPlatformForTesting(null);
      });

      // A slashed deny glob compiles to a pattern only a path ending in a
      // separator could satisfy, so it denies nothing on either backend —
      // fail-open, and with no diagnostic beyond a debug line about zero
      // expansions.
      void expectSlashedDenyGlobRejected(String spelling) {
        final result = SandboxRuntimeConfigSchema.safeParse({
          ...base,
          'filesystem': {
            ...base['filesystem']!,
            'denyRead': [spelling],
          },
        });
        expect(result.success, isFalse);
        if (!result.success) {
          expect(result.error.issues[0].message, contains(spelling));
          expect(result.error.issues[0].message, contains('can match no path'));
          expect(result.error.issues[0].path, ['filesystem', 'denyRead', 0]);
        }
      }

      for (final [spelling] in [
        ['/data/*/'],
        ['/data/**/'],
        ['/data/?/'],
      ]) {
        test(
          'rejects denyRead $spelling',
          () => expectSlashedDenyGlobRejected(spelling),
        );
      }

      // `[` and `]` are legal characters in a Windows filename, so
      // containsGlobCharsWin reads a bracket spelling as a literal path and
      // there is no inert pattern to reject.
      test('rejects denyRead /data/[ab]/', () {
        expectSlashedDenyGlobRejected('/data/[ab]/');
      }, skip: (!isWindows) ? false : 'requires !isWindows');

      test('rejects a slashed denyWrite glob, naming the spelling to use', () {
        final result = SandboxRuntimeConfigSchema.safeParse({
          ...base,
          'filesystem': {
            ...base['filesystem']!,
            'denyWrite': ['/data/*/'],
          },
        });
        expect(result.success, isFalse);
        if (!result.success) {
          expect(result.error.issues[0].message, contains('Write "/data/*"'));
          expect(result.error.issues[0].path, ['filesystem', 'denyWrite', 0]);
        }
      });

      // A `mode: 'deny'` credential file is unioned into the read-deny set, so
      // it takes the same glob branches and goes inert the same way.
      test('rejects a slashed glob on a mode "deny" credential file', () {
        final result = SandboxRuntimeConfigSchema.safeParse({
          ...base,
          'credentials': {
            'files': [
              {'path': '~/.aws/*/', 'mode': 'deny'},
            ],
          },
        });
        expect(result.success, isFalse);
        if (!result.success) {
          expect(result.error.issues[0].message, contains('Write "~/.aws/*"'));
          expect(result.error.issues[0].path, [
            'credentials',
            'files',
            0,
            'path',
          ]);
        }
      });

      test(
        'points a deny inside a folder named like a pattern at the spelling read both ways',
        () {
          // Whether the folder exists is for the disk to say, which validation
          // does not ask, so the separator is refused here as in any pattern.
          final result = SandboxRuntimeConfigSchema.safeParse({
            ...base,
            'filesystem': {
              ...base['filesystem']!,
              'denyWrite': ['/work/[WIP] project/keep/'],
            },
          });
          expect(result.success, isFalse);
          if (!result.success) {
            expect(
              result.error.issues[0].message,
              contains(
                'Write "/work/[WIP] project/keep", which is also read as the path of that name',
              ),
            );
          }
        },
        skip: (!isWindows) ? false : 'requires !isWindows',
      );

      test('accepts the slash-free glob spellings it points at', () {
        final result = SandboxRuntimeConfigSchema.safeParse({
          ...base,
          'filesystem': {
            ...base['filesystem']!,
            'denyRead': ['/data/*', '/data/**'],
            'denyWrite': ['/data/*'],
          },
        });
        expect(result.success, isTrue);
      });

      // Non-glob spellings are canonicalised at the sandbox chokepoint, and an
      // allow that matches nothing fails closed — neither is rejected here.
      test('leaves trailing-slash literals and allow globs alone', () {
        final result = SandboxRuntimeConfigSchema.safeParse({
          ...base,
          'filesystem': {
            'denyRead': ['/data/secrets/'],
            'allowRead': ['/data/*/'],
            'allowWrite': ['/work/*/'],
            'denyWrite': ['/data/secrets/'],
          },
        });
        expect(result.success, isTrue);
      });

      // A relative spelling is resolved through path.resolve, which drops the
      // trailing separator, so these globs are live rules.
      test('accepts relative slashed globs, which normalisation strips', () {
        final result = SandboxRuntimeConfigSchema.safeParse({
          ...base,
          'filesystem': {
            ...base['filesystem']!,
            'denyRead': ['build/*/', './*/', '*/'],
          },
        });
        expect(result.success, isTrue);
      });

      // filesystem.disabled drops every filesystem rule, credential file
      // denies included, so an inert deny under it is not a hole.
      test('accepts a slashed deny glob when filesystem.disabled', () {
        final result = SandboxRuntimeConfigSchema.safeParse({
          ...base,
          'filesystem': {
            ...base['filesystem']!,
            'disabled': true,
            'denyRead': ['/data/*/'],
            'denyWrite': ['/data/*/'],
          },
          'credentials': {
            'files': [
              {'path': '~/.aws/*/', 'mode': 'deny'},
            ],
          },
        });
        expect(result.success, isTrue);
      });

      // The Windows CI legs run only the winsrt and mux-proxy suites, so the
      // Windows arm of the check is driven here instead.
      test(
        'Windows: accepts a bracketed literal keeping its directory marker',
        () {
          // `[` and `]` are legal Win32 filename characters, so this is a
          // literal, and its trailing separator is the directory marker for a
          // deny target that does not exist yet.
          process.setPlatformForTesting('win32');
          final result = SandboxRuntimeConfigSchema.safeParse({
            ...base,
            'filesystem': {
              ...base['filesystem']!,
              'denyRead': ['C:/app/[prod]/'],
            },
          });
          expect(result.success, isTrue);
        },
      );

      for (final [spelling] in [
        ['C:\\data\\*\\'],
        ['C:/data/*/'],
      ]) {
        test('Windows: rejects the slashed glob $spelling', () {
          process.setPlatformForTesting('win32');
          final result = SandboxRuntimeConfigSchema.safeParse({
            ...base,
            'filesystem': {
              ...base['filesystem']!,
              'denyRead': [spelling],
            },
          });
          expect(result.success, isFalse);
        });
      }

      test(
        'POSIX: rejects a bracketed glob, where [ and ] are metacharacters',
        () {
          process.setPlatformForTesting('linux');
          final result = SandboxRuntimeConfigSchema.safeParse({
            ...base,
            'filesystem': {
              ...base['filesystem']!,
              'denyRead': ['/data/[ab]/'],
            },
          });
          expect(result.success, isFalse);
        },
      );
    });

    group('path entries marked literal', () {
      // type List = 'denyRead' | 'allowRead' | 'allowWrite' | 'denyWrite'
      const lists = ['denyRead', 'allowRead', 'allowWrite', 'denyWrite'];

      ConfigParseResult<SandboxRuntimeConfig> parse(
        String list,
        Object? entry,
      ) {
        return SandboxRuntimeConfigSchema.safeParse({
          'network': {'allowedDomains': [], 'deniedDomains': []},
          'filesystem': {
            'denyRead': [],
            'allowWrite': [],
            'denyWrite': [],
            list: [entry],
          },
        });
      }

      for (final list in lists) {
        test('$list takes a path marked literal beside a string', () {
          final marked = {'path': '/work/*.env', 'literal': true};
          final result = parse(list, marked);
          expect(result.success, isTrue);
          expect(
            result.success
                ? _filesystemJson(result.data.filesystem, list)
                : false,
            [marked],
          );
          final plain = parse(list, '/work/keep');
          expect(
            plain.success
                ? _filesystemJson(plain.data.filesystem, list)
                : false,
            ['/work/keep'],
          );
        });
      }

      for (final list in lists) {
        test('$list takes ~ and relative spellings marked literal', () {
          for (final path in [
            '~/notes (draft?)',
            './build*',
            '[WIP] project',
          ]) {
            expect(
              parse(list, {'path': path, 'literal': true}).success,
              isTrue,
            );
          }
        });
      }

      for (final [what, entry] in [
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
      ]) {
        test('refuses an entry with $what', () {
          for (final list in lists) {
            final result = parse(list, entry);
            expect(result.success, isFalse);
            if (!result.success) {
              expect(result.error.issues[0].path.sublist(0, 3), [
                'filesystem',
                list,
                0,
              ]);
            }
          }
        });
      }

      test('says what an entry may be when it is neither', () {
        final result = parse('denyRead', {'path': '/work/x', 'literal': false});
        expect(result.success, isFalse);
        if (!result.success) {
          expect(
            result.error.issues[0].message,
            'Expected a path, or { "path": "<path>", "literal": true }',
          );
        }
      });

      test('refuses a key it does not know, rather than ignore it', () {
        final result = parse('denyRead', {
          'path': '/work/x',
          'literal': true,
          'recursive': true,
        });
        expect(result.success, isFalse);
        if (!result.success) {
          expect(result.error.issues[0].code, 'unrecognized_keys');
        }
      });

      test('refuses an empty path, marked or not, with the same message', () {
        for (final entry in [
          '',
          {'path': '', 'literal': true},
        ]) {
          final result = parse('allowWrite', entry);
          expect(result.success, isFalse);
          if (!result.success) {
            expect(result.error.issues[0].message, 'Path cannot be empty');
          }
        }
      });

      test(
        'takes a separator at the end of a marked deny, which is no glob',
        () {
          // The same spelling as a string is a pattern that can match no path,
          // and is refused; marked, it is a name and the separator ends it.
          for (final list in ['denyRead', 'denyWrite']) {
            expect(parse(list, '/data/*/').success, isFalse);
            expect(
              parse(list, {'path': '/data/*/', 'literal': true}).success,
              isTrue,
            );
          }
        },
      );

      test('does not take the mark on a credential file', () {
        final result = SandboxRuntimeConfigSchema.safeParse({
          'network': {'allowedDomains': [], 'deniedDomains': []},
          'filesystem': {'denyRead': [], 'allowWrite': [], 'denyWrite': []},
          'credentials': {
            'files': [
              {
                'path': {'path': '~/.netrc', 'literal': true},
                'mode': 'deny',
              },
            ],
          },
        });
        expect(result.success, isFalse);
      });
    });

    group('bwrapPath / socatPath', () {
      final base = {
        'network': {'allowedDomains': [], 'deniedDomains': []},
        'filesystem': {'denyRead': [], 'allowWrite': [], 'denyWrite': []},
      };

      test('accepts absolute paths', () {
        final result = SandboxRuntimeConfigSchema.safeParse({
          ...base,
          'bwrapPath': '/usr/local/bin/bwrap',
          'socatPath': '/opt/tools/socat',
        });
        expect(result.success, isTrue);
      });

      test('rejects relative bwrapPath', () {
        final result = SandboxRuntimeConfigSchema.safeParse({
          ...base,
          'bwrapPath': 'bwrap',
        });
        expect(result.success, isFalse);
        if (!result.success) {
          expect(result.error.issues[0].message, contains('must be absolute'));
        }
      });

      test('rejects relative socatPath', () {
        final result = SandboxRuntimeConfigSchema.safeParse({
          ...base,
          'socatPath': './bin/socat',
        });
        expect(result.success, isFalse);
      });

      test('rejects empty bwrapPath', () {
        final result = SandboxRuntimeConfigSchema.safeParse({
          ...base,
          'bwrapPath': '',
        });
        expect(result.success, isFalse);
      });
    });

    group('credentials', () {
      final base = {
        'network': {'allowedDomains': [], 'deniedDomains': []},
        'filesystem': {'denyRead': [], 'allowWrite': [], 'denyWrite': []},
      };

      test('is optional — config without it validates and stays undefined', () {
        final result = SandboxRuntimeConfigSchema.safeParse(base);
        expect(result.success, isTrue);
        if (result.success) {
          expect(result.data.credentials, isNull);
        }
      });

      test('accepts file and env var entries with deny mode', () {
        final result = SandboxRuntimeConfigSchema.safeParse({
          ...base,
          'credentials': {
            'files': [
              {'path': '~/.netrc', 'mode': 'deny'},
              {'path': '~/.aws', 'mode': 'deny'},
            ],
            'envVars': [
              {'name': 'AWS_SECRET_ACCESS_KEY', 'mode': 'deny'},
              {'name': 'GH_TOKEN', 'mode': 'deny'},
            ],
          },
        });
        expect(result.success, isTrue);
        if (result.success) {
          expect(result.data.credentials?.files, hasLength(2));
          expect(result.data.credentials?.envVars, hasLength(2));
        }
      });

      test('rejects mode "allow" — no longer a valid mode', () {
        final result = SandboxRuntimeConfigSchema.safeParse({
          ...base,
          'credentials': {
            'files': [
              {'path': '~/.aws', 'mode': 'allow'},
            ],
          },
        });
        expect(result.success, isFalse);
      });

      test('accepts an empty credentials object', () {
        final result = SandboxRuntimeConfigSchema.safeParse({
          ...base,
          'credentials': {},
        });
        expect(result.success, isTrue);
      });

      test('accepts mode "mask" for files when tlsTerminate is enabled', () {
        final result = SandboxRuntimeConfigSchema.safeParse({
          ...base,
          'network': {
            'allowedDomains': ['api.github.com'],
            'deniedDomains': [],
            'tlsTerminate': {},
          },
          'credentials': {
            'files': [
              {'path': '~/.config/gh/token', 'mode': 'mask'},
            ],
          },
        });
        expect(result.success, isTrue);
      });

      test('rejects mode "mask" for files without tlsTerminate', () {
        // Same TLS-or-allowPlaintextInject gate as for env vars — the
        // substitution path is identical.
        final result = SandboxRuntimeConfigSchema.safeParse({
          ...base,
          'network': {
            'allowedDomains': ['api.github.com'],
            'deniedDomains': [],
          },
          'credentials': {
            'files': [
              {'path': '~/.config/gh/token', 'mode': 'mask'},
            ],
          },
        });
        expect(result.success, isFalse);
        if (!result.success) {
          final messages = result.error.issues.map((i) => i.message).join('\n');
          expect(messages, contains('tlsTerminate'));
        }
      });

      test('injectHosts covered by a port-scoped allowedDomains entry', () {
        // ":port" narrows the allow to one port but the host is still
        // reachable, so it counts as coverage; injectHosts itself stays
        // host-only.
        final ok = SandboxRuntimeConfigSchema.safeParse({
          ...base,
          'network': {
            'allowedDomains': ['api.github.com:443'],
            'deniedDomains': [],
            'tlsTerminate': {},
          },
          'credentials': {
            'files': [
              {
                'path': '~/.config/gh/token',
                'mode': 'mask',
                'injectHosts': ['api.github.com'],
              },
            ],
          },
        });
        expect(ok.success, isTrue);

        final bad = SandboxRuntimeConfigSchema.safeParse({
          ...base,
          'network': {
            'allowedDomains': ['api.github.com:443'],
            'deniedDomains': [],
            'tlsTerminate': {},
          },
          'credentials': {
            'files': [
              {
                'path': '~/.config/gh/token',
                'mode': 'mask',
                'injectHosts': ['api.github.com:443'],
              },
            ],
          },
        });
        expect(bad.success, isFalse);
      });

      test('accepts a masked file with per-entry injectHosts', () {
        final result = SandboxRuntimeConfigSchema.safeParse({
          ...base,
          'network': {
            'allowedDomains': ['api.github.com'],
            'deniedDomains': [],
            'tlsTerminate': {},
          },
          'credentials': {
            'files': [
              {
                'path': '~/.config/gh/token',
                'mode': 'mask',
                'injectHosts': ['api.github.com'],
              },
            ],
          },
        });
        expect(result.success, isTrue);
      });

      test(
        'rejects a masked file whose per-entry injectHosts is explicitly empty',
        () {
          final result = SandboxRuntimeConfigSchema.safeParse({
            ...base,
            'network': {
              'allowedDomains': ['api.github.com'],
              'deniedDomains': [],
              'tlsTerminate': {},
            },
            'credentials': {
              'files': [
                {
                  'path': '~/.config/gh/token',
                  'mode': 'mask',
                  'injectHosts': [],
                },
              ],
            },
          });
          expect(result.success, isFalse);
          if (!result.success) {
            final messages = result.error.issues
                .map((i) => i.message)
                .join('\n');
            expect(messages, contains('masked but never injected'));
          }
        },
      );

      test(
        'rejects per-entry file injectHosts not reachable via allowedDomains',
        () {
          final result = SandboxRuntimeConfigSchema.safeParse({
            ...base,
            'network': {
              'allowedDomains': ['api.github.com'],
              'deniedDomains': [],
              'tlsTerminate': {},
            },
            'credentials': {
              'files': [
                {
                  'path': '~/.npmrc-token',
                  'mode': 'mask',
                  'injectHosts': ['registry.npmjs.org'],
                },
              ],
            },
          });
          expect(result.success, isFalse);
          if (!result.success) {
            final issue = result.error.issues
                .where(
                  (i) => i.path
                      .join('.')
                      .startsWith('credentials.files.0.injectHosts'),
                )
                .firstOrNull;
            expect(issue?.message, contains('registry.npmjs.org'));
            expect(issue?.message, contains('network.allowedDomains'));
          }
        },
      );

      test('accepts a masked file with an extract regex', () {
        final result = SandboxRuntimeConfigSchema.safeParse({
          ...base,
          'network': {
            'allowedDomains': ['api.github.com'],
            'deniedDomains': [],
            'tlsTerminate': {},
          },
          'credentials': {
            'files': [
              {
                'path': '~/.config/gh/hosts.yml',
                'mode': 'mask',
                'extract': 'oauth_token:\\s*(\\S+)',
              },
            ],
          },
        });
        expect(result.success, isTrue);
      });

      test('rejects an extract value that is not a valid regex', () {
        final result = SandboxRuntimeConfigSchema.safeParse({
          ...base,
          'network': {
            'allowedDomains': ['api.github.com'],
            'deniedDomains': [],
            'tlsTerminate': {},
          },
          'credentials': {
            'files': [
              {
                'path': '~/.config/gh/hosts.yml',
                'mode': 'mask',
                'extract': '(',
              },
            ],
          },
        });
        expect(result.success, isFalse);
        if (!result.success) {
          final issue = result.error.issues
              .where((i) => i.path.join('.') == 'credentials.files.0.extract')
              .firstOrNull;
          expect(issue?.message, contains('not a valid regular expression'));
        }
      });

      test('rejects an extract regex with no capturing group', () {
        // Group 1 is the contract for "what to mask"; a pattern without
        // one would mask nothing and is almost certainly a mistake.
        final result = SandboxRuntimeConfigSchema.safeParse({
          ...base,
          'network': {
            'allowedDomains': ['api.github.com'],
            'deniedDomains': [],
            'tlsTerminate': {},
          },
          'credentials': {
            'files': [
              {
                'path': '~/.config/gh/hosts.yml',
                'mode': 'mask',
                'extract': 'oauth_token:\\s*\\S+',
              },
            ],
          },
        });
        expect(result.success, isFalse);
        if (!result.success) {
          final issue = result.error.issues
              .where((i) => i.path.join('.') == 'credentials.files.0.extract')
              .firstOrNull;
          expect(issue?.message, contains('capturing group'));
        }
      });

      test(
        'a non-capturing group does not satisfy the extract group requirement',
        () {
          final result = SandboxRuntimeConfigSchema.safeParse({
            ...base,
            'network': {
              'allowedDomains': ['api.github.com'],
              'deniedDomains': [],
              'tlsTerminate': {},
            },
            'credentials': {
              'files': [
                {
                  'path': '~/.netrc',
                  'mode': 'mask',
                  'extract': 'password (?:\\S+)',
                },
              ],
            },
          });
          expect(result.success, isFalse);
        },
      );

      test('extract on a deny-mode entry is accepted (ignored)', () {
        // Mirrors the injectHosts-on-deny precedent: harmless, so no error.
        final result = SandboxRuntimeConfigSchema.safeParse({
          ...base,
          'network': {
            'allowedDomains': ['api.github.com'],
            'deniedDomains': [],
          },
          'credentials': {
            'files': [
              {
                'path': '~/.netrc',
                'mode': 'deny',
                'extract': 'password (\\S+)',
              },
            ],
          },
        });
        expect(result.success, isTrue);
      });

      test('accepts a masked file with decode "jwt" and no extract', () {
        // extract is optional with decode — the built-in JWT pattern is used.
        final result = SandboxRuntimeConfigSchema.safeParse({
          ...base,
          'network': {
            'allowedDomains': ['api.github.com'],
            'deniedDomains': [],
            'tlsTerminate': {},
          },
          'credentials': {
            'files': [
              {
                'path': '~/.config/app/credentials',
                'mode': 'mask',
                'decode': 'jwt',
              },
            ],
          },
        });
        expect(result.success, isTrue);
      });

      test('accepts decode combined with an explicit extract pattern', () {
        final result = SandboxRuntimeConfigSchema.safeParse({
          ...base,
          'network': {
            'allowedDomains': ['api.github.com'],
            'deniedDomains': [],
            'tlsTerminate': {},
          },
          'credentials': {
            'files': [
              {
                'path': '~/.config/app/credentials',
                'mode': 'mask',
                'extract': 'id_token:\\s*(\\S+)',
                'decode': 'jwt',
              },
            ],
          },
        });
        expect(result.success, isTrue);
      });

      test('rejects an unknown decode encoding', () {
        final result = SandboxRuntimeConfigSchema.safeParse({
          ...base,
          'network': {
            'allowedDomains': ['api.github.com'],
            'deniedDomains': [],
          },
          'credentials': {
            'files': [
              {
                'path': '~/.config/app/credentials',
                'mode': 'mask',
                'decode': 'base64',
              },
            ],
          },
        });
        expect(result.success, isFalse);
        if (!result.success) {
          final issue = result.error.issues
              .where((i) => i.path.join('.') == 'credentials.files.0.decode')
              .firstOrNull;
          expect(issue, isNotNull);
        }
      });

      test('decode on a deny-mode entry is accepted (ignored)', () {
        // Mirrors the extract/injectHosts-on-deny precedent.
        final result = SandboxRuntimeConfigSchema.safeParse({
          ...base,
          'network': {
            'allowedDomains': ['api.github.com'],
            'deniedDomains': [],
          },
          'credentials': {
            'files': [
              {
                'path': '~/.config/app/credentials',
                'mode': 'deny',
                'decode': 'jwt',
              },
            ],
          },
        });
        expect(result.success, isTrue);
      });

      test('accepts maskClaims alongside decode "jwt"', () {
        final result = SandboxRuntimeConfigSchema.safeParse({
          ...base,
          'network': {
            'allowedDomains': ['api.github.com'],
            'deniedDomains': [],
            'tlsTerminate': {},
          },
          'credentials': {
            'files': [
              {
                'path': '~/.config/app/credentials',
                'mode': 'mask',
                'decode': 'jwt',
                'maskClaims': ['api_key', 'secret'],
              },
            ],
          },
        });
        expect(result.success, isTrue);
        if (result.success) {
          expect(result.data.credentials?.files?[0].maskClaims, [
            'api_key',
            'secret',
          ]);
        }
      });

      test('rejects maskClaims without decode', () {
        // maskClaims names fields inside a decoded payload; without decode
        // there is nothing to look inside.
        final result = SandboxRuntimeConfigSchema.safeParse({
          ...base,
          'network': {
            'allowedDomains': ['api.github.com'],
            'deniedDomains': [],
            'tlsTerminate': {},
          },
          'credentials': {
            'files': [
              {
                'path': '~/.config/app/credentials',
                'mode': 'mask',
                'maskClaims': ['api_key'],
              },
            ],
          },
        });
        expect(result.success, isFalse);
        if (!result.success) {
          final issue = result.error.issues
              .where(
                (i) => i.path.join('.') == 'credentials.files.0.maskClaims',
              )
              .firstOrNull;
          expect(issue?.message, contains('requires decode'));
        }
      });

      test('rejects an explicitly empty maskClaims', () {
        // Same posture as an explicitly empty injectHosts.
        final result = SandboxRuntimeConfigSchema.safeParse({
          ...base,
          'network': {
            'allowedDomains': ['api.github.com'],
            'deniedDomains': [],
            'tlsTerminate': {},
          },
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
        });
        expect(result.success, isFalse);
        if (!result.success) {
          final messages = result.error.issues.map((i) => i.message).join('\n');
          expect(messages, contains('explicitly empty'));
        }
      });

      test('rejects an empty string in maskClaims', () {
        final result = SandboxRuntimeConfigSchema.safeParse({
          ...base,
          'network': {
            'allowedDomains': ['api.github.com'],
            'deniedDomains': [],
            'tlsTerminate': {},
          },
          'credentials': {
            'files': [
              {
                'path': '~/.config/app/credentials',
                'mode': 'mask',
                'decode': 'jwt',
                'maskClaims': [''],
              },
            ],
          },
        });
        expect(result.success, isFalse);
      });

      test(
        'maskClaims with decode on a deny-mode entry is accepted (ignored)',
        () {
          // Mirrors the decode-on-deny precedent: mode "deny" ignores masking
          // options; the decode requirement is structural, not mode-dependent.
          final result = SandboxRuntimeConfigSchema.safeParse({
            ...base,
            'network': {
              'allowedDomains': ['api.github.com'],
              'deniedDomains': [],
            },
            'credentials': {
              'files': [
                {
                  'path': '~/.config/app/credentials',
                  'mode': 'deny',
                  'decode': 'jwt',
                  'maskClaims': ['api_key'],
                },
              ],
            },
          });
          expect(result.success, isTrue);
        },
      );

      for (final onExtractNoMatch in ['warn', 'deny', 'error']) {
        test('accepts onExtractNoMatch: "$onExtractNoMatch"', () {
          final result = SandboxRuntimeConfigSchema.safeParse({
            ...base,
            'network': {
              'allowedDomains': ['api.github.com'],
              'deniedDomains': [],
              'tlsTerminate': {},
            },
            'credentials': {
              'files': [
                {
                  'path': '~/.config/gh/hosts.yml',
                  'mode': 'mask',
                  'extract': 'oauth_token:\\s*(\\S+)',
                  'onExtractNoMatch': onExtractNoMatch,
                },
              ],
            },
          });
          expect(result.success, isTrue);
        });
      }

      test('rejects an invalid onExtractNoMatch value', () {
        final result = SandboxRuntimeConfigSchema.safeParse({
          ...base,
          'network': {
            'allowedDomains': ['api.github.com'],
            'deniedDomains': [],
            'tlsTerminate': {},
          },
          'credentials': {
            'files': [
              {
                'path': '~/.config/gh/hosts.yml',
                'mode': 'mask',
                'extract': 'oauth_token:\\s*(\\S+)',
                'onExtractNoMatch': 'ignore',
              },
            ],
          },
        });
        expect(result.success, isFalse);
        if (!result.success) {
          final issue = result.error.issues
              .where(
                (i) =>
                    i.path.join('.') == 'credentials.files.0.onExtractNoMatch',
              )
              .firstOrNull;
          expect(issue, isNotNull);
        }
      });

      test('accepts maskDuplicates alongside extract', () {
        final result = SandboxRuntimeConfigSchema.safeParse({
          ...base,
          'network': {
            'allowedDomains': ['api.github.com'],
            'deniedDomains': [],
            'tlsTerminate': {},
          },
          'credentials': {
            'files': [
              {
                'path': '~/.config/gh/hosts.yml',
                'mode': 'mask',
                'extract': 'oauth_token:\\s*(\\S+)',
                'maskDuplicates': true,
              },
            ],
          },
        });
        expect(result.success, isTrue);
        if (result.success) {
          expect(result.data.credentials?.files?[0].maskDuplicates, isTrue);
        }
      });

      test('maskDuplicates without extract is accepted (ignored)', () {
        // Mirrors the injectHosts-on-deny precedent: harmless, so no error.
        // Whole-file masking already replaces all content, so the option
        // has nothing to add.
        final result = SandboxRuntimeConfigSchema.safeParse({
          ...base,
          'network': {
            'allowedDomains': ['api.github.com'],
            'deniedDomains': [],
            'tlsTerminate': {},
          },
          'credentials': {
            'files': [
              {
                'path': '~/.config/gh/token',
                'mode': 'mask',
                'maskDuplicates': true,
              },
            ],
          },
        });
        expect(result.success, isTrue);
      });

      test('maskDuplicates on a deny-mode entry is accepted (ignored)', () {
        final result = SandboxRuntimeConfigSchema.safeParse({
          ...base,
          'network': {
            'allowedDomains': ['api.github.com'],
            'deniedDomains': [],
          },
          'credentials': {
            'files': [
              {'path': '~/.netrc', 'mode': 'deny', 'maskDuplicates': true},
            ],
          },
        });
        expect(result.success, isTrue);
      });

      test('rejects a non-boolean maskDuplicates', () {
        final result = SandboxRuntimeConfigSchema.safeParse({
          ...base,
          'network': {
            'allowedDomains': ['api.github.com'],
            'deniedDomains': [],
            'tlsTerminate': {},
          },
          'credentials': {
            'files': [
              {
                'path': '~/.netrc',
                'mode': 'mask',
                'extract': 'password (\\S+)',
                'maskDuplicates': 'yes',
              },
            ],
          },
        });
        expect(result.success, isFalse);
        if (!result.success) {
          final issue = result.error.issues
              .where(
                (i) => i.path.join('.') == 'credentials.files.0.maskDuplicates',
              )
              .firstOrNull;
          expect(issue, isNotNull);
        }
      });

      test('accepts a masked env var with an extract regex', () {
        final result = SandboxRuntimeConfigSchema.safeParse({
          ...base,
          'network': {
            'allowedDomains': ['db.example.com'],
            'deniedDomains': [],
            'tlsTerminate': {},
          },
          'credentials': {
            'envVars': [
              {
                'name': 'DATABASE_URL',
                'mode': 'mask',
                'extract': '://[^:]+:([^@]+)@',
              },
            ],
          },
        });
        expect(result.success, isTrue);
      });

      test('rejects an env extract value that is not a valid regex', () {
        final result = SandboxRuntimeConfigSchema.safeParse({
          ...base,
          'network': {
            'allowedDomains': ['db.example.com'],
            'deniedDomains': [],
            'tlsTerminate': {},
          },
          'credentials': {
            'envVars': [
              {'name': 'DATABASE_URL', 'mode': 'mask', 'extract': '('},
            ],
          },
        });
        expect(result.success, isFalse);
        if (!result.success) {
          final issue = result.error.issues
              .where((i) => i.path.join('.') == 'credentials.envVars.0.extract')
              .firstOrNull;
          expect(issue?.message, contains('not a valid regular expression'));
        }
      });

      test('rejects an env extract regex with no capturing group', () {
        final result = SandboxRuntimeConfigSchema.safeParse({
          ...base,
          'network': {
            'allowedDomains': ['db.example.com'],
            'deniedDomains': [],
            'tlsTerminate': {},
          },
          'credentials': {
            'envVars': [
              {'name': 'DATABASE_URL', 'mode': 'mask', 'extract': '://\\S+@'},
            ],
          },
        });
        expect(result.success, isFalse);
        if (!result.success) {
          final issue = result.error.issues
              .where((i) => i.path.join('.') == 'credentials.envVars.0.extract')
              .firstOrNull;
          expect(issue?.message, contains('capturing group'));
        }
      });

      test('extract on a deny-mode env var is accepted (ignored)', () {
        // Mirrors the files precedent (and injectHosts-on-deny): harmless,
        // so no error.
        final result = SandboxRuntimeConfigSchema.safeParse({
          ...base,
          'network': {
            'allowedDomains': ['db.example.com'],
            'deniedDomains': [],
          },
          'credentials': {
            'envVars': [
              {'name': 'DATABASE_URL', 'mode': 'deny', 'extract': ':([^@]+)@'},
            ],
          },
        });
        expect(result.success, isTrue);
      });

      for (final onExtractNoMatch in ['warn', 'deny', 'error']) {
        test('accepts onExtractNoMatch: "$onExtractNoMatch" on an env var', () {
          final result = SandboxRuntimeConfigSchema.safeParse({
            ...base,
            'network': {
              'allowedDomains': ['db.example.com'],
              'deniedDomains': [],
              'tlsTerminate': {},
            },
            'credentials': {
              'envVars': [
                {
                  'name': 'DATABASE_URL',
                  'mode': 'mask',
                  'extract': '://[^:]+:([^@]+)@',
                  'onExtractNoMatch': onExtractNoMatch,
                },
              ],
            },
          });
          expect(result.success, isTrue);
        });
      }

      test('rejects an invalid onExtractNoMatch value on an env var', () {
        final result = SandboxRuntimeConfigSchema.safeParse({
          ...base,
          'network': {
            'allowedDomains': ['db.example.com'],
            'deniedDomains': [],
            'tlsTerminate': {},
          },
          'credentials': {
            'envVars': [
              {
                'name': 'DATABASE_URL',
                'mode': 'mask',
                'extract': '://[^:]+:([^@]+)@',
                'onExtractNoMatch': 'ignore',
              },
            ],
          },
        });
        expect(result.success, isFalse);
        if (!result.success) {
          final issue = result.error.issues
              .where(
                (i) =>
                    i.path.join('.') ==
                    'credentials.envVars.0.onExtractNoMatch',
              )
              .firstOrNull;
          expect(issue, isNotNull);
        }
      });

      test('rejects mode "mask" on a directory path (trailing slash)', () {
        final result = SandboxRuntimeConfigSchema.safeParse({
          ...base,
          'network': {
            'allowedDomains': ['api.github.com'],
            'deniedDomains': [],
            'tlsTerminate': {},
          },
          'credentials': {
            'files': [
              {'path': '~/.aws/', 'mode': 'mask'},
            ],
          },
        });
        expect(result.success, isFalse);
        if (!result.success) {
          final issue = result.error.issues
              .where((i) => i.path.join('.') == 'credentials.files.0.path')
              .firstOrNull;
          expect(issue?.message, contains('single file'));
          expect(issue?.message, contains('directory'));
        }
      });

      test('accepts mode "mask" for env vars when tlsTerminate is enabled', () {
        final result = SandboxRuntimeConfigSchema.safeParse({
          ...base,
          'network': {
            'allowedDomains': ['api.github.com'],
            'deniedDomains': [],
            'tlsTerminate': {},
          },
          'credentials': {
            'envVars': [
              {'name': 'GH_TOKEN', 'mode': 'mask'},
            ],
          },
        });
        expect(result.success, isTrue);
      });

      test('rejects mode "mask" for env vars without tlsTerminate', () {
        final result = SandboxRuntimeConfigSchema.safeParse({
          ...base,
          'network': {
            'allowedDomains': ['api.github.com'],
            'deniedDomains': [],
          },
          'credentials': {
            'envVars': [
              {'name': 'GH_TOKEN', 'mode': 'mask'},
            ],
          },
        });
        expect(result.success, isFalse);
        if (!result.success) {
          final messages = result.error.issues.map((i) => i.message).join('\n');
          expect(messages, contains('tlsTerminate'));
          expect(messages, contains('allowPlaintextInject'));
        }
      });

      test('allowPlaintextInject permits mask without tlsTerminate', () {
        final result = SandboxRuntimeConfigSchema.safeParse({
          ...base,
          'network': {
            'allowedDomains': ['api.github.com'],
            'deniedDomains': [],
          },
          'credentials': {
            'envVars': [
              {'name': 'GH_TOKEN', 'mode': 'mask'},
            ],
            'allowPlaintextInject': true,
          },
        });
        expect(result.success, isTrue);
      });

      test(
        'accepts a masked env var with no injectHosts (defaults to allowedDomains)',
        () {
          // No per-entry injectHosts — the credential defaults to
          // network.allowedDomains (injection at every reachable host).
          // injectHosts is an optional narrowing.
          final result = SandboxRuntimeConfigSchema.safeParse({
            ...base,
            'network': {
              'allowedDomains': ['api.github.com'],
              'deniedDomains': [],
              'tlsTerminate': {},
            },
            'credentials': {
              'envVars': [
                {'name': 'GH_TOKEN', 'mode': 'mask'},
              ],
            },
          });
          expect(result.success, isTrue);
        },
      );

      test(
        'rejects a masked env var whose per-entry injectHosts is explicitly empty',
        () {
          final result = SandboxRuntimeConfigSchema.safeParse({
            ...base,
            'network': {
              'allowedDomains': ['api.github.com'],
              'deniedDomains': [],
              'tlsTerminate': {},
            },
            'credentials': {
              'envVars': [
                {'name': 'GH_TOKEN', 'mode': 'mask', 'injectHosts': []},
              ],
            },
          });
          // An explicit empty list would mean "mask but never inject", which
          // is self-contradictory.
          expect(result.success, isFalse);
          if (!result.success) {
            final messages = result.error.issues
                .map((i) => i.message)
                .join('\n');
            expect(messages, contains('explicitly empty'));
            expect(messages, contains('masked but never injected'));
          }
        },
      );

      test('rejects block-level credentials.injectHosts (removed key)', () {
        final result = SandboxRuntimeConfigSchema.safeParse({
          ...base,
          'network': {
            'allowedDomains': ['api.github.com'],
            'deniedDomains': [],
            'tlsTerminate': {},
          },
          'credentials': {
            'envVars': [
              {'name': 'GH_TOKEN', 'mode': 'mask'},
            ],
            'injectHosts': ['api.github.com'],
          },
        });
        // The block-level default no longer exists; the schema is strict so
        // a stale config fails rather than silently widening the credential
        // to every allowedDomain.
        expect(result.success, isFalse);
        if (!result.success) {
          final issue = result.error.issues
              .where((i) => i.path.join('.') == 'credentials')
              .firstOrNull;
          expect(issue?.message, contains('injectHosts'));
        }
      });

      test('accepts a masked env var with per-entry injectHosts', () {
        final result = SandboxRuntimeConfigSchema.safeParse({
          ...base,
          'network': {
            'allowedDomains': ['registry.npmjs.org'],
            'deniedDomains': [],
            'tlsTerminate': {},
          },
          'credentials': {
            'envVars': [
              {
                'name': 'NPM_TOKEN',
                'mode': 'mask',
                'injectHosts': ['registry.npmjs.org'],
              },
            ],
          },
        });
        expect(result.success, isTrue);
      });

      test(
        'rejects per-entry injectHosts not reachable via allowedDomains',
        () {
          final result = SandboxRuntimeConfigSchema.safeParse({
            ...base,
            'network': {
              'allowedDomains': ['api.github.com'],
              'deniedDomains': [],
              'tlsTerminate': {},
            },
            'credentials': {
              'envVars': [
                {
                  'name': 'NPM_TOKEN',
                  'mode': 'mask',
                  'injectHosts': ['registry.npmjs.org'],
                },
              ],
            },
          });
          expect(result.success, isFalse);
          if (!result.success) {
            final issue = result.error.issues
                .where(
                  (i) => i.path
                      .join('.')
                      .startsWith('credentials.envVars.0.injectHosts'),
                )
                .firstOrNull;
            expect(issue?.message, contains('registry.npmjs.org'));
            expect(issue?.message, contains('network.allowedDomains'));
          }
        },
      );

      test('rejects overly-broad wildcards in per-entry injectHosts', () {
        final result = SandboxRuntimeConfigSchema.safeParse({
          ...base,
          'network': {...base['network']!, 'tlsTerminate': {}},
          'credentials': {
            'envVars': [
              {
                'name': 'GH_TOKEN',
                'mode': 'mask',
                'injectHosts': ['*.com'],
              },
            ],
          },
        });
        expect(result.success, isFalse);
      });

      test('injectHosts on a deny-mode entry is accepted (ignored)', () {
        final result = SandboxRuntimeConfigSchema.safeParse({
          ...base,
          'network': {
            'allowedDomains': ['api.github.com'],
            'deniedDomains': [],
          },
          'credentials': {
            'envVars': [
              {
                'name': 'GH_TOKEN',
                'mode': 'deny',
                'injectHosts': ['api.github.com'],
              },
            ],
          },
        });
        expect(result.success, isTrue);
      });

      test('accepts a masked env var with decode "jwt"', () {
        final result = SandboxRuntimeConfigSchema.safeParse({
          ...base,
          'network': {
            'allowedDomains': ['api.github.com'],
            'deniedDomains': [],
            'tlsTerminate': {},
          },
          'credentials': {
            'envVars': [
              {'name': 'CI_JOB_JWT', 'mode': 'mask', 'decode': 'jwt'},
            ],
          },
        });
        expect(result.success, isTrue);
      });

      test('rejects an unknown decode encoding on an env var entry', () {
        final result = SandboxRuntimeConfigSchema.safeParse({
          ...base,
          'network': {
            'allowedDomains': ['api.github.com'],
            'deniedDomains': [],
            'tlsTerminate': {},
          },
          'credentials': {
            'envVars': [
              {'name': 'CI_JOB_JWT', 'mode': 'mask', 'decode': 'base64'},
            ],
          },
        });
        expect(result.success, isFalse);
        if (!result.success) {
          final issue = result.error.issues
              .where((i) => i.path.join('.') == 'credentials.envVars.0.decode')
              .firstOrNull;
          expect(issue, isNotNull);
        }
      });

      test('decode on a deny-mode env var entry is accepted (ignored)', () {
        // Mirrors the extract/injectHosts-on-deny precedent: harmless, so
        // no error.
        final result = SandboxRuntimeConfigSchema.safeParse({
          ...base,
          'network': {
            'allowedDomains': ['api.github.com'],
            'deniedDomains': [],
          },
          'credentials': {
            'envVars': [
              {'name': 'CI_JOB_JWT', 'mode': 'deny', 'decode': 'jwt'},
            ],
          },
        });
        expect(result.success, isTrue);
      });

      test('accepts maskClaims alongside decode "jwt" on an env var', () {
        final result = SandboxRuntimeConfigSchema.safeParse({
          ...base,
          'network': {
            'allowedDomains': ['api.github.com'],
            'deniedDomains': [],
            'tlsTerminate': {},
          },
          'credentials': {
            'envVars': [
              {
                'name': 'CI_JOB_JWT',
                'mode': 'mask',
                'decode': 'jwt',
                'maskClaims': ['api_key', 'secret'],
              },
            ],
          },
        });
        expect(result.success, isTrue);
        if (result.success) {
          expect(result.data.credentials?.envVars?[0].maskClaims, [
            'api_key',
            'secret',
          ]);
        }
      });

      test('rejects maskClaims without decode on an env var', () {
        // maskClaims names fields inside a decoded payload; without decode
        // there is nothing to look inside.
        final result = SandboxRuntimeConfigSchema.safeParse({
          ...base,
          'network': {
            'allowedDomains': ['api.github.com'],
            'deniedDomains': [],
            'tlsTerminate': {},
          },
          'credentials': {
            'envVars': [
              {
                'name': 'CI_JOB_JWT',
                'mode': 'mask',
                'maskClaims': ['api_key'],
              },
            ],
          },
        });
        expect(result.success, isFalse);
        if (!result.success) {
          final issue = result.error.issues
              .where(
                (i) => i.path.join('.') == 'credentials.envVars.0.maskClaims',
              )
              .firstOrNull;
          expect(issue?.message, contains('requires decode'));
        }
      });

      test('rejects an explicitly empty maskClaims on an env var', () {
        // Same posture as an explicitly empty injectHosts.
        final result = SandboxRuntimeConfigSchema.safeParse({
          ...base,
          'network': {
            'allowedDomains': ['api.github.com'],
            'deniedDomains': [],
            'tlsTerminate': {},
          },
          'credentials': {
            'envVars': [
              {
                'name': 'CI_JOB_JWT',
                'mode': 'mask',
                'decode': 'jwt',
                'maskClaims': [],
              },
            ],
          },
        });
        expect(result.success, isFalse);
        if (!result.success) {
          final messages = result.error.issues.map((i) => i.message).join('\n');
          expect(messages, contains('explicitly empty'));
        }
      });

      test('rejects an empty string in maskClaims on an env var', () {
        final result = SandboxRuntimeConfigSchema.safeParse({
          ...base,
          'network': {
            'allowedDomains': ['api.github.com'],
            'deniedDomains': [],
            'tlsTerminate': {},
          },
          'credentials': {
            'envVars': [
              {
                'name': 'CI_JOB_JWT',
                'mode': 'mask',
                'decode': 'jwt',
                'maskClaims': [''],
              },
            ],
          },
        });
        expect(result.success, isFalse);
      });

      test(
        'maskClaims with decode on a deny-mode env var entry is accepted (ignored)',
        () {
          // Mirrors the decode-on-deny precedent: mode "deny" ignores masking
          // options; the decode requirement is structural, not mode-dependent.
          final result = SandboxRuntimeConfigSchema.safeParse({
            ...base,
            'network': {
              'allowedDomains': ['api.github.com'],
              'deniedDomains': [],
            },
            'credentials': {
              'envVars': [
                {
                  'name': 'CI_JOB_JWT',
                  'mode': 'deny',
                  'decode': 'jwt',
                  'maskClaims': ['api_key'],
                },
              ],
            },
          });
          expect(result.success, isTrue);
        },
      );

      test(
        'accepts per-entry injectHosts that are a subset of allowedDomains',
        () {
          final result = SandboxRuntimeConfigSchema.safeParse({
            ...base,
            'network': {
              'allowedDomains': [
                'api.github.com',
                'github.com',
                '*.amazonaws.com',
              ],
              'deniedDomains': [],
              'tlsTerminate': {},
            },
            'credentials': {
              'envVars': [
                {
                  'name': 'GH_TOKEN',
                  'mode': 'mask',
                  'injectHosts': ['api.github.com', '*.amazonaws.com'],
                },
              ],
            },
          });
          expect(result.success, isTrue);
        },
      );

      test(
        'accepts an exact injectHost covered by a wildcard allowedDomain',
        () {
          // The injectHosts ⊆ allowedDomains check is semantic coverage, not
          // literal string membership — api.github.com is reachable via
          // *.github.com, so this must validate.
          final result = SandboxRuntimeConfigSchema.safeParse({
            ...base,
            'network': {
              'allowedDomains': ['*.github.com'],
              'deniedDomains': [],
              'tlsTerminate': {},
            },
            'credentials': {
              'envVars': [
                {
                  'name': 'GH_TOKEN',
                  'mode': 'mask',
                  'injectHosts': ['api.github.com'],
                },
              ],
            },
          });
          expect(result.success, isTrue);
        },
      );

      test(
        'accepts a wildcard injectHost covered by a broader allowed wildcard',
        () {
          // Every host under *.api.github.com is also under *.github.com.
          final result = SandboxRuntimeConfigSchema.safeParse({
            ...base,
            'network': {
              'allowedDomains': ['*.github.com'],
              'deniedDomains': [],
              'tlsTerminate': {},
            },
            'credentials': {
              'envVars': [
                {
                  'name': 'GH_TOKEN',
                  'mode': 'mask',
                  'injectHosts': ['*.api.github.com'],
                },
              ],
            },
          });
          expect(result.success, isTrue);
        },
      );

      test(
        'rejects a wildcard injectHost not covered by an exact allowedDomain',
        () {
          // *.github.com would inject at gist.github.com, which is not
          // reachable when allowedDomains only contains api.github.com.
          final result = SandboxRuntimeConfigSchema.safeParse({
            ...base,
            'network': {
              'allowedDomains': ['api.github.com'],
              'deniedDomains': [],
              'tlsTerminate': {},
            },
            'credentials': {
              'envVars': [
                {
                  'name': 'GH_TOKEN',
                  'mode': 'mask',
                  'injectHosts': ['*.github.com'],
                },
              ],
            },
          });
          expect(result.success, isFalse);
          if (!result.success) {
            final issue = result.error.issues
                .where(
                  (i) => i.path
                      .join('.')
                      .startsWith('credentials.envVars.0.injectHosts'),
                )
                .firstOrNull;
            expect(issue?.message, contains('*.github.com'));
            expect(issue?.message, contains('not reachable'));
          }
        },
      );

      test(
        'rejects an exact injectHost not covered by an unrelated wildcard',
        () {
          final result = SandboxRuntimeConfigSchema.safeParse({
            ...base,
            'network': {
              'allowedDomains': ['*.example.com'],
              'deniedDomains': [],
              'tlsTerminate': {},
            },
            'credentials': {
              'envVars': [
                {
                  'name': 'GH_TOKEN',
                  'mode': 'mask',
                  'injectHosts': ['api.github.com'],
                },
              ],
            },
          });
          expect(result.success, isFalse);
          if (!result.success) {
            final issue = result.error.issues
                .where(
                  (i) => i.path
                      .join('.')
                      .startsWith('credentials.envVars.0.injectHosts'),
                )
                .firstOrNull;
            expect(issue?.message, contains('api.github.com'));
            expect(issue?.message, contains('not reachable'));
          }
        },
      );

      test('rejects unknown modes', () {
        final result = SandboxRuntimeConfigSchema.safeParse({
          ...base,
          'credentials': {
            'files': [
              {'path': '~/.netrc', 'mode': 'block'},
            ],
          },
        });
        expect(result.success, isFalse);
      });

      test('rejects empty file paths', () {
        final result = SandboxRuntimeConfigSchema.safeParse({
          ...base,
          'credentials': {
            'files': [
              {'path': '', 'mode': 'deny'},
            ],
          },
        });
        expect(result.success, isFalse);
      });

      for (final name in [
        '',
        'FOO=BAR',
        'FOO BAR',
        '--bind',
        '-u',
        '1FOO',
        'FOO.BAR',
      ]) {
        test('rejects invalid env var name: ${jsonEncode(name)}', () {
          final result = SandboxRuntimeConfigSchema.safeParse({
            ...base,
            'credentials': {
              'envVars': [
                {'name': name, 'mode': 'deny'},
              ],
            },
          });
          expect(result.success, isFalse);
        });
      }

      for (final name in ['_FOO', 'FOO_BAR2']) {
        test('accepts valid env var name: ${jsonEncode(name)}', () {
          final result = SandboxRuntimeConfigSchema.safeParse({
            ...base,
            'credentials': {
              'envVars': [
                {'name': name, 'mode': 'deny'},
              ],
            },
          });
          expect(result.success, isTrue);
        });
      }
    });

    group('network.tlsTerminate', () {
      final base = {
        'network': {'allowedDomains': [], 'deniedDomains': []},
        'filesystem': {'denyRead': [], 'allowWrite': [], 'denyWrite': []},
      };

      test('is optional — config without it validates', () {
        expect(SandboxRuntimeConfigSchema.safeParse(base).success, isTrue);
      });

      test('accepts caCertPath + caKeyPath', () {
        final result = SandboxRuntimeConfigSchema.safeParse({
          ...base,
          'network': {
            ...base['network']!,
            'tlsTerminate': {
              'caCertPath': '/etc/ca.crt',
              'caKeyPath': '/etc/ca.key',
            },
          },
        });
        expect(result.success, isTrue);
      });

      test('rejects when caKeyPath is missing', () {
        final result = SandboxRuntimeConfigSchema.safeParse({
          ...base,
          'network': {
            ...base['network']!,
            'tlsTerminate': {'caCertPath': '/etc/ca.crt'},
          },
        });
        expect(result.success, isFalse);
      });

      test('rejects empty caCertPath', () {
        final result = SandboxRuntimeConfigSchema.safeParse({
          ...base,
          'network': {
            ...base['network']!,
            'tlsTerminate': {'caCertPath': '', 'caKeyPath': '/etc/ca.key'},
          },
        });
        expect(result.success, isFalse);
      });

      group('excludeDomains', () {
        test('accepts exact and wildcard patterns', () {
          final result = SandboxRuntimeConfigSchema.safeParse({
            ...base,
            'network': {
              'allowedDomains': ['*.mtls.example.com', 'pinned.example.com'],
              'deniedDomains': [],
              'tlsTerminate': {
                'excludeDomains': ['*.mtls.example.com', 'pinned.example.com'],
              },
            },
          });
          expect(result.success, isTrue);
        });

        test('rejects invalid domain patterns', () {
          final result = SandboxRuntimeConfigSchema.safeParse({
            ...base,
            'network': {
              ...base['network']!,
              'tlsTerminate': {
                'excludeDomains': ['https://example.com'],
              },
            },
          });
          expect(result.success, isFalse);
        });

        test('rejects a bare "*" (would silently disable termination)', () {
          final result = SandboxRuntimeConfigSchema.safeParse({
            ...base,
            'network': {
              ...base['network']!,
              'tlsTerminate': {
                'excludeDomains': ['*'],
              },
            },
          });
          expect(result.success, isFalse);
        });

        test(
          'rejects a masked credential whose explicit injectHosts entry is fully covered by excludeDomains',
          () {
            // Injection only happens on the terminated path, so an injectHost
            // that can never be terminated can never receive the credential —
            // the upstream would get the placeholder.
            final result = SandboxRuntimeConfigSchema.safeParse({
              ...base,
              'network': {
                'allowedDomains': ['*.example.com'],
                'deniedDomains': [],
                'tlsTerminate': {
                  'excludeDomains': ['*.internal.example.com'],
                },
              },
              'credentials': {
                'envVars': [
                  {
                    'name': 'TOKEN',
                    'mode': 'mask',
                    'injectHosts': ['api.internal.example.com'],
                  },
                ],
              },
            });
            expect(result.success, isFalse);
            if (!result.success) {
              final issue = result.error.issues
                  .where(
                    (i) => i.path
                        .join('.')
                        .startsWith('credentials.envVars.0.injectHosts'),
                  )
                  .firstOrNull;
              expect(issue?.message, contains('excludeDomains'));
              expect(issue?.message, contains('api.internal.example.com'));
            }
          },
        );

        test(
          'accepts an explicit wildcard injectHosts that merely overlaps excludeDomains',
          () {
            // Only mtls.example.com is opaque-tunnelled; every other
            // *.example.com host still gets the credential. Not a
            // contradiction — must not be rejected.
            final result = SandboxRuntimeConfigSchema.safeParse({
              ...base,
              'network': {
                'allowedDomains': ['*.example.com'],
                'deniedDomains': [],
                'tlsTerminate': {
                  'excludeDomains': ['mtls.example.com'],
                },
              },
              'credentials': {
                'envVars': [
                  {
                    'name': 'TOKEN',
                    'mode': 'mask',
                    'injectHosts': ['*.example.com'],
                  },
                ],
              },
            });
            expect(result.success, isTrue);
          },
        );

        test(
          'rejects a masked credential with default injectHosts when excludeDomains covers every allowed domain',
          () {
            // Effective injectHosts = allowedDomains, all of which are excluded
            // from termination: the credential could never be injected anywhere.
            final result = SandboxRuntimeConfigSchema.safeParse({
              ...base,
              'network': {
                'allowedDomains': ['*.example.com', 'pinned.example.net'],
                'deniedDomains': [],
                'tlsTerminate': {
                  'excludeDomains': ['*.example.com', 'pinned.example.net'],
                },
              },
              'credentials': {
                'envVars': [
                  {'name': 'TOKEN', 'mode': 'mask'},
                ],
              },
            });
            expect(result.success, isFalse);
            if (!result.success) {
              final messages = result.error.issues
                  .map((i) => i.message)
                  .join('\n');
              expect(messages, contains('never be injected'));
            }
          },
        );

        test(
          'a masked credential with default (absent) injectHosts coexists with a partial excludeDomains',
          () {
            // Default injectHosts = allowedDomains. Excluded hosts simply do not
            // get the credential; that is not an error.
            final result = SandboxRuntimeConfigSchema.safeParse({
              ...base,
              'network': {
                'allowedDomains': ['*.example.com'],
                'deniedDomains': [],
                'tlsTerminate': {
                  'excludeDomains': ['mtls.example.com'],
                },
              },
              'credentials': {
                'envVars': [
                  {'name': 'TOKEN', 'mode': 'mask'},
                ],
              },
            });
            expect(result.success, isTrue);
          },
        );

        test(
          'explicit injectHosts disjoint from excludeDomains is accepted',
          () {
            final result = SandboxRuntimeConfigSchema.safeParse({
              ...base,
              'network': {
                'allowedDomains': ['*.example.com'],
                'deniedDomains': [],
                'tlsTerminate': {
                  'excludeDomains': ['mtls.example.com'],
                },
              },
              'credentials': {
                'envVars': [
                  {
                    'name': 'TOKEN',
                    'mode': 'mask',
                    'injectHosts': ['api.example.com'],
                  },
                ],
              },
            });
            expect(result.success, isTrue);
          },
        );
      });

      group('extraCaCertPaths', () {
        test('accepts a list of paths and round-trips it', () {
          final result = SandboxRuntimeConfigSchema.safeParse({
            ...base,
            'network': {
              ...base['network']!,
              'tlsTerminate': {
                'extraCaCertPaths': [
                  '/etc/site-local-roots.pem',
                  '/etc/extra.pem',
                ],
              },
            },
          });
          expect(result.success, isTrue);
          if (result.success) {
            expect(result.data.network.tlsTerminate?.extraCaCertPaths, [
              '/etc/site-local-roots.pem',
              '/etc/extra.pem',
            ]);
          }
        });

        test('is optional', () {
          final result = SandboxRuntimeConfigSchema.safeParse({
            ...base,
            'network': {...base['network']!, 'tlsTerminate': {}},
          });
          expect(result.success, isTrue);
          if (result.success) {
            expect(result.data.network.tlsTerminate?.extraCaCertPaths, isNull);
          }
        });

        test('rejects an empty path', () {
          final result = SandboxRuntimeConfigSchema.safeParse({
            ...base,
            'network': {
              ...base['network']!,
              'tlsTerminate': {
                'extraCaCertPaths': [''],
              },
            },
          });
          expect(result.success, isFalse);
        });
      });

      group('maxTunnels and handshakeTimeoutMs', () {
        ConfigParseResult<SandboxRuntimeConfig> parse(
          Map<String, Object?> tlsTerminate,
        ) => SandboxRuntimeConfigSchema.safeParse({
          ...base,
          'network': {...base['network']!, 'tlsTerminate': tlsTerminate},
        });

        test('are optional and round-trip when given', () {
          final none = parse({});
          expect(none.success, isTrue);
          if (none.success) {
            expect(none.data.network.tlsTerminate?.maxTunnels, isNull);
            expect(none.data.network.tlsTerminate?.handshakeTimeoutMs, isNull);
          }
          final given = parse({
            'maxTunnels': 1024,
            'handshakeTimeoutMs': 30_000,
          });
          expect(given.success, isTrue);
          if (given.success) {
            expect(given.data.network.tlsTerminate?.maxTunnels, 1024);
            expect(given.data.network.tlsTerminate?.handshakeTimeoutMs, 30_000);
          }
        });

        test('accept their bounds', () {
          for (final v in [1, 65536]) {
            expect(parse({'maxTunnels': v}).success, isTrue);
          }
          for (final v in [100, 600_000]) {
            expect(parse({'handshakeTimeoutMs': v}).success, isTrue);
          }
        });

        test('reject a value that is not a positive integer in range', () {
          for (final v in [0, -1, 1.5, 65537, '256', null]) {
            expect(parse({'maxTunnels': v}).success, isFalse);
          }
          for (final v in [0, 99, 1500.5, 600_001, '10000', null]) {
            expect(parse({'handshakeTimeoutMs': v}).success, isFalse);
          }
        });
      });
    });
  });
}

/// `config.filesystem[list]` as the parsed JSON upstream compares against.
List<Object?>? _filesystemJson(FilesystemConfig config, String list) {
  final entries = switch (list) {
    'denyRead' => config.denyRead,
    'allowRead' => config.allowRead,
    'allowWrite' => config.allowWrite,
    'denyWrite' => config.denyWrite,
    _ => throw ArgumentError.value(list, 'list'),
  };
  return entries
      ?.map(
        (e) => switch (e) {
          FilesystemPathSpelling(:final path) => path,
          FilesystemPathLiteral(:final path) => {'path': path, 'literal': true},
        },
      )
      .toList();
}
