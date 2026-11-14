// Ported from sandbox-runtime test/sandbox/mxc-config.test.ts @ 0bbebed.

// ignore_for_file: slash_for_doc_comments, library_prefixes, empty_statements, unnecessary_brace_in_string_interps
import 'package:test/test.dart';
import 'package:sandbox_runtime/src/node/process.dart' as process;
import 'package:sandbox_runtime/src/node/stream.dart' as stream;
import 'package:sandbox_runtime/src/sandbox/windows_sandbox_utils.dart';
import 'package:sandbox_runtime/src/sandbox/mxc_sandbox_utils.dart' as mxcUtils;
import 'package:sandbox_runtime/src/sandbox/mxc_sandbox_utils.dart';
import 'package:sandbox_runtime/src/sandbox/sandbox_utils.dart';

/**
 * The request srt hands the MXC SDK, and the probe gate in front of
 * every spawn. Runs on every platform: request building is pure and
 * the SDK is a fake here, so only a Windows host runs the real thing.
 */

/** A probe answer that supports everything srt asks for. */
MxcProbeOutput fullSupport({
  String? tier = 'base-container',
  bool augmentation = false,
  String? error,
  bool denyPaths = true,
  bool loopback = true,
  bool proxy = true,
  bool clipboard = true,
  bool injection = true,
}) => MxcProbeOutput(
  tier: tier,
  needsDaclAugmentation: augmentation,
  warnings: [],
  error: error,
  probes: (
    baseContainerSupportsDenyPaths: denyPaths,
    baseContainerSupportsIngressHostLoopbackAllow: loopback,
    baseContainerSupportsIdentitylessLoopbackProxy: proxy,
    uiCapabilities: MxcUiCapabilities(
      canBlockClipboardRead: clipboard,
      canBlockClipboardWrite: true,
      canBlockInputInjection: injection,
    ),
  ),
);

/** A request with a proxy and a denied path, so every check applies. */
MxcRequest strictRequest() => buildMxcRequest(
  const MxcSandboxParams(
    command: 'exit 0',
    httpProxyPort: 48123,
    proxyAuthToken: 'tok',
    denyRead: [r'C:\secret'],
  ),
);

({FakeSdk sdk, List<MxcRequest> spawned}) fakeSdk(
  MxcProbeOutput Function() probe,
) {
  final spawned = <MxcRequest>[];
  final sdk = FakeSdk(probe, (request) async {
    spawned.add(request);
    return FakeProcess(1);
  });
  return (sdk: sdk, spawned: spawned);
}

class FakeSdk implements MxcSdk {
  MxcProbeOutput Function() answer;
  final Future<MxcProcessHandle> Function(MxcRequest) start;
  FakeSdk(this.answer, this.start);
  @override
  MxcProbeOutput probe(MxcRequest request) => answer();
  @override
  Future<MxcProcessHandle> spawn(MxcRequest request) => start(request);
}

class FakeProcess implements MxcProcessHandle {
  @override
  final int id;
  FakeProcess(this.id);
  @override
  stream.Writable? get standardInput => null;
  @override
  stream.Readable? get standardOutput => null;
  @override
  stream.Readable? get standardError => null;
  @override
  Future<({int exitCode, bool timedOut})> wait() async =>
      (exitCode: 0, timedOut: false);
  @override
  void kill() {}
  @override
  void dispose() {}
}

class Sdk implements MxcSdk {
  final _answer = fullSupport();
  @override
  MxcProbeOutput probe(MxcRequest request) => _answer;
  @override
  Future<MxcProcessHandle> spawn(MxcRequest request) async =>
      FakeProcess(_answer.warnings.length);
}

void main() {
  group('resolveMxcSdk', () {
    test(
      'returns the injected functions and does not load the package',
      () async {
        final load = mxcUtils.loadMxcSdk;
        var calls = 0;
        mxcUtils.loadMxcSdk = () async {
          calls++;
          return load();
        };
        try {
          final (:sdk, :spawned) = fakeSdk(fullSupport);
          final resolved = await resolveMxcSdk(sdk);
          expect(resolved.probe(strictRequest()).tier, fullSupport().tier);
          await resolved.spawn(strictRequest());
          expect(spawned, hasLength(1));
          expect(calls, 0);
        } finally {
          mxcUtils.loadMxcSdk = load;
        }
        ;
      },
    );

    test(
      'is not changed by a later change to the object it was given',
      () async {
        var sdk = fakeSdk(fullSupport).sdk;
        final resolved = await resolveMxcSdk(sdk);
        sdk = fakeSdk(() => fullSupport(tier: 'other')).sdk;
        expect(sdk.probe(strictRequest()).tier, 'other');
        expect(resolved.probe(strictRequest()).tier, 'base-container');
      },
    );

    test('keeps the receiver of an SDK whose methods use this', () async {
      final resolved = await resolveMxcSdk(Sdk());
      expect(resolved.probe(strictRequest()).tier, 'base-container');
      expect((await resolved.spawn(strictRequest())).id, 0);
    });

    test('refuses null rather than throwing a TypeError', () async {
      // eslint-disable-next-line @typescript-eslint/await-thenable
      await expectLater(
        resolveMxcSdk(null),
        throwsA(
          isA<WindowsSandboxError>().having(
            (e) => e.code,
            'code',
            'backend_unsupported',
          ),
        ),
      );
    });

    test('falls back to the package when none is injected', () async {
      final package_ = fakeSdk(fullSupport).sdk;
      final load = mxcUtils.loadMxcSdk;
      var calls = 0;
      mxcUtils.loadMxcSdk = () async {
        calls++;
        return package_;
      };
      try {
        expect(await resolveMxcSdk(), package_);
        expect(calls, 1);
      } finally {
        mxcUtils.loadMxcSdk = load;
      }
      ;
    });
  });

  group('MXC SDK request', () {
    test('seals the environment and sets no backend containment', () {
      final req = buildMxcRequest(MxcSandboxParams(command: 'exit 0'));
      expect(req.command, contains('exit 0'));
      expect(req.inheritDefaultEnvironment, isFalse);
      // The typed mirror has no containment field.
      expect(req.timeoutMs, isNull);
      expect(req.environment, isA<Map<String, String>>());
    });

    test(
      'denies egress, ingress and host loopback explicitly without a proxy',
      () {
        final req = buildMxcRequest(MxcSandboxParams(command: 'exit 0'));
        expect(req.network, (
          egress: (defaultAction: 'deny'),
          ingress: (defaultAction: 'deny', hostLoopback: 'deny'),
          runtimeConfig: null,
        ));
      },
    );

    test('routes egress through the host proxy when there is one', () {
      final req = buildMxcRequest(
        MxcSandboxParams(
          command: 'exit 0',
          commandId: 'tool-1',
          httpProxyPort: 48123,
          proxyAuthToken: 'tok',
        ),
      );
      final user = Uri.encodeComponent(
        proxyUsernameFor(
          encodeSandboxedCommand(attributionKeyFor('exit 0', 'tool-1')),
        ),
      );
      expect(req.network, (
        egress: (defaultAction: 'deny'),
        ingress: (defaultAction: 'allow', hostLoopback: 'allow'),
        runtimeConfig: (networkProxy: 'http://${user}:tok@127.0.0.1:48123'),
      ));
      expect(
        req.environment['https_proxy'],
        'http://${user}:tok@localhost:48123',
      );
      expect(req.environment, isNot(contains('NO_PROXY')));
    });

    test('carries the command id in the proxy username, as srt-win does', () {
      final req = buildMxcRequest(
        MxcSandboxParams(
          command: 'curl x',
          commandId: 'tool-42',
          httpProxyPort: 1,
          proxyAuthToken: 'tok',
        ),
      );
      final userinfo = Uri.parse(
        req.network.runtimeConfig!.networkProxy,
      ).userInfo.split(':').first;
      final user = Uri.decodeComponent(userinfo);
      expect(user.startsWith('srt.'), isTrue);
      expect(
        decodeSandboxedCommand(user.substring('srt.'.length)),
        attributionKeyFor('curl x', 'tool-42'),
      );
    });

    test(
      'keeps UI on for every shell, with clipboard and injection blocked',
      () {
        for (final binShell in [
          null,
          WindowsBinShell(exe: r'C:\Windows\System32\cmd.exe', args: ['/c']),
          WindowsBinShell(exe: r'C:\pwsh\pwsh.exe', args: ['-c']),
        ]) {
          expect(
            buildMxcRequest(
              MxcSandboxParams(command: 'exit 0', binShell: binShell),
            ).ui,
            (disable: false, clipboard: 'none', allowInputInjection: false),
          );
        }
      },
    );

    test('maps reads, writes and denies onto the allow-list model', () {
      final req = buildMxcRequest(
        MxcSandboxParams(
          command: 'exit 0',
          cwd: 'C:\\work',
          allowRead: ['D:\\data'],
          allowWrite: ['C:\\work\\out'],
          denyRead: ['C:\\work\\secret'],
          denyWrite: ['C:\\work\\out\\keep'],
          timeoutMs: 5000,
        ),
      );
      expect(req.workingDirectory, 'C:\\work');
      expect(req.filesystem.readonlyPaths, contains('C:\\work'));
      expect(req.filesystem.readonlyPaths, contains('D:\\data'));
      expect(req.filesystem.readwritePaths, contains('C:\\work\\out'));
      expect(req.filesystem.readwritePaths, isNot(contains('C:\\work')));
      expect(req.filesystem.deniedPaths, [
        'C:\\work\\secret',
        'C:\\work\\out\\keep',
      ]);
      expect(req.timeoutMs, 5000);
    });

    test("lays the caller's env over every other layer", () {
      final req = buildMxcRequest(
        MxcSandboxParams(
          command: 'exit 0',
          httpProxyPort: 48123,
          setEnvVars: {'MASKED': 'sentinel'},
          env: {
            'MASKED': 'caller',
            'CALLER_ONLY': '1',
            'NODE_USE_ENV_PROXY': '0',
          },
        ),
      );
      expect(req.environment['MASKED'], 'caller');
      expect(req.environment['CALLER_ONLY'], '1');
      expect(req.environment['NODE_USE_ENV_PROXY'], '0');
    });

    test('gives each name one spelling, as Windows reads names', () {
      final req = buildMxcRequest(
        MxcSandboxParams(
          command: 'exit 0',
          setEnvVars: {'Masked': 'sentinel'},
          env: {'MASKED': 'caller'},
        ),
      );
      expect(req.environment.keys.where((k) => k.toUpperCase() == 'MASKED'), [
        'MASKED',
      ]);
      expect(req.environment['MASKED'], 'caller');
    });

    test('sets NODE_USE_ENV_PROXY only when there is a proxy', () {
      expect(
        buildMxcRequest(
          MxcSandboxParams(command: 'exit 0', httpProxyPort: 48123),
        ).environment['NODE_USE_ENV_PROXY'],
        '1',
      );
      expect(
        buildMxcRequest(MxcSandboxParams(command: 'exit 0')).environment,
        isNot(contains('NODE_USE_ENV_PROXY')),
      );
    });

    test('does not pass the host environment through', () {
      process.setEnvForTesting({
        ...process.env,
        'SRT_MXC_HOST_ONLY': 'host-secret',
      });
      try {
        final req = buildMxcRequest(
          MxcSandboxParams(
            command: 'exit 0',
            setEnvVars: {'MASKED': 'sentinel'},
          ),
        );
        expect(req.environment, isNot(contains('SRT_MXC_HOST_ONLY')));
        expect(req.environment['MASKED'], 'sentinel');
      } finally {
        process.setEnvForTesting(null);
      }
      ;
    });
  });

  group('MXC probe gate (fail closed)', () {
    test('accepts a request the probe fully supports', () async {
      final (:sdk, :spawned) = fakeSdk(fullSupport);
      expect(mxcProbeRefusals(strictRequest(), fullSupport()), []);
      await spawnMxcRequest(sdk, strictRequest());
      expect(spawned, hasLength(1));
    });

    final unsupported = <(String, MxcProbeOutput Function(), RegExp)>[
      (
        'an AppContainer tier',
        () => fullSupport(tier: 'appcontainer-dacl'),
        RegExp('tier'),
      ),
      ('no tier', () => fullSupport(tier: null), RegExp("tier 'none'")),
      (
        'DACL augmentation',
        () => fullSupport(augmentation: true),
        RegExp('DACL'),
      ),
      (
        'no denied-path support',
        () => fullSupport(denyPaths: false),
        RegExp('denied paths'),
      ),
      (
        'no host-proxy confinement',
        () => fullSupport(proxy: false),
        RegExp('host proxy'),
      ),
      (
        'no host loopback',
        () => fullSupport(loopback: false),
        RegExp('host loopback'),
      ),
      (
        'no clipboard blocking',
        () => fullSupport(clipboard: false),
        RegExp('clipboard'),
      ),
      (
        'no input-injection blocking',
        () => fullSupport(injection: false),
        RegExp('input injection'),
      ),
      (
        'a detector error',
        () => fullSupport(error: 'detector broke'),
        RegExp('detector broke'),
      ),
    ];
    for (final (what, degrade, message) in unsupported) {
      test('refuses to spawn when the probe reports ${what}', () async {
        final (:sdk, :spawned) = fakeSdk(() {
          final p = degrade();
          return p;
        });
        // eslint-disable-next-line @typescript-eslint/await-thenable
        await expectLater(
          spawnMxcRequest(sdk, strictRequest()),
          throwsA(
            isA<WindowsSandboxError>()
                .having((e) => e.code, 'code', 'backend_unsupported')
                .having((e) => e.message, 'message', matches(message)),
          ),
        );
        expect(spawned, hasLength(0));
      });
    }

    test('refuses to spawn when the probe throws', () async {
      final (:sdk, :spawned) = fakeSdk(() {
        throw Exception('mxc_ffi missing');
      });
      // eslint-disable-next-line @typescript-eslint/await-thenable
      await expectLater(
        spawnMxcRequest(sdk, strictRequest()),
        throwsA(
          isA<WindowsSandboxError>()
              .having((e) => e.code, 'code', 'backend_unsupported')
              .having((e) => e.message, 'message', contains('mxc_ffi missing')),
        ),
      );
      expect(spawned, hasLength(0));
    });

    test(
      'only checks denied-path and proxy support when the request uses them',
      () {
        final p = fullSupport(denyPaths: false, proxy: false, loopback: false);
        expect(
          mxcProbeRefusals(buildMxcRequest(MxcSandboxParams(command: 'x')), p),
          [],
        );
      },
    );

    test('sends a grant beneath a deny in both lists, unrefused', () async {
      // MXC resolves by path specificity, so the nested grant wins for
      // its own subtree, matching srt's ranking.
      final (:sdk, :spawned) = fakeSdk(fullSupport);
      final req = buildMxcRequest(
        MxcSandboxParams(
          command: 'x',
          cwd: 'C:\\Users\\me\\project',
          denyRead: ['C:\\Users\\me'],
          allowRead: ['C:\\Users\\me\\docs'],
          allowWrite: ['C:\\Users\\me\\project'],
        ),
      );
      expect(req.filesystem.deniedPaths, ['C:\\Users\\me']);
      expect(req.filesystem.readonlyPaths, contains('C:\\Users\\me\\docs'));
      expect(req.filesystem.readwritePaths, contains('C:\\Users\\me\\project'));
      await spawnMxcRequest(sdk, req);
      expect(spawned, [req]);
    });

    test('never makes a write grant, or what is beneath it, read-only', () {
      final req = buildMxcRequest(
        MxcSandboxParams(
          command: 'x',
          cwd: 'C:\\proj\\src',
          allowWrite: ['C:\\proj'],
          allowRead: ['C:\\proj', 'C:\\proj\\docs', 'D:\\data'],
        ),
      );
      expect(req.filesystem.readwritePaths, contains('C:\\proj'));
      expect(req.filesystem.readonlyPaths, ['C:\\', 'D:\\data']);
    });

    test('keeps a read grant beneath a deny inside a write grant', () {
      final req = buildMxcRequest(
        MxcSandboxParams(
          command: 'x',
          cwd: 'C:\\elsewhere',
          allowWrite: ['C:\\proj'],
          denyRead: ['C:\\proj\\secret'],
          allowRead: ['C:\\proj\\secret\\ok'],
        ),
      );
      expect(req.filesystem.readonlyPaths, contains('C:\\proj\\secret\\ok'));
    });

    test('does not grant reads on a working directory beneath a deny', () {
      final req = buildMxcRequest(
        MxcSandboxParams(
          command: 'x',
          cwd: 'C:\\Users\\me\\private',
          denyRead: ['C:\\Users\\me'],
        ),
      );
      expect(
        req.filesystem.readonlyPaths,
        isNot(contains('C:\\Users\\me\\private')),
      );
    });

    test('sends a deny beneath a grant as a denied path', () {
      final req = buildMxcRequest(
        MxcSandboxParams(
          command: 'x',
          allowWrite: ['C:\\work'],
          denyWrite: ['C:\\work\\.git'],
        ),
      );
      expect(req.filesystem.readwritePaths, contains('C:\\work'));
      expect(req.filesystem.deniedPaths, ['C:\\work\\.git']);
    });

    test('verifyMxcBackend refuses like spawn', () {
      var p = fullSupport();
      final req = buildMxcRequest(MxcSandboxParams(command: 'x'));
      expect(
        () => verifyMxcBackend(fakeSdk(() => p).sdk, req),
        isNot(throwsA(anything)),
      );
      p = fullSupport(tier: 'appcontainer-bfs');
      expect(
        () => verifyMxcBackend(fakeSdk(() => p).sdk, req),
        throwsA(
          isA<WindowsSandboxError>().having(
            (e) => e.message,
            'message',
            contains('BaseContainer is required'),
          ),
        ),
      );
    });
  });
}
