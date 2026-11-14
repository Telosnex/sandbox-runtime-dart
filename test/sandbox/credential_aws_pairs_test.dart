// Ported from sandbox-runtime test/sandbox/credential-aws-pairs.test.ts @ 0bbebed.
// ignore_for_file: constant_identifier_names, non_constant_identifier_names, slash_for_doc_comments, prefer_adjacent_string_concatenation, prefer_interpolation_to_compose_strings
import 'dart:convert';

import 'package:sandbox_runtime/src/node/console.dart' as console;
import 'package:sandbox_runtime/src/node/http.dart' show IncomingHttpHeaders;
import 'package:sandbox_runtime/src/sandbox/aws_sigv4.dart'
    show
        Sigv4SignInput,
        UNSIGNED_PAYLOAD,
        parseSigv4Authorization,
        sha256Hex,
        signSigv4;
import 'package:sandbox_runtime/src/sandbox/credential_aws_pairs.dart';
import 'package:sandbox_runtime/src/sandbox/credential_mask_env.dart'
    show buildMaskedEnvVars;
import 'package:sandbox_runtime/src/sandbox/credential_sentinel.dart'
    show SentinelRegistry;
import 'package:sandbox_runtime/src/sandbox/sandbox_config.dart';
import 'package:test/test.dart';

const REAL_AKID = 'AKIAIOSFODNN7EXAMPLE';
const REAL_SECRET = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
const REAL_TOKEN = 'FQoGZXIvYXdzEXAMPLEsessiontoken';

/** Host matcher for tests: exact equality. */
bool eq(String h, String p) => h == p;

// Dart: `spyOn(console, 'warn').mockImplementation(() => {})` is a saved
// console.warn replaced by a recorder of its first arguments.
class _WarnSpy {
  _WarnSpy() : _saved = console.warn {
    console.warn = ([a, b, c, d]) {
      calls.add(a);
    };
  }
  final console.ConsoleMethod _saved;
  final calls = <Object?>[];
  void mockRestore() {
    console.warn = _saved;
  }
}

// Dart: `decision?.action`, which Sigv4Plan declares on its subclasses.
String? _action(Sigv4Plan? decision) => switch (decision) {
  Sigv4PlanResign() => 'resign',
  Sigv4PlanDeny() => 'deny',
  null => null,
};

// Dart: `JSON.stringify(result.error?.issues)`.
String _stringifyIssues(ConfigParseResult<SandboxRuntimeConfig> result) =>
    jsonEncode([
      for (final i in result.error.issues)
        {'code': i.code, 'path': i.path, 'message': i.message},
    ]);

/**
 * Run the real masked-env build so pairs register from the same
 * sentinels the sandbox would see, then register pairs.
 */
({
  AwsPairRegistry pairs,
  Map<String, String> setEnvVars,
  SentinelRegistry sentinels,
})
buildPairs(
  List<CredentialEnvVarConfig> envVars,
  Map<String, String?> env, {
  List<AwsPairConfig>? awsPairs,
  List<String>? allowedDomains,
}) {
  final sentinels = SentinelRegistry();
  final allowedDomains_ = allowedDomains ?? ['s3.amazonaws.com'];
  final setEnvVars = buildMaskedEnvVars(
    envVars,
    allowedDomains_,
    sentinels,
    env,
  ).setEnvVars;
  final pairs = AwsPairRegistry();
  registerAwsPairs(envVars, awsPairs, allowedDomains_, setEnvVars, pairs, env);
  return (pairs: pairs, setEnvVars: setEnvVars, sentinels: sentinels);
}

const CONVENTIONAL_MASK = <CredentialEnvVarConfig>[
  CredentialEnvVarConfig(name: 'AWS_ACCESS_KEY_ID', mode: 'mask'),
  CredentialEnvVarConfig(name: 'AWS_SECRET_ACCESS_KEY', mode: 'mask'),
];

/** A registry with one pair, plus its fake AKID, for planner tests. */
({AwsPairRegistry pairs, String fakeAkid}) plannerFixture({
  bool? sessionToken,
}) {
  final (:pairs, :setEnvVars, sentinels: _) = buildPairs(
    [
      ...CONVENTIONAL_MASK,
      if (sessionToken == true)
        const CredentialEnvVarConfig(name: 'AWS_SESSION_TOKEN', mode: 'mask'),
    ],
    {
      'AWS_ACCESS_KEY_ID': REAL_AKID,
      'AWS_SECRET_ACCESS_KEY': REAL_SECRET,
      if (sessionToken == true) 'AWS_SESSION_TOKEN': REAL_TOKEN,
    },
  );
  return (pairs: pairs, fakeAkid: setEnvVars['AWS_ACCESS_KEY_ID']!);
}

/** Client-side headers signed with the FAKE credentials, like an SDK would. */
({IncomingHttpHeaders headers, String method, String target}) fakeSignedHeaders(
  String fakeAkid, {
  String? method,
  String? target,
  String? contentSha,
  IncomingHttpHeaders? extra,
  String? service,
}) {
  method ??= 'GET';
  target ??= '/';
  final IncomingHttpHeaders headers = {
    'x-amz-date': '20150830T123600Z',
    if (contentSha != null && contentSha != '')
      'x-amz-content-sha256': contentSha,
    ...?extra,
  };
  final signedHeaders = ['host', ...headers.keys];
  final authorization = signSigv4(
    Sigv4SignInput(
      method: method,
      requestTarget: target,
      headers: headers,
      hostHeader: 's3.amazonaws.com',
      signedHeaders: signedHeaders,
      payloadHash: contentSha ?? sha256Hex(''),
      amzDate: '20150830T123600Z',
      scope: (date: '20150830', region: 'us-east-1', service: service ?? 's3'),
      accessKeyId: fakeAkid,
      secretAccessKey: 'fake_value_not-the-real-secret',
    ),
  ).authorization;
  headers['authorization'] = authorization;
  return (headers: headers, method: method, target: target);
}

void main() {
  group('registerAwsPairs', () {
    test('auto-detects the conventional trio when masked whole-value', () {
      final (:pairs, :setEnvVars, sentinels: _) = buildPairs(
        [
          ...CONVENTIONAL_MASK,
          const CredentialEnvVarConfig(name: 'AWS_SESSION_TOKEN', mode: 'mask'),
        ],
        {
          'AWS_ACCESS_KEY_ID': REAL_AKID,
          'AWS_SECRET_ACCESS_KEY': REAL_SECRET,
          'AWS_SESSION_TOKEN': REAL_TOKEN,
        },
      );
      expect(pairs.size, 1);
      final pair = pairs.lookup(setEnvVars['AWS_ACCESS_KEY_ID']!);
      expect(
        pair,
        isA<AwsCredentialPair>()
            .having((p) => p.realAccessKeyId, 'realAccessKeyId', REAL_AKID)
            .having(
              (p) => p.realSecretAccessKey,
              'realSecretAccessKey',
              REAL_SECRET,
            )
            .having((p) => p.realSessionToken, 'realSessionToken', REAL_TOKEN)
            .having((p) => p.injectHosts, 'injectHosts', ['s3.amazonaws.com']),
      );
    });

    test('session token is optional', () {
      final (:pairs, :setEnvVars, sentinels: _) = buildPairs(
        CONVENTIONAL_MASK,
        {'AWS_ACCESS_KEY_ID': REAL_AKID, 'AWS_SECRET_ACCESS_KEY': REAL_SECRET},
      );
      expect(pairs.size, 1);
      expect(
        pairs.lookup(setEnvVars['AWS_ACCESS_KEY_ID']!)?.realSessionToken,
        isNull,
      );
    });

    test('injectHosts comes from the access-key-id entry', () {
      final (:pairs, :setEnvVars, sentinels: _) = buildPairs(
        [
          const CredentialEnvVarConfig(
            name: 'AWS_ACCESS_KEY_ID',
            mode: 'mask',
            injectHosts: ['sts.amazonaws.com'],
          ),
          const CredentialEnvVarConfig(
            name: 'AWS_SECRET_ACCESS_KEY',
            mode: 'mask',
          ),
        ],
        {'AWS_ACCESS_KEY_ID': REAL_AKID, 'AWS_SECRET_ACCESS_KEY': REAL_SECRET},
      );
      expect(pairs.lookup(setEnvVars['AWS_ACCESS_KEY_ID']!)?.injectHosts, [
        'sts.amazonaws.com',
      ]);
    });

    test('no pair without both members masked and set', () {
      // Secret env var unset on the host → nothing to link.
      final (:pairs, setEnvVars: _, sentinels: _) = buildPairs(
        CONVENTIONAL_MASK,
        {'AWS_ACCESS_KEY_ID': REAL_AKID},
      );
      expect(pairs.size, 0);
    });

    test('masked secret without a masked access key id warns loudly', () {
      final warnSpy = _WarnSpy();
      try {
        final (:pairs, setEnvVars: _, sentinels: _) = buildPairs(
          [
            const CredentialEnvVarConfig(
              name: 'AWS_SECRET_ACCESS_KEY',
              mode: 'mask',
            ),
          ],
          {'AWS_SECRET_ACCESS_KEY': REAL_SECRET},
        );
        expect(pairs.size, 0);
        final msg = warnSpy.calls
            .map((c) => c as String)
            .where((m) => m.contains('AWS_SECRET_ACCESS_KEY'))
            .firstOrNull;
        expect(msg, isNotNull);
        expect(msg, contains('re-sign'));
      } finally {
        warnSpy.mockRestore();
      }
    });

    test('an extract entry is not usable as a pair member', () {
      final (:pairs, setEnvVars: _, sentinels: _) = buildPairs(
        [
          const CredentialEnvVarConfig(
            name: 'AWS_ACCESS_KEY_ID',
            mode: 'mask',
            extract: '(AKIA\\w+)',
          ),
          const CredentialEnvVarConfig(
            name: 'AWS_SECRET_ACCESS_KEY',
            mode: 'mask',
          ),
        ],
        {'AWS_ACCESS_KEY_ID': REAL_AKID, 'AWS_SECRET_ACCESS_KEY': REAL_SECRET},
      );
      expect(pairs.size, 0);
    });

    test('explicit awsPairs links non-standard names', () {
      final envVars = <CredentialEnvVarConfig>[
        const CredentialEnvVarConfig(name: 'MY_AKID', mode: 'mask'),
        const CredentialEnvVarConfig(name: 'MY_SECRET', mode: 'mask'),
        const CredentialEnvVarConfig(name: 'MY_TOKEN', mode: 'mask'),
      ];
      final (:pairs, :setEnvVars, sentinels: _) = buildPairs(
        envVars,
        {
          'MY_AKID': REAL_AKID,
          'MY_SECRET': REAL_SECRET,
          'MY_TOKEN': REAL_TOKEN,
        },
        awsPairs: [
          const AwsPairConfig(
            accessKeyIdVar: 'MY_AKID',
            secretAccessKeyVar: 'MY_SECRET',
            sessionTokenVar: 'MY_TOKEN',
          ),
        ],
      );
      expect(pairs.size, 1);
      expect(
        pairs.lookup(setEnvVars['MY_AKID']!),
        isA<AwsCredentialPair>()
            .having((p) => p.realAccessKeyId, 'realAccessKeyId', REAL_AKID)
            .having(
              (p) => p.realSecretAccessKey,
              'realSecretAccessKey',
              REAL_SECRET,
            )
            .having((p) => p.realSessionToken, 'realSessionToken', REAL_TOKEN),
      );
    });

    test(
      'an explicit pair naming a conventional var suppresses auto-detection',
      () {
        final envVars = <CredentialEnvVarConfig>[
          ...CONVENTIONAL_MASK,
          const CredentialEnvVarConfig(name: 'OTHER_SECRET', mode: 'mask'),
        ];
        final (:pairs, :setEnvVars, sentinels: _) = buildPairs(
          envVars,
          {
            'AWS_ACCESS_KEY_ID': REAL_AKID,
            'AWS_SECRET_ACCESS_KEY': REAL_SECRET,
            'OTHER_SECRET': 'other-secret',
          },
          awsPairs: [
            const AwsPairConfig(
              accessKeyIdVar: 'AWS_ACCESS_KEY_ID',
              secretAccessKeyVar: 'OTHER_SECRET',
            ),
          ],
        );
        // Only the explicit pair registered; the conventional trio spec did
        // not additionally fire on the same variables.
        expect(pairs.size, 1);
        expect(
          pairs.lookup(setEnvVars['AWS_ACCESS_KEY_ID']!)?.realSecretAccessKey,
          'other-secret',
        );
      },
    );

    test('clear drops every pair', () {
      final (:pairs, :setEnvVars, sentinels: _) = buildPairs(
        CONVENTIONAL_MASK,
        {'AWS_ACCESS_KEY_ID': REAL_AKID, 'AWS_SECRET_ACCESS_KEY': REAL_SECRET},
      );
      pairs.clear();
      expect(pairs.size, 0);
      expect(pairs.lookup(setEnvVars['AWS_ACCESS_KEY_ID']!), isNull);
    });
  });

  group('createSigv4Planner', () {
    test('re-signs a header-sigv4 request with the real credentials', () {
      final (:pairs, :fakeAkid) = plannerFixture();
      final plan = createSigv4Planner(pairs, null, eq);
      final (:headers, :method, :target) = fakeSignedHeaders(fakeAkid);

      final decision = plan(method, target, headers, 's3.amazonaws.com');
      expect(_action(decision), 'resign');
      if (decision is! Sigv4PlanResign) return;

      // GET signed the empty hash but carries no x-amz-content-sha256 →
      // caller buffers (an empty body) and provides the hash.
      expect(decision.payloadHash, isNull);
      final IncomingHttpHeaders fwd = {...headers};
      fwd.remove('host');
      decision.apply(fwd, 's3.amazonaws.com', sha256Hex(''));

      final parsed = parseSigv4Authorization(fwd['authorization'] as String)!;
      expect(parsed.accessKeyId, REAL_AKID);
      expect(parsed.region, 'us-east-1');
      expect(parsed.service, 's3');
      // The signature matches an independent re-computation from the REAL
      // secret over the forwarded request.
      final expected = signSigv4(
        Sigv4SignInput(
          method: method,
          requestTarget: target,
          headers: fwd,
          hostHeader: 's3.amazonaws.com',
          signedHeaders: parsed.signedHeaders,
          payloadHash: sha256Hex(''),
          amzDate: '20150830T123600Z',
          scope: (date: '20150830', region: 'us-east-1', service: 's3'),
          accessKeyId: REAL_AKID,
          secretAccessKey: REAL_SECRET,
        ),
      );
      expect(parsed.signature, expected.signature);
    });

    test('UNSIGNED-PAYLOAD re-signs without needing the body', () {
      final (:pairs, :fakeAkid) = plannerFixture();
      final plan = createSigv4Planner(pairs, null, eq);
      final (:headers, :method, :target) = fakeSignedHeaders(
        fakeAkid,
        method: 'PUT',
        target: '/bucket/key',
        contentSha: UNSIGNED_PAYLOAD,
      );
      final decision = plan(method, target, headers, 's3.amazonaws.com');
      expect(_action(decision), 'resign');
      if (decision is! Sigv4PlanResign) return;
      expect(decision.payloadHash, UNSIGNED_PAYLOAD);
      final IncomingHttpHeaders fwd = {...headers};
      fwd.remove('host');
      decision.apply(fwd, 's3.amazonaws.com', UNSIGNED_PAYLOAD);
      // The marker header is preserved, not overwritten with a hash.
      expect(fwd['x-amz-content-sha256'], UNSIGNED_PAYLOAD);
      expect(fwd['authorization'], contains('Credential=$REAL_AKID/'));
    });

    test('injects the real session token and adds it to SignedHeaders', () {
      final (:pairs, :fakeAkid) = plannerFixture(sessionToken: true);
      final plan = createSigv4Planner(pairs, null, eq);
      // Client did not send x-amz-security-token at all.
      final (:headers, :method, :target) = fakeSignedHeaders(fakeAkid);
      final decision = plan(method, target, headers, 's3.amazonaws.com');
      expect(_action(decision), 'resign');
      if (decision is! Sigv4PlanResign) return;
      final IncomingHttpHeaders fwd = {...headers};
      fwd.remove('host');
      decision.apply(fwd, 's3.amazonaws.com', sha256Hex(''));
      expect(fwd['x-amz-security-token'], REAL_TOKEN);
      final parsed = parseSigv4Authorization(fwd['authorization'] as String)!;
      expect(parsed.signedHeaders, contains('x-amz-security-token'));
    });

    test('replaces a client-sent fake session token with the real one', () {
      final (:pairs, :fakeAkid) = plannerFixture(sessionToken: true);
      final plan = createSigv4Planner(pairs, null, eq);
      final (:headers, :method, :target) = fakeSignedHeaders(
        fakeAkid,
        extra: {'x-amz-security-token': 'fake_value_session-sentinel'},
      );
      final decision = plan(method, target, headers, 's3.amazonaws.com');
      expect(_action(decision), 'resign');
      if (decision is! Sigv4PlanResign) return;
      final IncomingHttpHeaders fwd = {...headers};
      fwd.remove('host');
      decision.apply(fwd, 's3.amazonaws.com', sha256Hex(''));
      expect(fwd['x-amz-security-token'], REAL_TOKEN);
      final parsed = parseSigv4Authorization(fwd['authorization'] as String)!;
      // Only one occurrence — the client already listed it.
      expect(
        parsed.signedHeaders.where((h) => h == 'x-amz-security-token'),
        hasLength(1),
      );
    });

    test('a literal x-amz-content-sha256 is pinned to the recomputed hash', () {
      final (:pairs, :fakeAkid) = plannerFixture();
      final plan = createSigv4Planner(pairs, null, eq);
      final bodyHash = sha256Hex('Param1=value1');
      final (:headers, :method, :target) = fakeSignedHeaders(
        fakeAkid,
        method: 'POST',
        contentSha: bodyHash,
      );
      final decision = plan(method, target, headers, 's3.amazonaws.com');
      expect(_action(decision), 'resign');
      if (decision is! Sigv4PlanResign) return;
      // Literal hash → the proxy must buffer and recompute.
      expect(decision.payloadHash, isNull);
      final IncomingHttpHeaders fwd = {...headers};
      fwd.remove('host');
      decision.apply(fwd, 's3.amazonaws.com', bodyHash);
      expect(fwd['x-amz-content-sha256'], bodyHash);
    });

    test('an unmasked (real) access key id is never touched', () {
      final (:pairs, fakeAkid: _) = plannerFixture();
      final plan = createSigv4Planner(pairs, null, eq);
      final (:headers, :method, :target) = fakeSignedHeaders(REAL_AKID);
      expect(plan(method, target, headers, 's3.amazonaws.com'), isNull);
    });

    test('a destination outside injectHosts is untouched', () {
      final (:pairs, :fakeAkid) = plannerFixture();
      final plan = createSigv4Planner(pairs, null, eq);
      final (:headers, :method, :target) = fakeSignedHeaders(fakeAkid);
      expect(plan(method, target, headers, 'evil.example.com'), isNull);
    });

    test('non-SigV4 requests are untouched', () {
      final (:pairs, fakeAkid: _) = plannerFixture();
      final plan = createSigv4Planner(pairs, null, eq);
      expect(
        plan('GET', '/', {'authorization': 'Bearer tok'}, 's3.amazonaws.com'),
        isNull,
      );
      expect(plan('GET', '/', {}, 's3.amazonaws.com'), isNull);
    });

    test('missing x-amz-date fails closed', () {
      final (:pairs, :fakeAkid) = plannerFixture();
      final plan = createSigv4Planner(pairs, null, eq);
      final IncomingHttpHeaders headers = {
        'authorization':
            'AWS4-HMAC-SHA256 Credential=$fakeAkid/20150830/us-east-1/s3/aws4_request, ' +
            'SignedHeaders=host, Signature=ff00',
      };
      final decision = plan('GET', '/', headers, 's3.amazonaws.com');
      expect(_action(decision), 'deny');
      if (decision is Sigv4PlanDeny) {
        expect(decision.reason, contains('x-amz-date'));
      }
    });

    test('a signed header missing from the request fails closed', () {
      final (:pairs, :fakeAkid) = plannerFixture();
      final plan = createSigv4Planner(pairs, null, eq);
      final IncomingHttpHeaders headers = {
        'x-amz-date': '20150830T123600Z',
        'authorization':
            'AWS4-HMAC-SHA256 Credential=$fakeAkid/20150830/us-east-1/s3/aws4_request, ' +
            'SignedHeaders=content-type;host;x-amz-date, Signature=ff00',
      };
      final decision = plan('GET', '/', headers, 's3.amazonaws.com');
      expect(_action(decision), 'deny');
      if (decision is Sigv4PlanDeny) {
        expect(decision.reason, contains('content-type'));
      }
    });

    group('policies for non-re-signable shapes', () {
      Map<String, ({String method, String target, IncomingHttpHeaders headers})>
      shapes(String fakeAkid) {
        final streaming = fakeSignedHeaders(
          fakeAkid,
          method: 'PUT',
          target: '/bucket/key',
          contentSha: 'STREAMING-AWS4-HMAC-SHA256-PAYLOAD',
        );
        final presigned = (
          method: 'GET',
          target:
              '/key?X-Amz-Algorithm=AWS4-HMAC-SHA256' +
              '&X-Amz-Credential=${Uri.encodeComponent('$fakeAkid/20150830/us-east-1/s3/aws4_request')}' +
              '&X-Amz-Date=20150830T123600Z&X-Amz-SignedHeaders=host' +
              '&X-Amz-Signature=ff00',
          headers: <String, Object?>{},
        );
        final sigv4a = (
          method: 'GET',
          target: '/',
          headers: <String, Object?>{
            'x-amz-date': '20150830T123600Z',
            'x-amz-region-set': '*',
            'authorization':
                'AWS4-ECDSA-P256-SHA256 Credential=$fakeAkid/20150830/s3/aws4_request, ' +
                'SignedHeaders=host;x-amz-date;x-amz-region-set, Signature=ff00',
          },
        );
        return {
          'streaming': streaming,
          'presigned': presigned,
          'sigv4a': sigv4a,
        };
      }

      test(
        'streaming, presigned, and sigv4a deny by default, naming the knob',
        () {
          final (:pairs, :fakeAkid) = plannerFixture();
          final plan = createSigv4Planner(pairs, null, eq);
          final s = shapes(fakeAkid);
          for (final kind in ['streaming', 'presigned', 'sigv4a']) {
            final (:method, :target, :headers) = s[kind]!;
            final decision = plan(method, target, headers, 's3.amazonaws.com');
            expect(_action(decision), 'deny');
            if (decision is Sigv4PlanDeny) {
              expect(decision.reason, contains(kind));
              expect(decision.reason, contains('credentials.sigv4.$kind'));
            }
          }
        },
      );

      test('passthrough forwards each shape un-resigned when configured', () {
        final (:pairs, :fakeAkid) = plannerFixture();
        final plan = createSigv4Planner(
          pairs,
          const Sigv4Config(
            streaming: 'passthrough',
            presigned: 'passthrough',
            sigv4a: 'passthrough',
          ),
          eq,
        );
        final s = shapes(fakeAkid);
        for (final kind in ['streaming', 'presigned', 'sigv4a']) {
          final (:method, :target, :headers) = s[kind]!;
          expect(plan(method, target, headers, 's3.amazonaws.com'), isNull);
        }
      });

      test('policies are independent per shape', () {
        final (:pairs, :fakeAkid) = plannerFixture();
        final plan = createSigv4Planner(
          pairs,
          const Sigv4Config(streaming: 'passthrough'),
          eq,
        );
        final s = shapes(fakeAkid);
        expect(
          plan(
            s['streaming']!.method,
            s['streaming']!.target,
            s['streaming']!.headers,
            's3.amazonaws.com',
          ),
          isNull,
        );
        expect(
          _action(
            plan(
              s['presigned']!.method,
              s['presigned']!.target,
              s['presigned']!.headers,
              's3.amazonaws.com',
            ),
          ),
          'deny',
        );
      });
    });
  });

  group('config validation for awsPairs and sigv4', () {
    final base = {
      'network': {
        'allowedDomains': ['s3.amazonaws.com'],
        'deniedDomains': [],
        'tlsTerminate': {
          'caCertPath': '/tmp/ca.crt',
          'caKeyPath': '/tmp/ca.key',
        },
      },
      'filesystem': {'denyRead': [], 'allowWrite': [], 'denyWrite': []},
    };

    test('a valid awsPairs + sigv4 config parses', () {
      final result = SandboxRuntimeConfigSchema.safeParse({
        ...base,
        'credentials': {
          'envVars': [
            {'name': 'MY_AKID', 'mode': 'mask'},
            {'name': 'MY_SECRET', 'mode': 'mask'},
          ],
          'awsPairs': [
            {'accessKeyIdVar': 'MY_AKID', 'secretAccessKeyVar': 'MY_SECRET'},
          ],
          'sigv4': {'streaming': 'passthrough'},
        },
      });
      expect(result.success, true);
    });

    test('a pair member must reference a masked envVars entry', () {
      final result = SandboxRuntimeConfigSchema.safeParse({
        ...base,
        'credentials': {
          'envVars': [
            {'name': 'MY_AKID', 'mode': 'mask'},
          ],
          'awsPairs': [
            {'accessKeyIdVar': 'MY_AKID', 'secretAccessKeyVar': 'MISSING_VAR'},
          ],
        },
      });
      expect(result.success, false);
      expect(_stringifyIssues(result), contains('MISSING_VAR'));
    });

    test('a mode "deny" entry is not a valid pair member', () {
      final result = SandboxRuntimeConfigSchema.safeParse({
        ...base,
        'credentials': {
          'envVars': [
            {'name': 'MY_AKID', 'mode': 'mask'},
            {'name': 'MY_SECRET', 'mode': 'deny'},
          ],
          'awsPairs': [
            {'accessKeyIdVar': 'MY_AKID', 'secretAccessKeyVar': 'MY_SECRET'},
          ],
        },
      });
      expect(result.success, false);
    });

    test('an extract/decode entry is not a valid pair member', () {
      final result = SandboxRuntimeConfigSchema.safeParse({
        ...base,
        'credentials': {
          'envVars': [
            {'name': 'MY_AKID', 'mode': 'mask', 'extract': '(AKIA\\w+)'},
            {'name': 'MY_SECRET', 'mode': 'mask'},
          ],
          'awsPairs': [
            {'accessKeyIdVar': 'MY_AKID', 'secretAccessKeyVar': 'MY_SECRET'},
          ],
        },
      });
      expect(result.success, false);
      expect(_stringifyIssues(result), contains('whole-value'));
    });

    test('a variable cannot belong to two pairs', () {
      final result = SandboxRuntimeConfigSchema.safeParse({
        ...base,
        'credentials': {
          'envVars': [
            {'name': 'A', 'mode': 'mask'},
            {'name': 'B', 'mode': 'mask'},
            {'name': 'C', 'mode': 'mask'},
          ],
          'awsPairs': [
            {'accessKeyIdVar': 'A', 'secretAccessKeyVar': 'B'},
            {'accessKeyIdVar': 'C', 'secretAccessKeyVar': 'B'},
          ],
        },
      });
      expect(result.success, false);
      expect(_stringifyIssues(result), contains('more than one'));
    });

    test('sigv4 rejects unknown policies and keys', () {
      expect(
        SandboxRuntimeConfigSchema.safeParse({
          ...base,
          'credentials': {
            'envVars': [
              {'name': 'X', 'mode': 'mask'},
            ],
            'sigv4': {'streaming': 'allow'},
          },
        }).success,
        false,
      );
      expect(
        SandboxRuntimeConfigSchema.safeParse({
          ...base,
          'credentials': {
            'envVars': [
              {'name': 'X', 'mode': 'mask'},
            ],
            'sigv4': {'headerSigv4': 'deny'},
          },
        }).success,
        false,
      );
    });
  });
}
