// Ported from sandbox-runtime test/sandbox/credential-decode.test.ts @ 0bbebed.
// ignore_for_file: constant_identifier_names, non_constant_identifier_names, no_leading_underscores_for_local_identifiers, slash_for_doc_comments

import 'dart:convert';

import 'package:test/test.dart';

import 'package:sandbox_runtime/src/node/buffer.dart' show Buffer;
import 'package:sandbox_runtime/src/sandbox/credential_decode.dart';
import 'package:sandbox_runtime/src/sandbox/credential_sentinel.dart'
    show SentinelRegistry, SENTINEL_PREFIX;

/** base64url-encode a string, as test-fixture shorthand. */
String b64u(String s) {
  return Buffer.from(s, 'utf8').toString('base64url');
}

// The classic HS256 example token (header {"alg":"HS256","typ":"JWT"}).
const REAL_JWT =
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.'
    'eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.'
    'SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';

void main() {
  group('JWT_DEFAULT_EXTRACT_PATTERN', () {
    test('captures a whole JWT as group 1', () {
      final content = '{"access_token": "$REAL_JWT", "expires": 9}';
      final m = RegExp(JWT_DEFAULT_EXTRACT_PATTERN).firstMatch(content);
      expect(m, isNotNull);
      expect(m![1], REAL_JWT);
    });

    test('does not match a two-segment or non-eyJ string', () {
      final re = RegExp(JWT_DEFAULT_EXTRACT_PATTERN);
      expect(re.hasMatch('abc.def.ghi'), isFalse);
      expect(re.hasMatch('eyJhbGci.eyJzdWIi'), isFalse);
    });
  });

  group('verifyJwt', () {
    test('a real JWT passes', () {
      expect(verifyJwt(REAL_JWT), true);
    });

    test('a random base64 blob fails (no segments)', () {
      expect(verifyJwt(b64u('this is not a jwt')), false);
    });

    test('a two-segment candidate fails', () {
      final [h, p, ...] = REAL_JWT.split('.');
      expect(verifyJwt('$h.$p'), false);
    });

    test('a four-segment candidate fails', () {
      expect(verifyJwt('$REAL_JWT.extra'), false);
    });

    test('a non-JSON header fails', () {
      // Decodes to `{"oops` — truncated JSON, parse error.
      expect(verifyJwt('${b64u('{"oops')}.${b64u('{}')}.c2ln'), false);
    });

    test('a JSON header without an alg property fails', () {
      expect(
        verifyJwt('${b64u('{"typ":"JWT"}')}.${b64u('{"sub":"x"}')}.c2ln'),
        false,
      );
    });

    test('a non-JSON payload fails', () {
      expect(
        verifyJwt('${b64u('{"alg":"HS256"}')}.${b64u('not json')}.c2ln'),
        false,
      );
    });
  });

  group('mintFakeJwt', () {
    test('deterministic given the uuid', () {
      expect(mintFakeJwt('u-1'), mintFakeJwt('u-1'));
      expect(mintFakeJwt('u-1'), isNot(mintFakeJwt('u-2')));
    });

    test('mints a structurally valid JWT', () {
      expect(verifyJwt(mintFakeJwt('u')), true);
    });

    test('header is exactly {"alg":"HS256","typ":"JWT"} — never alg:none', () {
      // alg:none tokens are accepted by misconfigured validators; an HS256
      // header forces signature verification, which the garbage signature
      // always fails — so an unswapped fake is rejected by every validator.
      final header =
          jsonDecode(
                Buffer.from(
                  mintFakeJwt('u').split('.')[0],
                  'base64url',
                ).toString('utf8'),
              )
              as Map<String, Object?>;
      expect(header, {'alg': 'HS256', 'typ': 'JWT'});
    });

    test('signature segment is the fixed filler', () {
      expect(mintFakeJwt('u').split('.')[2], 'c3J0LWZha2U');
    });

    test(
      'payload carries the sentinel identity and a fixed far-future exp',
      () {
        final payload =
            jsonDecode(
                  Buffer.from(
                    mintFakeJwt('abc').split('.')[1],
                    'base64url',
                  ).toString('utf8'),
                )
                as Map<String, Object?>;
        expect(payload['sub'], '${SENTINEL_PREFIX}abc');
        expect(payload['exp'], 9999999999);
      },
    );

    test('the minted fake matches the default extraction pattern', () {
      // A re-run over an already-masked file must still see the fake as a
      // JWT candidate (idempotent registry handles re-registration).
      expect(
        mintFakeJwt('u'),
        matches(RegExp('^$JWT_DEFAULT_EXTRACT_PATTERN\$')),
      );
    });
  });

  group('maskJwtClaims', () {
    // Header with a kid, so header reuse is observable (mintFakeJwt's
    // header has no kid).
    final HEADER = b64u('{"alg":"RS256","typ":"JWT","kid":"key-7"}');
    final PAYLOAD = <String, Object?>{
      'sub': 'user-1',
      'api_key': 'real-secret',
      'aud': 'https://api.example.com',
      'n': 42,
      'naïve': 'café', // non-ASCII survives JSON.stringify re-encoding
    };
    final TOKEN = '$HEADER.${b64u(jsonEncode(PAYLOAD))}.cmVhbC1zaWc';

    String sentinelFor(String claim, String _real) => 'fake_value_$claim';

    test('the named claim is replaced; every other claim decodes verbatim', () {
      final result = maskJwtClaims(TOKEN, ['api_key'], sentinelFor);
      expect(result, isNotNull);
      final payload =
          jsonDecode(
                Buffer.from(
                  result!.fakeToken.split('.')[1],
                  'base64url',
                ).toString('utf8'),
              )
              as Map<String, Object?>;
      expect(payload, {...PAYLOAD, 'api_key': 'fake_value_api_key'});
      expect(result.claimSentinels, {'api_key': 'fake_value_api_key'});
      expect(result.fakeToken, isNot(contains(b64u(jsonEncode(PAYLOAD)))));
    });

    test('the header segment is reused byte-identical', () {
      final result = maskJwtClaims(TOKEN, ['api_key'], sentinelFor);
      expect(result!.fakeToken.split('.')[0], HEADER);
    });

    test('the signature is the fixed filler, never the real signature', () {
      // The real signature over a modified payload would give the sandbox
      // a public-key brute-force oracle for a low-entropy masked claim.
      final result = maskJwtClaims(TOKEN, ['api_key'], sentinelFor);
      expect(result!.fakeToken.split('.')[2], 'c3J0LWZha2U');
      expect(result.fakeToken.split('.')[2], mintFakeJwt('u').split('.')[2]);
    });

    test('the rebuilt token still verifies as a JWT', () {
      // A re-run over an already-masked file must see the fake as a
      // candidate again (idempotent registry handles re-registration).
      expect(
        verifyJwt(maskJwtClaims(TOKEN, ['api_key'], sentinelFor)!.fakeToken),
        true,
      );
    });

    test('an absent claim is skipped; present ones still mask', () {
      final result = maskJwtClaims(TOKEN, ['nope', 'api_key'], sentinelFor);
      expect(result, isNotNull);
      expect([...result!.claimSentinels.keys], ['api_key']);
    });

    test('a non-string claim is skipped; present ones still mask', () {
      final result = maskJwtClaims(TOKEN, ['n', 'api_key'], sentinelFor);
      expect(result, isNotNull);
      expect([...result!.claimSentinels.keys], ['api_key']);
      final payload =
          jsonDecode(
                Buffer.from(
                  result.fakeToken.split('.')[1],
                  'base64url',
                ).toString('utf8'),
              )
              as Map<String, Object?>;
      expect(payload['n'], 42);
    });

    test('no named claim matching → null, sentinelFor never invoked', () {
      var calls = 0;
      String counting(String claim, String _) {
        calls++;
        return 'fake_value_$claim';
      }

      expect(maskJwtClaims(TOKEN, ['nope', 'n'], counting), isNull);
      expect(calls, 0);
    });

    test('a non-object JSON payload → null', () {
      // verifyJwt only requires the payload to parse as JSON — a scalar or
      // array payload has no claims to mask.
      final scalar = '$HEADER.${b64u('"just-a-string"')}.c2ln';
      final array = '$HEADER.${b64u('["a","b"]')}.c2ln';
      expect(maskJwtClaims(scalar, ['api_key'], sentinelFor), isNull);
      expect(maskJwtClaims(array, ['api_key'], sentinelFor), isNull);
    });

    test('deterministic given the sentinels', () {
      expect(
        maskJwtClaims(TOKEN, ['api_key'], sentinelFor)!.fakeToken,
        maskJwtClaims(TOKEN, ['api_key'], sentinelFor)!.fakeToken,
      );
    });
  });

  group('SentinelRegistry.registerWithSentinel', () {
    bool eq(String h, String p) => h == p;

    test('roundtrip: JWT-shaped sentinel maps back to the real JWT', () {
      final reg = SentinelRegistry();
      final fake = mintFakeJwt('u');
      final got = reg.registerWithSentinel('cred', fake, REAL_JWT, [
        'api.x.com',
      ]);
      expect(got, fake);
      expect(reg.lookupReal(fake), REAL_JWT);
    });

    test(
      'substituteInHeaders swaps a sentinel that lacks the fake_value_ prefix',
      () {
        // The JWT fake does not contain the literal SENTINEL_PREFIX (it is
        // base64url-encoded inside the payload), so this exercises the
        // disabled fast path in substituteInString.
        final reg = SentinelRegistry();
        final fake = mintFakeJwt('u');
        expect(fake, isNot(contains(SENTINEL_PREFIX)));
        reg.registerWithSentinel('cred', fake, REAL_JWT, ['api.x.com']);

        final headers = <String, Object?>{'authorization': 'Bearer $fake'};
        reg.substituteInHeaders(headers, 'api.x.com', eq);
        expect(headers['authorization'], 'Bearer $REAL_JWT');
      },
    );

    test('a JWT sentinel does not substitute at a non-injectHost', () {
      final reg = SentinelRegistry();
      final fake = mintFakeJwt('u');
      reg.registerWithSentinel('cred', fake, REAL_JWT, ['api.x.com']);

      final headers = <String, Object?>{'authorization': 'Bearer $fake'};
      reg.substituteInHeaders(headers, 'evil.example.com', eq);
      expect(headers['authorization'], 'Bearer $fake');
    });

    test(
      'idempotent on name: repeat call keeps the first sentinel, updates the value',
      () {
        final reg = SentinelRegistry();
        final first = reg.registerWithSentinel(
          'n',
          mintFakeJwt('a'),
          'real-1',
          [],
        );
        final second = reg.registerWithSentinel(
          'n',
          mintFakeJwt('b'),
          'real-2',
          [],
        );
        expect(second, first);
        expect(reg.lookupReal(first), 'real-2');
        expect(reg.size, 1);
      },
    );

    test(
      'prefixed register() fast path still works alongside JWT sentinels',
      () {
        final reg = SentinelRegistry();
        final plain = reg.register('env', 'real-plain', ['api.x.com']);
        reg.registerWithSentinel('jwt', mintFakeJwt('u'), REAL_JWT, [
          'api.x.com',
        ]);

        final headers = <String, Object?>{'x-api-key': plain};
        reg.substituteInHeaders(headers, 'api.x.com', eq);
        expect(headers['x-api-key'], 'real-plain');
      },
    );

    test('clear() restores the fast path state', () {
      final reg = SentinelRegistry();
      reg.registerWithSentinel('jwt', mintFakeJwt('u'), REAL_JWT, [
        'api.x.com',
      ]);
      reg.clear();
      expect(reg.size, 0);
      // After clear, a fresh prefixed credential still substitutes.
      final plain = reg.register('env', 'real-plain', ['api.x.com']);
      final headers = <String, Object?>{'authorization': plain};
      reg.substituteInHeaders(headers, 'api.x.com', eq);
      expect(headers['authorization'], 'real-plain');
    });
  });
}
