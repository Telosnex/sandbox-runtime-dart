// Ported from sandbox-runtime src/sandbox/credential-aws-pairs.ts @ 24eb39e.
// ignore_for_file: constant_identifier_names, dangling_library_doc_comments, slash_for_doc_comments, prefer_interpolation_to_compose_strings, library_private_types_in_public_api

import '../node/console.dart' as console;
import '../node/http.dart' show IncomingHttpHeaders;
import '../node/process.dart' as process;
import '../utils/debug.dart' show logForDebugging;
import 'aws_sigv4.dart'
    show
        Sigv4SignInput,
        UNSIGNED_PAYLOAD,
        detectSigv4,
        parseSigv4Authorization,
        signSigv4,
        singleHeader;
import 'credential_sentinel.dart' show HostMatcher;
import 'sandbox_config.dart'
    show AwsPairConfig, CredentialEnvVarConfig, Sigv4Config;

/**
 * Linked AWS credential pairs for SigV4 re-signing.
 *
 * The sentinel registry maps independent name→value fakes, but SigV4
 * needs the access key id, secret access key, and optional session token
 * linked as ONE credential: the signature is an HMAC derived from the
 * secret, so a request signed with the fake secret must be re-signed with
 * the real one — and the only reliable trigger is the fake access key id
 * appearing in the signature's credential scope.
 *
 * Pairs come from two sources (see {@link registerAwsPairs}):
 * - an explicit `credentials.awsPairs` grouping, for non-standard
 *   variable names;
 * - auto-detection of the conventional AWS_ACCESS_KEY_ID /
 *   AWS_SECRET_ACCESS_KEY / AWS_SESSION_TOKEN trio when those vars are
 *   masked whole-value — the names the AWS SDKs and CLI actually read, so
 *   masking them is the opt-in.
 *
 * {@link createSigv4Planner} builds the per-request hook the
 * TLS-terminating proxy runs: exact-match the referenced access key id
 * against registered pair sentinels, classify the signature shape, and
 * either plan a re-sign (header-sigv4) or apply the configured
 * deny/passthrough policy (streaming, presigned, sigv4a).
 */

/** Conventional env var names the AWS SDKs and CLI read credentials from. */
const String AWS_ACCESS_KEY_ID_VAR = 'AWS_ACCESS_KEY_ID';
const String AWS_SECRET_ACCESS_KEY_VAR = 'AWS_SECRET_ACCESS_KEY';
const String AWS_SESSION_TOKEN_VAR = 'AWS_SESSION_TOKEN';

class AwsCredentialPair {
  const AwsCredentialPair({
    required this.accessKeyIdSentinel,
    required this.realAccessKeyId,
    required this.realSecretAccessKey,
    this.realSessionToken,
    required this.injectHosts,
  });

  /** The fake access key id the sandboxed process holds (the sentinel). */
  final String accessKeyIdSentinel;

  final String realAccessKeyId;

  final String realSecretAccessKey;

  final String? realSessionToken;

  /**
   * Hosts where the pair may be injected — the access-key-id entry's
   * effective injectHosts. Requests to other hosts keep the fake
   * signature untouched, same as ordinary sentinel substitution.
   */
  final List<String> injectHosts;
}

/**
 * AWS pairs for one sandbox session, keyed by the access-key-id sentinel.
 * Like the sentinel registry, it lives only in process memory — never
 * written to disk, never logged.
 */
class AwsPairRegistry {
  final Map<String, AwsCredentialPair> _bySentinel = {};

  /** Insert or replace the pair keyed on its access-key-id sentinel. */
  void register(AwsCredentialPair pair) {
    _bySentinel[pair.accessKeyIdSentinel] = pair;
  }

  /** Exact-match lookup by the fake access key id; never pattern-based. */
  AwsCredentialPair? lookup(String accessKeyIdSentinel) {
    return _bySentinel[accessKeyIdSentinel];
  }

  int get size {
    return _bySentinel.length;
  }

  /** Drop every pair. Called on session teardown. */
  void clear() {
    _bySentinel.clear();
  }
}

/**
 * Register AWS credential pairs from the masked env vars.
 *
 * Runs after `buildMaskedEnvVars`: `setEnvVars` maps each masked variable
 * to its fake in-sandbox value, which for whole-value masking IS the
 * sentinel. Pair specs are the explicit `credentials.awsPairs` entries
 * plus — when none of them claims a conventional name — an implicit
 * AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / AWS_SESSION_TOKEN spec.
 *
 * A spec registers only when both the access-key-id and secret variables
 * were actually masked (present in the host env, whole-value entries in
 * `setEnvVars`); the session token joins the pair when its variable was
 * masked too. A partially available spec is skipped — with one loud
 * warning for the dangerous half-masking: a masked secret without a
 * masked access key id means SigV4 requests carry a real key id (so
 * nothing triggers re-signing) over a fake-secret signature that can
 * never verify.
 */
void registerAwsPairs(
  List<CredentialEnvVarConfig> envVars,
  List<AwsPairConfig>? awsPairs,
  List<String> allowedDomains,
  Map<String, String> setEnvVars,
  AwsPairRegistry registry, [
  Map<String, String?>? env,
]) {
  env ??= process.env;
  final specs = <AwsPairConfig>[...(awsPairs ?? [])];
  final explicitNames = Set<String>.of(
    specs.expand(
      (p) => [
        p.accessKeyIdVar,
        p.secretAccessKeyVar,
        ...(p.sessionTokenVar != null && p.sessionTokenVar!.isNotEmpty
            ? [p.sessionTokenVar!]
            : <String>[]),
      ],
    ),
  );
  final conventional = [
    AWS_ACCESS_KEY_ID_VAR,
    AWS_SECRET_ACCESS_KEY_VAR,
    AWS_SESSION_TOKEN_VAR,
  ];
  if (!conventional.any((n) => explicitNames.contains(n))) {
    specs.add(
      const AwsPairConfig(
        accessKeyIdVar: AWS_ACCESS_KEY_ID_VAR,
        secretAccessKeyVar: AWS_SECRET_ACCESS_KEY_VAR,
        sessionTokenVar: AWS_SESSION_TOKEN_VAR,
      ),
    );
  }

  // A variable is usable as a pair member when it has a whole-value
  // mask entry AND was actually masked at runtime (set in the host env).
  CredentialEnvVarConfig? wholeValueEntry(String name) => envVars
      .where(
        (v) =>
            v.name == name &&
            v.mode == 'mask' &&
            v.extract == null &&
            v.decode == null,
      )
      .firstOrNull;
  String? maskedSentinel(String name) =>
      wholeValueEntry(name) != null ? setEnvVars[name] : null;

  for (final spec in specs) {
    final akidSentinel = maskedSentinel(spec.accessKeyIdVar);
    final secretMasked = maskedSentinel(spec.secretAccessKeyVar) != null;
    final realAkid = env[spec.accessKeyIdVar];
    final realSecret = env[spec.secretAccessKeyVar];
    if (akidSentinel == null ||
        !secretMasked ||
        realAkid == null ||
        realSecret == null) {
      if (secretMasked && akidSentinel == null) {
        final msg =
            '[sandbox-runtime] WARNING: "${spec.secretAccessKeyVar}" is '
            'masked but "${spec.accessKeyIdVar}" is not, so no AWS '
            'credential pair was registered. SigV4 requests will be signed '
            'with the masked placeholder secret and the proxy cannot '
            'detect or re-sign them — they will fail upstream. Mask both '
            'variables (whole-value) to enable re-signing.';
        console.warn(msg);
        logForDebugging(msg, level: 'warn');
      }
      continue;
    }

    final akidEntry = wholeValueEntry(spec.accessKeyIdVar)!;
    final sessionSentinel = spec.sessionTokenVar != null
        ? maskedSentinel(spec.sessionTokenVar!)
        : null;
    final realSessionToken =
        sessionSentinel != null && spec.sessionTokenVar != null
        ? env[spec.sessionTokenVar!]
        : null;

    registry.register(
      AwsCredentialPair(
        accessKeyIdSentinel: akidSentinel,
        realAccessKeyId: realAkid,
        realSecretAccessKey: realSecret,
        realSessionToken: realSessionToken,
        injectHosts: akidEntry.injectHosts ?? allowedDomains,
      ),
    );
    logForDebugging(
      '[credential-aws] registered SigV4 pair for '
              '${spec.accessKeyIdVar}/${spec.secretAccessKeyVar}' +
          (realSessionToken != null ? ' (+session token)' : ''),
    );
  }
}

/** Allowed values: `'deny'` | `'passthrough'`. */
typedef Sigv4Policy = String;

typedef _Sigv4Policies = ({
  Sigv4Policy streaming,
  Sigv4Policy presigned,
  Sigv4Policy sigv4a,
});

_Sigv4Policies resolveSigv4Policies(Sigv4Config? config) {
  return (
    streaming: config?.streaming ?? 'deny',
    presigned: config?.presigned ?? 'deny',
    sigv4a: config?.sigv4a ?? 'deny',
  );
}

/**
 * Decision for one request, produced before header substitution runs.
 */
sealed class Sigv4Plan {
  const Sigv4Plan();
}

class Sigv4PlanDeny extends Sigv4Plan {
  const Sigv4PlanDeny({required this.reason});

  final String action = 'deny';

  final String reason;
}

class Sigv4PlanResign extends Sigv4Plan {
  // Dart: upstream's object-literal `apply` method arrives as a closure.
  Sigv4PlanResign({
    required this.payloadHash,
    required void Function(
      IncomingHttpHeaders headers,
      String hostHeader,
      String payloadHash,
    )
    apply,
  }) : _apply = apply;

  final void Function(
    IncomingHttpHeaders headers,
    String hostHeader,
    String payloadHash,
  )
  _apply;

  final String action = 'resign';

  /**
   * Payload hash to sign. `undefined` means the client signed a
   * literal body hash (or none): the caller must buffer the body,
   * SHA-256 it, and pass the hex digest to `apply` — the hash must
   * cover the bytes actually sent upstream.
   */
  final String? payloadHash;

  /**
   * Mutate the outgoing (post-substitution) headers in place:
   * replace Authorization with the real-credential signature, pin
   * x-amz-content-sha256 to the signed hash, and inject the real
   * session token when the pair carries one.
   */
  void apply(
    IncomingHttpHeaders headers,
    String hostHeader,
    String payloadHash,
  ) {
    _apply(headers, hostHeader, payloadHash);
  }
}

/**
 * Per-request SigV4 hook for the TLS-terminating proxy. Returns
 * `undefined` when the request is not the re-signer's to handle (no
 * SigV4 signature, unknown/real access key id, destination outside the
 * pair's injectHosts, or a passthrough policy) — the proxy then forwards
 * it exactly as before this feature existed.
 *
 * Must be called with the ORIGINAL client headers, before sentinel
 * substitution: detection matches the fake access key id, which
 * substitution would have already replaced.
 */
typedef PlanSigv4 =
    Sigv4Plan? Function(
      String method,
      String requestTarget,
      IncomingHttpHeaders headers,
      String destHost,
    );

/**
 * Build the {@link PlanSigv4} hook from the session's pair registry and
 * configured policies. `matches` is the same host matcher used for
 * sentinel substitution, so injectHosts gating is consistent across both.
 */
PlanSigv4 createSigv4Planner(
  AwsPairRegistry registry,
  Sigv4Config? config,
  HostMatcher matches,
) {
  final policies = resolveSigv4Policies(config);
  return (method, requestTarget, headers, destHost) {
    if (registry.size == 0) return null;
    final detected = detectSigv4(headers, requestTarget);
    if (detected == null) return null;
    final pair = registry.lookup(detected.accessKeyId);
    // Unknown key id — including a real, unmasked AWS credential — is
    // never rewritten and never denied.
    if (pair == null) return null;
    if (!pair.injectHosts.any((p) => matches(destHost, p))) return null;

    if (detected.kind != 'header-sigv4') {
      // Dart: records are not indexable; `policies[detected.kind]` by switch.
      final policy = switch (detected.kind) {
        'streaming' => policies.streaming,
        'presigned' => policies.presigned,
        'sigv4a' => policies.sigv4a,
        _ => null,
      };
      if (policy == 'passthrough') {
        logForDebugging(
          '[credential-aws] ${detected.kind} request with masked '
          'credential passed through un-resigned per '
          'credentials.sigv4.${detected.kind} (its signature covers '
          'the placeholder secret and will fail upstream)',
        );
        return null;
      }
      return Sigv4PlanDeny(
        reason:
            'AWS SigV4 ${detected.kind} request uses a masked credential '
            'but cannot be re-signed by the sandbox proxy; denied by '
            'policy. Set credentials.sigv4.${detected.kind} to '
            '"passthrough" to forward it unmodified (it will fail '
            'upstream: the signature covers the masked placeholder).',
      );
    }

    final auth = parseSigv4Authorization(
      singleHeader(headers['authorization'])!,
    );
    if (auth == null) {
      return const Sigv4PlanDeny(
        reason:
            'AWS SigV4 request uses a masked credential but its '
            'Authorization header is malformed; the proxy cannot re-sign it.',
      );
    }
    final amzDate = singleHeader(headers['x-amz-date']);
    if (amzDate == null) {
      return const Sigv4PlanDeny(
        reason:
            'AWS SigV4 request uses a masked credential but carries no '
            'x-amz-date header; the proxy cannot re-sign it.',
      );
    }
    // Presence check now so apply() cannot fail after the body was
    // consumed. host is synthesized; a session token the pair carries
    // is injected by apply().
    final signedHeaders = [...auth.signedHeaders];
    for (final name in signedHeaders) {
      if (name == 'host') continue;
      if (name == 'x-amz-security-token' && pair.realSessionToken != null) {
        continue;
      }
      if (headers[name] == null) {
        return Sigv4PlanDeny(
          reason:
              'AWS SigV4 request uses a masked credential but signed '
              'header "$name" is missing; the proxy cannot re-sign it.',
        );
      }
    }
    if (pair.realSessionToken != null &&
        !signedHeaders.contains('x-amz-security-token')) {
      signedHeaders.add('x-amz-security-token');
    }

    final contentSha = singleHeader(headers['x-amz-content-sha256']);
    return Sigv4PlanResign(
      payloadHash: contentSha == UNSIGNED_PAYLOAD ? UNSIGNED_PAYLOAD : null,
      apply: (fwdHeaders, hostHeader, payloadHash) {
        if (pair.realSessionToken != null) {
          fwdHeaders['x-amz-security-token'] = pair.realSessionToken;
        }
        if (fwdHeaders['x-amz-content-sha256'] != null &&
            contentSha != UNSIGNED_PAYLOAD) {
          // The recomputed hash is authoritative: the signature must
          // cover the bytes forwarded upstream, not the client's claim.
          fwdHeaders['x-amz-content-sha256'] = payloadHash;
        }
        final authorization = signSigv4(
          Sigv4SignInput(
            method: method,
            requestTarget: requestTarget,
            headers: fwdHeaders,
            hostHeader: hostHeader,
            signedHeaders: signedHeaders,
            payloadHash: payloadHash,
            amzDate: amzDate,
            scope: (
              date: auth.date,
              region: auth.region,
              service: auth.service,
            ),
            accessKeyId: pair.realAccessKeyId,
            secretAccessKey: pair.realSecretAccessKey,
          ),
        ).authorization;
        fwdHeaders['authorization'] = authorization;
      },
    );
  };
}
