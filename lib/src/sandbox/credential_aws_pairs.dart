// STUB: pending port of src/sandbox/credential-aws-pairs.ts @ 24eb39e.
// ignore_for_file: constant_identifier_names, dangling_library_doc_comments, slash_for_doc_comments

import '../node/http.dart' show IncomingHttpHeaders;
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
  /** Insert or replace the pair keyed on its access-key-id sentinel. */
  void register(AwsCredentialPair pair) => throw UnimplementedError(
    'pending port of src/sandbox/credential-aws-pairs.ts',
  );

  /** Exact-match lookup by the fake access key id; never pattern-based. */
  AwsCredentialPair? lookup(String accessKeyIdSentinel) =>
      throw UnimplementedError(
        'pending port of src/sandbox/credential-aws-pairs.ts',
      );

  int get size => throw UnimplementedError(
    'pending port of src/sandbox/credential-aws-pairs.ts',
  );

  /** Drop every pair. Called on session teardown. */
  void clear() => throw UnimplementedError(
    'pending port of src/sandbox/credential-aws-pairs.ts',
  );
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
]) => throw UnimplementedError(
  'pending port of src/sandbox/credential-aws-pairs.ts',
);

/** Allowed values: `'deny'` | `'passthrough'`. */
typedef Sigv4Policy = String;

({Sigv4Policy streaming, Sigv4Policy presigned, Sigv4Policy sigv4a})
resolveSigv4Policies(Sigv4Config? config) => throw UnimplementedError(
  'pending port of src/sandbox/credential-aws-pairs.ts',
);

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
  const Sigv4PlanResign({required this.payloadHash});

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
  ) => throw UnimplementedError(
    'pending port of src/sandbox/credential-aws-pairs.ts',
  );
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
) => throw UnimplementedError(
  'pending port of src/sandbox/credential-aws-pairs.ts',
);
