// Ported from sandbox-runtime src/sandbox/credential-mask-files.ts @ 24eb39e.
// ignore_for_file: constant_identifier_names, dangling_library_doc_comments, slash_for_doc_comments

import 'dart:convert';
import 'dart:typed_data';

import 'package:path/path.dart' show join;

import '../node/buffer.dart' show Buffer;
import '../node/console.dart' as console;
import '../node/crypto.dart' show randomUUID;
import '../node/errno.dart' show NodeException;
import '../node/fs.dart' as fs;
import '../node/os.dart' show tmpdir;
import '../utils/debug.dart' show logForDebugging;
import 'credential_extract.dart' show extractAndSubstitute;
import 'sandbox_utils.dart' show normalizePathForSandbox;
import 'credential_decode.dart'
    show JWT_DEFAULT_EXTRACT_PATTERN, maskJwtClaims, mintFakeJwt, verifyJwt;
import 'sandbox_config.dart' show CredentialFileConfig;
import 'credential_sentinel.dart' show SentinelRegistry;

/**
 * Credential file masking (Linux).
 *
 * For a `credentials.files` entry with `mode: "mask"`, srt reads the real
 * file content on the host, registers one or more sentinels in the
 * {@link SentinelRegistry}, and writes a fake file (sentinel-substituted)
 * to a manager-owned temp directory. The Linux sandbox then `--ro-bind`s
 * the fake over the real path, so the sandboxed process reads the
 * sentinel(s). The proxy substitution from env-var masking already scans
 * every header for any registered sentinel, so a tool that
 * does `Authorization: Bearer $(cat <maskedFile>)` reaches the upstream with
 * the real bytes — no proxy changes required.
 *
 * Without `extract`, masking is **whole-file**: one sentinel replaces the
 * entire content. With `extract`, masking is **structured**: a regex picks
 * out the credential value(s) and only those spans are replaced, so a tool
 * that parses the file (JSON/YAML/.netrc) still sees valid syntax. See
 * {@link extractAndSubstitute} and {@link CredentialFileConfigSchema}.
 *
 * On macOS, SBPL cannot redirect reads, so masked files degrade to
 * `mode: "deny"` (see macos-sandbox-utils.ts). On Windows an ACL cannot
 * either (see `windowsMaskedFileDenies` in sandbox-manager.ts).
 */

/**
 * Sentinel-registry key prefix for masked files. Keeps file keys disjoint
 * from env-var names so a credential file at path `GH_TOKEN` cannot collide
 * with the env var `GH_TOKEN`.
 */
const String _FILE_KEY_PREFIX = 'file:';

/** One masked file's bind mapping for the platform builder. */
class MaskedFileBind {
  const MaskedFileBind({required this.realPath, required this.fakePath});

  /** Resolved (tilde-expanded, realpath'd) host path of the real file. */
  final String realPath;

  /** Path to the fake file containing the sentinel. */
  final String fakePath;
}

/**
 * Manager-owned temp dir holding the fake files.
 *
 * INVARIANT: this directory must never be writable from inside the sandbox.
 * The Linux layer enforces this by emitting `--ro-bind <dirPath> <dirPath>`
 * after every other filesystem mount (see generateFilesystemArgs), so the
 * store stays read-only even if a caller's allowWrite covers os.tmpdir() or
 * the host's $TMPDIR points under a default-writable path. If the sandbox
 * could write here it could replace a fake's content (the bind exposes the
 * source file) or plant a symlink for a later host-side write() to follow.
 */
class MaskedFileStore {
  String? _dir;
  final Map<String, String> _byKey = {};

  /**
   * Write `sentinel` to a fake file for `key` and return its path.
   * Idempotent on `key`: a repeat call rewrites the same fake (so a
   * changed sentinel after re-register propagates) instead of leaking a
   * new file per wrapWithSandbox() call.
   */
  String write(String key, String sentinel) {
    _dir ??= fs.mkdtempSync(join(tmpdir(), 'srt-credmask-'));
    var fakePath = _byKey[key];
    if (fakePath == null) {
      fakePath = join(_dir!, '${_byKey.length}.fake');
      _byKey[key] = fakePath;
    }
    // Never follow a symlink at fakePath: a prior sandbox invocation may
    // have planted one (the store dir is ro-bound now, but defence in
    // depth). Unlink first so writeFileSync creates a fresh regular file.
    fs.rmSync(fakePath, {'force': true});
    // 0600: owner rw so the idempotent rewrite above succeeds; the bind
    // into the sandbox is --ro-bind so the sandboxed process sees it
    // read-only regardless of the host mode. No group/other.
    fs.writeFileSync(fakePath, sentinel, {'mode': 384 /* 0o600 */});
    return fakePath;
  }

  /** Remove the temp dir and every fake file in it. Idempotent. */
  void dispose() {
    if (_dir != null) {
      try {
        fs.rmSync(_dir!, {'recursive': true, 'force': true});
      } catch (err) {
        logForDebugging('MaskedFileStore cleanup failed: $err', level: 'error');
      }
    }
    _dir = null;
    _byKey.clear();
  }

  /** Temp dir path, or undefined if no fake has been written yet. */
  String? get dirPath {
    return _dir;
  }
}

/** Result of {@link buildMaskedFileBinds}. */
class MaskedFileBuildResult {
  const MaskedFileBuildResult({
    required this.binds,
    required this.degradeToDenyPaths,
  });

  final List<MaskedFileBind> binds;

  /**
   * Resolved paths of `mode: "mask"` entries that degraded to deny at
   * runtime — populated when `extract` matches nothing (or, with
   * `decode`, no candidate verifies) and the entry's `onExtractNoMatch`
   * is `"deny"`. Callers union these into the read-deny set so the
   * credential file is unreadable rather than exposed.
   */
  final List<String> degradeToDenyPaths;
}

/**
 * For each `mode: "mask"` file entry: resolve the path, read the real
 * content, build the fake content (whole-file or structured per `extract`),
 * register sentinels in `registry`, write the fake via `store`, and return
 * the bind list plus any entries that degraded to deny.
 *
 * Whole-file mode (no `extract`): one sentinel keyed `file:<path>` whose
 * real value is the entire file content; the fake file *is* the sentinel.
 *
 * Structured mode (`extract` and/or `decode` set): one sentinel per
 * distinct captured value, keyed `file:<path>#<i>`; the fake file is the
 * real content with each captured span replaced by its sentinel. With
 * `decode: "jwt"`, candidates come from the explicit `extract` pattern or
 * the built-in JWT pattern, each candidate must pass {@link verifyJwt}
 * before it is masked (failed candidates are left untouched), and the
 * sentinel is a JWT-shaped fake ({@link mintFakeJwt}) registered via
 * `registerWithSentinel`. With `maskClaims`, masking goes one level
 * deeper: each named top-level payload claim present with a string value
 * gets its own sentinel and the token is rebuilt around the modified
 * payload ({@link maskJwtClaims}); BOTH mappings are registered — the
 * whole fake token → the whole real token (a tool sending the token as a
 * bearer credential) and each claim sentinel → the real claim value (a
 * tool extracting the claim and sending it alone) — under the same
 * injectHosts. Named claims absent or non-string in a token are skipped
 * with a debug log (portable-config posture, like a missing file). If the
 * regex matches nothing — or, with decode, no candidate verifies, or with
 * `maskClaims`, no named claim matches in any verified token — the
 * entry's `onExtractNoMatch` decides:
 * - `"warn"` (default): skip the entry with a loud stderr warning —
 *   fail-open, the file stays readable via the root mount;
 * - `"deny"`: push the path to `degradeToDenyPaths` — fail-closed, the
 *   file becomes unreadable inside the sandbox;
 * - `"error"`: throw, so nothing runs until the config is fixed.
 * With `maskDuplicates`, verbatim occurrences of each captured value
 * outside the matched spans are also replaced (see {@link ExtractOptions}).
 * Composed with `decode`, the duplicate pass covers only captures that
 * passed verification — a duplicate is the same value, so it inherits the
 * verified capture's sentinel without re-verification; unverified
 * candidates (left untouched by the decode gate) never mask duplicates.
 *
 * Entries whose path does not exist, is unreadable, or resolves to a
 * directory are skipped with a debug log — same posture as a masked env
 * var that's unset on the host: nothing to protect, and surfacing a hard
 * error would make a portable config brittle across machines.
 *
 * The directory check is the authoritative one (the schema only catches a
 * trailing slash); whole-file masking has no meaning for a directory.
 */
MaskedFileBuildResult buildMaskedFileBinds(
  List<CredentialFileConfig> files,
  List<String> allowedDomains,
  SentinelRegistry registry,
  MaskedFileStore store,
) {
  final binds = <MaskedFileBind>[];
  final degradeToDenyPaths = <String>[];
  for (final f in files) {
    if (f.mode != 'mask') continue;
    // Literal: this path is stat'd, read and (on Linux) bound over, so it
    // is the name of one file however it is spelled — a `[` in it is part
    // of that name, not a character class.
    final realPath = normalizePathForSandbox(f.path, literal: true);

    String content;
    try {
      final stat = fs.statSync(realPath);
      if (stat.isDirectory()) {
        logForDebugging(
          '[credential-mask] Skipping masked file entry that resolves to '
          'a directory: ${f.path} — use mode "deny" for directories.',
          level: 'warn',
        );
        continue;
      }
      // Read as bytes first: a utf8 read silently maps invalid sequences
      // to U+FFFD, so the sentinel would round-trip to corrupted bytes at
      // the proxy. Masking (whole-file or extract) is for text credential
      // files; reject binary.
      final raw = fs.readFileSync(realPath) as Uint8List;
      content = Buffer.from(raw).toString('utf8');
      if (Buffer.byteLength(content) != raw.length) {
        logForDebugging(
          '[credential-mask] Skipping masked file with non-UTF-8 content '
          '(binary credential files are not supported in mask mode): '
          '${f.path}',
          level: 'warn',
        );
        continue;
      }
    } catch (err) {
      logForDebugging(
        '[credential-mask] Skipping masked file (unreadable on host): '
        '${f.path} — ${err is NodeException ? err.message : err}',
      );
      continue;
    }

    final injectHosts = f.injectHosts ?? allowedDomains;
    final key = _FILE_KEY_PREFIX + realPath;

    String fakeContent;
    if (f.extract == null && f.decode == null) {
      // Whole-file: one sentinel for the entire content.
      fakeContent = registry.register(key, content, injectHosts);
    } else {
      // An explicit extract pattern wins; decode without one falls back to
      // the built-in JWT pattern so authors don't hand-write it.
      final pattern = f.extract ?? JWT_DEFAULT_EXTRACT_PATTERN;
      var maskedCount = 0;
      final extracted = extractAndSubstitute(content, pattern, (cap, i) {
        // Decode-verification: a regex match that is not actually a JWT
        // (the default pattern over-matches by design) is left untouched —
        // returning the capture replaces the span with itself.
        if (f.decode == 'jwt' && !verifyJwt(cap)) return cap;
        final name = '$key#$i';
        if (f.decode == 'jwt' && (f.maskClaims?.isNotEmpty ?? false)) {
          // Claim-level masking: sentinels go INSIDE the payload; the
          // rebuilt fake token is itself registered as a sentinel for
          // the whole real token, so both the bearer path (token sent
          // verbatim) and the extracted-claim path substitute on egress.
          final masked = maskJwtClaims(
            cap,
            f.maskClaims!,
            (claim, real) =>
                registry.register('$key#jwt$i.$claim', real, injectHosts),
          );
          if (masked == null) {
            // A verified JWT none of whose named claims are present as
            // strings: nothing to mask in THIS token — leave it as-is;
            // if no token matches any claim, onExtractNoMatch applies.
            logForDebugging(
              '[credential-mask] ${f.path}: verified JWT candidate has '
              'none of maskClaims ${jsonEncode(f.maskClaims)} as '
              'string claims — left unmasked.',
            );
            return cap;
          }
          final skipped = f.maskClaims!
              .where((c) => !masked.claimSentinels.containsKey(c))
              .toList();
          if (skipped.isNotEmpty) {
            logForDebugging(
              '[credential-mask] ${f.path}: maskClaims '
              '${jsonEncode(skipped)} absent or non-string in a '
              'verified JWT — skipped.',
            );
          }
          maskedCount++;
          return registry.registerWithSentinel(
            name,
            masked.fakeToken,
            cap,
            injectHosts,
          );
        }
        maskedCount++;
        // For decode the fake must keep the token's shape: a JWT-shaped
        // sentinel keeps client-side parsers (segment count, payload
        // decode, exp checks) working inside the sandbox.
        return f.decode == 'jwt'
            ? registry.registerWithSentinel(
                name,
                mintFakeJwt(randomUUID()),
                cap,
                injectHosts,
              )
            : registry.register(name, cap, injectHosts);
      }, maskDuplicates: f.maskDuplicates ?? false);
      if (extracted == null || maskedCount == 0) {
        // Nothing was masked — either the pattern matched nothing or, with
        // decode, no candidate survived verification. Both are the same
        // "masking cannot apply" condition, so both route through the
        // entry's onExtractNoMatch policy.
        final cause = f.decode == 'jwt'
            ? (f.maskClaims?.isNotEmpty ?? false)
                  ? 'decode "jwt" with pattern "$pattern" that matched no '
                        'verified JWT with maskable claims (maskClaims: '
                        '${jsonEncode(f.maskClaims)})'
                  : 'decode "jwt" with pattern "$pattern" that matched no '
                        'verified JWT'
            : 'extract pattern "$pattern" that matched nothing';
        final onNoMatch = f.onExtractNoMatch ?? 'warn';
        if (onNoMatch == 'error') {
          throw NodeException(
            'credentials.files entry "${f.path}": $cause '
            '(onExtractNoMatch: "error"). Fix the config, change to '
            '"warn"/"deny", or remove the entry.',
          );
        }
        if (onNoMatch == 'deny') {
          // Fail-closed: the operator declared this file as containing a
          // credential. Masking can't apply — degrade to deny so the
          // sandboxed process cannot read the credential at all.
          logForDebugging(
            '[credential-mask] ${f.path} has $cause — degrading to '
            'mode "deny".',
            level: 'warn',
          );
          degradeToDenyPaths.add(realPath);
          continue;
        }
        // 'warn' (default): fail-open. A non-matching config is an error
        // to surface, not a reason to block file access. Skip the entry
        // (no bind, no deny) — the file stays readable via the root mount
        // — and warn loudly on stderr so the operator fixes the config.
        final msg =
            '[sandbox-runtime] WARNING: credentials.files entry '
            '"${f.path}" has $cause in the file. The file is left '
            'UNPROTECTED (readable as-is inside the sandbox). Fix the '
            'config, set onExtractNoMatch to "deny" or "error", or remove '
            'the entry.';
        console.warn(msg);
        logForDebugging(msg, level: 'warn');
        continue;
      }
      fakeContent = extracted.fakeContent;
    }

    final fakePath = store.write(key, fakeContent);
    binds.add(MaskedFileBind(realPath: realPath, fakePath: fakePath));
  }
  return MaskedFileBuildResult(
    binds: binds,
    degradeToDenyPaths: degradeToDenyPaths,
  );
}

const String MASKED_FILE_STORE_PREFIX = 'srt-credmask-';
