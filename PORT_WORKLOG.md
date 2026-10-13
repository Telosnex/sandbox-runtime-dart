# Port worklog

Upstream: https://github.com/anthropics/sandbox-runtime, checked out at
`~/dev/sandbox-runtime`. Port baseline: v0.0.79, commit `24eb39e`.

## Rule 1: one-to-one with upstream

The goal is to keep porting upstream changes for years. So a reader must be
able to put an upstream file next to its Dart file and diff them by eye.

- **Files.** `src/<dir>/<kebab-name>.ts` becomes `lib/src/<dir>/<snake_name>.dart`.
  Only `-` changes to `_`. Do not merge, split, or move files.
  `test/<dir>/<name>.test.ts` becomes `test/<dir>/<snake_name>_test.dart`.
  `test/helpers/*.ts` becomes `test/helpers/*.dart`.
- **Names.** Every function, class, constant, type, field, and parameter keeps
  its upstream name. Only casing changes where Dart requires it:
  `SCREAMING_CASE` stays `SCREAMING_CASE` (ignore the lint per file).
  Exported TS names stay public in Dart; unexported names get a `_` prefix.
- **Order.** Declarations appear in the same order as upstream.
- **Comments.** Keep every upstream comment, edited only where it names a
  Node API that the Dart code does not use.
- **Tests.** Port every `it`/`test`/`describe` with the same title, in the same
  order. A test that cannot be ported stays as a `skip:` test with the reason.
- **Standalone Node tests.** A standalone `test/<dir>/<name>.mjs` is kept as a
  separate `test/<dir>/<name>_test.dart` file, with `-` changed to `_`; do not
  fold it into a sibling `*.test.ts` suite.
- **No improvements.** Port bugs too. Note a suspected bug here instead.
- **Each Dart file starts with:**
  `// Ported from sandbox-runtime src/<path>.ts @ <commit>.`

## Rule 1a: who ports a test file

Upstream test files are named for a behaviour, not a source file. So:

- A test file is always ported whole, as one Dart file named after it.
- The agent porting source file X ports the test files whose tests exercise X
  and otherwise only already-ported modules or modules in X's current batch.
- A test that needs a module that is not ported yet keeps its full body and
  gets `skip: 'pending port: <upstream file>.ts'`, in exactly that format, so
  one grep finds them all later.
- A test file where most tests need modules outside the current batch (for
  example sandbox-manager) is not ported yet. List it under "Related upstream
  tests not ported in this batch" with the modules it waits for.

## Rule 1b: partial files

A file may be created before its owner ports it, to supply declarations that
another file needs:

- **Stub:** declarations only, bodies `throw UnimplementedError('pending port
  of src/<path>.ts')`, header `// STUB: pending port of src/<path>.ts @ <commit>.`
- **Partial:** some declarations ported faithfully (with their upstream
  comments, in upstream order relative to each other), the rest absent.
  Header `// PARTIAL: ported <names>; pending port of the rest of
  src/<path>.ts @ <commit>.` Allowed only when /root approves it.

The agent that later ports the whole file replaces either kind, keeping any
faithful declarations that are already there.

## Rule 2: Node API shims

Upstream leans on Node behavior: error codes, `BlockList`, `isIP`, `rawHeaders`.
Dart equivalents behave differently. All such shims live in `lib/src/node/`
(no upstream counterpart), so that ported files read like the original.
A ported file never reimplements a Node API inline.

| Node | Dart shim (`lib/src/node/`) |
|------|-----------------------------|
| `err.code` (`ENOENT`, ...) | `errno.dart`: `NodeError { code, syscall, path }`; errno-to-code tables for macOS and Linux |
| `fs.*Sync` that throw with a code (`lstatSync`, `realpathSync`, `readlinkSync`) | `fs.dart`, using FFI where `dart:io` drops the errno; test-only `statIdentitySync` supplies Node's `dev:ino` oracle |
| `net.isIP`, `BlockList` | `net.dart`, with Node's internal IPv4/IPv6 regexes and cross-family matching |
| `process.env`, `process.platform`, `process.cwd()` | `process.dart`, overridable in tests (upstream tests patch `process.platform`) |
| `EventEmitter`-style callbacks | Dart `Stream`/`Future`; keep the upstream function boundaries |

## Rule 3: third-party packages

| Upstream | Dart |
|----------|------|
| `zod` schemas | Hand-written validators in the same file, same error messages |
| `commander` | `package:args`, same options and help text |
| `node-forge` | Pure Dart: `pointycastle` + `asn1lib`, no OpenSSL FFI |
| `@pondwader/socks5-server` | Open: port the parts used into `lib/src/node/socks5_server.dart` |
| `fast-check` | Open: a small property-test helper, or seeded random loops |
| `bun:test` | `package:test` |

## Rule 4: vendor

`vendor/seccomp-src`, `vendor/srt-win-src`, and `vendor/java-proxy-agent-src`
are copied unchanged. Their `build.ts` scripts become Dart under `tool/`.

## Conventions

Repeat these translation decisions for the rest of the port:

- **Option objects.** Flatten a TS final options object into Dart named
  parameters; keep arguments that are positional in TS positional in Dart.
  Example: TS `logForDebugging(message, options?: { level?: 'info' | 'error' |
  'warn' })` becomes `logForDebugging(message, {String? level})`.
- **Unions and literals.** A string-valued TS union stays a Dart `String` (or a
  `typedef` to `String`) when callers consume its literal spelling. Preserve
  the allowed values in comments and at runtime validation sites; do not turn
  serialized strings into Dart enums. Structural object types that are return
  values can become Dart records with named fields.
- **`undefined` and `null`.** TS optional values and `T | undefined` become
  nullable Dart values (`T?`) and use `null` for the absent case when the TS
  code only uses optional chaining or nullish/default checks. If upstream
  distinguishes an absent field from an explicit `null`, use a sentinel or a
  wrapper rather than collapsing the distinction.
- **Sync and async.** Keep synchronous Node `*Sync` calls synchronous in Dart;
  keep TS `Promise<T>` functions as `Future<T>`. Do not make an API async just
  because a Dart equivalent exists. EventEmitter-shaped boundaries use
  `Stream` subscriptions that are cancelled when the paired event wins, with
  the upstream promise represented as a `Future`.
- **Private names and constants.** Prefix unexported TS declarations with `_`.
  A private upstream `MAX_LINKS` therefore becomes `_MAX_LINKS`. Keep exported
  `SCREAMING_CASE` constants unchanged and add a file-local lint ignore rather
  than renaming the public declaration.
- **Tests.** `describe.skipIf(condition)` maps to `group(..., skip: condition ?
  reason : false)`; `describe.if(condition)` is the same with the inverse
  condition. A conditional assertion in a test body remains an early return,
  not a skipped test. Use Dart `test(..., skip: reason)` for an upstream case
  whose behavior cannot be run faithfully.
- **Assertions in test declarations.** Bun permits `expect(...)` directly in a
  `describe` callback; `package:test` does not. Move the assertion into a
  `test` at the same position, titled for what it checks.
- **Property tests.** `fast-check` properties use deterministic, seeded
  `Random` loops with the upstream sample counts and bounds. Keep the test
  title and timeout. Generate only values representable by the downstream
  process API (shell arguments cannot contain NUL bytes).
- **Node `Buffer`.** Use `Uint8List` for Node byte buffers; keep byte-oriented
  work byte-oriented and use `utf8.decode` only where upstream explicitly
  converts a Buffer to text. Do not decode raw HTTP/header/protocol bytes early.
- **Node errors and APIs.** Import Node behavior from `lib/src/node/` rather
  than rebuilding it in a ported file. `NodeError` carries `code`, `syscall`,
  and `path`; its FFI operation captures errno before another native call can
  overwrite it. Use `NodeException` for generic Node `Error` stringification.
  Dart's RegExp omits Node's `d`-flag capture offsets; `node/regexp.dart`
  instruments capture prefixes and lookbehind spans, and renumbers numeric
  backreferences. Unsupported quantified captures and legacy octal escapes
  throw rather than guess. Tests cover duplicate text, lookbehind, nesting,
  escapes, named captures, and backreferences.
- **Unavailable Node APIs.** Until an HTTP/socket shim exists, an unimplemented
  Node API must throw `UnimplementedError` with the blocking hard spot rather
  than silently no-op (particularly for body gates and budget enforcement).
- **`process` overrides.** Import the shim as `process`; read its `platform`,
  `env`, and `cwd()` getters at the point of use. Tests that patch Node globals
  call `setPlatformForTesting`, `setEnvForTesting`, or `setCwdForTesting` and
  restore with `null` in `finally`.
- **`sandbox-config` types.** Each inferred object configuration type is an
  immutable Dart class with the upstream field names and `final` fields;
  optional fields use nullable types. The inline TLS-termination object is
  represented by `TlsTerminateConfig`. `FilesystemPathEntry` is a sealed
  union: `FilesystemPathSpelling(path)` is the string spelling branch and
  `FilesystemPathLiteral(path)` is `{path, literal: true}` (`literal` is
  always true). String-literal unions remain `String` typedefs with adjacent
  allowed-value constants. The hand-written validators expose
  `ConfigSchema<T>.safeParse(Object?)`, returning `success`, typed `data`, or
  `error.issues` with `message`, `path`, and `code`. The request callback's web
  `Request`/`RequestInfo` types use `Object` at the stub boundary until the
  request-filter port supplies their Dart representations.

### Generators that return a value (`Steps<T>`)

TS `function*` generators that `return` a value and are composed with
`const x = yield* f()` (sandbox-utils `Steps<T>`, `finish`, `finishInTurns`)
cannot be Dart `async`, because upstream's `finish` runs them synchronously.
Dart `sync*` cannot return a value. So, decided by /root:

- `lib/src/node/generators.dart` (no upstream counterpart) defines
  `sealed class Step<T>`, `Pause<T>` (a TS `yield` / `yield undefined`) and
  `Done<T>(value)` (the TS `return value`), plus
  `Iterable<Step<R>> yieldStar<T, R>(Iterable<Step<T>> steps, Box<T> into)`,
  which re-yields each pause as `Pause<R>` and stores the `Done` value in
  `into`. `class Box<T> { late T value; }`.
- `sandbox_utils.dart` keeps upstream's declaration:
  `typedef Steps<T> = Iterable<Step<T>>;` and ports `finish`/`finishInTurns`
  to iterate until `Done`.
- Mapping, line for line:
  - `function* f(): Steps<T> {` → `Steps<T> f() sync* {`
  - `yield` → `yield Pause();`
  - `return v` → `yield Done(v); return;`
  - `const x = yield* g()` → `final x = Box<U>(); yield* yieldStar(g(), x);`
    then use `x.value` where upstream uses `x`.
- A `Steps` iterable must end with exactly one `Done`. `finish` throws
  `StateError` if it ends without one (fail closed).
- Plain value generators (`Generator<string>`, for example
  `properAncestors`) stay `Iterable<String> f() sync*`.

### Worked example

Upstream `listenInRange(server, doListen, range, exclude)` returns a
`Promise<void>` and gets `undefined` for an unbounded range. The Dart port keeps
the four positional arguments, maps `Promise<void>` to `Future<void>`, maps
`undefined` to nullable `List<int>?` (`null` means listen once on port `0`),
and replaces paired EventEmitter one-shot callbacks with the
`NodeEventEmitter` Stream boundary in `lib/src/node/events.dart`.

## Known hard spots (decide before porting the file)

- `--control-fd` (cli.ts): do not use `posix_spawn`. Read an inherited fd with
  `File('/dev/fd/N')`; keeping it out of the sandboxed child is a small FFI
  `fcntl(fd, F_SETFD, FD_CLOEXEC)` shim in `lib/src/node/`. Verified on macOS:
  `dart:io` `Process.start` and `Process.run` children inherit every parent fd
  that does not have `FD_CLOEXEC` set. Later ports must not assume Dart closes
  arbitrary inherited descriptors.
- `http-proxy.ts`, `tls-terminate-proxy.ts`: depend on Node `http` details
  (`rawHeaders`, CONNECT `head`). `dart:io` lowercases headers. Likely needs a
  raw HTTP/1.1 parser shim.
- `emitted-connection.ts`: depends on Node's raw HTTP parser callbacks and
  emitted-socket lifecycle. `emitted-connection.dart` is partial until the
  HTTP/socket shim exists; unsupported entry points fail with
  `UnimplementedError` rather than fail open.
- `mitm-leaf.ts`: Node picks a certificate per SNI. Dart has no SNI callback.
  Read the SNI from the ClientHello, then `SecureSocket.secureServer` with
  `bufferedData`.

## Port order (by imports)

1. Leaves: utils/*, address, listen-in-range, sandbox-schemas, credential-extract.
2. sandbox-config, sandbox-utils, platform-dependent path helpers.
3. macOS, Linux, Windows utils; seccomp; ripgrep users.
4. Proxies, MITM, credentials.
5. sandbox-manager, index, cli, proxy-cli.

## Status

| Upstream file | Dart | Tests | Notes |
|---------------|------|-------|-------|
| `src/utils/shell-quote.ts` | `lib/src/utils/shell_quote.dart` | `test/utils/shell_quote_test.dart` | Ported; wrapper-builder test skipped because its macOS builder is outside this step |
| `src/utils/real-path.ts` | `lib/src/utils/real_path.dart` | `test/utils/real_path_test.dart` | Ported; POSIX FFI preserves errno and `stat` dev/inode identity; property test compares against the sibling upstream module when present |
| `src/sandbox/address.ts` | `lib/src/sandbox/address.dart` | — | Ported; no matching standalone upstream test file |
| `src/sandbox/listen-in-range.ts` | `lib/src/sandbox/listen_in_range.dart` | — | Ported; no matching upstream test file; Stream adapter is in `node/events.dart` |
| `src/utils/debug.ts` | `lib/src/utils/debug.dart` | — | Ported as a downstream dependency; no matching upstream test file |
| `src/utils/platform.ts` | `lib/src/utils/platform.dart` | `test/utils/platform_test.dart` | Ported |
| `src/utils/which.ts` | `lib/src/utils/which.dart` | `test/utils/which_test.dart`, `test/utils/which_node_test.dart` | Ported; 7 pass, 2 skipped (Bun-only); Node fallback script kept separate; Dart's synchronous process API has no spawn timeout |
| `src/utils/ripgrep.ts` | `lib/src/utils/ripgrep.dart` | `test/utils/ripgrep_test.dart` | Ported; real `rg` process; six tests pass on this host; POSIX argv0 uses Bash `exec -a`; Windows argv0 case skips because Dart cannot override argv[0] |
| `src/sandbox/sandbox-schemas.ts` | `lib/src/sandbox/sandbox_schemas.dart` | — | Ported; no matching standalone test file; six other sandbox tests import it (listed below) |
| `src/sandbox/credential-extract.ts` | `lib/src/sandbox/credential_extract.dart` | — | Ported; no matching standalone test file; direct extraction tests in `credential-mask-files.test.ts` remain queued; exact capture offsets use the instrumented RegExp shim |
| `src/sandbox/emitted-connection.ts` | `lib/src/sandbox/emitted_connection.dart` | — | **Partial:** HTTP/socket core is now available; no matching upstream test file; TLS termination wiring and byte-budget/runtime tests remain deferred; unsupported paths stay fail-closed |
| `src/sandbox/mux-proxy.ts` | `lib/src/sandbox/mux_proxy.dart` | `test/sandbox/mux_proxy_test.dart` | **Partial:** net/HTTP shim dependencies are now present; source port remains partial and all 8 direct tests still skip pending that port |
| `src/sandbox/aws-sigv4.ts` | `lib/src/sandbox/aws_sigv4.dart` | `test/sandbox/aws_sigv4_test.dart` | Ported; 38 pass, including all 22 official test-suite vectors |
| `src/sandbox/sandbox-config.ts` | `lib/src/sandbox/sandbox_config.dart` | `test/config_validation_test.dart` | Ported; 151 config-validation cases pass, with hand-written typed validators |
| `src/sandbox/domain-pattern.ts` | `lib/src/sandbox/domain_pattern.dart` | `test/sandbox/domain_pattern_test.dart` | Ported; all 16 direct tests pass |
| `src/sandbox/parent-proxy.ts` | `lib/src/sandbox/parent_proxy.dart` | — | **Partial:** `stripBrackets` and `canonicalizeHost` ported for domain-pattern; rest of the module remains unported |
| `src/sandbox/request-filter.ts` | `lib/src/sandbox/request_filter.dart` | — | Stub; `FilterRequestCallback` declaration required by sandbox-config |
| `src/sandbox/sandbox-utils.ts` | `lib/src/sandbox/sandbox_utils.dart` | `test/sandbox/{sandbox_env_tmpdir_test,glob_walk_property_test}.dart` | Ported; 6 direct tests pass; no one-to-one utility suite exists upstream; Node shims `os.dart`, `buffer.dart`, `fs_sandbox_utils.dart` |
| `src/sandbox/path-entries.ts` | `lib/src/sandbox/path_entries.dart` | — | Ported; `literal-path-entries.test.ts` waits on sandbox-manager and Linux/macOS wrapper modules |
| `src/sandbox/sandbox-violation-store.ts` | `lib/src/sandbox/sandbox_violation_store.dart` | — | Ported; no one-to-one upstream test file; related assertions are in `command-text-registry.test.ts` |
| — (Node shims) | `lib/src/node/{errno,events,fs,http,net,process}.dart` | `test/node/{http,net}_test.dart` | No upstream counterparts; raw HTTP/1.1/socket subset with byte-preserving headers, body/trailer framing, CONNECT, keep-alive, and TCP/Unix listeners; 16 focused tests pass |
| — (Node shim) | `lib/src/node/url.dart` | `test/node/url_test.dart` | WHATWG URL host parsing subset for `canonicalizeHost`; seven Node v22.16.0 golden tests pass; unsupported IDNA fails closed |
| — (Node shims) | `lib/src/node/{abort,emitted_http,regexp}.dart` | `test/node/{emitted_http,regexp}_test.dart` | No upstream counterparts; AbortSignal, emitted-connection adapter over raw HTTP/socket shim, and exact supported RegExp-with-indices instrumentation |
| — (Node shims) | `lib/src/node/{aws_crypto,incoming_http_headers,url_search_params}.dart` | — | No upstream counterparts; Node crypto Buffer/HMAC, HTTP headers, and URLSearchParams used by `aws-sigv4.ts` |
| — (Node shims) | `lib/src/node/{forge,tls}.dart` | `test/node/{forge,tls}_test.dart` | Pure-Dart forge subset; Mozilla root bundle `2026-09-25` SHA-256 `a41b5d35…37d00505`; bounded ClientHello replay and ALPN; secure client HTTP uses the raw socket shim |

### Known port gaps

- `which.ts`: Dart's synchronous `Process.runSync` has no `spawnSync` timeout;
  the upstream one-second timeout cannot be reproduced synchronously.
- `emitted-connection.ts`: HTTP/socket parser and event adapters now exist;
  full TLS tunnel wiring and runtime/body-budget integration remain deferred.
- `mux-proxy.ts`: raw net stream/server and HTTP shim dependencies are present;
  inherited-FD listener support and the source port/test suite remain pending.
- TLS: malformed, oversized, or timed-out ClientHello inspection throws and
  destroys the raw socket; no-SNI is returned explicitly for caller policy.
  Unsupported forge extensions, non-RSA PEM keys, and signing algorithms throw
  rather than guessing. `checkServerIdentity` returns a mismatch error. Complex
  multi-valued user-CA RDNs are normalized when re-encoded for CRLs, matching
  node-forge's documented limitation.
- WHATWG URL host parsing: `node/url.dart` supports ASCII, IPv4 inet_aton
  forms, IPv6, percent decoding, Latin-1 Punycode, fullwidth ASCII and mapped
  dot separators. Full UTS-46/NFC IDNA behavior is not implemented; unsupported
  Unicode throws so `canonicalizeHost` returns null rather than guessing.
- `sandbox-utils.ts`: `os.homedir()`'s native passwd-database fallback is not
  available through Dart; the shim throws if HOME/USERPROFILE is absent. Dart
  also cannot create a `TypeError` carrying Node's custom message, so marked
  literal and invalid-anchor failures use `ArgumentError`.

### Related upstream tests not ported in this batch

These exercise the listed modules but belong to other source/test files, so
they stay queued for those files' port steps (per the one-file test rule):

- `credential-extract.ts`: `test/sandbox/credential-mask-files.test.ts`.
- `sandbox-schemas.ts`: `test/sandbox/{macos-seatbelt,symlink-boundary,macos-profile-size,allow-read,read-list-precedence,macos-pty}.test.ts`.
- `sandbox-violation-store.ts`: sanitizer/store cases in `test/sandbox/command-text-registry.test.ts` (not a one-to-one test file).
- `mux-proxy.ts`: `test/sandbox/{mux-proxy-e2e,request-rewriting}.test.ts`.
- `aws-sigv4.ts`: `test/sandbox/{credential-aws-pairs,credential-mask-sigv4}.test.ts`.
- `emitted-connection.ts`: direct tests in `test/sandbox/{byte-budget,tls-terminate-runtime,tls-terminate-upload-gate,tls-terminate-relay-budget}.test.ts`; its helper `test/helpers/emitted-connections.ts` is used by `test/proxy-cli.test.ts` and `test/sandbox/{canonical-host-routing,client-abort,connect-non-tls,credential-mask-body,credential-mask-sigv4,deny-late-body,invalid-upstream-response,proxy-only-edges,proxy-only,request-filter,request-rewriting,request-target-forwarding,resolved-address-guard,response-header-bytes,tls-terminate-handshake-deadline,tls-terminate-in-process,tls-terminate-keepalive,tls-terminate-proxy,trailers-then-request}.test.ts`.
- `sandbox-config.ts`: `test/config-validation.test.ts` is the one-to-one suite ported with this file. The other direct schema/type consumers belong to their own source/test steps and remain queued: `test/configurable-proxy-ports.test.ts`, `test/public-exports.test.ts`, and `test/sandbox/{brackets-that-spell-no-set,credential-aws-pairs,credential-deny,credential-mask-files,credential-mask-sigv4,credential-mask,filesystem-disabled,glob-expand,integration,java-proxy-agent,literal-path-entries,mux-proxy-e2e,names-with-a-backslash,own-files,proxy-env-vars,read-list-precedence,request-rewriting,resolved-address-guard,tls-terminate-runtime,update-config,winsrt,wrap-with-sandbox}.test.ts`.
- `path-entries.ts`: `test/sandbox/literal-path-entries.test.ts` waits on `sandbox-manager.ts`, `linux-sandbox-utils.ts`, `macos-sandbox-utils.ts`, `linux-violation-monitor.ts`, and its platform/bwrap/config-loader helpers.

The upstream `src` and `test` grep for `maskedFileBinds` and
`NetworkHostPattern` found reads and object construction only; no code mutates
`realPath`, `fakePath`, `host`, or `port` fields. The existing named records
remain appropriate for those nested object shapes.
