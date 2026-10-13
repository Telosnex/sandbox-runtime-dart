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
- **No improvements.** Port bugs too. Note a suspected bug here instead.
- **Each Dart file starts with:**
  `// Ported from sandbox-runtime src/<path>.ts @ <commit>.`

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
| `node-forge` | Open: `pointycastle` + `asn1lib`, or FFI to the system TLS library |
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
- **`process` overrides.** Import the shim as `process`; read its `platform`,
  `env`, and `cwd()` getters at the point of use. Tests that patch Node globals
  call `setPlatformForTesting`, `setEnvForTesting`, or `setCwdForTesting` and
  restore with `null` in `finally`.

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
| — (Node shims) | `lib/src/node/{errno,events,fs,net,process}.dart` | — | No upstream counterparts; small compatibility layer for these files |
