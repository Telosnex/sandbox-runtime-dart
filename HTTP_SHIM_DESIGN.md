# HTTP / socket shim design (upstream 24eb39e)

## Recommendation

Keep all upstream `src/sandbox/*.ts` files as one-to-one Dart files and keep the
runtime emulation out of them. `dart:io` is an adequate TCP/TLS/DNS substrate,
but its `HttpServer` is not a substitute for the particular Node HTTP/1.1
surface these files consume. Implement a focused Node-compatible layer in
`lib/src/node/http.dart`, extend the existing `lib/src/node/net.dart`, and put
the SOCKS protocol subset in `lib/src/node/socks5_server.dart`. Use raw sockets
for HTTP parsing/serialization; use `dart:io` `SecureSocket.secureServer` for
TLS after explicitly peeking the ClientHello. This can preserve the file and
function structure in the ported proxy code without putting parser branches in
each proxy.

Current `lib/src/node/net.dart` is only `isIP`, IPv6 parsing, and `BlockList`;
`lib/src/node/emitted_http.dart` is deliberately fail-closed. The emitted
connection adapter should become a thin wrapper over the same `node/http.dart`
and `node/net.dart` machinery, not a second parser. Do not replace failures in
`emitted_http.dart` with no-ops.

## API inventory: Node/third-party dependencies

| Upstream file(s) | Node / third-party surface actually used | Dart equivalent and shim decision |
|---|---|---|
| `http-proxy.ts` | `node:http`: `createServer`, `Server` and its `request`, `connect`, `clientError` events, `Agent`, `request`, `IncomingMessage` (`url`, `method`, `headers`, `rawHeaders`, `httpVersion`, `socket`, stream methods/events), `ServerResponse` (`writeHead`, `write`, `end`, `destroy`, header/socket state/events), `ClientRequest`, upstream `IncomingMessage`; `node:https` `request`; `node:net` `connect`, `Socket` (`write`, `end`, `destroy`, `pipe`, `pause`/`resume`, `read`, `unshift`, `allowHalfOpen`, `setTimeout`, readable/writable state and error/close/end/drain events); Node `Buffer`; `node:url.URL`; Node timers. | `dart:io` has TCP sockets and byte streams, but **not** Node parser callbacks, `rawHeaders`, CONNECT `head`, response/client request APIs, Agent semantics, or Node socket state/events. Use `node/http.dart` atop `NodeSocket`; preserve byte-oriented `Uint8List`. `dart:io` `Uri` is not a drop-in for Node URL edge spellings; keep URL behavior in one small node/url compatibility helper if differential tests show differences. |
| `tls-terminate-proxy.ts` | `node:https` `Agent` / `request`; `node:http` `createServer`, `ClientRequest`, `IncomingMessage`, `ServerResponse`, server `connection`/`request`/`clientError`/`upgrade` events and `emit('connection', tls)`; `node:tls` `TLSSocket`, `TLSSocketOptions`, `checkServerIdentity`, `SecureContext`, `ALPNProtocols`, upstream CA/client TLS; `node:net` `Socket`, `LookupFunction`; `node:stream` `Duplex`, `Readable`, `Writable`; low-level readable `read`, `unshift`, `pipe`, pause/resume, `drain`, `finish`, `secure`, `data`, `error`, `close`, timers. | `SecureSocket.secureServer` can TLS-wrap an accepted `Socket`, accepts `bufferedData`, context and `supportedProtocols`; it does not expose Node `TLSSocket`/`SNICallback`/socket-parser handoff or matching event lifecycle. The shim must own the accepted socket and hand decrypted bytes to its HTTP parser. `SecureSocket.secure` + an explicitly configured `SecurityContext` is viable for client legs; implement per-client-connection keep-alive/one-socket Agent policy in `node/http.dart`, using vetted literal dial addresses and host SNI. `server.emit('connection')` is replaced by `NodeHttpServer.serveConnection(NodeSocket)` rather than a real listener. |
| `mitm-ca.ts`, `mitm-leaf.ts` | `node-forge` `pki`, RSA keys, cert parse/create/PEM, `asn1` DER, SHA-256, randomness, X.509 extensions/SKI/AKI; `node:crypto` `sign`, `X509Certificate`; `node:tls` `rootCertificates`, `SecureContext`, `createSecureContext`; `node:fs`, `fs/promises`, `os.tmpdir`, `path`; `node:net.isIP`. | No `dart:io` X.509 certificate builder, no bundled-Node-root enumeration, and no node-forge equivalent in current pubspec. Prefer portable `pointycastle` + `asn1lib` behind a local certificate helper (PEM and exact DER/extensions remain our responsibility); choose FFI to OpenSSL only if platform support/build packaging is explicitly accepted. Load PEM chain/key into `SecurityContext`. Root bundle policy is a human decision (Node's bundled Mozilla roots vs OS roots). |
| `socks-proxy.ts` | `@pondwader/socks5-server`: `createServer`, auth handler, ruleset validator, connection handler, private `_handleConnection`; connection host/port/username/socket and exact binary method-selection/status writes. `node:net.Socket` stream, `setNoDelay`, events, `pipe`, `destroy`; direct/parent dial. | No dart SOCKS server API. Port the used SOCKS5 state machine (method negotiation, optional username/password, CONNECT, validator/status hooks) into `node/socks5_server.dart`; do not pull in or attempt to emulate the npm package wholesale. Share `NodeSocket` semantics with mux. Maintain exact RFC1928 replies and write-before-close SSH refusal payload. |
| `parent-proxy.ts` | `node:net.BlockList`, `isIP`, `connect`, `Socket`, `LookupFunction`; `node:tls.connect`, TLS `servername` / identity check; `node:http.IncomingMessage` and `ServerResponse`; URL; connect readiness events, pause, timeout, error/close and byte writes for a manual CONNECT parser. | `InternetAddress.lookup` gives an async list but not Node's callback overload / lookup-family options; adapt it to the `LookupFunction` contract in `node/net.dart` and retain the resolved-address guard. Use `Socket.connect`/`SecureSocket.connect`, explicitly time out and map OS error codes. `BlockList`/`isIP` already exist in the shim. HTTP response-head relay uses raw serializer. |
| `proxy-only.ts`, `mux-proxy.ts` | `node:net.createServer`, `Server`, `connect`, `Socket`; accepted-socket `read(1)` + `unshift`, `pipe`, event order, `end`, `destroy`, `unref`, `setNoDelay`, `address`, `listen`, `close`; Unix path and TCP backend; `node:http.Server` listen/close/emit; `node:stream.Readable`/`Writable` wrappers for inherited descriptor streams; fs/path/os for unix endpoint cleanup. | Extend `net.dart` with a `NodeSocket` facade over Dart `Socket` and `NodeServer` over `ServerSocket`; implement queued `read(n)`/`unshift`, backpressure-aware duplex piping, half-close, close/error ordering, `unref` bookkeeping and unix listener/client helpers. Dart streams do not return Node `write()`'s backpressure boolean or expose `writableLength`; count queued bytes and drive a `drain` event from `flush`/queue thresholds. Inherited-fd listeners are a separate FFI issue (not provided by `ServerSocket.bind`). |
| `decider-client.ts` | `node:net.isIP`; Node `Readable` / `Writable` and `Buffer`; `.write(frame, callback)`, `data`/`end`/`error`/`close`, `destroy`, output backpressure and callback/error order; `zod/v3` schemas. | Use `Stream<List<int>>` and `IOSink` through a Node-like stream adapter; ensure write completion/close failure fails closed. `zod` maps to the existing hand validators, but the byte framing/streams require the common adapter. |
| `request-filter.ts` | `node:http.IncomingMessage`/`ServerResponse`, `rawHeaders`, `req.pipe`, body `PassThrough`/`Readable`, request/response/socket error/close/finish, `destroy`, `pause`/`resume`; Node web globals `Request`, `Headers`, `AbortController`/`AbortSignal`; `node:net.isIP`. | No exact `Request` body tee / abort signal facade in `dart:io`; implement a small web-request view around the incoming body stream with explicit tee and cancellation. This must not buffer whole requests. Body/source errors, cancellation during async filtering, and response-flush-before-destroy are common-shim responsibilities. |
| `resolved-address-guard.ts` | `node:dns.lookup` and callback options `{all:true}`, `LookupAddress`, `LookupFunction`; `node:net.BlockList`, `isIP`; `node:os.networkInterfaces`. | `InternetAddress.lookup` and `NetworkInterface.list` are the substrate; wrap callback/all-family result semantics, host-not-found / socket error codes, stable surviving address order, and resolve-once guarded dialing. The current `BlockList`/`isIP` should stay the shared oracle. |
| `emitted-connection.ts` | `node:http.createServer`, hidden parser callbacks / `socket.parser.onHeaders` batches and `onMessageComplete`, emitted `connection` listener detection, `IncomingMessage` and its socket/body buffer; Node socket default string encoding (`latin1`), lifecycle, graceful TLS close. | No exact `dart:io` API. Implement parser-batch/trailer separation in `node/http.dart`; implement Latin-1 header serialization as bytes (not socket global encoding); budget and request-end hooks operate on shim messages/sockets. `emitted_http.dart` should delegate here and become supported only after these paths exist. |
| `body-substitution.ts` | `IncomingMessage.headers`; Node `Transform`/`Buffer`, stream transform/error/backpressure semantics; content-length vs transfer-encoding framing. | `StreamTransformer<Uint8List,Uint8List>` can do the byte transformation, but shim the Node Transform contract where source files use it. Serializer must recalculate framing after substitutions: retain length only when lengths match, otherwise remove Content-Length and chunk. |
| `credential-aws-pairs.ts`, `credential-sentinel.ts`, `aws-sigv4.ts` | `IncomingHttpHeaders`; `node:crypto` `randomUUID`, `randomBytes`, `createHash`, `createHmac`; mutable header values and duplicate/single-header checks. | `package:crypto` / secure random can cover crypto; the important transport dependency is Node header normalization plus exact duplicate visibility. Preserve raw headers separately while handing a normalized mutable map to signing/substitution hooks. |
| `credential-mask-env.ts`, `credential-mask-files.ts` | Node `randomUUID`; `fs` sync/promises, `os.tmpdir`, `path`; credential files and child env. | Existing file/process shims and `Random.secure`/crypto package can cover this; no HTTP-specific shim beyond shared header/body semantics. |
| `credential-decode.ts`, `credential-extract.ts` | Pure protocol/string code (decode imports sentinel prefix); no Node socket/HTTP API. | Direct one-to-one Dart port; no HTTP shim required. |

## Behavior the upstream tests pin

| Test area (representative files) | Node-sensitive behavior asserted | Consequence for the shim |
|---|---|---|
| Header preservation / decider (`proxy-only.test.ts`, `tls-terminate-in-process.test.ts`, `trailers-then-request.test.ts`) | `IncomingMessage.rawHeaders` is original alternating spelling/value order, including duplicate differently-cased fields. Repeated Host lines must be seen individually; tests inspect what the decider and upstream see. Normalized `headers` is a separate lower-case view. | Keep both views; never reconstruct `rawHeaders` from `Map`/`HttpHeaders`. Preserve order and repeated lines. Node merges ordinary duplicate fields in `headers`, preserves `set-cookie` as a list and has special duplicate handling; normalize in the adapter only. |
| CONNECT (`http-proxy`, `tls-terminate`, `parent-proxy-tunnel`, `connect-non-tls`) | Node's server emits `(req, socket, head)`, where `head` is bytes already read after `\r\n\r\n`; those bytes can be ClientHello, SSH, or payload. 200 response is a raw status line; remaining socket becomes a tunnel. | Parse delimiters as bytes and return the exact suffix as `head`; if a custom read already consumed it, queue/replay before the socket's next read. Do not route CONNECT through `HttpServer`. |
| Chunked bodies and trailers (`proxy-only.test.ts`, `trailers-then-request.test.ts`, `client-abort.test.ts`, credential body tests) | Chunk framing is removed from request body; trailers belong to that message, not the next request; proxy does not forward inbound trailers; incomplete aborted chunked upload must not reach upstream looking complete. Empty chunked GET body can be accepted; nonempty bodyless-method request is rejected. | Streaming chunk decoder with explicit trailer terminator and parse-state reset; on abort do not emit a synthetic final chunk. Preserve request body bytes only, and serialize a fresh outbound frame. |
| Persistence / streaming (`tls-terminate-keepalive.test.ts`, `tls-terminate-relay-budget.test.ts`, response tests) | Multiple requests on a client TLS connection, one upstream keep-alive socket per client connection; idle upstream close redials; reused-socket failure closes client rather than turning into 502; streamed SSE/large bodies remain incremental and backpressured. | HTTP/1.1 framing and persistent connection state, per-tunnel Agent semantics, bounded queues, and do not `readAsBytes()` entire messages. |
| `Expect: 100-continue` | No direct upstream test was found. Node's default HTTP server sends 100 Continue when no `checkContinue` listener takes over; forwarded-client behavior also depends on `ClientRequest` continue handling. | Model Node default for compatibility, but add an explicit spike/test before deciding whether to eagerly send 100 or wait for proxy policy. Avoid claiming this is already verified. |
| Socket aborts, half-close, errors (`client-abort.test.ts`, `http-proxy-verdict-liveness.test.ts`, `parent-proxy*.test.ts`) | `ECONNRESET` / `EPIPE` must not escape uncaught; aborting before a verdict releases the socket and never writes the late verdict; legal HTTP EOF can still receive verdict; established tunnel FIN flows one-way and opposite side can still reply. Denial response must flush before request/socket teardown. | Distinguish `end`/read EOF, `finish`/write shutdown, `close`, and `destroy`; do not collapse them into one Dart `Socket.close()`. Provide `shutdown(send)`/flush-then-close and Node-like idempotent destroy/error handling. |
| Parser errors / limits (`client-abort.test.ts`, `proxy-only.test.ts`) | `clientError` parse errors do not crash server; malformed request gets 400 (Node); default oversized header gets 431; caller max-size overflow maps to 400 per source; denial marker/status has exact CRLF bytes and response can need a one-second backstop. | Define stable HTTP parser error codes (`HPE_*`), exact max-header checks, `clientError` event, ordered flush-before-destroy, and timer fallback. |
| Response header bytes (`response-header-bytes.test.ts`) | High bytes in response header values are passed byte-for-byte; header output is not UTF-8-expanded. Refusal reason is written as bytes. | Serialize header field values as Latin-1 bytes after Node-compatible validation. No global UTF-8 `String` write for raw heads. |
| TLS SNI / ALPN / certificate (`tls-terminate-in-process.test.ts`, `tls-terminate-proxy.test.ts`, handshake/runtime tests) | HTTP/1.1 ALPN; SNI mismatch/unreadable handling and `requireHostMatch`; leaf cert identity is target or valid non-pinned SNI as policy says; trusted CA chain, AKI/SKI, ephemeral and supplied CA behavior; handshake deadline, silent and fragmented handshakes, failed setup frees tunnel slot; excluded hosts stay opaque; mTLS upstream fails because proxy has no client cert unless configured. | Read ClientHello before TLS, choose cert/context, replay bytes, enforce SNI/target policy, negotiate only HTTP/1.1, and enforce deadline independently. Certificate must include tested SAN, issuer, AKI/SKI and chain. Upstream TLS must use configured CA and `checkServerIdentity`; preserve explicit absence of client cert. |
| SOCKS / mux (`canonical-host-routing`, resolved-address SOCKS cases, mux tests) | Exact `05 00` no-auth method reply; CONNECT REP success/refusal code; deny-over-SSH writes SSH banner + DISCONNECT before EOF; mux sniffs one byte and restores it, HTTP client pipes through backend; Unix backend and cleanup/unref behavior. | Shared NodeSocket needs queue `read(1)`/`unshift`, half-close and flush-before-close. A focused SOCKS5 port and Unix socket server/client wrapper are enough. |

## Proposed shim boundaries

### `lib/src/node/http.dart`

Build a deliberately small, raw HTTP/1.1 Node facade on `NodeSocket`, not on
`dart:io.HttpServer`:

* `IncomingMessage`: request line, method/url/version, lower-case merged
  `headers`, exact alternating `rawHeaders`, `trailers`/`rawTrailers`, socket,
  byte stream, `pipe`/`destroy`, and one-shot end/error/aborted/close events.
* `ServerResponse`: status/header staging, `writeHead`/`write`/`end`, byte
  header output, default date/framing/persistence rules needed by these call
  sites, flush/finish/close/error state, and `addTrailers` if the upstream
  source surface needs it. The no-improvement rule means preserve Node's
  validation and oddities once differential fixtures cover them.
* `NodeHttpServer`: `request`, `connect`, `clientError`, `upgrade` and accepted
  `connection` callbacks; max-header-size option; same server usable either on
  a TCP/unix listener or by `serveConnection()` for terminated TLS sockets.
  CONNECT callback receives all already-buffered bytes in its `head` argument.
* `ClientRequest`/client response and `Agent`: serialize request head/body,
  parse responses including duplicate/raw header lines, support explicit
  socket path / already-vetted socket / TLS context / CA / SNI, request abort,
  and the one-socket keep-alive policy used by TLS termination. Responses must
  stream, not buffer.
* Per-connection parser: bounded request-line/header bytes; preserve all raw
  bytes through the head; decode Content-Length and chunked bodies; isolate
  trailer block; then begin the next pipelined message. Parser failures become
  a `clientError` carrying Node-like `code` and an untouched error message.

This is a subset tailored to actual imports, not a general Node HTTP library.
`node/emitted_http.dart` can then hold compatibility-specific helper names
(`keepFlushedHeaderBatches`, Latin-1 head writing, `gateSocketOnBufferedBody`,
`endRequestAfterResponse`) and forward to `http.dart` types rather than accept
`Object`/throw.

### `lib/src/node/net.dart` (extend, do not duplicate)

Retain the existing `isIP`, `ipv6Bytes`, and `BlockList`; add `NodeSocket`,
`NodeServer`, TCP/Unix `connect`, listener lifecycle, and the Node stream
adapter in this same boundary. `NodeSocket` needs: queued `read(n)` and
`unshift(bytes)`; a readable subscription that can pause/resume; ordered
`data`/`end`/`close`/`error`/`connect`/`drain` events; write queue accounting
(`writableLength`, `bytesWritten`); `pipe` with backpressure and end policy;
`setNoDelay`; timeout events; `destroy`; write-side `end`/half-close via
`Socket.close()` or shutdown only after flushing; and `unref` state that does
not keep a Dart isolate alive. A probe on `read(1)` followed by `unshift` must
work before handing the socket to SOCKS. Dart `Socket` offers `destroy`, stream
pause, `IOSink.close`, `done`, and `ServerSocket`, but no Node `read/unshift`,
boolean `write`, `writableLength`, `unref`, Node event ordering, or built-in
idle timeout; implement those semantics at the facade, not by relying on
`Stream.pipe`.

For mux, `NodeServer.listen(path)`/`connect(path)` should map to Unix-domain
`ServerSocket`/`Socket` on macOS/Linux and localhost TCP on Windows. Stale Unix
paths are unlinked before listen and after close (plus a sync best-effort exit
cleanup). `NodeServer.unref()` must track listener lifetime. Inherited listening
file descriptors are a different problem: `ServerSocket.bind` cannot adopt a
Node `listen({fd})` listener, so retain the worklog's explicit FFI decision;
do not imply that this design solves `--control-fd` / inherited listener IO.

### TLS and certificates

For SNI, read exactly the first TLS handshake record(s), bounded by the
ClientHello size and existing handshake deadline; parse `server_name`; choose
`secureContextFor(SNI)` or the CONNECT target according to
`requireHostMatch`; pass every consumed byte to `SecureSocket.secureServer`
with `bufferedData`. `SecureSocket.secureServer` documents that consumed bytes
are accepted in `bufferedData`, so this is a real available primitive. Dart
has `supportedProtocols` on `SecureSocket.secureServer` and reports negotiated
ALPN via `selectedProtocol`. ALPN works: the server `SecurityContext` must also
call `setAlpnProtocols(['http/1.1'], true)`. With that one call, the spike
negotiates `http/1.1` at both ends (checked 2026-10-13). Without it, both ends
report `null`, which is what the first spike run saw.

Certificate implementation must cover PEM parsing, RSA-2048 ephemeral CA and
reused leaf keypair, serial generation, exact validity cap, critical Basic
Constraints / Key Usage, EKU serverAuth, IP-vs-DNS SAN, SKI, raw-byte AKI,
CDP-to-empty-CRL, CA-signed empty CRL DER, user CA/key pair checking, and trust
bundle construction. `SecurityContext` can load and trust certificates but
cannot build them. PointyCastle/ASN1 is the portable default; FFI to libcrypto
is faster and can reuse Node's native signing details but adds macOS/Linux/
Windows library discovery and ABI/packaging risk. Ask the human to select one
before porting `mitm-ca` / `mitm-leaf`.

## Spikes (throwaway source retained under `tool/spikes/`)

* `tool/spikes/sni_secure_server.dart`: **SNI certificate selection works** on
  this Dart 3.13/macOS host. It generates distinct alpha/beta leaf-like test
  certs with OpenSSL, accepts raw TCP, peeks/parses ClientHello SNI, chooses a
  `SecurityContext`, then calls `SecureSocket.secureServer(...,
  bufferedData: consumedBytes)`. Clients receive `/CN=alpha.test` and
  `/CN=beta.test` respectively, and complete an HTTPS-like request/response.
  This proves the per-SNI + replay mechanism is viable, not the full parser or
  cert minting. The same run advertised `supportedProtocols: ['http/1.1']` on
  both sides but observed `selectedProtocol == null` at client and server.
  Cause: the per-host server contexts did not call
  `setAlpnProtocols(['http/1.1'], true)`. With that call, both ends report
  `http/1.1`. ALPN is not a blocker.
* `tool/spikes/raw_http_connect_spike.dart`: **raw preservation works with a
  custom byte parser; dart:io `HttpServer` is insufficient**. Its parsed
  `HttpHeaders` output lowercased `X-MiXeD`, retained duplicate values but
  returned no raw API and not input order. The paired raw `Socket` parser kept
  `Host`, `X-MiXeD`, `x-mixed`, `X-Order-B`, `X-Order-A` as written and returned
  the ten post-header bytes (`16 03 01 00 05 01 02 03 04 05`) unchanged as the
  CONNECT `head`. This is a focused mechanics spike, not a hardened parser.

## Decisions (founder, 2026-10-13)

1. Certificates: pure Dart, `pointycastle` + `asn1lib`, mapped one-to-one
   onto the upstream `node-forge` calls. No OpenSSL FFI.
2. Trust roots: vendor the Mozilla root list (the source Node bundles; for
   example curl's `cacert.pem`), pinned by version and hash, refreshed per
   release. It replaces Node's `tls.rootCertificates` in a `lib/src/node/tls.dart`
   shim. Platform stores are not used.
3. `Expect: 100-continue`: reproduce Node's default. The server sends
   `100 Continue` automatically unless a `checkContinue` listener exists.
4. ALPN: resolved (see above).

## Open decisions (historical, now resolved above)

1. Certificate implementation: portable `pointycastle` + `asn1lib` vs OpenSSL
   FFI; approve adding dependencies or native packaging work.
2. Trust-root policy: match Node's bundled Mozilla roots in generated child
   bundle (needs a bundled root source), or intentionally use host platform
   roots. `dart:io.SecurityContext.withTrustedRoots` uses the platform store,
   not Node's separately enumerable `rootCertificates`.
3. ALPN: resolved. Dart's `SecureSocket` is sufficient when the server
   context calls `setAlpnProtocols(protocols, true)`.
4. Scope of `Expect: 100-continue` and exact Node duplicate-header combine /
   invalid-header behavior: no direct test currently covers the former, but
   both need fixtures before claiming Node equivalence.
5. Inherited listener fd remains separate from mux's TCP/Unix design and
   requires the FFI path already noted in `PORT_WORKLOG.md`.

## Size estimate

A focused implementation is approximately **1,800–2,700 LOC** of shim source:
`node/net.dart` socket/server/pipe support ~450–700; `node/http.dart` parser,
message, serializer, client request/agent ~900–1,400; `node/socks5_server.dart`
~200–350; TLS ClientHello/ALPN/error adapters and certificate helper
~250–500. Add roughly **800–1,300 LOC** of golden/differential and lifecycle
tests (headers/body parser + persistent requests, CONNECT, abort/half-close,
TLS/SNI/cert chains, SOCKS). The estimate is for the observed API subset; a
general Node `http` implementation would be much larger. Porting all proxy
source/tests is additional and not included.
