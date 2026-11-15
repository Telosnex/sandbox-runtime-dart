# sandbox_runtime

Dart port of [Anthropic Sandbox Runtime](https://github.com/anthropics/sandbox-runtime), based on v0.0.83 (`0bbebed0aa9a8e628dc4df8bc30293550a1988eb`).

Provides filesystem and network restrictions for child processes. Import
`package:sandbox_runtime/sandbox_runtime.dart` for the public API, or run
`dart run sandbox_runtime:srt --help` for the CLI.

## Platform requirements

- **macOS:** uses the system `sandbox-exec` command.
- **Linux:** requires bubblewrap and socat. The host must permit unprivileged user namespaces. Build optional native helpers with `tool/build_spawn_helper.dart` and `tool/build_seccomp.dart` (GCC and libseccomp development files required).
- **Windows:** the MXC backend requires an SDK adapter supplied by the embedding application through `windowsMxcSdk`. No MXC SDK is bundled. The srt-win backend is not supported.
- The optional Java proxy agent requires a JDK 17 or later to build with `tool/build_java_proxy_agent.dart`.

This source package does not include prebuilt native helpers. Applications that need them must build and bundle them. Sandbox strength depends on the host platform and configuration; do not assume that unsupported configurations provide isolation.

## Development

Run `dart pub get`, `dart analyze`, and `dart test`.
For port-fidelity tests, check out the upstream baseline above and set
`SRT_UPSTREAM` to its directory. Some platform and optional-tool tests skip
when their prerequisites are absent. CI runs Linux x64/ARM64 and macOS
host suites, plus Windows configuration and fake-SDK tests; it does not
exercise a real Windows MXC installation.

## Releases

pub.dev publishes from `Telosnex/sandbox_runtime_dart`, environment `pub.dev`,
tag pattern `pub-sandbox_runtime-v{{version}}`. Tags use the pubspec version.
The shared Telosnex workflow runs analysis, tests and the pana quality gate
before publication. Upstream watch checks the pinned upstream commit daily.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE) for attribution.
