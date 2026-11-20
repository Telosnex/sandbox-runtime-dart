## 0.0.85

- Shorten the package description, add a runnable sandbox example, and fix analyzer lints.

## 0.0.84

- Fix `execFileSync`/`spawnSync` on macOS sometimes failing with `ECHILD` when
  the child exited quickly. The child now starts suspended until its exit
  watch is registered.

## 0.0.83

- Port Anthropic Sandbox Runtime v0.0.83 to Dart.
- Support macOS and Linux sandbox backends and an injectable Windows MXC SDK adapter.
- Add public-repository CI, pub.dev publication and daily upstream checks.
