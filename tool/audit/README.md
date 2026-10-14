# Port audit tools

No upstream counterpart. Python 3, no dependencies. Upstream is read from
`../sandbox-runtime`, or from `$SRT_UPSTREAM`.

| Script | Checks |
|---|---|
| `comments.py [name-fragment]` | Every upstream comment line of 12+ characters appears in the Dart file (after normalizing `{@link X}` -> `[X]` and `**\/`). Lists what is missing. |
| `titles.py [name-fragment \| all]` | `describe`/`it`/`test` titles match upstream, in order (`group`/`test` in Dart; `%s` and `$x` both count as a placeholder). |
| `audit.py` | Every Dart file's header (`Ported from` / `STUB` / `PARTIAL`) names an upstream file that exists, at the pinned commit, with the matching name. |
| `ts2dart.py <file.test.ts>` | Rough first draft of a test port, to stdout. Needs hand fixes; see its docstring. |
| `AGENT_BRIEF.md` | The brief given to agents in the test fidelity pass. |

Expected output on a clean tree (2026-10-13):

- `comments.py`: no test or tool file missing anything. The lib files it
  lists are PARTIAL or STUB ports (`request_filter`, `parent_proxy`,
  `mux_proxy`...) or are listed under Known port gaps in PORT_WORKLOG.md.
- `titles.py all`: `NOHEADER` for `test/node/` and `test/differential/` (no
  upstream counterpart); `aws_sigv4_test` has one extra test (upstream's
  describe-level vector count); `which_node_test` wraps a standalone script
  in one test.
