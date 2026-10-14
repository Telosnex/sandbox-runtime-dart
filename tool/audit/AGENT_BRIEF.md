# Test fidelity pass: brief for every agent

Repo: this one (Dart port). Upstream: ../sandbox-runtime (or $SRT_UPSTREAM) @ 24eb39e.
Read PORT_WORKLOG.md first: Rule 1, Rule 1a, Rule 1b, "Conventions" (especially
"Tests", "Test shape", "Comments", "Assertions in test declarations",
"Property tests", "Bun branches") and "Audit findings still open".

Goal: each test file you own must diff against its upstream file by eye.
- Same describe/it titles, same order (group/test).
- Every upstream comment kept, at the same place, including comments inside
  test bodies. `{@link X}` -> `[X]`, `**\/` -> `**/` in `///` comments.
- Test bodies in upstream's shape, statement for statement. Do NOT factor
  bodies into Dart-only helpers; inline them back if a previous port did.
  Upstream's own helpers (functions defined in the upstream test file) are
  ported under the same names, in the same order.
- A test that needs a module not ported yet keeps its full upstream body as
  `//` lines of the upstream TS text (never an empty `() {}`), and has
  `skip: 'pending port: src/<path>.ts'` in exactly that format.
- Do not change lib/ code. If a test needs a lib change, stop and report it.
- Do not touch files you do not own; other agents are
  editing other test files in the same checkout at the same time. Never
  revert or reformat anyone else's work. Never run `git add -A` / `git add .`
  / `git commit -a`, `git commit --amend`, `git reset`, `git rebase`, `git stash`, `git checkout <file>` on files you do not own.
- `lib/src/node/mozilla_roots.dart` may show as modified after `dart format`
  or builds; leave it alone (do not commit it).

Checks (run them until clean):
- `python3 tool/audit/comments.py <name-fragment>` lists upstream comment
  lines (12+ chars) missing from your Dart file. Target: none missing, except
  Bun-only comments where Rule 1 allows (say which in your report).
- `python3 tool/audit/titles.py <name-fragment>` must say OK for your file.
- `dart analyze <file>` clean, `dart format <file>`.
- `dart test <file>` passes (skips allowed only as above, or for platform
  conditions upstream also has). Run it 3 times if it touches sockets/timing.

Commit when your file is clean: `git add <your paths>` only, then
`git commit -m "<file>: restore upstream shape and comments"` (author is
already configured). If git reports index.lock, wait a few seconds and retry.
Do not edit PORT_WORKLOG.md; put anything the worklog should record in your
final report (suspected upstream bugs, gaps, lib changes you needed).

Before you report, rerun comments.py and titles.py after your last edit;
report their actual output. Never add a comment upstream does not have.

Final report: per file, comments found/total before and after, titles OK,
test counts (pass/skip), commit hash, and anything left undone and why.
Keep it short.
