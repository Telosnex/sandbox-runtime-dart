# Port audit tools

No upstream counterpart. Dart only. Upstream is read from
`../sandbox-runtime`, or from `$SRT_UPSTREAM`.

## In `dart test`

`test/port/fidelity_test.dart` fails when:

- a test or tool file is missing an upstream comment;
- a test file's titles differ from upstream's, or are out of order (two
  intended differences are listed in the test, with the exact titles
  expected);
- a header names an upstream file that does not exist, or that maps to a
  different Dart file name.

It skips when the upstream checkout is absent. `lib/` files are not checked
for comments: PARTIAL and STUB ports lack them by design (see Known port gaps
in PORT_WORKLOG.md).

## Commands

| Command | Does |
|---|---|
| `dart run tool/audit/comments.dart [fragment]` | Per ported file, upstream comment lines kept (12+ characters, after normalizing `{@link X}` -> `[X]` and `**\/`). With a fragment, lists the missing lines of matching files. |
| `dart run tool/audit/titles.dart [fragment \| all]` | Per test file, titles against upstream's (`%s` and `$x` both count as a placeholder). With a fragment or `all`, prints the difference. |
| `dart run tool/audit/headers.dart` | Per Dart file, its header, upstream file and comment-line counts; exits 1 on a bad header. |
| `dart run tool/audit/ts2dart.dart <upstream .test.ts> > test/x_test.dart` | First draft of a test port. See below. |

`AGENT_BRIEF.md` is the brief for agents restoring or porting test files.

## ts2dart

Rewrites text; it does not parse TypeScript. The draft keeps upstream's
statements, order, titles and comments, and gets the header, the Dart
imports for upstream src/ and test/ files, `describe`/`it`/`test` with
their `.if`/`.skipIf`/`.skip`/`.todo`/`.each` forms, `expect` matchers,
object-literal keys, regex literals, template literals and semicolons.
Types, spies, local functions and anything it does not know are left for
the porter: an unknown matcher becomes `TODO_<name>(...)` and an unknown
test option `/* TODO(ts2dart) ... */`, so `dart analyze` finds them.

Checked on 2026-10-13 against all 119 upstream test files: none fails to
translate, and every draft keeps all upstream titles and comments.
`config-validation.test.ts` drafts with 47 analyzer errors (the Python
version left 51, before its header and imports were written by hand).

Workflow: draft, then `dart analyze` and fix, then `dart test test/port`
and the file's own tests.
