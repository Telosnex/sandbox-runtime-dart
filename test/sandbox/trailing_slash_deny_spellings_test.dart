// Ported from sandbox-runtime test/sandbox/trailing-slash-deny-spellings.test.ts @ 0bbebed.
// ignore_for_file: constant_identifier_names, non_constant_identifier_names, slash_for_doc_comments, no_leading_underscores_for_local_identifiers, unintended_html_in_doc_comment
import 'package:path/path.dart' show join;
import 'package:sandbox_runtime/src/node/fs.dart' as fs;
import 'package:sandbox_runtime/src/node/os.dart' show tmpdir;
import 'package:sandbox_runtime/src/node/process.dart' as process;
import 'package:sandbox_runtime/src/sandbox/linux_sandbox_utils.dart'
    show
        LinuxSandboxParams,
        cleanupBwrapMountPoints,
        wrapCommandWithSandboxLinux;
import 'package:sandbox_runtime/src/sandbox/macos_sandbox_utils.dart'
    show MacOSSandboxParams, wrapCommandWithSandboxMacOS;
import 'package:sandbox_runtime/src/sandbox/sandbox_schemas.dart'
    show FsReadRestrictionConfig, FsWriteRestrictionConfig;
import 'package:sandbox_runtime/src/sandbox/sandbox_utils.dart'
    show normalizePathForSandbox;
import 'package:test/test.dart';

import '../helpers/platform.dart' show isLinux, isWindows;

/**
 * Trailing-slash spellings.
 *
 * The sandbox builders compare path spellings by exact match and
 * `path + '/'` prefixes, which a preserved trailing slash silently defeats
 * ('<dir>//' matches nothing). normalizePathForSandbox therefore strips
 * trailing slashes from non-glob spellings at the shared chokepoint, so
 * every consumer on the Linux and macOS paths sees one canonical form.
 * Confirmed pre-fix failure modes covered below:
 *
 * - Linux denyRead '<dir>/': records a tmpfs the hidden-by-tmpfs emission
 *   filter can never match, so a denyWrite bind beneath it is emitted AFTER
 *   the tmpfs and re-mounts the read-denied host contents readable.
 * - Linux allowWithinDeny + allowOnly sharing a slashed spelling: the
 *   re-allow skip in the tmpfs re-bind pass depends on both sides using the
 *   same spelling, or an extra ro-bind stacks over the writable re-bind and
 *   the allowed write dir becomes read-only (EROFS).
 * - macOS allowWithinDeny '<dir>/': the nested-deny re-emit never matches,
 *   so last-match-wins re-allows an explicitly denied nested path.
 *
 * Glob spellings are deliberately untouched (a slash after a glob segment
 * is semantic), as is Windows (a trailing separator there is the directory
 * marker for absent deny targets). The glob a trailing slash compiles to
 * matches nothing: harmless as an allow, which is why an allow still takes
 * it, and rejected at config validation as a deny.
 */

void main() {
  group('normalizePathForSandbox trailing slashes', () {
    // Pure string work on the POSIX spellings below, so it runs on Linux and
    // macOS alike. Gated off Windows only because the strip is deliberately
    // skipped there (see the header).
    test(
      'strips non-glob spellings, keeps globs and root',
      skip: !isWindows ? null : 'it.if(!isWindows)',
      () {
        expect(normalizePathForSandbox('/data/secrets/'), '/data/secrets');
        expect(normalizePathForSandbox('/data/secrets//'), '/data/secrets');
        expect(normalizePathForSandbox('/'), '/');
        // Glob spellings keep their trailing slash — it changes glob semantics.
        expect(normalizePathForSandbox('/data/*/'), '/data/*/');
        expect(normalizePathForSandbox('/data/**/'), '/data/**/');
        // Empty input means the cwd, like any other relative spelling, and is
        // not rewritten into the filesystem root. Anchored to the cwd itself:
        // comparing two outputs of the function under test would hold just as
        // well for a normaliser that answered '/' to everything.
        expect(normalizePathForSandbox(''), process.cwd());
      },
    );
  });

  group(
    'Linux: trailing-slash spellings',
    skip: isLinux ? null : 'describe.if(isLinux)',
    () {
      // realpathSync so exact-string assertions hold even when tmpdir itself
      // contains symlinks.
      late String BASE;
      late String AREA;
      late String SECRETS;
      late String SUB;

      setUp(() {
        BASE = fs.realpathSync(fs.mkdtempSync(join(tmpdir(), 'slash-deny-')));
        AREA = join(BASE, 'area');
        SECRETS = join(AREA, 'secrets');
        SUB = join(SECRETS, 'sub');
        fs.mkdirSync(SUB, {'recursive': true});
        fs.writeFileSync(join(SUB, 'token'), 'x\n');
      });

      tearDown(() {
        cleanupBwrapMountPoints(force: true);
        fs.rmSync(BASE, {'recursive': true, 'force': true});
      });

      for (final (_label, suffix) in [('plain', ''), ('trailing-slash', '/')]) {
        test(
          'drops a denyWrite bind hidden by a read-deny tmpfs ($_label spelling)',
          () async {
            final denyRead = '$SECRETS$suffix';

            final command = await wrapCommandWithSandboxLinux(
              LinuxSandboxParams(
                command: 'true',
                needsNetworkRestriction: false,
                readConfig: FsReadRestrictionConfig(denyOnly: [denyRead]),
                writeConfig: FsWriteRestrictionConfig(
                  allowOnly: [AREA],
                  denyWithinAllow: [SUB],
                ),
              ),
            );

            // The tmpfs mounts at the slash-free spelling either way (the trailing
            // space pins the full argument; the slashed spelling must not appear).
            expect(command, contains('--tmpfs $SECRETS '));
            expect(command, isNot(contains('--tmpfs $SECRETS/ ')));
            // The denyWrite bind under the read-denied dir is dropped as
            // hidden-by-the-tmpfs: emitting it after the tmpfs would re-mount the
            // read-denied host contents readable inside the sandbox.
            expect(command, isNot(contains('--ro-bind $SUB $SUB')));
          },
        );
      }

      test(
        'does not stack a ro-bind over an allowed write dir named by a slashed carve-out (EROFS shape)',
        () async {
          // The same directory appears (naturally, by copy-paste) as a
          // trailing-slash spelling in both allowWithinDeny and allowOnly. The
          // re-allow skip in the tmpfs re-bind pass compares the two lists; with
          // inconsistent spellings it misses and emits --ro-bind <data> <data> on
          // top of the writable re-bind, turning the allowed write dir read-only.
          final data = join(SECRETS, 'data');
          fs.mkdirSync(data);
          fs.writeFileSync(join(data, 'out.txt'), 'x\n');

          final command = await wrapCommandWithSandboxLinux(
            LinuxSandboxParams(
              command: 'true',
              needsNetworkRestriction: false,
              readConfig: FsReadRestrictionConfig(
                denyOnly: [SECRETS],
                allowWithinDeny: ['$data/'],
              ),
              writeConfig: FsWriteRestrictionConfig(
                allowOnly: [AREA, '$data/'],
                denyWithinAllow: [],
              ),
            ),
          );

          final writableRebind = command.lastIndexOf('--bind $data $data');
          expect(writableRebind, greaterThanOrEqualTo(0));
          // The ro-bind must be absent, or land before the writable re-bind — last
          // mount wins. `lastIndexOf` returns -1 when absent, which reads as
          // "before" given the precondition above.
          final roStack = command.lastIndexOf('--ro-bind $data $data');
          expect(roStack, lessThan(writableRebind));
        },
      );
    },
  );

  // Profile GENERATION is pure string building, so these assertions run under
  // Linux too even though the profile only executes under macOS sandbox-exec.
  // Windows is excluded: the chokepoint keeps the trailing separator there, so
  // the carve-out would not reach the profile in its slash-free spelling.
  group(
    'macOS profile: trailing-slash allowWithinDeny spelling',
    skip: !isWindows ? null : 'describe.if(!isWindows)',
    () {
      for (final (_label, suffix) in [('plain', ''), ('trailing-slash', '/')]) {
        test(
          're-emits a nested literal deny after the carve-out allow ($_label spelling)',
          () {
            final profile = wrapCommandWithSandboxMacOS(
              MacOSSandboxParams(
                command: 'true',
                needsNetworkRestriction: false,
                readConfig: FsReadRestrictionConfig(
                  denyOnly: ['/work/priv', '/work/priv/pub/secret'],
                  allowWithinDeny: ['/work/priv/pub$suffix'],
                ),
                writeConfig: null,
              ),
            );

            // The carve-out allow rule uses the slash-free subpath spelling.
            const allowRule = '(allow file-read*\n  (subpath "/work/priv/pub")';
            final allowIdx = profile.indexOf(allowRule);
            expect(allowIdx, greaterThanOrEqualTo(0));
            // Last-match-wins: the more-specific nested deny must land AFTER the
            // allow rule, or the carve-out silently re-allows it.
            final lastDenyIdx = profile.lastIndexOf(
              '(deny file-read*\n  (subpath "/work/priv/pub/secret")',
            );
            expect(lastDenyIdx, greaterThan(allowIdx));
          },
        );
      }

      test(
        'keeps glob carve-out spellings untouched (no dead-to-live regex flip)',
        () {
          // A glob carve-out ending in '/' compiles to whatever regex its author
          // wrote; the chokepoint must not rewrite it into a broader one.
          final profile = wrapCommandWithSandboxMacOS(
            MacOSSandboxParams(
              command: 'true',
              needsNetworkRestriction: false,
              readConfig: FsReadRestrictionConfig(
                denyOnly: ['/work/priv'],
                allowWithinDeny: ['/work/priv/pub/*/'],
              ),
              writeConfig: null,
            ),
          );
          expect(profile, contains('/work/priv/pub/[^/]*/\$'));
        },
      );
    },
  );
}
