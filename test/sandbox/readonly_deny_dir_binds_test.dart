// Ported from sandbox-runtime test/sandbox/readonly-deny-dir-binds.test.ts @ 24eb39e.
// ignore_for_file: slash_for_doc_comments, constant_identifier_names, non_constant_identifier_names, curly_braces_in_flow_control_structures
import 'dart:io' show Directory, Link;

import 'package:path/path.dart' show join;
import 'package:sandbox_runtime/src/sandbox/credential_mask_files.dart'
    show MaskedFileBind;
import 'package:sandbox_runtime/src/node/child_process.dart'
    show SpawnSyncResult, spawnSync;
import 'package:sandbox_runtime/src/node/fs.dart'
    show
        existsSync,
        mkdirSync,
        mkdtempSync,
        readFileSync,
        realpathSync,
        rmSync,
        writeFileSync;
import 'package:sandbox_runtime/src/node/os.dart' show tmpdir;
import 'package:sandbox_runtime/src/node/process.dart' as process;
import 'package:sandbox_runtime/src/sandbox/linux_sandbox_utils.dart'
    show
        LinuxSandboxParams,
        cleanupBwrapMountPoints,
        wrapCommandWithSandboxLinux;
import 'package:sandbox_runtime/src/sandbox/sandbox_manager.dart'
    show PartialSandboxRuntimeConfig, SandboxManager;
import 'package:sandbox_runtime/src/sandbox/sandbox_config.dart'
    show FilesystemConfig, FilesystemPathSpelling;
import 'package:sandbox_runtime/src/sandbox/sandbox_schemas.dart';
import 'package:sandbox_runtime/src/sandbox/sandbox_utils.dart'
    show isAtOrUnder;
import 'package:test/test.dart';

import '../helpers/bwrap_argv.dart' show countMounts, lastMountAt, mountsOf;
import '../helpers/bwrap_namespace.dart' show bwrapCanNamespace;
import '../helpers/captured_warnings.dart' show withCapturedWarnings;
import '../helpers/platform.dart' show isLinux;

void main() {
  /**
   * A deny path strictly beneath a directory that denyWithinAllow re-binds
   * read-only gets no --ro-bind of its own, under the same evidence and vetoes
   * as the absent-path stub skip (readonly-deny-dir-stubs.test.ts); a deny
   * equal to an allowOnly root, or with no covering directory, is still bound.
   */
  group(
    'Deny binds under a read-only denied directory',
    skip: isLinux ? false : 'not Linux',
    () {
      late String BASE;
      late String AREA; // allowed write area
      late String PROJ; // project dir inside AREA
      late String FILE; // existing file under PROJ/sub

      final savedCwd = process.cwd();

      final BWRAP_CAN_NAMESPACE = isLinux && bwrapCanNamespace();

      setUp(() {
        BASE = realpathSync(mkdtempSync(join(tmpdir(), 'ro-deny-bind-')));
        AREA = join(BASE, 'area');
        PROJ = join(AREA, 'proj');
        FILE = join(PROJ, 'sub', 'settings.json');
        mkdirSync(join(PROJ, 'sub'), {'recursive': true});
        writeFileSync(FILE, '{}\n');
        // Keep cwd outside the allowlist so the mandatory-deny scan adds no
        // binds of its own to reason about.
        Directory.current = BASE;
      });

      tearDown(() {
        Directory.current = savedCwd;
        cleanupBwrapMountPoints(force: true);
        rmSync(BASE, {'recursive': true, 'force': true});
      });

      // Same parameter order as readonly-deny-dir-stubs.test.ts, whose fixture
      // and covering-directory predicate this suite shares.
      Future<String> wrap(
        List<String> denyPaths, [
        List<String>? readDenyPaths,
        List<String>? allowPaths,
        String command = 'echo hello',
      ]) async {
        readDenyPaths ??= [];
        allowPaths ??= [AREA];
        return wrapCommandWithSandboxLinux(
          LinuxSandboxParams(
            command: command,
            needsNetworkRestriction: false,
            readConfig: FsReadRestrictionConfig(denyOnly: readDenyPaths),
            writeConfig: FsWriteRestrictionConfig(
              allowOnly: allowPaths,
              denyWithinAllow: denyPaths,
            ),
          ),
        );
      }

      const RUN_TIMEOUT_MS = 15000;

      SpawnSyncResult run(String wrapped) => spawnSync(wrapped, [], {
        'shell': true,
        'encoding': 'utf8',
        'timeout': RUN_TIMEOUT_MS,
        'cwd': BASE,
      });

      // Runs `payload` in the wrapped sandbox behind an `echo BOOTED`, so a bwrap
      // start-up abort cannot read as "the payload was blocked".
      Future<SpawnSyncResult> runSandboxed(
        List<String> denyPaths,
        List<String> readDenyPaths,
        List<String> allowPaths,
        String payload,
      ) async {
        final result = run(
          await wrap(
            denyPaths,
            readDenyPaths,
            allowPaths,
            "sh -c 'echo BOOTED; $payload'",
          ),
        );
        expect(result.stdout, contains('BOOTED'));
        return result;
      }

      /**
       * The write really hit a read-only mount, rather than the command failing
       * for some other reason that also exits non-zero: bwrap refusing to start,
       * or the spawn timing out.
       */
      void expectDeniedByReadOnlyMount(SpawnSyncResult result) {
        expect(result.error, isNull);
        expect(result.status, isNot(0));
        expect(result.stderr, isNot(contains('bwrap:')));
        expect(
          result.stderr,
          contains(RegExp(r'Read-only file system|Permission denied')),
        );
      }

      test(
        'binds the denied allow-root once and skips the existing file beneath it',
        () async {
          // allowOnly=[proj], denyWithinAllow=[proj, proj/sub/file]: the directory
          // deny equals the allow root and must still be emitted; the file is a
          // strict descendant of that read-only bind and needs nothing.
          final command = await wrap([PROJ, FILE], [], [PROJ]);

          expect(countMounts(command, ['--ro-bind', PROJ, PROJ]), 1);
          expect(command, isNot(contains('--ro-bind $FILE $FILE')));
        },
      );

      test(
        'holds the file beneath the covering bind readable and unwritable',
        () async {
          // The covering bind is all that protects FILE: it must still read, and
          // a write through it must fail and change nothing on the host.
          final read = await runSandboxed(
            [PROJ, FILE],
            [],
            [PROJ],
            'cat $FILE',
          );
          expect(read.status, 0);
          expect(read.stdout, contains('{}'));

          final write = await runSandboxed(
            [PROJ, FILE],
            [],
            [PROJ],
            'echo x >> $FILE',
          );
          // The specific failure, not merely a non-zero exit: a bwrap startup
          // abort or a spawn timeout would satisfy that just as well.
          expectDeniedByReadOnlyMount(write);
          expect(readFileSync(FILE, 'utf8'), '{}\n');
        },
        skip: !BWRAP_CAN_NAMESPACE,
      );

      test('is independent of the order the denies are listed in', () async {
        final command = await wrap([FILE, PROJ], [], [PROJ]);

        expect(countMounts(command, ['--ro-bind', PROJ, PROJ]), 1);
        expect(command, isNot(contains('--ro-bind $FILE $FILE')));
      });

      test(
        'still binds the file when its directory is not itself denied',
        () async {
          final command = await wrap([FILE], [], [PROJ]);

          expect(command, contains('--bind $PROJ $PROJ'));
          expect(command, contains('--ro-bind $FILE $FILE'));
        },
      );

      test(
        'collapses a chain of nested directory denies to the outermost bind',
        () async {
          final sub = join(PROJ, 'sub');
          final command = await wrap([PROJ, sub, FILE]);

          expect(countMounts(command, ['--ro-bind', PROJ, PROJ]), 1);
          expect(command, isNot(contains('--ro-bind $sub $sub')));
          expect(command, isNot(contains('--ro-bind $FILE $FILE')));
        },
      );

      test(
        'keeps the descendant bind when an allowed write path under a read-deny tmpfs sits beneath the covering dir (veto)',
        () async {
          // Same veto as the stub skip: an allowWrite beneath PROJ that a denyRead
          // tmpfs also covers is the one shape where anything is mounted inside
          // PROJ after its read-only bind, so the covering bind is not trusted and
          // the explicit deny keeps its own.
          final readDenied = join(PROJ, 'ro');
          final nestedAllow = join(readDenied, 'w');
          mkdirSync(nestedAllow, {'recursive': true});

          final command = await wrap([PROJ, FILE], [readDenied], [
            AREA,
            nestedAllow,
          ]);

          expect(command, contains('--ro-bind $PROJ $PROJ'));
          expect(command, contains('--ro-bind $FILE $FILE'));
        },
      );

      test(
        'skips the descendant bind when the allowed write path beneath the covering dir is buried',
        () async {
          // The veto needs a read-deny tmpfs over the nested allow. With none, the
          // allow's --bind is emitted before the covering read-only bind and stays
          // buried by it, so FILE is already unwritable and needs no bind of its
          // own — and stubbing its absent siblings would abort bwrap.
          final nestedAllow = join(PROJ, 'w');
          mkdirSync(nestedAllow);

          final command = await wrap([PROJ, FILE], [], [AREA, nestedAllow]);

          expect(command, contains('--ro-bind $PROJ $PROJ'));
          expect(command, isNot(contains('--ro-bind $FILE $FILE')));
        },
      );

      test(
        'skips the descendant bind when only a denyRead tmpfs sits under the covering dir',
        () async {
          // The tmpfs is re-applied after PROJ's bind, and what it restores comes
          // back read-only: all it adds under PROJ is a tmpfs whose contents never
          // reach the host, so FILE stays under the read-only bind.
          final readDenied = join(PROJ, 'secrets');
          mkdirSync(readDenied);

          final command = await wrap([PROJ, FILE], [readDenied]);

          final projBind = command.lastIndexOf('--ro-bind $PROJ $PROJ');
          expect(projBind, greaterThan(-1));
          expect(command, isNot(contains('--ro-bind $FILE $FILE')));
          expect(
            command.lastIndexOf('--tmpfs $readDenied'),
            greaterThan(projBind),
          );
        },
      );

      test(
        'keeps the file unwritable when only a denyRead tmpfs sits under the covering dir',
        () async {
          // The runtime half of the skip above: with the descendant bind gone,
          // the covering bind alone must still refuse the write.
          final readDenied = join(PROJ, 'secrets');
          mkdirSync(readDenied);

          final write = await runSandboxed([PROJ, FILE], [readDenied], [
            AREA,
          ], 'echo x >> $FILE');

          expectDeniedByReadOnlyMount(write);
          expect(readFileSync(FILE, 'utf8'), '{}\n');
        },
        skip: !BWRAP_CAN_NAMESPACE,
      );

      test(
        "covers a descendant deny with the root's own bind, and still re-applies the mask",
        () async {
          // allowOnly and denyWithinAllow both naming '/' records it as a
          // read-only deny directory that every path lies beneath. Its own
          // --ro-bind / / lands after both allow binds and holds PROJ read-only,
          // so PROJ's bind is dropped as covered — and that root bind is what the
          // FILE mask's re-application keys off, so the read-denied file is masked
          // again on top of it. Containment has to be root-aware for any of that:
          // a string-prefix comparison ('/' + '/') matched nothing, dropped the
          // root's own deny, and left the file readable.
          final command = await wrap(['/', PROJ], [FILE], ['/', AREA]);

          // Two whole triples: the base root mount, then the deny's own bind. Both
          // the dropped bind and the mask are measured against the SECOND —
          // against the base mount alone the assertions hold even when the deny
          // bind is missing, and that bind is what re-exposes the file.
          expect(countMounts(command, ['--ro-bind', '/', '/']), 2);
          final rootBind = command.lastIndexOf('--ro-bind / /');
          // PROJ's own deny bind is dropped; its ancestor pin, emitted before the
          // root's bind, is a different mount with the same spelling.
          expect(command.indexOf('--ro-bind $PROJ $PROJ', rootBind), -1);
          expect(
            command.lastIndexOf('--ro-bind /dev/null $FILE'),
            greaterThan(rootBind),
          );
        },
      );

      test(
        "keeps the file masked and the directory unwritable under the root's own bind",
        () async {
          final newFile = join(PROJ, 'new.txt');
          final result = run(
            await wrap(
              ['/', PROJ],
              [FILE],
              ['/', AREA],
              '(echo x > $newFile) 2>/dev/null && echo WROTE || echo REFUSED; echo "read:[\$(cat $FILE)]"',
            ),
          );
          expect(result.stderr ?? '', isNot(contains('bwrap:')));
          expect(result.stdout, contains('REFUSED'));
          expect(result.stdout, contains('read:[]'));
          expect(existsSync(newFile), false);
        },
        skip: !BWRAP_CAN_NAMESPACE,
      );

      test(
        'warns that a write deny covers an allowed write path beneath it',
        () async {
          // The deny's read-only bind is emitted after every allow bind, so this
          // shape starts with AREA read-only instead of aborting. Name both paths.
          final (:result, :warnings) = await withCapturedWarnings(
            () => wrap(['/'], [], ['/', AREA]),
          );

          expect(
            warnings.join('\n'),
            contains('Write deny / covers allowed write path $AREA'),
          );
        },
      );

      test(
        'skips the stubs under a write-denied cwd when a recorded "/" is vetoed',
        () async {
          // '/' recorded and vetoed: the allowed write path inside the read-denied
          // directory is both strictly beneath '/' and under that tmpfs. A veto
          // that disqualified every skip would stub each absent mandatory-deny
          // dotfile of the write-denied cwd after the cwd's own bind — the startup
          // abort readonly-deny-dir-stubs.test.ts documents.
          final readDenied = join(AREA, 'ro');
          final nestedAllow = join(readDenied, 'w');
          mkdirSync(nestedAllow, {'recursive': true});
          Directory.current = PROJ;
          final command = await wrap(['/', PROJ], [readDenied], [
            '/',
            AREA,
            nestedAllow,
          ]);

          // Two whole triples: the base root mount, then the deny's read-only bind
          // that holds PROJ and everything else uncreatable.
          expect(countMounts(command, ['--ro-bind', '/', '/']), 2);
          expect(command, isNot(contains('/dev/null $PROJ/')));
          expect(
            command,
            isNot(contains(RegExp(r'--ro-bind \S*claude-empty-\S+ \S*/proj/'))),
          );
        },
      );

      test(
        're-applies a read-deny mask and tmpfs shadowed by a bind of "/" alone',
        () async {
          // '/' is the only emitted deny bind, and it is recursive: it re-exposes
          // every read-denied path underneath, so the mask and the tmpfs must be
          // re-applied on top of it or the file and the directory stay readable.
          final secrets = join(PROJ, 'secrets');
          mkdirSync(secrets);
          final command = await wrap(['/'], [FILE, secrets], ['/']);

          // Two: the base root mount, then the deny bind under test.
          expect(countMounts(command, ['--ro-bind', '/', '/']), 2);
          final rootBind = command.lastIndexOf('--ro-bind / /');
          expect(
            command.lastIndexOf('--ro-bind /dev/null $FILE'),
            greaterThan(rootBind),
          );
          expect(
            command.lastIndexOf('--tmpfs $secrets'),
            greaterThan(rootBind),
          );
        },
      );

      test('does not treat a string-prefix sibling as covered', () async {
        // AREA/proj2/x.txt shares a prefix with AREA/proj without lying beneath
        // it: a plain startsWith would drop its bind and leave it writable.
        final proj2 = join(AREA, 'proj2');
        mkdirSync(proj2);
        final sibling = join(proj2, 'x.txt');
        writeFileSync(sibling, '');

        final command = await wrap([PROJ, sibling]);

        expect(command, contains('--ro-bind $PROJ $PROJ'));
        expect(command, contains('--ro-bind $sibling $sibling'));
      });

      test(
        'emits the root deny that covers a descendant, with no read policy',
        () async {
          // Containment must be root-aware even with readConfig undefined: a
          // string-prefix test ('/' + '/') judges '/' outside its own allowlist
          // and drops the bind that makes the whole tree read-only, leaving PROJ
          // writable with its own bind dropped as covered by it.
          final command = await wrapCommandWithSandboxLinux(
            LinuxSandboxParams(
              command: 'echo hello',
              needsNetworkRestriction: false,
              readConfig: null,
              writeConfig: FsWriteRestrictionConfig(
                allowOnly: ['/', AREA],
                denyWithinAllow: ['/', PROJ],
              ),
            ),
          );

          expect(countMounts(command, ['--ro-bind', '/', '/']), 2);
          expect(command, isNot(contains('--ro-bind $PROJ $PROJ')));
          // The root's own read-only bind is what holds them: it lands after every
          // allow bind, burying them.
          expect(
            command.lastIndexOf('--ro-bind / /'),
            greaterThan(command.indexOf('--bind $AREA $AREA')),
          );
        },
      );

      test(
        'holds the whole tree read-only when the per-path denies under "/" are dropped',
        () async {
          // The runtime half of the drop above, which was argv-only: with PROJ's
          // own bind gone, the root deny's read-only bind is all that stands
          // between the command and the allowed write area, and the denied file
          // must still read (it is read-only, not masked).
          final result = run(
            await wrapCommandWithSandboxLinux(
              LinuxSandboxParams(
                command:
                    "sh -c 'echo BOOTED; touch ${join(AREA, 'x')} 2>/dev/null || echo AREA-READONLY; cat $FILE'",
                needsNetworkRestriction: false,
                readConfig: null,
                writeConfig: FsWriteRestrictionConfig(
                  allowOnly: ['/', AREA],
                  denyWithinAllow: ['/', PROJ],
                ),
              ),
            ),
          );

          expect(result.stderr ?? '', isNot(contains('bwrap:')));
          expect(result.stdout, contains('BOOTED'));
          expect(result.stdout, contains('AREA-READONLY'));
          expect(result.stdout, contains('{}'));
          expect(existsSync(join(AREA, 'x')), false);
        },
        skip: !BWRAP_CAN_NAMESPACE,
      );

      test(
        'does not re-apply a tmpfs over the bind that denies the same directory',
        () async {
          // X in allowOnly, denyWithinAllow and denyRead: the read-only bind of X
          // is not "an ancestor that re-exposes X", so no --tmpfs X --bind X X may
          // follow it and make X writable again.
          final X = join(AREA, 'both');
          mkdirSync(X);
          final command = await wrap([X], [X], [AREA, X]);

          final lastRoBind = command.lastIndexOf('--ro-bind $X $X');
          expect(lastRoBind, greaterThan(-1));
          expect(command.indexOf('--bind $X $X', lastRoBind), -1);
        },
      );

      // A write-deny bind under a read-deny tmpfs is kept at emission BECAUSE an
      // allowed write path restored it. Re-applying that tmpfs over a write-deny
      // bind of an ancestor buries the deny bind again, so the re-application
      // must restore what it covers read-only: everything under it is inside
      // that write deny.
      group('a re-applied read-deny tmpfs restores read-only', () {
        late String RO; // read-denied dir inside PROJ
        late String nestedAllow; // allowed write path inside RO
        late String SECRET; // write-denied file inside nestedAllow
        late String
        UNREADABLE; // read-denied file inside RO, outside nestedAllow

        setUp(() {
          RO = join(PROJ, 'ro');
          nestedAllow = join(RO, 'w');
          mkdirSync(nestedAllow, {'recursive': true});
          SECRET = join(nestedAllow, 'secret.txt');
          writeFileSync(SECRET, 'HOST\n');
          UNREADABLE = join(RO, 'other.txt');
          writeFileSync(UNREADABLE, 'HIDDEN\n');
        });

        test(
          'restores the allow path read-only after the re-applied tmpfs',
          () async {
            final command = await wrap([PROJ, SECRET], [RO], [
              AREA,
              nestedAllow,
            ]);

            final lastTmpfs = command.lastIndexOf('--tmpfs $RO ');
            expect(lastTmpfs, greaterThan(-1));
            expect(
              command.lastIndexOf('--ro-bind $nestedAllow $nestedAllow'),
              greaterThan(lastTmpfs),
            );
            expect(
              command.indexOf('--bind $nestedAllow $nestedAllow', lastTmpfs),
              -1,
            );
          },
        );

        test(
          'leaves the allow path writable when no write deny re-exposes the tmpfs',
          () async {
            // Control: without a deny on PROJ nothing re-applies the tmpfs, so the
            // first pass's writable re-bind of nestedAllow is the last word and
            // only SECRET keeps its own deny bind.
            final command = await wrap([SECRET], [RO], [AREA, nestedAllow]);

            final lastTmpfs = command.lastIndexOf('--tmpfs $RO ');
            expect(lastTmpfs, greaterThan(-1));
            expect(
              command.indexOf('--bind $nestedAllow $nestedAllow', lastTmpfs),
              greaterThan(-1),
            );
            expect(command, contains('--ro-bind $SECRET $SECRET'));
          },
        );

        test(
          'blocks writes under the allow path while its contents stay readable',
          () async {
            final sibling = join(nestedAllow, 'notes.txt');
            writeFileSync(sibling, 'notes\n');

            final result = await runSandboxed(
              [PROJ, SECRET],
              [RO],
              [AREA, nestedAllow],
              'echo x >> $SECRET; echo y >> $sibling; cat $sibling; cat $UNREADABLE',
            );

            expect(result.stdout, contains('notes'));
            // The re-applied tmpfs still hides the read-denied directory around
            // the restored allow path.
            expect(result.stdout, isNot(contains('HIDDEN')));
            expect(readFileSync(SECRET, 'utf8'), 'HOST\n');
            expect(readFileSync(sibling, 'utf8'), 'notes\n');
          },
          skip: !BWRAP_CAN_NAMESPACE,
        );

        test(
          'keeps an allowRead carve-out readable and unwritable across the re-application',
          () async {
            final carveOut = join(RO, 'pub');
            final carveOutFile = join(carveOut, 'note.txt');
            mkdirSync(carveOut);
            writeFileSync(carveOutFile, 'PUBLIC\n');

            final command = await wrapCommandWithSandboxLinux(
              LinuxSandboxParams(
                command:
                    "sh -c 'echo BOOTED; cat $carveOutFile; echo x >> $carveOutFile'",
                needsNetworkRestriction: false,
                readConfig: FsReadRestrictionConfig(
                  denyOnly: [RO],
                  allowWithinDeny: [carveOut],
                ),
                writeConfig: FsWriteRestrictionConfig(
                  allowOnly: [AREA, nestedAllow],
                  denyWithinAllow: [PROJ],
                ),
              ),
            );

            // The carve-out is restored by the re-application, not just by the
            // first pass the deny bind of PROJ buries.
            final lastTmpfs = command.lastIndexOf('--tmpfs $RO ');
            expect(lastTmpfs, greaterThan(-1));
            expect(
              command.lastIndexOf('--ro-bind $carveOut $carveOut'),
              greaterThan(lastTmpfs),
            );

            final result = run(command);

            expect(result.stdout, contains('BOOTED'));
            expect(result.stdout, contains('PUBLIC'));
            expect(readFileSync(carveOutFile, 'utf8'), 'PUBLIC\n');
          },
          skip: !BWRAP_CAN_NAMESPACE,
        );

        test(
          'still writes under the allow path when no write deny re-exposes the tmpfs',
          () async {
            final sibling = join(nestedAllow, 'notes.txt');
            writeFileSync(sibling, 'notes\n');

            await runSandboxed([SECRET], [RO], [
              AREA,
              nestedAllow,
            ], 'echo x >> $SECRET; echo y >> $sibling');

            expect(readFileSync(SECRET, 'utf8'), 'HOST\n');
            expect(readFileSync(sibling, 'utf8'), 'notes\ny\n');
          },
          skip: !BWRAP_CAN_NAMESPACE,
        );

        test(
          'keeps the git hooks and config denies of a repo under the read-denied dir',
          () async {
            // The shape the emission filter's own .git/hooks exception describes:
            // a repo under a read-denied directory, writable, inside a
            // write-denied project.
            final hooks = join(nestedAllow, '.git', 'hooks');
            final config = join(nestedAllow, '.git', 'config');
            mkdirSync(hooks, {'recursive': true});
            writeFileSync(config, '[core]\n');

            await runSandboxed([PROJ, hooks, config], [RO], [
              AREA,
              nestedAllow,
            ], 'echo hook > ${join(hooks, 'pre-commit')}; echo x >> $config');

            expect(existsSync(join(hooks, 'pre-commit')), false);
            expect(readFileSync(config, 'utf8'), '[core]\n');
          },
          skip: !BWRAP_CAN_NAMESPACE,
        );

        // Absent deny paths are listed FIRST in the two cases below, so their
        // placeholder mount points are created while the allow path is still
        // writable and bwrap starts instead of aborting. A placeholder the
        // re-application buries is covered by the read-only restore above it.
        test(
          'keeps an absent deny path uncreatable through its /dev/null stub',
          () async {
            // bwrap leaves the mount point behind as a mode-444 file on the host,
            // so the write has to be preceded by a chmod: on a writable restore
            // its owner may widen the mode and write through it.
            final absent = join(nestedAllow, '.secret');

            await runSandboxed([absent, PROJ], [RO], [
              AREA,
              nestedAllow,
            ], 'chmod u+w $absent; echo pwned > $absent');

            expect(readFileSync(absent, 'utf8'), '');
          },
          skip: !BWRAP_CAN_NAMESPACE,
        );

        test(
          'keeps an absent deny path uncreatable through its empty-dir placeholder',
          () async {
            final placeholder = join(nestedAllow, '.cfg');
            final absent = join(placeholder, 'deep', 'x');

            await runSandboxed([absent, PROJ], [RO], [
              AREA,
              nestedAllow,
            ], 'mkdir -p ${join(placeholder, 'deep')} && echo pwned > $absent');

            expect(existsSync(absent), false);
          },
          skip: !BWRAP_CAN_NAMESPACE,
        );
      });

      // A write-deny bind whose dest is hidden by a read-deny tmpfs is dropped:
      // binding it would expose the read-denied contents. The allowed write paths
      // beneath the dest are a different matter — the read-deny loop re-bound
      // them writable and they are inside that write deny, so they come back
      // read-only.
      group('a write deny dropped as hidden by a read-deny tmpfs', () {
        late String RO; // read-denied dir inside PROJ
        late String DENIED; // write-denied dir inside RO
        late String INNER; // allowed write path inside DENIED
        late String INNER_FILE;
        late String UNREADABLE; // read-denied file inside DENIED, outside INNER

        setUp(() {
          RO = join(PROJ, 'ro');
          DENIED = join(RO, 'x');
          INNER = join(DENIED, 'inner');
          mkdirSync(INNER, {'recursive': true});
          INNER_FILE = join(INNER, 'f');
          writeFileSync(INNER_FILE, 'HOST\n');
          UNREADABLE = join(DENIED, 'other.txt');
          writeFileSync(UNREADABLE, 'SECRET\n');
        });

        test(
          'restores the allow path beneath the dropped dest read-only',
          () async {
            final command = await wrap([DENIED], [RO], [AREA, INNER]);

            expect(command, isNot(contains('--ro-bind $DENIED $DENIED')));
            final lastTmpfs = command.lastIndexOf('--tmpfs $RO ');
            expect(lastTmpfs, greaterThan(-1));
            expect(
              command.lastIndexOf('--ro-bind $INNER $INNER'),
              greaterThan(command.lastIndexOf('--bind $INNER $INNER')),
            );
          },
        );

        test('binds the dest itself when no read deny hides it', () async {
          final command = await wrap([DENIED], [], [AREA, INNER]);

          expect(
            command.lastIndexOf('--ro-bind $DENIED $DENIED'),
            greaterThan(command.lastIndexOf('--bind $INNER $INNER')),
          );
          expect(command, isNot(contains('--ro-bind $INNER $INNER')));
        });

        test(
          'blocks the write beneath the dropped dest without lifting the read deny',
          () async {
            final result = await runSandboxed([DENIED], [RO], [
              AREA,
              INNER,
            ], 'cat $INNER_FILE; echo pwned >> $INNER_FILE; cat $UNREADABLE');

            expect(result.stdout, contains('HOST'));
            expect(result.stdout, isNot(contains('SECRET')));
            expect(readFileSync(INNER_FILE, 'utf8'), 'HOST\n');
          },
          skip: !BWRAP_CAN_NAMESPACE,
        );

        test(
          'keeps a read deny mounted inside the restored allow path',
          () async {
            // The read-only restore lands above the mounts the denyRead loop made
            // under the allow path, so those are re-applied on top of it.
            final nestedReadDeny = join(INNER, 'sub');
            mkdirSync(nestedReadDeny);
            writeFileSync(join(nestedReadDeny, 'token.txt'), 'NESTED\n');

            final result = await runSandboxed([DENIED], [RO, nestedReadDeny], [
              AREA,
              INNER,
            ], 'cat ${join(nestedReadDeny, 'token.txt')}');

            expect(result.stdout, isNot(contains('NESTED')));
          },
          skip: !BWRAP_CAN_NAMESPACE,
        );
      });

      // An allowed write path that IS a masked file is the one restore to skip:
      // its mask already holds it unreadable and unwritable, and a read-only bind
      // of the real file would land above that mask; skipping keeps the mask the
      // last mount on the file instead of relying on the re-application pass. A
      // masked file BENEATH a restored directory is the opposite case and is
      // re-applied.
      group('a write path that is itself a masked file', () {
        const SECRET = 'REAL-PRIVATE-KEY';
        const SENTINEL = 'SENTINEL-NOT-A-KEY';

        late String SECRETS; // read-denied and write-denied dir inside PROJ
        late String
        PEM; // masked file inside SECRETS, and an allowed write path
        late String SUB; // allowed write DIRECTORY inside SECRETS
        late String NESTED; // masked file strictly beneath SUB
        late String PLAIN; // unmasked file beside NESTED
        late String STORE; // fake-file store for the credential mask
        late String FAKE;

        setUp(() {
          SECRETS = join(PROJ, 'secrets');
          mkdirSync(SECRETS, {'recursive': true});
          PEM = join(SECRETS, 'dev.pem');
          writeFileSync(PEM, '$SECRET\n');
          SUB = join(SECRETS, 'sub');
          mkdirSync(SUB);
          NESTED = join(SUB, 'nested.pem');
          writeFileSync(NESTED, '$SECRET\n');
          PLAIN = join(SUB, 'plain.txt');
          writeFileSync(PLAIN, 'PLAIN\n');
          STORE = join(BASE, 'store');
          mkdirSync(STORE, {'recursive': true});
          FAKE = join(STORE, 'dev.pem.fake');
          writeFileSync(FAKE, '$SENTINEL\n');
        });

        // The write deny on SECRETS has to stay hidden by its own tmpfs, with PEM
        // an allowed write path at-or-under it.
        Future<String> readDenyMask() =>
            wrap([SECRETS], [SECRETS, PEM], [AREA, PEM]);

        // Same shape with a credential mask in place of the /dev/null read deny.
        Future<String> credentialMask([String command = 'echo hello']) =>
            wrapCommandWithSandboxLinux(
              LinuxSandboxParams(
                command: command,
                needsNetworkRestriction: false,
                readConfig: FsReadRestrictionConfig(denyOnly: [SECRETS]),
                writeConfig: FsWriteRestrictionConfig(
                  allowOnly: [AREA, PEM],
                  denyWithinAllow: [SECRETS],
                ),
                maskedFileBinds: [
                  MaskedFileBind(realPath: PEM, fakePath: FAKE),
                ],
                maskedFileStoreDir: STORE,
              ),
            );

        test(
          'leaves the /dev/null mask as the last mount on the write path',
          () async {
            final command = await readDenyMask();

            expect(countMounts(command, ['--ro-bind', PEM, PEM]), 0);
            expect(lastMountAt(command, PEM), '--ro-bind /dev/null $PEM');
          },
        );

        test(
          'keeps the read-denied write path unreadable and unwritable',
          () async {
            final read = await runSandboxed([SECRETS], [SECRETS, PEM], [
              AREA,
              PEM,
            ], 'cat $PEM');
            // The whole of stdout, not merely "no secret in it": a read that fails
            // for any other reason satisfies that just as well. No exit-code
            // assertion — binds are mounted nodev, so opening the /dev/null mask
            // may be refused outright.
            expect((read.stdout as String).trim(), 'BOOTED');

            final write = await runSandboxed([SECRETS], [SECRETS, PEM], [
              AREA,
              PEM,
            ], 'echo pwned >> $PEM');
            expectDeniedByReadOnlyMount(write);
            expect(readFileSync(PEM, 'utf8'), '$SECRET\n');
          },
          skip: !BWRAP_CAN_NAMESPACE,
        );

        test(
          'leaves the credential mask as the last mount on the write path',
          () async {
            final command = await credentialMask();

            expect(countMounts(command, ['--ro-bind', PEM, PEM]), 0);
            expect(lastMountAt(command, PEM), '--ro-bind $FAKE $PEM');
          },
        );

        test(
          'serves the fake for a masked credential write path and refuses the write',
          () async {
            final read = run(
              await credentialMask("sh -c 'echo BOOTED; cat $PEM'"),
            );
            expect(read.stdout, contains('BOOTED'));
            expect(read.stdout, contains(SENTINEL));
            expect(read.stdout, isNot(contains(SECRET)));

            final write = run(
              await credentialMask("sh -c 'echo BOOTED; echo pwned >> $PEM'"),
            );
            expect(write.stdout, contains('BOOTED'));
            expectDeniedByReadOnlyMount(write);
            expect(readFileSync(PEM, 'utf8'), '$SECRET\n');
          },
          skip: !BWRAP_CAN_NAMESPACE,
        );

        test(
          're-masks a file strictly beneath a restored write directory',
          () async {
            final command = await wrap([SECRETS], [SECRETS, NESTED], [
              AREA,
              SUB,
            ]);

            expect(countMounts(command, ['--ro-bind', SUB, SUB]), 1);
            // Twice: the denyRead loop's mask, then the re-application on top of the
            // directory's restore. Position, not lastMountAt: both masks are the
            // same triple at the same destination, so only order distinguishes a
            // re-applied mask from one the restore buried.
            expect(countMounts(command, ['--ro-bind', '/dev/null', NESTED]), 2);
            expect(
              command.lastIndexOf('--ro-bind /dev/null $NESTED'),
              greaterThan(command.lastIndexOf('--ro-bind $SUB $SUB')),
            );
          },
        );

        test('keeps the rest of the restored directory readable', () async {
          final result = await runSandboxed([SECRETS], [SECRETS, NESTED], [
            AREA,
            SUB,
          ], 'cat $PLAIN; cat $NESTED');

          expect((result.stdout as String).trim(), 'BOOTED\nPLAIN');
        }, skip: !BWRAP_CAN_NAMESPACE);
      });

      // A symlinked ANCESTOR component makes the spelling a mask is listed under
      // differ from the canonical spelling deny-write dests and allowWrite entries
      // carry. The mask itself goes where the spelling resolves, so every
      // consumer below compares one location; each case hands the decision to a
      // different one.
      group('a mask listed through a symlinked ancestor', () {
        const SECRET = 'REAL-PRIVATE-KEY';
        const SENTINEL = 'SENTINEL-NOT-A-KEY';

        late String DOT; // the real directory PROJ/.claude points into
        late String REAL; // the masked file, canonically
        late String VIA_LINK; // the same file, spelled through PROJ/.claude
        late String STORE;
        late String FAKE;

        setUp(() {
          DOT = join(AREA, 'dotfiles', 'claude');
          mkdirSync(DOT, {'recursive': true});
          REAL = join(DOT, 'secrets.json');
          writeFileSync(REAL, '$SECRET\n');
          // Relative target: an absolute one resolves outside the not-yet-pivoted
          // root and bwrap aborts on the mask's own bind, before any of this.
          Link(
            join(PROJ, '.claude'),
          ).createSync(join('..', 'dotfiles', 'claude'));
          VIA_LINK = join(PROJ, '.claude', 'secrets.json');
          STORE = join(BASE, 'store');
          mkdirSync(STORE);
          FAKE = join(STORE, 'secrets.json.fake');
          writeFileSync(FAKE, '$SENTINEL\n');
        });

        /**
         * The policy that hands the decision to each consumer the cases above
         * cover, for the live arms to walk: the restore inside a deny bind
         * dropped as hidden by its own tmpfs, the flush's own skip where the deny
         * dest IS the masked file, and the mask re-application where a bind of
         * the canonical ancestor directory lands after the mask. The read-deny
         * arm adds VIA_LINK to readDenied; the credential arm masks that spelling
         * with the fake instead.
         */
        List<
          ({
            List<String> denyWrite,
            List<String> readDenied,
            List<String> allow,
          })
        >
        POLICIES() => [
          (denyWrite: [DOT], readDenied: [DOT], allow: [AREA, REAL]),
          (denyWrite: [REAL], readDenied: [], allow: [AREA]),
          (denyWrite: [DOT], readDenied: [], allow: [AREA]),
        ];

        Future<String> credentialWrap(
          List<String> denyWrite,
          List<String> readDenied,
          List<String> allow, [
          String command = 'echo hello',
        ]) => wrapCommandWithSandboxLinux(
          LinuxSandboxParams(
            command: command,
            needsNetworkRestriction: false,
            readConfig: FsReadRestrictionConfig(denyOnly: readDenied),
            writeConfig: FsWriteRestrictionConfig(
              allowOnly: allow,
              denyWithinAllow: denyWrite,
            ),
            maskedFileBinds: [
              MaskedFileBind(realPath: VIA_LINK, fakePath: FAKE),
            ],
            maskedFileStoreDir: STORE,
          ),
        );

        test(
          'keeps the mask when a dropped deny bind restores the file canonically',
          () async {
            final command = await wrap([DOT], [DOT, VIA_LINK], [AREA, REAL]);

            expect(countMounts(command, ['--ro-bind', REAL, REAL]), 0);
            expect(lastMountAt(command, REAL), '--ro-bind /dev/null $REAL');
            expect(lastMountAt(command, VIA_LINK), isNull);
          },
        );

        test(
          'keeps the mask when the deny dest resolves to the masked file',
          () async {
            final command = await wrap([REAL], [VIA_LINK], [AREA]);

            expect(countMounts(command, ['--ro-bind', REAL, REAL]), 0);
            expect(lastMountAt(command, REAL), '--ro-bind /dev/null $REAL');
          },
        );

        test(
          're-applies the mask a bind of the canonical ancestor directory buried',
          () async {
            final command = await wrap([DOT], [VIA_LINK], [AREA]);

            // Twice: the ancestor pin spliced in beneath the allow binds, then the
            // write deny's own bind. Both are self-binds of the same directory and
            // spell the same triple.
            expect(countMounts(command, ['--ro-bind', DOT, DOT]), 2);
            // Twice: the denyRead loop's mask, then the re-application above the
            // directory bind. Only order tells the two apart.
            expect(countMounts(command, ['--ro-bind', '/dev/null', REAL]), 2);
            expect(
              command.lastIndexOf('--ro-bind /dev/null $REAL'),
              greaterThan(command.lastIndexOf('--ro-bind $DOT $DOT')),
            );
          },
        );

        test(
          'reconciles the same three spellings for a credential mask',
          () async {
            final restored = await credentialWrap([DOT], [DOT], [AREA, REAL]);
            expect(countMounts(restored, ['--ro-bind', REAL, REAL]), 0);
            expect(lastMountAt(restored, REAL), '--ro-bind $FAKE $REAL');

            final skipped = await credentialWrap([REAL], [], [AREA]);
            expect(countMounts(skipped, ['--ro-bind', REAL, REAL]), 0);
            expect(lastMountAt(skipped, REAL), '--ro-bind $FAKE $REAL');

            final buried = await credentialWrap([DOT], [], [AREA]);
            expect(countMounts(buried, ['--ro-bind', FAKE, REAL]), 2);
            expect(
              buried.lastIndexOf('--ro-bind $FAKE $REAL'),
              greaterThan(buried.lastIndexOf('--ro-bind $DOT $DOT')),
            );
          },
        );

        test(
          'serves the read-denied file through neither spelling and refuses the write',
          () async {
            for (final (:denyWrite, :readDenied, :allow) in POLICIES()) {
              final read = await runSandboxed(
                denyWrite,
                [...readDenied, VIA_LINK],
                allow,
                'cat $REAL; cat $VIA_LINK',
              );
              expect((read.stdout as String).trim(), 'BOOTED');

              final write = await runSandboxed(
                denyWrite,
                [...readDenied, VIA_LINK],
                allow,
                'echo pwned >> $REAL',
              );
              expectDeniedByReadOnlyMount(write);
              expect(readFileSync(REAL, 'utf8'), '$SECRET\n');
            }
          },
          skip: !BWRAP_CAN_NAMESPACE,
        );

        test(
          'serves the fake through both spellings and refuses the write',
          () async {
            for (final (:denyWrite, :readDenied, :allow) in POLICIES()) {
              final read = run(
                await credentialWrap(
                  denyWrite,
                  readDenied,
                  allow,
                  "sh -c 'echo BOOTED; cat $REAL; cat $VIA_LINK'",
                ),
              );
              expect(
                (read.stdout as String).trim(),
                ['BOOTED', SENTINEL, SENTINEL].join('\n'),
              );

              final write = run(
                await credentialWrap(
                  denyWrite,
                  readDenied,
                  allow,
                  "sh -c 'echo BOOTED; echo pwned >> $REAL'",
                ),
              );
              expect(write.stdout, contains('BOOTED'));
              expectDeniedByReadOnlyMount(write);
              expect(readFileSync(REAL, 'utf8'), '$SECRET\n');
            }
          },
          skip: !BWRAP_CAN_NAMESPACE,
        );
      });

      test(
        'keeps the bind for a deny reached through a symlinked spelling',
        () async {
          // The re-application passes key off emitted raw spellings; a dest that
          // was reached via a symlink keeps its bind so that breadcrumb survives.
          final realSub = join(PROJ, 'sub');
          final linkSub = join(PROJ, 'link');
          Link(linkSub).createSync(realSub);
          final viaLink = join(linkSub, 'settings.json');

          final command = await wrap([PROJ, viaLink]);

          expect(command, contains('--ro-bind $PROJ $PROJ'));
          expect(command, contains('--ro-bind $FILE $FILE'));
        },
      );

      // denyWithinAllow wins over allowOnly however the two are nested. A deny's
      // read-only bind lands after every allow bind and is recursive, so it holds
      // the allowed write paths beneath it too.
      group('a write deny and an allowed write path, by where each lies', () {
        late String SUB; // PROJ/sub, the allowed write path most rows name

        setUp(() {
          SUB = join(PROJ, 'sub');
          mkdirSync(join(AREA, 'other'));
          mkdirSync(join(AREA, 'proj2'));
          Link(join(BASE, 'to-area')).createSync(AREA);
          Link(join(BASE, 'to-proj')).createSync(PROJ);
          Link(join(BASE, 'to-sub')).createSync(SUB);
        });

        List<String> under(List<String> names) =>
            names.map((name) => join(BASE, name)).toList();

        /** The mount that decides `p` in the sandbox: the last at or above it. */
        String? decidingMount(String command, String p) => mountsOf(
          command,
        ).where((mount) => isAtOrUnder(p, mount.split(' ').last)).lastOrNull;

        // Where the deny lies, denyWithinAllow, allowOnly, and the directories
        // that end up read-only and writable; every path is relative to BASE.
        final [A, P, S, O] = [
          'area',
          'area/proj',
          'area/proj/sub',
          'area/other',
        ];
        final PLACEMENTS =
            <(String, List<String>, List<String>, List<String>, List<String>)>[
              ('inside it', [P], [A], [S], [O]),
              ('equal to it', [P], [P], [S], []),
              ('above it', [P], [S], [S], []),
              ('two levels above it', [A], [S], [S], []),
              ('between two of them', [P], [A, S], [S], [O]),
              ('above one and beside another', [P], [O, S], [S], [O]),
              ('above two of them', [A], [O, S], [O, S], []),
              ('beside it', [O], [S], [], [S]),
              ('beside it, its name a prefix', [P], ['${P}2'], [], ['${P}2']),
              ('above it, through a symlink', ['to-proj'], [S], [S], []),
              (
                'above it, through a symlinked parent',
                ['to-area/proj'],
                [S],
                [S],
                [],
              ),
              ('above what it is a symlink to', [P], ['to-sub'], [S], []),
            ];

        for (final (where, deny, allow, readOnly, writable) in PLACEMENTS) {
          test('plans the mounts for a deny $where', () async {
            final command = await wrap(under(deny), [], under(allow));

            for (final dir in under(readOnly)) {
              expect(decidingMount(command, dir), startsWith('--ro-bind '));
            }
            for (final dir in under(writable)) {
              expect(decidingMount(command, dir), startsWith('--bind '));
            }
          });
        }

        for (final (where, deny, allow, readOnly, writable) in PLACEMENTS) {
          test('refuses and takes the writes for a deny $where', () async {
            final files = under([
              ...readOnly,
              ...writable,
            ]).map((d) => join(d, 'new')).toList();

            await runSandboxed(
              under(deny),
              [],
              under(allow),
              files.map((file) => 'echo x > $file').join('; '),
            );

            expect(
              files.where((file) => existsSync(file)).toList(),
              equals(under(writable).map((d) => join(d, 'new')).toList()),
            );
          }, skip: !BWRAP_CAN_NAMESPACE);
        }

        test(
          'mounts nothing for a deny that meets no allowed write path',
          () async {
            final command = await wrap(
              [join(AREA, 'other'), PROJ],
              [],
              ['${PROJ}2'],
            );

            expect(
              mountsOf(command).where((mount) => mount.contains(AREA)).toList(),
              equals(['--bind ${PROJ}2 ${PROJ}2']),
            );
          },
        );

        test('names the deny and the allowed write path beneath it', () async {
          final (:result, :warnings) = await withCapturedWarnings(
            () => wrap([PROJ], [], [SUB]),
          );

          expect(
            warnings.join('\n'),
            contains('Write deny $PROJ covers allowed write path $SUB'),
          );
        });

        test(
          'binds "/" again over the allowed write paths when "/" is denied',
          () async {
            final command = await wrap(['/'], [], [SUB]);

            // Two: the base root mount, then the deny's.
            expect(countMounts(command, ['--ro-bind', '/', '/']), 2);
            expect(decidingMount(command, SUB), '--ro-bind / /');
          },
        );

        test('starts with "/" denied, and nothing is writable', () async {
          await runSandboxed(['/'], [], [SUB], 'echo x > ${join(SUB, 'new')}');

          expect(existsSync(join(SUB, 'new')), false);
        }, skip: !BWRAP_CAN_NAMESPACE);

        // An absent deny path beneath the covered write path is uncreatable, and
        // bubblewrap could not make a mount point for it on a read-only mount.
        group('with absent deny paths in the allowed write path', () {
          List<List<String>> orders() {
            final denies = [PROJ, join(SUB, '.secret'), join(SUB, 'a', 'b')];
            return [
              denies,
              [...denies].reversed.toList(),
            ];
          }

          test('gives them no mount point, in either order', () async {
            for (final denies in orders()) {
              expect(
                mountsOf(
                  await wrap(denies, [], [SUB]),
                ).where((mount) => mount.contains(BASE)).toList(),
                equals(['--bind $SUB $SUB', '--ro-bind $PROJ $PROJ']),
              );
            }
          });

          test('starts and keeps them uncreatable, in either order', () async {
            for (final denies in orders()) {
              await runSandboxed(
                denies,
                [],
                [SUB],
                'echo x > ${join(SUB, '.secret')}; mkdir -p ${join(SUB, 'a', 'b')}',
              );

              expect(existsSync(join(SUB, '.secret')), false);
              expect(existsSync(join(SUB, 'a')), false);
            }
          }, skip: !BWRAP_CAN_NAMESPACE);

          test(
            'starts in an allowed working directory beneath the deny',
            () async {
              // The mandatory denies of the working directory are such paths.
              Directory.current = SUB;

              final command = await wrap([PROJ], [], [SUB], 'echo BOOTED');

              expect(command, isNot(contains('/dev/null $SUB/')));
              expect(run(command).stdout, contains('BOOTED'));
            },
            skip: !BWRAP_CAN_NAMESPACE,
          );
        });

        // A placeholder is bubblewrap's mount point for an absent deny path, made
        // on the host. A path that only covered write paths hold gets none, read
        // denies or not: nothing can create it, and nothing is left on the host.
        group('with the working directory in the allowed write path', () {
          late String
          ABSENT; // a configured deny path, absent like the dotfiles

          setUp(() {
            ABSENT = join(SUB, '.secret');
            Directory.current = SUB;
          });

          List<String> placeholdersIn(String command, String dir) =>
              mountsOf(command)
                  .where(
                    (m) => RegExp(
                      r'^--ro-bind (/dev/null|\S*claude-empty-\S+) ',
                    ).hasMatch(m),
                  )
                  .map((mount) => mount.split(' ').last)
                  .where((dest) => isAtOrUnder(dest, dir))
                  .toList();

          Future<String> wrapHere(
            List<String> denyWithinAllow,
            List<String> denyOnly,
            List<String> allowOnly, [
            String command = 'echo hello',
          ]) => wrapCommandWithSandboxLinux(
            LinuxSandboxParams(
              command: command,
              needsNetworkRestriction: false,
              readConfig: FsReadRestrictionConfig(
                denyOnly: denyOnly,
                allowWithinDeny: [SUB],
              ),
              writeConfig: FsWriteRestrictionConfig(
                allowOnly: allowOnly,
                denyWithinAllow: denyWithinAllow,
              ),
            ),
          );

          String attempt() =>
              "sh -c 'echo BOOTED; cat $FILE; for f in new .secret .bashrc; do echo x > $SUB/\$f; done'";

          // The read deny, relative to BASE, and how the write path is spelled.
          final READ_DENIES = <(String, List<String>, String)>[
            ('no read deny', [], S),
            ('a read deny at the write deny', [A], S),
            ('a read deny at the write deny, the write path "."', [A], '.'),
            ('a read deny above the write deny', ['.'], S),
            ('a read deny between the two', [P], S),
          ];

          for (final (name, readDenied, root) in READ_DENIES) {
            test('plans no placeholder with $name', () async {
              final command = await wrapHere(
                [AREA, ABSENT],
                under(readDenied),
                root == '.' ? ['.'] : under([root]),
              );

              expect(placeholdersIn(command, BASE), equals([]));
              expect(decidingMount(command, ABSENT), startsWith('--ro-bind '));
            });
          }

          for (final (name, readDenied, root) in READ_DENIES) {
            test(
              'runs read-only and leaves the host as it is with $name',
              () async {
                final result = run(
                  await wrapHere(
                    [AREA, ABSENT],
                    under(readDenied),
                    root == '.' ? ['.'] : under([root]),
                    attempt(),
                  ),
                );

                expect(result.stderr, isNot(contains('bwrap:')));
                expect(result.stdout, 'BOOTED\n{}\n');
                expect(_readdirNames(SUB), equals(['settings.json']));
              },
              skip: !BWRAP_CAN_NAMESPACE,
            );
          }

          test('plans them with a read deny and no write deny above', () async {
            final planned = placeholdersIn(
              await wrapHere([ABSENT], [AREA], [SUB]),
              BASE,
            );

            expect(planned, contains(ABSENT));
            expect(planned, contains(join(SUB, '.bashrc')));
          });

          test(
            'writes beside them with a read deny and no write deny above, and the clean-up removes them',
            () async {
              final result = run(
                await wrapHere([ABSENT], [AREA], [SUB], attempt()),
              );

              expect(result.stdout, 'BOOTED\n{}\n');
              expect(readFileSync(ABSENT, 'utf8'), '');
              cleanupBwrapMountPoints();
              expect(
                (_readdirNames(SUB)..sort()),
                equals(['new', 'settings.json']),
              );
            },
            skip: !BWRAP_CAN_NAMESPACE,
          );
        });

        // The other side of that rule: a path that any write path with no deny
        // directory above it holds can be created, and keeps its placeholder.
        for (final (name, readDenied) in <(String, List<String>)>[
          ('no read deny', []),
          ('a read deny above them all', [A]),
        ])
          group('with an absent deny path, by what holds it, and $name', () {
            setUp(() {
              mkdirSync(join(SUB, 'deeper'));
              mkdirSync(join(AREA, 'proj2', 'in'));
            });

            // denyWithinAllow's directories, allowOnly, the directory of the absent
            // deny path, and whether that directory ends up writable.
            final D = '$S/deeper';
            final HOLDERS =
                <(String, List<String>, List<String>, String, bool)>[
                  ('a covered write path', [P], [S], S, false),
                  ('two covered write paths', [P], [S, D], D, false),
                  ('one covered twice', [A, P], [S], S, false),
                  (
                    'one covered, a prefix beside it',
                    ['${P}2'],
                    [P, '${P}2/in'],
                    '${P}2/in',
                    false,
                  ),
                  ('one beside the deny', [P], [S, O], O, true),
                  (
                    'one beside it, its name a prefix',
                    [P],
                    [S, '${P}2'],
                    '${P}2',
                    true,
                  ),
                  ('one above the deny, beside it', [S], [P], P, true),
                ];

            for (final (name, deny, allow, dir, writable) in HOLDERS) {
              test('plans for one that $name holds', () async {
                final absent = join(BASE, dir, '.secret');
                final command = await wrap(
                  [...under(deny), absent],
                  under(readDenied),
                  under(allow),
                );

                expect(
                  countMounts(command, ['--ro-bind', '/dev/null', absent]),
                  writable ? 1 : 0,
                );
                expect(
                  decidingMount(command, absent),
                  startsWith('--ro-bind '),
                );
              });
            }

            for (final (name, deny, allow, dir, writable) in HOLDERS) {
              test('keeps one that $name holds uncreatable', () async {
                final absent = join(BASE, dir, '.secret');

                await runSandboxed(
                  [...under(deny), absent],
                  under(readDenied),
                  under(allow),
                  'echo x > $absent; echo x > ${join(BASE, dir, 'new')}',
                );
                cleanupBwrapMountPoints();

                expect(existsSync(absent), false);
                expect(existsSync(join(BASE, dir, 'new')), writable);
              }, skip: !BWRAP_CAN_NAMESPACE);
            }
          });

        // Each wrap plans from its own configuration and the host as it finds it.
        group('with the deny above there for one command and not the next', () {
          for (final (name, commands) in <(String, List<bool>)>[
            ('first', [true, false]),
            ('second', [false, true]),
          ])
            test('plans each command on its own, there $name', () async {
              final absent = join(SUB, '.secret');
              for (final covered in commands) {
                rmSync(join(SUB, 'new'), {'force': true});

                final command = await SandboxManager.wrapWithSandbox(
                  'echo BOOTED; echo x > $absent; echo x > ${join(SUB, 'new')}',
                  null,
                  PartialSandboxRuntimeConfig(
                    filesystem: FilesystemConfig(
                      denyRead: [],
                      allowWrite: [FilesystemPathSpelling(SUB)],
                      denyWrite: [
                        for (final p in covered ? [PROJ, absent] : [absent])
                          FilesystemPathSpelling(p),
                      ],
                    ),
                  ),
                );
                expect(
                  countMounts(command, ['--ro-bind', '/dev/null', absent]),
                  covered ? 0 : 1,
                );
                expect(run(command).stdout, contains('BOOTED'));

                // A mount point stays on the host until the clean-up, empty.
                expect(
                  _readdirNames(SUB)..sort(),
                  equals(
                    covered
                        ? ['settings.json']
                        : ['.secret', 'new', 'settings.json'],
                  ),
                );
                if (!covered) expect(readFileSync(absent, 'utf8'), '');
                SandboxManager.cleanupAfterCommand();
                expect(existsSync(absent), false);
              }
            }, skip: !BWRAP_CAN_NAMESPACE);
        });

        // The mandatory denies follow the same rule as the configured ones.
        group('with the working directory outside every allowed write path', () {
          for (final name in [
            '.git/hooks',
            '.vscode',
            '.idea',
            '.claude/commands',
            '.claude/agents',
          ])
            test(
              'holds an allowed write path beneath $name read-only',
              () async {
                final inner = join(BASE, name, 'inner');
                mkdirSync(inner, {'recursive': true});

                final command = await wrap([], [], [inner]);

                expect(
                  decidingMount(command, inner),
                  '--ro-bind ${join(BASE, name)} ${join(BASE, name)}',
                );
              },
            );

          test('leaves an allowed write path beside them writable', () async {
            final objects = join(BASE, '.git', 'objects');
            mkdirSync(objects, {'recursive': true});
            mkdirSync(join(BASE, '.git', 'hooks'));

            final command = await wrap([], [], [objects]);

            expect(decidingMount(command, objects), '--bind $objects $objects');
          });

          test(
            'refuses a write beneath .git/hooks and takes one beside it',
            () async {
              final inner = join(BASE, '.git', 'hooks', 'inner');
              final objects = join(BASE, '.git', 'objects');
              mkdirSync(inner, {'recursive': true});
              mkdirSync(objects);

              await runSandboxed(
                [],
                [],
                [inner, objects],
                'echo x > ${join(inner, 'new')}; echo x > ${join(objects, 'new')}',
              );

              expect(existsSync(join(inner, 'new')), false);
              expect(existsSync(join(objects, 'new')), true);
            },
            skip: !BWRAP_CAN_NAMESPACE,
          );
        });

        // The deny's bind shows the host's directory again, everything the read
        // section hid beneath it included, so all of that goes back on top of it:
        // each tmpfs with what it restores, then the file masks.
        group('with read denies beneath the deny', () {
          const HIDDEN = 'HIDDEN';
          late String SECRET; // read-denied directory beside SUB
          late String PUB; // allowRead directory inside SECRET
          late String VAULT; // credential-denied directory beside SUB
          late String TOKEN; // read-denied file beside SUB
          late String CRED; // credential-denied file beside SUB
          late String NETRC; // masked credential file beside SUB
          late String PRIVATE; // read-denied directory inside SUB
          late String ENV; // read-denied file inside SUB
          late String STORE;
          late String FAKE;

          setUp(() {
            SECRET = join(PROJ, 'secret');
            PUB = join(SECRET, 'pub');
            VAULT = join(PROJ, 'vault');
            PRIVATE = join(SUB, 'private');
            STORE = join(BASE, 'store');
            for (final dir in [PUB, VAULT, PRIVATE, STORE]) {
              mkdirSync(dir, {'recursive': true});
            }
            TOKEN = join(PROJ, 'token');
            CRED = join(PROJ, 'cred');
            NETRC = join(PROJ, 'netrc');
            ENV = join(SUB, '.env');
            for (final file in [
              TOKEN,
              CRED,
              NETRC,
              ENV,
              join(SECRET, 'key'),
              join(VAULT, 'key'),
              join(PRIVATE, 'key'),
            ]) {
              writeFileSync(file, '$HIDDEN\n');
            }
            writeFileSync(join(PUB, 'note'), 'PUBLIC\n');
            FAKE = join(STORE, 'netrc.fake');
            writeFileSync(FAKE, 'SENTINEL\n');
          });

          Future<String> wrapAll(
            List<String> denyWithinAllow, [
            String command = 'echo hello',
          ]) => wrapCommandWithSandboxLinux(
            LinuxSandboxParams(
              command: command,
              needsNetworkRestriction: false,
              readConfig: FsReadRestrictionConfig(
                denyOnly: [SECRET, VAULT, TOKEN, CRED, PRIVATE, ENV],
                credentialDenyOnly: [VAULT, CRED],
                allowWithinDeny: [PUB],
              ),
              writeConfig: FsWriteRestrictionConfig(
                allowOnly: [SUB],
                denyWithinAllow: denyWithinAllow,
              ),
              maskedFileBinds: [
                MaskedFileBind(realPath: NETRC, fakePath: FAKE),
              ],
              maskedFileStoreDir: STORE,
            ),
          );

          List<String> readSection() => [
            '--tmpfs $SECRET',
            '--ro-bind $PUB $PUB',
            '--tmpfs $VAULT',
            '--tmpfs $PRIVATE',
            '--ro-bind /dev/null $TOKEN',
            '--ro-bind /dev/null $CRED',
            '--ro-bind /dev/null $ENV',
            '--ro-bind $FAKE $NETRC',
          ];

          test(
            'puts every one of them back after the bind, the masks last',
            () async {
              final mounts = mountsOf(await wrapAll([PROJ]));

              expect(
                mounts.sublist(mounts.indexOf('--ro-bind $PROJ $PROJ')),
                equals([
                  '--ro-bind $PROJ $PROJ',
                  ...readSection(),
                  '--ro-bind $STORE $STORE',
                  '--dev /dev',
                  '--proc /proc',
                ]),
              );
            },
          );

          test('mounts each of them once with no write deny above', () async {
            final mounts = mountsOf(await wrapAll([]));

            expect(
              mounts.where((m) => m.contains(PROJ)).toList()..sort(),
              equals(
                [
                  ...['--bind $SUB $SUB', ...readSection()],
                ]..sort(),
              ),
            );
          });

          for (final (name, denied) in <(String, bool)>[
            ('a write deny above', true),
            ('no write deny', false),
          ])
            test('shows none of them with $name', () async {
              final reads = [
                TOKEN,
                CRED,
                ENV,
                join(SECRET, 'key'),
                join(VAULT, 'key'),
                join(PRIVATE, 'key'),
              ];
              final result = run(
                await wrapAll(
                  denied ? [PROJ] : [],
                  "sh -c 'echo BOOTED; cat ${reads.join(' ')} $NETRC ${join(PUB, 'note')} $FILE; echo x > ${join(SUB, 'new')}; echo x >> ${join(PUB, 'note')}; echo x >> $ENV'",
                ),
              );

              expect(result.stderr, isNot(contains('bwrap:')));
              expect(result.stdout, 'BOOTED\nSENTINEL\nPUBLIC\n{}\n');
              expect(existsSync(join(SUB, 'new')), !denied);
              expect(readFileSync(join(PUB, 'note'), 'utf8'), 'PUBLIC\n');
              expect(readFileSync(ENV, 'utf8'), '$HIDDEN\n');
            }, skip: !BWRAP_CAN_NAMESPACE);

          // A read deny at or above the write deny hides it, and binding it would
          // show it: the allowed write path alone comes back, read-only.
          for (final (where, hidden) in <(String, String Function())>[
            ('at', () => PROJ),
            ('above', () => AREA),
          ])
            test('does not bind a deny with a read deny $where it', () async {
              final command = await wrap([PROJ], [hidden(), ENV], [SUB]);

              expect(countMounts(command, ['--ro-bind', PROJ, PROJ]), 0);
              expect(
                decidingMount(command, join(SUB, 'new')),
                '--ro-bind $SUB $SUB',
              );
              expect(decidingMount(command, TOKEN), '--tmpfs ${hidden()}');
              expect(decidingMount(command, ENV), '--ro-bind /dev/null $ENV');
            });

          for (final (where, hidden) in <(String, String Function())>[
            ('at', () => PROJ),
            ('above', () => AREA),
          ])
            test(
              'refuses the write and shows nothing with a read deny $where the deny',
              () async {
                final result = await runSandboxed([PROJ], [hidden(), ENV], [
                  SUB,
                ], 'cat $TOKEN $ENV $FILE; echo x > ${join(SUB, 'new')}');

                expect(result.stdout, 'BOOTED\n{}\n');
                expect(existsSync(join(SUB, 'new')), false);
              },
              skip: !BWRAP_CAN_NAMESPACE,
            );
        });
      });

      /**
       * '/' is a legal allowOnly entry — normalization keeps it — and the allow
       * loop binds it writable. Every deny then depends on the one predicate
       * deciding whether its dest lies inside the write allowlist; a string
       * prefix spells that '//' for a root allow and matches nothing, which
       * drops every deny no other allow entry happens to cover.
       *
       * Mandatory denies are resolved against the cwd, and a '/' allowlist
       * contains the cwd whatever it is, so unlike the suite above these cases
       * reason about them too.
       */
      group('with "/" in the write allowlist', () {
        test(
          'binds a denyWrite file and directory no other allow entry covers',
          () async {
            final denied = join(BASE, 'denied');
            mkdirSync(denied);

            final command = await wrap([FILE, denied], [], ['/']);

            expect(countMounts(command, ['--bind', '/', '/']), 1);
            expect(countMounts(command, ['--ro-bind', FILE, FILE]), 1);
            expect(countMounts(command, ['--ro-bind', denied, denied]), 1);
          },
        );

        test(
          'binds the mandatory denies that exist and stubs the ones that do not',
          () async {
            final bashrc = join(BASE, '.bashrc');
            final hooks = join(BASE, '.git', 'hooks');
            final mcp = join(BASE, '.mcp.json');
            writeFileSync(bashrc, '');
            mkdirSync(hooks, {'recursive': true});

            final command = await wrap([], [], ['/']);

            expect(countMounts(command, ['--ro-bind', bashrc, bashrc]), 1);
            expect(countMounts(command, ['--ro-bind', hooks, hooks]), 1);
            // Absent: blocked from being created rather than bound read-only.
            expect(countMounts(command, ['--ro-bind', '/dev/null', mcp]), 1);
          },
        );

        test(
          'skips every per-path deny when "/" is denied whole, and keeps skipping them when "/" is vetoed',
          () async {
            // allowOnly ['/'] and denyWithinAllow ['/'] and nothing else: '/' is
            // recorded as a covering deny directory, and nothing vetoes it — no
            // allowed write path lies strictly beneath it, and there is no
            // read-deny tmpfs at all. Every other deny, bind and stub alike, is
            // then skipped as already covered, and the deny-side --ro-bind / /
            // after the allow's writable --bind / / is the whole protection.
            // readConfig is undefined rather than { denyOnly: [] } so the implicit
            // /etc/ssh/ssh_config.d deny cannot make the verdict host-dependent.
            final bashrc = join(BASE, '.bashrc');
            final hooks = join(BASE, '.git', 'hooks');
            final mcp = join(BASE, '.mcp.json');
            writeFileSync(bashrc, '');
            mkdirSync(hooks, {'recursive': true});
            Future<String> wrapRoot(
              List<String> allowOnly,
              FsReadRestrictionConfig? readConfig,
            ) => wrapCommandWithSandboxLinux(
              LinuxSandboxParams(
                command: 'echo hello',
                needsNetworkRestriction: false,
                readConfig: readConfig,
                writeConfig: FsWriteRestrictionConfig(
                  allowOnly: allowOnly,
                  denyWithinAllow: ['/'],
                ),
              ),
            );

            final rootDeniedWhole = await wrapRoot(['/'], null);

            expect(countMounts(rootDeniedWhole, ['--bind', '/', '/']), 1);
            // Two: the base root mount, then the deny bind of '/'.
            expect(countMounts(rootDeniedWhole, ['--ro-bind', '/', '/']), 2);
            expect(
              rootDeniedWhole.lastIndexOf('--ro-bind / /'),
              greaterThan(rootDeniedWhole.indexOf('--bind / /')),
            );
            expect(
              countMounts(rootDeniedWhole, ['--ro-bind', bashrc, bashrc]),
              0,
            );
            expect(
              countMounts(rootDeniedWhole, ['--ro-bind', hooks, hooks]),
              0,
            );
            expect(
              countMounts(rootDeniedWhole, ['--ro-bind', '/dev/null', mcp]),
              0,
            );
            expect(rootDeniedWhole, isNot(contains('claude-empty-')));

            // A second allow entry vetoes '/' — it lies strictly beneath it — and
            // so does a single read-deny directory, the re-application's trigger.
            // Neither brings the per-path denies back: the root's own read-only
            // bind still covers every candidate that lies outside the read-deny
            // tmpfs set. What does bring a deny back is a candidate that bind
            // cannot reach — one inside a predicted tmpfs, or a prediction that
            // could not be derived — which readonly-deny-dir-stubs.test.ts covers.
            final secondAllow = await wrapRoot(['/', AREA], null);
            expect(countMounts(secondAllow, ['--ro-bind', bashrc, bashrc]), 0);
            expect(
              countMounts(secondAllow, ['--ro-bind', '/dev/null', mcp]),
              0,
            );

            final readDenied = join(BASE, 'ro');
            mkdirSync(readDenied);
            final oneReadDeny = await wrapRoot([
              '/',
            ], FsReadRestrictionConfig(denyOnly: [readDenied]));
            expect(countMounts(oneReadDeny, ['--ro-bind', bashrc, bashrc]), 0);
            expect(
              countMounts(oneReadDeny, ['--ro-bind', '/dev/null', mcp]),
              0,
            );
          },
        );

        test(
          'boots with "/" denied whole, and the lone deny bind holds the write off',
          () async {
            // The argv arm above pins a single `--ro-bind / /` after the allow's
            // `--bind / /` as the entire protection. Prove bubblewrap agrees:
            // it starts (nothing beneath the read-only root needs creating,
            // because every per-path deny was skipped), the tree it re-binds is
            // readable, and a write through it fails and changes nothing.
            Future<String> wrapRootDeniedWhole(String command) =>
                wrapCommandWithSandboxLinux(
                  LinuxSandboxParams(
                    command: command,
                    needsNetworkRestriction: false,
                    readConfig: null,
                    writeConfig: FsWriteRestrictionConfig(
                      allowOnly: ['/'],
                      denyWithinAllow: ['/'],
                    ),
                  ),
                );

            final write = run(
              await wrapRootDeniedWhole("echo BOOTED; sh -c 'echo x >> $FILE'"),
            );
            expect(write.stdout, contains('BOOTED'));
            expectDeniedByReadOnlyMount(write);
            expect(readFileSync(FILE, 'utf8'), '{}\n');

            final read = run(
              await wrapRootDeniedWhole('echo BOOTED; cat $FILE'),
            );
            expect(read.error, isNull);
            expect(read.stderr, isNot(contains('bwrap:')));
            expect(read.status, 0);
            expect(read.stdout, contains('BOOTED'));
            expect(read.stdout, contains('{}'));
          },
          skip: !BWRAP_CAN_NAMESPACE,
        );

        test('masks a symlinked ancestor of a deny path', () async {
          // A self-referential link: resolveSymlinkedDenyPath gives up and the
          // fail-closed branch masks the symlink component, so it cannot be
          // deleted and recreated as a real directory.
          final loop = join(AREA, 'loop');
          Link(loop).createSync('loop');

          final command = await wrap([join(loop, 'settings.json')], [], ['/']);

          expect(countMounts(command, ['--ro-bind', '/dev/null', loop]), 1);
        });

        test(
          'denies the write at runtime and leaves the rest of the tree writable',
          () async {
            final control = join(AREA, 'control.txt');
            writeFileSync(control, '');

            final denied = run(
              await wrap([FILE], [], ['/'], "sh -c 'echo x >> $FILE'"),
            );
            expectDeniedByReadOnlyMount(denied);
            expect(readFileSync(FILE, 'utf8'), '{}\n');

            final allowed = run(
              await wrap([FILE], [], ['/'], "sh -c 'echo ok >> $control'"),
            );
            expect(allowed.error, isNull);
            expect(allowed.stderr, isNot(contains('bwrap:')));
            expect(allowed.status, 0);
            expect(readFileSync(control, 'utf8'), 'ok\n');
          },
          skip: !BWRAP_CAN_NAMESPACE,
        );
      });
    },
  );
}

// Dart: the shim's readdirSync has no names-only form; this is Node's
// readdirSync(dir) without withFileTypes.
List<String> _readdirNames(String dir) => Directory(
  dir,
).listSync().map((e) => e.path.substring(e.path.lastIndexOf('/') + 1)).toList();
