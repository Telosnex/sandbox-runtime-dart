// Ported from sandbox-runtime test/sandbox/linux-mount-plan-record.test.ts @ 0bbebed.
// ignore_for_file: constant_identifier_names, non_constant_identifier_names, slash_for_doc_comments
import 'package:path/path.dart' show dirname, join;
import 'package:sandbox_runtime/src/node/child_process.dart' show spawnSync;
import 'package:sandbox_runtime/src/node/fs.dart'
    show
        mkdirSync,
        mkdtempSync,
        realpathSync,
        rmSync,
        symlinkSync,
        writeFileSync;
import 'package:sandbox_runtime/src/node/os.dart' show tmpdir;
import 'package:sandbox_runtime/src/node/process.dart' as process;
import 'package:sandbox_runtime/src/sandbox/linux_sandbox_utils.dart'
    show
        LinuxSandboxParams,
        cleanupBwrapMountPoints,
        wrapCommandWithSandboxLinux;
import 'package:sandbox_runtime/src/sandbox/sandbox_schemas.dart'
    show FsReadRestrictionConfig, FsWriteRestrictionConfig;
import 'package:sandbox_runtime/src/utils/ripgrep.dart' show RipgrepConfig;
import 'package:test/test.dart';

import '../helpers/bwrap_argv.dart' show countMounts;
import '../helpers/bwrap_namespace.dart' show bwrapCanNamespace;
import '../helpers/platform.dart' show isLinux;

// Argument-level checks, plus one "(live bwrap)" arm per symlink shape: this
// suite has the densest symlink inputs, and where the emitted mounts land is
// only really settled by bubblewrap.
void main() {
  group(
    'Linux sandbox — mount-plan record and ordering',
    skip: isLinux ? null : 'requires Linux',
    () {
      // Dart: stands for `wrapCommandWithSandboxLinux({ ...baseParams, ... })`;
      // baseParams is { command: 'true', needsNetworkRestriction: false,
      // allowAllUnixSockets: true } and the overrides are its arguments.
      Future<String> wrapWithBase({
        String command = 'true',
        RipgrepConfig? ripgrepConfig,
        FsReadRestrictionConfig? readConfig,
        FsWriteRestrictionConfig? writeConfig,
      }) => wrapCommandWithSandboxLinux(
        LinuxSandboxParams(
          command: command,
          needsNetworkRestriction: false,
          allowAllUnixSockets: true,
          ripgrepConfig: ripgrepConfig,
          readConfig: readConfig,
          writeConfig: writeConfig,
        ),
      );

      // Dart: the group callback runs on every platform; the probe spawns a
      // process, so it runs only on Linux, where upstream's describe.if runs.
      final BWRAP_CAN_NAMESPACE = isLinux && bwrapCanNamespace();
      const BOOTED = 'BOOTED';

      final created = <String>[];
      tearDown(() {
        cleanupBwrapMountPoints(force: true);
        for (final dir in created.toList()) {
          rmSync(dir, {'recursive': true, 'force': true});
        }
        created.clear();
      });

      /**
       * Run a wrapped command and return its stdout, having first established
       * that bubblewrap started at all: an abort would leave every "the secret
       * is not in the output" assertion true for the wrong reason.
       */
      String runBooted(String wrapped) {
        final result = spawnSync(wrapped, [], {
          'shell': true,
          'encoding': 'utf8',
          'timeout': 15000,
        });
        expect(result.stderr ?? '', isNot(contains('bwrap:')));
        expect(result.stdout ?? '', contains(BOOTED));
        return (result.stdout ?? '') as String;
      }

      String tempTree(Map<String, String> files) {
        final proj = realpathSync(mkdtempSync(join(tmpdir(), 'mount-plan-')));
        created.add(proj);
        for (final MapEntry(key: rel, value: content) in files.entries) {
          mkdirSync(dirname(join(proj, rel)), {'recursive': true});
          writeFileSync(join(proj, rel), content);
        }
        return proj;
      }

      test(
        'preserves a carve-out under a denyRead dir when the inner deny mounts later',
        () async {
          final proj = tempTree({'data/build/logs/keep.txt': 'x'});
          final data = join(proj, 'data');
          final build = join(proj, 'data', 'build');
          final logs = join(proj, 'data', 'build', 'logs');
          final wrapped = await wrapWithBase(
            readConfig: FsReadRestrictionConfig(
              denyOnly: [data, logs],
              allowWithinDeny: [],
            ),
            writeConfig: FsWriteRestrictionConfig(
              allowOnly: [build],
              denyWithinAllow: [],
            ),
          );
          // The restore is a second occurrence of the allowWrite bind, after the
          // outer tmpfs; the deeper tmpfs mounts after the restore and on top.
          final bind = '--bind $build $build';
          final restoreIdx = wrapped.lastIndexOf(bind);
          // Space-terminated: data is a string prefix of logs.
          expect(restoreIdx, greaterThan(wrapped.indexOf('--tmpfs $data ')));
          expect(wrapped.indexOf('--tmpfs $logs'), greaterThan(restoreIdx));
        },
      );

      test(
        'restores a write root under a denyRead directory in whichever order a symlink-spelled entry inside it is listed',
        () async {
          final proj = tempTree({
            'a/t/w/secret-dir/s.txt': 'x',
            'a/t/w/deep/file.txt': 'x',
          });
          // secretLink is spelled shallow but lands deep inside the write root.
          final secretLink = join(proj, 's');
          symlinkSync(join(proj, 'a/t/w/secret-dir'), secretLink);
          final deniedDir = join(proj, 'a/t');
          final writeRoot = join(proj, 'a/t/w');
          final file = join(proj, 'a/t/w/deep/file.txt');
          Future<String> plan(List<String> denyOnly) => wrapWithBase(
            readConfig: FsReadRestrictionConfig(
              denyOnly: denyOnly,
              allowWithinDeny: [],
            ),
            writeConfig: FsWriteRestrictionConfig(
              allowOnly: [writeRoot],
              denyWithinAllow: [file],
            ),
          );
          final wrapped = await plan([secretLink, deniedDir]);
          expect(await plan([deniedDir, secretLink]), wrapped);

          // The denied directory is hidden, the write root comes back writable on
          // top of it, and the tmpfs on the secret directory and the deny bind
          // land on top of the write root.
          final writeRootBind = '--bind $writeRoot $writeRoot';
          final deniedTmpfs = wrapped.indexOf('--tmpfs $deniedDir ');
          expect(deniedTmpfs, greaterThan(-1));
          expect(wrapped.lastIndexOf(writeRootBind), greaterThan(deniedTmpfs));
          // The secret directory's tmpfs goes where the link leads, not on the
          // link.
          final secretDir = join(proj, 'a/t/w/secret-dir');
          expect(wrapped, isNot(contains('--tmpfs $secretLink ')));
          expect(
            wrapped.indexOf('--tmpfs $secretDir '),
            greaterThan(wrapped.lastIndexOf(writeRootBind)),
          );
          expect(
            wrapped.indexOf('--ro-bind $file $file'),
            greaterThan(wrapped.lastIndexOf(writeRootBind)),
          );
          // The deny bind's parent is pinned beneath the write root's first bind.
          final deepDir = join(writeRoot, 'deep');
          final deepPin = '--ro-bind $deepDir $deepDir';
          expect(wrapped.indexOf(deepPin), greaterThan(-1));
          expect(
            wrapped.indexOf(deepPin),
            lessThan(wrapped.indexOf(writeRootBind)),
          );
        },
      );

      test('emits a deny bind whose region a later unit re-exposed', () async {
        final proj = tempTree({'p/q/w/.git/config': 'x'});
        final writeRoot = join(proj, 'p/q/w');
        final cfg = join(proj, 'p/q/w/.git/config');
        // p/q hides the write root and restores it; the link and the write root
        // itself each mount a tmpfs there and restore it again, so the host
        // content is on top and the deny bind is still needed.
        symlinkSync(writeRoot, join(proj, 's'));
        final wrapped = await wrapWithBase(
          readConfig: FsReadRestrictionConfig(
            denyOnly: [join(proj, 's'), join(proj, 'p/q'), writeRoot],
            allowWithinDeny: [],
          ),
          writeConfig: FsWriteRestrictionConfig(
            allowOnly: [writeRoot],
            denyWithinAllow: [cfg],
          ),
        );
        final wBind = '--bind $writeRoot $writeRoot';
        expect(
          wrapped.lastIndexOf(wBind),
          greaterThan(wrapped.indexOf('--tmpfs $writeRoot')),
        );
        expect(wrapped, contains('--ro-bind $cfg $cfg'));
        final gitPin =
            '--ro-bind ${join(proj, 'p/q/w/.git')} ${join(proj, 'p/q/w/.git')}';
        expect(wrapped, contains(gitPin));
        // The pin sits beneath W's first (allow) bind and every tmpfs.
        expect(wrapped.indexOf(gitPin), lessThan(wrapped.indexOf(wBind)));
        expect(
          wrapped.indexOf(gitPin),
          lessThan(wrapped.indexOf('--tmpfs $writeRoot')),
        );
      });

      test(
        'resolves a symlink-spelled denyRead directory after the mandatory-deny scan, not before it',
        () async {
          // link points at old/ when the wrap starts and at now/ once the scan (a
          // stand-in for ripgrep that retargets it) has run. bwrap mounts the tmpfs
          // where the link points at spawn time, so the write path beneath that
          // target is the one the tmpfs wipes and the one to restore.
          final proj = tempTree({'old/w/f': 'x', 'now/w/f': 'x'});
          final link = join(proj, 'link');
          symlinkSync(join(proj, 'old'), link);
          final retarget = join(proj, 'retarget.sh');
          writeFileSync(
            retarget,
            '#!/bin/sh\nln -sfn ${join(proj, 'now')} $link\nexit 1\n',
            {'mode': 493},
          );
          final nowW = join(proj, 'now/w');
          final wrapped = await wrapWithBase(
            ripgrepConfig: RipgrepConfig(command: retarget),
            readConfig: FsReadRestrictionConfig(
              denyOnly: [link],
              allowWithinDeny: [],
            ),
            writeConfig: FsWriteRestrictionConfig(
              allowOnly: [nowW],
              denyWithinAllow: [],
            ),
          );
          final bind = '--bind $nowW $nowW';
          expect(
            wrapped.lastIndexOf(bind),
            greaterThan(wrapped.indexOf('--tmpfs $link')),
          );
        },
      );

      test(
        'masks a symlink-spelled file where it resolves, and drops the denyWrite bind naming that location',
        () async {
          // The mask goes to the canonical location, so the write deny on that
          // same location has nothing left to add: /dev/null is read-only, and
          // re-binding the real file on top would undo the mask.
          final proj = tempTree({'data/secrets/key.pem': 'SECRET'});
          symlinkSync(join(proj, 'data/secrets'), join(proj, 'secrets'));
          final rawSpelling = join(proj, 'secrets', 'key.pem');
          final canonical = join(proj, 'data', 'secrets', 'key.pem');
          final wrapped = await wrapWithBase(
            readConfig: FsReadRestrictionConfig(
              denyOnly: [rawSpelling],
              allowWithinDeny: [],
            ),
            writeConfig: FsWriteRestrictionConfig(
              allowOnly: [proj],
              denyWithinAllow: [canonical],
            ),
          );
          expect(wrapped, contains('--ro-bind /dev/null $canonical'));
          expect(wrapped, isNot(contains('--ro-bind /dev/null $rawSpelling')));
          expect(wrapped, isNot(contains('--ro-bind $canonical $canonical')));
        },
      );

      test(
        'emits a deny bind whose raw route is buried but whose canonical location is exposed',
        () async {
          final proj = tempTree({
            'x/W/secret': 'SECRET',
            'z/foo': 'host-content',
          });
          // The deny is spelled through link2, inside x, but its bind mounts at
          // the canonical dest under z, which no tmpfs covers.
          symlinkSync(join(proj, 'x/W/secret'), join(proj, 's'));
          symlinkSync(join(proj, 'z'), join(proj, 'x/W/link2'));
          final canonicalFoo = join(proj, 'z', 'foo');
          final wrapped = await wrapWithBase(
            readConfig: FsReadRestrictionConfig(
              denyOnly: [join(proj, 's'), join(proj, 'x')],
              allowWithinDeny: [],
            ),
            writeConfig: FsWriteRestrictionConfig(
              allowOnly: [proj, join(proj, 'x/W')],
              denyWithinAllow: [join(proj, 'x/W/link2/foo')],
            ),
          );
          expect(
            wrapped,
            contains('--ro-bind /dev/null ${join(proj, 'x/W/secret')}'),
          );
          expect(wrapped, contains('--ro-bind $canonicalFoo $canonicalFoo'));
        },
      );

      test(
        'pins the canonical parents of a symlink-spelled denyRead file mask beneath the mask, which is emitted once',
        () async {
          final proj = tempTree({
            'data/secrets/key.pem': 'SECRET',
            'data/other/thing.txt': 'x',
          });
          symlinkSync(join(proj, 'data/secrets'), join(proj, 'secrets'));
          final rawSpelling = join(proj, 'secrets', 'key.pem');
          final canonicalParent = join(proj, 'data', 'secrets');
          final wrapped = await wrapWithBase(
            readConfig: FsReadRestrictionConfig(
              denyOnly: [rawSpelling],
              allowWithinDeny: [],
            ),
            writeConfig: FsWriteRestrictionConfig(
              allowOnly: [proj],
              denyWithinAllow: [join(proj, 'data/other/thing.txt')],
            ),
          );
          final parentPin = '--ro-bind $canonicalParent $canonicalParent';
          final dataPin =
              '--ro-bind ${join(proj, 'data')} ${join(proj, 'data')}';
          expect(wrapped, contains(parentPin));
          expect(wrapped, contains(dataPin));
          final maskBind =
              '--ro-bind /dev/null ${join(canonicalParent, 'key.pem')}';
          final first = wrapped.indexOf(maskBind);
          expect(first, greaterThan(-1));
          // No pin lands over the mask, so it is never re-applied.
          expect(wrapped.lastIndexOf(maskBind), first);
          expect(wrapped.indexOf(parentPin), lessThan(first));
          expect(
            wrapped.indexOf(dataPin),
            lessThan(wrapped.indexOf('--bind $proj $proj')),
          );
        },
      );

      // The merged-/usr shape: lib -> usr/lib, denyRead lib, allowRead lib/x.
      ({String proj, String lib, Future<String> Function(String command) wrap})
      mergedUsrCarveOut() {
        final proj = tempTree({
          'usr/lib/x/lib.so': 'LIBSOBYTES\n',
          'usr/lib/y/other': 'OTHERBYTES\n',
        });
        final lib = join(proj, 'lib');
        symlinkSync('usr/lib', lib);
        final carveOut = join(lib, 'x');
        return (
          proj: proj,
          lib: lib,
          wrap: (String command) => wrapWithBase(
            command: command,
            readConfig: FsReadRestrictionConfig(
              denyOnly: [lib],
              allowWithinDeny: [carveOut],
            ),
            writeConfig: FsWriteRestrictionConfig(
              allowOnly: [],
              denyWithinAllow: [],
            ),
          ),
        );
      }

      test(
        'restores an allowRead carve-out spelled through a symlink whose target lies inside the denied directory',
        () async {
          final (:proj, :lib, :wrap) = mergedUsrCarveOut();

          final wrapped = await wrap('true');

          // Bound where it resolves: after the tmpfs, lib/x is a plain path on it.
          final resolved = join(proj, 'usr/lib/x');
          final restore = '--ro-bind $resolved $resolved';
          expect(
            wrapped.indexOf(restore),
            greaterThan(wrapped.indexOf('--tmpfs $lib ')),
          );
        },
      );

      test(
        'restores an allowRead carve-out spelled through a symlink whose target lies inside the denied directory (live bwrap)',
        skip: !BWRAP_CAN_NAMESPACE ? 'bwrap cannot create namespaces' : null,
        () async {
          final (:proj, :lib, :wrap) = mergedUsrCarveOut();

          final stdout = runBooted(
            await wrap(
              "sh -c 'echo $BOOTED; cat ${join(lib, 'x/lib.so')} 2>&1; cat ${join(lib, 'y/other')} 2>&1'",
            ),
          );

          expect(stdout, contains('LIBSOBYTES'));
          expect(stdout, isNot(contains('OTHERBYTES')));
        },
      );

      // The merged-/usr root expansion: bin -> usr/bin, both denied. After the
      // tmpfs on usr, bin dangles in the new root and bwrap cannot mount on it.
      ({String bin, String usr, Future<String> Function(String command) wrap})
      mergedUsrBothDenied() {
        final proj = tempTree({
          'usr/bin/tool': 'TOOLBYTES\n',
          'usr/share/doc': 'DOCBYTES\n',
        });
        final bin = join(proj, 'bin');
        symlinkSync('usr/bin', bin);
        final usr = join(proj, 'usr');
        return (
          bin: bin,
          usr: usr,
          wrap: (String command) => wrapWithBase(
            command: command,
            readConfig: FsReadRestrictionConfig(
              denyOnly: [bin, usr],
              allowWithinDeny: [],
            ),
            writeConfig: FsWriteRestrictionConfig(
              allowOnly: [],
              denyWithinAllow: [],
            ),
          ),
        );
      }

      test(
        'emits one mount for a symlinked entry whose target an earlier tmpfs already hides',
        () async {
          // bin resolves to usr/bin, which the tmpfs on usr already hides, so a
          // second mount there would be created inside that tmpfs and change
          // nothing. Mounting on the link itself is what bubblewrap 0.12 refuses.
          final (:bin, :usr, :wrap) = mergedUsrBothDenied();

          final wrapped = await wrap('true');

          expect(wrapped, contains('--tmpfs $usr '));
          expect(wrapped, isNot(contains('--tmpfs ${join(usr, 'bin')} ')));
          expect(wrapped, isNot(contains('--tmpfs $bin ')));
        },
      );

      test(
        'spells a read-deny mount by where it lands once an earlier tmpfs has hidden its symlink target (live bwrap)',
        skip: !BWRAP_CAN_NAMESPACE ? 'bwrap cannot create namespaces' : null,
        () async {
          final (:bin, :usr, :wrap) = mergedUsrBothDenied();

          final stdout = runBooted(
            await wrap(
              "sh -c 'echo $BOOTED; cat ${join(bin, 'tool')} 2>&1; cat ${join(usr, 'share/doc')} 2>&1'",
            ),
          );

          expect(stdout, isNot(contains('TOOLBYTES')));
          expect(stdout, isNot(contains('DOCBYTES')));
        },
      );

      ({String denied, Future<String> Function(String command) wrap})
      carveOutUnderSymlinkedParent() {
        final proj = tempTree({
          'var/home/u/work/f': 'WORKBYTES\n',
          'var/home/u/secret': 'SECRETBYTES\n',
        });
        symlinkSync('var/home', join(proj, 'home'));
        final denied = join(proj, 'home/u');
        return (
          denied: denied,
          wrap: (String command) => wrapWithBase(
            command: command,
            readConfig: FsReadRestrictionConfig(
              denyOnly: [denied],
              allowWithinDeny: [join(denied, 'work')],
            ),
            writeConfig: FsWriteRestrictionConfig(
              allowOnly: [],
              denyWithinAllow: [],
            ),
          ),
        );
      }

      test(
        'restores an allowRead carve-out under a denied directory reached through a symlinked parent',
        () async {
          final wrapped = await carveOutUnderSymlinkedParent().wrap('true');

          final restore = RegExp(
            r'--ro-bind (\S+\/u\/work) \1',
          ).firstMatch(wrapped);
          expect(restore, isNotNull);
          expect(
            wrapped.indexOf(restore![0]!),
            greaterThan(wrapped.indexOf('--tmpfs ')),
          );
        },
      );

      test(
        'restores an allowRead carve-out under a denied directory reached through a symlinked parent (live bwrap)',
        skip: !BWRAP_CAN_NAMESPACE ? 'bwrap cannot create namespaces' : null,
        () async {
          final (:denied, :wrap) = carveOutUnderSymlinkedParent();

          final stdout = runBooted(
            await wrap(
              "sh -c 'echo $BOOTED; cat ${join(denied, 'work/f')} 2>&1; cat ${join(denied, 'secret')} 2>&1'",
            ),
          );

          expect(stdout, contains('WORKBYTES'));
          expect(stdout, isNot(contains('SECRETBYTES')));
        },
      );

      test(
        'does not bind an allowRead symlink whose target lies outside the denied directory',
        () async {
          final proj = tempTree({'d/keep': 'x', 'elsewhere/secret': 's'});
          final link = join(proj, 'd/link');
          symlinkSync(join(proj, 'elsewhere'), link);
          final wrapped = await wrapWithBase(
            readConfig: FsReadRestrictionConfig(
              denyOnly: [join(proj, 'd')],
              allowWithinDeny: [link],
            ),
            writeConfig: FsWriteRestrictionConfig(
              allowOnly: [],
              denyWithinAllow: [],
            ),
          );
          expect(wrapped, contains('--tmpfs ${join(proj, 'd')} '));
          expect(wrapped, isNot(contains('--ro-bind $link $link')));
        },
      );

      // A command run earlier (or the repository) plants docs -> home/.ssh at an
      // allowed path: the entry names the link, not what it points at.
      ({String ssh, String docs, Future<String> Function(String command) wrap})
      plantedAllowReadLink() {
        final proj = tempTree({
          'home/.ssh/id_rsa': 'PRIVATEKEYBYTES\n',
          'proj/src.ts': 'x',
        });
        final ssh = join(proj, 'home/.ssh');
        final docs = join(proj, 'proj/docs');
        symlinkSync(ssh, docs);
        return (
          ssh: ssh,
          docs: docs,
          wrap: (String command) => wrapWithBase(
            command: command,
            readConfig: FsReadRestrictionConfig(
              denyOnly: [ssh],
              allowWithinDeny: [docs],
            ),
            writeConfig: FsWriteRestrictionConfig(
              allowOnly: [join(proj, 'proj')],
              denyWithinAllow: [],
            ),
          ),
        );
      }

      test(
        'does not restore an allowRead entry that is a symlink into a read-denied directory',
        () async {
          final (:ssh, :docs, :wrap) = plantedAllowReadLink();

          final wrapped = await wrap('true');

          expect(wrapped, contains('--tmpfs $ssh '));
          expect(wrapped, isNot(contains('--ro-bind $ssh $ssh')));
          expect(wrapped, isNot(contains('--ro-bind $docs ')));
        },
      );

      test(
        'does not restore an allowRead entry that is a symlink into a read-denied directory (live bwrap)',
        skip: !BWRAP_CAN_NAMESPACE ? 'bwrap cannot create namespaces' : null,
        () async {
          final (:ssh, :docs, :wrap) = plantedAllowReadLink();

          final stdout = runBooted(
            await wrap(
              "sh -c 'echo $BOOTED; cat ${join(docs, 'id_rsa')} 2>&1; cat ${join(ssh, 'id_rsa')} 2>&1'",
            ),
          );

          expect(stdout, isNot(contains('PRIVATEKEYBYTES')));
        },
      );

      test(
        'does not restore a file inside a read-denied directory through a symlink planted outside it',
        () async {
          final proj = tempTree({
            'home/.aws/credentials': 'SECRET',
            'proj/a': 'x',
          });
          final aws = join(proj, 'home/.aws');
          final credentials = join(aws, 'credentials');
          final cfg = join(proj, 'proj/cfg.json');
          symlinkSync(credentials, cfg);
          final wrapped = await wrapWithBase(
            readConfig: FsReadRestrictionConfig(
              denyOnly: [aws],
              allowWithinDeny: [cfg],
            ),
            writeConfig: FsWriteRestrictionConfig(
              allowOnly: [join(proj, 'proj')],
              denyWithinAllow: [],
            ),
          );
          expect(wrapped, contains('--tmpfs $aws '));
          expect(
            wrapped,
            isNot(contains('--ro-bind $credentials $credentials')),
          );
        },
      );

      test(
        'keeps a file mask when the allowRead entry is a symlink to the file, even one the deny list names too',
        () async {
          // sub/.env.example -> ../.env, matched by an allowRead glob and by a
          // denyRead glob: the deny lands on .env (bwrap cannot bind onto a link),
          // and the allow names the link, so nothing lifts it.
          final proj = tempTree({'.env': 'SECRET', 'sub/keep': 'x'});
          final env = join(proj, '.env');
          final planted = join(proj, 'sub/.env.example');
          symlinkSync('../.env', planted);
          final viaLink = await wrapWithBase(
            readConfig: FsReadRestrictionConfig(
              denyOnly: [planted],
              allowWithinDeny: [planted],
            ),
            writeConfig: FsWriteRestrictionConfig(
              allowOnly: [proj],
              denyWithinAllow: [],
            ),
          );
          expect(viaLink, contains('--ro-bind /dev/null $env'));
          final direct = await wrapWithBase(
            readConfig: FsReadRestrictionConfig(
              denyOnly: [env],
              allowWithinDeny: [planted],
            ),
            writeConfig: FsWriteRestrictionConfig(
              allowOnly: [proj],
              denyWithinAllow: [],
            ),
          );
          expect(direct, contains('--ro-bind /dev/null $env'));
        },
      );

      test(
        'still lifts a file mask for an allowRead entry naming that file through a symlinked directory',
        () async {
          final proj = tempTree({'real/.env.example': 'ok'});
          symlinkSync(join(proj, 'real'), join(proj, 'link'));
          final file = join(proj, 'real/.env.example');
          final wrapped = await wrapWithBase(
            readConfig: FsReadRestrictionConfig(
              denyOnly: [file],
              allowWithinDeny: [join(proj, 'link/.env.example')],
            ),
            writeConfig: FsWriteRestrictionConfig(
              allowOnly: [proj],
              denyWithinAllow: [],
            ),
          );
          expect(wrapped, isNot(contains('--ro-bind /dev/null $file')));
        },
      );

      test(
        'still hides a root child under a root deny when an allowRead entry is a symlink to it',
        () async {
          final proj = tempTree({'proj/a': 'x'});
          final docs = join(proj, 'proj/docs');
          symlinkSync('/etc', docs);
          final wrapped = await wrapWithBase(
            readConfig: FsReadRestrictionConfig(
              denyOnly: ['/'],
              allowWithinDeny: [docs],
            ),
            writeConfig: FsWriteRestrictionConfig(
              allowOnly: [join(proj, 'proj')],
              denyWithinAllow: [],
            ),
          );
          expect(wrapped, contains('--tmpfs /etc '));
          expect(wrapped, isNot(contains('--ro-bind /etc /etc')));
        },
      );

      test(
        'denies the target of a read-deny symlink whose route an earlier tmpfs hid, and drops the write deny the tmpfs covers',
        () async {
          // home/u/sec -> work/proj/secrets, and home/u is hidden first. The entry
          // is mounted where it resolves, so the secrets directory is hidden even
          // though the route that named it is inside the first tmpfs. The write
          // deny under it then needs no bind: writes into a tmpfs never reach the
          // host, and re-binding the host directory would undo the read deny.
          final proj = tempTree({
            'work/proj/secrets/token': 'T',
            'work/proj/src.ts': 'x',
            'home/u/other': 'o',
          });
          final secrets = join(proj, 'work/proj/secrets');
          symlinkSync(secrets, join(proj, 'home/u/sec'));
          final token = join(secrets, 'token');
          final wrapped = await wrapWithBase(
            readConfig: FsReadRestrictionConfig(
              denyOnly: [join(proj, 'home/u'), join(proj, 'home/u/sec')],
              allowWithinDeny: [],
            ),
            writeConfig: FsWriteRestrictionConfig(
              allowOnly: [join(proj, 'work/proj')],
              denyWithinAllow: [token],
            ),
          );
          expect(wrapped, contains('--tmpfs $secrets '));
          expect(wrapped, isNot(contains('--ro-bind $token $token')));
        },
      );

      test(
        'masks the target of a read-deny file symlink whose route an earlier tmpfs hid',
        () async {
          final proj = tempTree({'data/key': 'K', 'home/u/x': 'x'});
          symlinkSync(join(proj, 'data'), join(proj, 'home/u/lnk'));
          final key = join(proj, 'data/key');
          final wrapped = await wrapWithBase(
            readConfig: FsReadRestrictionConfig(
              denyOnly: [join(proj, 'home/u'), join(proj, 'home/u/lnk/key')],
              allowWithinDeny: [],
            ),
            writeConfig: FsWriteRestrictionConfig(
              allowOnly: [join(proj, 'data')],
              denyWithinAllow: [key],
            ),
          );
          // The mask is stronger than the write deny at the same place, so that
          // bind is dropped rather than landing on top of it.
          expect(wrapped, contains('--ro-bind /dev/null $key'));
          expect(wrapped, isNot(contains('--ro-bind $key $key')));
        },
      );

      test('seeds pins from a read-denied directory', () async {
        final proj = tempTree({
          'other/secrets/key.pem': 'K',
          'other/readme': 'r',
        });
        final secrets = join(proj, 'other/secrets');
        final wrapped = await wrapWithBase(
          readConfig: FsReadRestrictionConfig(
            denyOnly: [secrets],
            allowWithinDeny: [],
          ),
          writeConfig: FsWriteRestrictionConfig(
            allowOnly: [proj],
            denyWithinAllow: [],
          ),
        );
        final pin = '--ro-bind ${join(proj, 'other')} ${join(proj, 'other')}';
        expect(wrapped.indexOf(pin), greaterThan(-1));
        expect(
          wrapped.indexOf(pin),
          lessThan(wrapped.indexOf('--bind $proj $proj')),
        );
        expect(wrapped, contains('--tmpfs $secrets '));
      });

      test(
        're-applies an allowRead carve-out that contains a deeper read-deny, then the deeper deny',
        () async {
          final proj = tempTree({
            'cfg/private/pub/readme': 'r',
            'cfg/private/pub/sec/k': 'k',
          });
          final cfg = join(proj, 'cfg');
          final priv = join(proj, 'cfg/private');
          final pub = join(proj, 'cfg/private/pub');
          final sec = join(proj, 'cfg/private/pub/sec');
          final wrapped = await wrapWithBase(
            readConfig: FsReadRestrictionConfig(
              denyOnly: [priv, sec],
              allowWithinDeny: [pub],
            ),
            writeConfig: FsWriteRestrictionConfig(
              allowOnly: [proj],
              denyWithinAllow: [cfg],
            ),
          );
          // cfg is pinned as well as denied; the deny bind is the later of the two.
          final afterDeny = wrapped.substring(
            wrapped.lastIndexOf('--ro-bind $cfg $cfg'),
          );
          final privIdx = afterDeny.indexOf('--tmpfs $priv ');
          final pubIdx = afterDeny.indexOf('--ro-bind $pub $pub');
          final secIdx = afterDeny.indexOf('--tmpfs $sec ');
          expect(privIdx, greaterThan(-1));
          expect(pubIdx, greaterThan(privIdx));
          expect(secIdx, greaterThan(pubIdx));
        },
      );

      test(
        'denies beneath a writable root, and pins above its bind under one writable cover',
        () async {
          // '/' is a legal allowOnly entry, and the allow loop binds it writable,
          // so the denies inside it apply — which needs the containment test to be
          // root-aware, a plain string prefix having matched nothing there and
          // silently dropped every deny over a root already bound read-write.
          //
          // The pins cannot sit beneath that root's own recursive --bind / /,
          // which would bury them. They go after the allow binds, stopping below
          // the top-level directory, which a writable --bind takes over them.
          final savedCwd = process.cwd();
          // An explicit two-deep tree: with the ambient cwd a direct child of '/'
          // (a checkout at /src, WORKDIR /app) the parent pin IS the cover.
          final proj = tempTree({'work/proj/keep.txt': 'x'});
          final cwd = join(proj, 'work', 'proj');
          final top = '/${proj.split('/')[1]}';
          process.chdir(cwd);
          try {
            final wrapped = await wrapWithBase(
              writeConfig: FsWriteRestrictionConfig(
                allowOnly: ['/'],
                denyWithinAllow: [],
              ),
            );
            final rootBind = wrapped.indexOf('--bind / /');
            final parentPin = wrapped.indexOf(
              '--ro-bind ${dirname(cwd)} ${dirname(cwd)}',
            );
            final cwdPin = wrapped.indexOf('--ro-bind $cwd $cwd');
            final cover = wrapped.indexOf('--bind $top $top');
            for (final idx in [rootBind, parentPin, cwdPin, cover]) {
              expect(idx, greaterThan(-1));
            }
            expect(wrapped, contains(' ${join(cwd, '.bashrc')}'));
            // Read-only pins under one writable cover: a read-only cover would
            // make the whole top-level directory read-only.
            expect(wrapped, isNot(contains('--ro-bind $top $top')));
            expect(parentPin, greaterThan(rootBind));
            expect(cwdPin, greaterThan(parentPin));
            expect(cover, greaterThan(cwdPin));
            // The deny binds still land on top of the cover.
            expect(
              wrapped.indexOf('--ro-bind /dev/null ${join(cwd, '.bashrc')}'),
              greaterThan(cover),
            );
          } finally {
            process.chdir(savedCwd);
          }
        },
      );

      test(
        'stubs no absent path after a read-only root when the root is both allowed and denied',
        () async {
          // bwrap cannot create a stub's mount point on a read-only '/', so one
          // emitted here stops the sandbox from starting. Now that a '/' write
          // root contains the paths beneath it, the deny of '/' is emitted as a
          // second, read-only bind after the allow's writable one, and that is
          // what makes the whole tree uncreatable: the absent cwd dotfiles are
          // covered by it and need no stub of their own. The read-denied directory
          // is the exception the guard keeps — its tmpfs is writable inside.
          final proj = tempTree({'hidden/x': 'x'});
          final wrapped = await wrapWithBase(
            readConfig: FsReadRestrictionConfig(
              denyOnly: [join(proj, 'hidden')],
              allowWithinDeny: [],
            ),
            writeConfig: FsWriteRestrictionConfig(
              allowOnly: ['/'],
              denyWithinAllow: ['/'],
            ),
          );
          // Two: the base root mount, then the deny bind that holds it read-only.
          expect(countMounts(wrapped, ['--ro-bind', '/', '/']), 2);
          expect(wrapped, contains('--tmpfs ${join(proj, 'hidden')} '));
          expect(
            wrapped,
            isNot(contains('/dev/null ${join(process.cwd(), '.bashrc')}')),
          );
          expect(
            wrapped,
            isNot(contains('--ro-bind ${process.cwd()} ${process.cwd()}')),
          );
        },
      );
    },
  );
}
