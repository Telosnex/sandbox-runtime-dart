// Ported from sandbox-runtime test/sandbox/linux-unmakeable-mount-point.test.ts @ 0bbebed.

// ignore_for_file: no_leading_underscores_for_local_identifiers, curly_braces_in_flow_control_structures, prefer_function_declarations_over_variables
// ignore_for_file: constant_identifier_names, non_constant_identifier_names, slash_for_doc_comments, prefer_adjacent_string_concatenation, unnecessary_brace_in_string_interps, empty_statements, prefer_interpolation_to_compose_strings
import 'dart:convert';
import 'dart:io' show Platform;
import 'package:test/test.dart';
import 'package:sandbox_runtime/src/node/child_process.dart';
import 'package:sandbox_runtime/src/node/fs.dart' as fs;
import 'package:sandbox_runtime/src/node/errno.dart';
import 'package:sandbox_runtime/src/node/os.dart';
import 'package:sandbox_runtime/src/node/path.dart';
import 'package:sandbox_runtime/src/node/process.dart' as process;
import 'package:sandbox_runtime/src/sandbox/sandbox_schemas.dart';
import 'package:sandbox_runtime/src/sandbox/linux_sandbox_utils.dart';
import '../helpers/platform.dart';
import '../helpers/bwrap_argv.dart';
import '../helpers/bwrap_namespace.dart';

// upstream: import * as fs from 'fs'
// upstream: import { spawnSync } from 'node:child_process'
// upstream: import { basename, dirname, join } from 'node:path'
// upstream: import { tmpdir } from 'node:os'

final REPO_ROOT = process.cwd();
const V9FS_MAGIC = 0x01021997;

// The originals, for the stand-ins below to fall through to.
final real = {
  'accessSync': fs.accessSync,
  'chmodSync': fs.chmodSync,
  'closeSync': fs.closeSync,
  'fstatSync': fs.fstatSync,
  'mkdirSync': fs.mkdirSync,
  'openSync': fs.openSync,
  'readlinkSync': fs.readlinkSync,
  'statfsSync': fs.statfsSync,
};
typedef Stubbed = String;

NodeError errno(String code) => NodeError('$code: injected', code: code);

/** Whether `spelling` is `target` as the wrap names it: by a descriptor on
 * its directory, or on itself. */
bool names(Object? spelling, String target) {
  bool viaFd(String p, String dir) =>
      RegExp(r'^/proc/self/fd/\d+$').hasMatch(p) &&
      (real['readlinkSync'] as dynamic)(p) == dir;
  return spelling is String &&
      (viaFd(spelling, target) ||
          (basename(spelling) == basename(target) &&
              viaFd(dirname(spelling), dirname(target))));
}

/**
 * An absent deny path is blocked by a placeholder, whose mount point
 * bubblewrap makes on the host, as this user, before the command runs. Where
 * neither it nor the command can create the path there is none to make, and
 * the sandbox starts without.
 */

void main() {
  group('A placeholder where no mount point can be made', () {
    late String BASE;
    late String ROOT; // the allowed write path
    late String DIR; // a directory in it, holding the absent deny paths
    final savedCwd = process.cwd();
    final spies = <void Function()>[];
    final standIns = <Stubbed, List<Function>>{};

    final CAN_RUN = isLinux && bwrapCanNamespace();
    // Directories of another's that this user cannot write: not root's view.
    final UNPRIVILEGED =
        isLinux &&
        ['/usr', '/etc'].every((dir) {
          try {
            fs.accessSync(dir, fs.constants.W_OK);
            return false;
          } catch (_) {
            return fs.statSync(dir).uid != process.geteuid?.call();
          }
        });

    setUp(() {
      BASE = fs.realpathSync(fs.mkdtempSync(join(tmpdir(), 'no-mount-point-')));
      ROOT = join(BASE, 'root');
      DIR = join(ROOT, 'dir');
      fs.mkdirSync(DIR, {'recursive': true});
      // Outside the allowed write path, so that the mandatory denies add no
      // placeholders of their own.
      process.chdir(BASE);
    });

    tearDown(() {
      for (final spy in spies) {
        spy();
      }
      spies.clear();
      standIns.clear();
      process.chdir(savedCwd);
      cleanupBwrapMountPoints(force: true);
      fs.rmSync(BASE, {'recursive': true, 'force': true});
    });

    /** Stands in for fs[name] until the test ends. A stand-in gets the
     * arguments, and answers `undefined` to leave the call to the next one, the
     * original being the last. */
    void stub(Stubbed name, Function standIn) {
      final sofar = standIns[name];
      if (sofar != null) {
        sofar.add(standIn);
        return;
      }
      final all = [standIn];
      standIns[name] = all;
      final original = real[name] as Function;
      dynamic invoke(List<dynamic> args) {
        for (final each in all) {
          final stood = Function.apply(each, args) as Map<String, dynamic>?;
          if (stood != null) return stood['value'];
        }
        return Function.apply(original, args);
      }

      switch (name) {
        case 'accessSync':
          fs.accessSync = (String p, [int mode = 0]) => invoke([p, mode]);
          spies.add(
            () => fs.accessSync = original as void Function(String, [int]),
          );
        case 'chmodSync':
          fs.chmodSync = (String p, int mode) => invoke([p, mode]);
          spies.add(
            () => fs.chmodSync = original as void Function(String, int),
          );
        case 'closeSync':
          fs.closeSync = (int fd) => invoke([fd]);
          spies.add(() => fs.closeSync = original as void Function(int));
        case 'fstatSync':
          fs.fstatSync = (int fd) => invoke([fd]) as fs.Stats;
          spies.add(() => fs.fstatSync = original as fs.Stats Function(int));
        case 'mkdirSync':
          fs.mkdirSync =
              (Object p, [Map<String, Object?> options = const {}]) =>
                  invoke([p, options]) as String?;
          spies.add(
            () => fs.mkdirSync =
                original as String? Function(Object, [Map<String, Object?>]),
          );
        case 'openSync':
          fs.openSync = (String p, [Object flags = 'r', int mode = 438]) =>
              invoke([p, flags, mode]) as int;
          spies.add(
            () => fs.openSync = original as int Function(String, [Object, int]),
          );
        case 'readlinkSync':
          fs.readlinkSync = (String p) => invoke([p]) as String;
          spies.add(
            () => fs.readlinkSync = original as String Function(String),
          );
        case 'statfsSync':
          fs.statfsSync = (String p) => invoke([p]) as fs.StatFs;
          spies.add(
            () => fs.statfsSync = original as fs.StatFs Function(String),
          );
      }
    }

    /** fs[name] fails with `code` when asked of `target`. */
    void refuse(Stubbed name, String target, [String code = 'EACCES']) =>
        stub(name, (dynamic spelling, [dynamic second, dynamic third]) {
          if (names(spelling, target)) throw errno(code);
          return null;
        });
    /** `directory` belongs to somebody else. */
    void ownedByAnother(String directory) {
      final ino = fs.statSync(directory).ino;
      stub('fstatSync', (dynamic fd) {
        final stats = (real['fstatSync'] as dynamic)(fd) as fs.Stats;
        if (stats.ino != ino) return null;
        return {
          'value': fs.Stats(
            dev: stats.dev,
            ino: stats.ino,
            mode: stats.mode,
            nlink: stats.nlink,
            uid: stats.uid + 1,
            gid: stats.gid,
            rdev: stats.rdev,
            size: stats.size,
            blksize: stats.blksize,
            blocks: stats.blocks,
            atimeMs: stats.atimeMs,
            mtimeMs: stats.mtimeMs,
            ctimeMs: stats.ctimeMs,
            birthtimeMs: stats.birthtimeMs,
          ),
        };
      });
    }

    /** Everything is on a Windows drive under WSL 2. */
    void onWindowsDrive() => stub('statfsSync', (dynamic p) {
      (real['statfsSync'] as dynamic)(p);
      return {'value': const fs.StatFs(type: V9FS_MAGIC)};
    });

    Future<String> wrap(
      List<String> denyWithinAllow, [
      String command = 'true',
      List<String>? allowOnly,
    ]) => wrapCommandWithSandboxLinux(
      LinuxSandboxParams(
        command: command,
        needsNetworkRestriction: false,
        writeConfig: FsWriteRestrictionConfig(
          allowOnly: allowOnly ?? [ROOT],
          denyWithinAllow: denyWithinAllow,
        ),
      ),
    );

    SpawnSyncResult run(String command) => spawnSync(command, [], {
      'shell': true,
      'encoding': 'utf8',
      'timeout': 15000,
    });

    /** The mounts that land at `dest`. */
    List<String> mountsAt(String command, String dest) =>
        mountsOf(command).where((mount) => mount.endsWith(' $dest')).toList();
    Matcher emptyDirectoryAt(String dest) =>
        matches(RegExp(r'^--ro-bind \S*claude-empty-\S+ ' + dest + r'$'));

    group('by what the parent directory answers', () {
      // What access() says of the parent, whose it is, and whether the
      // placeholder is planned.
      final ANSWERS = <(String, String?, bool, bool)>[
        ('writable', null, true, true),
        ('writable, and of another', null, false, true),
        ('unwritable by its mode, and of this user', 'EACCES', true, true),
        ('unwritable by its mode, and of another', 'EACCES', false, false),
        ('on a read-only file system, and of this user', 'EROFS', true, false),
        ('on a read-only file system, and of another', 'EROFS', false, false),
        ('immutable, and of this user', 'EPERM', true, false),
        ('failing to answer, and of another', 'EIO', false, true),
      ];

      for (final (_name, code, own, planned) in ANSWERS) {
        test('plans for a parent that is $_name', () async {
          if (code != null) refuse('accessSync', DIR, code);
          if (!own) ownedByAnother(DIR);
          final leaf = join(DIR, 'policy.json');
          final nested = join(DIR, 'absent', 'policy.json');

          final command = await wrap([leaf, nested]);

          expect(
            mountsAt(command, leaf),
            planned ? ['--ro-bind /dev/null ${leaf}'] : [],
          );
          expect(
            mountsAt(command, join(DIR, 'absent')),
            planned ? [emptyDirectoryAt(join(DIR, 'absent'))] : [],
          );
          // The parent is pinned either way, beneath the allow bind.
          expect(mountsOf(command).indexOf('--ro-bind ${DIR} ${DIR}'), 1);
          // And the question is asked without a trace.
          expect(fs.readdirSync(DIR), []);
        });
      }

      test(
        'keeps a parent that takes no mount point from being moved aside',
        () async {
          refuse('accessSync', DIR);
          ownedByAnother(DIR);
          final aside = join(ROOT, 'aside');

          // In truth DIR is this user's, in a directory it may write: only the
          // pin stands in the way.
          final result = run(
            await wrap(
              [join(DIR, 'policy.json')],
              'echo BOOTED; mv ${DIR} ${aside}; rmdir ${DIR}; echo x > ${join(ROOT, 'new')}',
            ),
          );

          expect(result.stdout, 'BOOTED\n');
          expect(result.stderr, matches(RegExp(r'mv: .*busy')));
          expect(result.stderr, matches(RegExp(r'rmdir: .*busy')));
          expect((fs.readdirSync(ROOT)..sort()), ['dir', 'new']);
        },
        skip: (!CAN_RUN) ? 'skipped when !CAN_RUN' : false,
      );

      test('takes nothing that turns up at the path for its own', () async {
        refuse('accessSync', DIR);
        ownedByAnother(DIR);
        final denied = join(DIR, 'policy.json');

        await wrap([denied]);
        fs.writeFileSync(denied, '');
        cleanupBwrapMountPoints();

        expect(fs.existsSync(denied), isTrue);
      });

      test('asks for write and search together', () async {
        final asked = <Object?>[];
        stub('accessSync', (dynamic spelling, dynamic mode, [dynamic third]) {
          if (names(spelling, DIR)) asked.add(mode);
          return null;
        });

        await wrap([join(DIR, 'policy.json')]);

        expect(asked, [fs.constants.W_OK | fs.constants.X_OK]);
      });
    });

    group('on any doubt', () {
      setUp(() {
        // Every answer below would leave the placeholder out.
        refuse('accessSync', DIR);
        ownedByAnother(DIR);
      });

      Future<void> planned() async {
        final denied = join(DIR, 'policy.json');
        expect(mountsAt(await wrap([denied]), denied), [
          '--ro-bind /dev/null ${denied}',
        ]);
      }

      ;

      test('leaves it out when there is none', () async {
        final denied = join(DIR, 'policy.json');
        expect(mountsAt(await wrap([denied]), denied), []);
      });

      test('plans it when the parent cannot be opened', () async {
        stub('openSync', (dynamic p, [dynamic second, dynamic third]) {
          if (p == DIR) throw errno('EMFILE');
          return null;
        });
        await planned();
      });

      test(
        'plans it when /proc does not say where the descriptor leads',
        () async {
          stub('readlinkSync', (dynamic p, [dynamic second, dynamic third]) {
            if (names(p, DIR)) throw errno('ENOENT');
            return null;
          });
          await planned();
        },
      );

      test('plans it when the file system cannot be told', () async {
        refuse('statfsSync', DIR, 'ENOSYS');
        await planned();
      });

      test('closes the descriptor whatever the answer', () async {
        final open = <dynamic>[];
        stub('openSync', (dynamic p, dynamic flags, [dynamic third]) {
          if (p != DIR) return null;
          open.add((real['openSync'] as dynamic)(DIR, flags));
          return {'value': open.last};
        });
        stub('closeSync', (dynamic fd, [dynamic second, dynamic third]) {
          if (open.contains(fd)) open.removeAt(open.indexOf(fd));
          return null;
        });

        await wrap([join(DIR, 'policy.json')]);
        refuse('statfsSync', DIR, 'ENOSYS');
        await wrap([join(DIR, 'other.json')]);

        expect(open, []);
      });
    });

    // A command that is still running may write ROOT, and can put something
    // else at a path in it at any moment. /usr stands for a directory that
    // answers "no mount point": it is another's, and this user cannot write it.
    group('with the parent swapped under the wrap', () {
      void swapOnce(
        Stubbed name,
        bool Function(Object?) when,
        void Function() swap,
      ) {
        var done = false;
        stub(name, (dynamic p, [dynamic second, dynamic third]) {
          if (!done && when(p)) {
            done = true;
            swap();
          }
          return null;
        });
      }

      ;

      test(
        'plans the placeholder when the parent is a symlink as it is opened',
        () async {
          swapOnce('openSync', (p) => p == DIR, () {
            fs.rmdirSync(DIR);
            fs.symlinkSync('/usr', DIR);
          });
          final denied = join(DIR, 'policy.json');

          expect(mountsAt(await wrap([denied]), denied), hasLength(1));
        },
      );

      test(
        'plans it when a directory above the parent is a symlink as it is opened',
        () async {
          final parent = join(DIR, 'share');
          fs.mkdirSync(parent);
          swapOnce('openSync', (p) => p == parent, () {
            fs.renameSync(DIR, join(ROOT, 'aside'));
            fs.symlinkSync('/usr', DIR);
          });
          final denied = join(parent, 'policy.json');

          expect(mountsAt(await wrap([denied]), denied), hasLength(1));
        },
      );

      test('plans it when the parent is swapped once it is open', () async {
        swapOnce('fstatSync', (p) => true, () {
          fs.renameSync(DIR, join(ROOT, 'aside'));
          fs.symlinkSync('/usr', DIR);
        });
        final denied = join(DIR, 'policy.json');

        expect(mountsAt(await wrap([denied]), denied), hasLength(1));
      });
    }, skip: (UNPRIVILEGED) ? false : 'requires UNPRIVILEGED');

    // So that it is the directory that was opened that answers, whatever the
    // path names by then.
    for (final (_, drive) in <(String, bool)>[
      ('off a Windows drive', false),
      ('on a Windows drive', true),
    ]) {
      test('asks everything of one descriptor on the parent, %s', () async {
        final opened = <List<dynamic>>[];
        final asked = <String>[];
        void note(Object? p) {
          // From the open to the close.
          if (opened.length == 1)
            asked.add(p.toString().replaceFirst(RegExp(r'\d+'), 'N'));
        }

        ;
        stub('openSync', (dynamic p, dynamic flags, [dynamic third]) {
          if (p == DIR)
            opened.add([p, flags]);
          else
            note(p);
          // Refused, like mkdir below, so that the questions go on to the last.
          if (names(p, join(DIR, 'policy.json'))) throw errno('EACCES');
          return null;
        });
        for (final name in [
          'readlinkSync',
          'accessSync',
          'statfsSync',
          'mkdirSync',
          'chmodSync',
        ]) {
          stub(name, (dynamic p, [dynamic second, dynamic third]) {
            note(p);
            if (name == 'mkdirSync') throw errno('EACCES');
            return null;
          });
        }
        if (drive) onWindowsDrive();
        stub('closeSync', (dynamic fd, [dynamic second, dynamic third]) {
          opened.add([]);
          return null;
        });

        await wrap([join(DIR, 'policy.json')]);

        expect(opened[0], [
          DIR,
          2097152 | fs.constants.O_NOFOLLOW | fs.constants.O_DIRECTORY,
        ]);
        final parent = '/proc/self/fd/N';
        expect(asked, [
          ...[parent, parent, parent],
          ...(drive
              ? ['${parent}/policy.json', '${parent}/policy.json', parent]
              : []),
        ]);
      });
    }

    group('on a Windows drive under WSL 2', () {
      setUp(onWindowsDrive);

      final listing = () => (fs.readdirSync(DIR)..sort());

      test(
        'makes the mount point itself, and the clean-up removes it',
        () async {
          final leaf = join(DIR, 'policy.json');
          final nested = join(DIR, 'absent', 'policy.json');

          final command = await wrap([leaf, nested]);

          expect(mountsAt(command, leaf), ['--ro-bind /dev/null ${leaf}']);
          expect(mountsAt(command, join(DIR, 'absent')), [
            emptyDirectoryAt(join(DIR, 'absent')),
          ]);
          expect(listing(), ['absent', 'policy.json']);
          expect(fs.statSync(leaf).size, 0);
          expect(fs.statSync(leaf).mode & 511, 292);
          expect(fs.readdirSync(join(DIR, 'absent')), []);
          cleanupBwrapMountPoints();
          expect(listing(), []);
        },
      );

      test(
        'covers a file with a directory in a folder that takes subfolders and no files',
        () async {
          final denied = join(DIR, 'policy.json');
          refuse('openSync', denied);

          final command = await wrap([denied]);

          expect(mountsAt(command, denied), [emptyDirectoryAt(denied)]);
          expect(fs.statSync(denied).isDirectory(), isTrue);
          cleanupBwrapMountPoints();
          expect(listing(), []);
        },
      );

      for (final (_kind, denied, dest) in <(String, String, String)>[
        ('a file', 'policy.json', 'policy.json'),
        ('a directory', 'absent/policy.json', 'absent'),
      ]) {
        test(
          'leaves $_kind out in a folder that takes nothing and is beyond this user',
          () async {
            refuse('openSync', join(DIR, dest));
            refuse('mkdirSync', join(DIR, dest), 'EPERM');
            refuse('chmodSync', DIR);

            final command = await wrap([join(DIR, denied)]);

            expect(mountsAt(command, join(DIR, dest)), []);
            expect(countMounts(command, ['--ro-bind', DIR, DIR]), 1);
            expect(listing(), []);
          },
        );
      }

      test(
        'plans the kind asked for when the name is refused in a folder this user governs',
        () async {
          final denied = join(DIR, 'policy.json');
          fs.chmodSync(DIR, 1512);
          refuse('openSync', denied);
          refuse('mkdirSync', denied);
          final modes = <Object?>[];
          stub('chmodSync', (dynamic p, dynamic mode, [dynamic third]) {
            if (names(p, DIR)) modes.add(mode);
            return null;
          });

          final command = await wrap([denied]);

          expect(mountsAt(command, denied), ['--ro-bind /dev/null ${denied}']);
          // The mode it has, so that nothing changes.
          expect(modes, [1512]);
        },
      );

      for (final (_verdict, _governs, planned) in <(String, String, bool)>[
        ('plans it', 'governs', true),
        ('leaves it out', 'does not govern', false),
      ]) {
        test(
          '$_verdict, and tries nothing, where access() refuses a folder this user $_governs',
          () async {
            final denied = join(DIR, 'policy.json');
            refuse('accessSync', DIR);
            if (!planned) refuse('chmodSync', DIR, 'EROFS');

            final command = await wrap([denied]);

            expect(mountsAt(command, denied), hasLength(planned ? 1 : 0));
            expect(listing(), []);
          },
        );
      }

      test('tries no file where a directory is wanted', () async {
        final tried = <Object?>[];
        stub('openSync', (dynamic p, [dynamic second, dynamic third]) {
          if (names(p, join(DIR, 'absent'))) tried.add(p);
          return null;
        });
        refuse('mkdirSync', join(DIR, 'absent'));
        refuse('chmodSync', DIR);

        await wrap([join(DIR, 'absent', 'policy.json')]);

        expect(tried, []);
        expect(listing(), []);
      });

      test(
        'plans it, and takes nothing for its own, when the path is there by the time it is tried',
        () async {
          final denied = join(DIR, 'policy.json');
          stub('openSync', (dynamic p, [dynamic second, dynamic third]) {
            if (names(p, denied)) fs.writeFileSync(denied, 'theirs');
            return null;
          });

          final command = await wrap([denied]);

          expect(mountsAt(command, denied), hasLength(1));
          cleanupBwrapMountPoints();
          expect(fs.readFileSync(denied, 'utf8'), 'theirs');
        },
      );

      // What one deny path's mount point puts on the host, the next is not
      // misled by: the plan is the same in either order, and as off the drive.
      for (final (_name, denied) in <(String, List<String>)>[
        ('a missing folder', ['absent/policy.json', 'absent/policy.d/x']),
        ('a path and one beneath it', ['absent', 'absent/commands']),
      ]) {
        group('with deny paths that share $_name', () {
          for (final (_order, ordered)
              in <(String, List<String> Function(List<String>))>[
                ('as listed', (List<String> list) => list),
                ('reversed', (List<String> list) => list.reversed.toList()),
              ]) {
            test('plans one directory, $_order', () async {
              final command = await wrap(
                ordered(denied.map((d) => join(DIR, d)).toList()),
              );

              expect(
                mountsOf(command).where((m) => m.contains('${DIR}/')).toList(),
                [emptyDirectoryAt(join(DIR, 'absent'))],
              );
              expect(listing(), ['absent']);
              expect(fs.readdirSync(join(DIR, 'absent')), []);
            });
          }
        });
      }

      test('removes what it made when the wrap then fails', () async {
        final wrapped = wrapCommandWithSandboxLinux(
          LinuxSandboxParams(
            command: 'true',
            needsNetworkRestriction: false,
            writeConfig: FsWriteRestrictionConfig(
              allowOnly: [ROOT],
              denyWithinAllow: [join(DIR, 'policy.json')],
            ),
            binShell: 'no-such-shell',
          ),
        );
        await expectLater(
          wrapped,
          throwsA(predicate((e) => e.toString().contains('no-such-shell'))),
        );
        await wrapped.then<void>((_) {}, onError: (Object _) {});
        expect(listing(), []);
      });

      test(
        'runs on the mount points it made, and the paths cannot be created',
        () async {
          final leaf = join(DIR, 'policy.json');
          final nested = join(DIR, 'absent', 'policy.json');

          final result = run(
            await wrap(
              [leaf, nested],
              'echo BOOTED; echo x > ${leaf}; echo x > ${nested}; echo x > ${join(DIR, 'new')}',
            ),
          );

          expect(result.stdout, 'BOOTED\n');
          expect(result.stderr, isNot(contains('bwrap:')));
          cleanupBwrapMountPoints();
          expect(listing(), ['new']);
        },
        skip: (!CAN_RUN) ? 'skipped when !CAN_RUN' : false,
      );
    });

    test(
      'asks nothing of the host for a path that needs no placeholder',
      () async {
        final opened = <Object?>[];
        stub('openSync', (dynamic p, [dynamic second, dynamic third]) {
          opened.add(p);
          return null;
        });
        fs.writeFileSync(join(ROOT, 'file'), '');

        await wrap(
          [
            ROOT, // covers DIR, the one allowed write path
            join(DIR, 'covered.json'),
            join(BASE, 'outside.json'),
          ],
          'true',
          [DIR],
        );

        expect(opened, []);
      },
    );

    test('asks once for deny paths that share a missing directory', () async {
      final opened = <Object?>[];
      stub('openSync', (dynamic p, [dynamic second, dynamic third]) {
        opened.add(p);
        return null;
      });

      await wrap([join(DIR, 'absent', 'a'), join(DIR, 'absent', 'b', 'c')]);

      expect(opened, [DIR]);
    });

    group('in directories of another user', () {
      final PROBE = 'srt-no-mount-point-probe';
      final denied = [
        '/usr/${PROBE}/policy.json',
        '/etc/${PROBE}',
        '/${PROBE}',
      ];
      final dests = ['/usr/${PROBE}', '/etc/${PROBE}', '/${PROBE}'];

      test(
        'plans no placeholder, and keeps their top-level directories mount points',
        () async {
          final command = await wrap(denied, 'true', ['/']);

          for (final dest in dests) expect(mountsAt(command, dest), []);
          expect(countMounts(command, ['--bind', '/usr', '/usr']), 1);
          expect(countMounts(command, ['--bind', '/etc', '/etc']), 1);
        },
      );

      for (final (_name, allowOnly) in <(String, List<String>)>[
        ('"/"', ['/']),
        ('the directories themselves', ['/usr', '/etc']),
      ]) {
        test(
          'starts with $_name allowed, and the paths cannot be created',
          () async {
            final result = run(
              await wrap(
                denied,
                'echo BOOTED; mkdir ${dests[0]}; echo x > ${dests[1]}; echo x > ${dests[2]}; mv /usr/share /usr/aside; echo x > ${join(DIR, 'new')}',
                [...allowOnly, ROOT],
              ),
            );

            expect(result.stderr, isNot(contains('bwrap:')));
            expect(result.stdout, 'BOOTED\n');
            expect(dests.where((dest) => fs.existsSync(dest)).toList(), []);
            expect(fs.readdirSync(DIR), ['new']);
          },
          skip: (!CAN_RUN) ? 'skipped when !CAN_RUN' : false,
        );
      }
    }, skip: (UNPRIVILEGED) ? false : 'requires UNPRIVILEGED');

    group('in a directory of this user that its mode closes', () {
      setUp(() => fs.chmodSync(DIR, 365));
      tearDown(() => fs.chmodSync(DIR, 493));

      test(
        'plans the placeholder',
        () async {
          final denied = join(DIR, 'policy.json');

          expect(mountsAt(await wrap([denied]), denied), [
            '--ro-bind /dev/null ${denied}',
          ]);
        },
        skip: (process.geteuid?.call() == 0)
            ? 'skipped when process.geteuid?.call() === 0'
            : false,
      );

      test('holds the path against a command that opens the directory', () async {
        final denied = join(DIR, 'policy.json');

        final result = run(
          await wrap(
            [denied],
            'echo BOOTED; chmod 755 ${DIR}; echo x > ${denied}; echo x > ${join(DIR, 'new')}',
          ),
        );

        expect(result.stdout, 'BOOTED\n');
        expect(fs.readFileSync(denied, 'utf8'), '');
        expect(fs.existsSync(join(DIR, 'new')), isTrue);
      }, skip: (!CAN_RUN) ? 'skipped when !CAN_RUN' : false);
    });

    // A read-only file system that this user owns everything on: a sandbox
    // around the wrap and its own, with DIR bound read-only.
    test('starts with an absent deny path on a read-only file system', () {
      final denied = join(DIR, 'policy.json');
      final script =
          """
          import 'dart:convert';
          import 'package:sandbox_runtime/src/sandbox/linux_sandbox_utils.dart';
          import 'package:sandbox_runtime/src/sandbox/sandbox_schemas.dart';
          import 'package:sandbox_runtime/src/node/child_process.dart';
          Future<void> main() async {
            final command = await wrapCommandWithSandboxLinux(LinuxSandboxParams(
              command: ${jsonEncode('echo BOOTED; echo x > $denied; echo x > ${join(ROOT, 'new')}')},
              needsNetworkRestriction: false,
              writeConfig: FsWriteRestrictionConfig(allowOnly: [${jsonEncode(ROOT)}], denyWithinAllow: [${jsonEncode(denied)}]),
            ));
            final r = spawnSync(command, [], {'shell': true, 'encoding': 'utf8'});
            print(jsonEncode({'command': command, 'stdout': r.stdout, 'stderr': r.stderr}));
          }
        """;
      final scriptPath = join(BASE, 'readonly-probe.dart');
      fs.writeFileSync(scriptPath, script);
      final outer = spawnSync(
        'bwrap',
        [
          ...['--unshare-user', '--bind', '/', '/', '--ro-bind', DIR, DIR],
          ...['--dev', '/dev', '--proc', '/proc', '--chdir', REPO_ROOT],
          ...[
            Platform.resolvedExecutable,
            '--packages=${join(REPO_ROOT, '.dart_tool/package_config.json')}',
            scriptPath,
          ],
        ],
        {'encoding': 'utf8', 'timeout': 60000},
      );
      final data =
          jsonDecode((outer.stdout as String).trim().split('\n').last)
              as Map<String, dynamic>;
      final command = data['command'] as String;
      final stdout = data['stdout'] as String;
      final stderr = data['stderr'] as String;

      expect(stderr, isNot(contains('bwrap:')));
      expect(stdout, 'BOOTED\n');
      expect(mountsAt(command, denied), []);
      expect(fs.readdirSync(DIR), []);
      expect((fs.readdirSync(ROOT)..sort()), ['dir', 'new']);
    }, skip: (!CAN_RUN) ? 'skipped when !CAN_RUN' : false);
  }, skip: (isLinux) ? false : 'requires isLinux');
}
