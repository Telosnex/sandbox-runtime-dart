// Ported from sandbox-runtime test/sandbox/linux-ancestor-pin.test.ts @ 24eb39e.
// ignore_for_file: constant_identifier_names, non_constant_identifier_names, slash_for_doc_comments
import 'dart:convert';
import 'dart:io';

import 'package:path/path.dart' show dirname, join;
import 'package:sandbox_runtime/src/node/child_process.dart'
    show SpawnSyncResult, spawnSync;
import 'package:sandbox_runtime/src/node/errno.dart' show NodeError;
import 'package:sandbox_runtime/src/node/fs.dart' as fs;
import 'package:sandbox_runtime/src/node/os.dart' show tmpdir;
import 'package:sandbox_runtime/src/node/process.dart' as process;
import 'package:sandbox_runtime/src/sandbox/generate_seccomp_filter.dart'
    show getApplySeccompBinaryPath;
import 'package:sandbox_runtime/src/sandbox/linux_sandbox_utils.dart'
    show
        LinuxSandboxParams,
        cleanupBwrapMountPoints,
        wrapCommandWithSandboxLinux;
import 'package:sandbox_runtime/src/sandbox/sandbox_schemas.dart'
    show FsReadRestrictionConfig, FsWriteRestrictionConfig;
import 'package:sandbox_runtime/src/utils/which.dart' show whichSync;
import 'package:test/test.dart';

import '../helpers/bwrap_argv.dart'
    show countMounts, indexOfMount, lastIndexOfMount, lastMountAt;
import '../helpers/bwrap_namespace.dart' show bwrapCanNamespace;
import '../helpers/platform.dart' show isLinux;

// Dart: stands for the anonymous `filesystem` parameter type of `wrap`.
class _Filesystem {
  const _Filesystem({
    this.allowWrite,
    this.denyWrite,
    this.denyRead,
    this.allowRead,
  });
  final List<String>? allowWrite;
  final List<String>? denyWrite;
  final List<String>? denyRead;
  final List<String>? allowRead;
}

// Dart: no JS runtime hosts the test, so `process.execPath` is `node` on PATH.
final String _execPath = whichSync('node') ?? 'node';

void main() {
  // Every scenario has an argument-level arm that runs everywhere on Linux and,
  // where one is useful, a "(live bwrap)" companion that executes the wrapped
  // command. The companions are skipped, visibly, where unprivileged user
  // namespaces are unavailable.
  group('Linux sandbox — denyWrite ancestor pinning', () {
    late String BASE;
    late String PROJECT;
    final savedCwd = process.cwd();

    // Dart: the probes below spawn processes, so they run only on Linux,
    // where upstream's describe.if(isLinux) runs this callback.
    final BWRAP_CAN_NAMESPACE = isLinux && bwrapCanNamespace();

    // Built in CI; absent elsewhere, where the arm that needs it must skip
    // visibly rather than quietly run without the seccomp stage.
    final APPLY_SECCOMP = isLinux ? getApplySeccompBinaryPath() : null;

    // glibc before 2.28 and some other libcs have no renameat2 wrapper.
    final CAN_CALL_RENAMEAT2 =
        isLinux &&
        whichSync('python3') != null &&
        spawnSync(
              'python3',
              ['-c', 'import ctypes; ctypes.CDLL(None).renameat2'],
              {'timeout': 5000},
            ).status ==
            0;

    void mkTree(String root, Map<String, Object> tree) {
      for (final MapEntry(key: name, value: value) in tree.entries) {
        final entryPath = join(root, name);
        if (value is String) {
          fs.writeFileSync(entryPath, value);
        } else {
          fs.mkdirSync(entryPath, {'recursive': true});
          mkTree(entryPath, value as Map<String, Object>);
        }
      }
    }

    setUp(() {
      BASE = fs.realpathSync(fs.mkdtempSync(join(tmpdir(), 'ancestor-pin-')));
      PROJECT = join(BASE, 'project');
      fs.mkdirSync(PROJECT);
      fs.writeFileSync(join(PROJECT, 'README.md'), '# test\n');
    });

    tearDown(() {
      Directory.current = savedCwd;
      cleanupBwrapMountPoints(force: true);
      fs.rmSync(BASE, {'recursive': true, 'force': true});
    });

    // Dart: `command` is nullable so a caller can pass "undefined" through.
    Future<String> wrap([
      _Filesystem filesystem = const _Filesystem(),
      String? command,
    ]) async {
      command ??= 'echo ok';
      // Mandatory denies (.git/config, .git/hooks, dotfiles) are relative to
      // process.cwd(); the project is the sandbox's cwd like a real session.
      Directory.current = PROJECT;
      return wrapCommandWithSandboxLinux(
        LinuxSandboxParams(
          command: command,
          needsNetworkRestriction: false,
          allowAllUnixSockets: true,
          readConfig: FsReadRestrictionConfig(
            denyOnly: filesystem.denyRead ?? [],
            allowWithinDeny: filesystem.allowRead ?? [],
          ),
          writeConfig: FsWriteRestrictionConfig(
            allowOnly: [PROJECT, ...(filesystem.allowWrite ?? [])],
            denyWithinAllow: filesystem.denyWrite ?? [],
          ),
        ),
      );
    }

    SpawnSyncResult run(String command) {
      return spawnSync(command, [], {
        'shell': true,
        'encoding': 'utf8',
        'timeout': 15000,
        'cwd': PROJECT,
        // The EBUSY assertions match strerror text.
        'env': {...process.env, 'LC_ALL': 'C'},
      });
    }

    // A command that reports one errno per labelled raw syscall and ends with
    // PROBE_DONE, so a sandbox that never starts cannot pass as "no failures".
    const PROBE_DONE = 'PROBE_DONE';
    String asJsString(String s) => jsonEncode(s);
    String nodeProbe(List<(String, String)> ops) {
      final script = [
        "const fs = require('fs')",
        "const op = (n, f) => { try { f(); console.log(n + '=OK') } catch (e) { console.log(n + '=' + e.code) } }",
        ...ops.map(
          ((String, String) o) => 'op(${asJsString(o.$1)}, () => { ${o.$2} })',
        ),
        'console.log(${asJsString(PROBE_DONE)})',
      ].join('; ');
      final probeFile = join(BASE, 'probe.cjs');
      fs.writeFileSync(probeFile, script);
      return '$_execPath $probeFile';
    }

    test(
      'pins the directories between a mandatory deny leaf and the allowWrite root',
      () async {
        mkTree(PROJECT, {
          '.git': {'hooks': <String, Object>{}, 'config': '[core]\n'},
        });
        final gitDir = join(PROJECT, '.git');

        final command = await wrap();

        expect(command, contains('--ro-bind / /'));
        final configDeny = '$gitDir/config';
        expect(countMounts(command, ['--ro-bind', configDeny, configDeny]), 1);
        // .git sits strictly between the leaf denies and the allowWrite root.
        final gitPin = indexOfMount(command, ['--ro-bind', gitDir, gitDir]);
        expect(gitPin, greaterThan(-1));
        expect(
          gitPin,
          lessThan(indexOfMount(command, ['--bind', PROJECT, PROJECT])),
        );
        expect(
          gitPin,
          lessThan(
            indexOfMount(command, ['--ro-bind', configDeny, configDeny]),
          ),
        );
        final outside = dirname(PROJECT);
        expect(command, isNot(contains('--ro-bind $outside $outside')));
        // The allowWrite root is bound exactly once (its allow bind); a pin there
        // would add nothing.
        expect(countMounts(command, ['--bind', PROJECT, PROJECT]), 1);
        expect(countMounts(command, ['--ro-bind', PROJECT, PROJECT]), 0);
      },
    );

    test('pins ancestors of absent-path stub dests', () async {
      // .git exists but neither config nor hooks does: every deny dest on this
      // chain is a stub, so the .git pin can only come from stub dests.
      mkTree(PROJECT, {'.git': <String, Object>{}});
      final gitDir = join(PROJECT, '.git');

      final command = await wrap();

      expect(command, contains('--ro-bind /dev/null $gitDir/hooks'));
      expect(command, contains('--ro-bind /dev/null $gitDir/config'));
      expect(command, contains('--ro-bind $gitDir $gitDir'));
    });

    test(
      'pins every intermediate directory above a nested repo found by the depth scan',
      () async {
        mkTree(PROJECT, {
          'nested': {
            '.git': {'hooks': <String, Object>{}, 'config': '[core]\n'},
          },
        });
        final nestedDir = join(PROJECT, 'nested');
        final nestedGit = join(nestedDir, '.git');

        final command = await wrap();

        expect(
          command,
          contains('--ro-bind $nestedGit/config $nestedGit/config'),
        );
        expect(command, contains('--ro-bind $nestedGit $nestedGit'));
        expect(command, contains('--ro-bind $nestedDir $nestedDir'));
      },
    );

    // x and y are pinned beneath everything; the tmpfs on y lands on top of
    // both, the denyRead section's restore of the nested allowWrite z runs
    // before the buffered deny binds, and the config deny lands on top of it.
    ({
      String xDir,
      String yDir,
      String zDir,
      String configPath,
      _Filesystem filesystem,
    })
    nestedWriteRootsUnderTmpfs() {
      mkTree(PROJECT, {
        'x': {
          'y': {
            'z': {
              '.git': {'hooks': <String, Object>{}, 'config': '[core]\n'},
            },
          },
        },
      });
      final yDir = join(PROJECT, 'x', 'y');
      final zDir = join(yDir, 'z');
      return (
        xDir: join(PROJECT, 'x'),
        yDir: yDir,
        zDir: zDir,
        configPath: join(zDir, '.git', 'config'),
        filesystem: _Filesystem(
          allowWrite: [zDir],
          denyRead: [yDir],
          denyWrite: [join(zDir, '.git', 'config')],
        ),
      );
    }

    test(
      'keeps leaf denies enforced when a denyRead tmpfs sits between nested allowWrite roots',
      () async {
        final (:xDir, :yDir, :zDir, :configPath, :filesystem) =
            nestedWriteRootsUnderTmpfs();

        final command = await wrap(filesystem);

        expect(
          lastIndexOfMount(command, ['--ro-bind', configPath, configPath]),
          greaterThan(lastIndexOfMount(command, ['--bind', zDir, zDir])),
        );
        expect(countMounts(command, ['--bind', zDir, zDir]), greaterThan(0));
        final xPin = indexOfMount(command, ['--ro-bind', xDir, xDir]);
        expect(xPin, greaterThan(-1));
        expect(xPin, lessThan(indexOfMount(command, ['--tmpfs', yDir])));
      },
    );

    test(
      'keeps leaf denies enforced when a denyRead tmpfs sits between nested allowWrite roots (live bwrap)',
      () async {
        final (:zDir, :configPath, :filesystem, xDir: _, yDir: _) =
            nestedWriteRootsUnderTmpfs();

        final result = run(
          await wrap(filesystem, 'echo evil >> $configPath && echo PLANTED'),
        );
        expect(result.stdout ?? '', isNot(contains('PLANTED')));
        expect(result.status, isNot(0));
        expect(fs.readFileSync(configPath, 'utf8'), '[core]\n');

        final writable = await wrap(
          filesystem,
          'echo n > $zDir/newfile.txt && echo Z_WRITE_OK',
        );
        expect(run(writable).stdout, contains('Z_WRITE_OK'));
        expect(fs.existsSync(join(zDir, 'newfile.txt')), true);
      },
      skip: BWRAP_CAN_NAMESPACE ? false : 'bwrap cannot create namespaces',
    );

    ({
      String xDir,
      String yDir,
      String appDir,
      String dataDir,
      String secretPath,
      String configPath,
      _Filesystem filesystem,
    })
    tmpfsInsidePinnedAncestor() {
      mkTree(PROJECT, {
        'x': {
          'y': {
            'z': {
              'app': {
                'data': {'secret.txt': 'TOPSECRET\n'},
                'repo': {
                  '.git': {'hooks': <String, Object>{}, 'config': '[core]\n'},
                },
              },
            },
          },
        },
      });
      final yDir = join(PROJECT, 'x', 'y');
      final zDir = join(yDir, 'z');
      final appDir = join(zDir, 'app');
      final dataDir = join(appDir, 'data');
      final configPath = join(appDir, 'repo', '.git', 'config');
      return (
        xDir: join(PROJECT, 'x'),
        yDir: yDir,
        appDir: appDir,
        dataDir: dataDir,
        secretPath: join(dataDir, 'secret.txt'),
        configPath: configPath,
        filesystem: _Filesystem(
          allowWrite: [zDir],
          denyRead: [yDir, dataDir],
          denyWrite: [configPath],
        ),
      );
    }

    test(
      'pins an ancestor that contains a read-deny tmpfs; the tmpfs still lands on top',
      () async {
        final (
          :xDir,
          :yDir,
          :appDir,
          :dataDir,
          :filesystem,
          secretPath: _,
          configPath: _,
        ) = tmpfsInsidePinnedAncestor();

        final command = await wrap(filesystem);

        final dataTmpfs = indexOfMount(command, ['--tmpfs', dataDir]);
        final yTmpfs = indexOfMount(command, ['--tmpfs', yDir]);
        final appPin = indexOfMount(command, ['--ro-bind', appDir, appDir]);
        final xPin = indexOfMount(command, ['--ro-bind', xDir, xDir]);
        expect(dataTmpfs, greaterThan(-1));
        expect(yTmpfs, greaterThan(-1));
        expect(appPin, lessThan(dataTmpfs));
        expect(xPin, lessThan(yTmpfs));
        expect(appPin, greaterThan(-1));
        expect(xPin, greaterThan(-1));
        expect(
          command,
          contains('--ro-bind ${join(appDir, 'repo')} ${join(appDir, 'repo')}'),
        );
      },
    );

    test(
      'pins an ancestor that contains a read-deny tmpfs; the tmpfs still lands on top (live bwrap)',
      () async {
        final (
          :secretPath,
          :configPath,
          :filesystem,
          xDir: _,
          yDir: _,
          appDir: _,
          dataDir: _,
        ) = tmpfsInsidePinnedAncestor();

        final result = run(
          await wrap(
            filesystem,
            'cat $secretPath 2>&1; echo evil >> $secretPath 2>&1; echo evil >> $configPath 2>&1; echo DONE',
          ),
        );

        expect(result.stdout, contains('DONE'));
        expect(result.stdout, isNot(contains('TOPSECRET')));
        expect(fs.readFileSync(secretPath, 'utf8'), 'TOPSECRET\n');
        expect(fs.readFileSync(configPath, 'utf8'), '[core]\n');
      },
      skip: BWRAP_CAN_NAMESPACE ? false : 'bwrap cannot create namespaces',
    );

    // The tmpfs mounts at data/secrets via the symlink spelling; data is
    // pinned beneath it, so data cannot be renamed aside and the secret
    // stays hidden.
    ({
      String dataDir,
      String secretsLink,
      String secretsCanonical,
      String secretCanonical,
      _Filesystem filesystem,
    })
    symlinkSpelledTmpfs() {
      mkTree(PROJECT, {
        'data': {
          'secrets': {'secret.txt': 'TOPSECRET\n'},
        },
      });
      final dataDir = join(PROJECT, 'data');
      final secretsLink = join(PROJECT, 'secrets');
      Link(secretsLink).createSync(join('data', 'secrets'));
      return (
        dataDir: dataDir,
        secretsLink: secretsLink,
        secretsCanonical: join(dataDir, 'secrets'),
        secretCanonical: join(dataDir, 'secrets', 'secret.txt'),
        filesystem: _Filesystem(denyRead: [secretsLink]),
      );
    }

    test(
      'pins an ancestor that contains a symlink-spelled read-deny tmpfs location; the tmpfs still lands on top',
      () async {
        final (
          :dataDir,
          :secretsLink,
          :secretsCanonical,
          :filesystem,
          secretCanonical: _,
        ) = symlinkSpelledTmpfs();

        final command = await wrap(filesystem);

        // The tmpfs goes where the link leads, never on the link itself.
        expect(countMounts(command, ['--tmpfs', secretsLink]), 0);
        final tmpfsOp = indexOfMount(command, ['--tmpfs', secretsCanonical]);
        final dataPin = indexOfMount(command, ['--ro-bind', dataDir, dataDir]);
        expect(tmpfsOp, greaterThan(-1));
        expect(dataPin, greaterThan(-1));
        expect(dataPin, lessThan(tmpfsOp));
      },
    );

    test(
      'pins an ancestor that contains a symlink-spelled read-deny tmpfs location; the tmpfs still lands on top (live bwrap)',
      () async {
        final (
          :dataDir,
          :secretsLink,
          :secretCanonical,
          :filesystem,
          secretsCanonical: _,
        ) = symlinkSpelledTmpfs();

        final result = run(
          await wrap(
            filesystem,
            'cat $secretCanonical 2>&1; cat $secretsLink/secret.txt 2>&1; echo evil >> $secretCanonical 2>&1; mv $dataDir $dataDir-moved 2>&1; echo DONE',
          ),
        );

        expect(result.stdout ?? '', contains('DONE'));
        expect(result.stderr ?? '', isNot(contains('bwrap:')));
        expect(result.stdout ?? '', isNot(contains('TOPSECRET')));
        expect(
          result.stdout ?? '',
          matches(RegExp('busy', caseSensitive: false)),
        );
        expect(fs.existsSync('$dataDir-moved'), false);
        expect(fs.readFileSync(secretCanonical, 'utf8'), 'TOPSECRET\n');
      },
      skip: BWRAP_CAN_NAMESPACE ? false : 'bwrap cannot create namespaces',
    );

    ({
      String dDir,
      String wDir,
      String secretPath,
      String linkD,
      _Filesystem filesystem,
    })
    carveOutInsideSymlinkSpelledDenyRead() {
      mkTree(PROJECT, {
        'data': {
          'd': {
            'w': {'secret': 'DENYTEST\n'},
            'elsewhere.txt': 'ALSOSECRET\n',
          },
        },
      });
      final dDir = join(PROJECT, 'data', 'd');
      final wDir = join(dDir, 'w');
      final secretPath = join(wDir, 'secret');
      final linkD = join(PROJECT, 'link-d');
      Link(linkD).createSync(join('data', 'd'));
      return (
        dDir: dDir,
        wDir: wDir,
        secretPath: secretPath,
        linkD: linkD,
        filesystem: _Filesystem(
          allowWrite: [wDir],
          denyRead: [linkD],
          denyWrite: [secretPath],
        ),
      );
    }

    test(
      'restores a canonical allowWrite carve-out inside a symlink-spelled denyRead',
      () async {
        final (:dDir, :wDir, :linkD, :filesystem, secretPath: _) =
            carveOutInsideSymlinkSpelledDenyRead();

        final command = await wrap(filesystem);

        // The carve-out's writable re-bind must follow the tmpfs, which lands
        // where the link leads.
        expect(countMounts(command, ['--tmpfs', linkD]), 0);
        final tmpfsOp = lastIndexOfMount(command, ['--tmpfs', dDir]);
        expect(tmpfsOp, greaterThan(-1));
        expect(
          lastIndexOfMount(command, ['--bind', wDir, wDir]),
          greaterThan(tmpfsOp),
        );
      },
    );

    test(
      'restores a canonical allowWrite carve-out inside a symlink-spelled denyRead (live bwrap)',
      () async {
        final (:dDir, :wDir, :secretPath, :filesystem, linkD: _) =
            carveOutInsideSymlinkSpelledDenyRead();

        final result = run(
          await wrap(
            filesystem,
            'echo n > $wDir/newfile.txt 2>&1; echo evil >> $secretPath 2>&1; cat $dDir/elsewhere.txt 2>&1; echo DONE',
          ),
        );

        expect(result.stdout ?? '', contains('DONE'));
        expect(fs.existsSync(join(wDir, 'newfile.txt')), true);
        expect(fs.readFileSync(secretPath, 'utf8'), 'DENYTEST\n');
        expect(result.stdout ?? '', isNot(contains('ALSOSECRET')));
      },
      skip: BWRAP_CAN_NAMESPACE ? false : 'bwrap cannot create namespaces',
    );

    // The dotfile-manager shape: .netrc and docs inside a read-denied home are
    // links into a sibling directory inside it. Restoring them only where they
    // resolve leaves the names themselves missing in the sandbox; naming the
    // link as the bind SOURCE would hand bwrap the link to re-resolve at mount
    // time, after the containment check ran.
    symlinkedAllowReadCarveOuts() {
      mkTree(BASE, {
        'home': {
          'store': {
            'netrc': 'SECRETTOKEN\n',
            'pages': {'readme.md': 'PAGETEXT\n'},
          },
          'other.txt': 'HIDDEN\n',
        },
      });
      final homeDir = join(BASE, 'home');
      final netrcName = join(homeDir, '.netrc');
      final docsName = join(homeDir, 'docs');
      Link(netrcName).createSync(join('store', 'netrc'));
      Link(docsName).createSync(join('store', 'pages'));
      return (
        homeDir: homeDir,
        netrcName: netrcName,
        netrcTarget: join(homeDir, 'store', 'netrc'),
        docsName: docsName,
        docsTarget: join(homeDir, 'store', 'pages'),
        filesystem: _Filesystem(
          denyRead: [homeDir],
          allowRead: [netrcName, docsName],
        ),
      );
    }

    test(
      'restores an allowRead carve-out that is a symlink at the name it is, from its vetted target',
      () async {
        final (
          :homeDir,
          :netrcName,
          :netrcTarget,
          :docsName,
          :docsTarget,
          :filesystem,
        ) = symlinkedAllowReadCarveOuts();

        final command = await wrap(filesystem);

        expect(indexOfMount(command, ['--tmpfs', homeDir]), greaterThan(-1));
        // The name is the destination; the vetted target is the source.
        expect(countMounts(command, ['--ro-bind', netrcTarget, netrcName]), 1);
        expect(countMounts(command, ['--ro-bind', docsTarget, docsName]), 1);
        expect(command, isNot(contains('--ro-bind $netrcName ')));
        expect(command, isNot(contains('--ro-bind $docsName ')));
      },
    );

    test(
      'restores an allowRead carve-out that is a symlink at the name it is, from its vetted target (live bwrap)',
      () async {
        final (
          :homeDir,
          :netrcName,
          :docsName,
          :filesystem,
          netrcTarget: _,
          docsTarget: _,
        ) = symlinkedAllowReadCarveOuts();

        final result = run(
          await wrap(
            filesystem,
            'cat $netrcName 2>&1; cat ${join(docsName, 'readme.md')} 2>&1; cat ${join(homeDir, 'other.txt')} 2>&1; echo DONE',
          ),
        );

        expect(result.stdout, contains('DONE'));
        expect(result.stdout, contains('SECRETTOKEN'));
        expect(result.stdout, contains('PAGETEXT'));
        expect(result.stdout, isNot(contains('HIDDEN')));
      },
      skip: BWRAP_CAN_NAMESPACE ? false : 'bwrap cannot create namespaces',
    );

    // Restoring such a carve-out puts the TARGET's inode at the NAME: a second
    // mount of it, which a deny or a credential mask landing on the target's
    // own path does not cover. So the read section wins over the carve-out
    // whenever it hides anything at, inside or around the target, and the
    // carve-out is not restored at all. Each flavour below has a control whose
    // carve-out is an ordinary directory, where the deeper deny lands inside
    // the restore and the rest of the carve-out stays readable.
    carveOutsOverDeniedTargets() {
      mkTree(BASE, {
        'home': {
          'store': {
            'netrc': 'SECRETTOKEN\n',
            'pages': {
              'readme.md': 'PAGETEXT\n',
              'sec': {'x': 'SECRETPAGE\n'},
            },
          },
          'plain': {
            'readme.md': 'PAGETEXT\n',
            'sec': {'x': 'SECRETPAGE\n'},
          },
        },
      });
      final homeDir = join(BASE, 'home');
      final storeDir = join(homeDir, 'store');
      final netrcName = join(homeDir, '.netrc');
      final docsName = join(homeDir, 'docs');
      final hopName = join(homeDir, '.hop');
      final danglingName = join(homeDir, '.gone');
      Link(netrcName).createSync(join('store', 'netrc'));
      Link(docsName).createSync(join('store', 'pages'));
      // Two hops, through a directory link: the source has to be the full
      // realpath, not one hop of it.
      Link(join(homeDir, 'alias')).createSync('store');
      Link(hopName).createSync(join('alias', 'netrc'));
      Link(danglingName).createSync(join('store', 'gone'));
      return (
        homeDir: homeDir,
        netrcName: netrcName,
        netrcTarget: join(storeDir, 'netrc'),
        docsName: docsName,
        docsTarget: join(storeDir, 'pages'),
        deniedPage: join(storeDir, 'pages', 'sec'),
        storeDir: storeDir,
        hopName: hopName,
        danglingName: danglingName,
        plainDir: join(homeDir, 'plain'),
        plainDenied: join(homeDir, 'plain', 'sec'),
      );
    }

    test(
      'drops a symlinked allowRead carve-out whose target is read-denied',
      () async {
        final (
          :homeDir,
          :netrcName,
          :netrcTarget,
          :plainDir,
          :plainDenied,
          docsName: _,
          docsTarget: _,
          deniedPage: _,
          storeDir: _,
          hopName: _,
          danglingName: _,
        ) = carveOutsOverDeniedTargets();

        final command = await wrap(
          _Filesystem(denyRead: [homeDir, netrcTarget], allowRead: [netrcName]),
        );

        // Nothing lands at the name, whatever it would have been bound from:
        // asserting the absence of one spelling would pass for a restore spelled
        // `--ro-bind <name> <name>`, which bwrap resolves to the same inode.
        expect(lastMountAt(command, netrcName), isNull);
        // The target's own mask is not emitted: it would land inside the tmpfs
        // the home directory's deny already put over it, and one mount per
        // location is all this wrap makes. The entry still says the target is
        // denied, which is what costs the carve-out its restore above.
        expect(
          countMounts(command, ['--ro-bind', '/dev/null', netrcTarget]),
          0,
        );

        // The control: an ordinary directory carve-out keeps its restore, and
        // the deeper deny lands inside it.
        final control = await wrap(
          _Filesystem(denyRead: [homeDir, plainDenied], allowRead: [plainDir]),
        );
        final restore = indexOfMount(control, [
          '--ro-bind',
          plainDir,
          plainDir,
        ]);
        expect(restore, greaterThan(-1));
        expect(
          indexOfMount(control, ['--tmpfs', plainDenied]),
          greaterThan(restore),
        );
      },
    );

    test(
      'drops a symlinked directory carve-out whose target holds a read deny',
      () async {
        final (
          :homeDir,
          :docsName,
          :deniedPage,
          netrcName: _,
          netrcTarget: _,
          docsTarget: _,
          storeDir: _,
          hopName: _,
          danglingName: _,
          plainDir: _,
          plainDenied: _,
        ) = carveOutsOverDeniedTargets();

        final command = await wrap(
          _Filesystem(denyRead: [homeDir, deniedPage], allowRead: [docsName]),
        );

        expect(lastMountAt(command, docsName), isNull);
      },
    );

    test(
      'drops a symlinked carve-out whose target a deeper tmpfs hides',
      () async {
        final (
          :homeDir,
          :netrcName,
          :storeDir,
          netrcTarget: _,
          docsName: _,
          docsTarget: _,
          deniedPage: _,
          hopName: _,
          danglingName: _,
          plainDir: _,
          plainDenied: _,
        ) = carveOutsOverDeniedTargets();

        // The deny is neither at nor under the target: it is around it, and the
        // name would sit outside it serving what it hides.
        final command = await wrap(
          _Filesystem(denyRead: [homeDir, storeDir], allowRead: [netrcName]),
        );

        expect(lastMountAt(command, netrcName), isNull);
        // No tmpfs of its own: the store lies under the home directory's, which
        // hides it already. It is a denial around the target all the same.
        expect(countMounts(command, ['--tmpfs', storeDir]), 0);
      },
    );

    test(
      'drops a symlinked carve-out reached through more than one link',
      () async {
        final (
          :homeDir,
          :hopName,
          :netrcTarget,
          netrcName: _,
          docsName: _,
          docsTarget: _,
          deniedPage: _,
          storeDir: _,
          danglingName: _,
          plainDir: _,
          plainDenied: _,
        ) = carveOutsOverDeniedTargets();

        final command = await wrap(
          _Filesystem(denyRead: [homeDir, netrcTarget], allowRead: [hopName]),
        );

        expect(lastMountAt(command, hopName), isNull);
      },
    );

    test('restores nothing for a carve-out whose link dangles', () async {
      final (
        :homeDir,
        :danglingName,
        netrcName: _,
        netrcTarget: _,
        docsName: _,
        docsTarget: _,
        deniedPage: _,
        storeDir: _,
        hopName: _,
        plainDir: _,
        plainDenied: _,
      ) = carveOutsOverDeniedTargets();

      final command = await wrap(
        _Filesystem(denyRead: [homeDir], allowRead: [danglingName]),
      );

      expect(
        countMounts(command, ['--ro-bind', danglingName, danglingName]),
        0,
      );
      expect(command, isNot(contains('$danglingName ')));
    });

    test(
      'drops a symlinked carve-out whose target is a masked credential',
      () async {
        final (
          :homeDir,
          :netrcName,
          :netrcTarget,
          docsName: _,
          docsTarget: _,
          deniedPage: _,
          storeDir: _,
          hopName: _,
          danglingName: _,
          plainDir: _,
          plainDenied: _,
        ) = carveOutsOverDeniedTargets();
        final storeDir = join(BASE, 'fakes');
        fs.mkdirSync(storeDir);
        final fakePath = join(storeDir, 'netrc');
        fs.writeFileSync(fakePath, 'SENTINEL\n');

        final command = await wrapCommandWithSandboxLinux(
          LinuxSandboxParams(
            command: 'echo ok',
            needsNetworkRestriction: false,
            allowAllUnixSockets: true,
            readConfig: FsReadRestrictionConfig(
              denyOnly: [homeDir],
              allowWithinDeny: [netrcName],
            ),
            maskedFileBinds: [(realPath: netrcTarget, fakePath: fakePath)],
            maskedFileStoreDir: storeDir,
          ),
        );

        expect(lastMountAt(command, netrcName), isNull);
        expect(
          indexOfMount(command, ['--ro-bind', fakePath, netrcTarget]),
          greaterThan(-1),
        );
      },
    );

    test(
      'serves none of the denied bytes through a symlinked carve-out (live bwrap)',
      () async {
        final (
          :homeDir,
          :netrcName,
          :netrcTarget,
          :docsName,
          :deniedPage,
          :storeDir,
          :plainDir,
          :plainDenied,
          docsTarget: _,
          hopName: _,
          danglingName: _,
        ) = carveOutsOverDeniedTargets();

        final denied = run(
          await wrap(
            _Filesystem(
              denyRead: [homeDir, netrcTarget],
              allowRead: [netrcName],
            ),
            'cat $netrcName 2>&1; echo DONE',
          ),
        );
        expect(denied.stdout, contains('DONE'));
        expect(denied.stdout, isNot(contains('SECRETTOKEN')));

        final directory = run(
          await wrap(
            _Filesystem(denyRead: [homeDir, deniedPage], allowRead: [docsName]),
            'cat ${join(docsName, 'sec', 'x')} 2>&1; echo DONE',
          ),
        );
        expect(directory.stdout, contains('DONE'));
        expect(directory.stdout, isNot(contains('SECRETPAGE')));

        final around = run(
          await wrap(
            _Filesystem(denyRead: [homeDir, storeDir], allowRead: [netrcName]),
            'cat $netrcName 2>&1; echo DONE',
          ),
        );
        expect(around.stdout, contains('DONE'));
        expect(around.stdout, isNot(contains('SECRETTOKEN')));

        // The control still reads everything the deeper deny does not cover.
        final control = run(
          await wrap(
            _Filesystem(
              denyRead: [homeDir, plainDenied],
              allowRead: [plainDir],
            ),
            'cat ${join(plainDir, 'sec', 'x')} 2>&1; cat ${join(plainDir, 'readme.md')} 2>&1; echo DONE',
          ),
        );
        expect(control.stdout, contains('DONE'));
        expect(control.stdout, isNot(contains('SECRETPAGE')));
        expect(control.stdout, contains('PAGETEXT'));
      },
      skip: BWRAP_CAN_NAMESPACE ? false : 'bwrap cannot create namespaces',
    );

    test(
      'never serves the real credential through a symlinked carve-out (live bwrap)',
      () async {
        final (
          :homeDir,
          :netrcName,
          :netrcTarget,
          docsName: _,
          docsTarget: _,
          deniedPage: _,
          storeDir: _,
          hopName: _,
          danglingName: _,
          plainDir: _,
          plainDenied: _,
        ) = carveOutsOverDeniedTargets();
        final storeDir = join(BASE, 'fakes');
        fs.mkdirSync(storeDir);
        final fakePath = join(storeDir, 'netrc');
        fs.writeFileSync(fakePath, 'SENTINEL\n');

        final result = run(
          await wrapCommandWithSandboxLinux(
            LinuxSandboxParams(
              command: "sh -c 'cat $netrcName 2>&1; echo DONE'",
              needsNetworkRestriction: false,
              allowAllUnixSockets: true,
              readConfig: FsReadRestrictionConfig(
                denyOnly: [homeDir],
                allowWithinDeny: [netrcName],
              ),
              maskedFileBinds: [(realPath: netrcTarget, fakePath: fakePath)],
              maskedFileStoreDir: storeDir,
            ),
          ),
        );

        expect(result.stdout, contains('DONE'));
        expect(result.stdout, isNot(contains('SECRETTOKEN')));
      },
      skip: BWRAP_CAN_NAMESPACE ? false : 'bwrap cannot create namespaces',
    );

    // The other side of that rule: only a deny that MOUNTS something overlaps
    // the target. An entry naming a path that is not there mounts nothing (the
    // manager hands every configured credential file to the read denies,
    // present or not), and neither does a file deny an allowRead entry lifts —
    // so neither may cost the carve-out its restore.
    test(
      'restores a symlinked carve-out around a read deny that is not there',
      () async {
        final (
          :homeDir,
          :docsName,
          :docsTarget,
          netrcName: _,
          netrcTarget: _,
          filesystem: _,
        ) = symlinkedAllowReadCarveOuts();

        final command = await wrap(
          _Filesystem(
            denyRead: [homeDir, join(docsTarget, 'secret.txt')],
            allowRead: [docsName],
          ),
        );

        expect(countMounts(command, ['--ro-bind', docsTarget, docsName]), 1);
      },
    );

    test(
      'restores a symlinked carve-out around a file deny an allowRead entry lifts',
      () async {
        final (
          :homeDir,
          :docsName,
          :docsTarget,
          netrcName: _,
          netrcTarget: _,
          filesystem: _,
        ) = symlinkedAllowReadCarveOuts();
        final readme = join(docsTarget, 'readme.md');

        final command = await wrap(
          _Filesystem(
            denyRead: [homeDir, readme],
            allowRead: [docsName, readme],
          ),
        );

        expect(countMounts(command, ['--ro-bind', '/dev/null', readme]), 0);
        expect(countMounts(command, ['--ro-bind', readme, readme]), 1);
        expect(countMounts(command, ['--ro-bind', docsTarget, docsName]), 1);
      },
    );

    test(
      'serves a symlinked carve-out no read deny lands inside (live bwrap)',
      () async {
        final (
          :homeDir,
          :docsName,
          :docsTarget,
          netrcName: _,
          netrcTarget: _,
          filesystem: _,
        ) = symlinkedAllowReadCarveOuts();
        final readme = join(docsTarget, 'readme.md');
        final read =
            'cat ${join(docsName, 'readme.md')} 2>&1; cat ${join(homeDir, 'other.txt')} 2>&1; echo DONE';

        final absent = run(
          await wrap(
            _Filesystem(
              denyRead: [homeDir, join(docsTarget, 'secret.txt')],
              allowRead: [docsName],
            ),
            read,
          ),
        );
        expect(absent.stdout, contains('DONE'));
        expect(absent.stdout, contains('PAGETEXT'));
        expect(absent.stdout, isNot(contains('HIDDEN')));

        final lifted = run(
          await wrap(
            _Filesystem(
              denyRead: [homeDir, readme],
              allowRead: [docsName, readme],
            ),
            read,
          ),
        );
        expect(lifted.stdout, contains('DONE'));
        expect(lifted.stdout, contains('PAGETEXT'));
        expect(lifted.stdout, isNot(contains('HIDDEN')));
      },
      skip: BWRAP_CAN_NAMESPACE ? false : 'bwrap cannot create namespaces',
    );

    // An entry that cannot be inspected is not mounted where it was written:
    // the tmpfs lands on the deepest directory above it that can be. That
    // stand-in is what hides the target here, and the carve-out's name sits
    // outside it, where the stand-in never reaches.
    carveOutUnderStandIn() {
      mkTree(BASE, {
        'home': {
          'u': {
            'app': {
              'data': {'readme.md': 'PAGETEXT\n'},
              'cfg': 'CFGTEXT\n',
            },
          },
        },
      });
      final homeDir = join(BASE, 'home');
      final appDir = join(homeDir, 'u', 'app');
      final docsName = join(homeDir, 'docs');
      Link(docsName).createSync(join('u', 'app', 'data'));
      return (
        homeDir: homeDir,
        appDir: appDir,
        docsName: docsName,
        uninspectable: join(appDir, 'cfg'),
      );
    }

    /** The wrap `uninspectable` answers EACCES throughout, as a parent made
     * unsearchable would. The spy is gone before the command runs, so a live
     * arm executes the plan against the real tree. */
    Future<String> wrapWithUninspectable(
      String uninspectable,
      _Filesystem filesystem, [
      String? command,
    ]) async {
      final realStat = fs.statSync;
      fs.statSync = (String p) {
        if (p == uninspectable) {
          throw NodeError('EACCES: permission denied', code: 'EACCES');
        }
        return realStat(p);
      };
      try {
        return await wrap(filesystem, command);
      } finally {
        fs.statSync = realStat;
      }
    }

    test(
      'drops a symlinked carve-out whose target a stand-in tmpfs hides',
      () async {
        final (:homeDir, :appDir, :docsName, :uninspectable) =
            carveOutUnderStandIn();

        final command = await wrapWithUninspectable(
          uninspectable,
          _Filesystem(
            denyRead: [homeDir, uninspectable],
            allowRead: [docsName],
          ),
        );

        // The stand-in names the app directory, which the home directory's tmpfs
        // hides already, so it is not mounted a second time; the carve-out is
        // refused against where the stand-in would have landed.
        expect(countMounts(command, ['--tmpfs', appDir]), 0);
        expect(lastMountAt(command, docsName), isNull);
      },
    );

    test(
      'serves nothing through a symlinked carve-out a stand-in hides (live bwrap)',
      () async {
        final (:homeDir, :docsName, :uninspectable, appDir: _) =
            carveOutUnderStandIn();

        final result = run(
          await wrapWithUninspectable(
            uninspectable,
            _Filesystem(
              denyRead: [homeDir, uninspectable],
              allowRead: [docsName],
            ),
            'cat ${join(docsName, 'readme.md')} 2>&1; echo DONE',
          ),
        );

        expect(result.stdout, contains('DONE'));
        expect(result.stdout, isNot(contains('PAGETEXT')));
      },
      skip: BWRAP_CAN_NAMESPACE ? false : 'bwrap cannot create namespaces',
    );

    pinsInsideWriteDeniedDirectory() {
      mkTree(PROJECT, {
        'x': {
          'y': {
            'z': {
              'app': {
                'repo': {
                  '.git': {'hooks': <String, Object>{}, 'config': '[core]\n'},
                },
                'owned.txt': 'KEEP\n',
              },
            },
          },
        },
      });
      final yDir = join(PROJECT, 'x', 'y');
      final zDir = join(yDir, 'z');
      final appDir = join(zDir, 'app');
      final repoDir = join(appDir, 'repo');
      return (
        zDir: zDir,
        appDir: appDir,
        repoDir: repoDir,
        filesystem: _Filesystem(
          allowWrite: [zDir],
          denyRead: [yDir],
          denyWrite: [appDir, join(repoDir, '.git', 'config')],
        ),
      );
    }

    test(
      'pins inside a write-denied directory; the directory deny bind still lands on top',
      () async {
        final (:zDir, :appDir, :repoDir, :filesystem) =
            pinsInsideWriteDeniedDirectory();

        final command = await wrap(filesystem);

        final gitDir = join(repoDir, '.git');
        final repoPin = indexOfMount(command, ['--ro-bind', repoDir, repoDir]);
        final gitPin = indexOfMount(command, ['--ro-bind', gitDir, gitDir]);
        final projectBind = indexOfMount(command, ['--bind', PROJECT, PROJECT]);
        expect(repoPin, greaterThan(-1));
        expect(gitPin, greaterThan(-1));
        // app is both pinned (first occurrence) and denied (last occurrence);
        // the deny bind lands after z's writable restore and after every pin.
        expect(countMounts(command, ['--ro-bind', appDir, appDir]), 2);
        final firstAppRo = indexOfMount(command, ['--ro-bind', appDir, appDir]);
        final lastAppRo = lastIndexOfMount(command, [
          '--ro-bind',
          appDir,
          appDir,
        ]);
        expect(firstAppRo, lessThan(projectBind));
        expect(
          lastAppRo,
          greaterThan(lastIndexOfMount(command, ['--bind', zDir, zDir])),
        );
        expect(lastAppRo, greaterThan(gitPin));
        expect(repoPin, lessThan(projectBind));
      },
    );

    test(
      'pins inside a write-denied directory; the directory deny bind still lands on top (live bwrap)',
      () async {
        final (:appDir, :repoDir, :filesystem, zDir: _) =
            pinsInsideWriteDeniedDirectory();

        final result = run(
          await wrap(
            filesystem,
            'echo evil > $repoDir/.git/planted 2>&1; echo evil >> $appDir/owned.txt 2>&1; echo DONE',
          ),
        );

        expect(result.stdout, contains('DONE'));
        expect(fs.existsSync(join(repoDir, '.git', 'planted')), false);
        expect(fs.readFileSync(join(appDir, 'owned.txt'), 'utf8'), 'KEEP\n');
      },
      skip: BWRAP_CAN_NAMESPACE ? false : 'bwrap cannot create namespaces',
    );

    // repo is denyRead-hidden and the carve-out sub inside it is restored
    // writable; x, between sub and the deeper leaf, is pinned. That restore
    // buries the pin, and a buried mount still answers the kernel's rename
    // check, so x cannot be moved aside.
    //
    // A denyWrite on repo itself would make this a different shape: its own
    // bind is dropped as tmpfs-hidden and sub, inside that write deny, comes
    // back read-only instead of writable (readonly-deny-dir-binds.test.ts).
    pinnedCorridorBelowCarveOut() {
      mkTree(PROJECT, {
        'repo': {
          'sub': {
            'x': {'secret': 'DENYTEST\n'},
          },
          'hidden.txt': 'X\n',
        },
      });
      final repoDir = join(PROJECT, 'repo');
      final subDir = join(repoDir, 'sub');
      final xDir = join(subDir, 'x');
      final secretPath = join(xDir, 'secret');
      return (
        subDir: subDir,
        xDir: xDir,
        secretPath: secretPath,
        filesystem: _Filesystem(
          allowWrite: [subDir],
          denyRead: [repoDir],
          denyWrite: [secretPath],
        ),
      );
    }

    test(
      'pins the corridor below an allowWrite carve-out nested inside a read-denied directory',
      () async {
        final (:xDir, :filesystem, subDir: _, secretPath: _) =
            pinnedCorridorBelowCarveOut();

        final command = await wrap(filesystem);

        expect(countMounts(command, ['--ro-bind', xDir, xDir]), 1);
      },
    );

    test(
      'pins the corridor below an allowWrite carve-out nested inside a read-denied directory (live bwrap)',
      () async {
        final (:subDir, :secretPath, :filesystem, xDir: _) =
            pinnedCorridorBelowCarveOut();

        final result = run(
          await wrap(
            filesystem,
            'cd $subDir && mv x x2 && mkdir -p x && echo evil > $secretPath; echo $PROBE_DONE',
          ),
        );

        // The sentinel and a clean stderr first: a bwrap that never started
        // also exits non-zero and says nothing about the payload.
        expect(result.stdout ?? '', contains(PROBE_DONE));
        expect(result.stderr ?? '', isNot(contains('bwrap:')));
        expect(
          result.stderr ?? '',
          matches(RegExp('busy', caseSensitive: false)),
        );
        expect(fs.existsSync(join(subDir, 'x2')), false);
        expect(fs.readFileSync(secretPath, 'utf8'), 'DENYTEST\n');
      },
      skip: BWRAP_CAN_NAMESPACE ? false : 'bwrap cannot create namespaces',
    );

    // denyWrite dir > denyRead > allowWrite carve-out > denyWrite leaf, each
    // containing the next: the tmpfs re-application must not restore a write
    // path with an emitted deny bind under it.
    denyLeafUnderNestedCarveOut() {
      mkTree(PROJECT, {
        'd': {
          't': {
            'w': {'secret': 'PROTECT\n'},
          },
          'o.txt': 'X',
        },
      });
      final dDir = join(PROJECT, 'd');
      final tDir = join(dDir, 't');
      final wDir = join(tDir, 'w');
      final secretPath = join(wDir, 'secret');
      return (
        wDir: wDir,
        secretPath: secretPath,
        filesystem: _Filesystem(
          allowWrite: [wDir],
          denyRead: [tDir],
          denyWrite: [dDir, secretPath],
        ),
      );
    }

    test(
      'keeps a deny leaf protected when its carve-out sits inside a denyRead inside a denied directory',
      () async {
        final (:wDir, :secretPath, :filesystem) = denyLeafUnderNestedCarveOut();

        final command = await wrap(filesystem);

        final secretRo = lastIndexOfMount(command, [
          '--ro-bind',
          secretPath,
          secretPath,
        ]);
        expect(secretRo, greaterThan(-1));
        expect(
          lastIndexOfMount(command, ['--bind', wDir, wDir]),
          lessThan(secretRo),
        );
      },
    );

    test(
      'keeps a deny leaf protected when its carve-out sits inside a denyRead inside a denied directory (live bwrap)',
      () async {
        final (:secretPath, :filesystem, wDir: _) =
            denyLeafUnderNestedCarveOut();

        final result = run(
          await wrap(filesystem, 'echo evil >> $secretPath 2>&1; echo DONE'),
        );

        expect(result.stdout, contains('DONE'));
        expect(fs.readFileSync(secretPath, 'utf8'), 'PROTECT\n');
      },
      skip: BWRAP_CAN_NAMESPACE ? false : 'bwrap cannot create namespaces',
    );

    denyReadFileMask() {
      mkTree(PROJECT, {
        'config': {'secrets.json': '{"k":"REAL"}\n'},
      });
      final configDir = join(PROJECT, 'config');
      final secretPath = join(configDir, 'secrets.json');
      return (
        configDir: configDir,
        secretPath: secretPath,
        filesystem: _Filesystem(denyRead: [secretPath]),
      );
    }

    test('pins ancestors of denyRead file masks', () async {
      final (:configDir, :secretPath, :filesystem) = denyReadFileMask();

      final command = await wrap(filesystem);

      expect(countMounts(command, ['--ro-bind', '/dev/null', secretPath]), 1);
      expect(countMounts(command, ['--ro-bind', configDir, configDir]), 1);
    });

    test('pins ancestors of denyRead file masks (live bwrap)', () async {
      final (:secretPath, :filesystem, configDir: _) = denyReadFileMask();

      final result = run(
        await wrap(
          filesystem,
          'cd $PROJECT && mv config config-moved && mkdir config && echo attacker > $secretPath; echo $PROBE_DONE',
        ),
      );

      expect(result.stdout ?? '', contains(PROBE_DONE));
      expect(result.stderr ?? '', isNot(contains('bwrap:')));
      expect(result.stderr, matches(RegExp('busy', caseSensitive: false)));
      expect(fs.existsSync(join(PROJECT, 'config-moved')), false);
      expect(fs.readFileSync(secretPath, 'utf8'), '{"k":"REAL"}\n');
    }, skip: BWRAP_CAN_NAMESPACE ? false : 'bwrap cannot create namespaces');

    readDeniedDirectory() {
      mkTree(PROJECT, {
        'other': {
          'secrets': {'key.pem': 'REALKEY\n'},
        },
      });
      final otherDir = join(PROJECT, 'other');
      final secretsDir = join(otherDir, 'secrets');
      return (
        otherDir: otherDir,
        secretsDir: secretsDir,
        filesystem: _Filesystem(denyRead: [secretsDir]),
      );
    }

    test(
      'pins ancestors of a read-denied directory, so it cannot be renamed out from under its tmpfs',
      () async {
        final (:otherDir, :secretsDir, :filesystem) = readDeniedDirectory();

        final command = await wrap(filesystem);

        expect(indexOfMount(command, ['--tmpfs', secretsDir]), greaterThan(-1));
        expect(countMounts(command, ['--ro-bind', otherDir, otherDir]), 1);
      },
    );

    test(
      'pins ancestors of a read-denied directory, so it cannot be renamed out from under its tmpfs (live bwrap)',
      () async {
        final (:secretsDir, :filesystem, otherDir: _) = readDeniedDirectory();

        final result = run(
          await wrap(
            filesystem,
            'cd $PROJECT && mv other o2; cat o2/secrets/key.pem 2>&1; echo DONE',
          ),
        );

        expect(result.stdout, contains('DONE'));
        expect(result.stderr, matches(RegExp('busy', caseSensitive: false)));
        expect(result.stdout, isNot(contains('REALKEY')));
        expect(fs.existsSync(join(PROJECT, 'o2')), false);
        // The next command still finds the directory where its deny names it.
        final next = await wrap(
          filesystem,
          'cat $secretsDir/key.pem 2>&1; echo DONE',
        );
        expect(run(next).stdout, isNot(contains('REALKEY')));
      },
      skip: BWRAP_CAN_NAMESPACE ? false : 'bwrap cannot create namespaces',
    );

    test(
      'starts, and honours the carve-out, when a symlink and the directory holding its target are both read-denied',
      () async {
        // The merged-/usr shape under a root deny: bin -> usr/bin, lib -> usr/lib,
        // with the loader directory carved out through the lib link.
        mkTree(PROJECT, {
          'usr': {
            'bin': {'tool': 'TOOL\n'},
            'lib': {
              'x86': {'so': 'LIB\n'},
              'other': 'OTHER\n',
            },
            'share': {'doc': 'DOC\n'},
          },
        });
        Link(join(PROJECT, 'bin')).createSync(join('usr', 'bin'));
        Link(join(PROJECT, 'lib')).createSync(join('usr', 'lib'));
        final command = await wrap(
          _Filesystem(
            denyRead: [
              join(PROJECT, 'usr'),
              join(PROJECT, 'bin'),
              join(PROJECT, 'lib'),
            ],
            allowRead: [join(PROJECT, 'lib', 'x86')],
          ),
          'cat $PROJECT/lib/x86/so; cat $PROJECT/lib/other 2>&1; cat $PROJECT/bin/tool 2>&1; cat $PROJECT/usr/share/doc 2>&1; echo DONE',
        );
        final result = run(command);
        expect(result.stdout, contains('DONE'));
        expect(result.stdout, contains('LIB'));
        expect(result.stdout, isNot(contains('OTHER')));
        expect(result.stdout, isNot(contains('TOOL')));
        expect(result.stdout, isNot(contains('DOC')));
      },
      skip: BWRAP_CAN_NAMESPACE ? false : 'bwrap cannot create namespaces',
    );

    test(
      'does not let a symlink planted at an allowRead path re-open a read-denied directory',
      () async {
        final sshDir = join(BASE, 'home', '.ssh');
        mkTree(BASE, {
          'home': {
            '.ssh': {'id_rsa': 'PRIVATEKEY\n'},
          },
        });
        final docs = join(PROJECT, 'docs');
        final filesystem = _Filesystem(denyRead: [sshDir], allowRead: [docs]);

        // The first command plants the link where a docs directory is allowed.
        fs.mkdirSync(docs);
        final plant = await wrap(
          filesystem,
          'rm -rf $docs && ln -s $sshDir $docs && echo PLANTED',
        );
        expect(run(plant).stdout, contains('PLANTED'));

        final next = await wrap(
          filesystem,
          'cat $docs/id_rsa 2>&1; cat $sshDir/id_rsa 2>&1; echo DONE',
        );
        expect(next, isNot(contains('--ro-bind $sshDir $sshDir')));
        final result = run(next);
        expect(result.stdout, contains('DONE'));
        expect(result.stdout, isNot(contains('PRIVATEKEY')));
      },
      skip: BWRAP_CAN_NAMESPACE ? false : 'bwrap cannot create namespaces',
    );

    test(
      'pins ancestors of credential masks beneath the mask, which is emitted once',
      () async {
        mkTree(PROJECT, {
          'creds': {'token.txt': 'REAL\n'},
          'fakes': {'token.txt': 'FAKE\n'},
        });
        final credsDir = join(PROJECT, 'creds');
        final realPath = join(credsDir, 'token.txt');
        final fakePath = join(PROJECT, 'fakes', 'token.txt');
        Directory.current = PROJECT;

        final command = await wrapCommandWithSandboxLinux(
          LinuxSandboxParams(
            command: 'true',
            needsNetworkRestriction: false,
            allowAllUnixSockets: true,
            writeConfig: FsWriteRestrictionConfig(
              allowOnly: [PROJECT],
              denyWithinAllow: [],
            ),
            maskedFileBinds: [(realPath: realPath, fakePath: fakePath)],
          ),
        );

        final credsPin = indexOfMount(command, [
          '--ro-bind',
          credsDir,
          credsDir,
        ]);
        expect(credsPin, greaterThan(-1));
        expect(
          indexOfMount(command, ['--ro-bind', fakePath, realPath]),
          greaterThan(credsPin),
        );
        expect(countMounts(command, ['--ro-bind', fakePath, realPath]), 1);
      },
    );

    // A mask-only config passes no write config at all, so the root is bound
    // writable — the same shape as a '/' write root, and the pins go after that
    // bind under one writable cover. Without them the directory above the mask
    // is renamed aside and the real file read under its new name.
    maskOnlyConfig() {
      mkTree(PROJECT, {
        'creds': {'token.txt': 'REALTOKEN\n'},
        'fakes': {'token.txt': 'FAKE\n'},
      });
      final credsDir = join(PROJECT, 'creds');
      final realPath = join(credsDir, 'token.txt');
      final fakePath = join(PROJECT, 'fakes', 'token.txt');
      Directory.current = PROJECT;
      return (
        credsDir: credsDir,
        realPath: realPath,
        top: '/${BASE.split('/')[1]}',
        wrap: (String command) => wrapCommandWithSandboxLinux(
          LinuxSandboxParams(
            command: command,
            needsNetworkRestriction: false,
            allowAllUnixSockets: true,
            maskedFileBinds: [(realPath: realPath, fakePath: fakePath)],
          ),
        ),
      );
    }

    test(
      'pins and covers a credential mask when there are no write restrictions',
      () async {
        final (:credsDir, :realPath, :top, wrap: maskOnlyWrap) =
            maskOnlyConfig();
        final fakePath = join(PROJECT, 'fakes', 'token.txt');

        final command = await maskOnlyWrap('echo ok');

        expect(command, contains('--bind / /'));
        final credsPin = indexOfMount(command, [
          '--ro-bind',
          credsDir,
          credsDir,
        ]);
        final projectPin = indexOfMount(command, [
          '--ro-bind',
          PROJECT,
          PROJECT,
        ]);
        final cover = indexOfMount(command, ['--bind', top, top]);
        final mask = indexOfMount(command, ['--ro-bind', fakePath, realPath]);
        expect(credsPin, greaterThan(-1));
        expect(projectPin, greaterThan(-1));
        expect(cover, greaterThan(-1));
        expect(mask, greaterThan(-1));
        // A read-only cover would make the whole top-level directory read-only.
        expect(countMounts(command, ['--ro-bind', top, top]), 0);
        expect(credsPin, lessThan(cover));
        expect(cover, lessThan(mask));
      },
    );

    test(
      'pins and covers a credential mask when there are no write restrictions (live bwrap)',
      () async {
        final (:realPath, wrap: maskOnlyWrap, credsDir: _, top: _) =
            maskOnlyConfig();

        final result = run(
          await maskOnlyWrap(
            'cd $PROJECT && mv creds creds-moved 2>&1; cat $realPath 2>&1; echo DONE',
          ),
        );

        expect(result.stdout, contains('DONE'));
        expect(result.stderr ?? '', isNot(contains('bwrap:')));
        expect(result.stdout, matches(RegExp('busy', caseSensitive: false)));
        expect(result.stdout, isNot(contains('REALTOKEN')));
        expect(fs.existsSync(join(PROJECT, 'creds-moved')), false);
        expect(fs.readFileSync(realPath, 'utf8'), 'REALTOKEN\n');
      },
      skip: BWRAP_CAN_NAMESPACE ? false : 'bwrap cannot create namespaces',
    );

    maskInsideRestoredWritePath() {
      mkTree(PROJECT, {
        'd': {
          'w': {'secret': 'MASKME\n', 'other.txt': 'ok\n'},
        },
      });
      final wDir = join(PROJECT, 'd', 'w');
      final sLink = join(PROJECT, 's-link');
      final dLink = join(PROJECT, 'link');
      Link(sLink).createSync(join('d', 'w', 'secret'));
      Link(dLink).createSync('d');
      return (
        wDir: wDir,
        dLink: dLink,
        dDir: join(PROJECT, 'd'),
        secretCanonical: join(wDir, 'secret'),
        filesystem: _Filesystem(denyRead: [sLink, dLink], allowWrite: [wDir]),
      );
    }

    test(
      'restores a write path around a symlink-spelled mask inside it; the mask lands on top',
      () async {
        final (:wDir, :dLink, :dDir, :secretCanonical, :filesystem) =
            maskInsideRestoredWritePath();

        final command = await wrap(filesystem);

        // s-link is spelled shallower than link but lands deeper, so it mounts
        // after link's tmpfs and after w's restore. Both land where they lead.
        expect(countMounts(command, ['--tmpfs', dLink]), 0);
        final tmpfsOp = lastIndexOfMount(command, ['--tmpfs', dDir]);
        final wBind = lastIndexOfMount(command, ['--bind', wDir, wDir]);
        final mask = lastIndexOfMount(command, [
          '--ro-bind',
          '/dev/null',
          secretCanonical,
        ]);
        expect(tmpfsOp, greaterThan(-1));
        expect(wBind, greaterThan(tmpfsOp));
        expect(mask, greaterThan(wBind));
      },
    );

    test(
      'restores a write path around a symlink-spelled mask inside it; the mask lands on top (live bwrap)',
      () async {
        final (:wDir, :secretCanonical, :filesystem, dLink: _, dDir: _) =
            maskInsideRestoredWritePath();

        final result = run(
          await wrap(
            filesystem,
            'cat $secretCanonical 2>&1; echo evil >> $secretCanonical 2>&1; cat $wDir/other.txt; echo DONE',
          ),
        );

        expect(result.stdout, contains('DONE'));
        expect(result.stdout, contains('ok'));
        expect(result.stdout, isNot(contains('MASKME')));
        expect(fs.readFileSync(secretCanonical, 'utf8'), 'MASKME\n');
      },
      skip: BWRAP_CAN_NAMESPACE ? false : 'bwrap cannot create namespaces',
    );

    carveOutInsideEmittedDenyDir() {
      mkTree(PROJECT, {
        'D': {
          't': {
            'w': {'file.txt': 'KEEP\n'},
            'hidden.txt': 'HIDDEN\n',
          },
        },
      });
      final DDir = join(PROJECT, 'D');
      final tDir = join(DDir, 't');
      final wDir = join(tDir, 'w');
      return (
        DDir: DDir,
        tDir: tDir,
        wDir: wDir,
        filesystem: _Filesystem(
          allowWrite: [wDir],
          denyWrite: [DDir],
          denyRead: [tDir],
        ),
      );
    }

    test(
      'brings a carve-out inside an emitted denied directory back read-only across re-application',
      () async {
        final (:DDir, :tDir, :wDir, :filesystem) =
            carveOutInsideEmittedDenyDir();

        final command = await wrap(filesystem);

        // D's bind re-exposes t, so t's tmpfs is re-applied on top of it. The
        // write path inside is under the deny too: visible again, not writable.
        final DRo = lastIndexOfMount(command, ['--ro-bind', DDir, DDir]);
        final wBind = lastIndexOfMount(command, ['--bind', wDir, wDir]);
        final wRo = lastIndexOfMount(command, ['--ro-bind', wDir, wDir]);
        final tTmpfs = lastIndexOfMount(command, ['--tmpfs', tDir]);
        expect(DRo, greaterThan(-1));
        expect(wBind, lessThan(DRo));
        expect(tTmpfs, greaterThan(DRo));
        expect(wRo, greaterThan(tTmpfs));
      },
    );

    test(
      'brings a carve-out inside an emitted denied directory back read-only across re-application (live bwrap)',
      () async {
        final (:tDir, :wDir, :filesystem, DDir: _) =
            carveOutInsideEmittedDenyDir();

        final result = run(
          await wrap(
            filesystem,
            'echo evil > $wDir/planted.txt 2>&1; cat $wDir/file.txt; cat $tDir/hidden.txt 2>&1; echo DONE',
          ),
        );

        expect(result.stdout, contains('DONE'));
        expect(result.stdout, contains('KEEP'));
        expect(result.stdout, isNot(contains('HIDDEN')));
        expect(fs.existsSync(join(wDir, 'planted.txt')), false);
      },
      skip: BWRAP_CAN_NAMESPACE ? false : 'bwrap cannot create namespaces',
    );

    maskOverAllowWriteOfTheSameFile() {
      mkTree(PROJECT, {
        'd': {
          'w': {'secret': 'MASKME\n'},
        },
      });
      final secretCanonical = join(PROJECT, 'd', 'w', 'secret');
      final sLink = join(PROJECT, 's-link');
      final dLink = join(PROJECT, 'link');
      Link(sLink).createSync(join('d', 'w', 'secret'));
      Link(dLink).createSync('d');
      return (
        secretCanonical: secretCanonical,
        dLink: dLink,
        dDir: join(PROJECT, 'd'),
        filesystem: _Filesystem(
          denyRead: [sLink, dLink],
          allowWrite: [secretCanonical],
        ),
      );
    }

    test(
      'masks a read-denied file on top of an allowWrite entry naming the same file',
      () async {
        final (:secretCanonical, :dLink, :dDir, :filesystem) =
            maskOverAllowWriteOfTheSameFile();

        final command = await wrap(filesystem);

        expect(countMounts(command, ['--tmpfs', dLink]), 0);
        final tmpfsOp = lastIndexOfMount(command, ['--tmpfs', dDir]);
        final fileBind = lastIndexOfMount(command, [
          '--bind',
          secretCanonical,
          secretCanonical,
        ]);
        final mask = lastIndexOfMount(command, [
          '--ro-bind',
          '/dev/null',
          secretCanonical,
        ]);
        expect(tmpfsOp, greaterThan(-1));
        expect(mask, greaterThan(fileBind));
        expect(mask, greaterThan(tmpfsOp));
      },
    );

    test(
      'masks a read-denied file on top of an allowWrite entry naming the same file (live bwrap)',
      () async {
        final (:secretCanonical, :filesystem, dLink: _, dDir: _) =
            maskOverAllowWriteOfTheSameFile();

        final result = run(
          await wrap(
            filesystem,
            'cat $secretCanonical 2>&1; echo evil >> $secretCanonical 2>&1; echo DONE',
          ),
        );

        expect(result.stdout, contains('DONE'));
        expect(result.stdout, isNot(contains('MASKME')));
        expect(fs.readFileSync(secretCanonical, 'utf8'), 'MASKME\n');
      },
      skip: BWRAP_CAN_NAMESPACE ? false : 'bwrap cannot create namespaces',
    );

    test(
      'blocks renaming .git aside inside the sandbox, and the host tree is untouched',
      () async {
        mkTree(PROJECT, {
          '.git': {'hooks': <String, Object>{}, 'config': '[core]\n'},
        });

        final command = await wrap(
          const _Filesystem(),
          'cd $PROJECT && mv .git .git-moved && mkdir .git && echo planted > .git/config',
        );
        final result = run(command);

        expect(result.status, isNot(0));
        expect(
          result.stderr ?? '',
          matches(RegExp('busy', caseSensitive: false)),
        );
        expect(fs.existsSync(join(PROJECT, '.git-moved')), false);
        expect(
          fs.readFileSync(join(PROJECT, '.git', 'config'), 'utf8'),
          '[core]\n',
        );
      },
      skip: BWRAP_CAN_NAMESPACE ? false : 'bwrap cannot create namespaces',
    );

    test(
      'pins above the allow binds under one writable cover with a "/" write root',
      () async {
        mkTree(PROJECT, {
          '.git': {'hooks': <String, Object>{}, 'config': '[core]\n'},
        });
        final gitDir = join(PROJECT, '.git');
        final top = '/${BASE.split('/')[1]}';

        final command = await wrap(const _Filesystem(allowWrite: ['/']));

        // Pins beneath the root's own recursive bind would be buried by it, so
        // they go after the allow binds; the cover over them is what keeps them
        // off the lookup path, which lets the pins themselves stay read-only.
        final rootBind = indexOfMount(command, ['--bind', '/', '/']);
        final gitPin = indexOfMount(command, ['--ro-bind', gitDir, gitDir]);
        // Another write root is an ancestor like any other here: its own allow
        // bind is buried by the root's and no longer makes it a mountpoint.
        final projectPin = indexOfMount(command, [
          '--ro-bind',
          PROJECT,
          PROJECT,
        ]);
        final cover = indexOfMount(command, ['--bind', top, top]);
        expect(rootBind, greaterThan(-1));
        expect(projectPin, greaterThan(rootBind));
        expect(gitPin, greaterThan(projectPin));
        expect(cover, greaterThan(gitPin));
        // A read-only cover would make the whole top-level directory read-only.
        expect(countMounts(command, ['--ro-bind', top, top]), 0);
        // The deny bind still lands on top of both.
        final hooksDir = join(gitDir, 'hooks');
        expect(
          indexOfMount(command, ['--ro-bind', hooksDir, hooksDir]),
          greaterThan(cover),
        );
      },
    );

    test(
      'covers the top-level directory of a protected path sitting directly in it',
      () async {
        // The WORKDIR /app shape: a protected path one level below '/' has no
        // ancestor to pin, and the cover is the only thing that keeps its
        // top-level directory a mountpoint. /usr holds no other protected path,
        // so the cover can only come from this deny.
        final absent = '/usr/srt-ancestor-pin-probe';
        final command = await wrap(
          _Filesystem(allowWrite: ['/'], denyWrite: [absent]),
        );

        expect(command, contains('--ro-bind /dev/null $absent'));
        expect(command, contains('--bind /usr /usr'));
        expect(command, isNot(contains('--ro-bind /usr /usr')));
      },
    );

    test(
      'covers and pins nothing under /proc or /sys with a "/" write root',
      () async {
        // --proc and --dev replace two of those trees after the pins are spliced
        // in, and /sys is kernel state the root bind already holds read-only, so
        // a cover or a pin there would only fight the mount that follows it. A
        // sibling top-level directory still gets its cover from its own deny.
        final probe = 'srt-ancestor-pin-probe';
        final command = await wrap(
          _Filesystem(
            allowWrite: ['/'],
            denyWrite: ['/proc/$probe', '/sys/$probe', '/usr/$probe'],
          ),
        );

        expect(command, contains('--ro-bind /dev/null /proc/$probe'));
        expect(command, contains('--ro-bind /dev/null /sys/$probe'));
        expect(command, contains('--bind /usr /usr'));
        expect(command, isNot(contains('--bind /proc /proc')));
        expect(command, isNot(contains('--bind /sys /sys')));
        expect(command, isNot(contains('--ro-bind /sys /sys')));
      },
    );

    test(
      'adds no cover for a top-level directory that is an ordinary write root',
      () async {
        // The chain has to reach a top-level directory for the assertion to mean
        // anything, so the write root IS one: the walk visits it, finds it is an
        // allowed write root and stops. Without a '/' write root it keeps only
        // its own allow bind — never a second, writable cover over the pins.
        mkTree(PROJECT, {
          '.git': {'hooks': <String, Object>{}, 'config': '[core]\n'},
        });
        final top = '/${BASE.split('/')[1]}';

        final command = await wrap(_Filesystem(allowWrite: [top]));

        final gitDir = join(PROJECT, '.git');
        expect(countMounts(command, ['--ro-bind', gitDir, gitDir]), 1);
        expect(countMounts(command, ['--ro-bind', BASE, BASE]), 1);
        expect(countMounts(command, ['--bind', top, top]), 1);
      },
    );

    test(
      'renames and hard-links across every pinned ancestor under a "/" write root',
      () async {
        // mv copies when rename(2) fails with EXDEV, so only raw syscalls say
        // whether the pins put a filesystem boundary on the lookup path.
        mkTree(PROJECT, {
          '.git': {
            'hooks': <String, Object>{},
            'config': '[core]\n',
            'b.txt': 'b\n',
          },
          'sub': {'c.txt': 'c\n'},
          'a.txt': 'a\n',
        });
        final gitDir = join(PROJECT, '.git');
        fs.writeFileSync(join(BASE, 'outside.txt'), 'o\n');

        final result = run(
          await wrap(
            const _Filesystem(allowWrite: ['/']),
            nodeProbe([
              (
                'within',
                'fs.renameSync(${asJsString(join(PROJECT, 'a.txt'))}, ${asJsString(join(PROJECT, 'sub', 'a2.txt'))})',
              ),
              (
                'intoGit',
                'fs.renameSync(${asJsString(join(PROJECT, 'sub', 'c.txt'))}, ${asJsString(join(gitDir, 'c2.txt'))})',
              ),
              (
                'outOfGit',
                'fs.renameSync(${asJsString(join(gitDir, 'b.txt'))}, ${asJsString(join(PROJECT, 'b2.txt'))})',
              ),
              (
                'intoProject',
                'fs.renameSync(${asJsString(join(BASE, 'outside.txt'))}, ${asJsString(join(PROJECT, 'o2.txt'))})',
              ),
              (
                'linkIntoGit',
                'fs.linkSync(${asJsString(join(PROJECT, 'sub', 'a2.txt'))}, ${asJsString(join(gitDir, 'hard.txt'))})',
              ),
              (
                'writeInGit',
                "fs.writeFileSync(${asJsString(join(gitDir, 'new.txt'))}, 'x')",
              ),
            ]),
          ),
        );

        expect(result.stdout, contains(PROBE_DONE));
        for (final label in [
          'within',
          'intoGit',
          'outOfGit',
          'intoProject',
          'linkIntoGit',
          'writeInGit',
        ]) {
          expect(result.stdout, contains('$label=OK'));
        }
        expect(fs.existsSync(join(gitDir, 'hard.txt')), true);
        expect(fs.existsSync(join(PROJECT, 'o2.txt')), true);
      },
      skip: BWRAP_CAN_NAMESPACE ? false : 'bwrap cannot create namespaces',
    );

    test(
      'refuses to move, exchange or remove any pinned ancestor under a "/" write root',
      () async {
        mkTree(PROJECT, {
          '.git': {'hooks': <String, Object>{}, 'config': '[core]\n'},
          'exch': <String, Object>{},
        });
        final gitDir = join(PROJECT, '.git');

        final result = run(
          await wrap(
            const _Filesystem(allowWrite: ['/']),
            nodeProbe([
              (
                'moveGit',
                'fs.renameSync(${asJsString(gitDir)}, ${asJsString(join(PROJECT, '.git-aside'))})',
              ),
              (
                'moveProject',
                'fs.renameSync(${asJsString(PROJECT)}, ${asJsString(join(BASE, 'project2'))})',
              ),
              (
                'moveBase',
                'fs.renameSync(${asJsString(BASE)}, ${asJsString('${BASE}2')})',
              ),
              ('rmdirGit', 'fs.rmdirSync(${asJsString(gitDir)})'),
              (
                'rmdirHooks',
                'fs.rmdirSync(${asJsString(join(gitDir, 'hooks'))})',
              ),
            ]),
          ),
        );

        expect(result.stdout, contains(PROBE_DONE));
        for (final label in [
          'moveGit',
          'moveProject',
          'moveBase',
          'rmdirGit',
          'rmdirHooks',
        ]) {
          expect(result.stdout, contains('$label=EBUSY'));
        }
        expect(fs.readFileSync(join(gitDir, 'config'), 'utf8'), '[core]\n');
        expect(fs.existsSync('${BASE}2'), false);
      },
      skip: BWRAP_CAN_NAMESPACE ? false : 'bwrap cannot create namespaces',
    );

    test(
      'blocks an exchange-rename of a pinned directory under a "/" write root',
      () async {
        mkTree(PROJECT, {
          '.git': {'hooks': <String, Object>{}, 'config': '[core]\n'},
          'exch': <String, Object>{},
        });

        final result = run(
          await wrap(
            const _Filesystem(allowWrite: ['/']),
            '''cd $PROJECT && python3 -c "import ctypes, sys; libc = ctypes.CDLL(None, use_errno=True); r = libc.renameat2(-100, b'.git', -100, b'exch', 2); print('exchange=' + ('OK' if r == 0 else str(ctypes.get_errno())))"; echo $PROBE_DONE''',
          ),
        );

        expect(result.stdout, contains(PROBE_DONE));
        // 16 is EBUSY.
        expect(result.stdout, contains('exchange=16'));
        expect(fs.existsSync(join(PROJECT, '.git', 'config')), true);
      },
      skip: BWRAP_CAN_NAMESPACE && CAN_CALL_RENAMEAT2
          ? false
          : 'needs bwrap namespaces and renameat2',
    );

    test(
      'lets git commit in a pinned repository under a "/" write root',
      () async {
        mkTree(PROJECT, {'index.js': 'console.log(1)\n'});
        expect(
          spawnSync('git', [
            '-c',
            'init.defaultBranch=main',
            'init',
            '-q',
            PROJECT,
          ]).status,
          0,
        );

        final result = run(
          await wrap(
            const _Filesystem(allowWrite: ['/']),
            'cd $PROJECT && git add index.js && git -c user.name=t -c user.email=t@t -c commit.gpgsign=false -c core.hooksPath=/dev/null commit -q -m init && echo $PROBE_DONE',
          ),
        );

        expect(result.stdout, contains(PROBE_DONE));
        expect(
          fs.existsSync(join(PROJECT, '.git', 'refs', 'heads', 'main')),
          true,
        );
      },
      skip: BWRAP_CAN_NAMESPACE && whichSync('git') != null
          ? false
          : 'needs bwrap namespaces and git',
    );

    test('blocks renaming .git aside under a "/" write root too', () async {
      mkTree(PROJECT, {
        '.git': {'hooks': <String, Object>{}, 'config': '[core]\n'},
      });

      final command = await wrap(
        const _Filesystem(allowWrite: ['/']),
        'cd $PROJECT && echo work > newfile.txt && (mv .git .git-moved && mkdir .git && echo planted > .git/config) 2>&1; echo DONE',
      );
      final result = run(command);

      expect(result.stdout, contains('DONE'));
      expect(result.stderr ?? '', isNot(contains('bwrap:')));
      expect(result.stdout, matches(RegExp('busy', caseSensitive: false)));
      expect(fs.existsSync(join(PROJECT, 'newfile.txt')), true);
      expect(fs.existsSync(join(PROJECT, '.git-moved')), false);
      expect(
        fs.readFileSync(join(PROJECT, '.git', 'config'), 'utf8'),
        '[core]\n',
      );
    }, skip: BWRAP_CAN_NAMESPACE ? false : 'bwrap cannot create namespaces');

    test('blocks rmdir of the pinned directory', () async {
      mkTree(PROJECT, {
        '.git': {'hooks': <String, Object>{}, 'config': '[core]\n'},
      });

      final result = run(
        await wrap(
          const _Filesystem(),
          'cd $PROJECT && rmdir .git; echo $PROBE_DONE',
        ),
      );

      expect(result.stdout ?? '', contains(PROBE_DONE));
      expect(result.stderr ?? '', isNot(contains('bwrap:')));
      expect(result.stderr, matches(RegExp('busy', caseSensitive: false)));
      expect(fs.existsSync(join(PROJECT, '.git')), true);
    }, skip: BWRAP_CAN_NAMESPACE ? false : 'bwrap cannot create namespaces');

    test(
      'blocks renaming the pinned directory with the seccomp helper in the stack',
      () async {
        // Every other live arm here sets allowAllUnixSockets, which drops the
        // apply-seccomp stage. That stage makes its own user, PID and mount
        // namespaces and remounts /proc inside them, so the pins have to
        // survive it — otherwise they protect nothing in the configuration
        // the library actually ships.
        mkTree(PROJECT, {
          '.git': {'hooks': <String, Object>{}, 'config': '[core]\n'},
        });
        Directory.current = PROJECT;

        final result = run(
          await wrapCommandWithSandboxLinux(
            LinuxSandboxParams(
              command:
                  'cd $PROJECT && mv .git .git-moved 2>&1; echo $PROBE_DONE',
              needsNetworkRestriction: false,
              writeConfig: FsWriteRestrictionConfig(
                allowOnly: [PROJECT],
                denyWithinAllow: [],
              ),
            ),
          ),
        );

        expect(result.stdout ?? '', contains(PROBE_DONE));
        expect(result.stderr ?? '', isNot(contains('bwrap:')));
        expect(
          result.stdout ?? '',
          matches(RegExp('busy', caseSensitive: false)),
        );
        expect(fs.existsSync(join(PROJECT, '.git-moved')), false);
        expect(
          fs.readFileSync(join(PROJECT, '.git', 'config'), 'utf8'),
          '[core]\n',
        );
      },
      skip: BWRAP_CAN_NAMESPACE && APPLY_SECCOMP != null
          ? false
          : 'needs bwrap namespaces and the apply-seccomp helper',
    );

    test(
      'blocks an exchange-rename of the pinned directory',
      () async {
        mkTree(PROJECT, {
          '.git': {'hooks': <String, Object>{}, 'config': '[core]\n'},
          'exch': <String, Object>{},
        });

        // renameat2(RENAME_EXCHANGE) must fail EBUSY (errno 16): the probe
        // exits 0 only in that case.
        final command = await wrap(
          const _Filesystem(),
          '''cd $PROJECT && python3 -c "import ctypes, os, sys; libc = ctypes.CDLL(None, use_errno=True); r = libc.renameat2(-100, b'.git', -100, b'exch', 2); sys.exit(0 if r != 0 and ctypes.get_errno() == 16 else 1)"''',
        );

        expect(run(command).status, 0);
        expect(fs.existsSync(join(PROJECT, '.git', 'config')), true);
      },
      skip: BWRAP_CAN_NAMESPACE && CAN_CALL_RENAMEAT2
          ? false
          : 'needs bwrap namespaces and renameat2',
    );

    test(
      'leaves normal work inside the pinned directory and the project intact',
      () async {
        mkTree(PROJECT, {
          '.git': {'hooks': <String, Object>{}, 'config': '[core]\n'},
          'sub': {'file.txt': 'data\n'},
        });

        final command = await wrap(
          const _Filesystem(),
          'cd $PROJECT && echo idx > .git/index && mkdir .git/objects && echo n > newfile.txt && mv sub sub-renamed && echo ALL_OK',
        );
        final result = run(command);

        expect(result.stdout, contains('ALL_OK'));
        expect(result.status, 0);
        expect(fs.existsSync(join(PROJECT, '.git', 'index')), true);
        expect(fs.existsSync(join(PROJECT, 'sub-renamed')), true);

        final straddle = await wrap(
          const _Filesystem(),
          '''cd $PROJECT && $_execPath -e "require('fs').renameSync('README.md', '.git/README.md')" && echo STRADDLE_OK''',
        );
        expect(run(straddle).stdout, contains('STRADDLE_OK'));
        expect(fs.existsSync(join(PROJECT, '.git', 'README.md')), true);
        expect(fs.existsSync(join(PROJECT, 'README.md')), false);
      },
      skip: BWRAP_CAN_NAMESPACE ? false : 'bwrap cannot create namespaces',
    );

    test(
      'does not pin above a nested repo deeper than the mandatory-deny scan depth',
      () async {
        // a/b/c/.git/config sits at depth 5 (ripgrep's --max-depth counts the
        // file itself); the default scan depth of 3 never finds it, so there is
        // no deny bind there and nothing to pin. Raising the depth finds it and
        // pins the whole chain.
        mkTree(PROJECT, {
          'a': {
            'b': {
              'c': {
                '.git': {'hooks': <String, Object>{}, 'config': '[core]\n'},
              },
            },
          },
        });
        final cDir = join(PROJECT, 'a', 'b', 'c');
        final gitDir = join(cDir, '.git');

        final shallow = await wrap();
        expect(shallow, isNot(contains('--ro-bind $gitDir/config')));
        expect(shallow, isNot(contains('--ro-bind $gitDir $gitDir')));
        expect(shallow, isNot(contains('--ro-bind $cDir $cDir')));

        Directory.current = PROJECT;
        final deep = await wrapCommandWithSandboxLinux(
          LinuxSandboxParams(
            command: 'true',
            needsNetworkRestriction: false,
            allowAllUnixSockets: true,
            mandatoryDenySearchDepth: 5,
            writeConfig: FsWriteRestrictionConfig(
              allowOnly: [PROJECT],
              denyWithinAllow: [],
            ),
          ),
        );
        expect(deep, contains('--ro-bind $gitDir/config $gitDir/config'));
        for (final dir in [
          join(PROJECT, 'a'),
          join(PROJECT, 'a', 'b'),
          cDir,
          gitDir,
        ]) {
          expect(deep, contains('--ro-bind $dir $dir'));
        }
      },
    );

    test(
      'lets git and cross-directory renames work in a nested repo whose ancestors are pinned',
      () async {
        // app is a nested repo at depth 1: app/.git/config and hooks are
        // mandatory denies found by the depth scan, so app and app/.git are
        // pinned.
        mkTree(PROJECT, {
          'app': {
            'index.js': 'console.log(1)\n',
            'notes.txt': 'n\n',
            'node_modules': {
              '.staging': {
                'left-pad-abc': {'index.js': 'x'},
              },
            },
          },
        });
        final appDir = join(PROJECT, 'app');
        final gitInit = spawnSync(
          'git',
          ['-c', 'init.defaultBranch=main', 'init', '-q', appDir],
          {'encoding': 'utf8'},
        );
        expect(gitInit.status, 0);

        final command = await wrap(const _Filesystem());
        expect(command, contains('--ro-bind $appDir $appDir'));
        expect(
          command,
          contains('--ro-bind ${join(appDir, '.git')} ${join(appDir, '.git')}'),
        );

        // The npm-style staging rename (node_modules/.staging/x to
        // node_modules/x) inside the pinned directory works.
        final staged = join(appDir, 'node_modules', '.staging', 'left-pad-abc');
        final finalPath = join(appDir, 'node_modules', 'left-pad');
        final npmLike = await wrap(
          const _Filesystem(),
          '''$_execPath -e "require('fs').renameSync('$staged', '$finalPath')" && echo RENAME_OK''',
        );
        final npmResult = run(npmLike);
        expect(npmResult.stdout, contains('RENAME_OK'));
        expect(fs.existsSync(join(finalPath, 'index.js')), true);

        // A plain rename(2) that straddles the pinned directory (app to
        // PROJECT and back) sees no mount boundary: it succeeds without a
        // copy fallback in either direction.
        final straddle = await wrap(
          const _Filesystem(),
          '''cd $appDir && $_execPath -e "try { require('fs').renameSync('notes.txt', '../notes.txt'); console.log('NO_ERROR') } catch (e) { console.log('CODE=' + e.code) }" && mv ../notes.txt ./notes-back.txt && echo MV_OK''',
        );
        final straddleResult = run(straddle);
        expect(straddleResult.stdout, contains('NO_ERROR'));
        expect(straddleResult.stdout, contains('MV_OK'));
        expect(fs.existsSync(join(appDir, 'notes-back.txt')), true);
        expect(fs.existsSync(join(PROJECT, 'notes.txt')), false);
        expect(fs.existsSync(join(appDir, 'notes.txt')), false);

        // git's ordinary object/index/ref writes, including its atomic
        // rename-into-place of lockfiles within .git, work.
        final gitWork = await wrap(
          const _Filesystem(),
          'cd $appDir && git add index.js && git -c user.name=t -c user.email=t@t -c commit.gpgsign=false -c core.hooksPath=/dev/null commit -q -m init && git log --oneline | wc -l && echo GIT_OK',
        );
        final gitResult = run(gitWork);
        expect(gitResult.status, 0);
        expect(gitResult.stdout, contains('GIT_OK'));
        expect(
          fs.existsSync(join(appDir, '.git', 'refs', 'heads', 'main')),
          true,
        );
      },
      skip: BWRAP_CAN_NAMESPACE && whichSync('git') != null
          ? false
          : 'needs bwrap namespaces and git',
    );

    // top is read-denied and contains the nested repo's .git/config deny;
    // top/.git sits between them and is pinned, top itself is pinned too, and
    // the tmpfs on top is emitted after both so it still hides them.
    readDeniedDirAboveNestedRepo() {
      mkTree(PROJECT, {
        'top': {
          '.git': {'hooks': <String, Object>{}, 'config': '[core]\n'},
        },
      });
      final topDir = join(PROJECT, 'top');
      return (
        topDir: topDir,
        gitDir: join(topDir, '.git'),
        filesystem: _Filesystem(denyRead: [topDir]),
      );
    }

    test(
      'pins the ancestor between a read-denied directory and a nested repo deny below it; the tmpfs lands after the pin',
      () async {
        final (:topDir, :gitDir, :filesystem) = readDeniedDirAboveNestedRepo();

        final command = await wrap(filesystem);

        final topPin = indexOfMount(command, ['--ro-bind', topDir, topDir]);
        final gitPin = indexOfMount(command, ['--ro-bind', gitDir, gitDir]);
        final tmpfsOp = indexOfMount(command, ['--tmpfs', topDir]);
        expect(topPin, greaterThan(-1));
        expect(gitPin, greaterThan(-1));
        expect(topPin, lessThan(tmpfsOp));
        expect(gitPin, lessThan(tmpfsOp));
        expect(
          gitPin,
          lessThan(indexOfMount(command, ['--bind', PROJECT, PROJECT])),
        );
      },
    );

    test(
      'pins the ancestor between a read-denied directory and a nested repo deny below it; the tmpfs lands after the pin (live bwrap)',
      () async {
        final (:gitDir, :filesystem, topDir: _) =
            readDeniedDirAboveNestedRepo();

        final result = run(
          await wrap(filesystem, 'cat $gitDir/config 2>&1; echo DONE'),
        );

        expect(result.stdout ?? '', isNot(contains('[core]')));
        expect(result.stdout ?? '', contains('DONE'));
      },
      skip: BWRAP_CAN_NAMESPACE ? false : 'bwrap cannot create namespaces',
    );
  }, skip: isLinux ? false : 'Linux only');
}
