// Ported from sandbox-runtime test/sandbox/stale-mount-point.test.ts @ 24eb39e.
// ignore_for_file: constant_identifier_names, non_constant_identifier_names, slash_for_doc_comments, no_leading_underscores_for_local_identifiers
import 'dart:convert';
import 'dart:io' as io;

import 'package:path/path.dart' show basename, join;
import 'package:sandbox_runtime/src/node/child_process.dart' show spawnSync;
import 'package:sandbox_runtime/src/node/fs.dart'
    show
        chmodSync,
        existsSync,
        lstatSync,
        mkdirSync,
        mkdtempSync,
        readFileSync,
        readdirNamesSync,
        realpathSync,
        rmSync,
        rmdirSync,
        symlinkSync,
        writeFileSync;
import 'package:sandbox_runtime/src/node/os.dart' show tmpdir;
import 'package:sandbox_runtime/src/node/process.dart' as process;
import 'package:sandbox_runtime/src/sandbox/linux_sandbox_utils.dart'
    show
        cleanupBwrapMountPoints,
        wrapCommandWithSandboxLinux,
        LinuxSandboxParams;
import 'package:sandbox_runtime/src/sandbox/sandbox_config.dart'
    show
        FilesystemConfig,
        FilesystemPathSpelling,
        NetworkConfig,
        SandboxRuntimeConfig;
import 'package:sandbox_runtime/src/sandbox/sandbox_manager.dart';
import 'package:sandbox_runtime/src/sandbox/sandbox_schemas.dart'
    show FsReadRestrictionConfig, FsWriteRestrictionConfig;
import 'package:sandbox_runtime/src/utils/which.dart' show whichSync;
import 'package:test/test.dart';

import '../helpers/bwrap_argv.dart' show countMounts, lastMountAt;
import '../helpers/bwrap_namespace.dart'
    show bwrapCanNamespace, bwrapCanNamespaceNetwork;
import '../helpers/platform.dart' show isLinux;

// Dart: the tests run from the package root.
final REPO_ROOT = io.Directory.current.path;

/** Echoed first by every command that runs for real, so an assertion about
 *  what the command did cannot pass on a sandbox that never started. */
const BOOTED = 'BOOTED';

({int? status, String stdout}) run(String command, [String? cwd]) {
  final r = spawnSync(command, [], {
    'shell': true,
    'encoding': 'utf8',
    'timeout': 15000,
    'cwd': cwd,
  });
  return (status: r.status, stdout: '${r.stdout}${r.stderr}');
}

// Dart: upstream runs a TypeScript script with `process.execPath`; this runs
// a Dart program with the package config of this package.
String _runScript() => io.Platform.resolvedExecutable;
List<String> _scriptArgs(String script) => [
  '--packages=${join(REPO_ROOT, '.dart_tool', 'package_config.json')}',
  script,
];

void main() {
  /**
   * A denyWrite path that does not exist gets `--ro-bind /dev/null <path>`, and
   * bwrap creates the mount point for it on the host: an empty file, mode 0444.
   * The wrapping process removes it after the command, from a set it keeps in
   * memory. A file that only looks like one is not in that set, and is not the
   * process's to remove: it may be the caller's own, or the mount point of
   * another process's sandbox that is still running, whose deny goes with it.
   */
  group('A file at a write-deny path', skip: isLinux ? null : 'describe.if(isLinux)', () {
    // Dart: the probe spawns bwrap, so it runs only where this group does.
    final BWRAP_CAN_NAMESPACE = isLinux && bwrapCanNamespace();
    late String BASE;
    late String AREA; // allowed write area
    late String LOCK; // the denyWrite path

    setUp(() {
      BASE = realpathSync(mkdtempSync(join(tmpdir(), 'stale-mount-point-')));
      AREA = join(BASE, 'area');
      LOCK = join(AREA, 'repo', '.git', 'config.lock');
      mkdirSync(join(AREA, 'repo', '.git'), {'recursive': true});
    });

    tearDown(() {
      cleanupBwrapMountPoints(force: true);
      rmSync(BASE, {'recursive': true, 'force': true});
    });

    Future<String> wrap([String command = 'true']) async {
      return wrapCommandWithSandboxLinux(
        LinuxSandboxParams(
          command: command,
          needsNetworkRestriction: false,
          readConfig: FsReadRestrictionConfig(denyOnly: []),
          writeConfig: FsWriteRestrictionConfig(
            allowOnly: [AREA],
            denyWithinAllow: [LOCK],
          ),
        ),
      );
    }

    // The chmod, so that it is the bind that refuses and not the file's mode.
    String WRITE() =>
        'echo $BOOTED; chmod u+w $LOCK; echo x >> $LOCK; echo rc=\$?';

    const FILES = <(String, int, String)>[
      ('empty and read-only, like a mount point bwrap made', 292, ''),
      ('empty, with write bits', 420, ''),
      ('read-only, with content', 292, 'x'),
    ];

    void plant(int mode, String content) {
      writeFileSync(LOCK, content);
      chmodSync(LOCK, mode);
    }

    for (final (_what, mode, content) in FILES) {
      test(
        'is bound onto itself and is not among what the clean-up removes: $_what',
        () async {
          plant(mode, content);

          final command = await wrap();

          expect(lastMountAt(command, LOCK), '--ro-bind $LOCK $LOCK');
          expect(countMounts(command, ['--ro-bind', '/dev/null', LOCK]), 0);
          cleanupBwrapMountPoints();
          expect(existsSync(LOCK), isTrue);
          cleanupBwrapMountPoints(force: true);
          expect(existsSync(LOCK), isTrue);
        },
      );
    }

    // Dart: evaluated only on Linux, where upstream's it.if(...) condition
    // is meaningful and its probes can run.
    final canRunNetworkSandbox =
        isLinux && bwrapCanNamespaceNetwork() && whichSync('socat') != null;
    for (final (_what, mode, content) in FILES) {
      test(
        'cannot be written in the sandbox, and is as it was after the clean-up and after reset(): $_what',
        skip: canRunNetworkSandbox
            ? null
            : 'it.if(bwrapCanNamespaceNetwork() && Bun.which(\'socat\') !== null)',
        () async {
          plant(mode, content);
          await SandboxManager.initialize(
            SandboxRuntimeConfig(
              network: NetworkConfig(allowedDomains: [], deniedDomains: []),
              filesystem: FilesystemConfig(
                denyRead: [],
                allowWrite: [FilesystemPathSpelling(AREA)],
                denyWrite: [FilesystemPathSpelling(LOCK)],
              ),
            ),
          );
          try {
            final write = run(await SandboxManager.wrapWithSandbox(WRITE()));
            expect(write.stdout, contains(BOOTED));
            expect(write.stdout, matches(RegExp(r'rc=[1-9]')));
            SandboxManager.cleanupAfterCommand();
            expect(readFileSync(LOCK, 'utf8'), content);
          } finally {
            await SandboxManager.reset();
          }
          expect(readFileSync(LOCK, 'utf8'), content);
          expect(lstatSync(LOCK).mode & 511, mode);
        },
      );
    }

    test(
      'is removed when this process had it made, though a later wrap found it there',
      skip: BWRAP_CAN_NAMESPACE ? null : 'it.if(BWRAP_CAN_NAMESPACE)',
      () async {
        expect(run(await wrap('echo $BOOTED')).stdout, contains(BOOTED));
        expect(existsSync(LOCK), isTrue);

        expect(lastMountAt(await wrap(), LOCK), '--ro-bind $LOCK $LOCK');

        cleanupBwrapMountPoints();
        // Unlinking it now would detach the second sandbox's bind.
        expect(existsSync(LOCK), isTrue);
        cleanupBwrapMountPoints();
        expect(existsSync(LOCK), isFalse);
      },
    );

    // A real leftover, not a hand-made one: a process wraps a command against
    // the absent path, runs it, and is killed before it can clean up.
    test(
      'stays when a killed process left it, and the next command starts with the path still denied',
      skip: BWRAP_CAN_NAMESPACE ? null : 'it.if(BWRAP_CAN_NAMESPACE)',
      () async {
        final script = join(BASE, 'killed-wrapper.dart');
        writeFileSync(
          script,
          [
            "import 'dart:io';",
            "import 'package:sandbox_runtime/src/node/child_process.dart';",
            "import 'package:sandbox_runtime/src/sandbox/linux_sandbox_utils.dart';",
            "import 'package:sandbox_runtime/src/sandbox/sandbox_schemas.dart';",
            'Future<void> main() async {',
            '  final command = await wrapCommandWithSandboxLinux(LinuxSandboxParams(',
            "    command: 'true',",
            '    needsNetworkRestriction: false,',
            '    readConfig: FsReadRestrictionConfig(denyOnly: []),',
            '    writeConfig: FsWriteRestrictionConfig(allowOnly: [${jsonEncode(AREA)}], denyWithinAllow: [${jsonEncode(LOCK)}]),',
            '  ));',
            "  final r = spawnSync(command, [], {'shell': true, 'timeout': 15000});",
            '  if (r.status != 0) exit(3);',
            '  Process.killPid(pid, ProcessSignal.sigkill);',
            '  await Future<void>.delayed(const Duration(seconds: 30));',
            '}',
          ].join('\n'),
        );
        final killed = spawnSync(_runScript(), _scriptArgs(script), {
          'encoding': 'utf8',
          'timeout': 30000,
        });
        expect(killed.signal, 'SIGKILL');
        expect(lstatSync(LOCK).isFile(), isTrue);

        final command = await wrap(WRITE());
        expect(lastMountAt(command, LOCK), '--ro-bind $LOCK $LOCK');
        final after = run(command);
        expect(after.stdout, contains(BOOTED));
        expect(after.stdout, matches(RegExp(r'rc=[1-9]')));
        cleanupBwrapMountPoints();
        expect(lstatSync(LOCK).size, 0);
      },
    );
  });

  /**
   * A denyWrite path whose first MISSING component is an intermediate directory
   * is blocked by binding a read-only empty directory over that component. Both
   * ends of that bind are host state this library owns: the destination bwrap
   * creates, and the source it is bound from.
   */
  group(
    'Mount points for deny paths that do not exist yet',
    skip: isLinux ? null : 'describe.if(isLinux)',
    () {
      // Dart: the probe spawns bwrap, so it runs only where this group does.
      final BWRAP_CAN_NAMESPACE = isLinux && bwrapCanNamespace();
      late String BASE;
      late String AREA; // allowed write area
      late String PROJ; // a project with no .claude/, so two mandatory denies
      //                  (.claude/commands, .claude/agents) are absent under it
      late String DOT_CLAUDE; // the destination both of them land on

      final savedCwd = process.cwd();
      final savedTmpdir = process.env['TMPDIR'];
      const SENTINEL = 'srt-524-written-through-the-source';

      setUp(() {
        // Drop any source a previous test file left cached in the module.
        cleanupBwrapMountPoints(force: true);
        BASE = realpathSync(mkdtempSync(join(tmpdir(), 'deny-placeholder-')));
        AREA = join(BASE, 'area');
        PROJ = join(AREA, 'proj');
        DOT_CLAUDE = join(PROJ, '.claude');
        mkdirSync(PROJ, {'recursive': true});
        process.chdir(PROJ);
        // The sources are minted under os.tmpdir(), which is read from the
        // environment per call. Point it at BASE, so counting the sources this
        // file makes cannot see another test file's, a sandboxed session running
        // on the machine, or an earlier failed run's.
        process.env['TMPDIR'] = BASE;
      });

      tearDown(() {
        process.chdir(savedCwd);
        cleanupBwrapMountPoints(force: true);
        if (savedTmpdir == null) {
          process.env.remove('TMPDIR');
        } else {
          process.env['TMPDIR'] = savedTmpdir;
        }
        // Takes away whatever a test planted under BASE, impostors included.
        rmSync(BASE, {'recursive': true, 'force': true});
      });

      Future<String> wrap([
        List<String> denyPaths = const [],
        String command = 'echo hello',
      ]) async {
        return wrapCommandWithSandboxLinux(
          LinuxSandboxParams(
            command: command,
            needsNetworkRestriction: false,
            readConfig: FsReadRestrictionConfig(denyOnly: []),
            writeConfig: FsWriteRestrictionConfig(
              allowOnly: [AREA],
              denyWithinAllow: denyPaths,
            ),
          ),
        );
      }

      /**
       * Like wrap(), but with the temp dir the sources are minted under writable
       * too: the shape a host $TMPDIR inside a default write path produces
       * (/tmp/claude is one, and it is the value this library stamps on
       * sandboxed children).
       */
      Future<String> wrapWithWritableTempDir([
        String command = 'echo hello',
      ]) async {
        return wrapCommandWithSandboxLinux(
          LinuxSandboxParams(
            command: command,
            needsNetworkRestriction: false,
            readConfig: FsReadRestrictionConfig(denyOnly: []),
            writeConfig: FsWriteRestrictionConfig(
              allowOnly: [AREA, BASE],
              denyWithinAllow: [],
            ),
          ),
        );
      }

      /**
       * The empty directory the LAST mount at `dest` binds from, or undefined
       * when that mount is not a placeholder of this kind. lastMountAt reads
       * whole argv words, so a destination the wrapper shell-quotes, or a
       * profile that went to the argument file, is refused outright instead of
       * reported as "nothing bound there".
       */
      String? placeholderSourceAt(String command, String dest) {
        final parts = lastMountAt(command, dest)?.split(' ') ?? <String>[];
        final flag = parts.isNotEmpty ? parts[0] : null;
        final source = parts.length > 1 ? parts[1] : null;
        return flag == '--ro-bind' &&
                source != null &&
                source.contains('/claude-empty-')
            ? source
            : null;
      }

      List<String> emptySourceDirs() {
        return readdirNamesSync(
          tmpdir(),
        ).where((n) => n.startsWith('claude-empty-')).toList();
      }

      test(
        'binds one source for every empty-directory mount point, and takes it away with them',
        () async {
          // A source per bind left two directories behind under the temp dir on
          // every command: only the destination was ever tracked.
          final sources = <String>[];
          for (var i = 0; i < 3; i++) {
            final command = await wrap();
            final source = placeholderSourceAt(command, DOT_CLAUDE);
            expect(source, isNotNull);
            // .claude/commands and .claude/agents share the missing component
            // <cwd>/.claude: one destination, one bind, one source.
            expect(countMounts(command, ['--ro-bind', source!, DOT_CLAUDE]), 1);
            sources.add(source);
          }
          expect(sources.toSet().length, 1);
          expect(emptySourceDirs(), [basename(sources[0])]);

          cleanupBwrapMountPoints(force: true);
          expect(emptySourceDirs(), []);

          // A wrap after the cleanup makes a new one rather than binding a path
          // that is no longer there.
          final source = placeholderSourceAt(await wrap(), DOT_CLAUDE);
          expect(source, isNotNull);
          expect(source, isNot(sources[0]));
          expect(existsSync(source!), isTrue);
        },
      );

      test(
        'emits one placeholder per destination, as a directory when the kinds collide',
        () async {
          // denyWrite names the missing <cwd>/.claude itself, which asks for a
          // /dev/null placeholder, while the mandatory <cwd>/.claude/commands asks
          // for a directory at the same destination.
          final command = await wrap([DOT_CLAUDE]);

          final source = placeholderSourceAt(command, DOT_CLAUDE);
          expect(source, isNotNull);
          // One bind of the directory form, and no /dev/null one anywhere: the
          // last mount at the destination being the directory form is not on its
          // own enough, an earlier /dev/null bind there is the abort.
          expect(countMounts(command, ['--ro-bind', source!, DOT_CLAUDE]), 1);
          expect(
            countMounts(command, ['--ro-bind', '/dev/null', DOT_CLAUDE]),
            0,
          );
        },
      );

      test(
        'starts the sandbox when a deny and a mandatory deny share one missing component',
        skip: !BWRAP_CAN_NAMESPACE ? 'it.skipIf(!BWRAP_CAN_NAMESPACE)' : null,
        () async {
          // Two binds at one destination made bwrap refuse to start with
          // "Can't mkdir <dest>: Not a directory".
          final started = run(await wrap([DOT_CLAUDE], 'echo $BOOTED'), PROJ);
          expect(started.stdout, isNot(matches(RegExp(r'Not a directory'))));
          expect(started.status, 0);
          expect(started.stdout, contains(BOOTED));

          // That run left the mount point on the host. Without taking it away
          // the next wrap sees an existing path and emits no placeholder at all,
          // so the deny below would not be the one this test is about.
          cleanupBwrapMountPoints(force: true);
          expect(existsSync(DOT_CLAUDE), isFalse);

          final denyCommand = await wrap(
            [DOT_CLAUDE],
            'echo $BOOTED; mkdir -p ${join(DOT_CLAUDE, 'commands')}; echo rc=\$?',
          );
          final source = placeholderSourceAt(denyCommand, DOT_CLAUDE);
          expect(source, isNotNull);
          expect(
            countMounts(denyCommand, ['--ro-bind', source!, DOT_CLAUDE]),
            1,
          );

          // The deny still holds, and nothing is left on the host.
          final denied = run(denyCommand, PROJ);
          expect(denied.stdout, contains(BOOTED));
          expect(denied.stdout, matches(RegExp(r'rc=[1-9]')));
          cleanupBwrapMountPoints(force: true);
          expect(existsSync(DOT_CLAUDE), isFalse);
        },
      );

      test(
        'reuses the source while it is still our own empty directory',
        () async {
          final first = placeholderSourceAt(await wrap(), DOT_CLAUDE);
          expect(first, isNotNull);
          expect(placeholderSourceAt(await wrap(), DOT_CLAUDE), first!);
        },
      );

      // The source sits under the system temp dir, which sandboxed commands
      // commonly can write, and bwrap resolves a bind source on the host —
      // reusing a path that has become something else would publish it at the
      // placeholder's destination.
      for (final (_what, tamper) in <(String, void Function(String))>[
        (
          'it has been swapped for a symlink',
          (String p) {
            final decoy = join(BASE, 'decoy');
            mkdirSync(decoy, {'recursive': true});
            writeFileSync(join(decoy, 'secret.txt'), 'x\n');
            rmdirSync(p);
            symlinkSync(decoy, p);
          },
        ),
        (
          'something has been written into it',
          (String p) => writeFileSync(join(p, 'planted'), ''),
        ),
        ('its mode has been widened', (String p) => chmodSync(p, 493)),
      ]) {
        test('makes a fresh source when $_what', () async {
          final first = placeholderSourceAt(await wrap(), DOT_CLAUDE)!;
          tamper(first);

          final command = await wrap();
          final second = placeholderSourceAt(command, DOT_CLAUDE)!;
          expect(second, isNot(first));
          // Neither bound over the destination nor pinned: nothing in this wrap
          // reaches the path that is no longer ours.
          expect(countMounts(command, ['--ro-bind', first, DOT_CLAUDE]), 0);
          expect(countMounts(command, ['--ro-bind', first, first]), 0);
          expect(lstatSync(second).isSymbolicLink(), isFalse);
          expect(readdirNamesSync(second), []);

          // What was there is left exactly as found: it is not ours any more.
          cleanupBwrapMountPoints(force: true);
          expect(existsSync(first), isTrue);
        });
      }

      test('keeps one source under a umask that clears the owner write bit', () async {
        // mkdtemp asks for 0700 and the umask applies, so under `umask 0200` the
        // directory it makes is 0500. A revalidation that insists on exactly
        // 0700 rejects the directory the same call has just made, and every
        // placeholder mints another one that nothing will remove.
        final script = join(BASE, 'umask-wrapper.dart');
        writeFileSync(
          script,
          [
            "import 'dart:ffi';",
            "import 'package:sandbox_runtime/src/sandbox/linux_sandbox_utils.dart';",
            "import 'package:sandbox_runtime/src/sandbox/sandbox_schemas.dart';",
            'Future<void> main() async {',
            // Dart: no process.umask; call libc's umask directly.
            "  DynamicLibrary.process().lookupFunction<Uint32 Function(Uint32), int Function(int)>('umask')(128);",
            '  for (var i = 0; i < 2; i++) {',
            '    print(',
            '      await wrapCommandWithSandboxLinux(LinuxSandboxParams(',
            "        command: 'true',",
            '        needsNetworkRestriction: false,',
            '        readConfig: FsReadRestrictionConfig(denyOnly: []),',
            '        writeConfig: FsWriteRestrictionConfig(allowOnly: [${jsonEncode(AREA)}], denyWithinAllow: []),',
            '      )),',
            '    );',
            '  }',
            '}',
          ].join('\n'),
        );
        final wrapped = spawnSync(_runScript(), _scriptArgs(script), {
          'encoding': 'utf8',
          'timeout': 30000,
          'cwd': PROJ,
          'env': {...process.env, 'TMPDIR': BASE},
        });
        expect(wrapped.status, 0);

        final mapped = (wrapped.stdout as String)
            .split('\n')
            .where((line) => line.contains('--ro-bind'))
            .map((line) => placeholderSourceAt(line, DOT_CLAUDE))
            .toList();
        final first = mapped.isNotEmpty ? mapped[0] : null;
        final second = mapped.length > 1 ? mapped[1] : null;
        expect(first, isNotNull);
        expect(second, first!);
      });

      test('pins the source read-only, after every other mount', () async {
        final command = await wrap();
        final source = placeholderSourceAt(command, DOT_CLAUDE)!;

        // Last, like the masked-file store's own pin, so nothing emitted after
        // it can put a writable mount back over the source — neither on the
        // source nor on a directory above it, which the scan below is for.
        // countMounts reads argv words and refuses a command whose profile went
        // to the argument file, so that scan cannot pass for free on one.
        final pin = '--ro-bind $source $source';
        expect(countMounts(command, ['--ro-bind', source, source]), 1);
        final after = command.substring(command.lastIndexOf(pin) + pin.length);
        expect(
          after,
          isNot(matches(RegExp(r'--ro-bind |--bind |--dev-bind |--tmpfs '))),
        );
      });

      test(
        'refuses a write into the source from inside the sandbox, so nothing reaches the denied destination',
        skip: !BWRAP_CAN_NAMESPACE ? 'it.skipIf(!BWRAP_CAN_NAMESPACE)' : null,
        () async {
          // With the temp dir writable, the source and the DENIED destination
          // are the same directory: a write to the source would appear at the
          // deny, in this sandbox and in every concurrent one sharing it.
          final source = placeholderSourceAt(
            await wrapWithWritableTempDir(),
            DOT_CLAUDE,
          )!;
          final planted = join(source, 'commands');
          final command = await wrapWithWritableTempDir(
            'echo $BOOTED; '
            'mkdir -p $planted 2>&1; echo "mkdir rc=\$?"; '
            'echo $SENTINEL > ${join(planted, 'x.md')} 2>&1; '
            'cat ${join(DOT_CLAUDE, 'commands', 'x.md')} 2>&1',
          );
          expect(placeholderSourceAt(command, DOT_CLAUDE), source);
          expect(countMounts(command, ['--ro-bind', source, DOT_CLAUDE]), 1);

          final attempt = run(command, PROJ);
          expect(attempt.stdout, contains(BOOTED));
          expect(attempt.stdout, matches(RegExp(r'mkdir rc=[1-9]')));
          expect(attempt.stdout, isNot(contains(SENTINEL)));
          expect(readdirNamesSync(source), []);
        },
      );
    },
  );
}
