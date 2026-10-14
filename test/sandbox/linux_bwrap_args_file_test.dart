// Ported from sandbox-runtime test/sandbox/linux-bwrap-args-file.test.ts @ 24eb39e.
// ignore_for_file: constant_identifier_names, non_constant_identifier_names, slash_for_doc_comments, prefer_interpolation_to_compose_strings
import 'dart:convert';
import 'dart:io' show Platform;

import 'package:path/path.dart' show join;
import 'package:sandbox_runtime/src/index.dart' show LinuxSandboxProfileError;
import 'package:sandbox_runtime/src/node/child_process.dart' show spawnSync;
import 'package:sandbox_runtime/src/node/fs.dart'
    show
        existsSync,
        mkdirSync,
        mkdtempSync,
        readFileSync,
        readlinkSync,
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
import 'package:sandbox_runtime/src/sandbox/sandbox_config.dart';
import 'package:sandbox_runtime/src/sandbox/sandbox_manager.dart';
import 'package:sandbox_runtime/src/sandbox/sandbox_schemas.dart';
import 'package:test/test.dart';

import '../helpers/bwrap_namespace.dart' show bwrapCanNamespace;
import '../helpers/platform.dart' show isLinux;

void main() {
  group('the bwrap profile error at the package root', () {
    test('carries a name, a code, and a cause only when one is given', () {
      final plain = LinuxSandboxProfileError('command_too_long', 'refused');
      expect(plain.name, 'LinuxSandboxProfileError');
      expect(plain.code, 'command_too_long');
      // Dart: no `in` operator or Object.keys; the cause is null when absent.
      expect(plain.cause, isNull);

      final open = Exception('no directory took an unnamed file');
      final withCause = LinuxSandboxProfileError(
        'args_file_unavailable',
        'refused',
        open,
      );
      expect(withCause.cause, same(open));
      // Non-enumerable, as a native `cause` is, so it stays out of the keys and
      // out of anything that walks them.
      // Dart: no property descriptors; `cause` is a field, not a key of anything.
    });
  });

  /**
   * A bwrap profile too large for one shell argument (32 pages) has its mounts
   * handed to bwrap through `--args`, from an unnamed file this process holds
   * open and the string reopens through /proc; a profile that fits stays on the
   * command line.
   */
  group(
    'bwrap --args for over-long profiles',
    skip: isLinux ? null : 'describe.if(isLinux)',
    () {
      final MAX_ARG_STRLEN =
          32 *
          int.parse(
            (spawnSync('getconf', ['PAGESIZE'], {'encoding': 'utf8'}).stdout
                    as String)
                .trim(),
          );
      // The largest rendering kept on the command line: the kernel's limit less
      // the NUL, less the 4 KiB left for a prefix of the caller's own.
      final INLINE_MAX = MAX_ARG_STRLEN - 1 - 4096;
      // The one rendered shape: the profile's path, then the options left before
      // and the words left after `--args 9`.
      final VIA_ARGS_FILE = RegExp(
        r'''^/bin/sh -c 'exec 9<"\$1" && shift && exec "\$@"' srt-args (\S+) bwrap (.*?) ?--args 9 (.*)$''',
        dotAll: true,
      );
      // Dart: the isolated scripts import the module by package URI.
      const MODULE =
          'package:sandbox_runtime/src/sandbox/linux_sandbox_utils.dart';

      late String BASE;
      final savedCwd = process.cwd();
      final BWRAP_CAN_NAMESPACE = isLinux && bwrapCanNamespace();

      setUp(() {
        // Other suites wrap without cleaning up, and the active count is shared.
        cleanupBwrapMountPoints(force: true);
        BASE = realpathSync(mkdtempSync(join(tmpdir(), 'bwrap-args-')));
        // cwd outside the write allowlist keeps the mandatory-deny scan from
        // adding mounts of its own.
        process.chdir(BASE);
      });

      tearDown(() {
        process.chdir(savedCwd);
        cleanupBwrapMountPoints(force: true);
        rmSync(BASE, {'recursive': true, 'force': true});
      });

      // `count` files with names near the 255-byte limit, each its own /dev/null
      // mask, as the concrete list the wrapper takes (glob expansion happens a
      // layer up, in SandboxManager).
      List<String> maskedFiles(int count) {
        final dir = join(BASE, 'many');
        mkdirSync(dir, {'recursive': true});
        final files = <String>[];
        for (var i = 0; i < count; i++) {
          final file = join(dir, '${'a' * 240}-$i.log');
          // Content, so the e2e case can tell the host file was left alone.
          writeFileSync(file, 'secret\n');
          files.add(file);
        }
        return files;
      }

      // Each mask renders as about 300 bytes: comfortably past the cap.
      List<String> overLongProfile() =>
          maskedFiles((MAX_ARG_STRLEN / 300).ceil() + 50);

      // `count` variables to unset, two bwrap words each.
      List<String> envVarNames(int count) => List.generate(count, (i) => 'V$i');

      Future<String> wrap(
        List<String> files, [
        Map<String, Object?> opts = const {},
      ]) async {
        return wrapCommandWithSandboxLinux(
          LinuxSandboxParams(
            command: (opts['command'] as String?) ?? 'echo hello',
            needsNetworkRestriction: false,
            readConfig: FsReadRestrictionConfig(denyOnly: files),
            writeConfig: FsWriteRestrictionConfig(
              allowOnly: (opts['allowOnly'] as List<String>?) ?? [],
              denyWithinAllow: (opts['denyWithinAllow'] as List<String>?) ?? [],
            ),
            setEnvVars: opts['setEnvVars'] as Map<String, String>?,
            unsetEnvVars: opts['unsetEnvVars'] as List<String>?,
            mandatoryDenySearchDepth: opts['mandatoryDenySearchDepth'] as int?,
          ),
        );
      }

      Future<LinuxSandboxProfileError> refused(Future<String> wrapping) async {
        Object? thrown;
        try {
          final wrapped = await wrapping;
          // A rendering is up to the kernel's per-argument cap: its size, not the
          // string, is what a failure here needs to report.
          thrown = 'the wrap resolved, in ${wrapped.length} characters';
        } catch (error) {
          thrown = error;
        }
        expect(thrown, isA<LinuxSandboxProfileError>());
        if (thrown is! LinuxSandboxProfileError) {
          // Narrowing only.
          throw Exception('$thrown');
        }
        expect(thrown.name, 'LinuxSandboxProfileError');
        return thrown;
      }

      // `count` of what the mandatory-deny scan takes for a repository, directly
      // inside the working directory.
      List<String> repositories(int count) {
        return List.generate(count, (i) {
          final repository = join(BASE, 'repo-$i');
          mkdirSync(join(repository, '.git', 'hooks'), {'recursive': true});
          writeFileSync(join(repository, '.git', 'config'), '');
          writeFileSync(join(repository, '.git', 'HEAD'), '');
          return repository;
        });
      }

      // The two shares a refusal for too many arguments states.
      ({int total, int mandatory}) sharesIn(LinuxSandboxProfileError error) {
        expect(error.code, 'too_many_arguments');
        final said = RegExp(
          r'\. (\d+) of its arguments are built-in write protection, .*\. The other (\d+) are what the configuration expands to: ',
        ).firstMatch(error.message);
        if (said == null) {
          throw Exception('no shares in: ${error.message}');
        }
        return (
          total: int.parse(said[1]!) + int.parse(said[2]!),
          mandatory: int.parse(said[1]!),
        );
      }

      String argsPathOf(String wrapped) {
        final rendered = VIA_ARGS_FILE.firstMatch(wrapped);
        expect(rendered, isNotNull);
        return rendered![1]!;
      }

      // A fresh process for what depends on the module's per-process state (the
      // open profiles, the fd baseline) or on TMPDIR at first use. `body` runs
      // after the prelude and prints one JSON value; `launcher` runs the runtime
      // itself under something (bwrap, to take away the directories an unnamed
      // file can go in).
      Object? isolated(
        String body, [
        Map<String, String> env = const {},
        List<String> launcher = const [],
      ]) {
        final files = overLongProfile();
        final script =
            '''
      import 'dart:convert';
      import 'dart:io';
      import ${jsonEncode(MODULE).replaceAll('"', "'")};
      import 'package:sandbox_runtime/src/sandbox/sandbox_schemas.dart';
      import 'package:sandbox_runtime/src/node/errno.dart' show errorMessage;
      Future<void> main() async {
      final overLong = <String>${jsonEncode(files)};
      final small = overLong.sublist(0, 1);
      Future<String> wrap(List<String> denyOnly, [String command = 'echo hello']) => wrapCommandWithSandboxLinux(LinuxSandboxParams(
        command: command,
        needsNetworkRestriction: false,
        readConfig: FsReadRestrictionConfig(denyOnly: denyOnly),
        writeConfig: FsWriteRestrictionConfig(allowOnly: [], denyWithinAllow: []),
      ));
      Future<Object?> outcome(Future<String> wrapping) => wrapping.then((_) => 'resolved', onError: (Object error) => error.toString());
      // What a refusal carries, read in the process that threw it.
      Future<Object?> refusal(Future<String> wrapping) => wrapping.then((_) => 'resolved', onError: (Object error) => {
        'profileError': error is LinuxSandboxProfileError,
        'name': (error as LinuxSandboxProfileError).name,
        'code': error.code,
        'cause': errorMessage(error.cause),
        'message': error.message,
      });
      String? argsPathOf(String wrapped) => RegExp(r"' srt-args (\\S+) ").firstMatch(wrapped)?[1];
      $body
      }
    ''';
        // A file, not `-e`: the script names every fixture path, and would not
        // fit one argument itself.
        final scriptFile = join(BASE, 'isolated.dart');
        writeFileSync(scriptFile, script);
        // A tmpdir of its own, so what a scenario leaves there goes with BASE.
        mkdirSync(join(BASE, 'tmp'), {'recursive': true});
        // Dart: the runtime is `dart --packages=<this package's config> <script>`.
        final argv = [
          ...launcher,
          Platform.resolvedExecutable,
          '--packages=${join(savedCwd, '.dart_tool', 'package_config.json')}',
          scriptFile,
        ];
        final run = spawnSync(argv[0], argv.sublist(1), {
          'cwd': BASE,
          'encoding': 'utf8',
          'env': {...Platform.environment, 'TMPDIR': join(BASE, 'tmp'), ...env},
          'timeout': 60000,
        });
        expect(run.stderr, '');
        return jsonDecode(run.stdout as String);
      }

      test(
        'keeps a profile that fits on the command line, and names no file for it',
        () async {
          final files = maskedFiles(20);
          final wrapped = await wrap(files);
          expect(wrapped, isNot(contains('--args')));
          expect(wrapped, isNot(contains('srt-args')));
          expect(wrapped, contains('--ro-bind /dev/null ${files[0]}'));
        },
      );

      test(
        'moves the mounts, and only the mounts, to an unnamed file the string reopens through /proc',
        () async {
          final files = overLongProfile();
          final wrapped = await wrap(files, {
            'setEnvVars': {'SRT_TEST_VAR': "value with spaces and 'quotes'"},
          });

          expect(utf8.encode(wrapped).length, lessThan(MAX_ARG_STRLEN));
          final m = VIA_ARGS_FILE.firstMatch(wrapped)!;
          final argsPath = m[1]!;
          final before = m[2]!;
          final after = m[3]!;
          // This process's own fd: the profile has no name anywhere, so nothing
          // can be put in its place between here and the execution.
          expect(argsPath, matches(RegExp('^/proc/${process.pid}/fd/\\d+\$')));
          expect(readlinkSync(argsPath), matches(RegExp(r'\(deleted\)$')));

          final words = (readFileSync(argsPath, 'utf8') as String).split(
            '\x00',
          );
          expect(words[words.length - 1], '');
          final mounts = words.sublist(0, words.length - 1);
          expect(mounts.where((w) => w == '/dev/null').length, files.length);
          expect(mounts, contains(files[0]));
          // Only mounts go to the file: nothing about the command or its
          // environment is in it.
          expect(
            mounts.where(
              (w) =>
                  w.startsWith('--') &&
                  !RegExp(r'^--(ro-bind|bind|tmpfs)$').hasMatch(w),
            ),
            [],
          );
          expect(
            before,
            contains(
              "--setenv SRT_TEST_VAR 'value with spaces and '\"'\"'quotes'\"'\"''",
            ),
          );
          expect(before, contains('--new-session'));
          expect(before, isNot(contains('--ro-bind /dev/null')));
          // What followed the mounts still follows them.
          expect(
            after,
            matches(RegExp(r'--unshare-pid .* -- \S+ -c ', dotAll: true)),
          );
        },
      );

      test(
        'switches to the file exactly where one argument would come within 4 KiB of the cap',
        () async {
          // The command is the last word on the line; a trailing two-byte
          // character keeps the shell quoter's output constant while every
          // added 'a' adds one byte, so the padding sets the rendered size byte
          // for byte, and a regression to string length (UTF-16 units) would
          // miscount it by one.
          final files = maskedFiles(20);
          final base = await wrap(files, {'command': 'é'});
          expect(base, isNot(contains('--args')));
          Future<String> renderedAt(int bytes) => wrap(files, {
            'command': 'a' * (bytes - utf8.encode(base).length) + 'é',
          });

          final fits = await renderedAt(INLINE_MAX);
          expect(utf8.encode(fits).length, INLINE_MAX);
          expect(fits, isNot(contains('--args')));

          expect(await renderedAt(INLINE_MAX + 1), matches(VIA_ARGS_FILE));
        },
      );

      test(
        'refuses a command that is too long for one argument by itself',
        () async {
          final error = await refused(
            wrap(maskedFiles(20), {'command': 'a' * MAX_ARG_STRLEN}),
          );
          expect(error.code, 'command_too_long');
          expect(
            error.message,
            matches(
              RegExp(
                r'too long for one shell argument even with the mounts passed through a file \(\d+ bytes; the limit here is \d+\)',
              ),
            ),
          );
        },
      );

      test(
        'reaches the same refusal through SandboxManager, the way an embedder wraps',
        () async {
          await SandboxManager.initialize(
            SandboxRuntimeConfig(
              network: NetworkConfig(allowedDomains: [], deniedDomains: []),
              filesystem: FilesystemConfig(
                denyRead: [
                  for (final f in maskedFiles(20)) FilesystemPathSpelling(f),
                ],
                allowWrite: [],
                denyWrite: [],
              ),
            ),
          );
          try {
            final error = await refused(
              SandboxManager.wrapWithSandbox('a' * MAX_ARG_STRLEN),
            );
            expect(error.code, 'command_too_long');
          } finally {
            await SandboxManager.reset();
          }
        },
      );

      test('refuses a profile past the 9000 arguments bwrap accepts', () async {
        final error = await refused(
          wrap(maskedFiles(1), {'unsetEnvVars': envVarNames(4500)}),
        );
        expect(error.code, 'too_many_arguments');
        expect(
          error.message,
          matches(
            RegExp(
              r'has \d+ bwrap arguments and bwrap accepts at most 9000 \(about 3000 mounts\)',
            ),
          ),
        );
      });

      test(
        'refuses an over-long profile whose mounts, passed through a file, would pass the 9000 arguments',
        () async {
          // The two argument counts where the profile fits bwrap's cap but `--args
          // <fd>` would not. Each unset variable adds two words, so one of the two
          // counts is reachable; the first wrap reports the count it reached, which
          // gives the size of the rest of the profile. The command is over-long by
          // itself, so the line does not fit whatever the kernel's page size.
          final files = maskedFiles(20);
          final command = 'a' * MAX_ARG_STRLEN;
          const probe = 5000;
          final overflow = await refused(
            wrap(files, {
              'command': command,
              'unsetEnvVars': envVarNames(probe),
            }),
          );
          expect(overflow.code, 'too_many_arguments');
          final counted = RegExp(
            r'has (\d+) bwrap arguments',
          ).firstMatch(overflow.message);
          if (counted == null) {
            throw Exception('no argument count in: ${overflow.message}');
          }
          final rest = int.parse(counted[1]!) - 2 * probe;
          final target = rest % 2 == 0 ? 9000 : 8999;

          final error = await refused(
            wrap(files, {
              'command': command,
              'unsetEnvVars': envVarNames((target - rest) ~/ 2),
            }),
          );
          expect(error.code, 'too_many_arguments');
          expect(
            error.message,
            matches(
              RegExp(
                r'and, passed through a file, would exceed the 9000 arguments bwrap accepts',
              ),
            ),
          );
          expect(sharesIn(error).total, target);
        },
      );

      test(
        'tells the arguments of the mandatory denies from those of the configuration',
        () async {
          // The variables carry every profile here past the cap.
          Future<({int total, int mandatory})> shares([
            Map<String, Object?> opts = const {},
            int variables = 4500,
          ]) async {
            final error = await refused(
              wrap([], {
                'allowOnly': [BASE],
                'unsetEnvVars': envVarNames(variables),
                ...opts,
              }),
            );
            final said = sharesIn(error);
            expect(
              error.message,
              contains('has ${said.total} bwrap arguments'),
            );
            return said;
          }

          final none = await shares();
          final [first, second, ...] = repositories(10);
          // Hooks, config, and a pin on each of the two directories above them.
          final ten = await shares();
          expect(ten, (
            total: none.total + 10 * 12,
            mandatory: none.mandatory + 10 * 12,
          ));

          // What the configuration adds is not theirs: two words a variable, and a
          // bind and a pin for a write deny of its own.
          expect(await shares({}, 4600), (
            total: ten.total + 200,
            mandatory: ten.mandatory,
          ));
          mkdirSync(join(BASE, 'own'));
          writeFileSync(join(BASE, 'own', 'file'), '');
          expect(
            await shares({
              'denyWithinAllow': [join(BASE, 'own', 'file')],
            }),
            (total: ten.total + 6, mandatory: ten.mandatory),
          );

          // Each thing the refusal advises lowers their share.
          expect(
            (await shares({
              'allowOnly': [first, second],
            })).mandatory,
            // A write root is no pin.
            2 * 9,
          );
          expect(
            (await shares({'mandatoryDenySearchDepth': 2})).mandatory,
            none.mandatory,
          );
          process.chdir(first);
          expect((await shares()).mandatory, lessThan(ten.mandatory));
        },
      );

      test(
        'refuses a mount path with a NUL byte whether or not the profile fits the command line',
        () async {
          final nulInAPath = {
            'allowOnly': [BASE],
            'denyWithinAllow': [join(BASE, 'x\x00--cap-add\x00ALL')],
          };
          // The size decides the carrier, and neither carrier holds a NUL: the
          // command line ends at it, a file of bwrap arguments splits on it.
          for (final files in [maskedFiles(1), overLongProfile()]) {
            final error = await refused(wrap(files, nulInAPath));
            expect(error.code, 'nul_in_path');
            expect(
              error.message,
              matches(
                RegExp(
                  r'contains a path with a NUL byte, which neither a command line nor a file of bwrap arguments can carry',
                ),
              ),
            );
          }
        },
      );

      test(
        'holds one fd per pending profile and gives them all back at cleanup, a refused wrap included',
        () {
          final seen = isolated('''
      final openFds = () => Directory('/proc/self/fd').listSync().length;
      // The runtime opens event-loop fds of its own on the first wrap.
      // (Dart: an over-long wrap too, as Linux opens one more such fd then.)
      await wrap(small);
      await wrap(overLong);
      cleanupBwrapMountPoints(force: true);
      final baseline = openFds();
      await wrap(overLong);
      await wrap(overLong);
      final held = openFds() - baseline;
      // A rendering that cannot be run releases its profile too.
      final refused = await outcome(wrap(overLong, 'a' * $MAX_ARG_STRLEN));
      final afterRefusal = openFds() - baseline;
      cleanupBwrapMountPoints(force: true);
      print(jsonEncode({'held': held, 'refused': refused, 'afterRefusal': afterRefusal, 'afterCleanup': openFds() - baseline}));
    ''');
          expect(seen, {
            'held': 2,
            'refused': matches(RegExp(r'too long for one shell argument')),
            'afterRefusal': 2,
            'afterCleanup': 0,
          });
        },
      );

      test(
        'refuses at wrap time, with the reason, when no directory takes an unnamed file',
        () {
          // Both candidates read-only: tmpdir and /dev/shm. A profile that fits
          // needs neither and is unaffected.
          final roTmp = join(BASE, 'ro-tmp');
          mkdirSync(roTmp);
          final seen = isolated(
            '''
      final fits = await wrap(small);
      print(jsonEncode({
        'fits': fits.contains('--ro-bind /dev/null') && !fits.contains('srt-args'),
        'refused': await refusal(wrap(overLong)),
      }));
    ''',
            {'TMPDIR': roTmp},
            [
              'bwrap',
              '--dev-bind',
              '/',
              '/',
              '--ro-bind',
              '/etc',
              '/dev/shm',
              '--ro-bind',
              '/etc',
              roTmp,
            ],
          );
          expect(seen, {
            'fits': true,
            'refused': {
              'profileError': true,
              'name': 'LinuxSandboxProfileError',
              'code': 'args_file_unavailable',
              'cause': matches(
                RegExp(
                  r'^no unnamed file could be opened for it \(.*read-only',
                  dotAll: true,
                ),
              ),
              'message': matches(
                RegExp(
                  r'cannot be passed through a file: no unnamed file could be opened for it \(.*read-only',
                  dotAll: true,
                ),
              ),
            },
          });
        },
      );

      test(
        'fails in the redirection, and does not run the command, when the string is run after its cleanup',
        () async {
          final marker = join(BASE, 'ran');
          final wrapped = await wrap(overLongProfile(), {
            'command': 'touch $marker',
          });
          cleanupBwrapMountPoints(force: true);
          // No pipes for the run: a parent-side fd would take the number the
          // profile just gave up.
          final run = spawnSync(wrapped, [], {
            'shell': true,
            'stdio': 'ignore',
            'timeout': 60000,
          });
          expect(run.status, isNot(0));
          expect(existsSync(marker), false);
        },
      );

      test(
        'e2e: a pending profile survives a tmpdir whose parent is replaced, because no path leads to it',
        skip: BWRAP_CAN_NAMESPACE ? null : 'it.if(BWRAP_CAN_NAMESPACE)',
        timeout: const Timeout(Duration(seconds: 60)),
        () {
          final parent = join(BASE, 'scratch');
          mkdirSync(join(parent, 'tmp'), {'recursive': true});
          final marker = join(BASE, 'written-by-the-sandbox');
          final seen = isolated(
            '''
        final wrapped = await wrap(overLong, 'touch $marker 2>/dev/null && echo WROTE || echo DENIED');
        final argsPath = argsPathOf(wrapped)!;
        // The runtime leaves a cache of its own there; nothing of ours.
        final namedUnderTmpdir = Directory(Platform.environment['TMPDIR']!).listSync(recursive: true)
          .map((e) => e.path.substring(Platform.environment['TMPDIR']!.length + 1))
          .where((entry) => RegExp(r'srt|args|bwrap').hasMatch(entry))
          .toList();
        // What a sandbox with the parent writable, or another process of
        // this user sandboxing with tmpdir writable, can arrange: the
        // directory goes aside, and a profile that binds / read-write takes
        // the place of every path the string could still open.
        Directory(${jsonEncode(parent).replaceAll(r'$', r'\$')}).renameSync(${jsonEncode(parent + '.aside').replaceAll(r'$', r'\$')});
        String? planted;
        if (!argsPath.startsWith('/proc/')) {
          Directory(argsPath.substring(0, argsPath.lastIndexOf('/'))).createSync(recursive: true);
          File(argsPath).writeAsStringSync('--bind\\x00/\\x00/\\x00');
          planted = argsPath;
        }
        final run = Process.runSync('/bin/sh', ['-c', wrapped], stdoutEncoding: utf8);
        print(jsonEncode({
          'argsPath': argsPath,
          'namedUnderTmpdir': namedUnderTmpdir,
          'planted': planted,
          'status': run.exitCode,
          'stdout': (run.stdout as String).trim(),
          'marker': File(${jsonEncode(marker).replaceAll(r'$', r'\$')}).existsSync(),
        }));
      ''',
            {'TMPDIR': join(parent, 'tmp')},
          );
          expect(seen, {
            'argsPath': matches(RegExp(r'^/proc/\d+/fd/\d+$')),
            'namedUnderTmpdir': [],
            'planted': null,
            'status': 0,
            // The command ran under the profile that was wrapped, not one
            // planted after it.
            'stdout': 'DENIED',
            'marker': false,
          });
        },
      );

      test(
        'e2e: bwrap applies the mounts from the file, the string composes with a prefix and a suffix, and the command reaches neither fd 9 nor the profile',
        skip: BWRAP_CAN_NAMESPACE ? null : 'it.if(BWRAP_CAN_NAMESPACE)',
        timeout: const Timeout(Duration(seconds: 60)),
        () async {
          final files = overLongProfile();
          // tmpdir writable inside the sandbox: with nothing named there, that
          // is no longer a way to the pending profile. The runner's tmpdir is
          // scanned shallowly, since every mount costs bwrap time.
          final wrapped = await wrap(files, {
            'allowOnly': [tmpdir()],
            'mandatoryDenySearchDepth': 1,
            'command': [
              // The mask is a bind of /dev/null: a character device in place
              // of the file (opening a device node inside the user namespace
              // is not portable across hosts, so its type is the oracle).
              '[ -c ${files[0]} ] && echo MASKED || echo UNMASKED',
              '[ -e /proc/self/fd/9 ] && echo FD9_OPEN || echo FD9_CLOSED',
              // A fresh /proc in its own PID namespace: the wrapping process,
              // and so the fd its profiles are on, is not there at all.
              '[ -e /proc/${process.pid} ] && echo RUNTIME_PROC_VISIBLE || echo RUNTIME_PROC_HIDDEN',
            ].join('; '),
          });
          expect(
            argsPathOf(wrapped),
            matches(RegExp('^/proc/${process.pid}/fd/\\d+\$')),
          );
          final run = spawnSync('timeout 60 $wrapped && echo AFTER', [], {
            'shell': true,
            'encoding': 'utf8',
            'timeout': 60000,
            'cwd': BASE,
          });
          expect(run.status, 0);
          expect((run.stdout as String).trim().split('\n'), [
            'MASKED',
            'FD9_CLOSED',
            'RUNTIME_PROC_HIDDEN',
            'AFTER',
          ]);
          expect(readFileSync(files[0], 'utf8'), 'secret\n');
        },
      );
    },
  );
}
