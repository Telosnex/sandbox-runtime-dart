// Ported from sandbox-runtime test/sandbox/linux-one-mount-per-destination.test.ts @ 24eb39e.
// ignore_for_file: constant_identifier_names, non_constant_identifier_names, slash_for_doc_comments
import 'package:path/path.dart' show join;
import 'package:sandbox_runtime/src/node/child_process.dart' show spawnSync;
import 'package:sandbox_runtime/src/node/fs.dart'
    show
        mkdirSync,
        mkdtempSync,
        readFileSync,
        realpathSync,
        rmSync,
        symlinkSync,
        writeFileSync;
import 'package:sandbox_runtime/src/node/os.dart' show tmpdir;
import 'package:sandbox_runtime/src/node/process.dart' as process;
import 'package:sandbox_runtime/src/sandbox/credential_mask_files.dart'
    show MaskedFileBind;
import 'package:sandbox_runtime/src/sandbox/linux_sandbox_utils.dart'
    show
        LinuxSandboxParams,
        OLDEST_FULLY_SUPPORTED_BWRAP_VERSION,
        checkLinuxDependencies,
        cleanupBwrapMountPoints,
        wrapCommandWithSandboxLinux;
import 'package:sandbox_runtime/src/sandbox/sandbox_schemas.dart'
    show FsReadRestrictionConfig, FsWriteRestrictionConfig;
import 'package:test/test.dart';

import '../helpers/bwrap_namespace.dart' show bwrapCanNamespace;
import '../helpers/platform.dart' show isLinux;

// Dart: stands for the anonymous `Mount` type alias of the describe callback.
typedef Mount = ({int index, String flag, String? source, String dest});

/**
 * One mount per destination.
 *
 * A file mask is a `--ro-bind` of something other than the destination
 * itself: the `/dev/null` of a read deny or an absent write deny, the fake
 * of a credential mask. Two at one destination, with nothing between that
 * mounts at or above it, only replace one another, and bubblewrap before
 * 0.5.0 refuses to start on that ("Can't create file at <dest>: Permission
 * denied"). Spellings of one path converge on one destination, so the corpus
 * spells the same file several ways.
 *
 * A mask re-applied after a later bind re-exposed the real file is NOT one of
 * these: that bind sits between the two and puts a mount point back.
 */
void main() {
  group('One mount per destination', skip: isLinux ? null : 'not Linux', () {
    late String BASE;
    late String AREA;
    late String PROJ;
    late String SECRET;
    late String OTHER;
    late String SUB;
    late String LINK;
    late String FAKES;
    final savedCwd = process.cwd();

    setUpAll(() {
      BASE = realpathSync(mkdtempSync(join(tmpdir(), 'one-mount-')));
      AREA = join(BASE, 'area');
      PROJ = join(AREA, 'proj');
      SECRET = join(PROJ, 'secret.txt');
      OTHER = join(PROJ, 'other.txt');
      SUB = join(PROJ, 'sub');
      mkdirSync(SUB, {'recursive': true});
      writeFileSync(SECRET, 'secret\n');
      writeFileSync(OTHER, 'other\n');
      writeFileSync(join(SUB, 'inner.txt'), 'inner\n');
      LINK = join(BASE, 'link');
      symlinkSync(PROJ, LINK);
      FAKES = join(BASE, 'fakes');
      mkdirSync(FAKES);
      writeFileSync(join(FAKES, '0.fake'), 'fake-0\n');
      writeFileSync(join(FAKES, '1.fake'), 'fake-1\n');
      // Keep cwd outside the allowlist, so the mandatory-deny scan adds no
      // mounts of its own to reason about.
      process.chdir(BASE);
    });

    tearDownAll(() {
      process.chdir(savedCwd);
      cleanupBwrapMountPoints(force: true);
      rmSync(BASE, {'recursive': true, 'force': true});
    });

    /** Every mount in the wrapped command, in the order bwrap applies them. */
    List<Mount> mountsOf(String command) {
      final argv = command.split(RegExp(r'\s+'));
      final mounts = <Mount>[];
      for (final (index, flag) in argv.indexed) {
        if (flag == '--tmpfs' && index + 1 < argv.length) {
          mounts.add((
            index: index,
            flag: flag,
            source: null,
            dest: argv[index + 1],
          ));
        } else if ((flag == '--bind' ||
                flag == '--ro-bind' ||
                flag == '--dev-bind' ||
                flag == '--bind-try' ||
                flag == '--ro-bind-try') &&
            index + 2 < argv.length) {
          mounts.add((
            index: index,
            flag: flag,
            source: argv[index + 1],
            dest: argv[index + 2],
          ));
        }
      }
      return mounts;
    }

    bool isAtOrUnder(String candidate, String root) =>
        root == '/' || candidate == root || candidate.startsWith('$root/');

    /** A mask puts foreign content at the destination, so its source is not the
     * destination. A bind of a path onto itself is not one, nor is a tmpfs. */
    bool isFileMask(Mount mount) =>
        mount.flag == '--ro-bind' &&
        mount.source != null &&
        mount.source != mount.dest;

    /** Destinations given two file masks with nothing between them that mounts
     * at or above the destination, as text so a failure names the mounts. */
    List<String> maskedTwiceOver(String command) {
      final mounts = mountsOf(command);
      final masksByDest = <String, List<Mount>>{};
      for (final mount in mounts.where(isFileMask)) {
        final seen = masksByDest[mount.dest] ?? <Mount>[];
        seen.add(mount);
        masksByDest[mount.dest] = seen;
      }
      final offences = <String>[];
      for (final MapEntry(key: dest, value: masks) in masksByDest.entries) {
        for (var i = 1; i < masks.length; i++) {
          final previous = masks[i - 1];
          final current = masks[i];
          final between = mounts.any(
            (mount) =>
                mount.index > previous.index &&
                mount.index < current.index &&
                isAtOrUnder(dest, mount.dest),
          );
          if (!between) {
            offences.add(
              '$dest: ${previous.flag} ${previous.source} then ${current.flag} ${current.source}, nothing in between',
            );
          }
        }
      }
      return offences;
    }

    Future<String> wrap({
      List<String> denyRead = const [],
      List<String> allowRead = const [],
      List<String>? allowWrite,
      List<String> denyWrite = const [],
      List<MaskedFileBind>? maskedFileBinds,
    }) {
      allowWrite ??= [AREA];
      return wrapCommandWithSandboxLinux(
        LinuxSandboxParams(
          command: 'true',
          needsNetworkRestriction: false,
          readConfig: FsReadRestrictionConfig(
            denyOnly: denyRead,
            allowWithinDeny: allowRead,
          ),
          writeConfig: FsWriteRestrictionConfig(
            allowOnly: allowWrite,
            denyWithinAllow: denyWrite,
          ),
          maskedFileBinds: maskedFileBinds,
          maskedFileStoreDir: maskedFileBinds == null ? null : FAKES,
        ),
      );
    }

    // Each entry spells one place more than once. A tilde is expanded before
    // this function sees it, so the spellings are the absolute ones: a doubled
    // slash, a trailing slash and a symlinked directory.
    List<({String what, Future<String> wrapped})> corpus() => [
      (
        what: 'one file denied under two absolute spellings',
        wrapped: wrap(denyRead: [SECRET, '/$SECRET']),
      ),
      (
        what: 'one file denied directly and through a symlinked directory',
        wrapped: wrap(denyRead: [SECRET, join(LINK, 'secret.txt')]),
      ),
      (
        what: 'one file denied with and without a trailing slash',
        wrapped: wrap(denyRead: [SECRET, '$SECRET/']),
      ),
      (
        what: 'one file denied three ways at once',
        wrapped: wrap(denyRead: [SECRET, '/$SECRET', join(LINK, 'secret.txt')]),
      ),
      (
        what: 'a denied file that is also a masked credential file',
        wrapped: wrap(
          denyRead: [SECRET],
          maskedFileBinds: [
            MaskedFileBind(realPath: SECRET, fakePath: join(FAKES, '0.fake')),
          ],
        ),
      ),
      (
        what: 'a denied file masked through a symlinked directory',
        wrapped: wrap(
          denyRead: [SECRET],
          maskedFileBinds: [
            MaskedFileBind(
              realPath: join(LINK, 'secret.txt'),
              fakePath: join(FAKES, '0.fake'),
            ),
          ],
        ),
      ),
      (
        what: 'one file masked twice under two spellings',
        wrapped: wrap(
          maskedFileBinds: [
            MaskedFileBind(realPath: SECRET, fakePath: join(FAKES, '0.fake')),
            MaskedFileBind(
              realPath: join(LINK, 'secret.txt'),
              fakePath: join(FAKES, '1.fake'),
            ),
          ],
        ),
      ),
      (
        what: 'two denied spellings and two masked spellings of one file',
        wrapped: wrap(
          denyRead: [SECRET, join(LINK, 'secret.txt')],
          maskedFileBinds: [
            MaskedFileBind(realPath: SECRET, fakePath: join(FAKES, '0.fake')),
            MaskedFileBind(
              realPath: join(LINK, 'secret.txt'),
              fakePath: join(FAKES, '1.fake'),
            ),
          ],
        ),
      ),
      (
        what: 'a denied file under a write deny that re-exposes it',
        wrapped: wrap(denyRead: [SECRET], denyWrite: [PROJ]),
      ),
      (
        what: 'a masked file under a write deny that re-exposes it',
        wrapped: wrap(
          denyWrite: [PROJ],
          maskedFileBinds: [
            MaskedFileBind(realPath: SECRET, fakePath: join(FAKES, '0.fake')),
          ],
        ),
      ),
      (
        what: 'a denied directory and a denied file inside it',
        wrapped: wrap(denyRead: [SUB, join(SUB, 'inner.txt')]),
      ),
      (
        what: 'two absent write denies sharing one missing component',
        wrapped: wrap(
          denyWrite: [join(PROJ, 'gone', 'a'), join(PROJ, 'gone', 'b')],
        ),
      ),
      (
        what: 'a file denied for reading and for writing',
        wrapped: wrap(denyRead: [SECRET], denyWrite: [SECRET]),
      ),
      (
        what: 'a masked file that is also an allowed write path',
        wrapped: wrap(
          allowWrite: [AREA, SECRET],
          maskedFileBinds: [
            MaskedFileBind(realPath: SECRET, fakePath: join(FAKES, '0.fake')),
          ],
        ),
      ),
      (
        what: 'a denied file beside a masked one under a write deny',
        wrapped: wrap(
          denyRead: [SECRET, '$SECRET/'],
          denyWrite: [PROJ],
          maskedFileBinds: [
            MaskedFileBind(realPath: OTHER, fakePath: join(FAKES, '1.fake')),
          ],
        ),
      ),
    ];

    test('masks each destination once across the whole corpus', () async {
      final offences = <String>[];
      for (final (:what, :wrapped) in corpus()) {
        for (final offence in maskedTwiceOver(await wrapped)) {
          offences.add('$what -> $offence');
        }
      }
      expect(offences, equals([]));
    });

    // The check above reads argument lists; whether bubblewrap takes them is
    // settled only by starting it. From 0.5.0 on it starts on a doubled mask
    // too, so this arm catches one only where the bubblewrap on PATH is older,
    // as on CI's 0.4.1 leg.
    test(
      'starts on every configuration in the corpus (live bwrap)',
      // Dart: the probe spawns processes, so it runs only on Linux.
      skip: !(isLinux && bwrapCanNamespace())
          ? 'bwrap cannot namespace here'
          : null,
      () async {
        final refused = <String>[];
        for (final (:what, :wrapped) in corpus()) {
          final r = spawnSync(await wrapped, [], {
            'shell': true,
            'encoding': 'utf8',
            'timeout': 15000,
          });
          final status = r.status;
          final stderr = r.stderr as String;
          if (status != 0) refused.add('$what -> ${stderr.trim()}');
        }
        expect(refused, equals([]));
      },
      timeout: Timeout(Duration(milliseconds: 60000)),
    );

    test('still masks a file denied under several spellings', () async {
      final command = await wrap(
        denyRead: [SECRET, '$SECRET/', join(LINK, 'secret.txt')],
      );
      expect(command, contains('--ro-bind /dev/null $SECRET'));
    });

    test(
      'leaves a denied file to the credential mask that covers it',
      () async {
        // Both name one file. The mask hides the real bytes as the read deny
        // asked; a /dev/null mask under it would only be replaced.
        final command = await wrap(
          denyRead: [SECRET],
          maskedFileBinds: [
            MaskedFileBind(realPath: SECRET, fakePath: join(FAKES, '0.fake')),
          ],
        );
        expect(command, contains('--ro-bind ${join(FAKES, '0.fake')} $SECRET'));
        expect(command, isNot(contains('--ro-bind /dev/null $SECRET')));
      },
    );

    test('keeps the last fake where two entries name one file', () async {
      // The last of two masks at one destination is the one left in force.
      final command = await wrap(
        maskedFileBinds: [
          MaskedFileBind(realPath: SECRET, fakePath: join(FAKES, '0.fake')),
          MaskedFileBind(
            realPath: join(LINK, 'secret.txt'),
            fakePath: join(FAKES, '1.fake'),
          ),
        ],
      );
      expect(command, contains('--ro-bind ${join(FAKES, '1.fake')} $SECRET'));
      expect(
        command,
        isNot(contains('--ro-bind ${join(FAKES, '0.fake')} $SECRET')),
      );
    });

    test(
      're-applies a mask a write deny re-exposed, above that deny',
      () async {
        final command = await wrap(denyRead: [SECRET], denyWrite: [PROJ]);
        final argv = command.split(RegExp(r'\s+'));
        final masks = argv.indexed
            .expand(
              ((int, String) e) =>
                  e.$2 == '--ro-bind' &&
                      e.$1 + 1 < argv.length &&
                      argv[e.$1 + 1] == '/dev/null' &&
                      e.$1 + 2 < argv.length &&
                      argv[e.$1 + 2] == SECRET
                  ? [e.$1]
                  : <int>[],
            )
            .toList();
        // The last such bind. Array.prototype.findLastIndex is ES2023, and the
        // tests compile against the ES2020 library.
        final denyBind = argv.indexed
            .map(
              ((int, String) e) =>
                  e.$2 == '--ro-bind' &&
                  e.$1 + 1 < argv.length &&
                  argv[e.$1 + 1] == PROJ &&
                  e.$1 + 2 < argv.length &&
                  argv[e.$1 + 2] == PROJ,
            )
            .toList()
            .lastIndexOf(true);
        expect(masks.length, 2);
        expect(masks[0], lessThan(denyBind));
        expect(masks[1], greaterThan(denyBind));
      },
    );
  });

  group('Reporting an older bubblewrap', skip: isLinux ? null : 'not Linux', () {
    late String BASE;

    String stubBwrap(String name, String version) {
      final path = join(BASE, name);
      writeFileSync(path, '#!/bin/sh\necho "bubblewrap $version"\n', {
        'mode': 493,
      });
      return path;
    }

    setUpAll(() {
      BASE = realpathSync(mkdtempSync(join(tmpdir(), 'bwrap-version-')));
    });

    tearDownAll(() {
      rmSync(BASE, {'recursive': true, 'force': true});
    });

    test('warns, naming the version, about an older bubblewrap', () {
      final check = checkLinuxDependencies(
        bwrapPath: stubBwrap('old', '0.4.1'),
      );
      final warnings = check.warnings;
      final errors = check.errors;
      expect(
        warnings.any(
          (warning) =>
              warning.contains('0.4.1') &&
              warning.contains(OLDEST_FULLY_SUPPORTED_BWRAP_VERSION),
        ),
        isTrue,
      );
      // A warning, not a refusal: every other configuration starts on it.
      expect(errors.any((error) => error.contains('0.4.1')), isFalse);
    });

    test('says nothing about a bubblewrap new enough for everything', () {
      final check = checkLinuxDependencies(
        bwrapPath: stubBwrap('new', '0.11.2'),
      );
      final warnings = check.warnings;
      expect(
        warnings.any((warning) => warning.contains('bubblewrap 0.11.2')),
        isFalse,
      );
    });

    test('says nothing when the version cannot be asked for', () {
      final path = join(BASE, 'mute');
      writeFileSync(path, '#!/bin/sh\nexit 3\n', {'mode': 493});
      final check = checkLinuxDependencies(bwrapPath: path);
      final warnings = check.warnings;
      expect(
        warnings.any(
          (warning) => warning.contains(OLDEST_FULLY_SUPPORTED_BWRAP_VERSION),
        ),
        isFalse,
      );
    });

    for (final (name, onVersion) in [
      ('failing', 'exit 3'),
      ('wordless', 'echo bubblewrap'),
      ('killed', r'kill -KILL $$'),
      ('hung', 'exec sleep 20'),
    ]) {
      test(
        'does not ask again after a probe that got no answer: $name',
        () {
          final path = join(BASE, name);
          final asked = join(BASE, '$name.asked');
          writeFileSync(
            path,
            '#!/bin/sh\n[ "\$1" = --version ] || exit 0\necho >> \'$asked\'\n$onVersion\n',
            {'mode': 493},
          );
          for (var ask = 0; ask < 3; ask++) {
            final check = checkLinuxDependencies(bwrapPath: path);
            final warnings = check.warnings;
            expect(
              warnings.any(
                (warning) =>
                    warning.contains(OLDEST_FULLY_SUPPORTED_BWRAP_VERSION),
              ),
              isFalse,
            );
          }
          expect(readFileSync(asked, 'utf8'), '\n');
        },
        // The hung one blocks for the probe's whole timeout.
        timeout: Timeout(Duration(milliseconds: 20000)),
      );
    }
  });
}
