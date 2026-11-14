// Ported from sandbox-runtime test/sandbox/seccomp-filter-generator.test.ts @ 0bbebed.
// ignore_for_file: no_leading_underscores_for_local_identifiers, curly_braces_in_flow_control_structures, prefer_function_declarations_over_variables
// ignore_for_file: constant_identifier_names, non_constant_identifier_names, slash_for_doc_comments
import 'dart:typed_data';
import 'package:test/test.dart';
import 'package:sandbox_runtime/src/node/buffer.dart';
import 'package:sandbox_runtime/src/node/child_process.dart';
import 'package:sandbox_runtime/src/node/fs.dart';
import 'package:sandbox_runtime/src/node/os.dart';
import 'package:sandbox_runtime/src/node/path.dart';
import 'package:sandbox_runtime/src/node/process.dart' as process;
import '../helpers/platform.dart';

/**
 * vendor/seccomp/build.ts compiles the filter generator
 * (vendor/seccomp-src/seccomp-unix-block.c), runs it and deletes it, so it is
 * compiled here once more where there is a compiler and a libseccomp to link
 * against (elsewhere these tests skip). It must never write a `namespaces`
 * filter with one of its calls left out.
 */
typedef Arch = String; // 'x86_64' | 'aarch64'

// The fifteen calls the filter answers itself, by their numbers. The old ones
// have a number of their own on each architecture; every call added since
// Linux 5.1 has the same one everywhere.
const SINCE_5_1 = {
  'clone3': 435,
  'open_tree': 428,
  'move_mount': 429,
  'fsopen': 430,
  'fsconfig': 431,
  'fsmount': 432,
  'fspick': 433,
  'mount_setattr': 442,
  'open_tree_attr': 467,
};
const REFUSED = <Arch, Map<String, int>>{
  'x86_64': {
    'clone': 56,
    'unshare': 272,
    'setns': 308,
    'mount': 165,
    'umount2': 166,
    'pivot_root': 155,
    ...SINCE_5_1,
  },
  'aarch64': {
    'clone': 220,
    'unshare': 97,
    'setns': 268,
    'mount': 40,
    'umount2': 39,
    'pivot_root': 41,
    ...SINCE_5_1,
  },
};
final Arch? NATIVE = {'x64': 'x86_64', 'arm64': 'aarch64'}[process.arch];
final Arch OTHER = NATIVE == 'x86_64' ? 'aarch64' : 'x86_64';

// Asked when the file is loaded, and leaves nothing behind: under a name
// filter that matches no test here, no hook would run to remove a build.
bool canBuildGenerator() {
  if (!isLinux || NATIVE == null) return false;
  final header = spawnSync(
    'gcc',
    ['-E', '-x', 'c', '-'],
    {
      'input': '#include <seccomp.h>\n',
      'stdio': ['pipe', 'ignore', 'ignore'],
      'timeout': 30000,
    },
  );
  // The path it would link, or the bare name where it has found none.
  final library = spawnSync(
    'gcc',
    ['-print-file-name=libseccomp.a'],
    {'encoding': 'utf8', 'timeout': 30000},
  );
  return header.status == 0 &&
      library.status == 0 &&
      isAbsolute((library.stdout as String).trim());
}

final CAN_BUILD = canBuildGenerator();

// The generator, compiled with the flags build.ts gives it.
String? GENERATOR;
void compileGenerator() {
  final work = mkdtempSync(join(tmpdir(), 'seccomp-generator-'));
  GENERATOR = join(work, 'seccomp-unix-block');
  final source = join(process.cwd(), 'vendor/seccomp-src');
  final gcc = spawnSync(
    'gcc',
    [
      '-static',
      '-O2',
      '-Wall',
      '-Wextra',
      '-o',
      GENERATOR!,
      join(source, 'seccomp-unix-block.c'),
      '-lseccomp',
    ],
    {
      'stdio': ['ignore', 'ignore', 'pipe'],
      'encoding': 'utf8',
      'timeout': 60000,
    },
  );
  if (gcc.status != 0) {
    rmSync(work, {'recursive': true, 'force': true});
    throw Exception('the generator did not compile: ${gcc.stderr}');
  }
}

// A classic BPF instruction is eight bytes: the operation in two, two jump
// offsets of one each, and an operand of four. A filter from libseccomp tells
// system calls apart with one "jump if equal to this number" each.
const JUMP_IF_EQUAL = 0x15;
Set<int> numbersComparedWith(Uint8List filter) {
  expect(filter.length % 8, 0);
  final numbers = <int>{};
  final bytes = ByteData.sublistView(filter);
  for (var at = 0; at < filter.length; at += 8) {
    if (bytes.getUint16(at, Endian.little) == JUMP_IF_EQUAL) {
      numbers.add(bytes.getUint32(at + 4, Endian.little));
    }
  }
  return numbers;
}

({int? status, String stderr, String out}) generate(Arch arch) {
  final out = join(dirname(GENERATOR!), '$arch.namespaces.bpf');
  rmSync(out, {'force': true});
  final run = spawnSync(
    GENERATOR!,
    [out, arch, 'namespaces'],
    {'encoding': 'utf8', 'timeout': 30000},
  );
  return (status: run.status, stderr: run.stderr as String, out: out);
}

void expectEveryCall(Arch arch, String out) {
  final compared = numbersComparedWith(
    Uint8List.fromList(readFileSync(out) as Buffer),
  );
  for (final MapEntry(key: call, value: number) in REFUSED[arch]!.entries) {
    // Named, so that a failure says which call is missing.
    expect([call, compared.contains(number)], [call, true]);
  }
}

void main() {
  group('the generator of the seccomp filters', () {
    setUpAll(() {
      if (CAN_BUILD) compileGenerator();
    });
    tearDownAll(() {
      if (GENERATOR != null)
        rmSync(dirname(GENERATOR!), {'recursive': true, 'force': true});
    });
    test(
      "the namespaces filter for the builder's own architecture has every one of its calls",
      () {
        final made = generate(NATIVE!);
        expect(made.stderr, '');
        expect(made.status, 0);
        expect(REFUSED[NATIVE!]!.keys, hasLength(15));
        expectEveryCall(NATIVE!, made.out);
      },
      skip: CAN_BUILD ? false : 'requires gcc and static libseccomp',
    );
    test(
      'for another architecture it writes the whole filter or none, and says which call it could not put in',
      () {
        // Which of the two depends on the libseccomp it was linked with: one
        // that names every call can carry them all to another architecture.
        final made = generate(OTHER);
        if (made.status == 0) {
          expectEveryCall(OTHER, made.out);
        } else {
          expect(
            made.stderr,
            matches(RegExp('cannot name (${REFUSED[OTHER]!.keys.join('|')})')),
          );
          expect(existsSync(made.out), false);
        }
      },
      skip: CAN_BUILD ? false : 'requires gcc and static libseccomp',
    );
  }, skip: isLinux ? false : 'not Linux');
}
