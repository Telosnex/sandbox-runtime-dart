// Ported from sandbox-runtime test/helpers/bwrap-argv.ts @ 24eb39e.
import '../../lib/src/utils/shell_quote.dart' show quote;

/** The $0 renderBwrapInvocation gives the shell that opens an over-long
 * profile's argument file. Its presence means the mount words are in that
 * file and not in the command. */
const ARGS_FILE_ARGV0 = 'srt-args';

/** The mount flags this generator emits with a source and a destination. */
const MOUNT_FLAGS = ['--bind', '--ro-bind'];

/** How many words follow each mount flag this generator emits. */
const MOUNT_ARITY = <String, int>{
  '--bind': 2,
  '--ro-bind': 2,
  '--dev-bind': 2,
  '--tmpfs': 1,
  '--dev': 1,
  '--proc': 1,
};

/**
 * A whole mount, in the two shapes bwrap is given here: a destination-only
 * `--tmpfs`, or a flag with a source and a destination. Spelling them out is
 * what keeps an absence assertion honest — a run of any length would let a
 * typo'd flag, or a transposed source and destination, match nothing and
 * report 0 for free.
 */
typedef MountWords = List<String>;

/**
 * The wrapped command as argv words. Refused when the mounts went to the
 * argument file, where nothing below can see them: every absence assertion
 * would otherwise pass for free.
 */
List<String> _argvOf(String command) {
  final argv = command.split(RegExp(r'\s+'));
  if (argv.contains(ARGS_FILE_ARGV0)) {
    throw Exception(
      'bwrap-argv cannot read this command: the profile was too long for the command line, so its mount words are in the argument file',
    );
  }
  return argv;
}

/**
 * The command is a shell-quoted string, so this can only see a token the
 * wrapper emitted verbatim. A path that needs quoting is silently absent
 * from the split, which would make every absence assertion pass for free —
 * so such a token is refused outright rather than reported as 0 matches.
 */
void _assertLiteralToken(String token) {
  if (quote([token]) != token) {
    throw Exception(
      'bwrap-argv cannot match ${token}: the wrapper shell-quotes it, so it is not one whitespace-separated argv token',
    );
  }
}

/**
 * Argv indices of every run of adjacent words equal to `words`. Matching a
 * run, not a substring, is what keeps a '/' assertion honest: the base
 * `--ro-bind / /` root mount spells the deny-side bind of '/' exactly, so
 * `lastIndexOf('--ro-bind / /')` finds the root mount and passes even when
 * the deny-side bind was never emitted.
 */
List<int> _runIndices(String command, List<String> words) {
  for (final token in words) {
    _assertLiteralToken(token);
  }
  final argv = _argvOf(command);
  final found = <int>[];
  for (var i = 0; i + words.length <= argv.length; i++) {
    if (List.generate(
      words.length,
      (offset) => argv[i + offset] == words[offset],
    ).every((x) => x))
      found.add(i);
  }
  return found;
}

/** How many times that whole mount appears. */
int countMounts(String command, List<String> words) =>
    _runIndices(command, words).length;

/**
 * Argv index of the first occurrence of that whole mount, or -1. Comparable
 * with another mount's index to assert mount order — but never with a
 * character offset from `String.indexOf`.
 */
int indexOfMount(String command, List<String> words) {
  final found = _runIndices(command, words);
  return found.isEmpty ? -1 : found.first;
}

/**
 * Every mount the command carries, in emission order, each as the words bwrap
 * is given for it. Compare as a MULTISET: the mandatory-deny scan takes
 * ripgrep's hits in thread order, so that order varies run to run.
 */
List<String> mountsOf(String command) {
  final argv = _argvOf(command);
  final mounts = <String>[];
  for (var i = 0; i < argv.length; i++) {
    final flag = argv[i];
    final arity = MOUNT_ARITY[flag];
    if (arity == null) continue;
    final words = argv.skip(i).take(1 + arity).toList();
    if (words.length == 1 + arity) mounts.add(words.join(' '));
  }
  return mounts;
}

/** Argv index of the last occurrence of that whole mount, or -1. */
int lastIndexOfMount(String command, List<String> words) {
  final found = _runIndices(command, words);
  return found.isEmpty ? -1 : found.last;
}

/**
 * The last mount whose destination is exactly `dest`, as the words it was
 * emitted with. That is what the sandbox sees there only if nothing later
 * mounts over an ANCESTOR of it, which this does not look for. Scanning argv
 * words rather than `lastIndexOf` keeps a path that appears as a mount
 * SOURCE from passing for a mount at that destination; `--tmpfs` takes a
 * destination alone and needs its own arm.
 */
String? lastMountAt(String command, String dest) {
  _assertLiteralToken(dest);
  final argv = _argvOf(command);
  String? last;
  for (var i = 0; i + 1 < argv.length; i++) {
    if (argv[i] == '--tmpfs' && argv[i + 1] == dest) {
      last = '--tmpfs $dest';
    } else if (MOUNT_FLAGS.contains(argv[i]) &&
        i + 2 < argv.length &&
        argv[i + 2] == dest) {
      last = '${argv[i]} ${argv[i + 1]} ${argv[i + 2]}';
    }
  }
  return last;
}
