// Ported from sandbox-runtime src/sandbox/read-deny-glob.ts @ 0bbebed.
// ignore_for_file: slash_for_doc_comments, constant_identifier_names

import '../utils/debug.dart';
import '../node/generators.dart';
import 'sandbox_utils.dart';

/**
 * A read-deny glob still needing more than this many mounts after collapsing
 * is logged at warn level (SRT_DEBUG) as a hint that the pattern is broad.
 * The expansion is never truncated, which would silently un-deny paths.
 */
const int READ_DENY_GLOB_MOUNT_WARN_THRESHOLD = 256;

/** The directory holding `p`, or '' for a root child. */
String _parentOf(String p) => p.substring(0, p.lastIndexOf('/'));

/**
 * Reduce the places a read-deny glob's matches really live to the ones whose
 * mount changes what the sandbox can read. A location is dropped only when a
 * kept proper ancestor's tmpfs already hides it and no re-exposer sits at the
 * ancestor or between the two.
 */
Set<String> _collapseReadDenyLocations({
  /** Absolute, symlink-free, trailing-slash-free paths. */
  required Iterable<String> locations,
  /** allowRead/allowWrite paths the denyRead loop binds back over a tmpfs, as
   *  spelled and as resolved. */
  required Set<String> reExposedPaths,
}) {
  // A proper ancestor is a proper string prefix, so lexicographic order
  // visits every ancestor before its descendants.
  final sorted = locations.toSet().toList()..sort();
  final kept = <String>{};
  for (final location in sorted) {
    var reExposedBetween = reExposedPaths.contains(location);
    var hidden = false;
    for (final ancestor in properAncestors(location)) {
      // A re-exposer at the kept ancestor counts: the deny loop binds it back
      // over the tmpfs, so everything beneath needs its own mount.
      if (reExposedPaths.contains(ancestor)) reExposedBetween = true;
      if (kept.contains(ancestor)) {
        hidden = true;
        break;
      }
    }
    if (!hidden || reExposedBetween) kept.add(location);
  }
  return kept;
}

// Dart block comments nest, so `/**` inside one opens another: this block
// uses `///` to keep upstream's text verbatim.
/// Expand a read-deny glob into the paths bwrap should mount over, collapsed
/// against `reExposedPaths` (the caller's allowRead and allowWrite entries).
/// A pattern ending in `/**` also takes its directory form, so
/// `**\/build/**` yields one mount per `build/` directory. A match reached
/// through a symlink is listed where it really lives, and a directory the walk
/// could not list is denied whole. Sorted, so an ancestor precedes its
/// descendants.
///
/// @param unlistableDirs - receives the returned locations that hide something
/// the walk could not enumerate, whether by being that directory or by
/// covering it. The Linux wrapper binds nothing back beneath one: what the
/// pattern matches under an allowed path in there was never found, and would
/// come back unmasked.
/// @param opts.anchor - as in `ExpandGlobOptions.anchor`.
/// @param opts.listings - one map for all the patterns of a configuration.
List<String> expandReadDenyGlobLinux(
  String globPattern,
  List<String> reExposedPaths, {
  Set<String>? unlistableDirs,
  String? anchor,
  GlobWalkListings? listings,
}) => finish(
  expandReadDenyGlobLinuxSteps(
    globPattern,
    reExposedPaths,
    unlistableDirs: unlistableDirs,
    anchor: anchor,
    listings: listings,
  ),
);

/** [expandReadDenyGlobLinux], in the walk's steps. */
Steps<List<String>> expandReadDenyGlobLinuxSteps(
  String globPattern,
  List<String> reExposedPaths, {
  Set<String>? unlistableDirs,
  String? anchor,
  GlobWalkListings? listings,
}) sync* {
  final walkBox = Box<GlobWalk>();
  yield* yieldStar(
    walkGlobPatternSteps(
      globPattern,
      withDirectoryForm: true,
      followSymlinkedDirectories: true,
      anchor: anchor,
      listings: listings,
    ),
    walkBox,
  );
  final walk = walkBox.value;
  // Where a path the walk reported really lives: the denyRead loop mounts an
  // entry there, whatever spelling named it.
  String locationOf(String p) => walk.realOf[p] ?? p;
  // An unlisted directory hides whatever the pattern matches beneath it.
  final candidates = <String>{...walk.matches, ...walk.unlisted};
  if (walk.directoryMatches.isNotEmpty) {
    // Everything beneath a directory-form match is itself a match (the
    // pattern ends in /**), so a directory with something to deny holds one.
    // An empty one gets no mount: it has nothing to deny, and as a tmpfs it
    // would swallow later writes. Compared where they live, since one
    // spelling of a directory is walked and the matches found through it are
    // reported at their real locations.
    final holdMatches = walk.matches
        .map((m) => _parentOf(locationOf(m)))
        .toSet();
    for (final dir in walk.directoryMatches) {
      // A directory-form match that is a symlink counts in its own right: one
      // the walk did not list through (a link back up the tree, or a further
      // name for a directory already listed) has no match beneath it, yet
      // denies everything it reaches.
      if (holdMatches.contains(locationOf(dir)) ||
          walk.symlinks.contains(dir)) {
        candidates.add(dir);
      }
    }
  }
  final locations = <String>{};
  /** Links kept under their own spelling, which is not where they lead: a
   *  directory denied above one hides the link and not that place, so they
   *  take no part in the collapse. */
  final spelledLinks = <String>[];
  /** Which spelling first put a location in the list, for the warning below. */
  final namedBy = <String, String>{};
  void addLocation(String location, String candidate) {
    locations.add(location);
    namedBy.putIfAbsent(location, () => candidate);
  }

  for (final candidate in candidates) {
    if (walk.symlinks.contains(candidate) &&
        !walk.realOf.containsKey(candidate)) {
      if (!walk.uninspectableLinks.contains(candidate)) {
        // A link that resolves to nothing denies nothing, and bwrap cannot mount on the link itself.
        logForDebugging(
          '[Sandbox Linux] denyRead glob "$globPattern": $candidate does not resolve, skipping',
        );
        continue;
      }
      // A link whose target is there but cannot be looked at: kept under its
      // own spelling, where the denyRead loop's stand-in rule hides the
      // nearest directory above it that can be inspected.
      logForDebugging(
        '[Sandbox Linux] denyRead glob "$globPattern": $candidate leads somewhere that cannot be inspected; denying what holds it',
        level: 'warn',
      );
      spelledLinks.add(candidate);
      continue;
    }
    final location = locationOf(candidate);
    if (location != '/') {
      addLocation(location, candidate);
      continue;
    }
    // A link to the root. A tmpfs there would wipe every mount placed before
    // it and the pivot would promote it, booting the command on an empty tree,
    // and bwrap cannot mount on the link itself. The nearest directory above
    // the link stands in for it, as for an entry that cannot be inspected — never the root itself.
    final standIn = locationOf(_parentOf(candidate));
    if (standIn.isEmpty || standIn == '/') {
      logForDebugging(
        '[Sandbox Linux] denyRead glob "$globPattern": $candidate resolves to / and nothing but / holds it, skipping',
        level: 'warn',
      );
      continue;
    }
    logForDebugging(
      '[Sandbox Linux] denyRead glob "$globPattern": $candidate resolves to /; denying $standIn, which holds it, instead',
      level: 'warn',
    );
    addLocation(standIn, candidate);
  }
  // Allow paths, which reach this backend as names whatever they hold.
  final reExposed = <String>{
    for (final p in reExposedPaths)
      ...pathSpellings(normalizePathForSandbox(p, literal: true)),
  };
  final mounts = _collapseReadDenyLocations(
    locations: locations,
    reExposedPaths: reExposed,
  );
  // Which mounts stand for something the walk could not enumerate: the
  // unlistable directory itself when it survived the collapse, otherwise the
  // kept ancestor that hides it.
  for (final unlisted in walk.unlisted) {
    final location = locationOf(unlisted);
    if (mounts.contains(location)) {
      unlistableDirs?.add(location);
      continue;
    }
    for (final ancestor in properAncestors(location)) {
      if (mounts.contains(ancestor)) {
        unlistableDirs?.add(ancestor);
        break;
      }
    }
  }
  logForDebugging(
    '[Sandbox Linux] Expanded denyRead glob "$globPattern": ${walk.matches.length} matches -> ${mounts.length} mounts',
  );
  for (final mount in mounts) {
    // A matched link decides what is hidden for the whole sandbox: a
    // `certs/*` entry pointing at a database directory mounts a tmpfs over
    // that directory, not over anything the pattern names.
    if (walk.baseLocation != '' && !isAtOrUnder(mount, walk.baseLocation)) {
      logForDebugging(
        '[Sandbox Linux] denyRead glob "$globPattern" hides $mount, outside ${walk.baseLocation}: reached through ${namedBy[mount] == mount ? 'a symlinked directory' : namedBy[mount]}',
        level: 'warn',
      );
    }
  }
  if (mounts.length > READ_DENY_GLOB_MOUNT_WARN_THRESHOLD) {
    logForDebugging(
      '[Sandbox Linux] denyRead glob "$globPattern" still needs ${mounts.length} mounts after collapsing '
      '(threshold $READ_DENY_GLOB_MOUNT_WARN_THRESHOLD); each is a separate bwrap mount at sandbox start. '
      'Prefer denying the enclosing directories.',
      level: 'warn',
    );
  }
  yield Done([...mounts, ...spelledLinks]..sort());
}
