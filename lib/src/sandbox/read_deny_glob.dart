// STUB: pending port of src/sandbox/read-deny-glob.ts @ 24eb39e.

import 'sandbox_utils.dart';

/// Expand a read-deny glob into the paths bwrap should mount over, collapsed
/// against `reExposedPaths` (the caller's allowRead and allowWrite entries).
/// A pattern ending in `/**` also takes its directory form, so
/// `**/build/**` yields one mount per `build/` directory. A match reached
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
}) {
  throw UnimplementedError('pending port of src/sandbox/read-deny-glob.ts');
}

/// [expandReadDenyGlobLinux], in the walk's steps.
Steps<List<String>> expandReadDenyGlobLinuxSteps(
  String globPattern,
  List<String> reExposedPaths, {
  Set<String>? unlistableDirs,
  String? anchor,
  GlobWalkListings? listings,
}) {
  throw UnimplementedError('pending port of src/sandbox/read-deny-glob.ts');
}
