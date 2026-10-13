// STUB: pending port of src/sandbox/request-filter.ts @ 24eb39e.
// ignore_for_file: dangling_library_doc_comments, slash_for_doc_comments

/**
 * Callback supplied through `network.filterRequest`. It receives the parsed
 * web-standard request and optional request information, and returns the
 * caller's allow/deny decision asynchronously. `Object` stands for the web
 * `Request` / `RequestInfo` shapes until their Dart representations are
 * introduced by the full request-filter port.
 */
typedef FilterRequestCallback =
    Future<Object?> Function(Object request, [Object? info]);
