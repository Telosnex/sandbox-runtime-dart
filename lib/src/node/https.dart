// Node-compatible HTTPS subset built on the HTTP and TLS shims.
// ignore_for_file: use_super_parameters
import 'http.dart' as http;
import 'net.dart' as net;
import 'tls.dart' as tls;
import 'url.dart' as url;

/// Node HTTPS server. The secure context is provided by `key` and `cert`, or
/// by `secureContext`.
class Server extends http.NodeHttpServer {
  Server(this.options, [Function? requestListener]) {
    if (requestListener != null) on('request', requestListener);
  }
  final Map<Object?, Object?> options;

  /// TLS server side over each accepted socket, then the HTTP parser on it.
  @override
  void serveConnection(net.NodeSocket accepted) {
    final context =
        options['secureContext'] as tls.SecureContext? ??
        tls.createSecureContext(
          cert: _pem(options['cert']),
          key: _pem(options['key']),
        );
    final secured = tls.TLSSocket(accepted, {
      'isServer': true,
      'secureContext': context,
    });
    secured.on('error', ([_]) {});
    super.serveConnection(secured);
  }

  static String _pem(Object? v) => v is String
      ? v
      : v is List<int>
      ? String.fromCharCodes(v)
      : throw ArgumentError('https.createServer needs PEM cert and key');

  @override
  Server on(String event, Function listener) {
    super.on(event, listener);
    return this;
  }

  @override
  Server listen([Object? a, Object? b, Object? c, Object? d]) {
    super.listen(a, b, c, d);
    return this;
  }
}

Server createServer([Object? options, Function? requestListener]) {
  final opts = options is Map
      ? Map<Object?, Object?>.of(options)
      : <Object?, Object?>{};
  return Server(opts, requestListener);
}

class Agent extends http.Agent {
  Agent({
    bool keepAlive = true,
    int maxSockets = 1,
    String? socketPath,
    tls.SecureContext? securityContext,
    Object? ca,
    Function? checkServerIdentity,
  }) : super(
         keepAlive: keepAlive,
         maxSockets: maxSockets,
         socketPath: socketPath,
         secure: true,
         securityContext: securityContext,
         ca: ca,
         checkServerIdentity: checkServerIdentity,
       );
}

final Agent globalAgent = Agent(keepAlive: true, maxSockets: 1);

/// Node's `https.request(url[, options][, callback])` and
/// `https.request(options[, callback])`: [input] is a URL string, [url.URL],
/// [Uri] or an options map; a map in [options] is merged over the URL's
/// fields, as Node's `urlToHttpOptions` then `Object.assign` do.
http.ClientRequest request(
  Object input, [
  Object? options,
  Function? responseListener,
]) {
  if (options is Function && responseListener == null) {
    responseListener = options;
    options = null;
  }
  final Map<Object?, Object?> opts;
  if (input is Map) {
    opts = Map<Object?, Object?>.of(input);
  } else if (input is String || input is url.URL || input is Uri) {
    final parsed = url.URL(input is String ? input : input.toString());
    opts = _urlToHttpOptions(parsed);
  } else {
    throw ArgumentError(
      'https.request options must be a Map, URL, Uri, or URL string',
    );
  }
  if (options is Map) opts.addAll(options);
  opts.putIfAbsent('protocol', () => 'https:');
  if (opts['protocol'] != 'https:') {
    throw ArgumentError.value(
      opts['protocol'],
      'protocol',
      'Protocol "${opts['protocol']}" not supported. Expected "https:"',
    );
  }
  opts.putIfAbsent('agent', () => globalAgent);
  opts['port'] ??= 443;
  return http.request(opts, responseListener);
}

/// Node's `urlToHttpOptions`.
Map<Object?, Object?> _urlToHttpOptions(url.URL u) {
  final hostname = u.hostname.startsWith('[')
      ? u.hostname.substring(1, u.hostname.length - 1)
      : u.hostname;
  return {
    'protocol': u.protocol,
    'hostname': hostname,
    'hash': u.hash,
    'search': u.search,
    'pathname': u.pathname,
    'path': '${u.pathname}${u.search}',
    'href': u.href,
    if (u.port != '') 'port': int.parse(u.port),
    if (u.username.isNotEmpty || u.password.isNotEmpty)
      'auth':
          '${Uri.decodeComponent(u.username)}:${Uri.decodeComponent(u.password)}',
  };
}

http.ClientRequest get(
  Object input, [
  Object? options,
  Function? responseListener,
]) => request(input, options, responseListener)..end();

/// Public Node socket type used by HTTPS callbacks.
typedef Socket = net.NodeSocket;

/// TLS socket type used by HTTPS connections.
typedef TLSSocket = tls.TLSSocket;

/// Node HTTP request and response types exposed by HTTPS.
typedef IncomingMessage = http.IncomingMessage;
typedef ServerResponse = http.ServerResponse;
typedef ClientRequest = http.ClientRequest;
