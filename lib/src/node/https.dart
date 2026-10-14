// Node-compatible HTTPS subset built on the HTTP and TLS shims.
// ignore_for_file: use_super_parameters
import 'http.dart' as http;
import 'net.dart' as net;
import 'tls.dart' as tls;

/// Node HTTPS server. The secure context is provided by `key` and `cert`, or
/// by `secureContext`.
class Server extends http.NodeHttpServer {
  Server(this.options, [Function? requestListener]) {
    if (requestListener != null) on('request', requestListener);
  }
  final Map<Object?, Object?> options;

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

http.ClientRequest request(Object options, [Function? responseListener]) {
  final Map<Object?, Object?> opts;
  if (options is Map) {
    opts = Map<Object?, Object?>.of(options);
  } else if (options is Uri) {
    opts = {
      'protocol': 'https:',
      'hostname': options.host,
      'port': options.hasPort ? options.port : null,
      'path': '${options.path}${options.hasQuery ? '?${options.query}' : ''}',
    };
  } else if (options is String) {
    final uri = Uri.parse(options);
    opts = {
      'protocol': 'https:',
      'hostname': uri.host,
      'port': uri.hasPort ? uri.port : null,
      'path': '${uri.path}${uri.hasQuery ? '?${uri.query}' : ''}',
    };
  } else {
    throw ArgumentError(
      'https.request options must be a Map, Uri, or URL string',
    );
  }
  opts['protocol'] = 'https:';
  opts.putIfAbsent('agent', () => globalAgent);
  return http.request(opts, responseListener);
}

http.ClientRequest get(Object options, [Function? responseListener]) =>
    request(options, responseListener)..end();

/// Public Node socket type used by HTTPS callbacks.
typedef Socket = net.NodeSocket;

/// TLS socket type used by HTTPS connections.
typedef TLSSocket = tls.TLSSocket;

/// Node HTTP request and response types exposed by HTTPS.
typedef IncomingMessage = http.IncomingMessage;
typedef ServerResponse = http.ServerResponse;
typedef ClientRequest = http.ClientRequest;
