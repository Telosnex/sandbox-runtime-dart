// Node-compatible HTTPS subset built on the HTTP and TLS shims.
import 'http.dart' as http;
import 'net.dart' as net;
import 'tls.dart' as tls;

/// Node HTTPS server. The secure context is provided by `key` and `cert`, or
/// by `secureContext`.
class Server extends http.NodeHttpServer {
  Server(this.options, [Function? requestListener]);
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
    super.keepAlive,
    super.maxSockets,
    super.socketPath,
    super.secure,
    super.securityContext,
    super.ca,
    super.checkServerIdentity,
  });
}

final Agent globalAgent = Agent(keepAlive: true, maxSockets: 1, secure: true);

http.ClientRequest request(Object options, [Function? responseListener]) {
  final opts = options is Map
      ? Map<Object?, Object?>.of(options)
      : <Object?, Object?>{};
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
