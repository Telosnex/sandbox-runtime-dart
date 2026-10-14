// Port of @pondwader/socks5-server 1.0.10 (dist/index.js): Socks5Server,
// Socks5Connection, createServer and defaultConnectionHandler.
//
// Dart differences: Node's `socket.push(rest)` in readBytes becomes
// `socket.unshift(rest)` (the readable buffer is empty while flowing, so
// the order is the same); enum lookups are maps.
// ignore_for_file: constant_identifier_names, prefer_function_declarations_over_variables
import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'errno.dart' show NodeError;
import 'net.dart' as net;

/// `Socks5ConnectionCommand`: byte code to name.
const Map<int, String> Socks5ConnectionCommand = {
  1: 'connect',
  2: 'bind',
  3: 'udp',
};

/// `Socks5ConnectionStatus`: name to reply code.
const Map<String, int> Socks5ConnectionStatus = {
  'REQUEST_GRANTED': 0,
  'GENERAL_FAILURE': 1,
  'CONNECTION_NOT_ALLOWED': 2,
  'NETWORK_UNREACHABLE': 3,
  'HOST_UNREACHABLE': 4,
  'CONNECTION_REFUSED': 5,
  'TTL_EXPIRED': 6,
  'COMMAND_NOT_SUPPORTED': 7,
  'ADDRESS_TYPE_NOT_SUPPORTED': 8,
};

typedef AuthHandler =
    FutureOr<Object?> Function(
      Socks5Connection connection,
      void Function() accept,
      void Function() deny,
    );
typedef RulesetValidator =
    FutureOr<Object?> Function(
      Socks5Connection connection,
      void Function() accept,
      void Function() deny,
    );
typedef ConnectionHandler =
    Object? Function(
      Socks5Connection connection,
      void Function(String status) sendStatus,
    );

class Socks5Connection {
  Socks5Connection(this.server, this.socket) {
    socket.on('error', errorHandler);
    socket.pause();
    unawaited(handleGreeting());
  }

  final net.NodeSocket socket;
  final Socks5Server server;
  final void Function(Object? error) errorHandler = (_) {};
  final Map<String, Object?> metadata = {};
  String? username;
  String? password;
  String? command;
  String? destAddress;
  int? destPort;

  Future<Uint8List> readBytes(int len) {
    final completer = Completer<Uint8List>();
    final buf = Uint8List(len);
    var offset = 0;
    late void Function(Object?) dataListener;
    dataListener = (Object? data) {
      final chunk = data as Uint8List;
      final readAmount = _min(chunk.length, len - offset);
      buf.setRange(offset, offset + readAmount, chunk);
      offset += readAmount;
      if (offset < len) return;
      socket.removeListener('data', dataListener);
      final rest = chunk.sublist(readAmount);
      if (rest.isNotEmpty) socket.unshift(rest);
      completer.complete(buf);
      socket.pause();
    };
    socket.on('data', dataListener);
    socket.resume();
    return completer.future;
  }

  Future<void> handleGreeting() async {
    final ver = (await readBytes(1))[0];
    if (ver != 5) {
      socket.destroy();
      return;
    }
    final authMethodsAmount = (await readBytes(1))[0];
    if (authMethodsAmount > 128 || authMethodsAmount == 0) {
      socket.destroy();
      return;
    }
    final authMethods = await readBytes(authMethodsAmount);
    final authMethodByteCode = server.authHandler != null ? 2 : 0;
    if (!authMethods.contains(authMethodByteCode)) {
      socket.write(Uint8List.fromList([5, 255]));
      socket.destroy();
      return;
    }
    socket.write(Uint8List.fromList([5, authMethodByteCode]));
    if (server.authHandler != null) {
      unawaited(handleUserPassword());
    } else {
      unawaited(handleConnectionRequest());
    }
  }

  Future<void> handleUserPassword() async {
    await readBytes(1);
    final usernameLength = (await readBytes(1))[0];
    final username = _toString(await readBytes(usernameLength));
    final passwordLength = (await readBytes(1))[0];
    final password = _toString(await readBytes(passwordLength));
    this.username = username;
    this.password = password;
    var calledBack = false;
    void acceptCallback() {
      if (calledBack) return;
      calledBack = true;
      socket.write(Uint8List.fromList([1, 0]));
      unawaited(handleConnectionRequest());
    }

    void denyCallback() {
      if (calledBack) return;
      calledBack = true;
      socket.write(Uint8List.fromList([1, 1]));
      socket.destroy();
    }

    final resp = await server.authHandler!(this, acceptCallback, denyCallback);
    if (resp == true) {
      acceptCallback();
    } else if (resp == false) {
      denyCallback();
    }
  }

  Future<void> handleConnectionRequest() async {
    await readBytes(1);
    final commandByte = (await readBytes(1))[0];
    final command = Socks5ConnectionCommand[commandByte];
    if (command == null) {
      socket.destroy();
      return;
    }
    this.command = command;
    await readBytes(1);
    final addrType = (await readBytes(1))[0];
    var address = '';
    switch (addrType) {
      case 1:
        address = (await readBytes(4)).join('.');
      case 3:
        final hostLength = (await readBytes(1))[0];
        address = _toString(await readBytes(hostLength));
      case 4:
        final bytes = await readBytes(16);
        for (var i = 0; i < 16; i++) {
          if (i % 2 == 0 && i > 0) address += ':';
          address += '${bytes[i] < 16 ? '0' : ''}${bytes[i].toRadixString(16)}';
        }
      default:
        socket.destroy();
        return;
    }
    final portBytes = await readBytes(2);
    final port = (portBytes[0] << 8) | portBytes[1];
    if (!server.supportedCommands.contains(command)) {
      socket.write(Uint8List.fromList([5, 7]));
      socket.destroy();
      return;
    }
    destAddress = address;
    destPort = port;
    var calledBack = false;
    void acceptCallback() {
      if (calledBack) return;
      calledBack = true;
      connect();
    }

    if (server.rulesetValidator == null) return acceptCallback();
    void denyCallback() {
      if (calledBack) return;
      calledBack = true;
      socket.write(Uint8List.fromList([5, 2, 0, 1, 0, 0, 0, 0, 0, 0]));
      socket.destroy();
    }

    final resp = await server.rulesetValidator!(
      this,
      acceptCallback,
      denyCallback,
    );
    if (resp == true) {
      acceptCallback();
    } else if (resp == false) {
      denyCallback();
    }
  }

  void connect() {
    socket.removeListener('error', errorHandler);
    server.connectionHandler(this, (status) {
      final code = Socks5ConnectionStatus[status];
      if (code == null) throw StateError('"$status" is not a valid status.');
      socket.write(Uint8List.fromList([5, code, 0, 1, 0, 0, 0, 0, 0, 0]));
      if (status != 'REQUEST_GRANTED') socket.destroy();
    });
    socket.resume();
  }
}

int _min(int a, int b) => a < b ? a : b;

// Node's Buffer#toString(): UTF-8 with U+FFFD for malformed input.
String _toString(Uint8List bytes) => utf8.decode(bytes, allowMalformed: true);

/// The library's default handler (`defaultConnectionHandler`).
net.NodeSocket? defaultConnectionHandler(
  Socks5Connection connection,
  void Function(String status) sendStatus,
) {
  if (connection.command != 'connect') {
    sendStatus('COMMAND_NOT_SUPPORTED');
    return null;
  }
  connection.socket.on('error', (_) {});
  final stream = net.createConnection({
    'host': connection.destAddress,
    'port': connection.destPort,
  });
  stream.setNoDelay();
  var streamOpened = false;
  stream.on('error', (Object? err) {
    if (!streamOpened) {
      final code = err is NodeError ? err.code : null;
      switch (code) {
        case 'EINVAL':
        case 'ENOENT':
        case 'ENOTFOUND':
        case 'ETIMEDOUT':
        case 'EADDRNOTAVAIL':
        case 'EHOSTUNREACH':
          sendStatus('HOST_UNREACHABLE');
        case 'ENETUNREACH':
          sendStatus('NETWORK_UNREACHABLE');
        case 'ECONNREFUSED':
          sendStatus('CONNECTION_REFUSED');
        default:
          sendStatus('GENERAL_FAILURE');
      }
    }
  });
  stream.on('ready', () {
    streamOpened = true;
    sendStatus('REQUEST_GRANTED');
    connection.socket.pipe(stream).pipe(connection.socket);
  });
  connection.socket.on('close', ([_]) => stream.destroy());
  return stream;
}

class Socks5Server {
  Socks5Server() {
    server = net.createServer((net.NodeSocket socket) {
      socket.setNoDelay();
      _handleConnection(socket);
    });
  }

  late final net.NodeServer server;
  AuthHandler? authHandler;
  RulesetValidator? rulesetValidator;
  final Set<String> supportedCommands = {'connect'};
  ConnectionHandler connectionHandler = defaultConnectionHandler;

  Socks5Server listen([Object? a, Object? b, Object? c, Object? d]) {
    server.listen(a, b, c, d);
    return this;
  }

  Socks5Server close([Function? callback]) {
    server.close(callback);
    return this;
  }

  Socks5Server setAuthHandler(AuthHandler handler) {
    authHandler = handler;
    return this;
  }

  Socks5Server disableAuthHandler() {
    authHandler = null;
    return this;
  }

  Socks5Server setRulesetValidator(RulesetValidator handler) {
    rulesetValidator = handler;
    return this;
  }

  Socks5Server disableRulesetValidator() {
    rulesetValidator = null;
    return this;
  }

  Socks5Server setConnectionHandler(ConnectionHandler handler) {
    connectionHandler = handler;
    return this;
  }

  Socks5Server useDefaultConnectionHandler() {
    connectionHandler = defaultConnectionHandler;
    return this;
  }

  // Not private because someone may want to inject a duplex stream to be
  // handled as a connection. (Dart: `_handleConnection` would be
  // library-private, so the public name drops the underscore.)
  Socks5Server handleConnection(net.NodeSocket socket) =>
      _handleConnection(socket);

  Socks5Server _handleConnection(net.NodeSocket socket) {
    Socks5Connection(this, socket);
    return this;
  }
}

/// `createServer(opts?: {auth?: {username, password}, port?, hostname?})`.
Socks5Server createServer({
  ({String username, String password})? auth,
  int? port,
  String? hostname,
}) {
  final server = Socks5Server();
  if (auth != null) {
    server.setAuthHandler(
      (conn, _, _) =>
          conn.username == auth.username && conn.password == auth.password,
    );
  }
  if (port != null && port != 0) server.listen(port, hostname);
  return server;
}
