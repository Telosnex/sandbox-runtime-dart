// Ported from @pondwader/socks5-server 1.0.10.
import 'dart:async';
import 'dart:typed_data';

import 'net.dart' as net;

class Socks5Connection {
  Socks5Connection(this.socket);
  final net.NodeSocket socket;
  String? username;
  String? password;
  String? destAddress;
  int? destPort;
  String? command;
}

typedef SocksAuthHandler =
    FutureOr<Object?> Function(
      Socks5Connection connection,
      void Function() accept,
      void Function() deny,
    );
typedef SocksRulesetValidator =
    FutureOr<Object?> Function(Socks5Connection connection);
typedef SocksConnectionHandler =
    void Function(
      Socks5Connection connection,
      void Function(String status) sendStatus,
    );

class Socks5Server {
  SocksAuthHandler? authHandler;
  SocksRulesetValidator? rulesetValidator;
  SocksConnectionHandler connectionHandler = (_, send) =>
      send('GENERAL_FAILURE');
  final Set<String> supportedCommands = {'connect'};

  Socks5Server setAuthHandler(SocksAuthHandler handler) {
    authHandler = handler;
    return this;
  }

  Socks5Server setRulesetValidator(SocksRulesetValidator handler) {
    rulesetValidator = handler;
    return this;
  }

  Socks5Server setConnectionHandler(SocksConnectionHandler handler) {
    connectionHandler = handler;
    return this;
  }

  void handleConnection(net.NodeSocket socket) {
    final conn = Socks5Connection(socket);
    unawaited(_process(conn));
  }

  Future<void> _process(Socks5Connection c) async {
    try {
      final v = await _read(c.socket, 2);
      if (v[0] != 5 || v[1] == 0) {
        c.socket.destroy();
        return;
      }
      final methods = await _read(c.socket, v[1]);
      final method = authHandler == null ? 0 : 2;
      if (!methods.contains(method)) {
        c.socket.write(Uint8List.fromList([5, 255]));
        c.socket.destroy();
        return;
      }
      c.socket.write(Uint8List.fromList([5, method]));
      if (authHandler != null) {
        final ver = await _read(c.socket, 2);
        c.username = (await _read(c.socket, ver[1])).toString();
        final plen = await _read(c.socket, 1);
        c.password = (await _read(c.socket, plen[0])).toString();
        var called = false;
        void accept() {
          if (called) return;
          called = true;
          c.socket.write(Uint8List.fromList([1, 0]));
          unawaited(_request(c));
        }

        void deny() {
          if (called) return;
          called = true;
          c.socket.write(Uint8List.fromList([1, 1]));
          c.socket.destroy();
        }

        final r = await authHandler!(c, accept, deny);
        if (r == true)
          accept();
        else if (r == false)
          deny();
        return;
      }
      await _request(c);
    } catch (_) {
      c.socket.destroy();
    }
  }

  Future<void> _request(Socks5Connection c) async {
    final h = await _read(c.socket, 4);
    if (h[0] != 5 || h[1] != 1) {
      c.socket.destroy();
      return;
    }
    c.command = 'connect';
    if (h[3] == 1) {
      c.destAddress = (await _read(c.socket, 4)).join('.');
    } else if (h[3] == 3) {
      final n = (await _read(c.socket, 1))[0];
      c.destAddress = (await _read(c.socket, n)).toString();
    } else if (h[3] == 4) {
      final b = await _read(c.socket, 16);
      c.destAddress = List.generate(
        8,
        (i) =>
            ((b[i * 2] << 8) | b[i * 2 + 1]).toRadixString(16).padLeft(4, '0'),
      ).join(':');
    } else {
      c.socket.destroy();
      return;
    }
    c.destPort = (await _read(c.socket, 2)).buffer.asByteData().getUint16(0);
    var accepted = false;
    void accept() {
      if (accepted) return;
      accepted = true;
      connectionHandler(c, (s) {
        const codes = {
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
        c.socket.write(
          Uint8List.fromList([5, codes[s] ?? 1, 0, 1, 0, 0, 0, 0, 0, 0]),
        );
        if (s != 'REQUEST_GRANTED') c.socket.destroy();
      });
    }

    final r = rulesetValidator == null ? true : await rulesetValidator!(c);
    if (r == true)
      accept();
    else if (r == false) {
      c.socket.write(Uint8List.fromList([5, 2, 0, 1, 0, 0, 0, 0, 0, 0]));
      c.socket.destroy();
    }
  }

  Future<Uint8List> _read(net.NodeSocket s, int n) async {
    final c = Completer<Uint8List>();
    final b = BytesBuilder();
    late Function listener;
    listener = (Object? x) {
      final bytes = x as List<int>;
      b.add(bytes);
      final all = b.toBytes();
      if (all.length >= n) {
        s.off('data', listener);
        if (all.length > n) s.unshift(all.sublist(n));
        c.complete(Uint8List.fromList(all.sublist(0, n)));
      }
    };
    s.on('data', listener);
    s.resume();
    return c.future;
  }
}

Socks5Server createServer() => Socks5Server();
