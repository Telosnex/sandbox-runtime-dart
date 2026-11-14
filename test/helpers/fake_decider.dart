// Ported from sandbox-runtime test/helpers/fake-decider.ts @ 0bbebed.
import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';
import 'package:sandbox_runtime/src/node/stream.dart' as stream;

/** A frame: the 4-byte big-endian length, then the JSON text as given. */
Uint8List frameOf(String json) {
  final b = Uint8List.fromList(utf8.encode(json));
  final n = ByteData(4)..setUint32(0, b.length, Endian.big);
  return Uint8List.fromList([...n.buffer.asUint8List(), ...b]);
}

typedef Frame = Map<String, Object?>;

/** An in-test decider on a pair of streams, driven by a verdict function. */
Map<String, Object> fakeDecider(
  List<String> allowedDomains,
  Object Function(Frame f) decide, {
  List<String> deniedDomains = const [],
}) {
  final toProxy = stream.PassThrough();
  final fromProxy = stream.PassThrough();
  final seen = <Frame>[];
  var buf = Uint8List(0);
  var hello = false;
  void send(Frame m) {
    final b = Uint8List.fromList(utf8.encode(jsonEncode(m)));
    final n = ByteData(4)..setUint32(0, b.length, Endian.big);
    toProxy.write(Uint8List.fromList([...n.buffer.asUint8List(), ...b]));
  }

  fromProxy.on('data', (Object? chunk) {
    final c = chunk as Uint8List;
    buf = Uint8List.fromList([...buf, ...c]);
    while (buf.length >= 4 &&
        buf.length >= 4 + ByteData.sublistView(buf).getUint32(0, Endian.big)) {
      final n = ByteData.sublistView(buf).getUint32(0, Endian.big);
      final f =
          jsonDecode(utf8.decode(buf.sublist(4, 4 + n)))
              as Map<String, Object?>;
      buf = Uint8List.fromList(buf.sublist(4 + n));
      if (!hello) {
        hello = true;
        send({
          't': 'hello',
          'proto': 1,
          'allowedDomains': allowedDomains,
          'deniedDomains': deniedDomains,
        });
        continue;
      }
      seen.add(f);
      final v = decide(f);
      if (v is Future<Frame>) {
        unawaited(
          v.then((late) => send({'t': 'verdict', 'id': f['id'], ...late})),
        );
        continue;
      }
      if (v == 'hang') continue;
      if (v == 'garbage')
        toProxy.write(Uint8List.fromList([0, 0, 0, 3, 120, 121, 122]));
      else if (v == 'end')
        toProxy.end();
      else
        send({'t': 'verdict', 'id': f['id'], ...(v as Frame)});
    }
  });
  return {
    'streams': {'input': toProxy, 'output': fromProxy},
    'seen': seen,
  };
}
