import 'dart:typed_data';
import 'dart:io';

Uint8List gzipSync(List<int> data) => Uint8List.fromList(gzip.encode(data));

Uint8List gunzipSync(List<int> data) => Uint8List.fromList(gzip.decode(data));
