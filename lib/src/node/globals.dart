// JavaScript globals the port uses: parseInt, Number, Number.isInteger,
// setTimeout, setInterval. No upstream counterpart; Node is the spec.
// ignore_for_file: non_constant_identifier_names
import 'dart:async';

// JS StrWhiteSpaceChar: WhiteSpace and LineTerminator.
final RegExp _jsSpace = RegExp(
  '[\t\n\v\f\r \u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\ufeff]',
);

String _trimStart(String s) {
  var i = 0;
  while (i < s.length && _jsSpace.hasMatch(s[i])) {
    i++;
  }
  return s.substring(i);
}

String _trim(String s) {
  final start = _trimStart(s);
  var end = start.length;
  while (end > 0 && _jsSpace.hasMatch(start[end - 1])) {
    end--;
  }
  return start.substring(0, end);
}

/// JS `parseInt(string, radix)`: leading whitespace and sign, then the
/// longest run of digits valid in [radix]; `NaN` when there is none.
num parseInt(String string, [int? radix]) {
  var s = _trimStart(string);
  var sign = 1;
  if (s.startsWith('-')) {
    sign = -1;
    s = s.substring(1);
  } else if (s.startsWith('+')) {
    s = s.substring(1);
  }
  var r = radix ?? 0;
  var stripPrefix = true;
  if (r != 0) {
    if (r < 2 || r > 36) return double.nan;
    if (r != 16) stripPrefix = false;
  } else {
    r = 10;
  }
  if (stripPrefix && (s.startsWith('0x') || s.startsWith('0X'))) {
    s = s.substring(2);
    r = 16;
  }
  var end = 0;
  while (end < s.length) {
    final d = int.tryParse(s[end], radix: 36);
    if (d == null || d >= r) break;
    end++;
  }
  if (end == 0) return double.nan;
  final digits = s.substring(0, end);
  final big = BigInt.parse(digits, radix: r);
  if (big.bitLength < 53) return sign * big.toInt();
  return sign * big.toDouble();
}

/// JS `Number(value)` for the values the port passes: `undefined`/`null`,
/// strings, numbers and booleans.
num Number(Object? value) {
  if (value == null) return double.nan; // undefined; Number(null) is 0
  if (value is num) return value;
  if (value is bool) return value ? 1 : 0;
  if (value is! String) {
    throw UnimplementedError('Number(${value.runtimeType})');
  }
  final s = _trim(value);
  if (s.isEmpty) return 0;
  final prefixed = RegExp(r'^0([xXoObB])([0-9a-zA-Z]+)$').firstMatch(s);
  if (prefixed != null) {
    final radix = switch (prefixed[1]!.toLowerCase()) {
      'x' => 16,
      'o' => 8,
      _ => 2,
    };
    final big = BigInt.tryParse(prefixed[2]!, radix: radix);
    if (big == null) return double.nan;
    return big.bitLength < 53 ? big.toInt() : big.toDouble();
  }
  if (RegExp(r'^[+-]?Infinity$').hasMatch(s)) {
    return s.startsWith('-') ? double.negativeInfinity : double.infinity;
  }
  if (!RegExp(r'^[+-]?(\d+\.?\d*|\.\d+)([eE][+-]?\d+)?$').hasMatch(s)) {
    return double.nan;
  }
  final d = double.parse(s);
  if (d == d.truncateToDouble() && d.abs() < 9007199254740992) {
    return d.toInt();
  }
  return d;
}

/// JS `Number.isInteger(value)`.
bool NumberIsInteger(Object? value) =>
    value is int ||
    (value is double && value.isFinite && value == value.truncateToDouble());

/// Node's `Timeout`. Dart has no isolate-level unref: `unref()` is recorded
/// (see [unrefed]) but the timer still keeps the isolate alive.
class Timeout {
  Timeout._(this._timer);

  final Timer _timer;
  bool _unrefed = false;

  bool get unrefed => _unrefed;

  Timeout unref() {
    _unrefed = true;
    return this;
  }

  Timeout ref() {
    _unrefed = false;
    return this;
  }

  void close() => _timer.cancel();
}

/// Node's `setTimeout(callback, ms)`.
Timeout setTimeout(void Function() callback, int ms) =>
    Timeout._(Timer(Duration(milliseconds: ms < 1 ? 1 : ms), callback));

/// Node's `setInterval(callback, ms)`.
Timeout setInterval(void Function() callback, int ms) => Timeout._(
  Timer.periodic(Duration(milliseconds: ms < 1 ? 1 : ms), (_) => callback()),
);

/// Node's `clearTimeout` / `clearInterval`.
void clearTimeout(Timeout? timeout) => timeout?.close();
void clearInterval(Timeout? timeout) => timeout?.close();
