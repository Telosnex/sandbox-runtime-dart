// JS `Number(string)`: ECMAScript StringToNumber.

// StrWhiteSpaceChar: WhiteSpace and LineTerminator (U+0085 is neither).
bool _isStrWhiteSpaceChar(int c) =>
    c == 0x09 ||
    c == 0x0A ||
    c == 0x0B ||
    c == 0x0C ||
    c == 0x0D ||
    c == 0x20 ||
    c == 0xA0 ||
    c == 0x1680 ||
    (c >= 0x2000 && c <= 0x200A) ||
    c == 0x2028 ||
    c == 0x2029 ||
    c == 0x202F ||
    c == 0x205F ||
    c == 0x3000 ||
    c == 0xFEFF;

final RegExp _decimal = RegExp(
  r'^[+-]?(?:Infinity|(?:[0-9]+\.?[0-9]*|\.[0-9]+)(?:[eE][+-]?[0-9]+)?)$',
);

/// JS `Number(s)` for a string `s`: NaN when it is not a numeric literal.
double jsNumber(String s) {
  var start = 0;
  var end = s.length;
  while (start < end && _isStrWhiteSpaceChar(s.codeUnitAt(start))) {
    start++;
  }
  while (end > start && _isStrWhiteSpaceChar(s.codeUnitAt(end - 1))) {
    end--;
  }
  final t = s.substring(start, end);
  if (t.isEmpty) return 0;
  if (t.length > 2 && t[0] == '0') {
    final radix = switch (t[1]) {
      'x' || 'X' => 16,
      'o' || 'O' => 8,
      'b' || 'B' => 2,
      _ => 0,
    };
    if (radix != 0) {
      final digits = t.substring(2);
      if (!RegExp(
        radix == 16
            ? r'^[0-9a-fA-F]+$'
            : radix == 8
            ? r'^[0-7]+$'
            : r'^[01]+$',
      ).hasMatch(digits)) {
        return double.nan;
      }
      return BigInt.parse(digits, radix: radix).toDouble();
    }
  }
  if (!_decimal.hasMatch(t)) return double.nan;
  final neg = t.startsWith('-');
  final body = t.startsWith('+') || neg ? t.substring(1) : t;
  if (body == 'Infinity') {
    return neg ? double.negativeInfinity : double.infinity;
  }
  var n = body;
  if (n.startsWith('.')) n = '0$n';
  n = n.replaceFirst(RegExp(r'\.(?=[eE]|$)'), '');
  final d = double.parse(n);
  return neg ? -d : d;
}
