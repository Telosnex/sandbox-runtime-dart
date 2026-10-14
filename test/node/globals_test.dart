import 'package:sandbox_runtime/src/node/globals.dart';
import 'package:test/test.dart';

void main() {
  group('parseInt', () {
    test('prefix, whitespace and sign', () {
      expect(parseInt('42px'), 42);
      expect(parseInt('  7'), 7);
      expect(parseInt('-12'), -12);
      expect(parseInt('+5'), 5);
      expect(parseInt('3.9'), 3);
      expect(parseInt('0x1f'), 31);
    });
    test('NaN', () {
      expect(parseInt('').isNaN, isTrue);
      expect(parseInt('abc').isNaN, isTrue);
      expect(parseInt('-').isNaN, isTrue);
      expect(parseInt('1', 1).isNaN, isTrue);
      expect(parseInt('1', 37).isNaN, isTrue);
    });
    test('radix', () {
      expect(parseInt('ff', 16), 255);
      expect(parseInt('0xff', 16), 255);
      expect(parseInt('101', 2), 5);
      expect(parseInt('z', 36), 35);
      expect(parseInt('12', 2), 1);
      expect(parseInt('0x1f', 10), 0);
      expect(parseInt('10', 0), 10);
    });
  });

  group('Number', () {
    test('hex, octal, binary', () {
      expect(Number('0x10'), 16);
      expect(Number('0o17'), 15);
      expect(Number('0b11'), 3);
      expect(Number('0xg').isNaN, isTrue);
    });
    test('whitespace and empty', () {
      expect(Number('  12 '), 12);
      expect(Number('\n'), 0);
      expect(Number(''), 0);
      expect(Number('1 2').isNaN, isTrue);
    });
    test('Infinity, decimals, junk', () {
      expect(Number('Infinity'), double.infinity);
      expect(Number('-Infinity'), double.negativeInfinity);
      expect(Number('infinity').isNaN, isTrue);
      expect(Number('1.5e2'), 150);
      expect(Number('.5'), 0.5);
      expect(Number('5px').isNaN, isTrue);
      expect(Number(null).isNaN, isTrue);
      expect(Number(true), 1);
    });
  });

  test('NumberIsInteger', () {
    expect(NumberIsInteger(5), isTrue);
    expect(NumberIsInteger(5.0), isTrue);
    expect(NumberIsInteger(5.5), isFalse);
    expect(NumberIsInteger(double.infinity), isFalse);
    expect(NumberIsInteger(double.nan), isFalse);
    expect(NumberIsInteger('5'), isFalse);
  });

  test('setTimeout, setInterval, unref/ref/close', () async {
    var t = 0;
    setTimeout(() => t++, 5);
    final i = setInterval(() => t += 10, 5);
    await Future<void>.delayed(const Duration(milliseconds: 40));
    i.close();
    final after = t;
    expect(after >= 11, isTrue);
    await Future<void>.delayed(const Duration(milliseconds: 20));
    expect(t, after);
    final c = setTimeout(() => t = -1, 5)..close();
    expect(c.unref().unrefed, isTrue);
    expect(c.ref().unrefed, isFalse);
    await Future<void>.delayed(const Duration(milliseconds: 20));
    expect(t, after);
  });
}
