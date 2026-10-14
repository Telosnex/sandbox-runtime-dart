import 'package:sandbox_runtime/src/node/globals_number.dart';
import 'package:test/test.dart';

void main() {
  test('jsNumber matches JS Number(string)', () {
    expect(jsNumber(''), 0);
    expect(jsNumber(' \u00A0\uFEFF\n'), 0);
    expect(jsNumber(' 12 '), 12);
    expect(jsNumber('\u00850'), isNaN);
    expect(jsNumber('+0x10'), isNaN);
    expect(jsNumber('-0x10'), isNaN);
    expect(jsNumber('0x10'), 16);
    expect(jsNumber('0XfF'), 255);
    expect(jsNumber('0b11'), 3);
    expect(jsNumber('0o7'), 7);
    expect(jsNumber('0b12'), isNaN);
    expect(jsNumber('0x'), isNaN);
    expect(jsNumber('5.'), 5);
    expect(jsNumber('.5'), 0.5);
    expect(jsNumber('.'), isNaN);
    expect(jsNumber('1e3'), 1000);
    expect(jsNumber('1e'), isNaN);
    expect(jsNumber('-Infinity'), double.negativeInfinity);
    expect(jsNumber('+Infinity'), double.infinity);
    expect(jsNumber('infinity'), isNaN);
    expect(jsNumber('1_0'), isNaN);
    expect(jsNumber('-0').isNegative, isTrue);
    expect(jsNumber('007'), 7);
  });
}
