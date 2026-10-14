import 'package:sandbox_runtime/src/node/fs.dart' as fs;
import 'package:sandbox_runtime/src/node/path.dart' as path;
import 'package:test/test.dart';

void main() {
  readdirMain();
  test('path basics', () {
    expect(path.join('/a', 'b', '../c'), '/a/c');
    expect(path.resolve('/a', 'b'), '/a/b');
    expect(path.dirname('/a/b'), '/a');
    expect(path.dirname('C:/a//x'), 'C:/a/');
    expect(path.dirname('H://x'), 'H:/');
    expect(path.dirname('/a//x'), '/a/');
    expect(path.dirname('/x'), '/');
    expect(path.dirname('x'), '.');
    expect(path.dirname('a/b/'), 'a');
    expect(path.dirname('//x'), '//');
    expect(path.basename('/a/b.txt', '.txt'), 'b');
    expect(path.extname('x.js'), '.js');
    expect(path.relative('/a/b', '/a/c'), '../c');
  });
  test('spies', () {
    final o = fs.lstatSync;
    fs.lstatSync = (p) => throw StateError('x');
    expect(() => fs.lstatSync('/'), throwsStateError);
    fs.lstatSync = o;
    final d = path.dirname;
    path.dirname = (_) => 'z';
    expect(path.dirname('/a'), 'z');
    path.dirname = d;
  });
}

void readdirMain() {
  test('readdirSync names', () {
    final names = fs.readdirSync('/', withFileTypes: false);
    expect(names.map((d) => d.name), contains('tmp'));
    expect(fs.readdirNamesSync('/'), contains('tmp'));
    expect(fs.readdirSync('/', withFileTypes: true).first, isA<fs.Dirent>());
  });
}

// ignore: unused_element
void procErrMain() {}
