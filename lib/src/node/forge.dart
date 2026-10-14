// ignore_for_file: non_constant_identifier_names
// Node-forge subset used by sandbox-runtime src/sandbox/{mitm-ca,mitm-leaf}.ts.
// Implemented in portable Dart with PointyCastle RSA and ASN.1 DER primitives.
import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:asn1lib/asn1lib.dart' as asn1lib;
import 'package:crypto/crypto.dart' as crypto;
import 'package:pointycastle/export.dart' as pc;

/// `node-forge`'s default export shape. Fields are deliberately small and
/// match the methods used in mitm-ca.ts and mitm-leaf.ts.
final class Forge {
  const Forge._();
  final asn1 = const ForgeAsn1Api();
  final pki = const ForgePkiApi();
  final md = const ForgeMdApi();
  final random = const ForgeRandomApi();
  final util = const ForgeUtilApi();
}

/// Singleton mirroring `import forge from 'node-forge'`.
const forge = Forge._();

typedef Certificate = ForgeCertificate;
typedef DistinguishedName = ForgeDistinguishedName;
typedef PrivateKey = ForgeRsaPrivateKey;
typedef PublicKey = ForgeRsaPublicKey;
typedef KeyPair = ForgeRsaKeyPair;

class ForgePkiApi {
  const ForgePkiApi();
  final oids = const ForgeOids();
  final rsa = const ForgeRsaApi();
  ForgeCertificate createCertificate() => ForgeCertificate();
  String privateKeyToPem(ForgeRsaPrivateKey key) => key.toPem();
  String certificateToPem(ForgeCertificate cert) => cert.toPem();
  ForgeCertificate certificateFromPem(String pem) =>
      ForgeCertificate.fromPem(pem);
  ForgeRsaPrivateKey privateKeyFromPem(String pem) =>
      ForgeRsaPrivateKey.fromPem(pem);
  ForgeAsn1 distinguishedNameToAsn1(ForgeDistinguishedName name) =>
      name.toAsn1();
  ForgeRsaPublicKey setRsaPublicKey(BigInt n, BigInt e) =>
      ForgeRsaPublicKey(n, e);
  ForgeAsn1 getTBSCertificate(ForgeCertificate cert) =>
      cert.getTBSCertificate();
}

class ForgeRsaApi {
  const ForgeRsaApi();
  ForgeRsaKeyPair generateKeyPair([int bits = 2048]) =>
      ForgeRsaKeyPair.generate(bits);
}

class ForgeOids {
  const ForgeOids();
  final String sha256WithRSAEncryption = '1.2.840.113549.1.1.11';
  final String rsaEncryption = '1.2.840.113549.1.1.1';
  final String basicConstraints = '2.5.29.19';
  final String keyUsage = '2.5.29.15';
  final String extKeyUsage = '2.5.29.37';
  final String subjectAltName = '2.5.29.17';
  final String subjectKeyIdentifier = '2.5.29.14';
  final String authorityKeyIdentifier = '2.5.29.35';
  final String cRLDistributionPoints = '2.5.29.31';
}

class ForgeMdApi {
  const ForgeMdApi();
  final sha256 = const ForgeDigestFactory('sha256');
}

class ForgeDigestFactory {
  const ForgeDigestFactory(this.algorithm);
  final String algorithm;
  ForgeMessageDigest create() => ForgeMessageDigest(algorithm);
}

class ForgeMessageDigest {
  ForgeMessageDigest(this.algorithm);
  final String algorithm;
  final List<int> _input = [];
  List<int> get _messageBytes => List<int>.unmodifiable(_input);
  void update(String binary) => _input.addAll(_binaryBytes(binary));
  String get digestBytes => _binary(crypto.sha256.convert(_input).bytes);
  ForgeBinaryBuffer digest() => ForgeBinaryBuffer(digestBytes);
}

class ForgeRandomApi {
  const ForgeRandomApi();

  /// Test spy: when set, [getBytesSync] returns its result instead.
  static String Function(int length)? getBytesSyncSpy;

  String getBytesSync(int length) {
    final spy = getBytesSyncSpy;
    if (spy != null) return spy(length);
    final random = Random.secure();
    return _binary(List<int>.generate(length, (_) => random.nextInt(256)));
  }
}

class ForgeUtilApi {
  const ForgeUtilApi();
  String bytesToHex(String binary) => _binaryBytes(
    binary,
  ).map((byte) => byte.toRadixString(16).padLeft(2, '0')).join();
  String hexToBytes(String hex) {
    if (hex.length.isOdd || !RegExp(r'^[0-9a-fA-F]*$').hasMatch(hex)) {
      throw FormatException('Invalid hex string');
    }
    return _binary([
      for (var i = 0; i < hex.length; i += 2)
        int.parse(hex.substring(i, i + 2), radix: 16),
    ]);
  }
}

class ForgeAsn1Api {
  const ForgeAsn1Api();
  final Class = const ForgeAsn1Class();
  final Type = const ForgeAsn1Type();

  ForgeAsn1 create(int tagClass, int type, bool constructed, dynamic value) =>
      ForgeAsn1(tagClass, type, constructed, value);

  ForgeDerBuffer toDer(ForgeAsn1 object) => ForgeDerBuffer(object.encode());

  ForgeDerBuffer oidToDer(String oid) =>
      ForgeDerBuffer(Uint8List.fromList(_oidContents(oid)));

  String dateToUtcTime(DateTime date) {
    final d = date.toUtc();
    return '${(d.year % 100).toString().padLeft(2, '0')}'
        '${d.month.toString().padLeft(2, '0')}${d.day.toString().padLeft(2, '0')}'
        '${d.hour.toString().padLeft(2, '0')}${d.minute.toString().padLeft(2, '0')}'
        '${d.second.toString().padLeft(2, '0')}Z';
  }

  String dateToGeneralizedTime(DateTime date) {
    final d = date.toUtc();
    return '${d.year.toString().padLeft(4, '0')}'
        '${d.month.toString().padLeft(2, '0')}${d.day.toString().padLeft(2, '0')}'
        '${d.hour.toString().padLeft(2, '0')}${d.minute.toString().padLeft(2, '0')}'
        '${d.second.toString().padLeft(2, '0')}Z';
  }
}

class ForgeAsn1Class {
  const ForgeAsn1Class();
  final UNIVERSAL = 0;
  final APPLICATION = 0x40;
  final CONTEXT_SPECIFIC = 0x80;
  final PRIVATE = 0xc0;
}

class ForgeAsn1Type {
  const ForgeAsn1Type();
  final BOOLEAN = 1;
  final INTEGER = 2;
  final BITSTRING = 3;
  final OCTETSTRING = 4;
  final NULL = 5;
  final OID = 6;
  final UTF8 = 12;
  final SEQUENCE = 16;
  final SET = 17;
  final PRINTABLESTRING = 19;
  final IA5STRING = 22;
  final UTCTIME = 23;
  final GENERALIZEDTIME = 24;
}

class ForgeDerBuffer {
  ForgeDerBuffer(this._bytes);
  final Uint8List _bytes;
  String getBytes() => _binary(_bytes);
  Uint8List getBuffer() => Uint8List.fromList(_bytes);
}

/// Forge-shaped ASN.1 value, backed by strict DER bytes. Context-specific
/// primitive values are treated as binary strings, just as node-forge does.
class ForgeAsn1 {
  ForgeAsn1(this.tagClass, this.type, this.constructed, this.value);
  final int tagClass;
  final int type;
  final bool constructed;
  final dynamic value;

  Uint8List encode() {
    final tag = tagClass | (constructed ? 0x20 : 0) | type;
    final List<int> content;
    if (constructed) {
      content = <int>[];
      for (final child in value as List<ForgeAsn1>) {
        content.addAll(child.encode());
      }
    } else if (value is String) {
      content = _binaryBytes(value as String);
    } else if (value is Uint8List) {
      content = value as Uint8List;
    } else if (value is List<int>) {
      content = value as List<int>;
    } else {
      content = const [];
    }
    return Uint8List.fromList(_derTlv(tag, content));
  }
}

class ForgeDistinguishedName {
  ForgeDistinguishedName(List<Map<String, String>> attributes)
    : attributes = attributes.map((a) => Map<String, String>.from(a)).toList();
  final List<Map<String, String>> attributes;

  ForgeAsn1 toAsn1() => _nameAsn1(attributes);
}

class ForgeValidity {
  DateTime notBefore = DateTime.now().toUtc();
  DateTime notAfter = DateTime.now().toUtc();
}

class ForgeCertificate {
  String serialNumber = '01';
  ForgeRsaPublicKey? publicKey;
  final validity = ForgeValidity();
  ForgeDistinguishedName subject = ForgeDistinguishedName([]);
  ForgeDistinguishedName issuer = ForgeDistinguishedName([]);
  final List<Map<String, dynamic>> extensions = [];
  String signature = '';
  String signatureOid = forge.pki.oids.sha256WithRSAEncryption;
  ForgeSigInfo siginfo = ForgeSigInfo();
  ForgeAsn1? tbsCertificate;
  ForgeMessageDigest? md;

  void setSubject(List<Map<String, dynamic>> attributes) {
    subject = ForgeDistinguishedName(
      attributes.map(_normalizeAttribute).toList(),
    );
  }

  void setIssuer(List<Map<String, dynamic>> attributes) {
    issuer = ForgeDistinguishedName(
      attributes.map(_normalizeAttribute).toList(),
    );
  }

  void setExtensions(List<Map<String, dynamic>> values) {
    extensions
      ..clear()
      ..addAll(values.map((e) => Map<String, dynamic>.from(e)));
  }

  Map<String, dynamic>? getExtension(String name) {
    for (final extension in extensions) {
      if (extension['name'] == name ||
          extension['id'] == _extensionOidForName(name)) {
        return extension;
      }
    }
    return null;
  }

  ForgeBinaryBuffer generateSubjectKeyIdentifier() {
    final key = publicKey;
    if (key == null) throw StateError('Certificate publicKey is unset');
    // RFC 5280 method 1 hashes the subjectPublicKey BIT STRING contents.
    final spki = _rsaPublicKeyAsn1(key).encode();
    final digest = crypto.sha1.convert(spki).bytes;
    return ForgeBinaryBuffer(_binary(digest));
  }

  ForgeAsn1 getTBSCertificate() {
    final key = publicKey;
    if (key == null) throw StateError('Certificate publicKey is unset');
    for (final extension in extensions) {
      if (extension['name'] == 'subjectKeyIdentifier' &&
          extension['subjectKeyIdentifier'] == null) {
        extension['subjectKeyIdentifier'] = forge.util.bytesToHex(
          generateSubjectKeyIdentifier().getBytes(),
        );
      }
    }
    final extensionsDer = extensions.map(_extensionAsn1).toList();
    final fields = <ForgeAsn1>[
      ForgeAsn1(forge.asn1.Class.CONTEXT_SPECIFIC, 0, true, [
        _integerAsn1(BigInt.from(2)), // X.509 v3
      ]),
      _integerAsn1(BigInt.parse(serialNumber, radix: 16)),
      _algorithmIdentifier(signatureOid),
      issuer.toAsn1(),
      ForgeAsn1(0, forge.asn1.Type.SEQUENCE, true, [
        _asn1Time(validity.notBefore),
        _asn1Time(validity.notAfter),
      ]),
      subject.toAsn1(),
      _subjectPublicKeyInfo(key),
    ];
    if (extensionsDer.isNotEmpty) {
      fields.add(
        ForgeAsn1(forge.asn1.Class.CONTEXT_SPECIFIC, 3, true, [
          ForgeAsn1(0, forge.asn1.Type.SEQUENCE, true, extensionsDer),
        ]),
      );
    }
    return ForgeAsn1(0, forge.asn1.Type.SEQUENCE, true, fields);
  }

  String toPem() {
    if (signature.isEmpty) throw StateError('Certificate has not been signed');
    final tbs = tbsCertificate ?? getTBSCertificate();
    final certificate = ForgeAsn1(0, forge.asn1.Type.SEQUENCE, true, [
      tbs,
      _algorithmIdentifier(signatureOid),
      ForgeAsn1(0, forge.asn1.Type.BITSTRING, false, '\x00$signature'),
    ]).encode();
    return _pem('CERTIFICATE', certificate);
  }

  /// node-forge's standard RSA/SHA-256 certificate signing operation.
  void sign(ForgeRsaPrivateKey key, [ForgeMessageDigest? digest]) {
    final tbs = getTBSCertificate();
    tbsCertificate = tbs;
    final der = _binary(tbs.encode());
    final messageDigest = digest ?? forge.md.sha256.create();
    messageDigest.update(der);
    md = messageDigest;
    signatureOid = forge.pki.oids.sha256WithRSAEncryption;
    siginfo.algorithmOid = signatureOid;
    signature = key.sign(messageDigest);
  }

  static ForgeCertificate fromPem(String pem) {
    final match = RegExp(
      r'-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----',
    ).firstMatch(pem);
    if (match == null) throw FormatException('PEM is not a CERTIFICATE');
    final der = base64.decode(match.group(1)!.replaceAll(RegExp(r'\s'), ''));
    final root =
        asn1lib.ASN1Parser(Uint8List.fromList(der)).nextObject()
            as asn1lib.ASN1Sequence;
    final certFields = root.elements;
    final tbs = certFields[0] as asn1lib.ASN1Sequence;
    var offset = tbs.elements.first.tag == 0xa0 ? 1 : 0;
    final result = ForgeCertificate();
    result.serialNumber = _bigIntHex(
      (tbs.elements[offset++] as asn1lib.ASN1Integer).valueAsBigInteger,
    );
    offset++; // signature algorithm
    result.issuer = _parseName(tbs.elements[offset++] as asn1lib.ASN1Sequence);
    final validity = tbs.elements[offset++] as asn1lib.ASN1Sequence;
    result.validity.notBefore = _parseTime(validity.elements[0]);
    result.validity.notAfter = _parseTime(validity.elements[1]);
    result.subject = _parseName(tbs.elements[offset++] as asn1lib.ASN1Sequence);
    result.publicKey = _parseSubjectPublicKeyInfo(
      tbs.elements[offset++] as asn1lib.ASN1Sequence,
    );
    for (final field in tbs.elements.skip(offset)) {
      if (field.tag != 0xa3) continue;
      final parsed =
          asn1lib.ASN1Parser(field.valueBytes()).nextObject()
              as asn1lib.ASN1Sequence;
      for (final extObject in parsed.elements.cast<asn1lib.ASN1Sequence>()) {
        final oid =
            (extObject.elements[0] as asn1lib.ASN1ObjectIdentifier).identifier!;
        var index = 1;
        var critical = false;
        if (extObject.elements[index] is asn1lib.ASN1Boolean) {
          critical =
              (extObject.elements[index++] as asn1lib.ASN1Boolean).booleanValue;
        }
        final raw =
            (extObject.elements[index] as asn1lib.ASN1OctetString).octets;
        final extension = _parseExtension(oid, critical, raw);
        result.extensions.add(extension);
      }
    }
    result.signature = _binary(
      (certFields[2] as asn1lib.ASN1BitString).stringValue,
    );
    return result;
  }
}

class ForgeSigInfo {
  String algorithmOid = forge.pki.oids.sha256WithRSAEncryption;
}

class ForgeBinaryBuffer {
  ForgeBinaryBuffer(this._bytes);
  final String _bytes;
  String getBytes() => _bytes;
  String toHex() => const ForgeUtilApi().bytesToHex(_bytes);
}

class ForgeRsaKeyPair {
  ForgeRsaKeyPair(this.publicKey, this.privateKey);
  final ForgeRsaPublicKey publicKey;
  final ForgeRsaPrivateKey privateKey;

  factory ForgeRsaKeyPair.generate(int bits) {
    final seed = Uint8List.fromList(
      List<int>.generate(32, (_) => Random.secure().nextInt(256)),
    );
    final random = pc.FortunaRandom()..seed(pc.KeyParameter(seed));
    final generator = pc.RSAKeyGenerator()
      ..init(
        pc.ParametersWithRandom(
          pc.RSAKeyGeneratorParameters(BigInt.from(65537), bits, 64),
          random,
        ),
      );
    final pair = generator.generateKeyPair();
    final pub = pair.publicKey as pc.RSAPublicKey;
    final priv = pair.privateKey as pc.RSAPrivateKey;
    return ForgeRsaKeyPair(
      ForgeRsaPublicKey(pub.modulus!, pub.exponent!),
      ForgeRsaPrivateKey(
        priv.modulus!,
        priv.privateExponent!,
        priv.p!,
        priv.q!,
        publicExponent: pub.exponent!,
      ),
    );
  }
}

class ForgeRsaPublicKey {
  ForgeRsaPublicKey(this.n, this.e);
  final BigInt n;
  final BigInt e;
  int compareModulus(ForgeRsaPublicKey other) => n.compareTo(other.n);
}

class ForgeRsaPrivateKey {
  ForgeRsaPrivateKey(
    this.n,
    this.d,
    this.p,
    this.q, {
    required this.publicExponent,
  });
  final BigInt n;
  final BigInt d;
  final BigInt p;
  final BigInt q;
  final BigInt publicExponent;
  BigInt get e => publicExponent;

  String sign(dynamic digest, {String algorithm = 'RSASSA-PKCS1-V1_5'}) {
    if (algorithm != 'RSASSA-PKCS1-V1_5') {
      throw UnsupportedError(
        'node-forge RSA signing mode $algorithm is unsupported',
      );
    }
    final message = digest is ForgeMessageDigest
        ? _binary(digest._messageBytes)
        : digest is String
        ? digest
        : _binary(digest as List<int>);
    final signer = pc.RSASigner(pc.SHA256Digest(), '0609608648016503040201')
      ..init(
        true,
        pc.PrivateKeyParameter<pc.RSAPrivateKey>(pc.RSAPrivateKey(n, d, p, q)),
      );
    return _binary(
      signer.generateSignature(Uint8List.fromList(_binaryBytes(message))).bytes,
    );
  }

  String toPem() => _pem('RSA PRIVATE KEY', _rsaPrivateKeyDer(this));

  static ForgeRsaPrivateKey fromPem(String pem) {
    final match = RegExp(
      r'-----BEGIN (?:RSA )?PRIVATE KEY-----([\s\S]*?)-----END (?:RSA )?PRIVATE KEY-----',
    ).firstMatch(pem);
    if (match == null) throw FormatException('PEM is not an RSA PRIVATE KEY');
    var der = Uint8List.fromList(
      base64.decode(match.group(1)!.replaceAll(RegExp(r'\s'), '')),
    );
    var root = asn1lib.ASN1Parser(der).nextObject() as asn1lib.ASN1Sequence;
    // PKCS#8 PrivateKeyInfo wraps the PKCS#1 key in an OCTET STRING.
    if (root.elements.length == 3 &&
        root.elements[2] is asn1lib.ASN1OctetString) {
      der = (root.elements[2] as asn1lib.ASN1OctetString).octets;
      root = asn1lib.ASN1Parser(der).nextObject() as asn1lib.ASN1Sequence;
    }
    final fields = root.elements.cast<asn1lib.ASN1Integer>();
    if (fields.length < 9) throw FormatException('Malformed RSA private key');
    final n = fields[1].valueAsBigInteger;
    final e = fields[2].valueAsBigInteger;
    final d = fields[3].valueAsBigInteger;
    final p = fields[4].valueAsBigInteger;
    final q = fields[5].valueAsBigInteger;
    return ForgeRsaPrivateKey(n, d, p, q, publicExponent: e);
  }
}

class ForgeBinary {
  ForgeBinary(this.bytes);
  final String bytes;
  String getBytes() => bytes;
}

ForgeRsaPublicKey _parseSubjectPublicKeyInfo(asn1lib.ASN1Sequence spki) {
  final bitString = spki.elements[1] as asn1lib.ASN1BitString;
  final rsa =
      asn1lib.ASN1Parser(Uint8List.fromList(bitString.stringValue)).nextObject()
          as asn1lib.ASN1Sequence;
  return ForgeRsaPublicKey(
    (rsa.elements[0] as asn1lib.ASN1Integer).valueAsBigInteger,
    (rsa.elements[1] as asn1lib.ASN1Integer).valueAsBigInteger,
  );
}

ForgeAsn1 _subjectPublicKeyInfo(ForgeRsaPublicKey key) =>
    ForgeAsn1(0, 16, true, [
      _algorithmIdentifier(forge.pki.oids.rsaEncryption, includeNull: true),
      ForgeAsn1(0, 3, false, '\x00${_binary(_rsaPublicKeyAsn1(key).encode())}'),
    ]);

ForgeAsn1 _rsaPublicKeyAsn1(ForgeRsaPublicKey key) =>
    ForgeAsn1(0, 16, true, [_integerAsn1(key.n), _integerAsn1(key.e)]);

Uint8List _rsaPrivateKeyDer(ForgeRsaPrivateKey key) {
  final dp = key.d % (key.p - BigInt.one);
  final dq = key.d % (key.q - BigInt.one);
  final qi = key.q.modInverse(key.p);
  final der = ForgeAsn1(0, 16, true, [
    _integerAsn1(BigInt.zero),
    _integerAsn1(key.n),
    _integerAsn1(key.e),
    _integerAsn1(key.d),
    _integerAsn1(key.p),
    _integerAsn1(key.q),
    _integerAsn1(dp),
    _integerAsn1(dq),
    _integerAsn1(qi),
  ]).encode();
  return Uint8List.fromList(der);
}

ForgeAsn1 _algorithmIdentifier(String oid, {bool includeNull = false}) =>
    ForgeAsn1(0, 16, true, [
      ForgeAsn1(0, 6, false, _binary(_oidContents(oid))),
      if (includeNull || oid == forge.pki.oids.sha256WithRSAEncryption)
        ForgeAsn1(0, 5, false, ''),
    ]);

ForgeAsn1 _extensionAsn1(Map<String, dynamic> ext) {
  final oid =
      (ext['id'] as String?) ??
      _extensionOidForName(ext['name'] as String? ?? '');
  final encodedValue = _extensionValue(ext).encode();
  return ForgeAsn1(0, 16, true, [
    ForgeAsn1(0, 6, false, _binary(_oidContents(oid))),
    if (ext['critical'] == true) ForgeAsn1(0, 1, false, '\xff'),
    ForgeAsn1(0, 4, false, _binary(encodedValue)),
  ]);
}

ForgeAsn1 _extensionValue(Map<String, dynamic> ext) {
  final name = ext['name'] as String?;
  switch (name) {
    case 'basicConstraints':
      return ForgeAsn1(0, 16, true, [
        if (ext['cA'] == true) ForgeAsn1(0, 1, false, '\xff'),
        if (ext['pathLenConstraint'] != null)
          _integerAsn1(BigInt.from(ext['pathLenConstraint'] as int)),
      ]);
    case 'keyUsage':
      final names = [
        'digitalSignature',
        'nonRepudiation',
        'keyEncipherment',
        'dataEncipherment',
        'keyAgreement',
        'keyCertSign',
        'cRLSign',
        'encipherOnly',
        'decipherOnly',
      ];
      final selected = <int>[
        for (var i = 0; i < names.length; i++)
          if (ext[names[i]] == true) i,
      ];
      final last = selected.isEmpty ? 0 : selected.last;
      final bytes = List<int>.filled((last ~/ 8) + 1, 0);
      for (final bit in selected) {
        bytes[bit ~/ 8] |= 1 << (7 - bit % 8);
      }
      final unused = selected.isEmpty ? 7 : (7 - last % 8);
      return ForgeAsn1(0, 3, false, _binary([unused, ...bytes]));
    case 'extKeyUsage':
      final usages = <String, String>{
        'serverAuth': '1.3.6.1.5.5.7.3.1',
        'clientAuth': '1.3.6.1.5.5.7.3.2',
        'codeSigning': '1.3.6.1.5.5.7.3.3',
      };
      return ForgeAsn1(0, 16, true, [
        for (final entry in usages.entries)
          if (ext[entry.key] == true)
            ForgeAsn1(0, 6, false, _binary(_oidContents(entry.value))),
      ]);
    case 'subjectAltName':
      return ForgeAsn1(0, 16, true, [
        for (final alt in (ext['altNames'] as List<dynamic>? ?? []))
          _generalName(Map<String, dynamic>.from(alt as Map)),
      ]);
    case 'subjectKeyIdentifier':
      final bytes = ext['subjectKeyIdentifier'] is String
          ? forge.util.hexToBytes(ext['subjectKeyIdentifier'] as String)
          : '';
      return ForgeAsn1(0, 4, false, bytes);
    case 'authorityKeyIdentifier':
      final raw = ext['keyIdentifier'] as String? ?? '';
      return ForgeAsn1(0, 16, true, [
        ForgeAsn1(forge.asn1.Class.CONTEXT_SPECIFIC, 0, false, raw),
      ]);
    case 'cRLDistributionPoints':
      return ForgeAsn1(0, 16, true, [
        for (final alt in (ext['altNames'] as List<dynamic>? ?? []))
          ForgeAsn1(0, 16, true, [
            ForgeAsn1(forge.asn1.Class.CONTEXT_SPECIFIC, 0, true, [
              ForgeAsn1(forge.asn1.Class.CONTEXT_SPECIFIC, 0, true, [
                _generalName(Map<String, dynamic>.from(alt as Map)),
              ]),
            ]),
          ]),
      ]);
    default:
      throw UnsupportedError(
        'node-forge extension ${name ?? ext['id']} is not implemented',
      );
  }
}

ForgeAsn1 _generalName(Map<String, dynamic> alt) {
  final type = alt['type'] as int;
  if (type == 7) {
    final address = alt['ip'] as String? ?? alt['value'] as String? ?? '';
    final bytes = _ipAddressBytes(address);
    return ForgeAsn1(
      forge.asn1.Class.CONTEXT_SPECIFIC,
      7,
      false,
      _binary(bytes),
    );
  }
  final value = alt['value'] as String? ?? '';
  return ForgeAsn1(forge.asn1.Class.CONTEXT_SPECIFIC, type, false, value);
}

ForgeAsn1 _nameAsn1(List<Map<String, String>> attrs) {
  final oidForName = <String, String>{
    'commonName': '2.5.4.3',
    'organizationName': '2.5.4.10',
    'organizationalUnitName': '2.5.4.11',
    'countryName': '2.5.4.6',
    'stateOrProvinceName': '2.5.4.8',
    'localityName': '2.5.4.7',
    'emailAddress': '1.2.840.113549.1.9.1',
  };
  return ForgeAsn1(0, 16, true, [
    for (final attr in attrs)
      ForgeAsn1(0, 17, true, [
        ForgeAsn1(0, 16, true, [
          ForgeAsn1(
            0,
            6,
            false,
            _binary(
              _oidContents(
                attr['oid'] ?? oidForName[attr['name']] ?? '2.5.4.3',
              ),
            ),
          ),
          // node-forge _dnToAsn1: valueTagClass defaults to PRINTABLESTRING;
          // UTF8 values are UTF-8 encoded, others are binary strings.
          ForgeAsn1(
            0,
            int.tryParse(attr['valueTagClass'] ?? '') ?? 19,
            false,
            attr['valueTagClass'] == '12'
                ? _binary(utf8.encode(attr['value'] ?? ''))
                : attr['value'] ?? '',
          ),
        ]),
      ]),
  ]);
}

ForgeAsn1 _integerAsn1(BigInt value) =>
    ForgeAsn1(0, 2, false, _binary(_bigIntBytes(value)));

ForgeAsn1 _asn1Time(DateTime date) => date.toUtc().year < 2050
    ? ForgeAsn1(0, 23, false, forge.asn1.dateToUtcTime(date))
    : ForgeAsn1(0, 24, false, forge.asn1.dateToGeneralizedTime(date));

String _extensionOidForName(String name) => switch (name) {
  'basicConstraints' => '2.5.29.19',
  'keyUsage' => '2.5.29.15',
  'extKeyUsage' => '2.5.29.37',
  'subjectAltName' => '2.5.29.17',
  'subjectKeyIdentifier' => '2.5.29.14',
  'authorityKeyIdentifier' => '2.5.29.35',
  'cRLDistributionPoints' => '2.5.29.31',
  _ => name,
};

Map<String, dynamic> _parseExtension(String oid, bool critical, List<int> raw) {
  final name = switch (oid) {
    '2.5.29.19' => 'basicConstraints',
    '2.5.29.15' => 'keyUsage',
    '2.5.29.37' => 'extKeyUsage',
    '2.5.29.17' => 'subjectAltName',
    '2.5.29.14' => 'subjectKeyIdentifier',
    '2.5.29.35' => 'authorityKeyIdentifier',
    '2.5.29.31' => 'cRLDistributionPoints',
    _ => oid,
  };
  final result = <String, dynamic>{
    'id': oid,
    'name': name,
    'critical': critical,
  };
  try {
    final der = asn1lib.ASN1Parser(Uint8List.fromList(raw)).nextObject();
    if (name == 'subjectKeyIdentifier' && der is asn1lib.ASN1OctetString) {
      result['subjectKeyIdentifier'] = der.octets
          .map((b) => b.toRadixString(16).padLeft(2, '0'))
          .join();
    } else if (name == 'authorityKeyIdentifier' &&
        der is asn1lib.ASN1Sequence) {
      for (final child in der.elements) {
        if (child.tag == 0x80) {
          result['keyIdentifier'] = _binary(child.valueBytes());
        }
      }
    } else if (name == 'cRLDistributionPoints') {
      result['value'] = _binary(raw);
    } else if (name == 'subjectAltName' && der is asn1lib.ASN1Sequence) {
      result['altNames'] = [
        for (final child in der.elements)
          if (child.tag == 0x82)
            {'type': 2, 'value': ascii.decode(child.valueBytes())}
          else if (child.tag == 0x87)
            {'type': 7, 'ip': _ipString(child.valueBytes())},
      ];
    } else if (name == 'basicConstraints' && der is asn1lib.ASN1Sequence) {
      for (final child in der.elements) {
        if (child is asn1lib.ASN1Boolean) result['cA'] = child.booleanValue;
      }
    } else if (name == 'keyUsage' && der is asn1lib.ASN1BitString) {
      final labels = [
        'digitalSignature',
        'nonRepudiation',
        'keyEncipherment',
        'dataEncipherment',
        'keyAgreement',
        'keyCertSign',
        'cRLSign',
        'encipherOnly',
        'decipherOnly',
      ];
      for (var i = 0; i < labels.length; i++) {
        final byte = i ~/ 8 < der.stringValue.length
            ? der.stringValue[i ~/ 8]
            : 0;
        result[labels[i]] = (byte & (1 << (7 - i % 8))) != 0;
      }
    }
  } catch (_) {
    // Unknown/unsupported extension contents remain accessible as raw bytes.
  }
  return result;
}

ForgeDistinguishedName _parseName(asn1lib.ASN1Sequence name) {
  const names = {
    '2.5.4.3': 'commonName',
    '2.5.4.10': 'organizationName',
    '2.5.4.11': 'organizationalUnitName',
    '2.5.4.6': 'countryName',
    '2.5.4.8': 'stateOrProvinceName',
    '2.5.4.7': 'localityName',
    '1.2.840.113549.1.9.1': 'emailAddress',
  };
  final attrs = <Map<String, String>>[];
  for (final rdn in name.elements.cast<asn1lib.ASN1Set>()) {
    for (final entry in rdn.elements.cast<asn1lib.ASN1Sequence>()) {
      final oid =
          (entry.elements[0] as asn1lib.ASN1ObjectIdentifier).identifier!;
      final valueObject = entry.elements[1];
      // node-forge keeps the parsed tag as valueTagClass and decodes only
      // UTF8String values; other string types stay binary strings.
      final tag = valueObject.tag & 0x1f;
      final bytes = valueObject.valueBytes();
      final value = tag == 12
          ? utf8.decode(bytes, allowMalformed: true)
          : _binary(bytes);
      attrs.add({
        'name': names[oid] ?? oid,
        'oid': oid,
        'value': value,
        'valueTagClass': '$tag',
      });
    }
  }
  return ForgeDistinguishedName(attrs);
}

DateTime _parseTime(asn1lib.ASN1Object value) {
  if (value is asn1lib.ASN1UtcTime) return value.dateTimeValue.toUtc();
  if (value is asn1lib.ASN1GeneralizedTime) return value.dateTimeValue.toUtc();
  throw FormatException('Unsupported X.509 validity time tag ${value.tag}');
}

Map<String, String> _normalizeAttribute(Map<String, dynamic> source) {
  final value = source['value'];
  return {
    if (source['name'] != null) 'name': source['name'].toString(),
    if (source['oid'] != null) 'oid': source['oid'].toString(),
    'value': value?.toString() ?? '',
    if (source['valueTagClass'] != null)
      'valueTagClass': source['valueTagClass'].toString(),
  };
}

List<int> _oidContents(String oid) {
  final parts = oid.split('.').map(int.parse).toList();
  if (parts.length < 2 || parts[0] > 2 || (parts[0] < 2 && parts[1] > 39)) {
    throw FormatException('Invalid OID $oid');
  }
  final output = <int>[];
  void append(int value) {
    final digits = <int>[value & 0x7f];
    value >>= 7;
    while (value > 0) {
      digits.insert(0, (value & 0x7f) | 0x80);
      value >>= 7;
    }
    output.addAll(digits);
  }

  append(parts[0] * 40 + parts[1]);
  for (final component in parts.skip(2)) {
    append(component);
  }
  return output;
}

List<int> _derTlv(int tag, List<int> content) => [
  tag,
  ..._derLength(content.length),
  ...content,
];

List<int> _derLength(int length) {
  if (length < 128) return [length];
  final bytes = <int>[];
  var remaining = length;
  while (remaining > 0) {
    bytes.insert(0, remaining & 0xff);
    remaining >>= 8;
  }
  return [0x80 | bytes.length, ...bytes];
}

List<int> _bigIntBytes(BigInt value) {
  if (value < BigInt.zero) {
    throw ArgumentError('Negative ASN.1 INTEGER unsupported');
  }
  if (value == BigInt.zero) return [0];
  final bytes = <int>[];
  var current = value;
  while (current > BigInt.zero) {
    bytes.insert(0, (current & BigInt.from(255)).toInt());
    current >>= 8;
  }
  if ((bytes.first & 0x80) != 0) bytes.insert(0, 0);
  return bytes;
}

String _bigIntHex(BigInt value) => value.toRadixString(16).padLeft(2, '0');

String _pem(String type, List<int> der) {
  final encoded = base64.encode(der);
  final lines = [
    for (var i = 0; i < encoded.length; i += 64)
      encoded.substring(i, min(i + 64, encoded.length)),
  ];
  // forge.pem.encode: CRLF line endings, 64-column body.
  return '-----BEGIN $type-----\r\n${lines.join('\r\n')}\r\n'
      '-----END $type-----\r\n';
}

List<int> _ipAddressBytes(String address) {
  final ipv4 = _parseIpv4(address);
  if (ipv4 != null) return ipv4;
  var noZone = address.split('%').first;
  if (!noZone.contains(':')) {
    throw FormatException('Invalid IP address $address');
  }
  if (noZone.contains('.')) {
    final colon = noZone.lastIndexOf(':');
    final ipv4Tail = _parseIpv4(noZone.substring(colon + 1));
    if (colon < 0 || ipv4Tail == null) {
      throw FormatException('Invalid IP address $address');
    }
    final first = (ipv4Tail[0] << 8) | ipv4Tail[1];
    final second = (ipv4Tail[2] << 8) | ipv4Tail[3];
    noZone =
        '${noZone.substring(0, colon + 1)}'
        '${first.toRadixString(16)}:${second.toRadixString(16)}';
  }
  var sides = noZone.split('::');
  if (sides.length > 2) throw FormatException('Invalid IP address $address');
  final left = sides[0].isEmpty ? <String>[] : sides[0].split(':');
  final right = sides.length == 1 || sides[1].isEmpty
      ? <String>[]
      : sides[1].split(':');
  final groups = [...left, ...right];
  if (groups.any((g) => !RegExp(r'^[0-9a-fA-F]{1,4}$').hasMatch(g))) {
    throw FormatException('Invalid IP address $address');
  }
  final fill = sides.length == 1 ? 0 : 8 - groups.length;
  final all = [...left, ...List<String>.filled(fill, '0'), ...right];
  if (all.length != 8) throw FormatException('Invalid IP address $address');
  return [
    for (final group in all) ...[
      (int.parse(group, radix: 16) >> 8) & 0xff,
      int.parse(group, radix: 16) & 0xff,
    ],
  ];
}

List<int>? _parseIpv4(String address) {
  if (!RegExp(
    r'^(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$',
  ).hasMatch(address)) {
    return null;
  }
  return address.split('.').map(int.parse).toList();
}

String _ipString(List<int> bytes) {
  if (bytes.length == 4) return bytes.join('.');
  if (bytes.length != 16) return _binary(bytes);
  final groups = [
    for (var i = 0; i < 16; i += 2) (bytes[i] << 8) | bytes[i + 1],
  ];
  return groups.map((g) => g.toRadixString(16)).join(':');
}

List<int> _binaryBytes(String value) =>
    value.codeUnits.map((c) => c & 0xff).toList();
String _binary(Iterable<int> bytes) =>
    String.fromCharCodes(bytes.map((b) => b & 0xff));
