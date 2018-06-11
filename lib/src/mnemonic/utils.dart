import 'dart:typed_data';

import 'package:pointycastle/api.dart';
import 'package:pointycastle/digests/sha512.dart';
import 'package:pointycastle/macs/hmac.dart';

Uint8List intToByteArray(int data) {
  Uint8List result = new Uint8List(4);

  result[0] = ((data & 0xFF000000) >> 24);
  result[1] = ((data & 0x00FF0000) >> 16);
  result[2] = ((data & 0x0000FF00) >> 8);
  result[3] = ((data & 0x000000FF) >> 0);

  return result;
}

Uint8List getExtendedPrivateKey(Uint8List extendedPrivateKey, int index) {
  var chainCodeParent = new Uint8List(32);
  var privateKeyParent = new Uint8List(32);
  List.copyRange(privateKeyParent, 0, extendedPrivateKey, 0, 32);
  List.copyRange(chainCodeParent, 0, extendedPrivateKey, 32, 64);

  print('Bit lenght: ${index.bitLength}');

  var indexByteArray = intToByteArray(index);

  int padding = 0x00;
  var data = (privateKeyParent + indexByteArray).toList(growable: true);
  data.insert(0, padding);

  var dataByteArray = new Uint8List.fromList(data);

  print("PrivateKey Parent: ${privateKeyParent}");

  print("DataBuffer Hex: ${dataByteArray}");

  print("Data Buffer size: ${dataByteArray.length}");

  var key = hmacSha512(dataByteArray, chainCodeParent);

  return key;
}

Uint8List hmacSha512(List<int> seed, List<int> passphraseByteArray) {
  var hmac = new HMac(new SHA512Digest(), 128);

  var rootSeed = new Uint8List(hmac.macSize);

  hmac.init(new KeyParameter(passphraseByteArray));

  hmac.update(seed, 0, seed.length);

  hmac.doFinal(rootSeed, 0);
  return rootSeed;
}
