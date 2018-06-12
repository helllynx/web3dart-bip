import 'dart:math';
import 'dart:typed_data';

import 'package:pointycastle/api.dart';
import 'package:pointycastle/digests/sha512.dart';
import 'package:pointycastle/ecc/curves/secp256k1.dart';
import 'package:pointycastle/macs/hmac.dart';
import 'package:web3dart/src/utils/numbers.dart';

Uint8List intToByteArray(int data) {
  Uint8List result = new Uint8List(4);

  result[0] = ((data & 0xFF000000) >> 24);
  result[1] = ((data & 0x00FF0000) >> 16);
  result[2] = ((data & 0x0000FF00) >> 8);
  result[3] = ((data & 0x000000FF) >> 0);

  return result;
}

List<Uint8List> CKDprivHardened(Uint8List extendedPrivateKey, int index) {

  var curveParamN = new ECCurve_secp256k1().n;

  Uint8List chainCodeParent = new Uint8List(32);
  Uint8List privateKeyParent = new Uint8List(32);
  List.copyRange(privateKeyParent, 0, extendedPrivateKey, 0, 32);
  List.copyRange(chainCodeParent, 0, extendedPrivateKey, 32, 64);

  int hardenedIndex = pow(2, 31) + index; // For hardened keys we add 2^31 to the index

  var indexByteArray = intToByteArray(hardenedIndex);

  final padding = new Uint8List(1);

  var data = (padding + privateKeyParent + indexByteArray);

  var dataByteArray = new Uint8List.fromList(data);

  print("Extended PrivKey Input: ${bytesToHex(extendedPrivateKey)}");


  print("Index Byte Array: ${bytesToHex(indexByteArray)}");

  print("PrivateKey Parent: ${bytesToHex(privateKeyParent)}");

  print("DataBuffer Hex: ${bytesToHex(dataByteArray)}");

  print("Data Buffer size: ${dataByteArray.length}");

  Uint8List hmacOutput = hmacSha512(dataByteArray, chainCodeParent);

  print("hMac512(${bytesToHex(dataByteArray)}, ${bytesToHex(chainCodeParent)})");
  print("HMac Output: ${bytesToHex(hmacOutput)}");



  Uint8List childChainCode = new Uint8List(32);
  Uint8List childPrivateKey = new Uint8List(32);

  Uint8List leftHandHash = new Uint8List(32);

  List.copyRange(leftHandHash, 0, hmacOutput, 0, 32);
  List.copyRange(childChainCode, 0, hmacOutput, 32, 64);

  // https://bitcoin.org/en/developer-guide#hierarchical-deterministic-key-creation
  BigInt privateKeyBigInt = (BigInt.parse(bytesToHex(privateKeyParent), radix: 16) + BigInt.parse(bytesToHex(leftHandHash), radix: 16)) % curveParamN;

//  print("Addition: ${ bytesToHex(leftHandHash) } + ${ bytesToHex(privateKeyParent)}");

  childPrivateKey = intToBytes(privateKeyBigInt);

  List<Uint8List> chainCodeKeyPair = new List<Uint8List>(2);

  chainCodeKeyPair[0] = childPrivateKey;
  chainCodeKeyPair[1] = childChainCode;

  return chainCodeKeyPair; // Hold both the child private key and the child chain code
}

Uint8List hmacSha512(List<int> seed, List<int> passphraseByteArray) {
  var hmac = new HMac(new SHA512Digest(), 128);

  var rootSeed = new Uint8List(hmac.macSize);

  hmac.init(new KeyParameter(passphraseByteArray));

  hmac.update(seed, 0, seed.length);

  hmac.doFinal(rootSeed, 0);
  return rootSeed;
}
