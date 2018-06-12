import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:pointycastle/api.dart';
import 'package:pointycastle/digests/sha512.dart';
import 'package:pointycastle/ecc/curves/secp256k1.dart';
import 'package:pointycastle/macs/hmac.dart';
import 'package:web3dart/src/bip39/mnemonic.dart';
import 'package:web3dart/src/bip39/utils.dart';
import 'package:web3dart/src/utils/numbers.dart';

List<Uint8List> CKDprivHardened(Uint8List extendedPrivateKey, int index) {
  var curveParamN = new ECCurve_secp256k1().n;

  Uint8List chainCodeParent = new Uint8List(32);
  Uint8List privateKeyParent = new Uint8List(32);
  List.copyRange(privateKeyParent, 0, extendedPrivateKey, 0, 32);
  List.copyRange(chainCodeParent, 0, extendedPrivateKey, 32, 64);

  int hardenedIndex =
      pow(2, 31) + index; // For hardened keys we add 2^31 to the index

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

  print(
      "hMac512(${bytesToHex(dataByteArray)}, ${bytesToHex(chainCodeParent)})");
  print("HMac Output: ${bytesToHex(hmacOutput)}");

  Uint8List childChainCode = new Uint8List(32);
  Uint8List childPrivateKey = new Uint8List(32);

  Uint8List leftHandHash = new Uint8List(32);

  List.copyRange(leftHandHash, 0, hmacOutput, 0, 32);
  List.copyRange(childChainCode, 0, hmacOutput, 32, 64);

  // https://bitcoin.org/en/developer-guide#hierarchical-deterministic-key-creation
  BigInt privateKeyBigInt =
      (BigInt.parse(bytesToHex(privateKeyParent), radix: 16) +
              BigInt.parse(bytesToHex(leftHandHash), radix: 16)) %
          curveParamN;

//  print("Addition: ${ bytesToHex(leftHandHash) } + ${ bytesToHex(privateKeyParent)}");

  childPrivateKey = intToBytes(privateKeyBigInt);

  List<Uint8List> chainCodeKeyPair = new List<Uint8List>(2);

  chainCodeKeyPair[0] = childPrivateKey;
  chainCodeKeyPair[1] = childChainCode;

  return chainCodeKeyPair; // Hold both the child private key and the child chain code
}

List<Uint8List> CKDprivNonHardened(Uint8List extendedPrivateKey, int index) {
  var curveParamN = new ECCurve_secp256k1().n;

  Uint8List chainCodeParent = new Uint8List(32);
  Uint8List privateKeyParent = new Uint8List(32);
  List.copyRange(privateKeyParent, 0, extendedPrivateKey, 0, 32);
  List.copyRange(chainCodeParent, 0, extendedPrivateKey, 32, 64);

  int hardenedIndex = index; //

  var indexByteArray = intToByteArray(hardenedIndex);

  String publicKeyParent = bytesToHex(
      (new ECCurve_secp256k1().G * bytesToInt(privateKeyParent))
          .getEncoded(false));

  print("publicKeyParent Len: ${publicKeyParent.length} | $publicKeyParent");

  var pubKCompressed = getCompressedPubKey(publicKeyParent);

  print("=================================================================");

  print("Pubk Compressed: $pubKCompressed");

  print("=================================================================");

  var data =
      (intToBytes(BigInt.parse(pubKCompressed, radix: 16)) + indexByteArray);

  var dataByteArray = new Uint8List.fromList(data);

  print("Extended PrivKey Input: ${bytesToHex(extendedPrivateKey)}");

  print("Index Byte Array: ${bytesToHex(indexByteArray)}");

  print("PrivateKey Parent: ${bytesToHex(privateKeyParent)}");

  print("PublicKey Parent: ${(publicKeyParent)}");

  print("DataBuffer Hex: ${bytesToHex(dataByteArray)}");

  print("Data Buffer size: ${dataByteArray.length}");

  Uint8List hmacOutput = hmacSha512(dataByteArray, chainCodeParent);

  print(
      "hMac512(${bytesToHex(dataByteArray)}, ${bytesToHex(chainCodeParent)})");
  print("HMac Output: ${bytesToHex(hmacOutput)}");

  Uint8List childChainCode = new Uint8List(32);
  Uint8List childPrivateKey = new Uint8List(32);

  Uint8List leftHandHash = new Uint8List(32);

  List.copyRange(leftHandHash, 0, hmacOutput, 0, 32);
  List.copyRange(childChainCode, 0, hmacOutput, 32, 64);

  // https://bitcoin.org/en/developer-guide#hierarchical-deterministic-key-creation
  BigInt privateKeyBigInt =
      (BigInt.parse(bytesToHex(privateKeyParent), radix: 16) +
              BigInt.parse(bytesToHex(leftHandHash), radix: 16)) %
          curveParamN;

  print("Addition: ${ bytesToHex(leftHandHash) } + ${ bytesToHex(
      privateKeyParent)}");

  childPrivateKey = intToBytes(privateKeyBigInt);

  List<Uint8List> chainCodeKeyPair = new List<Uint8List>(2);

  chainCodeKeyPair[0] = childPrivateKey;
  chainCodeKeyPair[1] = childChainCode;

  return chainCodeKeyPair; // Hold both the child private key and the child chain code
}

Uint8List getMasterPrivateKey(Uint8List masterSeed) {
  Uint8List rootSeed = getRootSeed(masterSeed);

  var privateKey = new Uint8List(32);

  /// The first 256 bits are saved as Master Private Key
  List.copyRange(privateKey, 0, rootSeed, 0, 32);
  return privateKey;
}

Uint8List getMasterChainCode(Uint8List masterSeed) {
  Uint8List rootSeed = getRootSeed(masterSeed);

  var chainCode = new Uint8List(32);
  List.copyRange(chainCode, 0, rootSeed, 32, 64);

  /// The last 256 bits are saved as Master Chain code
  return chainCode;
}

Uint8List getRootSeed(Uint8List masterSeed) {
  var passphrase = "Bitcoin seed";
  var passphraseByteArray = utf8.encode(passphrase);

  var hmac = new HMac(new SHA512Digest(), 128);

  var rootSeed = new Uint8List(hmac.macSize);

  hmac.init(new KeyParameter(passphraseByteArray));

  hmac.update(masterSeed, 0, masterSeed.length);

  hmac.doFinal(rootSeed, 0);
  return rootSeed;
}

String generateMasterSeedHex(String mnemonic, String passphrase) {
  var seed = MnemonicUtils.generateMasterSeed(mnemonic, passphrase);
  return bytesToHex(seed);
}

String exportExtendedPrivKey(
    {String network,
    String depth,
    String parenFingerPrint,
    String KeyIndex,
    String chainCode,
    String Key}) {}

String exportExtendedPubKey() {}
