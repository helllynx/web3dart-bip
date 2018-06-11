import 'dart:convert';
import 'dart:typed_data';

import 'package:pointycastle/api.dart';
import "package:pointycastle/digests/sha512.dart";
import 'package:pointycastle/macs/hmac.dart';
import 'package:test/test.dart';
import 'package:web3dart/src/mnemonic/mnemonic.dart';
import 'package:web3dart/src/utils/numbers.dart';

void main() {
//  test("Mnemonic List Word Loading Test", () {
//    var mnemonicList = MnemonicUtils.populateWordList();
//
//    mnemonicList.forEach((word) => print(word));
//
//
//  });
//
//  test("Generate Mnemonic List", () {
//    Random random = new Random.secure();
//    var mnemonic = MnemonicUtils.generateMnemonic(new DartRandom(random).nextBytes(32));
//
//   print(mnemonic);
//
//
//  });

//  test("Generate Seed", () {
//    var seed = MnemonicUtils.generateSeed(
//        "industry cram alley magnet odor crew expose flock frame relax rent diesel",
//        "");
//
//    print(bytesToHex(seed));
//  });

//  test("Generate Seed Hexadecimal", () {
//    var seedHex = MnemonicUtils.generateMasterSeedHex(
//        "earn only broken federal uniform delay frozen faith usual kit fluid degree omit work recipe song jeans decide auction evolve skull public vivid rotate",
//        "");
//
//    var seed = hexToBytes(seedHex);
//
//    print("Seed Hex: " + seedHex);
//
//    var passphrase = "Bitcoin seed";
//    var passphraseByteArray = utf8.encode(passphrase);
//
//    Uint8List rootSeed = hmacSha512(seed, passphraseByteArray);
//
//    var rootSeedHex = bytesToHex(rootSeed);
//
//    print("Root Seed Hex: $rootSeedHex | size: ${rootSeed.length}");
//    print("Root Seed Hex (0): ${rootSeed[0].toRadixString(
//        16)} |Root Seed Hex (31): ${rootSeed[31].toRadixString(16)}" +
//        "| Root Seed Hex (32): ${rootSeed[32].toRadixString(
//            16)} | Root Seed Hex (63): ${rootSeed[63].toRadixString(16)}   ");
//
//    var privateKey = new Uint8List(32);
//    var chainCode = new Uint8List(32);
//
//    List.copyRange(privateKey, 0, rootSeed, 0, 32);
//    List.copyRange(chainCode, 0, rootSeed, 32, 64);
//
//    var privateKeyHex = bytesToHex(privateKey);
//    print("Private Key Hex (${privateKey
//        .length}): ${privateKeyHex}  | Chain Code (${chainCode
//        .length}): ${bytesToHex(chainCode)}");
//
//    var publicKey = privateKeyToPublic(privateKey);
//    var publicKeyHex = bytesToHex(publicKey);
//
//    print("PublicKey Hex (L: ${publicKey.length}): $publicKeyHex ");
//  });

  test("Generate Path Early Tests", () {
    var seed = MnemonicUtils.generateMasterSeed(
        "earn only broken federal uniform delay frozen faith usual kit fluid degree omit work recipe song jeans decide auction evolve skull public vivid rotate",
        "");
    Uint8List extendedPrivateKey = MnemonicUtils.getRootSeed(seed);
    var privk = getExtendedPrivateKey(extendedPrivateKey, 0);
    print(bytesToHex(privk));
  });
}

Uint8List hmacSha512(List<int> seed, List<int> passphraseByteArray) {
  var hmac = new HMac(new SHA512Digest(), 128);

  var rootSeed = new Uint8List(hmac.macSize);

  hmac.init(new KeyParameter(passphraseByteArray));

  hmac.update(seed, 0, seed.length);

  hmac.doFinal(rootSeed, 0);
  return rootSeed;
}

Uint8List getExtendedPrivateKey(Uint8List extendedPrivateKey, int index) {
  var chainCodeParent = new Uint8List(32);
  var privateKeyParent = new Uint8List(32);
  List.copyRange(privateKeyParent, 0, extendedPrivateKey, 0, 32);
  List.copyRange(chainCodeParent, 0, extendedPrivateKey, 32, 64);


  print('Bit lenght: ${index.bitLength}');

  var indexByteArray = intToByteArray(index);


  int padding = 0x00;
  var data =  (privateKeyParent + indexByteArray).toList(growable: true);
  data.insert(0, padding);

  var dataByteArray = new Uint8List.fromList(data);

  print("PrivateKey Parent: ${privateKeyParent}");

  print("DataBuffer Hex: ${dataByteArray}");

  print("Data Buffer size: ${dataByteArray.length}");


  var key = hmacSha512(dataByteArray, chainCodeParent);

  return key;
}

Uint8List intToByteArray( int data ) {

    Uint8List result = new Uint8List(4);

    result[0] =  ((data & 0xFF000000) >> 24);
    result[1] =  ((data & 0x00FF0000) >> 16);
    result[2] =  ((data & 0x0000FF00) >> 8);
    result[3] =  ((data & 0x000000FF) >> 0);

    return result;
}

