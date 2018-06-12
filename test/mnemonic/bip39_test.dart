import 'package:test/test.dart';
import 'package:web3dart/src/bip39/hdkey.dart';
import 'package:web3dart/src/bip39/mnemonic.dart';
import 'package:web3dart/src/bip39/utils.dart';
import 'package:web3dart/src/utils/credentials.dart';
import 'package:web3dart/src/utils/numbers.dart';

void main() {
  /*test("Mnemonic List Word Loading Test", () {
    var mnemonicWordList = MnemonicUtils.populateWordList();
    expect(mnemonicWordList.isNotEmpty, true);
  });

  test("Generate Mnemonic List", () {
    Random random = new Random.secure();
    var mnemonic =
        MnemonicUtils.generateMnemonic(new DartRandom(random).nextBytes(32));

    expect(mnemonic.isNotEmpty, true);
  });*/

  test(
      "Generate Master Seed From Known Mnemonic List Compare With Pre-Known Seed",
      () {
    var seed = MnemonicUtils.generateMasterSeed(
        "uniform snow notice device spring universe source pulp road meadow slow kind hurry silly crowd",
        "");

    var masterSeedHex = bytesToHex(seed);

    expect(masterSeedHex,
        "bada2b2d32593027a42e37bc42196faec8d7a7ecea7ecddbf9cf5ef4bf2e18073bad102048e1a4ae30d0f767822377d13bde1e05f0300f3f7c93e62e279f257e");
  });

/*  test("Generate Master Seed With Passphrase", () {
    var seed = MnemonicUtils.generateMasterSeed(
        "cram vacuum rebuild assault cruise fit dinner asthma crew social unique keen turtle display autumn",
        "passw0rd");

    var masterSeedHex = bytesToHex(seed);

    expect(masterSeedHex,
        "004c3148612fb6329be0000971df301f6fbe002a0099f31c043b4b2678ce02aec806f470052b7b1822032bce2871fc3b989bebd2cfcf54a5687137b25753f533");
  });*/

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

//  test("Generate Path Early Tests", () {
//    var seed = MnemonicUtils.generateMasterSeed(
//        "earn only broken federal uniform delay frozen faith usual kit fluid degree omit work recipe song jeans decide auction evolve skull public vivid rotate",
//        "");
//    Uint8List extendedPrivateKey = MnemonicUtils.getRootSeed(seed);
//    var privk = CKDprivHardened(extendedPrivateKey, 19).first;
//    print(bytesToHex(privk));
//  });

//  test("Child Private Key Derivation Test ", () {
//    var data =
//        "003C6CB8D0F6A264C91EA8B5030FADAA8E538B020F0A387421A12DE9319DC9336880000002";
//    var parentPrivateKeyHex =
//        "003C6CB8D0F6A264C91EA8B5030FADAA8E538B020F0A387421A12DE9319DC93368";
//    Uint8List hmac = hmacSha512(
//      hexToBytes(data),
//      hexToBytes(
//          "2A7857631386BA23DACAC34180DD1983734E444FDBF774041578E9B6ADB37C19"),
//    );
//
//    print("hmac: ${ bytesToHex(hmac) }");
//
//    var leftSideHash = new Uint8List(32);
//    List.copyRange(leftSideHash, 0, hmac, 0, 32);
//
//    BigInt cprivk = bytesToInt(leftSideHash) +
//        BigInt.parse(parentPrivateKeyHex, radix: 16) %
//            new ECCurve_secp256k1().n;
//
//    print("Addition: ${ bytesToHex(leftSideHash) } + ${parentPrivateKeyHex}");
//
//    print("cprivk: ${ cprivk
//        .toRadixString(16) }");
//
//    var cpubk = Credentials
//        .fromHexPrivateKey("ca2a7395e1886a34f846b6ed06f00515aa223b8252fbd9989aa0012d1a46f5f1")
//        .publicKey
//        .toRadixString(16);
//

  /*test("Child Private Key Hardened Derivation Test", () {


    var rootSeed = getRootSeed(hexToBytes("bada2b2d32593027a42e37bc42196faec8d7a7ecea7ecddbf9cf5ef4bf2e18073bad102048e1a4ae30d0f767822377d13bde1e05f0300f3f7c93e62e279f257e"));



    print("Root Seed: ${ bytesToHex(rootSeed) }");



    var childPrivateKeyHardened = CKDprivHardened(
      rootSeed,
      0,
    )[0];



    var childChainCode = CKDprivHardened(
      rootSeed,
      0,
    )[1];

    var cprivkHardHex = bytesToHex(childPrivateKeyHardened);
    var publicKey = Credentials.fromHexPrivateKey(cprivkHardHex).publicKey.toRadixString(16);
    var address = Credentials.fromHexPrivateKey(cprivkHardHex).addressHex;
    var chainCodeHex = bytesToHex(childChainCode);



    print("Private Key: ${cprivkHardHex} \nPublic Key: ${publicKey} \nAddress: ${address} \nChainCode: ${chainCodeHex}");




    expect(address,
        "0xdc04c29a3ce6c09edf7b3b38ae3f39413148a8ba");
  });*/

  test("Child Private Key Non Hardened Derivation Test", () {
    var rootSeed = getRootSeed(hexToBytes(
        "271ef7ac032bb8a313e2d3339ac6bc308bd984de98c6095767b7496a517708d6ade22355e0415e771a732e3db45fe3e15da7ad7550cda08787b3902a1d092e15"));

    print("Root Seed: ${ bytesToHex(rootSeed) }");

    var childPrivateKeyHardened = CKDprivNonHardened(
      rootSeed,
      0,
    )[0];

    var childChainCode = CKDprivNonHardened(
      rootSeed,
      0,
    )[1];

    var cprivkHardHex = bytesToHex(childPrivateKeyHardened);
    var publicKey = Credentials
        .fromHexPrivateKey(cprivkHardHex)
        .publicKey
        .toRadixString(16);
    var address = Credentials.fromHexPrivateKey(cprivkHardHex).addressHex;
    var chainCodeHex = bytesToHex(childChainCode);

    print(
        "Private Key: ${cprivkHardHex} \nPublic Key: ${publicKey} \nAddress: ${address} \nChainCode: ${chainCodeHex}");

    expect(address,
        "0x81e873d1be33d0e4b044d5c0ebeb27834ddea944");
//
  });




  /*test("Public key compression", () {
    var pubk =
        "04"+"a563d19906ea9208d6e6879cab449646571420f7ce2236890fdd71f73eadc75e64c540ad3ddf64b379d7a56f4baa16a83a7957db2c6f4243ada01a45bef39852";

    var pubKeyCompr = (getCompressedPubKey((pubk)));

    print("\n${pubKeyCompr}");
  });

  print("RAND PUB : ${Credentials.generateNew().publicKey.toRadixString(16)}");*/
}
