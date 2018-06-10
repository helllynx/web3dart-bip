import 'dart:math';

import 'package:test/test.dart';
import 'package:web3dart/src/mnemonic/mnemonic.dart';
import 'package:web3dart/src/utils/dartrandom.dart';

void main() {
  test("Mnemonic List Word Loading Test", () {
    var mnemonicList = MnemonicUtils.populateWordList();

    mnemonicList.forEach((word) => print(word));


  });

  test("Generate Mnemonic List", () {
    Random random = new Random.secure();
    var mnemonic = MnemonicUtils.generateMnemonic(new DartRandom(random).nextBytes(32));

   print(mnemonic);


  });
}
