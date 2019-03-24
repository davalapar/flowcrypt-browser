/* © 2016-2018 FlowCrypt Limited. Limitations apply. Contact human@flowcrypt.com */

'use strict';

import { Catch } from '../../../js/common/platform/catch.js';
import { Ui, Xss } from '../../../js/common/browser.js';

declare const openpgp: typeof OpenPGP;

let naughtyStrings: string[];
$.ajax({ dataType: 'json', url: 'https://raw.githubusercontent.com/minimaxir/big-list-of-naughty-strings/master/blns.json' })
  .done((result) => {
    naughtyStrings = result; // tslint:disable:no-unsafe-any
  });

Catch.try(async () => {
  const genKey = await openpgp.generateKey({ userIds: [{ name: 'naughty_strings_test' }] });
  const prv = genKey.key;
  let testIndex: number;
  let output: string;

  $('.action_test').click(Ui.event.prevent('double', async () => {
    if (naughtyStrings === null || typeof naughtyStrings === 'undefined') { return; }
    testIndex = 1;
    output = "";
    $('pre').css("display", "block");
    for (const str of naughtyStrings) {
      try {
        const encryptedMsg = await openpgp.encrypt({ message: openpgp.message.fromText(str), publicKeys: prv.toPublic(), armor: true });
        console.log("E: ", encryptedMsg);

        const decryptedMsg = await openpgp.decrypt({ message: await openpgp.message.readArmored(encryptedMsg.data), privateKeys: prv });
        console.log("D: ", decryptedMsg);

        appendOutput(testIndex, str, decryptedMsg);
      } catch (err) {
        console.error("Failed to handle naughty string: ", err);
      }
      testIndex++;
    }
    Xss.sanitizeAppend('pre', output);
  }));

  const appendOutput = (index: number, str: string, dec: OpenPGP.DecryptMessageResult) => {
    if (str === dec.data) {
      output += Xss.escape(`[${index}] -- Success: string "${str}" was decrypted successfully \n`);
    } else {
      output += Xss.escape(`[${index}] -- Failure: string "${str}" was not decrypted \n`);
    }
  };

})();
