/* © 2016-2018 FlowCrypt Limited. Limitations apply. Contact human@flowcrypt.com */

'use strict';

import { Catch } from '../common/platform/catch.js';
import { Store } from '../common/platform/store.js';
import { Value, Str } from '../common/core/common.js';
import { Api } from '../common/api/api.js';
import { Pgp } from '../common/core/pgp.js';
import { Attester } from '../common/api/attester.js';
import { Backend } from '../common/api/backend.js';

export const migrateGlobal = async () => {
  if (window.localStorage && window.localStorage.length > 0) { // window.localStorage may be null on Firefox, likely disabled in settings?
    // a very long time ago, this extension used to store values in localStorage
    // for a very long time, there used to be a procedure to migrate this localStorage into current form of storage
    // not anymore. users who had this extension disabled the whole time and now re-enabled will have to set it up again
    window.localStorage.clear();
  }
  // some emails in storage were not lowercased due to a bug around Oct 2018, this should be kept here until Feb 2019
  const acctEmails = await Store.acctEmailsGet();
  const lowerCasedAcctEmails = acctEmails.map(e => e.toLowerCase());
  if (acctEmails.join() !== lowerCasedAcctEmails.join()) {
    await Store.setGlobal({ account_emails: JSON.stringify(lowerCasedAcctEmails) });
  }
  // update local info about keyserver status of user keys
  updateAcctInfo(acctEmails).catch(reportSignificantErrs);
};

const updateAcctInfo = async (acctEmails: string[]) => {
  for (const acctEmail of acctEmails) {
    await accountUpdateStatusKeyserver(acctEmail);
  }
};

const accountUpdateStatusKeyserver = async (acctEmail: string) => { // checks which emails were registered on Attester
  const keyinfos = await Store.keysGet(acctEmail);
  const myLongids = keyinfos.map(ki => ki.longid);
  const storage = await Store.getAcct(acctEmail, ['addresses', 'addresses_keyserver']);
  if (storage.addresses && storage.addresses.length) {
    const unique = Value.arr.unique(storage.addresses.map(a => a.toLowerCase().trim())).filter(a => a && Str.isEmailValid(a));
    if (unique.length < storage.addresses.length) {
      storage.addresses = unique;
      await Store.setAcct(acctEmail, storage); // fix duplicate email addresses
    }
    try {
      const lookupEmailsRes = await Attester.lookupEmails(storage.addresses);
      const addressesKeyserver = [];
      for (const email of Object.keys(lookupEmailsRes)) {
        const result = lookupEmailsRes[email];
        if (result && result.pubkey && myLongids.includes(String(await Pgp.key.longid(result.pubkey)))) {
          addressesKeyserver.push(email);
        }
      }
      await Store.setAcct(acctEmail, { addresses_keyserver: addressesKeyserver });
    } catch (e) {
      reportSignificantErrs(e);
    }
  }
};

const reportSignificantErrs = (e: any) => {
  if (Api.err.isSignificant(e)) {
    Catch.reportErr(e);
  }
};

export const scheduleFcSubscriptionLevelCheck = (bgProcessStartReason: 'update' | 'chrome_update' | 'browser_start' | string) => {
  Catch.setHandledTimeout(() => {
    if (bgProcessStartReason === 'update' || bgProcessStartReason === 'chrome_update') {
      // update may happen to too many people at the same time -- server overload
      Catch.setHandledTimeout(() => Backend.accountCheckSync().catch(reportSignificantErrs), Value.int.hoursAsMiliseconds(Math.random() * 3)); // random 0-3 hours
    } else {
      // the user just installed the plugin or started their browser, no risk of overloading servers
      Backend.accountCheckSync().catch(reportSignificantErrs); // now
    }
  }, 10 * 60 * 1000); // 10 minutes
  Catch.setHandledInterval(() => Backend.accountCheckSync().catch(reportSignificantErrs), Value.int.hoursAsMiliseconds(23 + Math.random())); // random 23-24 hours
};
