/* © 2016-2018 FlowCrypt Limited. Limitations apply. Contact human@flowcrypt.com */

'use strict';

import { Catch } from '../../js/common/platform/catch.js';
import { Store } from '../../js/common/platform/store.js';
import { Ui, Env } from '../../js/common/browser.js';
import { FcAcct } from '../../js/common/account.js';
import { Assert } from '../../js/common/assert.js';
import { Xss } from '../../js/common/platform/xss.js';

Catch.try(async () => {

  Ui.event.protect();

  const uncheckedUrlParams = Env.urlParams(['acctEmail', 'verificationEmailText', 'parentTabId']);
  const acctEmail = Assert.urlParamRequire.string(uncheckedUrlParams, 'acctEmail');
  const verificationEmailText = Assert.urlParamRequire.string(uncheckedUrlParams, 'verificationEmailText');

  const fcAcct = new FcAcct({}, true);
  const token = fcAcct.parseTokenEmailText(verificationEmailText);

  const renderStatus = (content: string, spinner = false) => {
    Xss.sanitizeRender('body .status', Xss.htmlSanitize(content + (spinner ? ' ' + Ui.spinner('white') : '')));
  };

  if (!token) {
    renderStatus('This verification email seems to have wrong format. Email human@flowcrypt.com to get this resolved.');
  } else {
    try {
      const { cryptup_subscription_attempt } = await Store.getGlobal(['cryptup_subscription_attempt']);
      await fcAcct.verify(acctEmail, [token]);
      if (cryptup_subscription_attempt) {
        const subscription = await fcAcct.subscribe(acctEmail, cryptup_subscription_attempt, cryptup_subscription_attempt.source);
        if (subscription && subscription.level === 'pro') {
          renderStatus('Welcome to FlowCrypt Advanced.');
        } else {
          renderStatus('Email verified, but had trouble enabling FlowCrypt Advanced. Email human@flowcrypt.com to get this resolved.');
        }
      } else {
        renderStatus('Email verified, no further action needed.');
      }
    } catch (e) {
      renderStatus(`Could not complete: ${String(e)}`);
      Catch.log('problem in verification.js', String(e));
    }
  }

})();
