/* © 2016-2018 FlowCrypt Limited. Limitations apply. Contact human@flowcrypcom */

'use strict';

import { Catch } from './platform/catch.js';
import { Store, SubscriptionAttempt, GlobalStore, Subscription } from './platform/store.js';
import { Api } from './api/api.js';
import { Env } from './browser.js';
import { Google } from './api/google.js';
import { Buf } from './core/buf.js';
import { Backend } from './api/backend.js';

type AccountEventHandlersOptional = {
  renderStatusText?: (text: string, showSpinner?: boolean) => void;
  findMatchingTokensFromEmail?: (acctEmail: string, uuid: string) => Promise<string[] | undefined>;
};
type AccountEventHandlers = {
  renderStatusText: (text: string, showSpinner?: boolean) => void;
  findMatchingTokensFromEmail: (acctEmail: string, uuid: string) => Promise<string[] | undefined>;
};

export type PaymentMethod = 'stripe' | 'group' | 'trial';
export type ProductLevel = 'pro' | null;
export type ProductName = 'null' | 'trial' | 'advancedMonthly';
export type Product = { id: null | string, method: null | PaymentMethod, name: null | string, level: ProductLevel };

export class CheckVerificationEmail extends Error { }

export class FcAcct {

  PRODUCTS: { [productName in ProductName]: Product } = {
    null: { id: null, method: null, name: null, level: null }, // tslint:disable-line:no-null-keyword
    trial: { id: 'free_month', method: 'trial', name: 'trial', level: 'pro' },
    advancedMonthly: { id: 'cu-adv-month', method: 'stripe', name: 'advanced_monthly', level: 'pro' },
  };

  private canReadEmail: boolean;
  private cryptupVerificationEmailSender = 'verify@cryptup.org';
  private eventHandlers: AccountEventHandlers;

  constructor(handlers: AccountEventHandlersOptional, canReadEmail: boolean) {
    this.eventHandlers = {
      renderStatusText: handlers.renderStatusText || ((text: string, showSpinner?: boolean) => undefined),
      findMatchingTokensFromEmail: handlers.findMatchingTokensFromEmail || this.fetchTokenEmailsOnGmailAndFindMatchingToken,
    };
    this.canReadEmail = canReadEmail;
  }

  subscribe = async (acctEmail: string, chosenProduct: Product, source: string | undefined) => {
    this.eventHandlers.renderStatusText(chosenProduct.method === 'trial' ? 'enabling trial..' : 'upgrading..', true);
    await Backend.accountCheckSync();
    try {
      const newSubscriptionInfo = await this.doSubscribe(chosenProduct, source);
      const globalStoreUpdate: GlobalStore = {};
      Subscription.updateSubscriptionGlobalStore(globalStoreUpdate, await Store.subscription(), newSubscriptionInfo);
      if (Object.keys(globalStoreUpdate).length) {
        await Store.setGlobal(globalStoreUpdate);
      }
      return newSubscriptionInfo;
    } catch (e) {
      if (Api.err.isAuthErr(e)) {
        await this.saveSubscriptionAttempt(chosenProduct, undefined);
        await this.register(acctEmail);
        return await this.doSubscribe(chosenProduct, source);
      }
      throw e;
    }
  }

  register = async (acctEmail: string) => { // register_and_attempt_to_verify
    this.eventHandlers.renderStatusText('registering..', true);
    const response = await Backend.accountLogin(acctEmail);
    if (response.verified) {
      return response;
    }
    if (this.canReadEmail) {
      this.eventHandlers.renderStatusText('verifying..', true);
      const tokens = await this.waitForTokenEmail(30);
      if (tokens && tokens.length) {
        return await this.verify(acctEmail, tokens);
      } else {
        throw new CheckVerificationEmail(`Please check your inbox (${acctEmail}) for a verification email`);
      }
    } else {
      throw new CheckVerificationEmail(`Please check your inbox (${acctEmail}) for a verification email`);
    }
  }

  verify = async (acctEmail: string, tokens: string[]) => {
    this.eventHandlers.renderStatusText('verifying your email address..', true);
    let lastTokenErr;
    for (const token of tokens) {
      try {
        return await Backend.accountLogin(acctEmail, token);
      } catch (e) {
        if (Api.err.isStandardErr(e, 'token')) {
          lastTokenErr = e;
        } else {
          throw e;
        }
      }
    }
    throw lastTokenErr;
  }

  registerNewDevice = async (acctEmail: string) => {
    await Store.setGlobal({ cryptup_account_uuid: undefined });
    this.eventHandlers.renderStatusText('checking..', true);
    return await this.register(acctEmail);
  }

  saveSubscriptionAttempt = async (product: Product, source: string | undefined) => {
    (product as any as SubscriptionAttempt).source = source;
    await Store.setGlobal({ 'cryptup_subscription_attempt': product as any as SubscriptionAttempt });
  }

  parseTokenEmailText = (verifEmailText: string, storedUuidToCrossCheck?: string): string | undefined => {
    const tokenLinkMatch = verifEmailText.match(/account\/login?([^\s"<]+)/g);
    if (tokenLinkMatch) {
      const tokenLinkParams = Env.urlParams(['account', 'uuid', 'token'], tokenLinkMatch[0].split('?')[1]);
      if ((!storedUuidToCrossCheck || tokenLinkParams.uuid === storedUuidToCrossCheck) && tokenLinkParams.token) {
        return String(tokenLinkParams.token);
      }
    }
    return undefined;
  }

  private doSubscribe = async (chosenProduct: Product, source?: string) => {
    await Store.removeGlobal(['cryptup_subscription_attempt']);
    // todo - deal with auth error? would need to know account_email for new registration
    const response = await Backend.accountSubscribe(chosenProduct.id!, chosenProduct.method!, source);
    if (response.subscription.level === chosenProduct.level && response.subscription.method === chosenProduct.method) {
      return response.subscription;
    }
    throw new Error('Something went wrong when upgrading (values don\'t match), please email human@flowcrypt.com to get this resolved.');
  }

  private fetchTokenEmailsOnGmailAndFindMatchingToken = async (acctEmail: string, uuid: string): Promise<string[] | undefined> => {
    const tokens: string[] = [];
    const response = await Google.gmail.msgList(acctEmail, 'from:' + this.cryptupVerificationEmailSender + ' to:' + acctEmail + ' in:anywhere', true);
    if (!response.messages) {
      return undefined;
    }
    const msgs = await Google.gmail.msgsGet(acctEmail, response.messages.map(m => m.id), 'full');
    for (const gmailMsg of msgs) {
      if (gmailMsg.payload.mimeType === 'text/plain' && gmailMsg.payload.body && gmailMsg.payload.body.size > 0 && gmailMsg.payload.body.data) {
        const token = this.parseTokenEmailText(Buf.fromBase64UrlStr(gmailMsg.payload.body.data).toUtfStr(), uuid);
        if (token && typeof token === 'string') {
          tokens.push(token);
        }
      }
    }
    tokens.reverse(); // most recent first
    return tokens.length ? tokens : undefined;
  }

  private sleep(seconds: number) {
    return new Promise(resolve => Catch.setHandledTimeout(resolve, seconds * 1000));
  }

  private waitForTokenEmail = async (timeout: number) => {
    const end = Date.now() + timeout * 1000;
    while (Date.now() < end) {
      if ((end - Date.now()) < 20000) { // 20s left
        this.eventHandlers.renderStatusText('Still working..');
      } else if ((end - Date.now()) < 10000) { // 10s left
        this.eventHandlers.renderStatusText('A little while more..');
      }
      const authInfo = await Store.authInfo();
      const tokens = await this.eventHandlers.findMatchingTokensFromEmail(authInfo.acctEmail!, authInfo.uuid!);
      if (tokens) {
        return tokens;
      } else {
        await this.sleep(5);
      }
    }
    return undefined;
  }

}
