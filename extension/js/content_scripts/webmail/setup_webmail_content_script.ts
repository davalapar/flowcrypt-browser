/* © 2016-2018 FlowCrypt Limited. Limitations apply. Contact human@flowcrypt.com */

'use strict';

import { VERSION } from '../../common/core/const.js';
import { Catch } from '../../common/platform/catch.js';
import { Store } from '../../common/platform/store.js';
import { Injector } from '../../common/inject.js';
import { Notifications } from '../../common/notifications.js';
import { ContentScriptWindow, BrowserMsg, TabIdRequiredError, Bm } from '../../common/extension.js';
import { Ui, WebMailName, Env } from '../../common/browser.js';
import { XssSafeFactory, WebmailVariantString } from '../../common/xss_safe_factory.js';

export type WebmailVariantObject = { newDataLayer: undefined | boolean, newUi: undefined | boolean, email: undefined | string, gmailVariant: WebmailVariantString };
export type IntervalFunction = { interval: number, handler: () => void };
type WebmailSpecificInfo = {
  name: WebMailName;
  variant: WebmailVariantString;
  getUserAccountEmail: () => string | undefined;
  getUserFullName: () => string | undefined;
  getReplacer: () => WebmailElementReplacer;
  start: (acctEmail: string, inject: Injector, notifications: Notifications, factory: XssSafeFactory, notifyMurdered: () => void) => Promise<void>;
};
export interface WebmailElementReplacer {
  getIntervalFunctions: () => Array<IntervalFunction>;
  setReplyBoxEditable: () => void;
  reinsertReplyBox: (subject: string, myEmail: string, replyTo: string[], threadId: string) => void;
  scrollToBottomOfConvo: () => void;
}

// tslint:disable:no-blank-lines-func
export const contentScriptSetupIfVacant = async (webmailSpecific: WebmailSpecificInfo) => {

  const setUpNotification = `
    <a href="#" class="action_open_settings" data-test="notification-setup-action-open-settings">Set up FlowCrypt</a> to send and receive secure email on this account.
    <a href="#" class="notification_setup_needed_dismiss" data-test="notification-setup-action-dismiss">dismiss</a>
    <a href="#" class="close" data-test="notification-setup-action-close">remind me later</a>
  `;
  let wasDestroyed = false;
  class DestroyTrigger extends Error { }

  const waitForAcctEmail = async (): Promise<string> => {
    let acctEmailInterval = 1000;
    const webmails = await Env.webmails();
    while (true) {
      const acctEmail = webmailSpecific.getUserAccountEmail();
      if (typeof acctEmail !== 'undefined') {
        (window as ContentScriptWindow).account_email_global = acctEmail;
        if (webmails.includes(webmailSpecific.name)) {
          console.info(`Loading FlowCrypt ${VERSION} for ${acctEmail}`);
          return acctEmail;
        } else {
          console.info(`FlowCrypt disabled: ${webmailSpecific.name} integration currently for development only`);
          throw new DestroyTrigger();
        }
      }
      if (acctEmailInterval > 6000) {
        console.info(`Cannot load FlowCrypt yet. Page: ${window.location} (${document.title})`);
      }
      await Ui.time.sleep(acctEmailInterval, (window as ContentScriptWindow).TrySetDestroyableTimeout);
      acctEmailInterval += 1000;
      if (wasDestroyed) {
        throw new DestroyTrigger(); // maybe not necessary, but don't want to take chances
      }
    }
  };

  const initInternalVars = async (acctEmail: string) => {
    const tabId = await BrowserMsg.requiredTabId(30, 1000); // keep trying for 30 seconds
    const notifications = new Notifications(tabId);
    const factory = new XssSafeFactory(acctEmail, tabId, (window as ContentScriptWindow).reloadable_class, (window as ContentScriptWindow).destroyable_class);
    const inject = new Injector(webmailSpecific.name, webmailSpecific.variant, factory);
    inject.meta();
    await Store.acctEmailsAdd(acctEmail);
    saveAcctEmailFullNameIfNeeded(acctEmail).catch(Catch.reportErr); // may take a long time, thus async
    return { tabId, notifications, factory, inject };
  };

  const showNotificationsAndWaitTilAcctSetUp = async (acctEmail: string, notifications: Notifications) => {
    let showSetupNeededNotificationIfSetupNotDone = true;
    while (true) {
      const storage = await Store.getAcct(acctEmail, ['setup_done', 'cryptup_enabled', 'notification_setup_needed_dismissed']);
      if (storage.setup_done === true && storage.cryptup_enabled !== false) { // "not false" is due to cryptup_enabled unfedined in previous versions, which means "true"
        notifications.clear();
        return;
      } else if (!$("div.webmail_notification").length && !storage.notification_setup_needed_dismissed && showSetupNeededNotificationIfSetupNotDone && storage.cryptup_enabled !== false) {
        notifications.show(setUpNotification, {
          notification_setup_needed_dismiss: () => Store.setAcct(acctEmail, { notification_setup_needed_dismissed: true }).then(() => notifications.clear()).catch(Catch.reportErr),
          action_open_settings: () => BrowserMsg.send.bg.settings({ acctEmail }),
          close: () => {
            showSetupNeededNotificationIfSetupNotDone = false;
          },
        });
      }
      await Ui.time.sleep(3000, (window as ContentScriptWindow).TrySetDestroyableTimeout);
      if (wasDestroyed) {
        throw new DestroyTrigger(); // maybe not necessary, but don't want to take chances
      }
    }
  };

  const browserMsgListen = (acctEmail: string, tabId: string, inject: Injector, factory: XssSafeFactory, notifications: Notifications) => {
    BrowserMsg.addListener('open_new_message', async () => inject.openComposeWin());
    BrowserMsg.addListener('close_new_message', async () => {
      $('div.new_message').remove();
    });
    BrowserMsg.addListener('close_reply_message', async ({ frameId }: Bm.CloseReplyMessage) => {
      $(`iframe#${frameId}`).remove();
    });
    BrowserMsg.addListener('reinsert_reply_box', async ({ subject, myEmail, theirEmail, threadId }: Bm.ReinsertReplyBox) => {
      webmailSpecific.getReplacer().reinsertReplyBox(subject, myEmail, theirEmail, threadId);
    });
    BrowserMsg.addListener('render_public_keys', async ({ traverseUp, afterFrameId, publicKeys }: Bm.RenderPublicKeys) => {
      const traverseUpLevels = traverseUp as number || 0;
      let appendAfter = $(`iframe#${afterFrameId}`);
      for (let i = 0; i < traverseUpLevels; i++) {
        appendAfter = appendAfter.parent();
      }
      for (const armoredPubkey of publicKeys) {
        appendAfter.after(factory.embeddedPubkey(armoredPubkey, false));
      }
    });
    BrowserMsg.addListener('close_dialog', async () => {
      $('#cryptup_dialog').remove();
    });
    BrowserMsg.addListener('scroll_to_bottom_of_conversation', async () => {
      webmailSpecific.getReplacer().scrollToBottomOfConvo();
    });
    BrowserMsg.addListener('passphrase_dialog', async ({ longids, type }: Bm.PassphraseDialog) => {
      if (!$('#cryptup_dialog').length) {
        $('body').append(factory.dialogPassphrase(longids, type)) // xss-safe-factory;
          .click(Ui.event.handle(e => { // click on the area outside the iframe
            $('#cryptup_dialog').remove();
          }));
      }
    });
    BrowserMsg.addListener('subscribe_dialog', async ({ isAuthErr }: Bm.SubscribeDialog) => {
      if (!$('#cryptup_dialog').length) {
        $('body').append(factory.dialogSubscribe(undefined, isAuthErr)); // xss-safe-factory
      }
    });
    BrowserMsg.addListener('add_pubkey_dialog', async ({ emails }: Bm.AddPubkeyDialog) => {
      if (!$('#cryptup_dialog').length) {
        $('body').append(factory.dialogAddPubkey(emails)); // xss-safe-factory
      }
    });
    BrowserMsg.addListener('notification_show', async ({ notification, callbacks }: Bm.NotificationShow) => {
      notifications.show(notification, callbacks);
      $('body').one('click', Catch.try(notifications.clear));
    });
    BrowserMsg.addListener('notification_show_auth_popup_needed', async ({ acctEmail }: Bm.NotificationShowAuthPopupNeeded) => {
      notifications.showAuthPopupNeeded(acctEmail);
    });
    BrowserMsg.addListener('reply_pubkey_mismatch', async () => {
      const replyIframe = $('iframe.reply_message').get(0) as HTMLIFrameElement | undefined;
      if (replyIframe) {
        replyIframe.src = replyIframe.src.replace('/compose.htm?', '/reply_pubkey_mismatch.htm?');
      }
    });
    BrowserMsg.addListener('add_end_session_btn', () => inject.insertEndSessionBtn(acctEmail));
    BrowserMsg.listen(tabId);
  };

  const saveAcctEmailFullNameIfNeeded = async (acctEmail: string) => {
    const storage = await Store.getAcct(acctEmail, ['full_name']);
    let timeout = 1000;
    if (typeof storage.full_name === 'undefined') {
      while (true) {
        const fullName = webmailSpecific.getUserFullName();
        if (fullName) {
          await Store.setAcct(acctEmail, { full_name: fullName });
          return;
        }
        await Ui.time.sleep(timeout, (window as ContentScriptWindow).TrySetDestroyableTimeout);
        timeout += 1000;
        if (wasDestroyed) {
          return;
        }
      }
    }
  };

  const notifyMurdered = () => {
    const notifEl = document.getElementsByClassName('webmail_notifications')[0];
    notifEl.innerHTML = '<div class="webmail_notification">FlowCrypt has updated, please reload the tab.<a href="#" onclick="parentNode.remove()">close</a></div>'; // xss-direct
  };

  const entrypoint = async () => {
    try {
      const acctEmail = await waitForAcctEmail();
      const { tabId, notifications, factory, inject } = await initInternalVars(acctEmail);
      await showNotificationsAndWaitTilAcctSetUp(acctEmail, notifications);
      browserMsgListen(acctEmail, tabId, inject, factory, notifications);
      await webmailSpecific.start(acctEmail, inject, notifications, factory, notifyMurdered);
    } catch (e) {
      if (e instanceof TabIdRequiredError) {
        console.error(`FlowCrypt cannot start: ${String(e)}`);
      } else if (e instanceof Error && e.message === 'Extension context invalidated.') {
        console.info(`FlowCrypt cannot start: extension context invalidated. Destroying.`);
        (window as ContentScriptWindow).destroy();
      } else if (!(e instanceof DestroyTrigger)) {
        Catch.reportErr(e);
      }
    }
  };

  if (!(window as ContentScriptWindow).injected) {

    /**
     * This tries to deal with initial environment setup and plugin updtates in a running tab.
     * - vacant: no influence of previous script is apparent in the DOM
     * - destroy: script from old world will receive destroy event from new script (DOM event) and tear itself down. Should cause tab to be vacant.
     * - murdered: what Firefox does to detached scripts. Will NOT cause tab to be vacant.
     */

    (window as ContentScriptWindow).injected = true; // background script will use this to test if scripts were already injected, and inject if not
    (window as ContentScriptWindow).account_email_global = undefined; // used by background script
    (window as ContentScriptWindow).same_world_global = true; // used by background_script

    (window as ContentScriptWindow).destruction_event = Env.runtimeId() + '_destroy';
    (window as ContentScriptWindow).destroyable_class = Env.runtimeId() + '_destroyable';
    (window as ContentScriptWindow).reloadable_class = Env.runtimeId() + '_reloadable';
    (window as ContentScriptWindow).destroyable_intervals = [];
    (window as ContentScriptWindow).destroyable_timeouts = [];

    (window as ContentScriptWindow).destroy = () => {
      Catch.try(() => {
        console.info('Updating FlowCrypt');
        document.removeEventListener((window as ContentScriptWindow).destruction_event, (window as ContentScriptWindow).destroy);
        for (const id of (window as ContentScriptWindow).destroyable_intervals) {
          clearInterval(id);
        }
        for (const id of (window as ContentScriptWindow).destroyable_timeouts) {
          clearTimeout(id);
        }
        $('.' + (window as ContentScriptWindow).destroyable_class).remove();
        $('.' + (window as ContentScriptWindow).reloadable_class).each((i, reloadableEl) => {
          $(reloadableEl).replaceWith($(reloadableEl)[0].outerHTML); // xss-reinsert - inserting code that was already present should not be dangerous
        });
        wasDestroyed = true;
      })();
    };

    (window as ContentScriptWindow).vacant = () => {
      return !$('.' + (window as ContentScriptWindow).destroyable_class).length;
    };

    (window as ContentScriptWindow).TrySetDestroyableInterval = (code, ms) => {
      const id = Catch.setHandledInterval(code, ms);
      (window as ContentScriptWindow).destroyable_intervals.push(id);
      return id;
    };

    (window as ContentScriptWindow).TrySetDestroyableTimeout = (code, ms) => {
      const id = Catch.setHandledTimeout(code, ms);
      (window as ContentScriptWindow).destroyable_timeouts.push(id);
      return id;
    };

    document.dispatchEvent(new CustomEvent((window as ContentScriptWindow).destruction_event));
    document.addEventListener((window as ContentScriptWindow).destruction_event, (window as ContentScriptWindow).destroy);

    if ((window as ContentScriptWindow).vacant()) {
      await entrypoint();
    } else if (Catch.browser().name === 'firefox') {
      notifyMurdered();
    }

  }

};
