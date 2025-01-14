import { TestWithNewBrowser, TestWithGlobalBrowser } from '../../test';
import { SettingsPageRecipe, InboxPageRecipe } from '../page_recipe';
import { Url } from '../../browser';
import * as ava from 'ava';
import { Util, Config } from '../../util';
import { expect } from 'chai';
import { BrowserRecipe } from '../browser_recipe';
import { TestVariant } from '../../util';

// tslint:disable:no-blank-lines-func

export let defineSettingsTests = (testVariant: TestVariant, testWithNewBrowser: TestWithNewBrowser, testWithSemaphoredGlobalBrowser: TestWithGlobalBrowser) => {

  if (testVariant !== 'CONSUMER-LIVE-GMAIL') {

    ava.test('settings[global:compatibility] - my own emails show as contacts', testWithSemaphoredGlobalBrowser('compatibility', async (t, browser) => {
      const settingsPage = await browser.newPage(t, Url.extensionSettings('flowcrypt.compatibility@gmail.com'));
      await SettingsPageRecipe.toggleScreen(settingsPage, 'additional');
      const comtactsFrame = await SettingsPageRecipe.awaitNewPageFrame(settingsPage, '@action-open-contacts-page', ['contacts.htm', 'placement=settings']);
      await comtactsFrame.waitAll('@page-contacts');
      await Util.sleep(1);
      expect(await comtactsFrame.read('@page-contacts')).to.contain('flowcrypt.compatibility@gmail.com');
      expect(await comtactsFrame.read('@page-contacts')).to.contain('flowcryptcompatibility@gmail.com');
      await SettingsPageRecipe.closeDialog(settingsPage);
      await SettingsPageRecipe.toggleScreen(settingsPage, 'basic');
    }));

    ava.test('settings[global:compatibility] - attester shows my emails', testWithSemaphoredGlobalBrowser('compatibility', async (t, browser) => {
      const settingsPage = await browser.newPage(t, Url.extensionSettings('flowcrypt.compatibility@gmail.com'));
      await SettingsPageRecipe.toggleScreen(settingsPage, 'additional');
      const attesterFrame = await SettingsPageRecipe.awaitNewPageFrame(settingsPage, '@action-open-attester-page', ['keyserver.htm', 'placement=settings']);
      await attesterFrame.waitAll('@page-attester');
      await Util.sleep(1);
      await attesterFrame.waitTillGone('@spinner');
      await Util.sleep(1);
      expect(await attesterFrame.read('@page-attester')).to.contain('flowcrypt.compatibility@gmail.com');
      expect(await attesterFrame.read('@page-attester')).to.contain('flowcryptcompatibility@gmail.com');
      await SettingsPageRecipe.closeDialog(settingsPage);
      await SettingsPageRecipe.toggleScreen(settingsPage, 'basic');
    }));

    ava.test('settings[global:compatibility] - verify key presense 1pp1', testWithSemaphoredGlobalBrowser('compatibility', async (t, browser) => {
      const settingsPage = await browser.newPage(t, Url.extensionSettings('flowcrypt.compatibility@gmail.com'));
      await SettingsPageRecipe.verifyMyKeyPage(settingsPage, 'flowcrypt.compatibility.1pp1', 'button');
    }));

    ava.test('settings[global:compatibility] - test pass phrase', testWithSemaphoredGlobalBrowser('compatibility', async (t, browser) => {
      const settingsPage = await browser.newPage(t, Url.extensionSettings('flowcrypt.compatibility@gmail.com'));
      await SettingsPageRecipe.passphraseTest(settingsPage, Config.key('flowcrypt.wrong.passphrase').passphrase, false);
      await SettingsPageRecipe.passphraseTest(settingsPage, Config.key('flowcrypt.compatibility.1pp1').passphrase, true);
    }));

    ava.test.todo('settings - verify 2pp1 key presense');
    // await tests.settings_my_key_tests(settingsPage, 'flowcrypt.compatibility.2pp1', 'link');

    ava.test('settings[global:compatibility] - feedback form', testWithSemaphoredGlobalBrowser('compatibility', async (t, browser) => {
      const settingsPage = await browser.newPage(t, Url.extensionSettings('flowcrypt.compatibility@gmail.com'));
      await settingsPage.waitAndClick('@action-open-modules-help');
      await settingsPage.waitAll('@dialog');
      const helpFrame = await settingsPage.getFrame(['help.htm']);
      await helpFrame.waitAndType('@input-feedback-message', 'automated puppeteer test: help form from settings footer');
      await helpFrame.waitAndClick('@action-feedback-send');
      await helpFrame.waitAndRespondToModal('info', 'confirm', 'Message sent!');
    }));

    ava.test('settings[new:compatibility] - view contact public key', testWithNewBrowser(async (t, browser) => {
      await BrowserRecipe.setUpCommonAcct(t, browser, 'compatibility');
      const settingsPage = await browser.newPage(t, Url.extensionSettings('flowcrypt.compatibility@gmail.com'));
      await SettingsPageRecipe.toggleScreen(settingsPage, 'additional');
      const contactsFrame = await SettingsPageRecipe.awaitNewPageFrame(settingsPage, '@action-open-contacts-page', ['contacts.htm', 'placement=settings']);
      await contactsFrame.waitAll('@page-contacts');
      await Util.sleep(1);
      await contactsFrame.waitAndClick('@action-show-pubkey', { confirmGone: true });
      await Util.sleep(1);
      expect(await contactsFrame.read('@page-contacts')).to.contain('flowcrypt.compatibility@gmail.com');
      expect(await contactsFrame.read('@page-contacts')).to.contain('LEMON VIABLE BEST MULE TUNA COUNTRY');
      expect(await contactsFrame.read('@page-contacts')).to.contain('5520CACE2CB61EA713E5B0057FDE685548AEA788');
      expect(await contactsFrame.read('@page-contacts')).to.contain('-----BEGIN PGP PUBLIC KEY BLOCK-----');
      await contactsFrame.waitAndClick('@action-back-to-contact-list', { confirmGone: true });
      await Util.sleep(1);
      expect(await contactsFrame.read('@page-contacts')).to.contain('flowcrypt.compatibility@gmail.com');
      expect(await contactsFrame.read('@page-contacts')).to.contain('flowcryptcompatibility@gmail.com');
      await SettingsPageRecipe.closeDialog(settingsPage);
      await SettingsPageRecipe.toggleScreen(settingsPage, 'basic');
    }));

    ava.test('settings[global:compatibility] - my key page - primary + secondary', testWithSemaphoredGlobalBrowser('compatibility', async (t, browser) => {
      const settingsPage = await browser.newPage(t, Url.extensionSettings('flowcrypt.compatibility@gmail.com'));
      await SettingsPageRecipe.verifyMyKeyPage(settingsPage, 'flowcrypt.compatibility.1pp1', 'link', 0);
      await SettingsPageRecipe.verifyMyKeyPage(settingsPage, 'flowcrypt.compatibility.2pp1', 'link', 1);
    }));

    ava.test.todo('settings - edit contact public key');

    ava.test('[standalone] settings - change passphrase - current in local storage', testWithNewBrowser(async (t, browser) => {
      const { acctEmail, settingsPage } = await BrowserRecipe.setUpFcPpChangeAcct(t, browser);
      const newPp = `temp ci test pp: ${Util.lousyRandom()}`;
      await SettingsPageRecipe.changePassphrase(settingsPage, undefined, newPp); // change pp and test
      await InboxPageRecipe.checkDecryptMsg(t, browser, { acctEmail, threadId: '16819bec18d4e011', expectedContent: 'changed correctly if this can be decrypted' });
    }));

    ava.test('[standalone] settings - change passphrase - current in session known', testWithNewBrowser(async (t, browser) => {
      const { acctEmail, k, settingsPage } = await BrowserRecipe.setUpFcPpChangeAcct(t, browser);
      const newPp = `temp ci test pp: ${Util.lousyRandom()}`;
      await SettingsPageRecipe.changePassphraseRequirement(settingsPage, k.passphrase, 'session');
      // decrypt msg and enter pp so that it's remembered in session
      await InboxPageRecipe.checkDecryptMsg(t, browser, { acctEmail, threadId: '16819bec18d4e011', expectedContent: 'changed correctly if this can be decrypted', enterPp: k.passphrase });
      // change pp - should not ask for pp because already in session
      await SettingsPageRecipe.changePassphrase(settingsPage, undefined, newPp);
      // now it will remember the pass phrase so decrypts without asking
      await InboxPageRecipe.checkDecryptMsg(t, browser, { acctEmail, threadId: '16819bec18d4e011', expectedContent: 'changed correctly if this can be decrypted' });
      // make it forget pass phrase by switching requirement to storage then back to session
      await SettingsPageRecipe.changePassphraseRequirement(settingsPage, newPp, 'storage');
      await SettingsPageRecipe.changePassphraseRequirement(settingsPage, newPp, 'session');
      // test decrypt - should ask for new pass phrase
      await InboxPageRecipe.checkDecryptMsg(t, browser, { acctEmail, threadId: '16819bec18d4e011', expectedContent: 'changed correctly if this can be decrypted', enterPp: newPp });
    }));

    ava.test('[standalone] settings - change passphrase - current in session unknown', testWithNewBrowser(async (t, browser) => {
      const { acctEmail, k, settingsPage } = await BrowserRecipe.setUpFcPpChangeAcct(t, browser);
      const newPp = `temp ci test pp: ${Util.lousyRandom()}`;
      await SettingsPageRecipe.changePassphraseRequirement(settingsPage, k.passphrase, 'session');
      // pp wiped after switching to session - should be needed to change pp
      await SettingsPageRecipe.changePassphrase(settingsPage, k.passphrase, newPp);
      // now it will remember the pass phrase so decrypts without asking
      await InboxPageRecipe.checkDecryptMsg(t, browser, { acctEmail, threadId: '16819bec18d4e011', expectedContent: 'changed correctly if this can be decrypted' });
      // make it forget pass phrase by switching requirement to storage then back to session
      await SettingsPageRecipe.changePassphraseRequirement(settingsPage, newPp, 'storage');
      await SettingsPageRecipe.changePassphraseRequirement(settingsPage, newPp, 'session');
      // test decrypt - should ask for new pass phrase
      await InboxPageRecipe.checkDecryptMsg(t, browser, { acctEmail, threadId: '16819bec18d4e011', expectedContent: 'changed correctly if this can be decrypted', enterPp: newPp });
    }));

    ava.test.todo('[standalone] settings - change passphrase - mismatch curent pp');

    ava.test.todo('[standalone] settings - change passphrase - mismatch new pp');

  }

};
