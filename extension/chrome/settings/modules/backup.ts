/* © 2016-2018 FlowCrypt Limited. Limitations apply. Contact human@flowcrypt.com */

'use strict';

import { Catch, UnreportableError } from '../../../js/common/platform/catch.js';
import { Store, KeyBackupMethod, EmailProvider } from '../../../js/common/platform/store.js';
import { Value } from '../../../js/common/core/common.js';
import { Att } from '../../../js/common/core/att.js';
import { Ui, Env, Browser } from '../../../js/common/browser.js';
import { BrowserMsg } from '../../../js/common/extension.js';
import { Rules } from '../../../js/common/rules.js';
import { Lang } from '../../../js/common/lang.js';
import { Settings } from '../../../js/common/settings.js';
import { Api } from '../../../js/common/api/api.js';
import { Pgp, KeyInfo } from '../../../js/common/core/pgp.js';
import { Google, GoogleAuth } from '../../../js/common/api/google.js';
import { Buf } from '../../../js/common/core/buf.js';
import { GMAIL_RECOVERY_EMAIL_SUBJECTS } from '../../../js/common/core/const.js';
import { Assert } from '../../../js/common/assert.js';
import { initPassphraseToggle } from '../../../js/common/ui/passphrase_ui.js';
import { Xss } from '../../../js/common/platform/xss.js';

declare const openpgp: typeof OpenPGP;

Catch.try(async () => {

  const uncheckedUrlParams = Env.urlParams(['acctEmail', 'action', 'parentTabId']);
  const acctEmail = Assert.urlParamRequire.string(uncheckedUrlParams, 'acctEmail');
  const action = Assert.urlParamRequire.oneof(uncheckedUrlParams, 'action', ['setup', 'passphrase_change_gmail_backup', 'options', undefined]);
  let parentTabId: string | undefined;
  if (action !== 'setup') {
    parentTabId = Assert.urlParamRequire.string(uncheckedUrlParams, 'parentTabId');
  }

  let emailProvider: EmailProvider;

  await initPassphraseToggle(['password', 'password2']);

  const storage = await Store.getAcct(acctEmail, ['setup_simple', 'email_provider']);
  emailProvider = storage.email_provider || 'gmail';

  const rules = await Rules.newInstance(acctEmail);
  if (!rules.canBackupKeys()) {
    Xss.sanitizeRender('body', `<div class="line" style="margin-top: 100px;">${Lang.setup.keyBackupsNotAllowed}</div>`);
    return;
  }

  const displayBlock = (name: string) => {
    const blocks = ['loading', 'step_0_status', 'step_1_password', 'step_2_confirm', 'step_3_automatic_backup_retry', 'step_3_manual'];
    for (const block of blocks) {
      $('#' + block).css('display', 'none');
    }
    $('#' + name).css('display', 'block');
  };

  $('#password').on('keyup', Ui.event.prevent('spree', () => Settings.renderPwdStrength('#step_1_password', '#password', '.action_password')));

  const showStatus = async () => {
    $('.hide_if_backup_done').css('display', 'none');
    $('h1').text('Key Backups');
    displayBlock('loading');
    const storage = await Store.getAcct(acctEmail, ['setup_simple', 'key_backup_method', 'google_token_scopes', 'email_provider']);
    if (emailProvider === 'gmail' && GoogleAuth.hasReadScope(storage.google_token_scopes || [])) {
      let keys;
      try {
        keys = await Google.gmail.fetchKeyBackups(acctEmail);
      } catch (e) {
        if (Api.err.isNetErr(e)) {
          Xss.sanitizeRender('#content', `Could not check for backups: no internet. ${Ui.retryLink()}`);
        } else if (Api.err.isAuthPopupNeeded(e)) {
          if (parentTabId) {
            BrowserMsg.send.notificationShowAuthPopupNeeded(parentTabId, { acctEmail });
          }
          Xss.sanitizeRender('#content', `Could not check for backups: account needs to be re-connected. ${Ui.retryLink()}`);
        } else {
          if (Api.err.isSignificant(e)) {
            Catch.reportErr(e);
          }
          Xss.sanitizeRender('#content', `Could not check for backups: unknown error (${String(e)}). ${Ui.retryLink()}`);
        }
        return;
      }
      displayBlock('step_0_status');
      if (keys && keys.length) {
        $('.status_summary').text('Backups found: ' + keys.length + '. Your account is backed up correctly in your email inbox.');
        Xss.sanitizeRender('#step_0_status .container', '<div class="button long green action_go_manual">SEE MORE BACKUP OPTIONS</div>');
        $('.action_go_manual').click(Ui.event.handle(() => {
          displayBlock('step_3_manual');
          $('h1').text('Back up your private key');
        }));
      } else if (storage.key_backup_method) {
        if (storage.key_backup_method === 'file') {
          $('.status_summary').text('You have previously backed up your key into a file.');
          Xss.sanitizeRender('#step_0_status .container', '<div class="button long green action_go_manual">SEE OTHER BACKUP OPTIONS</div>');
          $('.action_go_manual').click(Ui.event.handle(() => {
            displayBlock('step_3_manual');
            $('h1').text('Back up your private key');
          }));
        } else if (storage.key_backup_method === 'print') {
          $('.status_summary').text('You have previously backed up your key by printing it.');
          Xss.sanitizeRender('#step_0_status .container', '<div class="button long green action_go_manual">SEE OTHER BACKUP OPTIONS</div>');
          $('.action_go_manual').click(Ui.event.handle(() => {
            displayBlock('step_3_manual');
            $('h1').text('Back up your private key');
          }));
        } else { // inbox or other methods
          $('.status_summary').text('There are no backups on this account. If you lose your device, or it stops working, you will not be able to read your encrypted email.');
          Xss.sanitizeRender('#step_0_status .container', '<div class="button long green action_go_manual">SEE BACKUP OPTIONS</div>');
          $('.action_go_manual').click(Ui.event.handle(() => {
            displayBlock('step_3_manual');
            $('h1').text('Back up your private key');
          }));
        }
      } else {
        if (storage.setup_simple) {
          $('.status_summary').text('No backups found on this account. You can store a backup of your key in email inbox. Your key will be protected by a pass phrase of your choice.');
          Xss.sanitizeRender(
            '#step_0_status .container',
            '<div class="button long green action_go_backup">BACK UP MY KEY</div><br><br><br><a href="#" class="action_go_manual">See more advanced backup options</a>'
          );
          $('.action_go_backup').click(Ui.event.handle(() => {
            displayBlock('step_1_password');
            $('h1').text('Set Backup Pass Phrase');
          }));
          $('.action_go_manual').click(Ui.event.handle(() => {
            displayBlock('step_3_manual');
            $('h1').text('Back up your private key');
          }));
        } else {
          $('.status_summary').text('No backups found on this account. If you lose your device, or it stops working, you will not be able to read your encrypted email.');
          Xss.sanitizeRender('#step_0_status .container', '<div class="button long green action_go_manual">BACK UP MY KEY</div>');
          $('.action_go_manual').click(Ui.event.handle(() => {
            displayBlock('step_3_manual');
            $('h1').text('Back up your private key');
          }));
        }
      }
    } else { // gmail read permission not granted - cannot check for backups
      displayBlock('step_0_status');
      $('.status_summary').text('FlowCrypt cannot check your backups.');
      const pemissionsBtnIfGmail = emailProvider === 'gmail' ? '<div class="button long green action_go_auth_denied">SEE PERMISSIONS</div>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;' : '';
      Xss.sanitizeRender('#step_0_status .container', `${pemissionsBtnIfGmail}<div class="button long gray action_go_manual">SEE BACKUP OPTIONS</div>`);
      $('.action_go_manual').click(Ui.event.handle(() => {
        displayBlock('step_3_manual');
        $('h1').text('Back up your private key');
      }));
      $('.action_go_auth_denied').click(Ui.event.handle(() => BrowserMsg.send.bg.settings({ acctEmail, page: '/chrome/settings/modules/auth_denied.htm' })));
    }
  };

  $('.action_password').click(Ui.event.handle(async target => {
    if ($(target).hasClass('green')) {
      displayBlock('step_2_confirm');
    } else {
      await Ui.modal.warning('Please select a stronger pass phrase. Combinations of 4 to 5 uncommon words are the best.');
    }
  }));

  $('.action_reset_password').click(Ui.event.handle(() => {
    $('#password').val('');
    $('#password2').val('');
    displayBlock('step_1_password');
    Settings.renderPwdStrength('#step_1_password', '#password', '.action_password');
    $('#password').focus();
  }));
  $("#password2").keydown(event => {
    if (event.which === 13) {
      $('.action_backup').click();
    }
  });

  $('.action_backup').click(Ui.event.prevent('double', async (target: HTMLElement) => {
    const newPassphrase = String($('#password').val());
    if (newPassphrase !== $('#password2').val()) {
      await Ui.modal.warning('The two pass phrases do not match, please try again.');
      $('#password2').val('');
      $('#password2').focus();
    } else {
      const btnText = $(target).text();
      Xss.sanitizeRender(target, Ui.spinner('white'));
      const [primaryKi] = await Store.keysGet(acctEmail, ['primary']);
      Assert.abortAndRenderErrorIfKeyinfoEmpty(primaryKi);
      const { keys: [prv] } = await openpgp.key.readArmored(primaryKi.private);
      await Settings.openpgpKeyEncrypt(prv, newPassphrase);
      await Store.passphraseSave('local', acctEmail, primaryKi.longid, newPassphrase);
      await Store.keysAdd(acctEmail, prv.armor());
      try {
        await doBackupOnEmailProvider(acctEmail, prv.armor());
      } catch (e) {
        if (Api.err.isNetErr(e)) {
          await Ui.modal.warning('Need internet connection to finish. Please click the button again to retry.');
        } else if (parentTabId && Api.err.isAuthPopupNeeded(e)) {
          BrowserMsg.send.notificationShowAuthPopupNeeded(parentTabId, { acctEmail });
          await Ui.modal.warning('Account needs to be re-connected first. Please try later.');
        } else {
          Catch.reportErr(e);
          await Ui.modal.error(`Error happened, please try again (${String(e)})`);
        }
        $(target).text(btnText);
        return;
      }
      await writeBackupDoneAndRender(false, 'inbox');
    }
  }));

  const isMasterPrivateKeyEncrypted = async (ki: KeyInfo) => {
    const { keys: [prv] } = await openpgp.key.readArmored(ki.private);
    if (prv.primaryKey.isDecrypted()) {
      return false;
    }
    for (const packet of prv.getKeys()) {
      if (packet.isDecrypted() === true) {
        return false;
      }
    }
    if (await Pgp.key.decrypt(prv, ['']) === true) {
      return false;
    }
    return true;
  };

  const asBackupFile = (acctEmail: string, armoredKey: string) => {
    return new Att({ name: `flowcrypt-backup-${acctEmail.replace(/[^A-Za-z0-9]+/g, '')}.key`, type: 'text/plain', data: Buf.fromUtfStr(armoredKey) });
  };

  const doBackupOnEmailProvider = async (acctEmail: string, armoredKey: string) => {
    const emailMsg = String(await $.get({ url: '/chrome/emails/email_intro.template.htm', dataType: 'html' }));
    const emailAtts = [asBackupFile(acctEmail, armoredKey)];
    const msg = await Google.createMsgObj(acctEmail, acctEmail, [acctEmail], GMAIL_RECOVERY_EMAIL_SUBJECTS[0], { 'text/html': emailMsg }, emailAtts);
    if (emailProvider === 'gmail') {
      return await Google.gmail.msgSend(acctEmail, msg);
    } else {
      throw Error(`Backup method not implemented for ${emailProvider}`);
    }
  };

  const backupOnEmailProviderAndUpdateUi = async (primaryKi: KeyInfo) => {
    const pp = await Store.passphraseGet(acctEmail, primaryKi.longid);
    if (!pp || !await isPassPhraseStrongEnough(primaryKi, pp)) {
      await Ui.modal.warning('Your key is not protected with a strong pass phrase, skipping');
      return;
    }
    const btn = $('.action_manual_backup');
    const origBtnText = btn.text();
    Xss.sanitizeRender(btn, Ui.spinner('white'));
    try {
      await doBackupOnEmailProvider(acctEmail, primaryKi.private);
    } catch (e) {
      if (Api.err.isNetErr(e)) {
        return await Ui.modal.warning('Need internet connection to finish. Please click the button again to retry.');
      } else if (parentTabId && Api.err.isAuthPopupNeeded(e)) {
        BrowserMsg.send.notificationShowAuthPopupNeeded(parentTabId, { acctEmail });
        return await Ui.modal.warning('Account needs to be re-connected first. Please try later.');
      } else {
        Catch.reportErr(e);
        return await Ui.modal.error(`Error happened: ${String(e)}`);
      }
    } finally {
      btn.text(origBtnText);
    }
    await writeBackupDoneAndRender(false, 'inbox');
  };

  const backupAsFile = async (primaryKi: KeyInfo) => { // todo - add a non-encrypted download option
    const attachment = asBackupFile(acctEmail, primaryKi.private);
    if (Catch.browser().name !== 'firefox') {
      Browser.saveToDownloads(attachment);
      await writeBackupDoneAndRender(false, 'file');
    } else {
      Browser.saveToDownloads(attachment, $('.backup_action_buttons_container'));
    }
  };

  const backupByBrint = async (primaryKi: KeyInfo) => { // todo - implement + add a non-encrypted print option
    throw new Error('not implemented');
  };

  const backupRefused = async (ki: KeyInfo) => {
    await writeBackupDoneAndRender(Value.int.getFutureTimestampInMonths(3), 'none');
  };

  const writeBackupDoneAndRender = async (prompt: number | false, method: KeyBackupMethod) => {
    await Store.setAcct(acctEmail, { key_backup_prompt: prompt, key_backup_method: method });
    if (action === 'setup') {
      window.location.href = Env.urlCreate('/chrome/settings/setup.htm', { acctEmail, action: 'finalize' });
    } else {
      await showStatus();
    }
  };

  $('.action_manual_backup').click(Ui.event.prevent('double', async (target) => {
    const selected = $('input[type=radio][name=input_backup_choice]:checked').val();
    const [primaryKi] = await Store.keysGet(acctEmail, ['primary']);
    Assert.abortAndRenderErrorIfKeyinfoEmpty(primaryKi);
    if (!await isMasterPrivateKeyEncrypted(primaryKi)) {
      await Ui.modal.error('Sorry, cannot back up private key because it\'s not protected with a pass phrase.');
      return;
    }
    if (selected === 'inbox') {
      await backupOnEmailProviderAndUpdateUi(primaryKi);
    } else if (selected === 'file') {
      await backupAsFile(primaryKi);
    } else if (selected === 'print') {
      await backupByBrint(primaryKi);
    } else {
      await backupRefused(primaryKi);
    }
  }));

  const isPassPhraseStrongEnough = async (ki: KeyInfo, passphrase: string) => {
    const prv = await Pgp.key.read(ki.private);
    if (prv.isDecrypted()) {
      return false;
    }
    if (!passphrase) {
      const pp = prompt('Please enter your pass phrase:');
      if (!pp) {
        return false;
      }
      if (await Pgp.key.decrypt(prv, [pp]) !== true) {
        await Ui.modal.warning('Pass phrase did not match, please try again.');
        return false;
      }
      passphrase = pp;
    }
    if (Settings.evalPasswordStrength(passphrase).word.pass === true) {
      return true;
    }
    await Ui.modal.warning('Please change your pass phrase first.\n\nIt\'s too weak for this backup method.');
    return false;
  };

  const setupCreateSimpleAutomaticInboxBackup = async () => {
    const [primaryKi] = await Store.keysGet(acctEmail, ['primary']);
    if ((await Pgp.key.read(primaryKi.private)).isDecrypted()) {
      await Ui.modal.warning('Key not protected with a pass phrase, skipping');
      throw new UnreportableError('Key not protected with a pass phrase, skipping');
    }
    Assert.abortAndRenderErrorIfKeyinfoEmpty(primaryKi);
    try {
      await doBackupOnEmailProvider(acctEmail, primaryKi.private);
      await writeBackupDoneAndRender(false, 'inbox');
    } catch (e) {
      if (Api.err.isAuthPopupNeeded(e)) {
        await Ui.modal.info("Authorization Error. FlowCrypt needs to reconnect your Gmail account");
        const connectResult = await GoogleAuth.newAuthPopup({ acctEmail });
        if (!connectResult.error) {
          await setupCreateSimpleAutomaticInboxBackup();
        } else {
          throw e;
        }
      }
    }
  };

  $('.action_skip_backup').click(Ui.event.prevent('double', async () => {
    if (action === 'setup') {
      await Store.setAcct(acctEmail, { key_backup_prompt: false });
      window.location.href = Env.urlCreate('/chrome/settings/setup.htm', { acctEmail });
    } else {
      if (parentTabId) {
        BrowserMsg.send.closePage(parentTabId);
      } else {
        Catch.report(`backup.ts: missing parentTabId for ${action}`);
      }
    }
  }));

  $('#step_3_manual input[name=input_backup_choice]').click(Ui.event.handle(target => {
    if ($(target).val() === 'inbox') {
      $('.action_manual_backup').text('back up as email');
      $('.action_manual_backup').removeClass('red').addClass('green');
    } else if ($(target).val() === 'file') {
      $('.action_manual_backup').text('back up as a file');
      $('.action_manual_backup').removeClass('red').addClass('green');
    } else if ($(target).val() === 'print') {
      $('.action_manual_backup').text('back up on paper');
      $('.action_manual_backup').removeClass('red').addClass('green');
    } else {
      $('.action_manual_backup').text('try my luck');
      $('.action_manual_backup').removeClass('green').addClass('red');
    }
  }));

  if (action === 'setup') {
    $('.back').css('display', 'none');
    $('.action_skip_backup').parent().css('display', 'none');
    if (storage.setup_simple) {
      try {
        await setupCreateSimpleAutomaticInboxBackup();
      } catch (e) {
        return await Settings.promptToRetry('REQUIRED', e, Lang.setup.failedToBackUpKey, setupCreateSimpleAutomaticInboxBackup);
      }
    } else {
      displayBlock('step_3_manual');
      $('h1').text('Back up your private key');
    }
  } else if (action === 'passphrase_change_gmail_backup') {
    if (storage.setup_simple) {
      displayBlock('loading');
      const [primaryKi] = await Store.keysGet(acctEmail, ['primary']);
      Assert.abortAndRenderErrorIfKeyinfoEmpty(primaryKi);
      try {
        await doBackupOnEmailProvider(acctEmail, primaryKi.private);
        $('#content').text('Pass phrase changed. You will find a new backup in your inbox.');
      } catch (e) {
        if (Api.err.isNetErr(e)) {
          Xss.sanitizeRender('#content', 'Connection failed, please <a href="#" class="reload">try again</a>').find('.reload').click(() => window.location.reload());
        } else if (Api.err.isAuthPopupNeeded(e)) {
          Xss.sanitizeRender('#content', 'Need to reconnect to Google to save backup: <a href="#" class="auth">reconnect now</a>').find('.auth').click(async () => {
            await GoogleAuth.newAuthPopup({ acctEmail });
            window.location.reload();
          });
        } else {
          Xss.sanitizeRender('#content', `Unknown error: ${String(e)}<br><a href="#" class="reload">try again</a>`).find('.reload').click(() => window.location.reload());
          Catch.reportErr(e);
        }
      }
    } else { // should never happen on this action. Just in case.
      displayBlock('step_3_manual');
      $('h1').text('Back up your private key');
    }
  } else if (action === 'options') {
    displayBlock('step_3_manual');
    $('h1').text('Back up your private key');
  } else {
    await showStatus();
  }

})();
