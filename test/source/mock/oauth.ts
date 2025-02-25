import { HttpClientErr, Status } from './api';
import { Config } from '../util';
import { Buf } from '../core/buf';

// tslint:disable:variable-name

export class OauthMock {

  private authCodesByAcct: { [acct: string]: string } = {};
  private refreshTokenByAuthCode: { [authCode: string]: string } = {};
  private accessTokenByRefreshToken: { [refreshToken: string]: string } = {};
  private acctByAccessToken: { [acct: string]: string } = {};

  public clientId = '717284730244-ostjo2fdtr3ka4q9td69tdr9acmmru2p.apps.googleusercontent.com';
  public expiresIn = 2 * 60 * 60; // 2hrs in seconds
  public redirectUri = 'urn:ietf:wg:oauth:2.0:oob:auto';

  public consentChooseAccountPage = (url: string) => {
    return this.htmlPage('oauth mock choose acct', '<h1>Choose mock oauth email</h1>' + Config.secrets.auth.google.map(({ email }) => {
      return `<a href="${url + '&login_hint=' + email}" id="profileIdentifier" data-email="${email}">${email}</a><br>`;
    }).join('<br>'));
  }

  public consentPage = (url: string, acct: string) => {
    this.checkKnownAcct(acct);
    return this.htmlPage('oauth mock', `Mock oauth: ${acct}<br><br><a href="${url}&result=Success" id="submit_approve_access">Approve</a>`);
  }

  public consentResultPage = (acct: string, state: string, result: string) => {
    this.checkKnownAcct(acct);
    if (result === 'Success') {
      const authCode = `mock-auth-code-${acct.replace(/[^a-z0-9]+/g, '')}`;
      const refreshToken = `mock-refresh-token-${acct.replace(/[^a-z0-9]+/g, '')}`;
      const accessToken = `mock-access-token-${acct.replace(/[^a-z0-9]+/g, '')}`;
      this.authCodesByAcct[acct] = authCode;
      this.refreshTokenByAuthCode[authCode] = refreshToken;
      this.accessTokenByRefreshToken[refreshToken] = accessToken;
      this.acctByAccessToken[accessToken] = acct;
      return this.htmlPage(`${result} code=${authCode}&state=${state}&error=`, `Authorized successfully, please return to app`);
    } else {
      return this.htmlPage(`${result} code=&state=${state}&error=Result+is+${result}`, `Got a non-success result: ${result}`);
    }
  }

  public getRefreshTokenResponse = (code: string) => {
    const refresh_token = this.refreshTokenByAuthCode[code];
    const access_token = this.getAccessToken(refresh_token);
    this.checkKnownAcct(this.acctByAccessToken[access_token]);
    const id_token = this.getIdToken();
    return { access_token, refresh_token, expires_in: this.expiresIn, id_token, token_type: 'refresh_token' }; // guessed the token_type
  }

  public getAccessTokenResponse = (refreshToken: string) => {
    try {
      const access_token = this.getAccessToken(refreshToken);
      this.checkKnownAcct(this.acctByAccessToken[access_token]);
      const id_token = this.getIdToken();
      return { access_token, expires_in: this.expiresIn, id_token, token_type: 'Bearer' };
    } catch (e) {
      throw new HttpClientErr('invalid_grant', Status.BAD_REQUEST);
    }
  }

  public checkAuthorizationHeader = (authorization: string | undefined) => {
    if (!authorization) {
      throw new HttpClientErr('Missing mock bearer authorization header', Status.UNAUTHORIZED);
    }
    const accessToken = authorization.replace(/^Bearer /, '');
    const acct = this.acctByAccessToken[accessToken];
    if (!acct) {
      throw new HttpClientErr('Invalid auth token', Status.UNAUTHORIZED);
    }
    this.checkKnownAcct(acct);
    return acct;
  }

  private getAccessToken = (refreshToken: string): string => {
    if (this.accessTokenByRefreshToken[refreshToken]) {
      return this.accessTokenByRefreshToken[refreshToken];
    }
    throw new HttpClientErr('Wrong mock refresh token', Status.UNAUTHORIZED);
  }

  private htmlPage = (title: string, content: string) => {
    return `<!DOCTYPE HTML><html><head><title>${title}</title></head><body>${content}</body></html>`;
  }

  private checkKnownAcct = (acct: string) => {
    if (!Config.secrets.auth.google.map(a => a.email).includes(acct)) {
      throw new HttpClientErr(`Unknown test account: ${acct}`);
    }
  }

  private getIdToken = () => {
    const data = {
      at_hash: 'at_hash',
      exp: this.expiresIn,
      iat: 123, sub: 'sub',
      aud: 'aud', azp: 'azp',
      iss: "http://localhost:8001",
      name: 'First Last',
      picture: 'picture',
      locale: 'en',
      family_name: 'Last',
      given_name: 'First',
    };
    return `dunnowhatgoeshere.${Buf.fromUtfStr(JSON.stringify(data)).toBase64UrlStr()}`;
  }
}
