
import * as http from 'http';
import { IncomingMessage, ServerResponse } from 'http';

export class HttpAuthErr extends Error { }
export class HttpClientErr extends Error {
  constructor(message: string, public statusCode = 400) {
    super(message);
  }
}

export enum Status {
  OK = 200,
  CREATED = 201,
  BAD_REQUEST = 400,
  UNAUTHORIZED = 401,
  FORBIDDEN = 403,
  NOT_FOUND = 404,
  CONFLICT = 409, // conflicts with key on record - request needs to be verified
  SERVER_ERROR = 500,
  NOT_IMPLEMENTED = 501,
}

export type RequestHandler<REQ, RES> = (parsedReqBody: REQ, req: IncomingMessage) => Promise<RES>;
type Handlers<REQ, RES> = { [request: string]: RequestHandler<REQ, RES> };

export class Api<REQ, RES> {

  public server: http.Server;
  protected apiName: string;
  protected maxRequestSizeMb = 0;
  protected maxRequestSizeBytes = 0;

  constructor(apiName: string, protected handlers: Handlers<REQ, RES>, protected urlPrefix = '') {
    this.apiName = apiName;
    this.server = http.createServer((request, response) => {
      this.handleReq(request, response).then((r) => {
        response.end(r);
        try {
          this.log(request, response);
        } catch (e) {
          console.error(e);
          process.exit(1);
        }
      }).catch((e) => {
        if (e instanceof HttpAuthErr) {
          response.statusCode = Status.UNAUTHORIZED;
          response.setHeader('WWW-Authenticate', `Basic realm="${this.apiName}"`);
          e.stack = undefined;
        } else if (e instanceof HttpClientErr) {
          response.statusCode = e.statusCode;
          e.stack = undefined;
        } else {
          console.error(`url:${request.method}:${request.url}`, e);
          response.statusCode = Status.SERVER_ERROR;
        }
        response.setHeader('Access-Control-Allow-Origin', '*');
        response.setHeader('content-type', 'application/json');
        const formattedErr = this.fmtErr(e);
        response.end(formattedErr);
        try {
          this.log(request, response, formattedErr);
        } catch (e) {
          console.error('error logging req', e);
        }
      });
    });
  }

  public listen = (port: number, host = '127.0.0.1', maxMb = 100) => new Promise((resolve, reject) => {
    this.maxRequestSizeMb = maxMb;
    this.maxRequestSizeBytes = maxMb * 1024 * 1024;
    this.server.listen(port, host);
    this.server.on('listening', () => {
      const address = this.server.address();
      const msg = `${this.apiName} listening on ${typeof address === 'object' && address ? address.port : address}`;
      console.log(msg);
      resolve();
    });
  })

  public close = (): Promise<void> => new Promise((resolve, reject) => this.server.close((err: any) => err ? reject(err) : resolve()));

  protected log = (req: http.IncomingMessage, res: http.ServerResponse, errRes?: Buffer) => undefined as void;

  protected handleReq = async (req: IncomingMessage, res: ServerResponse): Promise<Buffer> => {
    if (req.method === 'OPTIONS') {
      res.setHeader('Allow', 'GET,HEAD,POST,PUT,DELETE,OPTIONS');
      res.setHeader('Access-Control-Allow-Origin', '*');
      res.setHeader('Access-Control-Allow-Headers', '*');
      return this.fmtRes({});
    }
    const handler = this.chooseHandler(req);
    if (handler) {
      return this.fmtHandlerRes(await handler(this.parseReqBody(await this.collectReq(req), req), req), res);
    }
    if ((req.url === '/' || req.url === `${this.urlPrefix}/`) && (req.method === 'GET' || req.method === 'HEAD')) {
      res.setHeader('content-type', 'application/json');
      return this.fmtRes({ app_name: this.apiName });
    }
    if ((req.url === '/alive' || req.url === `${this.urlPrefix}/alive`) && (req.method === 'GET' || req.method === 'HEAD')) {
      res.setHeader('content-type', 'application/json');
      return this.fmtRes({ alive: true });
    }
    throw new HttpClientErr(`unknown MOCK path ${req.url}`);
  }

  protected chooseHandler = (req: IncomingMessage): RequestHandler<REQ, RES> | undefined => {
    if (!req.url) {
      throw new Error('no url');
    }
    if (this.handlers[req.url]) { // direct handler name match
      return this.handlers[req.url];
    }
    const url = req.url.split('?')[0];
    if (this.handlers[url]) { // direct handler name match - ignoring query
      return this.handlers[url];
    }
    // handler match where definition url ends with "/?" - incomplete path definition
    for (const handlerPathDefinition of Object.keys(this.handlers).filter(def => /\/\?$/.test(def))) {
      if (req.url.startsWith(handlerPathDefinition.replace(/\?$/, ''))) {
        return this.handlers[handlerPathDefinition];
      }
    }
  }

  protected fmtErr = (e: any): Buffer => {
    if (String(e).includes('invalid_grant')) {
      return Buffer.from(JSON.stringify({ "error": "invalid_grant", "error_description": "Bad Request" }));
    }
    return Buffer.from(JSON.stringify({ "error": { "message": e instanceof Error ? e.message : String(e) } }));
  }

  protected fmtHandlerRes = (handlerRes: RES, serverRes: ServerResponse): Buffer => {
    if (String(handlerRes).match(/^<!DOCTYPE HTML><html>/)) {
      serverRes.setHeader('content-type', 'text/html');
    } else {
      serverRes.setHeader('content-type', 'application/json');
    }
    serverRes.setHeader('Access-Control-Allow-Origin', '*');
    return this.fmtRes(handlerRes);
  }

  protected fmtRes = (response: {} | string): Buffer => {
    if (response instanceof Buffer) {
      return response;
    } else if (typeof response === 'string') {
      return Buffer.from(response);
    }
    return Buffer.from(JSON.stringify(response));
  }

  protected collectReq = (req: IncomingMessage): Promise<Buffer> => new Promise((resolve, reject) => {
    const body: Buffer[] = [];
    let byteLength = 0;
    req.on('data', (chunk: Buffer) => {
      byteLength += chunk.length;
      if (this.maxRequestSizeBytes && byteLength > this.maxRequestSizeBytes) {
        reject(new HttpClientErr(`Message over ${this.maxRequestSizeMb} MB`));
      } else {
        body.push(chunk);
      }
    });
    req.on('end', () => {
      try {
        resolve(Buffer.concat(body));
      } catch (e) {
        reject(e);
      }
    });
  })

  private parseUrlQuery = (url: string): { [k: string]: string } => {
    const queryIndex = url.indexOf('?');
    if (!queryIndex) {
      return {};
    }
    const queryStr = url.substring(queryIndex + 1);
    const valuePairs = queryStr.split('&');
    const params: { [k: string]: string } = {};
    for (const valuePair of valuePairs) {
      if (valuePair) {
        const equalSignSeparatedParts = valuePair.split('=');
        params[equalSignSeparatedParts.shift()!] = decodeURIComponent(equalSignSeparatedParts.join('='));
      }
    }
    return params;
  }

  protected parseReqBody = (body: Buffer, req: IncomingMessage): REQ => {
    return { query: this.parseUrlQuery(req.url!), body: body.length ? (req.url!.startsWith('/upload/') ? body.toString() : JSON.parse(body.toString())) : undefined } as unknown as REQ;
  }

}
