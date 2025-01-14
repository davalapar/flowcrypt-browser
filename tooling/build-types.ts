import { execSync as exec } from 'child_process';
import { readFileSync, writeFileSync } from 'fs';

const CHROME_CONSUMER = 'chrome-consumer';
const CHROME_ENTERPRISE = 'chrome-enterprise';
const MOCK_HOST: { [buildType: string]: string } = { 'chrome-consumer': 'http://localhost:8001', 'chrome-enterprise': 'http://google.mock.flowcrypt.com:8001' };

const buildDir = (buildType: string) => `./build/${buildType}`;

const edit = (filepath: string, editor: (content: string) => string) => {
  writeFileSync(filepath, editor(readFileSync(filepath, { encoding: 'UTF-8' })));
};

const makeMockBuild = (buildType: string) => {
  const mockBuildType = `${buildType}-mock`;
  exec(`cp -r ${buildDir(buildType)} ${buildDir(mockBuildType)}`);
  const editor = (code: string) => code.replace(/const (GOOGLE_API_HOST|GOOGLE_OAUTH_SCREEN_HOST) = [^;]+;/g, `const $1 = '${MOCK_HOST[buildType]}';`);
  edit(`${buildDir(mockBuildType)}/js/common/core/const.js`, editor);
  edit(`${buildDir(mockBuildType)}/js/content_scripts/webmail_bundle.js`, editor);
};

makeMockBuild(CHROME_CONSUMER);
makeMockBuild(CHROME_ENTERPRISE);
