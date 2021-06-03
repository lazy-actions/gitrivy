import * as fs from 'fs';
import * as path from 'path';
import { Downloader } from '../src/downloader';

export const template = path.join(__dirname, '../src/default.tpl');

const downloader = new Downloader();

export function removeTrivyCmd(path: string) {
  path = path.replace(/\/trivy$/, '');
  if (downloader.trivyExists(path)) {
    fs.unlinkSync(`${path}/trivy`);
  }
}
