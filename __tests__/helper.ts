import * as fs from 'fs';
import { Downloader } from '../src/downloader';

const downloader = new Downloader();

export function removeTrivyCmd(path: string) {
  path = path.replace(/\/trivy$/, '');
  if (downloader.trivyExists(path)) {
    fs.unlinkSync(`${path}/trivy`);
  }
}
