import * as fs from 'fs';
import { removeTrivyCmd } from './helper';
import { Downloader } from '../src/downloader';

const downloader = new Downloader();

describe('Check Platform', () => {
  test('is Liniux', () => {
    const result = downloader.checkPlatform('linux');
    expect(result).toBe('Linux');
  });

  test('is Darwin', () => {
    const result = downloader.checkPlatform('darwin');
    expect(result).toBe('macOS');
  });

  test('is not linux and darwin', () => {
    expect(() => {
      downloader.checkPlatform('other');
    }).toThrowError('Sorry, other is not supported.');
  });
});

describe('getDownloadUrl', () => {
  test('with latest version and linux', async () => {
    const version = 'latest';
    const os = 'Linux';
    const result = await downloader.getDownloadUrl(version, os);
    expect(result).toMatch(
      /releases\/download\/v[0-9]+\.[0-9]+\.[0-9]+\/trivy_[0-9]+\.[0-9]+\.[0-9]+_Linux-64bit\.tar\.gz$/
    );
  });

  test('with 0.18.3 and macOS', async () => {
    const version = '0.18.3';
    const os = 'macOS';
    const result = await downloader.getDownloadUrl(version, os);
    expect(result).toMatch(
      /releases\/download\/v0\.18\.3\/trivy_0\.18\.3_macOS-64bit\.tar\.gz$/
    );
  });

  test('with non-supported version', async () => {
    const version = 'none';
    const os = 'Linux';
    await expect(downloader.getDownloadUrl(version, os)).rejects.toThrowError(
      'Could not find Trivy asset that you specified.'
    );
  });

  test('with non-supported os', async () => {
    const version = 'latest';
    const os = 'none';
    await expect(downloader.getDownloadUrl(version, os)).rejects.toThrowError(
      'Could not find Trivy asset that you specified.'
    );
  });
});

describe('Download trivy command', () => {
  afterAll(() => {
    removeTrivyCmd('__tests__');
  });

  test('with valid download URL and save in __tests__', async () => {
    let downloadUrl = 'https://github.com/aquasecurity/trivy';
    downloadUrl += '/releases/download/v0.18.3/trivy_0.18.3_Linux-64bit.tar.gz';
    const savePath = './__tests__';
    await expect(
      downloader.downloadTrivyCmd(downloadUrl, savePath)
    ).resolves.toEqual(`${savePath}/trivy`);
  }, 300000);

  test('with invalid download URL', async () => {
    const downloadUrl = 'https://github.com/this_is_invalid';
    await expect(downloader.downloadTrivyCmd(downloadUrl)).rejects.toThrow();
  });
});

describe('Trivy command', () => {
  beforeAll(() => {
    fs.writeFileSync('./trivy', '');
  });

  afterAll(() => {
    removeTrivyCmd('.');
  });

  test('exists', () => {
    const result = downloader.trivyExists('.');
    expect(result).toBeTruthy();
  });

  test('does not exist', () => {
    const result = downloader.trivyExists('src');
    expect(result).toBeFalsy();
  });
});

describe('Exists trivy command', () => {
  beforeAll(() => {
    fs.writeFileSync('./trivy', '');
  });

  afterAll(() => {
    removeTrivyCmd('.');
  });

  test('exists', () => {
    const result = downloader.trivyExists('.');
    expect(result).toBeTruthy();
  });

  test('does not exist', () => {
    const result = downloader.trivyExists('src');
    expect(result).toBeFalsy();
  });
});
