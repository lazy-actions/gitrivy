import fs from 'fs';
import zlib from 'zlib';
import tar from 'tar';
import * as core from '@actions/core';
import { Octokit } from '@octokit/rest';
import fetch, { Response } from 'node-fetch';

export class Downloader {
  readonly trivyRepo = {
    owner: 'aquasecurity',
    repo: 'trivy',
  };

  async download(
    version: string,
    trivyCmdDir: string = __dirname
  ): Promise<string> {
    const os = this.checkPlatform(process.platform);
    const downloadUrl = await this.getDownloadUrl(version, os);
    console.debug(`Download URL: ${downloadUrl}`);
    const trivyCmdBaseDir = process.env.GITHUB_WORKSPACE || trivyCmdDir;
    const trivyCmdPath = await this.downloadTrivyCmd(
      downloadUrl,
      trivyCmdBaseDir
    );
    console.debug(`Trivy Command Path: ${trivyCmdPath}`);
    return trivyCmdPath;
  }

  checkPlatform(platform: string): string {
    switch (platform) {
      case 'linux':
        return 'Linux';
      case 'darwin':
        return 'macOS';
      default:
        const errorMsg = `Sorry, ${platform} is not supported.
        Trivy support Linux, MacOS, FreeBSD and OpenBSD.`;
        throw new Error(errorMsg);
    }
  }

  async getDownloadUrl(version: string, os: string): Promise<string> {
    try {
      const response = await this.getAssets(version);
      const filename = `trivy_${response.version}_${os}-64bit.tar.gz`;
      for (const asset of response.assets) {
        if (asset.name === filename) {
          return asset.browser_download_url;
        }
      }
      throw new Error(`${filename} does not include in GitHub releases`);
    } catch (err) {
      core.error(err.message);

      const errMsg = `Could not find Trivy asset that you specified.
      Version: ${version}
      OS: ${os}
      `;
      throw new Error(errMsg);
    }
  }

  async getAssets(
    version: string
  ): Promise<{
    assets: any;
    version: string;
  }> {
    let response;
    const client = new Octokit();

    if (version === 'latest') {
      response = await client.repos.getLatestRelease({ ...this.trivyRepo });
      version = response.data.tag_name.replace(/v/, '');
    } else {
      response = await client.repos.getReleaseByTag({
        ...this.trivyRepo,
        tag: `v${version}`,
      });
    }

    return { assets: response.data.assets, version };
  }

  async downloadTrivyCmd(
    downloadUrl: string,
    savedPath: string = '.'
  ): Promise<string> {
    const response: Response = await fetch(downloadUrl);

    return new Promise((resolve, reject) => {
      const gunzip = zlib.createGunzip();
      const extract = tar.extract({ C: savedPath }, ['trivy']);
      response.body
        .on('error', reject)
        .pipe(gunzip)
        .on('error', reject)
        .pipe(extract)
        .on('error', reject)
        .on('finish', () => {
          if (!this.trivyExists(savedPath)) {
            reject('Failed to extract Trivy command file.');
          }
          resolve(`${savedPath}/trivy`);
        });
    });
  }

  trivyExists(targetDir: string): boolean {
    const trivyCmdPaths: string[] = fs
      .readdirSync(targetDir)
      .filter(f => f === 'trivy');
    return trivyCmdPaths.length === 1;
  }
}
