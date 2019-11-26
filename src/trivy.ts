import fs from 'fs';
import zlib from 'zlib';
import tar from 'tar';
import Octokit, { ReposGetLatestReleaseResponse } from '@octokit/rest';
import fetch, { Response } from 'node-fetch';
import { spawnSync, SpawnSyncReturns } from 'child_process';

import { TrivyOption, Vulnerability } from './interface';

interface Repository {
  owner: string;
  repo: string;
}

export class Downloader {
  githubClient: Octokit;

  static readonly trivyRepository: Repository = {
    owner: 'aquasecurity',
    repo: 'trivy',
  };

  constructor() {
    this.githubClient = new Octokit();
  }

  public async download(
    version: string = 'latest',
    trivyCmdDir: string = __dirname,
  ): Promise<string> {
    const os: string = this.checkPlatform(process.platform);
    const downloadUrl: string = await this.getDownloadUrl(version, os);
    console.debug(`Download URL: ${downloadUrl}`);
    const trivyCmdBaseDir: string = process.env.GITHUB_WORKSPACE || trivyCmdDir;
    const trivyCmdPath: string = await this.downloadTrivyCmd(
      downloadUrl,
      trivyCmdBaseDir,
    );
    console.debug(`Trivy Command Path: ${trivyCmdPath}`);
    return trivyCmdPath;
  }

  private checkPlatform(platform: string): string {
    switch (platform) {
      case 'linux':
        return 'Linux';
      case 'darwin':
        return 'macOS';
      default:
        const errorMsg: string = `Sorry, ${platform} is not supported.
        Trivy support Linux, MacOS, FreeBSD and OpenBSD.`;
        throw new Error(errorMsg);
    }
  }

  private async getDownloadUrl(version: string, os: string): Promise<string> {
    let response: Octokit.Response<ReposGetLatestReleaseResponse>;

    try {
      if (version === 'latest') {
        response = await this.githubClient.repos.getLatestRelease({
          ...Downloader.trivyRepository,
        });
        version = response.data.tag_name.replace(/v/, '');
      } else {
        response = await this.githubClient.repos.getReleaseByTag({
          ...Downloader.trivyRepository,
          tag: `v${version}`,
        });
      }
    } catch (error) {
      throw new Error(`The Trivy version that you specified does not exist.
      Version: ${version}
      `);
    }

    const filename: string = `trivy_${version}_${os}-64bit.tar.gz`;
    for await (const asset of response.data.assets) {
      if (asset.name === filename) {
        return asset.browser_download_url;
      }
    }

    const errorMsg: string = `Cloud not be found Trivy asset that You specified.
    Version: ${version}
    OS: ${os}`;
    throw new Error(errorMsg);
  }

  private async downloadTrivyCmd(
    downloadUrl: string,
    savedPath: string = '.',
  ): Promise<string> {
    const response: Response = await fetch(downloadUrl);

    return new Promise((resolve, reject) => {
      const extract = tar.extract({ C: savedPath }, ['trivy']);
      response.body
        .on('error', reject)
        .pipe(zlib.createGunzip())
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

  public trivyExists(targetDir: string): boolean {
    const trivyCmdPaths: string[] = fs
      .readdirSync(targetDir)
      .filter(f => f === 'trivy');
    return trivyCmdPaths.length === 1;
  }
}

export class Trivy {
  static scan(
    trivyPath: string,
    image: string,
    options: TrivyOption,
  ): Vulnerability[] {
    const args: string[] = [
      '--severity',
      options.severity,
      '--vuln-type',
      options.vulnType,
      '--format',
      'json',
      '--quiet',
      '--no-progress',
    ];

    if (options.ignoreUnfixed) {
      args.push('--ignore-unfixed');
    }

    args.push(image);
    const result: SpawnSyncReturns<string> = spawnSync(trivyPath, args, {
      encoding: 'utf-8',
    });

    if (result.stdout && result.stdout.length > 0) {
      return JSON.parse(result.stdout);
    }

    throw new Error(`Failed vulnerability scan using Trivy.
      stdout: ${result.stdout}
      stderr: ${result.stderr}
      erorr: ${result.error}
    `);
  }

  static parse(vulnerabilities: Vulnerability[]): string {
    let issueContent: string = '';

    for (const vuln of vulnerabilities) {
      if (vuln.Vulnerabilities === null) continue;

      issueContent += `## ${vuln.Target}\n`;
      let vulnTable: string = '|Title|Severity|CVE|Package Name|';
      vulnTable += 'Installed Version|Fixed Version|References|\n';
      vulnTable += '|:--:|:--:|:--:|:--:|:--:|:--:|:--|\n';

      for (const cve of vuln.Vulnerabilities) {
        vulnTable += `|${cve.Title || 'N/A'}|${cve.Severity || 'N/A'}`;
        vulnTable += `|${cve.VulnerabilityID || 'N/A'}|${cve.PkgName || 'N/A'}`;
        vulnTable += `|${cve.InstalledVersion || 'N/A'}|${cve.FixedVersion ||
          'N/A'}|`;

        for (const reference of cve.References) {
          vulnTable += `${reference || 'N/A'}<br>`;
        }

        vulnTable.replace(/<br>$/, '|\n');
      }
      issueContent += `${vulnTable}\n\n`;
    }
    console.debug(issueContent);
    return issueContent;
  }
}
