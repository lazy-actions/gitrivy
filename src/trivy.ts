import fs from 'fs';
import zlib from 'zlib';
import tar from 'tar';
import Octokit, {
  ReposGetLatestReleaseResponse,
  ReposGetLatestReleaseResponseAssetsItem,
} from '@octokit/rest';
import fetch, { Response } from 'node-fetch';
import { spawnSync, SpawnSyncReturns } from 'child_process';

import { TrivyOption, Vulnerability } from './interface';

export class Downloader {
  githubClient: Octokit;

  static readonly trivyRepository = {
    owner: 'aquasecurity',
    repo: 'trivy',
  };

  constructor() {
    this.githubClient = new Octokit();
  }

  public async download(
    version: string,
    trivyCmdDir: string = __dirname
  ): Promise<string> {
    const os: string = this.checkPlatform(process.platform);
    const downloadUrl: string = await this.getDownloadUrl(version, os);
    console.debug(`Download URL: ${downloadUrl}`);
    const trivyCmdBaseDir: string = process.env.GITHUB_WORKSPACE || trivyCmdDir;
    const trivyCmdPath: string = await this.downloadTrivyCmd(
      downloadUrl,
      trivyCmdBaseDir
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
    try {
      const response = await this.getAssets(version);
      const filename: string = `trivy_${response.version}_${os}-64bit.tar.gz`;
      for (const asset of response.assets) {
        if (asset.name === filename) {
          return asset.browser_download_url;
        }
      }
      throw new Error();
    } catch (error) {
      const errorMsg: string = `
      Cloud not be found a Trivy asset that you specified.
      Version: ${version}
      OS: ${os}
      `;
      throw new Error(errorMsg);
    }
  }

  private async getAssets(
    version: string
  ): Promise<{
    assets: ReposGetLatestReleaseResponseAssetsItem[];
    version: string;
  }> {
    let response: Octokit.Response<ReposGetLatestReleaseResponse>;

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
    return { assets: response.data.assets, version };
  }

  private async downloadTrivyCmd(
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

  public trivyExists(targetDir: string): boolean {
    const trivyCmdPaths: string[] = fs
      .readdirSync(targetDir)
      .filter(f => f === 'trivy');
    return trivyCmdPaths.length === 1;
  }
}

export class Trivy {
  public scan(
    trivyPath: string,
    image: string,
    option: TrivyOption
  ): Vulnerability[] | string {
    this.validateOption(option);

    const args: string[] = [
      '--severity',
      option.severity,
      '--vuln-type',
      option.vulnType,
      '--format',
      option.format,
      '--quiet',
      '--no-progress',
    ];

    if (option.ignoreUnfixed) args.push('--ignore-unfixed');
    args.push(image);

    const result: SpawnSyncReturns<string> = spawnSync(trivyPath, args, {
      encoding: 'utf-8',
    });

    if (result.stdout && result.stdout.length > 0) {
      const vulnerabilities: Vulnerability[] | string =
        option.format === 'json' ? JSON.parse(result.stdout) : result.stdout;
      if (vulnerabilities.length > 0) {
        return vulnerabilities;
      }
    }

    throw new Error(`Failed vulnerability scan using Trivy.
      stdout: ${result.stdout}
      stderr: ${result.stderr}
      erorr: ${result.error}
    `);
  }

  public parse(vulnerabilities: Vulnerability[]): string {
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
    return issueContent;
  }

  private validateOption(option: TrivyOption): void {
    this.validateSeverity(option.severity.split(','));
    this.validateVulnType(option.vulnType.split(','));
  }

  private validateSeverity(severities: string[]): boolean {
    const allowedSeverities = /UNKNOWN|LOW|MEDIUM|HIGH|CRITICAL/;
    if (!validateArrayOption(allowedSeverities, severities)) {
      throw new Error(
        `Trivy option error: ${severities.join(',')} is unknown severity.
        Trivy supports UNKNOWN, LOW, MEDIUM, HIGH and CRITICAL.`
      );
    }
    return true;
  }

  private validateVulnType(vulnTypes: string[]): boolean {
    const allowedVulnTypes = /os|library/;
    if (!validateArrayOption(allowedVulnTypes, vulnTypes)) {
      throw new Error(
        `Trivy option error: ${vulnTypes.join(',')} is unknown vuln-type.
        Trivy supports os and library.`
      );
    }
    return true;
  }
}

function validateArrayOption(allowedValue: RegExp, options: string[]): boolean {
  for (const option of options) {
    if (!allowedValue.test(option)) {
      return false;
    }
  }
  return true;
}
