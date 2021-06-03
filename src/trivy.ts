import { spawnSync, SpawnSyncReturns } from 'child_process';
import { TrivyOption, Vulnerability } from './interface';
import { isIterable } from './utils';

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
      error: ${result.error}
    `);
  }

  public parse(image: string, vulnerabilities: Vulnerability[]): string {
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

        const references = cve.References;
        if (!isIterable(references)) continue;
        for (const reference of references) {
          vulnTable += `${reference || 'N/A'}<br>`;
        }

        vulnTable.replace(/<br>$/, '|\n');
      }
      issueContent += `${vulnTable}\n\n`;
    }

    return issueContent ? `_(image scanned: \`${image}\`)_\n\n${issueContent}` : issueContent;
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
