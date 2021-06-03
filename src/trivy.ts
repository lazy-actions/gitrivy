import { spawnSync } from 'child_process';
import * as core from '@actions/core';
import { TrivyOption } from './interface';

export function scan(
  trivyPath: string,
  image: string,
  option: TrivyOption
): string | undefined {
  validateOption(option);

  const args = [
    '--severity',
    option.severity,
    '--vuln-type',
    option.vulnType,
    '--format',
    'template',
    '--template',
    option.template,
    '--quiet',
    '--no-progress',
    '--exit-code',
    '255'
  ];

  if (option.ignoreUnfixed) args.push('--ignore-unfixed');
  args.push(image);

  const result = spawnSync(trivyPath, args, { encoding: 'utf-8' });
  switch (result.status) {
    case 0:
      core.info(`Vulnerabilities were not found.
      Your maintenance looks good 👍`);
    case 255:
      if (result.stdout && result.stdout.length > 0) {
        core.info('Vulnerabilities found !!!');
        return result.stdout;
      }
    default:
      throw new Error(`Failed to execute Trivy command.
      exit code: ${result.status}
      stdout: ${result.stdout}
      stderr: ${result.stderr}`);
  }
}

function validateOption(option: TrivyOption): void {
  validateSeverity(option.severity.split(','));
  validateVulnType(option.vulnType.split(','));
}

function validateSeverity(severities: string[]): boolean {
  const allowedSeverities = /UNKNOWN|LOW|MEDIUM|HIGH|CRITICAL/;
  if (!validateArrayOption(allowedSeverities, severities)) {
    throw new Error(
      `Trivy option error: ${severities.join(',')} is unknown severity.
      Trivy supports UNKNOWN, LOW, MEDIUM, HIGH and CRITICAL.`
    );
  }
  return true;
}

function validateVulnType(vulnTypes: string[]): boolean {
  const allowedVulnTypes = /os|library/;
  if (!validateArrayOption(allowedVulnTypes, vulnTypes)) {
    throw new Error(
      `Trivy option error: ${vulnTypes.join(',')} is unknown vuln-type.
      Trivy supports os and library.`
    );
  }
  return true;
}

function validateArrayOption(allowedValue: RegExp, options: string[]): boolean {
  for (const option of options) {
    if (!allowedValue.test(option)) {
      return false;
    }
  }
  return true;
}
