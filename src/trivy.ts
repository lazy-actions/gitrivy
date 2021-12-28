import { spawnSync } from 'child_process';
import * as core from '@actions/core';
import { TrivyCmdOption } from './interface';

export function scan(
  trivyPath: string,
  image: string,
  option: TrivyCmdOption
): string | undefined {
  const args = [
    'image',
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
