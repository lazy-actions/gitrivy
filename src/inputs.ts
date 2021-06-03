import * as core from '@actions/core';
import {
  IssueInputs,
  TrivyInputs,
  TrivyCmdOption,
  Validator
} from './interface';

export class Inputs {
  token: string;
  image: string;
  trivy: TrivyInputs;
  issue: IssueInputs;
  fail_on_vulnerabilities: boolean;

  constructor() {
    this.token = core.getInput('token', { required: true });

    const image = core.getInput('image') || process.env.IMAGE_NAME;
    if (!image) {
      throw new Error('Please specify target image');
    }
    this.image = image;

    this.trivy = {
      version: core.getInput('trivy_version').replace(/^v/, ''),
      option: {
        severity: core.getInput('severity').replace(/\s+/g, ''),
        vulnType: core.getInput('vuln_type').replace(/\s+/g, ''),
        ignoreUnfixed: core.getInput('ignore_unfixed').toLowerCase() === 'true',
        template:
          core.getInput('template') || `${__dirname}/template/default.tpl`
      }
    };

    this.issue = {
      title: core.getInput('issue_title'),
      labels: core
        .getInput('issue_label')
        .replace(/\s+/g, '')
        .split(','),
      assignees: core
        .getInput('issue_assignee')
        .replace(/\s+/g, '')
        .split(',')
    };

    this.fail_on_vulnerabilities =
      core.getInput('fail_on_vulnerabilities') === 'true';
  }

  validate(): void {
    const trivy = new TrivyCmdOptionValidator(this.trivy.option);
    trivy.validate();
  }
}

class TrivyCmdOptionValidator implements Validator {
  option: TrivyCmdOption;

  constructor(option: TrivyCmdOption) {
    this.option = option;
  }

  validate(): void {
    this.validateSeverity();
    this.validateVulnType();
  }

  private validateSeverity(): boolean {
    const severities = this.option.severity.split(',');
    const allowedSeverities = /UNKNOWN|LOW|MEDIUM|HIGH|CRITICAL/;
    if (!this.validateArrayOption(allowedSeverities, severities)) {
      throw new Error(
        `Trivy option error: ${severities.join(',')} is unknown severity.
        Trivy supports UNKNOWN, LOW, MEDIUM, HIGH and CRITICAL.`
      );
    }
    return true;
  }

  private validateVulnType(): boolean {
    const vulnTypes = this.option.vulnType.split(',');
    const allowedVulnTypes = /os|library/;
    if (!this.validateArrayOption(allowedVulnTypes, vulnTypes)) {
      throw new Error(
        `Trivy option error: ${vulnTypes.join(',')} is unknown vuln-type.
        Trivy supports os and library.`
      );
    }
    return true;
  }

  private validateArrayOption(
    allowedValue: RegExp,
    options: string[]
  ): boolean {
    for (const option of options) {
      if (!allowedValue.test(option)) {
        return false;
      }
    }
    return true;
  }
}
