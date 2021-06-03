import * as core from '@actions/core';
import { IssueInputs, TrivyInputs } from './interface';
import { TrivyCmdOptionValidator } from './validator';

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
        template: core.getInput('template') || `@${__dirname}/default.tpl`
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
