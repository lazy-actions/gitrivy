import * as core from '@actions/core';
import { Trivy, Downloader } from './trivy';
import { createOrUpdateIssue } from './issue';
import {
  TrivyOption,
  IssueOption,
  IssueResponse,
  Vulnerability,
} from './interface';

async function run() {
  try {
    const trivyVersion: string = core
      .getInput('trivy_version')
      .replace(/^v/, '');
    const image: string | undefined =
      core.getInput('image') || process.env.IMAGE_NAME;
    const issueFlag: boolean = core.getInput('issue').toLowerCase() == 'true';

    if (image === undefined || image === '') {
      throw new Error('Please specify scan target image name');
    }

    const trivyOption: TrivyOption = {
      severity: core.getInput('severity').replace(/\s+/g, ''),
      vulnType: core.getInput('vuln_type').replace(/\s+/g, ''),
      ignoreUnfixed: core.getInput('ignore_unfixed').toLowerCase() === 'true',
      format: issueFlag ? 'json' : 'table',
    };

    const downloader = new Downloader();
    const trivyCmdPath: string = await downloader.download(trivyVersion);

    const trivy = new Trivy();
    const result: Vulnerability[] | string = trivy.scan(
      trivyCmdPath,
      image,
      trivyOption
    );

    if (!issueFlag) {
      core.info(
        `Not create a issue because issue parameter is false.
        Vulnerabilities:
        ${result}`
      );
      return;
    }

    const issueContent: string = trivy.parse(image, result as Vulnerability[]);

    if (issueContent === '') {
      core.info(
        'Vulnerabilities were not found.\nYour maintenance looks good 👍'
      );
      return;
    }

    const issueOption: IssueOption = {
      title: core.getInput('issue_title'),
      body: issueContent,
      labels: core
        .getInput('issue_label')
        .replace(/\s+/g, '')
        .split(','),
      assignees: core
        .getInput('issue_assignee')
        .replace(/\s+/g, '')
        .split(','),
    };
    const token: string = core.getInput('token', { required: true });
    const output: IssueResponse = await createOrUpdateIssue(token, image, issueOption);
    core.setOutput('html_url', output.htmlUrl);
    core.setOutput('issue_number', output.issueNumber.toString());

    if (core.getInput("fail_on_vulnerabilities") === 'true') {
      core.setFailed(`Vulnerabilities found.\n${issueContent}`)
    }
  } catch (error) {
    core.error(error.stack);
    core.setFailed(error.message);
  }
}

run();
