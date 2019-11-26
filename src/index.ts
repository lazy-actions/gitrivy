import * as core from '@actions/core';
import { Trivy, Downloader } from './trivy';
import { createIssue } from './issue';
import {
  TrivyOption,
  IssueOption,
  IssueResponse,
  Vulnerability,
} from './interface';

async function run() {
  try {
    const token: string = core.getInput('token', { required: true });
    const trivyVersion: string = core
      .getInput('trivy_version')
      .replace(/^v/, '');
    const image: string | undefined =
      core.getInput('image') || process.env.IMAGE_NAME;

    if (image === undefined || image === '') {
      throw new Error('Please specify scan target image name');
    }

    const trivyOptions: TrivyOption = {
      severity: core.getInput('severity').replace(/\s+/g, ''),
      vulnType: core.getInput('vuln_type').replace(/\s+/g, ''),
      ignoreUnfixed:
        core.getInput('ignore_unfixed').toLowerCase() === 'true' ? true : false,
    };

    const downloader = new Downloader();
    const trivyCmdPath: string = await downloader.download(trivyVersion);
    const result: Vulnerability[] = Trivy.scan(
      trivyCmdPath,
      image,
      trivyOptions,
    );
    const issueContent: string = Trivy.parse(result);

    if (issueContent === '') {
      core.info(
        'Vulnerabilities were not found.\nYour maintenance looks good 👍',
      );
      return;
    }

    const issueOptions: IssueOption = {
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
    const output: IssueResponse = await createIssue(token, issueOptions);
    core.setOutput('html_url', output.htmlUrl);
    core.setOutput('issue_number', output.issueNumber.toString());
  } catch (error) {
    core.error(error.stack);
    core.setFailed(error.message);
  }
}

run();
