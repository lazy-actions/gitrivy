import * as core from '@actions/core';
import { Downloader } from './downloader';
import { GitHub } from './github';
import { scan } from './trivy';
import { TrivyOption } from './interface';

async function run(): Promise<void> {
  const trivyVersion = core.getInput('trivy_version').replace(/^v/, '');
  const image = core.getInput('image') || process.env.IMAGE_NAME;

  if (!image) {
    throw new Error('Please specify scan target image name');
  }

  const trivyOption: TrivyOption = {
    severity: core.getInput('severity').replace(/\s+/g, ''),
    vulnType: core.getInput('vuln_type').replace(/\s+/g, ''),
    ignoreUnfixed: core.getInput('ignore_unfixed').toLowerCase() === 'true',
    template: core.getInput('template') || `${__dirname}/template/default.tpl`,
  };

  const downloader = new Downloader();
  const trivyCmdPath = await downloader.download(trivyVersion);
  const result = scan(trivyCmdPath, image, trivyOption);

  if (!result) {
    return;
  }

  const issueOption = {
    title: core.getInput('issue_title'),
    body: result,
    labels: core
      .getInput('issue_label')
      .replace(/\s+/g, '')
      .split(','),
    assignees: core
      .getInput('issue_assignee')
      .replace(/\s+/g, '')
      .split(','),
  };
  const token = core.getInput('token', { required: true });
  const github = new GitHub(token);
  const output = await github.createOrUpdateIssue(image, issueOption);

  core.setOutput('html_url', output.htmlUrl);
  core.setOutput('issue_number', output.issueNumber.toString());

  if (core.getInput('fail_on_vulnerabilities') === 'true') {
    throw new Error('Abnormal termination because vulnerabilities found');
  }
}

run().catch(err => core.setFailed(err.message));
