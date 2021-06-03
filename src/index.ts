import * as core from '@actions/core';
import { Downloader } from './downloader';
import { GitHub } from './github';
import { Trivy } from './trivy';
import { TrivyOption, IssueOption, Vulnerability } from './interface';

async function run() {
  const trivyVersion = core.getInput('trivy_version').replace(/^v/, '');
  const image = core.getInput('image') || process.env.IMAGE_NAME;
  const issueFlag = core.getInput('issue').toLowerCase() == 'true';

  if (!image) {
    throw new Error('Please specify scan target image name');
  }

  const trivyOption: TrivyOption = {
    severity: core.getInput('severity').replace(/\s+/g, ''),
    vulnType: core.getInput('vuln_type').replace(/\s+/g, ''),
    ignoreUnfixed: core.getInput('ignore_unfixed').toLowerCase() === 'true',
    format: issueFlag ? 'json' : 'table',
  };

  const downloader = new Downloader();
  const trivyCmdPath = await downloader.download(trivyVersion);

  const trivy = new Trivy();
  const result = trivy.scan(trivyCmdPath, image, trivyOption);

  if (!issueFlag) {
    core.info(`Not create a issue because issue parameter is false.
      Vulnerabilities: ${result}`);
    return;
  }

  const issueContent = trivy.parse(image, result as Vulnerability[]);
  if (issueContent === '') {
    core.info(
      'Vulnerabilities were not found.\nYour maintenance looks good 👍'
    );
    return;
  }

  const issueOption = {
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
  const token = core.getInput('token', { required: true });
  const github = new GitHub(token);
  const output = await github.createOrUpdateIssue(image, issueOption);

  core.setOutput('html_url', output.htmlUrl);
  core.setOutput('issue_number', output.issueNumber.toString());

  if (core.getInput('fail_on_vulnerabilities') === 'true') {
    throw new Error(`Vulnerabilities found.\n${issueContent}`);
  }
}

run().catch(err => core.setFailed(err.message));
