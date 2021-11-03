import * as core from '@actions/core';
import * as github from '@actions/github';
import { Octokit } from '@octokit/rest';
import { IssueOption, IssueResponse } from './interface';

export class GitHub {
  client: Octokit;

  constructor(token: string) {
    this.client = new Octokit({
      auth: token,
      baseUrl: process.env['GITHUB_SERVER_URL'] + "/api/v3" || 'https://github.com/api/v3',
    });
  }

  async getTrivyIssues(image: string, labels: string[] | undefined) {
    if (labels == null) {
      return [];
    }

    let { data: trivyIssues } = await this.client.issues.listForRepo({
      ...github.context.repo,
      state: 'open',
      labels: labels.join(','),
    });

    return trivyIssues.filter(
      issue => issue.body && issue.body.includes(image)
    );
  }

  async createIssue(options: IssueOption): Promise<IssueResponse> {
    const { data: issue } = await this.client.issues.create({
      ...github.context.repo,
      ...options,
    });
    return { issueNumber: issue.number, htmlUrl: issue.html_url };
  }

  async updateIssue(issueNumber: number, options: IssueOption): Promise<void> {
    await this.client.issues.update({
      ...github.context.repo,
      issue_number: issueNumber,
      body: options.body,
    });
  }

  async createOrUpdateIssue(
    image: string,
    options: IssueOption
  ): Promise<IssueResponse> {
    const trivyIssues = await this.getTrivyIssues(image, options.labels);

    if (trivyIssues.length > 0) {
      core.info('Found existing issue. Updating existing issue.');

      const existingIssue = trivyIssues[0];
      await this.updateIssue(existingIssue.number, options);
      return {
        issueNumber: existingIssue.number,
        htmlUrl: existingIssue.html_url,
      };
    } else {
      core.info('Create new issue');

      return await this.createIssue(options);
    }
  }
}
