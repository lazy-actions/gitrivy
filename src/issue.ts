import { Octokit } from '@octokit/rest';
import * as core from '@actions/core';
import * as github from '@actions/github';
import { IssueOption, IssueResponse } from './interface';

async function get_trivy_issues(repository: string, token: string) {
  const client: Octokit = new Octokit({ auth: token });

  let trivyIssues = await client.issues.list(
      { state: "open", labels: "tool:trivy" , filter: "all" })

  trivyIssues = trivyIssues.data.filter(issue => issue.repository.full_name == repository)

  core.info(`Found ${trivyIssues.length} open trivy issues for this repository.`)
  core.exportVariable('issues', trivyIssues);

  return trivyIssues
}

async function createIssue(
  token: string,
  options: IssueOption
): Promise<any> {
  const client: Octokit = new Octokit({ auth: token });
  const {
    data: issue,
  }: Octokit.Response<Octokit.IssuesCreateResponse> = await client.issues.create(
    {
      ...github.context.repo,
      ...options,
    }
  );
  return issue
}

export async function getExistingOrCreateIssue(
  token: string,
  options: IssueOption
): Promise<IssueResponse> {
  const currentVulnerability = options.body.match(/\|CVE-[0-9-]+\|/)
  core.info(`Current vulnerability is ${currentVulnerability}`)
  core.exportVariable('v', currentVulnerability);

  let issue = null
  if (currentVulnerability != null) {
    const trivyIssues = await get_trivy_issues(github.context.repo, token)
    issue = trivyIssues.find(issue => issue.body.includes(currentVulnerability[0]))
  }

  if (issue != null) {
    core.info("Found existing issue. Skip creating a new one.")
  } else {
    issue = await createIssue(token, options)
  }

  const result: IssueResponse = {
    issueNumber: issue.number,
    htmlUrl: issue.html_url,
  };

  return result;
}
