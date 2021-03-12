import { Octokit } from '@octokit/rest';
import * as core from '@actions/core';
import * as github from '@actions/github';
import { IssueOption, IssueResponse } from './interface';

async function getTrivyIssues(client: Octokit, image: string, labels: string[] | undefined) {
  if (labels == null) {
    return []
  }

  let {
    data: trivyIssues,
  } = await client.issues.listForRepo(
    { ...github.context.repo, state: "open", labels: labels.join(",") }
    );

  return trivyIssues.filter(issue => issue.body.includes(image))
}

async function createIssue(
  client: Octokit,
  options: IssueOption
): Promise<any> {
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

async function updateIssue(
  issueNumber: number,
  client: Octokit,
  options: IssueOption
): Promise<void> {
  await client.issues.update(
    {
      ...github.context.repo,
      issue_number: issueNumber,
      body: options.body
    }
  );
}

export async function createOrUpdateIssue(
  token: string,
  image: string,
  options: IssueOption
): Promise<IssueResponse> {
  const client: Octokit = new Octokit({ auth: token });

  const trivyIssues = await getTrivyIssues(client, image, options.labels)

  if (trivyIssues.length > 0) {
    core.info("Found existing issue. Updating existing issue.")

    const existingIssue = trivyIssues[0]
    await updateIssue(existingIssue.number, client, options)
    return {
      issueNumber: existingIssue.number,
      htmlUrl: existingIssue.html_url,
    }
  } else {
    core.info("Create new issue")

    const newIssue = await createIssue(client, options)
    return {
      issueNumber: newIssue.number,
      htmlUrl: newIssue.html_url,
    }
  }
}
