import { Octokit } from '@octokit/rest';
import * as github from '@actions/github';
import { IssueOption, IssueResponse } from './interface';

export async function createIssue(
  token: string,
  options: IssueOption
): Promise<IssueResponse> {
  const client: Octokit = new Octokit({ auth: token });
  const {
    data: issue,
  }: Octokit.Response<Octokit.IssuesCreateResponse> = await client.issues.create(
    {
      ...github.context.repo,
      ...options,
    }
  );
  const result: IssueResponse = {
    issueNumber: issue.number,
    htmlUrl: issue.html_url,
  };
  return result;
}
