export interface IssueOption {
  title: string;
  body: string;
  labels?: string[];
  assignees?: string[];
}

export interface IssueResponse {
  issueNumber: number;
  htmlUrl: string;
}

export interface TrivyOption {
  severity: string;
  vulnType: string;
  ignoreUnfixed: boolean;
  template: string;
}
