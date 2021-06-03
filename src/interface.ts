export interface IssueInputs {
  title: string;
  labels?: string[];
  assignees?: string[];
}

export interface IssueOption extends IssueInputs {
  body: string;
}

export interface IssueResponse {
  issueNumber: number;
  htmlUrl: string;
}

export interface TrivyInputs {
  version: string;
  option: TrivyCmdOption;
}

export interface TrivyCmdOption {
  severity: string;
  vulnType: string;
  ignoreUnfixed: boolean;
  template: string;
}
