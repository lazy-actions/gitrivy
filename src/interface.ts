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
  format: string;
}

export interface Vulnerability {
  Target: string;
  Vulnerabilities: CVE[] | null;
}

interface CVE {
  VulnerabilityID: string;
  PkgName: string;
  InstalledVersion: string;
  FixedVersion: string;
  Title?: string;
  Description: string;
  Severity: string;
  References: string[];
}
