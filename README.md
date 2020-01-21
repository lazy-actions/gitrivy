# Gitrivy

![GitHub release (latest by date)](https://img.shields.io/github/v/release/homoluctus/gitrivy?color=brightgreen&include_prereleases)
![GitHub](https://img.shields.io/github/license/homoluctus/gitrivy?color=brightgreen)

This is a GitHub Actions to scan vulnerability using [Trivy](https://github.com/aquasecurity/trivy).<br>
If vulnerabilities are found by Trivy, it creates the following GitHub Issue.

![image](https://github.com/homoluctus/gitrivy/blob/master/issue.png)

## Usage

### Inputs

|Parameter|Required|Default Value|Description|
|:--:|:--:|:--:|:--|
|trivy_version|False|latest|Trivy version|
|image|True|N/A|The target image name to scan the vulnerability<br>Specify this parameter or `IMAGE_NAME` environment variable|
|severity|False|HIGH,CRITICAL|Severities of vulnerabilities (separated by commma)|
|vuln_type|False|os,library|Scan target are os and / or library (separated by commma)|
|ignore_unfixed|False|false|Ignore unfixed vulnerabilities<br>Please specify `true` or `false`|
|issue|False|true|Decide whether creating issue when vulnerabilities are found by trivy.<br>Please specify `true` or `false`|
|token|True if issue parameter is true else False|N/A|GitHub Access Token.<br>${{ secrets.GITHUB_TOKEN }} is recommended.|
|issue_title|False|Security Alert|Issue title|
|issue_label|False|trivy,vulnerability|Issue label (separated by commma)|
|issue_assignee|False|N/A|Issue assignee (separated by commma)|

### Outputs

|Parameter|Description|
|:--:|:--|
|html_url|The URL to view the issue|
|issue_number|The created issue number|

## Example Workflow

Detect your docker image vulnerability everyday at 9:00 (UTC).

```yaml
name: Vulnerability Scan

on:
  schedule:
    - cron: '0 9 * * *'

jobs:
  scan:
    name: Daily Vulnerability Scan
    runs-on: ubuntu-18.04
    steps:
      - name: Pull docker image
        run: docker pull sample

      - uses: homoluctus/gitrivy@v1.0.0
        with:
          token: ${{ secrets.GITHUB_TOKEN }}
          image: sample
```
