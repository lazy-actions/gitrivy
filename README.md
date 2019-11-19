# Gitrivy

![GitHub release (latest by date)](https://img.shields.io/github/v/release/homoluctus/gitrivy?color=brightgreen&include_prereleases)
![GitHub](https://img.shields.io/github/license/homoluctus/gitrivy?color=brightgreen)

This is a GitHub Actions to scan vulnerability using [Trivy](https://github.com/aquasecurity/trivy).<br>
If vulnerabilities are found by Trivy, it creates the following GitHub Issue.

![image](https://github.com/homoluctus/gitrivy/blob/master/issue.png)

## Usage

### Inputs

|Parameter|Required|Default|Description|
|:--:|:--:|:--:|:--|
|token|True|N/A|GitHub access token<br>${{ secrets.GITHUB_TOKEN }} is recommended|
|trivy_version|False|latest|Trivy version|
|image|True|N/A|The target image name to scan the vulnerability<br>Specify this parameter or `IMAGE_NAME` environment variable|
|severity|False|HIGH,CRITICAL|Sevirities of vulunerabilities (separeted by commma)|
|vuln_type|False|os,library|Scan target are os and / or library (separeted by commma)|
|ignore_unfixed|False|false|Ignore unfixed vulnerabilities<br>Specify true or false|
|issue_title|False|Security Alert|Issue title|
|issue_label|False|trivy,vulnerability|Issue label (separeted by commma)|
|issue_assignee|False|N/A|Issue assignee (separeted by commma)|

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
    - cron: '00 9 * * *'

jobs:
  scan:
    name: Daily Vulnerability Scan
    runs-on: ubuntu-18.04
    steps:
      - name: Pull docker image
        run: docker pull sample

      - uses: homoluctus/gitrivy@v0.0.1
        with:
          token: ${{ secrets.GITHUB_TOKEN }}
          image: sample
```
