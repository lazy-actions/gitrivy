# Gitrivy

![GitHub release (latest by date)](https://img.shields.io/github/v/release/homoluctus/gitrivy?color=brightgreen)
![GitHub](https://img.shields.io/github/license/homoluctus/gitrivy?color=brightgreen)

This is a GitHub Actions to scan vulnerability using [Trivy](https://github.com/aquasecurity/trivy).<br>

## Usage

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

      - uses: homoluctus/gitrivy@v0.0.1
        with:
          image: sample
```
