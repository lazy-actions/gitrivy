import Octokit, {
  ReposGetLatestReleaseResponse
} from '@octokit/rest'
import { spawnSync, SpawnSyncReturns } from 'child_process'
import axios, { AxiosResponse, AxiosPromise } from 'axios'
import fs from 'fs'
import tar from 'tar'

import { TrivyOption, Vulnerability } from './interface'
import { Stream } from 'stream'

interface Repository {
  owner: string,
  repo: string
}

export class Downloader {
  githubClient: Octokit

  static readonly trivyRepository: Repository = {
    owner: 'aquasecurity',
    repo: 'trivy'
  }

  constructor(token: string) {
    this.githubClient = new Octokit({ auth: `token ${token}` })
  }

  public async download(version: string): Promise<string> {
    const os: string = this.checkPlatform(process.platform)
    const downloadUrl: string = await this.getDownloadUrl(version, os)
    const trivyPath: string = `${__dirname}/trivy.tgz`
    const writer: fs.WriteStream = fs.createWriteStream(trivyPath)
    const response: AxiosResponse<Stream> = await axios.get(downloadUrl, { responseType: 'stream' })
    response.data.pipe(writer)
    const trivyCmdPath: string = this.extractTrivyCmd(trivyPath, '/usr/local/bin')
    return trivyCmdPath
  }

  private checkPlatform(platform: string): string {
    if (platform === 'linux') {
      return 'Linux'
    } else if (platform === 'darwin') {
      return 'macOS'
    } else {
      throw new Error(`
        Sorry, ${platform} is not supported.
        Trivy support Linux, MacOS, FreeBSD and OpenBSD.
      `)
    }
  }

  private async getDownloadUrl(version: string, os: string): Promise<string> {
    let response: Octokit.Response<ReposGetLatestReleaseResponse>

    try {
      if (version === 'latest') {
        response = await this.githubClient.repos.getLatestRelease({
          ...Downloader.trivyRepository
        })
        version = response.data.tag_name.replace(/v/, '')
      } else {
        response = await this.githubClient.repos.getReleaseByTag({
          ...Downloader.trivyRepository,
          tag: `v${version}`
        })
      }
    } catch (error) {
      throw new Error(`
        The Trivy version that you specified does not exist.
        Version: ${version}
      `)
    }

    const filename: string = `trivy_${version}_${os}-64bit.tar.gz`

    for await (const asset of response.data.assets) {
      if (asset.name === filename) {
        return asset.browser_download_url
      }
    }

    throw new Error(`
      Cloud not be found Trivy asset that You specified.
      Version: ${version}
      OS: ${os}
    `)
  }

  private extractTrivyCmd(targetFile: string, outputDir?: string): string {
    let baseDir: string = __dirname
    const options: object = {
      file: targetFile,
      sync: true,
    }

    if (outputDir !== undefined) {
      baseDir = outputDir
      options['C'] = outputDir
    }

    tar.x(options)
    const trivyCmdPath: string[] = fs.readdirSync(baseDir).filter(f => f === 'trivy')

    if (trivyCmdPath.length !== 1) {
      throw new Error('Failed to extract Trivy command file.')
    }

    return trivyCmdPath[0]
  }
}

export class Trivy {
  static scan(trivyPath: string, image: string, options: TrivyOption): Vulnerability[] {
    const args: string[] = [
      '--severity', options.severity,
      '--vuln-type', options.vulnType,
      '--format', 'json',
      '--quiet',
      '--no-progress',
    ]

    if (options.ignoreUnfixed) {
      args.push('--ignore-unfixed')
    }

    args.push(image)
    const result: SpawnSyncReturns<string> = spawnSync(trivyPath, args, { encoding: 'utf-8' })
    const stdout: string = result.stdout

    if (stdout && stdout.length > 0) {
      return JSON.parse(stdout)
    }

    throw new Error(`
      Failed vulnerability scan using Trivy.
      stderr: ${result.stderr}
    `)
  }

  static parse(vulnerabilities: Vulnerability[]): string {
    let issueContent: string = ''

    for (const vuln of vulnerabilities) {
      if (vuln.Vulnerabilities === null) continue

      issueContent += `## ${vuln.Target}`
      let vulnTable: string = `
      |Title|Severity|CVE|Description|Package Name|Installed Version|Fixed Version|References|
      |:--:|:--:|:--:|:--|:--:|:--:|:--:|:--|
      `

      for (const cve of vuln.Vulnerabilities) {
        vulnTable += `|${cve.Title}|${cve.Severity}|${cve.VulnerabilityID}|${cve.Description}`
        vulnTable += `|${cve.PkgName}|${cve.InstalledVersion}|${cve.FixedVersion}|`

        for (const reference in cve.References) {
          vulnTable += `${reference}<br>`
        }

        vulnTable.replace(/<br>$/, '|\n')
      }
      issueContent += `${vulnTable}<br><br>`
    }
    return issueContent
  }
}