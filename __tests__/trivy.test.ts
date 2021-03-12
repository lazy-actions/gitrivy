import { Downloader, Trivy } from '../src/trivy';
import { unlinkSync, writeFileSync } from 'fs';
import { Vulnerability, TrivyOption } from '../src/interface';

const downloader = new Downloader();
const trivy = new Trivy();

function removeTrivyCmd(path: string) {
  path = path.replace(/\/trivy$/, '');
  if (downloader.trivyExists(path)) {
    unlinkSync(`${path}/trivy`);
  }
}

describe('Platform', () => {
  test('is Liniux', () => {
    const result = downloader['checkPlatform']('linux');
    expect(result).toBe('Linux');
  });

  test('is Darwin', () => {
    const result = downloader['checkPlatform']('darwin');
    expect(result).toBe('macOS');
  });

  test('is not linux and darwin', () => {
    expect(() => {
      downloader['checkPlatform']('other');
    }).toThrowError('Sorry, other is not supported.');
  });
});

describe('getDownloadUrl', () => {
  test('with latest version and linux', async () => {
    const version = 'latest';
    const os = 'Linux';
    const result = await downloader['getDownloadUrl'](version, os);
    expect(result).toMatch(
      /releases\/download\/v[0-9]*\.[0-9]*\.[0-9]*\/trivy_[0-9]*\.[0-9]*\.[0-9]*_Linux-64bit\.tar\.gz$/
    );
  });

  test('with 0.2.0 and macOS', async () => {
    const version = '0.2.0';
    const os = 'macOS';
    const result = await downloader['getDownloadUrl'](version, os);
    expect(result).toMatch(
      /releases\/download\/v0\.2\.0\/trivy_0\.2\.0_macOS-64bit\.tar\.gz$/
    );
  });

  test('with non-supported version', async () => {
    const version = 'none';
    const os = 'Linux';
    await expect(
      downloader['getDownloadUrl'](version, os)
    ).rejects.toThrowError(
      'Cloud not be found a Trivy asset that you specified.'
    );
  });

  test('with non-supported os', async () => {
    const version = 'latest';
    const os = 'none';
    await expect(
      downloader['getDownloadUrl'](version, os)
    ).rejects.toThrowError(
      'Cloud not be found a Trivy asset that you specified.'
    );
  });
});

describe('Download trivy command', () => {
  afterAll(() => {
    removeTrivyCmd('__tests__');
  });

  test('with valid download URL and save in __tests__', async () => {
    let downloadUrl = 'https://github.com/aquasecurity/trivy';
    downloadUrl += '/releases/download/v0.2.1/trivy_0.2.1_Linux-64bit.tar.gz';
    const savePath = './__tests__';
    await expect(
      downloader['downloadTrivyCmd'](downloadUrl, savePath)
    ).resolves.toEqual(`${savePath}/trivy`);
  }, 300000);

  test('with invalid download URL', async () => {
    const downloadUrl = 'https://github.com/this_is_invalid';
    await expect(downloader['downloadTrivyCmd'](downloadUrl)).rejects.toThrow();
  });
});

describe('Trivy command', () => {
  beforeAll(() => {
    writeFileSync('./trivy', '');
  });

  afterAll(() => {
    removeTrivyCmd('.');
  });

  test('exists', () => {
    const result = downloader.trivyExists('.');
    expect(result).toBeTruthy();
  });

  test('does not exist', () => {
    const result = downloader.trivyExists('src');
    expect(result).toBeFalsy();
  });
});

describe('Trivy scan', () => {
  let trivyPath: string;
  const image: string = 'alpine:3.10';

  beforeAll(async () => {
    trivyPath = !downloader.trivyExists('./__tests__')
      ? await downloader.download('latest', './__tests__')
      : './__tests__/trivy';
  }, 300000);

  afterAll(() => {
    removeTrivyCmd(trivyPath);
  });

  test('with valid option', () => {
    const option: TrivyOption = {
      severity: 'HIGH,CRITICAL',
      vulnType: 'os,library',
      ignoreUnfixed: true,
      format: 'json',
    };
    const result: Vulnerability[] | string = trivy.scan(
      trivyPath,
      image,
      option
    );
    expect(result.length).toBeGreaterThanOrEqual(1);
    expect(result).toBeInstanceOf(Object);
  });

  test('without ignoreUnfixed', () => {
    const option: TrivyOption = {
      severity: 'HIGH,CRITICAL',
      vulnType: 'os,library',
      ignoreUnfixed: false,
      format: 'json',
    };
    const result: Vulnerability[] | string = trivy.scan(
      trivyPath,
      image,
      option
    );
    expect(result.length).toBeGreaterThanOrEqual(1);
    expect(result).toBeInstanceOf(Object);
  });

  test('with table format', () => {
    const option: TrivyOption = {
      severity: 'HIGH,CRITICAL',
      vulnType: 'os,library',
      ignoreUnfixed: false,
      format: 'table',
    };
    const result: Vulnerability[] | string = trivy.scan(
      trivyPath,
      image,
      option
    );
    expect(result.length).toBeGreaterThanOrEqual(1);
    expect(result).toMatch(/alpine:3\.10/);
  });

  test('with invalid severity', () => {
    const invalidOption: TrivyOption = {
      severity: 'INVALID',
      vulnType: 'os,library',
      ignoreUnfixed: true,
      format: 'json',
    };
    expect(() => {
      trivy.scan(trivyPath, image, invalidOption);
    }).toThrowError('Trivy option error: INVALID is unknown severity');
  });

  test('with invalid vulnType', () => {
    const invalidOption: TrivyOption = {
      severity: 'HIGH',
      vulnType: 'INVALID',
      ignoreUnfixed: true,
      format: 'json',
    };
    expect(() => {
      trivy.scan(trivyPath, image, invalidOption);
    }).toThrowError('Trivy option error: INVALID is unknown vuln-type');
  });
});

describe('Parse', () => {
  test('the result without vulnerabilities', () => {
    const vulnerabilities: Vulnerability[] = [
      {
        Target: 'alpine:3.10 (alpine 3.10.3)',
        Vulnerabilities: null,
      },
    ];
    const result = trivy.parse(vulnerabilities);
    expect(result).toBe('');
  });

  test('the result including vulnerabilities', () => {
    const vulnerabilities: Vulnerability[] = [
      {
        Target: 'alpine:3.9 (alpine 3.9.4)',
        Vulnerabilities: [
          {
            VulnerabilityID: 'CVE-2019-14697',
            PkgName: 'musl',
            InstalledVersion: '1.1.20-r4',
            FixedVersion: '1.1.20-r5',
            Description:
              "musl libc through 1.1.23 has an x87 floating-point stack adjustment imbalance, related to the math/i386/ directory. In some cases, use of this library could introduce out-of-bounds writes that are not present in an application's source code.",
            Severity: 'HIGH',
            References: [
              'http://www.openwall.com/lists/oss-security/2019/08/06/4',
              'https://www.openwall.com/lists/musl/2019/08/06/1',
            ],
          },
          {
            VulnerabilityID: 'CVE-2019-1549',
            PkgName: 'openssl',
            InstalledVersion: '1.1.1b-r1',
            FixedVersion: '1.1.1d-r0',
            Title: 'openssl: information disclosure in fork()',
            Description:
              'OpenSSL 1.1.1 introduced a rewritten random number generator (RNG). This was intended to include protection in the event of a fork() system call in order to ensure that the parent and child processes did not share the same RNG state. However this protection was not being used in the default case. A partial mitigation for this issue is that the output from a high precision timer is mixed into the RNG state so the likelihood of a parent and child process sharing state is significantly reduced. If an application already calls OPENSSL_init_crypto() explicitly using OPENSSL_INIT_ATFORK then this problem does not occur at all. Fixed in OpenSSL 1.1.1d (Affected 1.1.1-1.1.1c).',
            Severity: 'MEDIUM',
            References: [
              'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-1549',
              'https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=1b0fe00e2704b5e20334a16d3c9099d1ba2ef1be',
              'https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/GY6SNRJP2S7Y42GIIDO3HXPNMDYN2U3A/',
              'https://security.netapp.com/advisory/ntap-20190919-0002/',
              'https://support.f5.com/csp/article/K44070243',
              'https://www.openssl.org/news/secadv/20190910.txt',
            ],
          },
        ],
      },
    ];
    const result = trivy.parse(vulnerabilities);
    expect(result).toMatch(
      /\|Title\|Severity\|CVE\|Package Name\|Installed Version\|Fixed Version\|References\|/
    );
  });
});

describe('Validate trivy option', () => {
  test('with a valid severity', () => {
    const options: string[] = ['HIGH'];
    const result = trivy['validateSeverity'](options);
    expect(result).toBeTruthy();
  });

  test('with two valid severities', () => {
    const options: string[] = ['HIGH', 'CRITICAL'];
    const result = trivy['validateSeverity'](options);
    expect(result).toBeTruthy();
  });

  test('with an invalid severity', () => {
    const options: string[] = ['INVALID'];
    expect(() => {
      trivy['validateSeverity'](options);
    }).toThrowError('Trivy option error: INVALID is unknown severity');
  });

  test('with two invalid severities', () => {
    const options: string[] = ['INVALID', 'ERROR'];
    expect(() => {
      trivy['validateSeverity'](options);
    }).toThrowError('Trivy option error: INVALID,ERROR is unknown severity');
  });

  test('with an invalid and a valid severities', () => {
    const options: string[] = ['INVALID', 'HIGH'];
    expect(() => {
      trivy['validateSeverity'](options);
    }).toThrowError('Trivy option error: INVALID,HIGH is unknown severity');
  });

  test('with a valid vuln-type', () => {
    const options: string[] = ['os'];
    const result = trivy['validateVulnType'](options);
    expect(result).toBeTruthy();
  });

  test('with two valid vuln-types', () => {
    const options: string[] = ['os', 'library'];
    const result = trivy['validateVulnType'](options);
    expect(result).toBeTruthy();
  });

  test('with an invalid vuln-type', () => {
    const options: string[] = ['INVALID'];
    expect(() => {
      trivy['validateVulnType'](options);
    }).toThrowError('Trivy option error: INVALID is unknown vuln-type');
  });

  test('with two invalid vuln-types', () => {
    const options: string[] = ['INVALID', 'ERROR'];
    expect(() => {
      trivy['validateVulnType'](options);
    }).toThrowError('Trivy option error: INVALID,ERROR is unknown vuln-type');
  });

  test('with a valid and an invalid vuln-types', () => {
    const options: string[] = ['INVALID', 'os'];
    expect(() => {
      trivy['validateVulnType'](options);
    }).toThrowError('Trivy option error: INVALID,os is unknown vuln-type');
  });
});
