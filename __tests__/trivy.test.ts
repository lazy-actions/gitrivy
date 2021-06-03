import * as path from 'path';
import { Downloader } from '../src/downloader';
import { scan } from '../src/trivy';
import { TrivyCmdOption } from '../src/interface';
import { removeTrivyCmd } from './helper';

const downloader = new Downloader();
const template = `@${path.join(__dirname, '../src/default.tpl')}`;

describe('Trivy scan', () => {
  let trivyPath: string;
  const image = 'knqyf263/vuln-image';

  beforeAll(async () => {
    trivyPath = !downloader.trivyExists(__dirname)
      ? await downloader.download('latest', __dirname)
      : `${__dirname}/trivy`;
  }, 300000);

  afterAll(() => {
    removeTrivyCmd(trivyPath);
  });

  test('with valid option', () => {
    const option: TrivyCmdOption = {
      severity: 'HIGH,CRITICAL',
      vulnType: 'os,library',
      ignoreUnfixed: true,
      template
    };
    const result = scan(trivyPath, image, option) as string;
    expect(result).toContain(
      'knqyf263/vuln-image (alpine 3.7.1) - Trivy Report'
    );
  });

  test('without ignoreUnfixed', () => {
    const option: TrivyCmdOption = {
      severity: 'HIGH,CRITICAL',
      vulnType: 'os,library',
      ignoreUnfixed: false,
      template
    };
    const result: string = scan(trivyPath, image, option) as string;
    expect(result).toContain(
      'knqyf263/vuln-image (alpine 3.7.1) - Trivy Report'
    );
  });
});
