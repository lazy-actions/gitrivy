import * as path from 'path';
import { Inputs } from '../src/inputs';

describe('Inputs class Test', () => {
  const initEnv = process.env;
  const template = path.join(__dirname, '../src/template/default.tpl');

  beforeEach(() => {
    process.env = {
      INPUT_TOKEN: 'xxxxx',
      INPUT_IMAGE: 'yyyyy',
      ...initEnv
    };
  });

  test('Specify required parameters only', () => {
    expect(() => new Inputs()).not.toThrow();
  });

  test('Specify all parameter', () => {
    process.env = {
      INPUT_TOKEN: 'xxx',
      INPUT_IMAGE: 'yyy',
      INPUT_TRIVY_VERSION: '0.18.3',
      INPUT_SEVERITY: 'HIGH',
      INPUT_VULN_TYPE: 'os',
      INPUT_IGNORE_UNFIXED: 'true',
      INPUT_TEMPLATE: template,
      INPUT_ISSUE_TITLE: 'hello',
      INPUT_ISSUE_LABEL: 'world',
      INPUT_ISSUE_ASSIGNEE: 'aaaa',
      ...initEnv
    };
    const inputs = new Inputs();
    expect(() => inputs.validate()).not.toThrow();
  });

  test('Invalid severity', () => {
    process.env['INPUT_SEVERITY'] = '?';
    const inputs = new Inputs();
    expect(() => inputs.validate()).toThrow(
      'Trivy option error: ? is unknown severity.'
    );
  });

  test('Invalid vuln_type', () => {
    process.env['INPUT_VULN_TYPE'] = '?';
    const inputs = new Inputs();
    expect(() => inputs.validate()).toThrow(
      'Trivy option error: ? is unknown vuln-type'
    );
  });

  test('Invalid template', () => {
    process.env['INPUT_TEMPLATE'] = '?';
    const inputs = new Inputs();
    expect(() => inputs.validate()).toThrow('Could not find ?');
  });
});
