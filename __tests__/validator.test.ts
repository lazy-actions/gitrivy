import { TrivyCmdOptionValidator } from '../src/validator';
import { template } from './helper';

describe('TrivyCmdOptionValidator Test', () => {
  test('Correct option', () => {
    const validator = new TrivyCmdOptionValidator({
      severity: 'HIGH',
      vulnType: 'os',
      ignoreUnfixed: false,
      template
    });
    expect(() => validator.validate()).not.toThrow();
  });

  test('Invalid severity', () => {
    const validator = new TrivyCmdOptionValidator({
      severity: '?',
      vulnType: 'os',
      ignoreUnfixed: false,
      template
    });
    expect(() => validator.validate()).toThrow(
      'Trivy option error: ? is unknown severity'
    );
  });

  test('Invalid vuln_type', () => {
    const validator = new TrivyCmdOptionValidator({
      severity: 'HIGH',
      vulnType: '?',
      ignoreUnfixed: false,
      template
    });
    expect(() => validator.validate()).toThrow(
      'Trivy option error: ? is unknown vuln-type'
    );
  });

  test('Invalid template', () => {
    const validator = new TrivyCmdOptionValidator({
      severity: 'HIGH',
      vulnType: 'os',
      ignoreUnfixed: false,
      template: '?'
    });
    expect(() => validator.validate()).toThrow('Could not find ?');
  });
});
