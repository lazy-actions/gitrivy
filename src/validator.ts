import * as fs from 'fs';
import { TrivyCmdOption, Validator } from './interface';

export class TrivyCmdOptionValidator implements Validator {
  option: TrivyCmdOption;

  constructor(option: TrivyCmdOption) {
    this.option = option;
  }

  validate(): void {
    this.validateSeverity();
    this.validateVulnType();
    this.validateTemplate();
  }

  private validateSeverity(): void {
    const severities = this.option.severity.split(',');
    const allowedSeverities = /UNKNOWN|LOW|MEDIUM|HIGH|CRITICAL/;
    if (!this.validateArrayOption(allowedSeverities, severities)) {
      throw new Error(
        `Trivy option error: ${severities.join(',')} is unknown severity.
        Trivy supports UNKNOWN, LOW, MEDIUM, HIGH and CRITICAL.`
      );
    }
  }

  private validateVulnType(): void {
    const vulnTypes = this.option.vulnType.split(',');
    const allowedVulnTypes = /os|library/;
    if (!this.validateArrayOption(allowedVulnTypes, vulnTypes)) {
      throw new Error(
        `Trivy option error: ${vulnTypes.join(',')} is unknown vuln-type.
        Trivy supports os and library.`
      );
    }
  }

  private validateArrayOption(
    allowedValue: RegExp,
    options: string[]
  ): boolean {
    for (const option of options) {
      if (!allowedValue.test(option)) {
        return false;
      }
    }
    return true;
  }

  private validateTemplate(): void {
    const template = this.option.template;

    const exists = fs.existsSync(template);
    if (!exists) {
      throw new Error(`Could not find ${template}`);
    }

    const isFile = fs.statSync(template).isFile();
    if (!isFile) {
      throw new Error(`${template} is not a file`);
    }
  }
}
