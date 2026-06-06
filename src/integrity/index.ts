import { getNativeModule } from '../native/bridge';
import type { AppIntegrityReport, BuildType } from '../types/detection';

function parseBuildType(value: unknown): BuildType {
  if (value === 'debug' || value === 'release' || value === 'testflight') {
    return value;
  }
  return 'release';
}

function parseIntegrityReport(
  raw: Record<string, unknown>
): AppIntegrityReport {
  const report: AppIntegrityReport = {
    validSignature: Boolean(raw.validSignature),
    debuggable: Boolean(raw.debuggable),
    tampered: Boolean(raw.tampered),
    buildType: parseBuildType(raw.buildType),
  };

  if (raw.installerTrusted !== undefined) {
    report.installerTrusted = Boolean(raw.installerTrusted);
  }

  if (typeof raw.signingCertificateSha256 === 'string') {
    report.signingCertificateSha256 = raw.signingCertificateSha256;
  }

  if (
    raw.installerPackage === null ||
    typeof raw.installerPackage === 'string'
  ) {
    report.installerPackage = raw.installerPackage as string | null;
  }

  if (typeof raw.bundleIdentifier === 'string') {
    report.bundleIdentifier = raw.bundleIdentifier;
  }

  return report;
}

export const AppIntegrity = {
  verify(): Promise<AppIntegrityReport> {
    return getNativeModule()
      .appIntegrityVerify()
      .then((result) => parseIntegrityReport(result));
  },
};

export type { AppIntegrityReport, BuildType };
