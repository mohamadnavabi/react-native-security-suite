import { NativeModules } from 'react-native';

import { SecurityErrorCode } from '../errors';
import { SecuritySuite } from '../securitySuite';

describe('SecuritySuite.getSecurityReport', () => {
  beforeEach(() => {
    NativeModules.SecuritySuite = {
      runtimeDetect: jest.fn().mockResolvedValue({
        debuggerAttached: false,
        fridaDetected: false,
        suspiciousLibraries: [],
        suspiciousPorts: [],
      }),
      appIntegrityVerify: jest.fn().mockResolvedValue({
        validSignature: true,
        debuggable: false,
        tampered: false,
        buildType: 'release',
      }),
      deviceGetEnvironment: jest.fn().mockResolvedValue({
        isEmulator: false,
        isSimulator: false,
        indicators: [],
      }),
      deviceHasSecurityRisk: jest.fn().mockResolvedValue(false),
      networkGetEnvironment: jest.fn().mockResolvedValue({
        vpnDetected: true,
        proxyDetected: false,
        indicators: ['transport:vpn'],
      }),
    };
  });

  it('aggregates native detection results', async () => {
    const report = await SecuritySuite.getSecurityReport();

    expect(report.device.isRooted).toBe(false);
    expect(report.device.isJailbroken).toBe(false);
    expect(report.runtime.fridaDetected).toBe(false);
    expect(report.app.validSignature).toBe(true);
    expect(report.network).toEqual({
      vpnDetected: true,
      proxyDetected: false,
      indicators: ['transport:vpn'],
    });
  });

  it('does not count a VPN or proxy towards the risk score', async () => {
    const report = await SecuritySuite.getSecurityReport();

    expect(report.riskScore).toBe(0);
    expect(report.riskLevel).toBe('low');
  });

  it('enforces blockVpn through protect()', async () => {
    await expect(SecuritySuite.protect()).resolves.toBeDefined();
    await expect(SecuritySuite.protect({ blockVpn: true })).rejects.toThrow(
      expect.objectContaining({ code: SecurityErrorCode.VPN_DETECTED })
    );
  });
});
