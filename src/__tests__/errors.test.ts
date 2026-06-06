import { mapNativeError, SecurityError, SecurityErrorCode } from '../errors';

describe('SecurityError', () => {
  it('maps native secure storage codes', () => {
    const error = mapNativeError({ code: 'SECURE_STORAGE_ERROR', message: 'KeyStore failed' });

    expect(error).toBeInstanceOf(SecurityError);
    expect((error as SecurityError).code).toBe(
      SecurityErrorCode.SECURE_STORAGE_UNAVAILABLE
    );
  });

  it('returns generic Error for unknown codes', () => {
    const error = mapNativeError(new Error('network failure'));
    expect(error).toBeInstanceOf(Error);
    expect(error).not.toBeInstanceOf(SecurityError);
  });
});
