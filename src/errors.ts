export enum SecurityErrorCode {
  ROOT_DETECTED = 'ROOT_DETECTED',
  JAILBREAK_DETECTED = 'JAILBREAK_DETECTED',
  FRIDA_DETECTED = 'FRIDA_DETECTED',
  XPOSED_DETECTED = 'XPOSED_DETECTED',
  SUBSTRATE_DETECTED = 'SUBSTRATE_DETECTED',
  MAGISK_DETECTED = 'MAGISK_DETECTED',
  DEBUGGER_DETECTED = 'DEBUGGER_DETECTED',
  EMULATOR_DETECTED = 'EMULATOR_DETECTED',
  SECURITY_RISK_THRESHOLD = 'SECURITY_RISK_THRESHOLD',
  SSL_PINNING_FAILED = 'SSL_PINNING_FAILED',
  SECURE_STORAGE_UNAVAILABLE = 'SECURE_STORAGE_UNAVAILABLE',
  CRYPTO_KEY_NOT_FOUND = 'CRYPTO_KEY_NOT_FOUND',
  CONFIGURATION_ERROR = 'CONFIGURATION_ERROR',
  BIOMETRIC_UNAVAILABLE = 'BIOMETRIC_UNAVAILABLE',
  BIOMETRIC_AUTH_FAILED = 'BIOMETRIC_AUTH_FAILED',
  ATTESTATION_UNSUPPORTED = 'ATTESTATION_UNSUPPORTED',
  ATTESTATION_ERROR = 'ATTESTATION_ERROR',
  NETWORK_PINNING_FAILED = 'NETWORK_PINNING_FAILED',
  CLIPBOARD_UNAVAILABLE = 'CLIPBOARD_UNAVAILABLE',
  CRYPTO_RANDOM_ERROR = 'CRYPTO_RANDOM_ERROR',
}

const NATIVE_CODE_MAP: Record<string, SecurityErrorCode> = {
  BIOMETRIC_UNAVAILABLE: SecurityErrorCode.BIOMETRIC_UNAVAILABLE,
  BIOMETRIC_AUTH_FAILED: SecurityErrorCode.BIOMETRIC_AUTH_FAILED,
  ATTESTATION_UNSUPPORTED: SecurityErrorCode.ATTESTATION_UNSUPPORTED,
  ATTESTATION_ERROR: SecurityErrorCode.ATTESTATION_ERROR,
  NETWORK_PINNING_FAILED: SecurityErrorCode.NETWORK_PINNING_FAILED,
  CRYPTO_RANDOM_ERROR: SecurityErrorCode.CRYPTO_RANDOM_ERROR,
  ROOT_DETECTED: SecurityErrorCode.ROOT_DETECTED,
  JAILBREAK_DETECTED: SecurityErrorCode.JAILBREAK_DETECTED,
  FRIDA_DETECTED: SecurityErrorCode.FRIDA_DETECTED,
  XPOSED_DETECTED: SecurityErrorCode.XPOSED_DETECTED,
  SUBSTRATE_DETECTED: SecurityErrorCode.SUBSTRATE_DETECTED,
  MAGISK_DETECTED: SecurityErrorCode.MAGISK_DETECTED,
  DEBUGGER_DETECTED: SecurityErrorCode.DEBUGGER_DETECTED,
  EMULATOR_DETECTED: SecurityErrorCode.EMULATOR_DETECTED,
  SECURITY_RISK_THRESHOLD: SecurityErrorCode.SECURITY_RISK_THRESHOLD,
  SSL_PINNING_FAILED: SecurityErrorCode.SSL_PINNING_FAILED,
  SECURE_STORAGE_ERROR: SecurityErrorCode.SECURE_STORAGE_UNAVAILABLE,
  SECURE_STORAGE_UNAVAILABLE: SecurityErrorCode.SECURE_STORAGE_UNAVAILABLE,
  GET_SHARED_KEY_ERROR: SecurityErrorCode.CRYPTO_KEY_NOT_FOUND,
  ENCRYPT_ERROR: SecurityErrorCode.CRYPTO_KEY_NOT_FOUND,
  DECRYPT_ERROR: SecurityErrorCode.CRYPTO_KEY_NOT_FOUND,
  CRYPTO_KEY_NOT_FOUND: SecurityErrorCode.CRYPTO_KEY_NOT_FOUND,
  CONFIGURATION_ERROR: SecurityErrorCode.CONFIGURATION_ERROR,
  GET_PUBLIC_KEY_ERROR: SecurityErrorCode.CONFIGURATION_ERROR,
};

export class SecurityError extends Error {
  readonly code: SecurityErrorCode;
  readonly details?: Record<string, unknown>;

  constructor(
    code: SecurityErrorCode,
    message: string,
    details?: Record<string, unknown>
  ) {
    super(message);
    this.name = 'SecurityError';
    this.code = code;
    this.details = details;
  }
}

export function isSecurityError(error: unknown): error is SecurityError {
  return error instanceof SecurityError;
}

export function mapNativeError(error: unknown): SecurityError | Error {
  if (error instanceof SecurityError) {
    return error;
  }

  const nativeError = error as {
    code?: string;
    message?: string;
    userInfo?: Record<string, unknown>;
  };

  const code =
    typeof nativeError?.code === 'string'
      ? nativeError.code
      : error instanceof Error && 'code' in error
        ? String((error as Error & { code?: string }).code)
        : undefined;

  const message =
    typeof nativeError?.message === 'string'
      ? nativeError.message
      : error instanceof Error
        ? error.message
        : typeof error === 'string'
          ? error
          : 'Unknown security error';

  if (code && NATIVE_CODE_MAP[code]) {
    return new SecurityError(NATIVE_CODE_MAP[code], message, {
      nativeCode: code,
      ...(nativeError?.userInfo ?? {}),
    });
  }

  if (error instanceof Error) {
    return error;
  }

  return new Error(message);
}
