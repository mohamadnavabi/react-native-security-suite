export enum SecurityErrorCode {
  ROOT_DETECTED = 'ROOT_DETECTED',
  JAILBREAK_DETECTED = 'JAILBREAK_DETECTED',
  FRIDA_DETECTED = 'FRIDA_DETECTED',
  DEBUGGER_DETECTED = 'DEBUGGER_DETECTED',
  SSL_PINNING_FAILED = 'SSL_PINNING_FAILED',
  SECURE_STORAGE_UNAVAILABLE = 'SECURE_STORAGE_UNAVAILABLE',
  CRYPTO_KEY_NOT_FOUND = 'CRYPTO_KEY_NOT_FOUND',
}

const NATIVE_CODE_MAP: Record<string, SecurityErrorCode> = {
  ROOT_DETECTED: SecurityErrorCode.ROOT_DETECTED,
  JAILBREAK_DETECTED: SecurityErrorCode.JAILBREAK_DETECTED,
  FRIDA_DETECTED: SecurityErrorCode.FRIDA_DETECTED,
  DEBUGGER_DETECTED: SecurityErrorCode.DEBUGGER_DETECTED,
  SSL_PINNING_FAILED: SecurityErrorCode.SSL_PINNING_FAILED,
  SECURE_STORAGE_ERROR: SecurityErrorCode.SECURE_STORAGE_UNAVAILABLE,
  SECURE_STORAGE_UNAVAILABLE: SecurityErrorCode.SECURE_STORAGE_UNAVAILABLE,
  GET_SHARED_KEY_ERROR: SecurityErrorCode.CRYPTO_KEY_NOT_FOUND,
  ENCRYPT_ERROR: SecurityErrorCode.CRYPTO_KEY_NOT_FOUND,
  DECRYPT_ERROR: SecurityErrorCode.CRYPTO_KEY_NOT_FOUND,
  CRYPTO_KEY_NOT_FOUND: SecurityErrorCode.CRYPTO_KEY_NOT_FOUND,
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
