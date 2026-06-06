export type JwsAlgorithm = 'HS256' | 'HS384' | 'HS512';

export type JwsPayload =
  | string
  | Record<string, unknown>
  | unknown[]
  | number
  | boolean
  | null
  | undefined;

export type JwsHeaderValue = string | number | boolean | null;

export type JwsHeaders = Record<string, JwsHeaderValue>;

const SUPPORTED_ALGORITHMS: readonly JwsAlgorithm[] = [
  'HS256',
  'HS384',
  'HS512',
];

const SAFE_HEADER_KEY = /^[a-zA-Z][a-zA-Z0-9_-]*$/;

export interface GenerateJWSOptions {
  payload?: JwsPayload;
  algorithm?: JwsAlgorithm;
  headers?: JwsHeaders;
  secret: string;
}

export interface JwsFetchOptions {
  algorithm?: JwsAlgorithm;
  headers?: JwsHeaders;
  secret: string;
  payload?: JwsPayload;
  detached?: boolean;
  headerName?: string;
}

export function isEmptyJwsPayload(payload: JwsPayload | undefined): boolean {
  return (
    payload === undefined ||
    payload === null ||
    (typeof payload === 'string' && payload.length === 0)
  );
}

/**
 * Normalizes a JWS payload to the exact UTF-8 string used for signing.
 * Empty payload cases return an empty string (never "null" or "undefined").
 */
export function normalizeJwsPayload(payload: JwsPayload | undefined): string {
  if (isEmptyJwsPayload(payload)) {
    return '';
  }

  if (typeof payload === 'string') {
    return payload;
  }

  if (typeof payload === 'number' || typeof payload === 'boolean') {
    return JSON.stringify(payload);
  }

  return JSON.stringify(payload);
}

export function validateJwsAlgorithm(
  algorithm: string | undefined
): JwsAlgorithm {
  if (!algorithm) {
    return 'HS256';
  }
  if (!SUPPORTED_ALGORITHMS.includes(algorithm as JwsAlgorithm)) {
    throw new Error(`Unsupported JWS algorithm: ${algorithm}`);
  }
  return algorithm as JwsAlgorithm;
}

export function validateJwsSecret(secret: unknown): string {
  if (typeof secret !== 'string' || secret.trim().length === 0) {
    throw new Error('JWS secret is required and must be a non-empty string');
  }
  return secret;
}

export function validateJwsHeaderKey(key: string): void {
  if (!SAFE_HEADER_KEY.test(key)) {
    throw new Error(`Invalid JWS header key: ${key}`);
  }
}

export function validateJwsHeaderValue(
  key: string,
  value: unknown
): JwsHeaderValue {
  if (
    value === null ||
    typeof value === 'string' ||
    typeof value === 'number' ||
    typeof value === 'boolean'
  ) {
    if (typeof value === 'string' && value.length > 0) {
      for (let i = 0; i < value.length; i++) {
        const code = value.charCodeAt(i);
        if (code < 0x20 || code > 0x7e) {
          throw new Error(`Invalid JWS header value for key: ${key}`);
        }
      }
    }
    return value as JwsHeaderValue;
  }

  throw new Error(
    `JWS header values must be JSON-serializable primitives: ${key}`
  );
}

export function validateJwsHeaders(headers: unknown): JwsHeaders {
  if (headers === undefined || headers === null) {
    return {};
  }
  if (typeof headers !== 'object' || Array.isArray(headers)) {
    throw new Error('JWS headers must be an object when provided');
  }

  const result: JwsHeaders = {};
  for (const [key, value] of Object.entries(headers as Record<string, unknown>)) {
    validateJwsHeaderKey(key);
    result[key] = validateJwsHeaderValue(key, value);
  }
  return result;
}

/**
 * Resolves the JWS algorithm from options and/or protected headers.
 */
export function resolveJwsAlgorithm(
  algorithm: JwsAlgorithm | undefined,
  headers: JwsHeaders
): JwsAlgorithm {
  const headerAlg =
    headers.alg !== undefined && headers.alg !== null
      ? String(headers.alg)
      : undefined;

  if (algorithm && headerAlg && algorithm !== headerAlg) {
    throw new Error(
      'JWS algorithm mismatch: options.algorithm and headers.alg must match'
    );
  }

  if (algorithm) {
    return validateJwsAlgorithm(algorithm);
  }

  if (headerAlg) {
    return validateJwsAlgorithm(headerAlg);
  }

  return 'HS256';
}

export interface NativeGenerateJWSOptions {
  payload: string;
  algorithm: JwsAlgorithm;
  secret: string;
  headers: JwsHeaders;
  detached: boolean;
}

export function toNativeGenerateJWSOptions(
  options: GenerateJWSOptions,
  detached = false
): NativeGenerateJWSOptions {
  const secret = validateJwsSecret(options.secret);
  const headers = validateJwsHeaders(options.headers);
  const algorithm = resolveJwsAlgorithm(options.algorithm, headers);
  const payload = normalizeJwsPayload(options.payload);

  return {
    payload,
    algorithm,
    secret,
    headers: { ...headers, alg: algorithm },
    detached,
  };
}

export function toNativeJwsFetchOptions(
  jws: JwsFetchOptions
): NativeGenerateJWSOptions {
  const secret = validateJwsSecret(jws.secret);
  const headers = validateJwsHeaders(jws.headers);
  const algorithm = resolveJwsAlgorithm(jws.algorithm, headers);

  return {
    payload: normalizeJwsPayload(jws.payload),
    algorithm,
    secret,
    headers: { ...headers, alg: algorithm },
    detached: jws.detached ?? false,
  };
}

export function assertCompactJwsShape(jws: string): void {
  const segments = jws.split('.');
  if (segments.length !== 3) {
    throw new Error(
      `Invalid compact JWS: expected 3 segments, got ${segments.length}`
    );
  }
}
