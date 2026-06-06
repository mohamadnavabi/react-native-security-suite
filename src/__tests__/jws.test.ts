import crypto from 'crypto';

import {
  assertCompactJwsShape,
  isEmptyJwsPayload,
  normalizeJwsPayload,
  resolveJwsAlgorithm,
  toNativeGenerateJWSOptions,
  validateJwsAlgorithm,
  validateJwsHeaders,
  validateJwsSecret,
  type JwsPayload,
} from '../jws';

function base64UrlEncode(input: string | Uint8Array): string {
  return Buffer.from(input)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

function buildProtectedHeader(
  algorithm: string,
  headers: Record<string, string | number | boolean | null> = {}
): string {
  const protectedHeader = { alg: algorithm, ...headers };
  const sorted = Object.keys(protectedHeader)
    .sort()
    .reduce<Record<string, unknown>>((acc, key) => {
      acc[key] = protectedHeader[key as keyof typeof protectedHeader];
      return acc;
    }, {});
  return base64UrlEncode(JSON.stringify(sorted));
}

function signJws(
  algorithm: 'HS256' | 'HS384' | 'HS512',
  secret: string,
  protectedHeader: string,
  payloadString: string
): string {
  const encodedPayload = payloadString
    ? base64UrlEncode(payloadString)
    : '';
  const signingInput = `${protectedHeader}.${encodedPayload}`;
  const hash = algorithm === 'HS384' ? 'sha384' : algorithm === 'HS512' ? 'sha512' : 'sha256';
  const signature = crypto
    .createHmac(hash, secret)
    .update(signingInput, 'utf8')
    .digest();
  const encodedSignature = base64UrlEncode(new Uint8Array(signature));
  return `${protectedHeader}.${encodedPayload}.${encodedSignature}`;
}

describe('normalizeJwsPayload', () => {
  it.each([
    [undefined, ''],
    [null, ''],
    ['', ''],
  ])('treats %p as empty payload', (payload, expected) => {
    expect(normalizeJwsPayload(payload)).toBe(expected);
  });

  it('uses string payload as-is', () => {
    expect(normalizeJwsPayload('null')).toBe('null');
    expect(normalizeJwsPayload('undefined')).toBe('undefined');
  });

  it('JSON-stringifies objects and arrays without mutation', () => {
    const payload = { amount: 1000 };
    expect(normalizeJwsPayload(payload)).toBe('{"amount":1000}');
    expect(payload).toEqual({ amount: 1000 });
  });

  it('JSON-stringifies numbers and booleans', () => {
    expect(normalizeJwsPayload(42)).toBe('42');
    expect(normalizeJwsPayload(true)).toBe('true');
  });
});

describe('isEmptyJwsPayload', () => {
  it('identifies empty payload cases', () => {
    expect(isEmptyJwsPayload(undefined)).toBe(true);
    expect(isEmptyJwsPayload(null)).toBe(true);
    expect(isEmptyJwsPayload('')).toBe(true);
    expect(isEmptyJwsPayload('null')).toBe(false);
  });
});

describe('resolveJwsAlgorithm', () => {
  it('defaults to HS256 when algorithm is omitted', () => {
    expect(resolveJwsAlgorithm(undefined, { kid: 'test-key' })).toBe('HS256');
  });

  it('uses headers.alg when options.algorithm is omitted', () => {
    expect(resolveJwsAlgorithm(undefined, { alg: 'HS384', kid: 'test-key' })).toBe(
      'HS384'
    );
  });

  it('throws on algorithm mismatch', () => {
    expect(() =>
      resolveJwsAlgorithm('HS512', { alg: 'HS256' })
    ).toThrow('algorithm mismatch');
  });
});

describe('validateJwsSecret', () => {
  it('requires a non-empty secret', () => {
    expect(() => validateJwsSecret('')).toThrow('secret is required');
    expect(() => validateJwsSecret('   ')).toThrow('secret is required');
    expect(validateJwsSecret('secret')).toBe('secret');
  });
});

describe('validateJwsHeaders', () => {
  it('accepts JSON-serializable primitives', () => {
    expect(
      validateJwsHeaders({
        kid: 'test-key',
        count: 1,
        enabled: true,
        note: null,
      })
    ).toEqual({
      kid: 'test-key',
      count: 1,
      enabled: true,
      note: null,
    });
  });

  it('rejects non-primitive header values', () => {
    expect(() => validateJwsHeaders({ kid: { nested: true } })).toThrow(
      'JSON-serializable primitives'
    );
  });
});

describe('toNativeGenerateJWSOptions', () => {
  it('normalizes empty payload options', () => {
    const native = toNativeGenerateJWSOptions({
      algorithm: 'HS256',
      secret: 'secret',
      headers: { kid: 'test-key' },
    });

    expect(native.payload).toBe('');
    expect(native.algorithm).toBe('HS256');
    expect(native.headers.alg).toBe('HS256');
    expect(native.detached).toBe(false);
  });
});

describe('compact JWS reference vectors', () => {
  const secret = 'secret';
  const headers = { kid: 'test-key' };

  const emptyPayloadCases: Array<JwsPayload | undefined> = [
    undefined,
    null,
    '',
  ];

  it.each(emptyPayloadCases)(
    'produces three segments with empty middle payload for %p',
    (payload) => {
      const native = toNativeGenerateJWSOptions({
        payload,
        algorithm: 'HS256',
        secret,
        headers,
      });
      const protectedHeader = buildProtectedHeader('HS256', headers);
      const expected = signJws('HS256', secret, protectedHeader, '');
      const segments = expected.split('.');

      expect(segments).toHaveLength(3);
      expect(segments[1]).toBe('');
      expect(expected).toContain('..');
      assertCompactJwsShape(expected);
      expect(native.payload).toBe('');
    }
  );

  it('encodes string "null" and "undefined" as non-empty payload segments', () => {
    for (const payload of ['null', 'undefined']) {
      const protectedHeader = buildProtectedHeader('HS256', headers);
      const expected = signJws('HS256', secret, protectedHeader, payload);
      const segments = expected.split('.');

      expect(segments[1]).toBe(base64UrlEncode(payload));
      expect(segments[1]).not.toBe('');
    }
  });

  it('encodes object payload as base64url JSON', () => {
    const payload = { amount: 1000 };
    const payloadString = JSON.stringify(payload);
    const protectedHeader = buildProtectedHeader('HS256', headers);
    const expected = signJws('HS256', secret, protectedHeader, payloadString);

    expect(expected.split('.')[1]).toBe(base64UrlEncode(payloadString));
    assertCompactJwsShape(expected);
  });

  it('throws for unsupported algorithms', () => {
    expect(() => validateJwsAlgorithm('RS256')).toThrow('Unsupported JWS algorithm');
  });
});
