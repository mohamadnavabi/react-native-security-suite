/**
 * Input guards for the secure storage bridge.
 *
 * The native keychain APIs are handed the key and value verbatim, and a nil
 * string there aborts the process instead of raising a catchable error. Callers
 * regularly pass `undefined` by accident (an API response missing a field, for
 * example), so every value is checked here before it reaches the bridge.
 *
 * The thrown messages carry only the detail — the calling wrapper prefixes them
 * with `Secure storage operation failed (<operation>)`.
 */

function describe(input: unknown): string {
  if (input === null) return 'null';
  if (input === undefined) return 'undefined';
  if (typeof input === 'string') return 'a blank string';
  return `a ${typeof input}`;
}

export function assertKey(key: unknown): asserts key is string {
  if (typeof key !== 'string' || key.trim().length === 0) {
    throw new Error(
      `a non-empty string key is required, received ${describe(key)}`
    );
  }
}

export function assertValue(value: unknown): asserts value is string {
  if (typeof value !== 'string') {
    throw new Error(`a string value is required, received ${describe(value)}`);
  }
}

export function assertKeys(keys: unknown): asserts keys is string[] {
  if (!Array.isArray(keys)) {
    throw new Error(`an array of keys is required, received ${describe(keys)}`);
  }
  keys.forEach(assertKey);
}

export function assertPairs(
  pairs: unknown
): asserts pairs is Array<[string, string]> {
  if (!Array.isArray(pairs)) {
    throw new Error(
      `an array of [key, value] pairs is required, received ${describe(pairs)}`
    );
  }
  pairs.forEach((pair) => {
    if (!Array.isArray(pair) || pair.length !== 2) {
      throw new Error(
        `each entry must be a [key, value] pair, received ${describe(pair)}`
      );
    }
    assertKey(pair[0]);
    assertValue(pair[1]);
  });
}

/** Formats the error a storage operation rejects with. */
export function storageFailure(operation: string, error: unknown): Error {
  const detail =
    error instanceof Error
      ? error.message
      : typeof error === 'string'
        ? error
        : 'Unknown error';
  return new Error(`Secure storage operation failed (${operation}): ${detail}`);
}

/** Validates arguments up front, prefixing any failure with the operation. */
export function checkInput(operation: string, assert: () => void): void {
  try {
    assert();
  } catch (error: unknown) {
    throw storageFailure(operation, error);
  }
}

/**
 * Runs a storage call, turning both synchronous input errors and native
 * rejections into a single rejected promise. Nothing here throws synchronously.
 */
export function guardStorage<T>(
  operation: string,
  call: () => Promise<T>
): Promise<T> {
  try {
    return Promise.resolve(call()).catch((error: unknown) => {
      throw storageFailure(operation, error);
    });
  } catch (error: unknown) {
    return Promise.reject(storageFailure(operation, error));
  }
}
