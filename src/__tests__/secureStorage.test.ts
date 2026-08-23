jest.mock('react-native', () => ({
  NativeModules: {
    SecuritySuite: {
      secureStorageSetItem: jest.fn().mockResolvedValue(null),
      secureStorageGetItem: jest.fn().mockResolvedValue('value'),
      secureStorageRemoveItem: jest.fn().mockResolvedValue(null),
      secureStorageGetAllKeys: jest.fn().mockResolvedValue(['key']),
      secureStorageClear: jest.fn().mockResolvedValue(null),
      secureStorageSetItemBiometric: jest.fn().mockResolvedValue(null),
      secureStorageGetItemBiometric: jest.fn().mockResolvedValue('value'),
    },
  },
  Platform: {
    OS: 'ios',
    select: jest.fn(
      (options: { ios?: unknown; default?: unknown }) => options.ios
    ),
  },
  requireNativeComponent: jest.fn(() => 'SecureView'),
  UIManager: {
    getViewManagerConfig: jest.fn(),
    dispatchViewManagerCommand: jest.fn(),
  },
  findNodeHandle: jest.fn(),
}));

import { NativeModules } from 'react-native';
import { SecureStorage, Storage } from '../index';

const mockSecureStorage = NativeModules.SecuritySuite as {
  secureStorageSetItem: jest.Mock;
  secureStorageGetItem: jest.Mock;
  secureStorageRemoveItem: jest.Mock;
  secureStorageGetAllKeys: jest.Mock;
  secureStorageClear: jest.Mock;
  secureStorageSetItemBiometric: jest.Mock;
  secureStorageGetItemBiometric: jest.Mock;
};

describe('SecureStorage', () => {
  beforeEach(() => {
    mockSecureStorage.secureStorageSetItem.mockResolvedValue(null);
    mockSecureStorage.secureStorageGetItem.mockResolvedValue('value');
    mockSecureStorage.secureStorageRemoveItem.mockResolvedValue(null);
    mockSecureStorage.secureStorageGetAllKeys.mockResolvedValue(['key']);
    mockSecureStorage.secureStorageClear.mockResolvedValue(null);
  });

  it('delegates setItem to native module', async () => {
    await SecureStorage.setItem('token', 'secret');
    expect(mockSecureStorage.secureStorageSetItem).toHaveBeenCalledWith(
      'token',
      'secret'
    );
  });

  it('rejects with a security-related message when native setItem fails', async () => {
    mockSecureStorage.secureStorageSetItem.mockRejectedValue(
      new Error('KeyStore unavailable')
    );

    await expect(SecureStorage.setItem('token', 'secret')).rejects.toThrow(
      'Secure storage operation failed (setItem): KeyStore unavailable'
    );
  });

  it('rejects with a security-related message when native getItem fails', async () => {
    mockSecureStorage.secureStorageGetItem.mockRejectedValue('native failure');

    await expect(SecureStorage.getItem('token')).rejects.toThrow(
      'Secure storage operation failed (getItem): native failure'
    );
  });
});

describe('SecureStorage input validation', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockSecureStorage.secureStorageSetItem.mockResolvedValue(null);
    mockSecureStorage.secureStorageGetItem.mockResolvedValue('value');
    mockSecureStorage.secureStorageRemoveItem.mockResolvedValue(null);
  });

  it.each([
    ['undefined', undefined],
    ['null', null],
  ])(
    'rejects setItem when the value is %s instead of reaching the bridge',
    async (label, value) => {
      await expect(
        SecureStorage.setItem('token', value as unknown as string)
      ).rejects.toThrow(
        `Secure storage operation failed (setItem): a string value is required, received ${label}`
      );
      expect(mockSecureStorage.secureStorageSetItem).not.toHaveBeenCalled();
    }
  );

  it.each([
    ['undefined', undefined],
    ['null', null],
    ['a blank string', '   '],
  ])('rejects setItem when the key is %s', async (label, key) => {
    await expect(
      SecureStorage.setItem(key as unknown as string, 'secret')
    ).rejects.toThrow(
      `Secure storage operation failed (setItem): a non-empty string key is required, received ${label}`
    );
    expect(mockSecureStorage.secureStorageSetItem).not.toHaveBeenCalled();
  });

  it('rejects getItem and removeItem for a missing key', async () => {
    await expect(
      SecureStorage.getItem(undefined as unknown as string)
    ).rejects.toThrow(
      'Secure storage operation failed (getItem): a non-empty string key is required, received undefined'
    );
    await expect(
      SecureStorage.removeItem(null as unknown as string)
    ).rejects.toThrow(
      'Secure storage operation failed (removeItem): a non-empty string key is required, received null'
    );
    expect(mockSecureStorage.secureStorageGetItem).not.toHaveBeenCalled();
    expect(mockSecureStorage.secureStorageRemoveItem).not.toHaveBeenCalled();
  });

  it('rejects multiSet when a pair carries a missing value', async () => {
    await expect(
      SecureStorage.multiSet([['token', undefined as unknown as string]])
    ).rejects.toThrow(
      'Secure storage operation failed (multiSet): a string value is required, received undefined'
    );
    expect(mockSecureStorage.secureStorageSetItem).not.toHaveBeenCalled();
  });

  it('rejects multiGet and multiRemove when keys is not an array', async () => {
    await expect(
      SecureStorage.multiGet(undefined as unknown as string[])
    ).rejects.toThrow(
      'Secure storage operation failed (multiGet): an array of keys is required, received undefined'
    );
    await expect(
      SecureStorage.multiRemove(undefined as unknown as string[])
    ).rejects.toThrow(
      'Secure storage operation failed (multiRemove): an array of keys is required, received undefined'
    );
  });

  it('still writes when the value is an empty string', async () => {
    await SecureStorage.setItem('token', '');
    expect(mockSecureStorage.secureStorageSetItem).toHaveBeenCalledWith(
      'token',
      ''
    );
  });

  it('rejects instead of throwing synchronously', () => {
    const result = SecureStorage.setItem(
      'token',
      undefined as unknown as string
    );
    expect(result).toBeInstanceOf(Promise);
    return expect(result).rejects.toBeInstanceOf(Error);
  });
});

describe('Storage namespace input validation', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockSecureStorage.secureStorageSetItem.mockResolvedValue(null);
    mockSecureStorage.secureStorageGetItem.mockResolvedValue('value');
    mockSecureStorage.secureStorageGetAllKeys.mockResolvedValue(['key']);
  });

  it('rejects setItem with a missing value', async () => {
    await expect(
      Storage.setItem('token', undefined as unknown as string)
    ).rejects.toThrow(
      'Secure storage operation failed (setItem): a string value is required, received undefined'
    );
    expect(mockSecureStorage.secureStorageSetItem).not.toHaveBeenCalled();
  });

  it('rejects the biometric path with a missing value', async () => {
    await expect(
      Storage.setItem('token', undefined as unknown as string, {
        requireBiometric: true,
      })
    ).rejects.toThrow(
      'Secure storage operation failed (setItem): a string value is required, received undefined'
    );
    expect(
      mockSecureStorage.secureStorageSetItemBiometric
    ).not.toHaveBeenCalled();
  });

  it('rejects setItemWithExpiry with a missing key', async () => {
    await expect(
      Storage.setItemWithExpiry(
        undefined as unknown as string,
        'secret',
        new Date()
      )
    ).rejects.toThrow('a non-empty string key is required, received undefined');
    expect(mockSecureStorage.secureStorageSetItem).not.toHaveBeenCalled();
  });

  it('tolerates a native module that returns no keys', async () => {
    mockSecureStorage.secureStorageGetAllKeys.mockResolvedValue(null);
    await expect(Storage.getAllKeys()).resolves.toEqual([]);
  });
});
