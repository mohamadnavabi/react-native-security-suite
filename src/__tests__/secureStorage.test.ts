jest.mock('react-native', () => ({
  NativeModules: {
    SecuritySuite: {
      secureStorageSetItem: jest.fn().mockResolvedValue(null),
      secureStorageGetItem: jest.fn().mockResolvedValue('value'),
      secureStorageRemoveItem: jest.fn().mockResolvedValue(null),
      secureStorageGetAllKeys: jest.fn().mockResolvedValue(['key']),
      secureStorageClear: jest.fn().mockResolvedValue(null),
    },
  },
  Platform: {
    OS: 'ios',
    select: jest.fn((options: { ios?: unknown; default?: unknown }) => options.ios),
  },
  requireNativeComponent: jest.fn(() => 'SecureView'),
  UIManager: {
    getViewManagerConfig: jest.fn(),
    dispatchViewManagerCommand: jest.fn(),
  },
  findNodeHandle: jest.fn(),
}));

import { NativeModules } from 'react-native';
import { SecureStorage } from '../index';

const mockSecureStorage = NativeModules.SecuritySuite as {
  secureStorageSetItem: jest.Mock;
  secureStorageGetItem: jest.Mock;
  secureStorageRemoveItem: jest.Mock;
  secureStorageGetAllKeys: jest.Mock;
  secureStorageClear: jest.Mock;
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
