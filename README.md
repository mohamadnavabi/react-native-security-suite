# React Native Security Suite 🔒

[![npm version](https://badge.fury.io/js/react-native-security-suite.svg)](https://www.npmjs.com/package/react-native-security-suite)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Downloads](https://img.shields.io/npm/dm/react-native-security-suite.svg)](https://www.npmjs.com/package/react-native-security-suite)

**Comprehensive security solutions for React Native applications** - Protect your mobile apps with advanced security features including root/jailbreak detection, SSL certificate pinning, encryption, secure storage, screenshot protection, and network monitoring.

<div style="display: flex; flex-direction: row; justify-content: center; align-items: center; gap: 20px;">
<img src="https://raw.githubusercontent.com/mohamadnavabi/react-native-security-suite/master/pulse.gif" alt="iOS Pulse Network Monitor" width="200" />
<img src="https://raw.githubusercontent.com/mohamadnavabi/react-native-security-suite/master/chucker.gif" alt="Android Chucker Network Monitor" width="200" />
</div>

## 🚀 Features

### Security Detection & Protection

- **Root Detection**: Detect rooted Android devices
- **Jailbreak Detection**: Detect jailbroken iOS devices
- **Screenshot Protection**: Prevent screenshots and screen recordings
- **SSL Certificate Pinning**: Secure network communications
- **Public Key Pinning**: Advanced certificate validation

### Data Security & Encryption

- **Text Encryption/Decryption**: Secure data encryption with multiple algorithms
- **Secure Storage**: Encrypted local storage with AsyncStorage integration
- **Diffie-Hellman Key Exchange**: Secure key generation and sharing
- **Hard & Soft Encryption**: Multiple encryption levels for different security needs

### Network Security & Monitoring

- **Network Logger**: Built-in request/response logging
- **Android Chucker Integration**: Advanced network debugging
- **iOS Pulse Integration**: Network monitoring for iOS
- **SSL Pinning with Custom Certificates**: Enhanced security for API calls

## 📱 Supported Platforms

- ✅ **Android** (API 21+)
- ✅ **iOS** (iOS 11.0+)
- ✅ **React Native** (0.60+)

## 🛠 Installation

### Using Yarn

```bash
yarn add react-native-security-suite
```

### Using NPM

```bash
npm install react-native-security-suite
```

### iOS Setup

```bash
cd ios && pod install
```

## 📖 Usage Examples

### 1. Root/Jailbreak Detection

Detect compromised devices to protect your app from security risks:

```javascript
import { deviceHasSecurityRisk } from 'react-native-security-suite';

const checkDeviceSecurity = async () => {
  const isRiskyDevice = await deviceHasSecurityRisk();

  if (isRiskyDevice) {
    console.log('⚠️ Device is rooted/jailbroken - Security risk detected');
    // Handle security risk - show warning or restrict features
  } else {
    console.log('✅ Device security check passed');
  }
};
```

### 2. Screenshot Protection

Protect sensitive content from screenshots and screen recordings:

```javascript
import { SecureView } from 'react-native-security-suite';

const SensitiveScreen = () => {
  return (
    <View style={styles.container}>
      <SecureView style={styles.secureContainer}>
        <Text style={styles.sensitiveText}>
          🔒 This content is protected from screenshots
        </Text>
        <TextInput
          placeholder="Enter sensitive information"
          secureTextEntry={true}
        />
      </SecureView>
    </View>
  );
};
```

### 3. Text Encryption & Decryption

Secure your data with multiple encryption methods:

```javascript
import { encrypt, decrypt } from 'react-native-security-suite';

const handleEncryption = async () => {
  // Soft encryption (faster, less secure)
  const softEncrypted = await encrypt('Sensitive data', false);
  console.log('Soft encrypted:', softEncrypted);

  const softDecrypted = await decrypt(softEncrypted, false);
  console.log('Soft decrypted:', softDecrypted);

  // Hard encryption (slower, more secure)
  const hardEncrypted = await encrypt('Highly sensitive data', true);
  console.log('Hard encrypted:', hardEncrypted);

  const hardDecrypted = await decrypt(hardEncrypted, true);
  console.log('Hard decrypted:', hardDecrypted);
};
```

### 4. Secure Storage

Store sensitive data securely with automatic encryption:

```javascript
import { SecureStorage } from 'react-native-security-suite';

const handleSecureStorage = async () => {
  try {
    // Store encrypted data
    await SecureStorage.setItem(
      'userToken',
      'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'
    );
    await SecureStorage.setItem(
      'userCredentials',
      JSON.stringify({
        username: 'user@example.com',
        password: 'encrypted_password',
      })
    );

    // Retrieve and decrypt data
    const token = await SecureStorage.getItem('userToken');
    const credentials = await SecureStorage.getItem('userCredentials');

    console.log('Retrieved token:', token);
    console.log('Retrieved credentials:', JSON.parse(credentials));

    // Remove sensitive data
    await SecureStorage.removeItem('userToken');
  } catch (error) {
    console.error('Secure storage error:', error);
  }
};
```

### 5. Diffie-Hellman Key Exchange

Implement secure key exchange for encrypted communications:

```javascript
import {
  getPublicKey,
  getSharedKey,
  encryptBySharedKey,
  decryptBySharedKey,
} from 'react-native-security-suite';

const handleKeyExchange = async () => {
  try {
    // Generate client public key
    const clientPublicKey = await getPublicKey();
    console.log('Client public key:', clientPublicKey);

    // Send to server and receive server's public key
    const serverPublicKey = 'SERVER_PUBLIC_KEY_FROM_API';

    // Generate shared secret key
    const sharedKey = await getSharedKey(serverPublicKey);
    console.log('Shared key generated:', sharedKey);

    // Encrypt data with shared key
    const encryptedMessage = await encryptBySharedKey('Secret message');
    console.log('Encrypted message:', encryptedMessage);

    // Decrypt data with shared key
    const decryptedMessage = await decryptBySharedKey(encryptedMessage);
    console.log('Decrypted message:', decryptedMessage);
  } catch (error) {
    console.error('Key exchange error:', error);
  }
};
```

### 6. SSL Certificate Pinning

Secure your API communications with certificate pinning:

```javascript
import { fetch } from 'react-native-security-suite';

const secureApiCall = async () => {
  try {
    const response = await fetch('https://api.yourapp.com/secure-endpoint', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer your-token',
      },
      body: JSON.stringify({
        userId: 123,
        action: 'sensitive_operation',
      }),
      certificates: [
        'sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
        'sha256/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=',
      ],
      validDomains: ['api.yourapp.com', 'secure.yourapp.com'],
      timeout: 10000,
    });

    const data = await response.json();
    console.log('Secure API response:', data);
  } catch (error) {
    console.error('SSL pinning failed:', error);
    // Handle certificate validation failure
  }
};
```

### 7. Network Monitoring & Debugging

Monitor network requests in development:

```javascript
import { fetch } from 'react-native-security-suite';

const monitoredRequest = async () => {
  try {
    const response = await fetch(
      'https://api.example.com/data',
      {
        method: 'GET',
        headers: {
          Accept: 'application/json',
        },
      },
      __DEV__
    ); // Enable logging in development

    return await response.json();
  } catch (error) {
    console.error('Network request failed:', error);
  }
};
```

## 🔧 API Reference

### Security Detection

- `deviceHasSecurityRisk()` - Detect rooted/jailbroken devices

### Encryption & Storage

- `encrypt(text, hardEncryption?, secretKey?)` - Encrypt text
- `decrypt(encryptedText, hardEncryption?, secretKey?)` - Decrypt text
- `SecureStorage` - Encrypted storage methods

### Key Exchange

- `getPublicKey()` - Generate public key
- `getSharedKey(serverPublicKey)` - Generate shared key
- `encryptBySharedKey(text)` - Encrypt with shared key
- `decryptBySharedKey(encryptedText)` - Decrypt with shared key

### Network Security

- `fetch(url, options, loggerEnabled?)` - Secure fetch with SSL pinning

### UI Components

- `SecureView` - Screenshot-protected view component

## 🛡️ Security Best Practices

1. **Always validate certificates** - Use SSL pinning for production APIs
2. **Detect compromised devices** - Check for root/jailbreak before sensitive operations
3. **Use appropriate encryption levels** - Hard encryption for highly sensitive data
4. **Protect sensitive UI** - Wrap sensitive content in SecureView
5. **Monitor network traffic** - Use built-in logging for debugging
6. **Secure key management** - Implement proper key exchange protocols

## 🐛 Troubleshooting

### Common Issues

**iOS Build Errors:**

```bash
cd ios && pod install && cd ..
npx react-native run-ios
```

**Android Build Errors:**

```bash
cd android && ./gradlew clean && cd ..
npx react-native run-android
```

**Metro Cache Issues:**

```bash
npx react-native start --reset-cache
```

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Setup

```bash
git clone https://github.com/mohamadnavabi/react-native-security-suite.git
cd react-native-security-suite
yarn install
cd example && yarn install && cd ..
yarn example android # or ios
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [Chucker](https://github.com/ChuckerTeam/chucker) for Android network monitoring
- [Pulse](https://github.com/kean/Pulse) for iOS network monitoring
- React Native community for continuous support

## 📞 Support

- 📧 Email: 7navabi@gmail.com
- 🐛 Issues: [GitHub Issues](https://github.com/mohamadnavabi/react-native-security-suite/issues)
- 📖 Documentation: [GitHub Wiki](#)

---

**Made with ❤️ for the React Native community**
