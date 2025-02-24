# react-native-security-suite

Security solutions for React Native both platform Android and iOS
You can use any of the following:

<ol><li>Android Root device or iOS Jailbreak device detection</li><li>Disable screenshot or screen record</li><li>Text Encryption/Decryption</li><li>Secure storage</li><li>Diffie–Hellman key exchange</li><li>SSL Pinning &amp; public key pinning</li><li>Network Logger (Android Chucker - iOS Pulse)</li></ol>

<div style="display: flex; flex-direction: row;">
<img src="https://raw.githubusercontent.com/mohamadnavabi/react-native-security-suite/master/pulse.png" />
<img src="https://raw.githubusercontent.com/mohamadnavabi/react-native-security-suite/master/chucker.gif" />
</div>

## Installation

```sh
yarn add react-native-security-suite @react-native-async-storage/async-storage
```

```sh
npm install react-native-security-suite @react-native-async-storage/async-storage
```

## Usage

1. Android Root or iOS Jailbreak devices detection example:

```js
import { deviceHasSecurityRisk } from 'react-native-security-suite';

const isRiskyDevice = await deviceHasSecurityRisk();
console.log('Root/Jailbreak detection result: ', isRiskyDevice);
```

2\. Disable capture/screenshot:

```js
import { SecureView } from 'react-native-security-suite';

<View style={styles.container}>
  <SecureView>
    <Text>Protect this from screenshot or screen record</Text>
  </SecureView>
</View>;
```

3\. Text Encryption/Decryption example:

```js
const softEncrypted = await encrypt('STR_FOR_ENCRYPT');
console.log('Encrypted result: ', softEncrypted);
const softDecrypted = await decrypt('STR_FOR_DECRYPT');
console.log('Decrypted result: ', softDecrypted);
```

4\. Secure storage example:

```js
import { SecureStorage } from 'react-native-security-suite';

SecureStorage.setItem('key', 'value');
console.log(await SecureStorage.getItem('key'));
```

5\. Diffie–Hellman key exchange:

```js
import {
  getPublicKey,
  getSharedKey,
  encryptBySharedKey,
  decryptBySharedKey,
  encrypt,
  decrypt,
} from 'react-native-security-suite';

const publicKey = await getPublicKey();
console.log('Public key: ', publicKey);
/*
 * Sending the publicKey to the server and receiving the SERVER_PUBLIC_KEY
 * Using the SERVER_PUBLIC_KEY to generate sharedKey
 */
const sharedKey = await getSharedKey('SERVER_PUBLIC_KEY');
console.log('Shared key: ', sharedKey);

const hardEncrypted = await encryptBySharedKey('STR_FOR_ENCRYPT');
console.log('Encrypted result: ', hardEncrypted);
const hardDecrypted = await decryptBySharedKey('STR_FOR_DECRYPT');
console.log('Decrypted result: ', hardDecrypted);
```

6\. SSL Pinning with network logger:

```js
import { fetch } from 'react-native-security-suite';

const response = await fetch('https://example.com/api', {
  method: 'POST', // or any http methods
  headers: {
    'Content-Type': 'application/json',
  },
  body: {
    key: value,
  },
  certificates: ['sha256/XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX='],
  validDomains: ['example.com'],
  timeout: 6000,
});
console.log('server response: ', response.json());
```

7\. Network Logger (Android Chucker - iOS Pulse):

```js
import { fetch } from 'react-native-security-suite';

fetch(YOUR_REQUEST, __DEV__);
```

## Contributing

See the [contributing guide](CONTRIBUTING.md) to learn how to contribute to the repository and the development workflow.

## License

MIT
