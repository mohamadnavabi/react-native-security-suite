# react-native-security-suite

React Native security solutions for both Android and iOS

<ol>
<li>SSL Pinning</li>
<li>Secure storage</li>
<li>Encryption/Decryption</li>
<li>Root/Jailbreak detection</li>
</ol>

## Installation

```sh
yarn add react-native-security-suite
```

```sh
npm install react-native-security-suite
```

## Usage

1. SSL Pinning example:

```js
import { fetch } from 'react-native-security-suite';

const response = await fetch('URL', {
  method: 'GET',
  body: {},
  headers: {},
  certificates: [
    /* certificates */
  ],
  validDomains: [
    /* your valid domains */
  ],
  timeout: 6000,
});
console.log('server response: ', response.json());
```

\
2. Secure storage example:

```js
import { SecureStorage } from 'react-native-security-suite';

SecureStorage.setItem('key', 'value');
console.log(await SecureStorage.getItem('key'));
```

\
3. Encryption/Decryption example(with key exchange or without key exchange):

```js
import {
  getPublicKey,
  getSharedKey,
  encryptBySharedKey,
  decryptBySharedKey,
  encrypt,
  decrypt,
} from 'react-native-security-suite';

// Hard Encrypt/Decrypt with sharedKey
const publicKey = await getPublicKey();
console.log('Public key: ', publicKey);
/*
 * Sending the publicKey to the server and receiving the SERVER_PUBLIC_KEY
 * Using the SERVER_PUBLIC_KEY to generate sharedKey
 */
const sharedKey = await getSharedKey('SERVER_PUBLIC_KEY');
console.log('Shared key: ', sharedKey);

// 1. Hard Encrypt/Decrypt by sharedKey
const hardEncrypted = await encryptBySharedKey('STR_FOR_ENCRYPT');
console.log('Encrypted result: ', hardEncrypted);
const hardDecrypted = await decryptBySharedKey('STR_FOR_DECRYPT');
console.log('Decrypted result: ', hardDecrypted);

// ------- OR --------

// 2. Soft Encrypt/Decrypt without sharedKey
const softEncrypted = await encrypt('STR_FOR_ENCRYPT');
console.log('Encrypted result: ', softEncrypted);
const softDecrypted = await decrypt('STR_FOR_DECRYPT');
console.log('Decrypted result: ', softDecrypted);
```

\
4. Root/Jailbreak detection example:

```js
import { deviceHasSecurityRisk } from 'react-native-security-suite';

const isRiskyDevice = await deviceHasSecurityRisk();
console.log('Root/Jailbreak detection result: ', isRiskyDevice);
```

## Contributing

See the [contributing guide](CONTRIBUTING.md) to learn how to contribute to the repository and the development workflow.

## License

MIT
