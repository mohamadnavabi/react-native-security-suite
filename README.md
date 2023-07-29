# react-native-security-suite

Security solutions for Android and iOS
SSL Pinning
A native implementation encryption/decryption
Root/Jailbreak detection

## Installation

```sh
yarn add react-native-security-suite
```

```sh
npm install react-native-security-suite
```

## Usage

```js
import {
  getPublicKey,
  getSharedKey,
  encryptBySharedKey,
  decryptBySharedKey,
  encrypt,
  decrypt,
  deviceHasSecurityRisk,
  fetch,
} from 'react-native-security-suite';

// SSL Pinning
const response = await fetch('URL', {
  body: {},
  headers: {},
  certificates: [
    /* certs */
  ],
  validDomains: [
    /* your valid domain */
  ],
  timeout: 6000,
});
let responseJson = await response.json();
console.log('SSL Pinning server response: ', responseJson);

// ------- OR --------

// Hard Encrypt/Decrypt with sharedKey
const publicKey = await getPublicKey();
console.log('Public key: ', publicKey);
/*
 * Sending the publicKey to the server and receiving the SERVER_PUBLIC_KEY
 * Using the SERVER_PUBLIC_KEY to generate sharedKey
 */
const sharedKey = await getSharedKey('SERVER_PUBLIC_KEY');
console.log('Shared key: ', sharedKey);
// Encrypt/Decrypt by sharedKey
const hardEncrypted = await encryptBySharedKey('STR_FOR_ENCRYPT');
console.log('Encrypted result: ', hardEncrypted);
const hardDecrypted = await decryptBySharedKey('STR_FOR_DECRYPT');
console.log('Decrypted result: ', hardDecrypted);

// ------- OR --------

// Soft Encrypt/Decrypt without sharedKey
const softEncrypted = await encrypt('STR_FOR_ENCRYPT');
console.log('Encrypted result: ', softEncrypted);
const softDecrypted = await decrypt('STR_FOR_DECRYPT');
console.log('Decrypted result: ', softDecrypted);

// Root/Jailbreak detection
const isRiskyDevice = await deviceHasSecurityRisk();
console.log('Root/Jailbreak detection result: ', isRiskyDevice);
```

## Contributing

See the [contributing guide](CONTRIBUTING.md) to learn how to contribute to the repository and the development workflow.

## License

MIT
