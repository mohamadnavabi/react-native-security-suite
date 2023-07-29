import React, { useEffect } from 'react';

import { StyleSheet, View, Text } from 'react-native';
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

export default function App() {
  useEffect(() => {
    (async () => {
      try {
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

        // Soft Encrypt/Decrypt without sharedKey
        const softEncrypted = await encrypt('STR_FOR_ENCRYPT');
        console.log('Encrypted result: ', softEncrypted);
        const softDecrypted = await decrypt('STR_FOR_DECRYPT');
        console.log('Decrypted result: ', softDecrypted);

        // Root/Jailbreak detection
        const isRiskyDevice = await deviceHasSecurityRisk();
        console.log('Root/Jailbreak detection result: ', isRiskyDevice);
      } catch (error) {
        console.error('Catch error: ', error);
      }
    })();
  }, []);

  return (
    <View style={styles.container}>
      <Text>Security solutions for Android and iOS</Text>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    alignItems: 'center',
    justifyContent: 'center',
  },
  box: {
    width: 60,
    height: 60,
    marginVertical: 20,
  },
});
