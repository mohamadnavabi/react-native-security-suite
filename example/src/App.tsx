import { useEffect } from 'react';

import {
  StyleSheet,
  View,
  Text,
  PermissionsAndroid,
  Platform,
} from 'react-native';
import {
  getPublicKey,
  // getSharedKey,
  // encryptBySharedKey,
  // decryptBySharedKey,
  encrypt,
  decrypt,
  deviceHasSecurityRisk,
  fetch,
  SecureStorage,
  setScreenshotGuard,
} from 'react-native-security-suite';

export default function App() {
  useEffect(() => {
    // Request permission for the network logger notification
    requestNotificationPermission();

    (async () => {
      try {
        fetch(
          'https://reqres.in/api/users?page=2',
          {
            method: 'GET', // or any http methods
            headers: {
              'Content-Type': 'application/json',
            },
            // body: {},
            // certificates: [
            //   'sha256/XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX=',
            // ],
            // validDomains: ['reqres.in'],
            timeout: 6000,
          },
          __DEV__
        )
          .then((response) => console.log(response.json()))
          .catch((error) => console.log(error));

        // Root/Jailbreak detection
        const isRiskyDevice = await deviceHasSecurityRisk();
        console.log('Root/Jailbreak detection result: ', isRiskyDevice);

        // Disable capture/screenshot
        setScreenshotGuard(true);

        // SecureStorage
        SecureStorage.setItem('key', 'value');
        console.log(`Stored value is: ${await SecureStorage.getItem('key')}`);

        // Soft Encrypt/Decrypt without sharedKey
        const softEncrypted = await encrypt('ENCRYPTED_STR');
        console.log('Encrypted result: ', softEncrypted);
        const softDecrypted = await decrypt(softEncrypted);
        console.log('Decrypted result: ', softDecrypted);

        // Key exchange
        const publicKey = await getPublicKey('p256');
        console.log('Public key: ', publicKey);
        /*
         * Sending the publicKey to the server and receiving the SERVER_PUBLIC_KEY
         * Using the SERVER_PUBLIC_KEY to generate sharedKey
         */
        // const sharedKey = await getSharedKey('SERVER_PUBLIC_KEY');
        // console.log('Shared key: ', sharedKey);
        // Encrypt/Decrypt by sharedKey
        //   const hardEncrypted = await encryptBySharedKey('STR_FOR_ENCRYPT');
        //   console.log('Encrypted result: ', hardEncrypted);
        //   const hardDecrypted = await decryptBySharedKey('STR_FOR_DECRYPT');
        //   console.log('Decrypted result: ', hardDecrypted);
      } catch (error) {
        console.error('Catch error: ', error);
      }
    })();
  }, []);

  const requestNotificationPermission = async () => {
    if (Platform.OS === 'android') {
      try {
        PermissionsAndroid.check('android.permission.POST_NOTIFICATIONS')
          .then((response) => {
            if (!response) {
              PermissionsAndroid.request(
                'android.permission.POST_NOTIFICATIONS',
                {
                  title: 'Notification',
                  message:
                    'App needs access to your notification ' +
                    'so you can get Updates',
                  buttonNeutral: 'Ask Me Later',
                  buttonNegative: 'Cancel',
                  buttonPositive: 'OK',
                }
              );
            }
          })
          .catch((err) => {
            console.log('Notification Error=====>', err);
          });
      } catch (err) {
        console.log(err);
      }
    }
  };

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
