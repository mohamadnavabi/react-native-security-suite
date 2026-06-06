import { useEffect, useState } from 'react';

import {
  StyleSheet,
  View,
  Text,
  PermissionsAndroid,
  Platform,
  ScrollView,
} from 'react-native';
import {
  getPublicKey,
  deviceHasSecurityRisk,
  fetch,
  SecureStorage,
  SecureView,
  SecuritySuite,
  RuntimeSecurity,
  AppIntegrity,
  DeviceSecurity,
} from 'react-native-security-suite';

export default function App() {
  const [reportSummary, setReportSummary] = useState(
    'Loading security report...'
  );

  useEffect(() => {
    // Request permission for the network logger notification
    requestNotificationPermission();

    (async () => {
      try {
        fetch(
          'https://reqres.in/api/users?page=2',
          {
            method: 'GET',
            headers: {
              'Content-Type': 'application/json',
            },
            timeout: 6000,
          },
          __DEV__
        )
          .then((response) => console.log(response.json()))
          .catch((error) => console.log(error));

        const isRiskyDevice = await deviceHasSecurityRisk();
        console.log('Root/Jailbreak detection result: ', isRiskyDevice);

        const runtime = await RuntimeSecurity.detect();
        console.log('Runtime detection: ', runtime);

        const integrity = await AppIntegrity.verify();
        console.log('App integrity: ', integrity);

        const environment = await DeviceSecurity.getEnvironment();
        console.log('Device environment: ', environment);

        const report = await SecuritySuite.getSecurityReport();
        console.log('Security report: ', report);
        setReportSummary(
          `Risk: ${report.riskLevel} (${report.riskScore}) · ` +
            `Root/JB: ${report.device.isRooted || report.device.isJailbroken} · ` +
            `Frida: ${report.runtime.fridaDetected} · ` +
            `Emulator: ${report.device.isEmulator || report.device.isSimulator}`
        );

        await SecureStorage.setItem('key', 'value');
        console.log(`Stored value is: ${await SecureStorage.getItem('key')}`);

        const publicKey = await getPublicKey();
        console.log('Public key: ', publicKey);
      } catch (error) {
        console.error('Catch error: ', error);
        setReportSummary(`Security check failed: ${String(error)}`);
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
      <SecureView>
        <ScrollView contentContainerStyle={styles.content}>
          <Text>Security solutions for Android and iOS</Text>
          <Text style={styles.report}>{reportSummary}</Text>
        </ScrollView>
      </SecureView>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    alignItems: 'center',
    justifyContent: 'center',
  },
  content: {
    alignItems: 'center',
    justifyContent: 'center',
    padding: 24,
    gap: 12,
  },
  report: {
    marginTop: 12,
    textAlign: 'center',
  },
});
