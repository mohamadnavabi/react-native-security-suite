import * as React from 'react';

import { StyleSheet, View, Text } from 'react-native';
import { deviceHasSecurityRisk } from 'react-native-security-suite';

export default function App() {
  const [hasRisk, setHasRisk] = React.useState<boolean | undefined>();

  React.useEffect(() => {
    deviceHasSecurityRisk().then(setHasRisk);
  }, []);

  return (
    <View style={styles.container}>
      <Text>Has risk: {hasRisk}</Text>
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
