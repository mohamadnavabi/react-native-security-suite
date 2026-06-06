package com.securitysuite.security;

import android.content.Context;
import android.hardware.Sensor;
import android.hardware.SensorManager;
import android.os.Build;

import com.facebook.react.bridge.Arguments;
import com.facebook.react.bridge.WritableArray;
import com.facebook.react.bridge.WritableMap;
import com.scottyab.rootbeer.RootBeer;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Emulator and device environment detection (Android).
 */
public final class EmulatorDetector {
  private EmulatorDetector() {}

  public static WritableMap detect(Context context) {
    WritableMap result = Arguments.createMap();
    List<String> indicators = new ArrayList<>();

    collectBuildIndicators(indicators);
    collectQemuIndicators(indicators);
    collectTelephonyIndicators(indicators);
    collectSensorIndicators(context, indicators);

    RootBeer rootBeer = new RootBeer(context);
    if (rootBeer.isEmulator()) {
      indicators.add("RootBeer.isEmulator");
    }

    result.putBoolean("isEmulator", !indicators.isEmpty());
    result.putBoolean("isSimulator", false);
    result.putArray("indicators", toStringArray(indicators));
    return result;
  }

  private static void collectBuildIndicators(List<String> indicators) {
    String fingerprint = safeLower(Build.FINGERPRINT);
    String model = safeLower(Build.MODEL);
    String manufacturer = safeLower(Build.MANUFACTURER);
    String hardware = safeLower(Build.HARDWARE);
    String product = safeLower(Build.PRODUCT);
    String brand = safeLower(Build.BRAND);
    String device = safeLower(Build.DEVICE);

    if (containsAny(fingerprint, "generic", "unknown", "test-keys", "emulator")) {
      indicators.add("Build.FINGERPRINT");
    }
    if (containsAny(model, "google_sdk", "emulator", "android sdk built for x86", "sdk_gphone")) {
      indicators.add("Build.MODEL");
    }
    if (containsAny(manufacturer, "genymotion", "unknown")) {
      indicators.add("Build.MANUFACTURER");
    }
    if (containsAny(hardware, "goldfish", "ranchu", "qemu")) {
      indicators.add("Build.HARDWARE");
    }
    if (containsAny(product, "sdk", "google_sdk", "sdk_gphone", "vbox")) {
      indicators.add("Build.PRODUCT");
    }
    if (containsAny(brand, "generic")) {
      indicators.add("Build.BRAND");
    }
    if (containsAny(device, "generic", "emu64a", "goldfish")) {
      indicators.add("Build.DEVICE");
    }
  }

  private static void collectQemuIndicators(List<String> indicators) {
    String qemu = getSystemProperty("ro.kernel.qemu");
    if ("1".equals(qemu)) {
      indicators.add("ro.kernel.qemu");
    }

    String[] props = {
        "ro.hardware",
        "ro.product.device",
        "ro.product.model",
        "ro.product.name"
    };
    for (String prop : props) {
      String value = safeLower(getSystemProperty(prop));
      if (containsAny(value, "goldfish", "ranchu", "qemu", "sdk_gphone", "emulator")) {
        indicators.add(prop);
      }
    }
  }

  private static void collectTelephonyIndicators(List<String> indicators) {
    String telephony = getSystemProperty("ro.telephony.call_ring.multiple");
    if (telephony != null && !telephony.isEmpty()) {
      indicators.add("ro.telephony.call_ring.multiple");
    }
  }

  private static void collectSensorIndicators(Context context, List<String> indicators) {
    SensorManager sensorManager = (SensorManager) context.getSystemService(Context.SENSOR_SERVICE);
    if (sensorManager == null) {
      indicators.add("SensorManager unavailable");
      return;
    }

    Sensor accelerometer = sensorManager.getDefaultSensor(Sensor.TYPE_ACCELEROMETER);
    Sensor gyroscope = sensorManager.getDefaultSensor(Sensor.TYPE_GYROSCOPE);
    if (accelerometer == null) {
      indicators.add("Missing accelerometer");
    }
    if (gyroscope == null) {
      indicators.add("Missing gyroscope");
    }
  }

  private static String getSystemProperty(String key) {
    try {
      Class<?> systemProperties = Class.forName("android.os.SystemProperties");
      return (String) systemProperties
          .getMethod("get", String.class)
          .invoke(null, key);
    } catch (Exception ignored) {
      return null;
    }
  }

  private static boolean containsAny(String value, String... needles) {
    if (value == null || value.isEmpty()) {
      return false;
    }
    for (String needle : needles) {
      if (value.contains(needle)) {
        return true;
      }
    }
    return false;
  }

  private static String safeLower(String value) {
    return value == null ? "" : value.toLowerCase(Locale.US);
  }

  private static WritableArray toStringArray(List<String> values) {
    WritableArray array = Arguments.createArray();
    for (String value : values) {
      array.pushString(value);
    }
    return array;
  }
}
