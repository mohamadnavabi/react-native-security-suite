package com.securitysuite.security;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

import android.os.Debug;

import com.facebook.react.bridge.Arguments;
import com.facebook.react.bridge.WritableArray;
import com.facebook.react.bridge.WritableMap;

/**
 * Native runtime instrumentation and debugger detection (Android).
 */
public final class RuntimeDetector {
  private static final int[] FRIDA_PORTS = {27042, 27043, 4444};
  private static final int PORT_CONNECT_TIMEOUT_MS = 300;
  private static final Set<String> SUSPICIOUS_MAP_KEYWORDS = new HashSet<>(Arrays.asList(
      "frida", "frida-agent", "frida-gadget", "linjector", "xposed", "lsposed",
      "substrate", "magisk", "zygisk", "libhooker"
  ));
  private static final Set<String> SUSPICIOUS_THREAD_NAMES = new HashSet<>(Arrays.asList(
      "gmain", "gdbus", "pool-frida", "frida-agent", "frida-server"
  ));

  private RuntimeDetector() {}

  public static WritableMap detect() {
    WritableMap result = Arguments.createMap();
    List<String> suspiciousLibraries = scanProcMaps();
    List<Integer> suspiciousPorts = scanFridaPorts();
    boolean fridaDetected = !suspiciousLibraries.isEmpty()
        || !suspiciousPorts.isEmpty()
        || hasSuspiciousThreads()
        || hasSuspiciousFileDescriptors();
    boolean debuggerAttached = Debug.isDebuggerConnected() || Debug.waitingForDebugger() || hasTracerPid();
    boolean xposedDetected = detectXposed();
    boolean magiskDetected = detectMagisk();
    boolean substrateDetected = suspiciousLibraries.stream()
        .anyMatch(keyword -> {
          String lower = keyword.toLowerCase(Locale.US);
          return lower.contains("substrate")
              || lower.contains("libhooker")
              || lower.contains("zygisk");
        });

    result.putBoolean("debuggerAttached", debuggerAttached);
    result.putBoolean("fridaDetected", fridaDetected);
    result.putBoolean("xposedDetected", xposedDetected);
    result.putBoolean("magiskDetected", magiskDetected);
    result.putBoolean("substrateDetected", substrateDetected);
    result.putArray("suspiciousLibraries", toStringArray(suspiciousLibraries));
    result.putArray("suspiciousPorts", toIntArray(suspiciousPorts));
    return result;
  }

  private static boolean hasSuspiciousFileDescriptors() {
    File fdDir = new File("/proc/self/fd");
    File[] fds = fdDir.listFiles();
    if (fds == null) {
      return false;
    }

    for (File fd : fds) {
      try {
        String target = Files.readSymbolicLink(fd.toPath()).toString();
        String lower = target.toLowerCase(Locale.US);
        if (lower.contains("frida") || lower.contains("linjector")) {
          return true;
        }
      } catch (IOException | UnsupportedOperationException ignored) {
        // Continue scanning other descriptors.
      }
    }
    return false;
  }

  private static List<String> scanProcMaps() {
    List<String> matches = new ArrayList<>();
    File maps = new File("/proc/self/maps");
    if (!maps.canRead()) {
      return matches;
    }

    try (BufferedReader reader = new BufferedReader(new FileReader(maps))) {
      String line;
      while ((line = reader.readLine()) != null) {
        String lower = line.toLowerCase(Locale.US);
        for (String keyword : SUSPICIOUS_MAP_KEYWORDS) {
          if (lower.contains(keyword)) {
            matches.add(keyword);
            break;
          }
        }
      }
    } catch (IOException ignored) {
      // Best-effort detection.
    }
    return matches;
  }

  private static List<Integer> scanFridaPorts() {
    List<Integer> openPorts = new ArrayList<>();
    for (int port : FRIDA_PORTS) {
      if (isLocalPortOpen(port)) {
        openPorts.add(port);
      }
    }
    return openPorts;
  }

  private static boolean isLocalPortOpen(int port) {
    Socket socket = new Socket();
    try {
      socket.connect(new InetSocketAddress("127.0.0.1", port), PORT_CONNECT_TIMEOUT_MS);
      return true;
    } catch (IOException ignored) {
      return false;
    } finally {
      try {
        socket.close();
      } catch (IOException ignored) {
        // Ignore close failures.
      }
    }
  }

  private static boolean hasSuspiciousThreads() {
    File taskDir = new File("/proc/self/task");
    File[] tasks = taskDir.listFiles();
    if (tasks == null) {
      return false;
    }

    for (File task : tasks) {
      File comm = new File(task, "comm");
      if (!comm.canRead()) {
        continue;
      }
      try (BufferedReader reader = new BufferedReader(new FileReader(comm))) {
        String name = reader.readLine();
        if (name == null) {
          continue;
        }
        String normalized = name.trim().toLowerCase(Locale.US);
        if (SUSPICIOUS_THREAD_NAMES.contains(normalized)) {
          return true;
        }
      } catch (IOException ignored) {
        // Continue scanning other tasks.
      }
    }
    return false;
  }

  private static boolean hasTracerPid() {
    File status = new File("/proc/self/status");
    if (!status.canRead()) {
      return false;
    }

    try (BufferedReader reader = new BufferedReader(new FileReader(status))) {
      String line;
      while ((line = reader.readLine()) != null) {
        if (line.startsWith("TracerPid:")) {
          String pid = line.substring("TracerPid:".length()).trim();
          return !"0".equals(pid);
        }
      }
    } catch (IOException ignored) {
      // Best-effort detection.
    }
    return false;
  }

  private static boolean detectXposed() {
    String[] paths = {
        "/system/framework/XposedBridge.jar",
        "/system/lib/libxposed_art.so",
        "/system/lib64/libxposed_art.so",
        "/data/adb/lspd",
        "/data/adb/modules/zygisk_lsposed"
    };
    for (String path : paths) {
      if (new File(path).exists()) {
        return true;
      }
    }

    try {
      throw new Exception("xposed_probe");
    } catch (Exception exception) {
      for (StackTraceElement element : exception.getStackTrace()) {
        String className = element.getClassName().toLowerCase(Locale.US);
        if (className.contains("de.robv.android.xposed")
            || className.contains("org.lsposed")
            || className.contains("io.github.lsposed")) {
          return true;
        }
      }
    }
    return false;
  }

  private static boolean detectMagisk() {
    String[] paths = {
        "/sbin/.magisk",
        "/sbin/.core",
        "/data/adb/magisk",
        "/data/adb/modules",
        "/cache/.disable_magisk"
    };
    for (String path : paths) {
      if (new File(path).exists()) {
        return true;
      }
    }

    if (hasOverlayMounts()) {
      return true;
    }

    String[] props = {"ro.boot.vbmeta.device_state", "ro.boot.verifiedbootstate"};
    for (String prop : props) {
      String value = getSystemProperty(prop);
      if (value != null && value.toLowerCase(Locale.US).contains("orange")) {
        return true;
      }
    }
    return false;
  }

  private static boolean hasOverlayMounts() {
    File mounts = new File("/proc/mounts");
    if (!mounts.canRead()) {
      return false;
    }

    try (BufferedReader reader = new BufferedReader(new FileReader(mounts))) {
      String line;
      while ((line = reader.readLine()) != null) {
        String lower = line.toLowerCase(Locale.US);
        if (lower.contains("magisk")) {
          return true;
        }
      }
    } catch (IOException ignored) {
      // Best-effort detection.
    }
    return false;
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

  private static WritableArray toStringArray(List<String> values) {
    WritableArray array = Arguments.createArray();
    for (String value : values) {
      array.pushString(value);
    }
    return array;
  }

  private static WritableArray toIntArray(List<Integer> values) {
    WritableArray array = Arguments.createArray();
    for (Integer value : values) {
      array.pushInt(value);
    }
    return array;
  }
}
