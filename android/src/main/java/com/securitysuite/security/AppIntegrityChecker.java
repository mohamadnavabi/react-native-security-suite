package com.securitysuite.security;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.os.Build;

import com.facebook.react.bridge.Arguments;
import com.facebook.react.bridge.WritableMap;

import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

/**
 * Native app integrity checks (Android).
 */
public final class AppIntegrityChecker {
  private static final Set<String> TRUSTED_INSTALLERS = new HashSet<>(Arrays.asList(
      "com.android.vending",
      "com.google.android.packageinstaller",
      "com.android.packageinstaller"
  ));

  private AppIntegrityChecker() {}

  public static WritableMap verify(Context context) {
    WritableMap result = Arguments.createMap();
    PackageManager pm = context.getPackageManager();
    String packageName = context.getPackageName();

    boolean debuggable = (context.getApplicationInfo().flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0;
    String buildType = debuggable ? "debug" : "release";
    String signingSha256 = getSigningCertificateSha256(pm, packageName);
    boolean validSignature = signingSha256 != null && !signingSha256.isEmpty();

    String installer = getInstallerPackageName(pm, packageName);
    boolean installerTrusted = installer == null
        ? debuggable
        : TRUSTED_INSTALLERS.contains(installer);

    boolean tampered = !validSignature
        || (!debuggable && installer != null && !installerTrusted)
        || hasSuspiciousSplitSource(context.getApplicationInfo());

    result.putBoolean("validSignature", validSignature);
    result.putBoolean("debuggable", debuggable);
    result.putBoolean("tampered", tampered);
    result.putBoolean("installerTrusted", installerTrusted);
    result.putString("buildType", buildType);
    if (signingSha256 != null) {
      result.putString("signingCertificateSha256", signingSha256);
    }
    if (installer != null) {
      result.putString("installerPackage", installer);
    } else {
      result.putNull("installerPackage");
    }
    result.putString("bundleIdentifier", packageName);
    return result;
  }

  private static String getSigningCertificateSha256(PackageManager pm, String packageName) {
    try {
      Signature[] signatures;
      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
        PackageInfo info = pm.getPackageInfo(
            packageName,
            PackageManager.GET_SIGNING_CERTIFICATES
        );
        if (info.signingInfo == null) {
          return null;
        }
        signatures = info.signingInfo.hasMultipleSigners()
            ? info.signingInfo.getApkContentsSigners()
            : info.signingInfo.getSigningCertificateHistory();
      } else {
        @SuppressWarnings("deprecation")
        PackageInfo info = pm.getPackageInfo(packageName, PackageManager.GET_SIGNATURES);
        @SuppressWarnings("deprecation")
        Signature[] legacySignatures = info.signatures;
        signatures = legacySignatures;
      }

      if (signatures == null || signatures.length == 0) {
        return null;
      }

      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      byte[] hash = digest.digest(signatures[0].toByteArray());
      return bytesToHex(hash).toLowerCase(Locale.US);
    } catch (Exception ignored) {
      return null;
    }
  }

  private static String getInstallerPackageName(PackageManager pm, String packageName) {
    try {
      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
        return pm.getInstallSourceInfo(packageName).getInstallingPackageName();
      }
      @SuppressWarnings("deprecation")
      String installer = pm.getInstallerPackageName(packageName);
      return installer;
    } catch (Exception ignored) {
      return null;
    }
  }

  private static boolean hasSuspiciousSplitSource(ApplicationInfo info) {
    if (info.splitSourceDirs == null) {
      return false;
    }
    for (String split : info.splitSourceDirs) {
      if (split != null && split.toLowerCase(Locale.US).contains("/data/local/tmp")) {
        return true;
      }
    }
    return false;
  }

  private static String bytesToHex(byte[] bytes) {
    StringBuilder builder = new StringBuilder(bytes.length * 2);
    for (byte value : bytes) {
      builder.append(String.format(Locale.US, "%02x", value));
    }
    return builder.toString();
  }
}
