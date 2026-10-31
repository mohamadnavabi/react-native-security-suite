package com.securitysuite.security;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.ProxyInfo;
import android.net.Uri;

import com.facebook.react.bridge.Arguments;
import com.facebook.react.bridge.WritableArray;
import com.facebook.react.bridge.WritableMap;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.regex.Pattern;

/**
 * VPN and proxy detection (Android).
 */
public final class NetworkEnvironmentDetector {
  /**
   * Catches VPNs that exclude this app (split tunnelling), which the active network does not
   * report. Deliberately narrow: "tunl0" is an idle kernel tunnel, "ipsec" is used by VoWiFi and
   * "ppp" by some carriers, so matching those would flag devices with no VPN.
   */
  private static final Pattern VPN_INTERFACE = Pattern.compile("^(tun|wg|pptp)\\d+$");

  private static final String[] PROXY_SYSTEM_PROPERTIES = {
    "http.proxyHost", "https.proxyHost", "socksProxyHost",
  };

  private NetworkEnvironmentDetector() {}

  public static WritableMap detect(Context context) {
    ConnectivityManager connectivity =
        (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);

    List<String> vpnIndicators = new ArrayList<>();
    List<String> proxyIndicators = new ArrayList<>();

    collectVpnTransportIndicators(connectivity, vpnIndicators);
    collectVpnInterfaceIndicators(vpnIndicators);
    collectProxySettingsIndicators(connectivity, proxyIndicators);
    collectProxySystemPropertyIndicators(proxyIndicators);

    WritableArray indicators = Arguments.createArray();
    for (String indicator : vpnIndicators) {
      indicators.pushString(indicator);
    }
    for (String indicator : proxyIndicators) {
      indicators.pushString(indicator);
    }

    WritableMap result = Arguments.createMap();
    result.putBoolean("vpnDetected", !vpnIndicators.isEmpty());
    result.putBoolean("proxyDetected", !proxyIndicators.isEmpty());
    result.putArray("indicators", indicators);
    return result;
  }

  private static void collectVpnTransportIndicators(
      ConnectivityManager connectivity, List<String> indicators) {
    if (connectivity == null) {
      return;
    }

    Network active = connectivity.getActiveNetwork();
    NetworkCapabilities capabilities =
        active == null ? null : connectivity.getNetworkCapabilities(active);

    if (capabilities != null && capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
      indicators.add("transport:vpn");
    }
  }

  private static void collectVpnInterfaceIndicators(List<String> indicators) {
    try {
      Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
      if (interfaces == null) {
        return;
      }

      for (NetworkInterface networkInterface : Collections.list(interfaces)) {
        if (networkInterface.isUp() && VPN_INTERFACE.matcher(networkInterface.getName()).matches()) {
          indicators.add("interface:" + networkInterface.getName());
        }
      }
    } catch (SocketException ignored) {
      // The transport check above still covers VPNs that carry this app's traffic.
    }
  }

  /** Reports only the proxy type: hosts and PAC URLs can identify the user or embed credentials. */
  private static void collectProxySettingsIndicators(
      ConnectivityManager connectivity, List<String> indicators) {
    if (connectivity == null) {
      return;
    }

    ProxyInfo proxy = connectivity.getDefaultProxy();
    if (proxy == null) {
      return;
    }

    Uri pacFileUrl = proxy.getPacFileUrl();
    if (pacFileUrl != null && !Uri.EMPTY.equals(pacFileUrl)) {
      indicators.add("proxy:pac");
    } else if (proxy.getHost() != null && !proxy.getHost().isEmpty()) {
      indicators.add("proxy:http");
    }
  }

  private static void collectProxySystemPropertyIndicators(List<String> indicators) {
    for (String property : PROXY_SYSTEM_PROPERTIES) {
      String value = System.getProperty(property);
      if (value != null && !value.isEmpty()) {
        indicators.add("sysprop:" + property);
      }
    }
  }
}
