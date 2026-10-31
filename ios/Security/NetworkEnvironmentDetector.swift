import CFNetwork
import Foundation

enum NetworkEnvironmentDetector {
  /// iOS keeps idle `utun`/`ipsec` interfaces for system services, so listing interfaces would
  /// flag devices with no VPN. The proxy settings' `__SCOPED__` entries only name interfaces
  /// that have network configuration applied.
  private static let vpnInterfacePrefixes = ["tap", "tun", "ppp", "ipsec", "utun"]

  private static let proxyFlags = [
    ("HTTPEnable", "proxy:http"),
    ("HTTPSEnable", "proxy:https"),
    ("SOCKSEnable", "proxy:socks"),
    ("ProxyAutoConfigEnable", "proxy:pac"),
  ]

  static func detect() -> [String: Any] {
    let settings = systemProxySettings()
    let vpnIndicators = collectVpnIndicators(settings)
    let proxyIndicators = collectProxyIndicators(settings)

    return [
      "vpnDetected": !vpnIndicators.isEmpty,
      "proxyDetected": !proxyIndicators.isEmpty,
      "indicators": vpnIndicators + proxyIndicators,
    ]
  }

  private static func systemProxySettings() -> [String: Any] {
    guard let settings = CFNetworkCopySystemProxySettings()?.takeRetainedValue() else {
      return [:]
    }
    return settings as NSDictionary as? [String: Any] ?? [:]
  }

  private static func collectVpnIndicators(_ settings: [String: Any]) -> [String] {
    guard let scoped = settings["__SCOPED__"] as? [String: Any] else {
      return []
    }

    return scoped.keys
      .filter { name in vpnInterfacePrefixes.contains { name.hasPrefix($0) } }
      .sorted()
      .map { "interface:\($0)" }
  }

  /// Reports only the proxy type: hosts and PAC URLs can identify the user or embed credentials.
  private static func collectProxyIndicators(_ settings: [String: Any]) -> [String] {
    return proxyFlags
      .filter { (settings[$0.0] as? NSNumber)?.boolValue == true }
      .map { $0.1 }
  }
}
