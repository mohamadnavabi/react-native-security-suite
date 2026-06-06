import Foundation
import Security

enum AppIntegrityChecker {
  static func verify() -> [String: Any] {
    let bundleId = Bundle.main.bundleIdentifier ?? ""
    let debuggable = isDebugBuild()
    let buildType = resolveBuildType(debuggable: debuggable)
    let validSignature = validateCodeSignature()
    let suspiciousLibraries = scanInjectedDylibs()
    let tampered = !validSignature || !suspiciousLibraries.isEmpty

    var result: [String: Any] = [
      "validSignature": validSignature,
      "debuggable": debuggable,
      "tampered": tampered,
      "buildType": buildType,
      "bundleIdentifier": bundleId,
    ]

    if debuggable {
      result["installerTrusted"] = true
    }

    return result
  }

  private static func validateCodeSignature() -> Bool {
    guard let bundleURL = Bundle.main.bundleURL as CFURL? else {
      return false
    }

    var staticCode: SecStaticCode?
    let createStatus = SecStaticCodeCreateWithPath(bundleURL, [], &staticCode)
    guard createStatus == errSecSuccess, let code = staticCode else {
      return false
    }

    let verifyStatus = SecStaticCodeCheckValidity(code, [], nil)
    return verifyStatus == errSecSuccess
  }

  private static func scanInjectedDylibs() -> [String] {
    let suspiciousKeywords = ["frida", "substrate", "cycript", "libhooker", "substitute", "ellekit"]
    var matches: [String] = []
    let imageCount = _dyld_image_count()

    for index in 0..<imageCount {
      guard let imageName = _dyld_get_image_name(index) else {
        continue
      }
      let path = String(cString: imageName).lowercased()
      guard path.hasPrefix("/var/") || path.contains("/mobilesubstrate/") else {
        continue
      }
      for keyword in suspiciousKeywords where path.contains(keyword) {
        matches.append(String(cString: imageName))
        break
      }
    }

    return matches
  }

  private static func isDebugBuild() -> Bool {
    #if DEBUG
    return true
    #else
    return false
    #endif
  }

  private static func resolveBuildType(debuggable: Bool) -> String {
    if debuggable {
      return "debug"
    }

    if let receiptURL = Bundle.main.appStoreReceiptURL,
       receiptURL.lastPathComponent == "sandboxReceipt" {
      return "testflight"
    }

    return "release"
  }
}
