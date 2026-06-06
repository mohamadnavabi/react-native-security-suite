import Foundation
import IOSSecuritySuite

enum EmulatorDetector {
  static func detect() -> [String: Any] {
    var indicators: [String] = []

    #if targetEnvironment(simulator)
    indicators.append("TARGET_OS_SIMULATOR")
    #endif

    if IOSSecuritySuite.amIRunInEmulator() {
      indicators.append("IOSSecuritySuite.amIRunInEmulator")
    }

    if let model = hardwareModel()?.lowercased() {
      if model.contains("simulator") || model.contains("x86_64") || model.contains("i386") {
        indicators.append("hw.model:\(model)")
      }
    }

    let isSimulator = !indicators.isEmpty

    return [
      "isEmulator": false,
      "isSimulator": isSimulator,
      "indicators": indicators,
    ]
  }

  private static func hardwareModel() -> String? {
    var size: size_t = 0
    sysctlbyname("hw.model", nil, &size, nil, 0)
    guard size > 0 else {
      return nil
    }

    var model = [CChar](repeating: 0, count: size)
    let result = sysctlbyname("hw.model", &model, &size, nil, 0)
    guard result == 0 else {
      return nil
    }
    return String(cString: model)
  }
}
