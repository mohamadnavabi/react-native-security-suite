import Foundation
import IOSSecuritySuite
import Darwin
import MachO

enum RuntimeDetector {
  private static let fridaPorts: [UInt16] = [27042, 27043, 4444]
  private static let fridaPaths = [
    "/usr/sbin/frida-server",
    "/usr/local/bin/frida-server",
    "/var/jb/usr/sbin/frida-server",
    "/Library/MobileSubstrate/MobileSubstrate.dylib",
  ]
  private static let suspiciousKeywords = [
    "frida", "substrate", "cycript", "libhooker", "ellekit", "substitute", "xposed", "lsposed"
  ]
  private static let portConnectTimeoutMs: Int32 = 300

  static func detect() -> [String: Any] {
    let suspiciousLibraries = scanLoadedLibraries()
    let suspiciousPorts = scanFridaPorts()
    let reverseEngineered = IOSSecuritySuite.amIReverseEngineered()
    let fridaPathsDetected = hasFridaPaths()
    let fridaDetected = hasDyldInsert()
      || reverseEngineered
      || fridaPathsDetected
      || !suspiciousLibraries.isEmpty
      || !suspiciousPorts.isEmpty
      || canConnectToFrida()
    let debuggerAttached = isDebuggerAttached()
    let substrateDetected = fridaPathsDetected
      || suspiciousLibraries.contains(where: {
        $0.lowercased().contains("substrate")
          || $0.lowercased().contains("substitute")
          || $0.lowercased().contains("ellekit")
      })

    return [
      "debuggerAttached": debuggerAttached,
      "fridaDetected": fridaDetected,
      "substrateDetected": substrateDetected,
      "suspiciousLibraries": suspiciousLibraries,
      "suspiciousPorts": suspiciousPorts,
    ]
  }

  private static func hasFridaPaths() -> Bool {
    fridaPaths.contains { FileManager.default.fileExists(atPath: $0) }
  }

  private static func hasDyldInsert() -> Bool {
    if let env = getenv("DYLD_INSERT_LIBRARIES") {
      let value = String(cString: env)
      return !value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }
    return false
  }

  private static func scanLoadedLibraries() -> [String] {
    var matches: [String] = []
    let imageCount = _dyld_image_count()
    for index in 0..<imageCount {
      guard let imageName = _dyld_get_image_name(index) else {
        continue
      }
      let name = String(cString: imageName).lowercased()
      for keyword in suspiciousKeywords where name.contains(keyword) {
        matches.append(String(cString: imageName))
        break
      }
    }
    return matches
  }

  private static func scanFridaPorts() -> [Int] {
    fridaPorts.compactMap { port in
      canConnect(to: port) ? Int(port) : nil
    }
  }

  private static func canConnectToFrida() -> Bool {
    fridaPorts.contains(where: canConnect)
  }

  private static func canConnect(to port: UInt16) -> Bool {
    var addr = sockaddr_in()
    addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
    addr.sin_family = sa_family_t(AF_INET)
    addr.sin_port = port.bigEndian
    addr.sin_addr = in_addr(s_addr: inet_addr("127.0.0.1"))

    let socketFd = socket(AF_INET, SOCK_STREAM, 0)
    if socketFd < 0 {
      return false
    }
    defer { close(socketFd) }

    var timeout = timeval(
      tv_sec: Int(portConnectTimeoutMs / 1000),
      tv_usec: Int32((portConnectTimeoutMs % 1000) * 1000)
    )
    _ = withUnsafePointer(to: &timeout) {
      setsockopt(socketFd, SOL_SOCKET, SO_RCVTIMEO, $0, socklen_t(MemoryLayout<timeval>.size))
    }
    _ = withUnsafePointer(to: &timeout) {
      setsockopt(socketFd, SOL_SOCKET, SO_SNDTIMEO, $0, socklen_t(MemoryLayout<timeval>.size))
    }

    let result = withUnsafePointer(to: &addr) {
      $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
        connect(socketFd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
      }
    }
    return result == 0
  }

  private static func isDebuggerAttached() -> Bool {
    if IOSSecuritySuite.amIDebugged() {
      return true
    }

    var info = kinfo_proc()
    var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
    var size = MemoryLayout<kinfo_proc>.stride
    let result = mib.withUnsafeMutableBufferPointer { buffer -> Int32 in
      sysctl(buffer.baseAddress, u_int(buffer.count), &info, &size, nil, 0)
    }
    if result != 0 {
      return false
    }
    return (info.kp_proc.p_flag & P_TRACED) != 0
  }
}
