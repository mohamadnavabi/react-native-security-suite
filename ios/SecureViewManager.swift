import Foundation
import React

@objc(RNSSecureViewManager)
class RNSSecureViewManager: RCTViewManager {
  
  override func view() -> UIView! {
    return SecureView()
  }

  @objc override static func requiresMainQueueSetup() -> Bool {
    return true
  }
}
