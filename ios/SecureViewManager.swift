import Foundation
import React

@objc(SecureViewManager)
class SecureViewManager: RCTViewManager {
  
  override func view() -> UIView! {
    return SecureView()
  }

  @objc override static func requiresMainQueueSetup() -> Bool {
    return true
  }
}
