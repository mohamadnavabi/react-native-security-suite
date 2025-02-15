import UIKit

class ScreenGuard: UIView {
  private var secureView: UIView?

  func enableScreenshotGuard() {
    disableScreenshotGuard()
    
    let secureView = UIView(frame: UIScreen.main.bounds)
    secureView.backgroundColor = .black
    secureView.isUserInteractionEnabled = false
    secureView.isHidden = true
    
    if let window = UIApplication.shared.windows.first(where: { $0.isKeyWindow }) {
      window.addSubview(secureView)
      self.secureView = secureView
    }
    
    NotificationCenter.default.addObserver(
      self,
      selector: #selector(self.handleScreenCaptureChange),
      name: UIScreen.capturedDidChangeNotification,
      object: nil
    )
  }
  
  func disableScreenshotGuard() {
    secureView?.removeFromSuperview()
    secureView = nil
    
    NotificationCenter.default.removeObserver(
      self,
      name: UIScreen.capturedDidChangeNotification,
      object: nil
    )
  }
  
  @objc private func handleScreenCaptureChange() {
    DispatchQueue.main.async {
      if UIScreen.main.isCaptured {
        self.secureView?.isHidden = false
      } else {
        self.secureView?.isHidden = true
      }
    }
  }
}
