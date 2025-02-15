import UIKit

class ScreenGuard: UIView {
    private var secureView: UIView?
    private var secureField: UITextField?
    
    func enableScreenshotGuard() {
        disableScreenshotGuard()
        
        DispatchQueue.main.async {
            self.addSecureView()
            self.addSecureTextField()
            self.registerForNotifications()
        }
    }
    
    func disableScreenshotGuard() {
        DispatchQueue.main.async {
            self.removeSecureView()
            self.removeSecureTextField()
            self.unregisterFromNotifications()
        }
    }
    
    private func addSecureView() {
        guard secureView == nil else { return }
        
        let secureView = UIView(frame: UIScreen.main.bounds)
        secureView.backgroundColor = .black
        secureView.isUserInteractionEnabled = false
        secureView.isHidden = true
        
        if let window = UIApplication.shared.windows.first(where: { $0.isKeyWindow }) {
            window.addSubview(secureView)
            self.secureView = secureView
        }
    }
    
    private func removeSecureView() {
        secureView?.removeFromSuperview()
        secureView = nil
    }
    
    private func addSecureTextField() {
        guard secureField == nil else { return }
        
        guard let window = UIApplication.shared.windows.first(where: { $0.isKeyWindow }) else { return }
        
        let secureField = UITextField(frame: window.bounds)
        secureField.isSecureTextEntry = true
        secureField.isUserInteractionEnabled = false
        secureField.font = UIFont.systemFont(ofSize: 25)
        secureField.textAlignment = .center
        secureField.text = "This action has been restricted by your app."
        secureField.isHidden = true
        
        window.addSubview(secureField)
        self.secureField = secureField
    }
    
    private func removeSecureTextField() {
        secureField?.removeFromSuperview()
        secureField = nil
    }
    
    private func registerForNotifications() {
        NotificationCenter.default.addObserver(
            self,
            selector: #selector(self.handleScreenCaptureChange),
            name: UIScreen.capturedDidChangeNotification,
            object: nil
        )
        
        NotificationCenter.default.addObserver(
            self,
            selector: #selector(self.handleScreenshotTaken),
            name: UIApplication.userDidTakeScreenshotNotification,
            object: nil
        )
    }
    
    private func unregisterFromNotifications() {
        NotificationCenter.default.removeObserver(
            self,
            name: UIScreen.capturedDidChangeNotification,
            object: nil
        )
        
        NotificationCenter.default.removeObserver(
            self,
            name: UIApplication.userDidTakeScreenshotNotification,
            object: nil
        )
    }
    
    @objc private func handleScreenCaptureChange() {
        DispatchQueue.main.async {
            if UIScreen.main.isCaptured {
                self.showSecureViewAndField()
            } else {
                self.hideSecureViewAndField()
            }
        }
    }
    
    @objc private func handleScreenshotTaken() {
        DispatchQueue.main.async {
            self.showSecureViewAndField()
        }
        
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.0) {
            self.hideSecureViewAndField()
        }
    }
    
    private func showSecureViewAndField() {
        secureView?.isHidden = false
        secureField?.isHidden = false
    }
    
    private func hideSecureViewAndField() {
        secureView?.isHidden = true
        secureField?.isHidden = true
    }
}
