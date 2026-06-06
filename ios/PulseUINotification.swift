import UserNotifications
import PulseUI
import SwiftUI

@available(iOS 13.0, *)
class PulseUINotification: NSObject, UNUserNotificationCenterDelegate {
  override init() {
    super.init()

    UNUserNotificationCenter.current().delegate = self
  }

  func userNotificationCenter(_ center: UNUserNotificationCenter, willPresent notification: UNNotification, withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void) {
      completionHandler([.list])
  }
  
  func userNotificationCenter(_ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse, withCompletionHandler completionHandler: @escaping () -> Void) {
      switch response.actionIdentifier {
        case "openPulse":
          openPulseUI()
          break
        default:
          openPulseUI()
          break
      }
    completionHandler()
  }
  
  func requestPermission() {
    UNUserNotificationCenter.current().requestAuthorization(options: [.alert]) { granted, error in
      if granted {
//        print("PulseUI Notification Permission Granted")
      } else {
        print("PulseUI Notification Permission Denied")
      }
    }
  }
  
  func showNotification(body: String) {
     requestPermission()
     
     let content = UNMutableNotificationContent()
     content.title = "Recording HTTP Activity"
     content.body = body
     content.sound = .none
     content.badge = 1

     let action = UNNotificationAction(identifier: "openPulse", title: "Open Pulse", options: [])
     let category = UNNotificationCategory(identifier: "pulseCategory", actions: [action], intentIdentifiers: [], options: [])
     
     UNUserNotificationCenter.current().setNotificationCategories([category])
     content.categoryIdentifier = "pulseCategory"
     
     let trigger = UNTimeIntervalNotificationTrigger(timeInterval: 1, repeats: false)
     
     let request = UNNotificationRequest(identifier: "pulseNotification", content: content, trigger: trigger)
     
     UNUserNotificationCenter.current().add(request) { error in
         if let error = error {
             print("Error scheduling notification: \(error.localizedDescription)")
         }
     }
  }
  
  @objc(openPulseUI)
  func openPulseUI() {
    DispatchQueue.main.async {
      if #available(iOS 14.0, *) {
        let hostingController = UIHostingController(rootView: ConsoleView())
        if let rootViewController = UIApplication.shared.keyWindow?.rootViewController {
          let navigationController = UINavigationController()
          navigationController.setViewControllers([hostingController], animated: false)
          rootViewController.present(navigationController, animated: true, completion: nil)
        }
      } else {
        if let rootViewController = UIApplication.shared.keyWindow?.rootViewController {
          rootViewController.present(UIViewController(), animated: true, completion: nil)
        }
      }
    }
  }
}
