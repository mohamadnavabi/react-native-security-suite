import IOSSecuritySuite

@objc(SecuritySuite)
class SecuritySuite: NSObject {

    @objc(deviceHasSecurityRisk:withRejecter:)
    func deviceHasSecurityRisk(resolve:RCTPromiseResolveBlock, reject:RCTPromiseRejectBlock) -> Void {
        do {
            let jailbreakStatus = IOSSecuritySuite.amIJailbrokenWithFailMessage()
            resolve(jailbreakStatus.jailbroken)
        } catch {
            reject("ERROR", nil, nil)
        }
    }
}
