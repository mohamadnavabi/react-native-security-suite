#import <React/RCTBridgeModule.h>

@interface RCT_EXTERN_MODULE(SecuritySuite, NSObject)

RCT_EXTERN_METHOD(deviceHasSecurityRisk:(RCTPromiseResolveBlock)resolve withRejecter:(RCTPromiseRejectBlock)reject)

+ (BOOL)requiresMainQueueSetup
{
  return NO;
}

@end
