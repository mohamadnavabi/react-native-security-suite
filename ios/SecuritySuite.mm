#import <React/RCTBridgeModule.h>

@interface RCT_EXTERN_MODULE(SecuritySuite, NSObject)

RCT_EXTERN_METHOD(getPublicKey:(RCTPromiseResolveBlock)resolve withRejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(getSharedKey:(NSString)serverPK withResolver:(RCTPromiseResolveBlock)resolve withRejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(encrypt:(NSString)input withResolver:(RCTPromiseResolveBlock)resolve withRejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(decrypt:(NSString)input withResolver:(RCTPromiseResolveBlock)resolve withRejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(getDeviceId:(RCTResponseSenderBlock)callback)

RCT_EXTERN_METHOD(storageEncrypt:(NSString)input withSecretKey:(NSString*)secretKey withHardEncryption:(BOOL)hardEncryption withCallback:(RCTResponseSenderBlock)callback)

RCT_EXTERN_METHOD(storageDecrypt:(NSString)input withSecretKey:(NSString*)secretKey withHardEncryption:(BOOL)hardEncryption withCallback:(RCTResponseSenderBlock)callback)

RCT_EXTERN_METHOD(fetch:(NSString)url withData:(NSDictionary)data withCallback:(RCTResponseSenderBlock)callback)

RCT_EXTERN_METHOD(deviceHasSecurityRisk:(RCTPromiseResolveBlock)resolve withRejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(setScreenshotGuard:(BOOL)enable)

+ (BOOL)requiresMainQueueSetup
{
  return NO;
}

@end
