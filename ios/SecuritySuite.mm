#import <React/RCTBridgeModule.h>
#import <SecureViewManager.h>

@interface RCT_EXTERN_MODULE(SecuritySuite, NSObject)

RCT_EXTERN_METHOD(getPublicKey:(RCTPromiseResolveBlock)resolve withRejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(getSharedKey:(NSString)serverPK withOptions:(NSDictionary *)options withResolver:(RCTPromiseResolveBlock)resolve withRejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(establishSharedKey:(NSString)serverPK withOptions:(NSDictionary *)options withResolver:(RCTPromiseResolveBlock)resolve withRejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(encrypt:(NSString)input withOptions:(NSDictionary *)options withResolver:(RCTPromiseResolveBlock)resolve withRejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(decrypt:(NSString)input withOptions:(NSDictionary *)options withResolver:(RCTPromiseResolveBlock)resolve withRejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(generateJWS:(NSDictionary)options withResolver:(RCTPromiseResolveBlock)resolve withRejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(obfuscate:(NSString)input withSecret:(NSString)secret withResolver:(RCTPromiseResolveBlock)resolve withRejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(deobfuscate:(NSString)input withSecret:(NSString)secret withResolver:(RCTPromiseResolveBlock)resolve withRejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(storageEncrypt:(NSString)input withSecretKey:(NSString*)secretKey withHardEncryption:(BOOL)hardEncryption withCallback:(RCTResponseSenderBlock)callback)

RCT_EXTERN_METHOD(storageDecrypt:(NSString)input withSecretKey:(NSString*)secretKey withHardEncryption:(BOOL)hardEncryption withCallback:(RCTResponseSenderBlock)callback)

RCT_EXTERN_METHOD(secureStorageSetItem:(NSString)key withValue:(NSString)value withResolver:(RCTPromiseResolveBlock)resolve withRejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(secureStorageGetItem:(NSString)key withResolver:(RCTPromiseResolveBlock)resolve withRejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(secureStorageRemoveItem:(NSString)key withResolver:(RCTPromiseResolveBlock)resolve withRejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(secureStorageClear:(RCTPromiseResolveBlock)resolve withRejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(secureStorageGetAllKeys:(RCTPromiseResolveBlock)resolve withRejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(getDeviceId:(RCTResponseSenderBlock)callback)

RCT_EXTERN_METHOD(fetch:(NSString)url withData:(NSDictionary)data withCallback:(RCTResponseSenderBlock)callback)

RCT_EXTERN_METHOD(deviceHasSecurityRisk:(RCTPromiseResolveBlock)resolve withRejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(runtimeDetect:(RCTPromiseResolveBlock)resolve withRejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(appIntegrityVerify:(RCTPromiseResolveBlock)resolve withRejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(deviceGetEnvironment:(RCTPromiseResolveBlock)resolve withRejecter:(RCTPromiseRejectBlock)reject)

+ (BOOL)requiresMainQueueSetup
{
  return NO;
}

@end
