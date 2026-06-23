#import <React/RCTBridgeModule.h>
#import <SecureViewManager.h>

@interface RCT_EXTERN_MODULE(SecuritySuite, NSObject)

RCT_EXTERN_METHOD(configure:(NSDictionary *)config withResolver:(RCTPromiseResolveBlock)resolve withRejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(getPublicKey:(NSDictionary *)options withResolver:(RCTPromiseResolveBlock)resolve withRejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(getSharedKey:(NSString)serverPK withOptions:(NSDictionary *)options withResolver:(RCTPromiseResolveBlock)resolve withRejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(establishSharedKey:(NSString)serverPK withOptions:(NSDictionary *)options withResolver:(RCTPromiseResolveBlock)resolve withRejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(encrypt:(NSString)input withOptions:(NSDictionary *)options withResolver:(RCTPromiseResolveBlock)resolve withRejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(decrypt:(NSString)input withOptions:(NSDictionary *)options withResolver:(RCTPromiseResolveBlock)resolve withRejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(generateJWS:(NSDictionary)options withResolver:(RCTPromiseResolveBlock)resolve withRejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(obfuscate:(NSString)input withSecret:(NSString)secret withResolver:(RCTPromiseResolveBlock)resolve withRejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(deobfuscate:(NSString)input withSecret:(NSString)secret withResolver:(RCTPromiseResolveBlock)resolve withRejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(storageEncrypt:(NSString)input withSecretKey:(NSString*)secretKey withHardEncryption:(BOOL)hardEncryption withResolver:(RCTPromiseResolveBlock)resolve withRejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(storageDecrypt:(NSString)input withSecretKey:(NSString*)secretKey withHardEncryption:(BOOL)hardEncryption withResolver:(RCTPromiseResolveBlock)resolve withRejecter:(RCTPromiseRejectBlock)reject)

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

RCT_EXTERN_METHOD(cryptoHash:(NSString)input withAlgorithm:(NSString)algorithm withResolver:(RCTPromiseResolveBlock)resolve withRejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(cryptoDeriveKeys:(NSDictionary)params withResolver:(RCTPromiseResolveBlock)resolve withRejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(cryptoEncryptAesGcm:(NSString)plaintext withKey:(NSString)key withResolver:(RCTPromiseResolveBlock)resolve withRejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(cryptoDecryptAesGcm:(NSString)ciphertext withKey:(NSString)key withResolver:(RCTPromiseResolveBlock)resolve withRejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(cryptoGetEcdhPublicKey:(RCTPromiseResolveBlock)resolve withRejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(cryptoEcdhComputeAndDeriveKeys:(NSDictionary)params withResolver:(RCTPromiseResolveBlock)resolve withRejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(cryptoGetX25519PublicKey:(RCTPromiseResolveBlock)resolve withRejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(cryptoX25519ComputeAndDeriveKeys:(NSDictionary)params withResolver:(RCTPromiseResolveBlock)resolve withRejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(cryptoGenerateEd25519KeyPair:(RCTPromiseResolveBlock)resolve withRejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(cryptoSignEd25519:(NSString)message withPrivateKey:(NSString)privateKey withResolver:(RCTPromiseResolveBlock)resolve withRejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(cryptoVerifyEd25519:(NSString)message withSignature:(NSString)signature withPublicKey:(NSString)publicKey withResolver:(RCTPromiseResolveBlock)resolve withRejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(cryptoGenerateEcdsaKeyPair:(RCTPromiseResolveBlock)resolve withRejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(cryptoSignEcdsa:(NSString)message withPrivateKey:(NSString)privateKey withResolver:(RCTPromiseResolveBlock)resolve withRejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(cryptoVerifyEcdsa:(NSString)message withSignature:(NSString)signature withPublicKey:(NSString)publicKey withResolver:(RCTPromiseResolveBlock)resolve withRejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(cryptoRandomBytes:(NSInteger)count withResolver:(RCTPromiseResolveBlock)resolve withRejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(generateAsymmetricJWS:(NSDictionary)options withResolver:(RCTPromiseResolveBlock)resolve withRejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(secureStorageSetItemBiometric:(NSString)key withValue:(NSString)value withOptions:(NSDictionary)options withResolver:(RCTPromiseResolveBlock)resolve withRejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(secureStorageGetItemBiometric:(NSString)key withOptions:(NSDictionary)options withResolver:(RCTPromiseResolveBlock)resolve withRejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(secureStorageBiometricIsAvailable:(RCTPromiseResolveBlock)resolve withRejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(screenSetWindowSecure:(BOOL)enabled withResolver:(RCTPromiseResolveBlock)resolve withRejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(deviceAttestationIsSupported:(RCTPromiseResolveBlock)resolve withRejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(deviceAttestationGenerateKey:(RCTPromiseResolveBlock)resolve withRejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(deviceAttestationAttestKey:(NSString)keyId withClientDataHash:(NSString)clientDataHash withResolver:(RCTPromiseResolveBlock)resolve withRejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(deviceAttestationGenerateAssertion:(NSString)keyId withClientDataHash:(NSString)clientDataHash withResolver:(RCTPromiseResolveBlock)resolve withRejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(deviceAttestationGetPlayIntegrityToken:(NSString)nonce withResolver:(RCTPromiseResolveBlock)resolve withRejecter:(RCTPromiseRejectBlock)reject)

+ (BOOL)requiresMainQueueSetup
{
  return NO;
}

@end
