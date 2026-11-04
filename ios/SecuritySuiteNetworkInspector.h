#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/**
 * Mirrors requests made by the native pinned fetch into the React Native
 * DevTools Network panel. Every call is a no-op when the React Native
 * inspector network reporter is unavailable (unsupported React Native version
 * or a build without debugger support).
 */
@interface SecuritySuiteNetworkInspector : NSObject

+ (void)reportRequestStart:(NSString *)requestId
                   request:(NSURLRequest *)request
    NS_SWIFT_NAME(reportRequestStart(_:request:));

+ (void)reportResponseStart:(NSString *)requestId
                   response:(NSURLResponse *)response
                 statusCode:(NSInteger)statusCode
                    headers:(NSDictionary<NSString *, NSString *> *)headers
    NS_SWIFT_NAME(reportResponseStart(_:response:statusCode:headers:));

+ (void)reportDataReceived:(NSString *)requestId
                      data:(NSData *)data
    NS_SWIFT_NAME(reportDataReceived(_:data:));

+ (void)reportResponseEnd:(NSString *)requestId
                     body:(NSData *)body
    NS_SWIFT_NAME(reportResponseEnd(_:body:));

+ (void)reportRequestFailed:(NSString *)requestId
    NS_SWIFT_NAME(reportRequestFailed(_:));

@end

NS_ASSUME_NONNULL_END
