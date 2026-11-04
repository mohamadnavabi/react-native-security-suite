#import "SecuritySuiteNetworkInspector.h"

#if __has_include(<React/RCTInspectorNetworkReporter.h>)
#import <React/RCTInspectorNetworkReporter.h>
#define SECURITY_SUITE_NETWORK_REPORTER_AVAILABLE 1
#endif

#if __has_include(<react/featureflags/ReactNativeFeatureFlags.h>)
#import <react/featureflags/ReactNativeFeatureFlags.h>
#define SECURITY_SUITE_FEATURE_FLAGS_AVAILABLE 1
#endif

#ifdef SECURITY_SUITE_NETWORK_REPORTER_AVAILABLE
static BOOL SecuritySuiteNetworkReportingEnabled(void)
{
#ifdef SECURITY_SUITE_FEATURE_FLAGS_AVAILABLE
  return facebook::react::ReactNativeFeatureFlags::enableNetworkEventReporting();
#else
  return YES;
#endif
}
#endif

@implementation SecuritySuiteNetworkInspector

+ (void)reportRequestStart:(NSString *)requestId request:(NSURLRequest *)request
{
#ifdef SECURITY_SUITE_NETWORK_REPORTER_AVAILABLE
  if (!SecuritySuiteNetworkReportingEnabled()) {
    return;
  }
  [RCTInspectorNetworkReporter reportRequestStart:requestId
                                          request:request
                                encodedDataLength:(int)request.HTTPBody.length];
  [RCTInspectorNetworkReporter reportConnectionTiming:requestId request:request];
#endif
}

+ (void)reportResponseStart:(NSString *)requestId
                   response:(NSURLResponse *)response
                 statusCode:(NSInteger)statusCode
                    headers:(NSDictionary<NSString *, NSString *> *)headers
{
#ifdef SECURITY_SUITE_NETWORK_REPORTER_AVAILABLE
  if (!SecuritySuiteNetworkReportingEnabled()) {
    return;
  }
  [RCTInspectorNetworkReporter reportResponseStart:requestId
                                          response:response
                                        statusCode:(int)statusCode
                                           headers:headers];
#endif
}

+ (void)reportDataReceived:(NSString *)requestId data:(NSData *)data
{
#ifdef SECURITY_SUITE_NETWORK_REPORTER_AVAILABLE
  if (!SecuritySuiteNetworkReportingEnabled()) {
    return;
  }
  [RCTInspectorNetworkReporter reportDataReceived:requestId data:data];
#endif
}

+ (void)reportResponseEnd:(NSString *)requestId body:(NSData *)body
{
#ifdef SECURITY_SUITE_NETWORK_REPORTER_AVAILABLE
  if (!SecuritySuiteNetworkReportingEnabled()) {
    return;
  }
  // Always hand over the raw bytes base64-encoded; DevTools decodes them back to text.
  // Passing an NSString instead goes through React Native's RCTStringViewFromNSString,
  // which pairs the UTF-8 buffer with the UTF-16 length, so any body containing
  // multi-byte characters (e.g. Persian text) gets cut short in the Network panel.
  [RCTInspectorNetworkReporter maybeStoreResponseBody:requestId data:body base64Encoded:YES];
  [RCTInspectorNetworkReporter reportResponseEnd:requestId encodedDataLength:(int)body.length];
#endif
}

+ (void)reportRequestFailed:(NSString *)requestId
{
#ifdef SECURITY_SUITE_NETWORK_REPORTER_AVAILABLE
  if (!SecuritySuiteNetworkReportingEnabled()) {
    return;
  }
  [RCTInspectorNetworkReporter reportRequestFailed:requestId cancelled:NO];
#endif
}

@end
