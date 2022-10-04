package com.reactnativesecuritysuite;

import androidx.annotation.NonNull;

import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.module.annotations.ReactModule;
import com.scottyab.rootbeer.RootBeer;

@ReactModule(name = SecuritySuiteModule.NAME)
public class SecuritySuiteModule extends ReactContextBaseJavaModule {
    public static final String NAME = "SecuritySuite";
    private ReactApplicationContext context;

    public SecuritySuiteModule(ReactApplicationContext reactContext) {
        super(reactContext);
        context = reactContext;
    }

    @Override
    @NonNull
    public String getName() {
        return NAME;
    }


    // Example method
    // See https://reactnative.dev/docs/native-modules-android
    @ReactMethod
    public void deviceHasSecurityRisk(Promise promise) {
        RootBeer rootBeer = new RootBeer(context);
        promise.resolve(rootBeer.isRooted());
    }

    public static native int nativeMultiply(int a, int b);
}
