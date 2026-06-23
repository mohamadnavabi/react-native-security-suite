package com.securitysuite.security;

import android.content.Context;

import com.facebook.react.bridge.Promise;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;

/**
 * Optional Play Integrity integration loaded via reflection so the native module
 * can initialize even when the app has not added the Play Integrity dependency.
 */
public final class PlayIntegrityHelper {
  private PlayIntegrityHelper() {}

  public static boolean isPlayIntegrityAvailable(Context context) {
    try {
      Class<?> apiClass = Class.forName("com.google.android.gms.common.GoogleApiAvailability");
      Object api = apiClass.getMethod("getInstance").invoke(null);
      int result = (Integer) apiClass
          .getMethod("isGooglePlayServicesAvailable", Context.class)
          .invoke(api, context);
      Class<?> connectionResultClass = Class.forName("com.google.android.gms.common.ConnectionResult");
      int success = connectionResultClass.getField("SUCCESS").getInt(null);
      return result == success;
    } catch (Throwable t) {
      return false;
    }
  }

  public static void requestIntegrityToken(Context context, String nonce, Promise promise) {
    try {
      Class<?> factoryClass = Class.forName("com.google.android.play.core.integrity.IntegrityManagerFactory");
      Object manager = factoryClass.getMethod("create", Context.class).invoke(null, context);

      Class<?> requestClass = Class.forName("com.google.android.play.core.integrity.IntegrityTokenRequest");
      Object builder = requestClass.getMethod("builder").invoke(null);
      builder.getClass().getMethod("setNonce", String.class).invoke(builder, nonce);
      Object request = builder.getClass().getMethod("build").invoke(builder);

      Object task = manager.getClass()
          .getMethod("requestIntegrityToken", requestClass)
          .invoke(manager, request);

      Class<?> onSuccessListenerClass = Class.forName("com.google.android.gms.tasks.OnSuccessListener");
      Object successListener = Proxy.newProxyInstance(
          onSuccessListenerClass.getClassLoader(),
          new Class<?>[] { onSuccessListenerClass },
          new OnSuccessHandler(promise)
      );

      Class<?> onFailureListenerClass = Class.forName("com.google.android.gms.tasks.OnFailureListener");
      Object failureListener = Proxy.newProxyInstance(
          onFailureListenerClass.getClassLoader(),
          new Class<?>[] { onFailureListenerClass },
          new OnFailureHandler(promise)
      );

      task.getClass()
          .getMethod("addOnSuccessListener", onSuccessListenerClass)
          .invoke(task, successListener);
      task.getClass()
          .getMethod("addOnFailureListener", onFailureListenerClass)
          .invoke(task, failureListener);
    } catch (Throwable t) {
      promise.reject("ATTESTATION_ERROR", "Play Integrity API unavailable: " + t.getMessage(), t);
    }
  }

  private static final class OnSuccessHandler implements InvocationHandler {
    private final Promise promise;

    private OnSuccessHandler(Promise promise) {
      this.promise = promise;
    }

    @Override
    public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
      if ("onSuccess".equals(method.getName()) && args != null && args.length == 1) {
        Object response = args[0];
        String token = (String) response.getClass().getMethod("token").invoke(response);
        promise.resolve(token);
      }
      return null;
    }
  }

  private static final class OnFailureHandler implements InvocationHandler {
    private final Promise promise;

    private OnFailureHandler(Promise promise) {
      this.promise = promise;
    }

    @Override
    public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
      if ("onFailure".equals(method.getName()) && args != null && args.length >= 1) {
        Exception error = args[0] instanceof Exception
            ? (Exception) args[0]
            : new Exception(String.valueOf(args[0]));
        promise.reject("ATTESTATION_ERROR", error.getMessage(), error);
      }
      return null;
    }
  }
}
