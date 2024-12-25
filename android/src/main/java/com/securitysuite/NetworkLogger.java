package com.securitysuite;

import android.content.Context;

import com.facebook.react.modules.network.OkHttpClientFactory;
import com.facebook.react.modules.network.ReactCookieJarContainer;
import com.securitysuite.api.ChuckerInterceptor;

import okhttp3.OkHttpClient;
public class NetworkLogger implements OkHttpClientFactory {
  private Context context;

  public NetworkLogger(Context context) {
    this.context = context;
  }

  public OkHttpClient createNewNetworkModuleClient() {
    OkHttpClient client = new OkHttpClient.Builder()
      .addInterceptor(new ChuckerInterceptor.Builder(context).build())
      .cookieJar(new ReactCookieJarContainer())
      .build();

    return client;
  }
}
