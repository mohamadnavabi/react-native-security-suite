package com.securitysuite;

import android.app.Activity;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.view.WindowManager;

import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;

import com.facebook.react.bridge.ReactApplicationContext;

public class SecureViewFragment extends Fragment {
  SecureView secureView;
  ReactApplicationContext reactContext;

  public SecureViewFragment(ReactApplicationContext reactContext) {
    this.reactContext = reactContext;
  }

  @Override
  public View onCreateView(LayoutInflater inflater, ViewGroup parent, Bundle savedInstanceState) {
    super.onCreateView(inflater, parent, savedInstanceState);
    secureView = new SecureView(this.getContext(), this.reactContext);
    return secureView;
  }

  @Override
  public void onCreate(@Nullable Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    final Activity activity = getActivity();
    if (activity != null) {
      activity.runOnUiThread(new Runnable() {
        @Override
        public void run() {
          Window window = activity.getWindow();
          window.addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        }
      });
    }
  }

  @Override
  public void onDestroy() {
    super.onDestroy();
    final Activity activity = getActivity();
    if (activity != null) {
      activity.runOnUiThread(new Runnable() {
        @Override
        public void run() {
          Window window = activity.getWindow();
          window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE);
        }
      });
    }
  }
}
