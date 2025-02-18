package com.securitysuite;

import android.app.Activity;
import android.content.Context;
import android.os.Bundle;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.view.WindowManager;

import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;

public class SecureFragment extends Fragment {
  SecureView secureView;

  @Override
  public View onCreateView(LayoutInflater inflater, ViewGroup parent, Bundle savedInstanceState) {
    super.onCreateView(inflater, parent, savedInstanceState);
    secureView = new SecureView(this.getContext());
    return secureView;
  }

  @Override
  public void onCreate(@Nullable Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    Log.d("SecureFragment", "onCreate");
  }

  @Override
  public void onAttach(Context context) {
    super.onAttach(context);
    Log.d("SecureFragment", "onAttach");
  }

  @Override
  public void onActivityCreated(@Nullable Bundle savedInstanceState) {
    super.onActivityCreated(savedInstanceState);
    Log.d("SecureFragment", "onActivityCreated");
  }

  @Override
  public void onViewCreated(View view, Bundle savedInstanceState) {
    super.onViewCreated(view, savedInstanceState);
    Log.d("SecureFragment", "onViewCreated");
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
  public void onPause() {
    super.onPause();
    Log.d("SecureFragment", "onPause");
  }

  @Override
  public void onResume() {
    super.onResume();
    Log.d("SecureFragment", "onResume");
  }

  @Override
  public void onDestroy() {
    super.onDestroy();
    Log.d("SecureFragment", "onDestroy");
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
