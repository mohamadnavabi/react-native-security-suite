package com.securitysuite;

import android.view.Window;
import android.view.WindowManager;

public final class SecureWindowHelper {
  private static int refCount = 0;

  private SecureWindowHelper() {}

  public static synchronized void acquire(Window window) {
    if (window == null) {
      return;
    }
    if (refCount == 0) {
      window.addFlags(WindowManager.LayoutParams.FLAG_SECURE);
    }
    refCount++;
  }

  public static synchronized void release(Window window) {
    if (window == null) {
      return;
    }
    refCount = Math.max(0, refCount - 1);
    if (refCount == 0) {
      window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE);
    }
  }
}
