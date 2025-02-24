package com.securitysuite;

import android.app.Activity;
import android.graphics.Color;
import android.view.View;
import android.view.Window;
import android.view.WindowManager;
import android.widget.FrameLayout;
import android.content.Context;

import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReadableMap;
import com.facebook.react.bridge.ReadableType;
import com.facebook.react.uimanager.ThemedReactContext;
import com.facebook.react.uimanager.UIManagerModule;
import com.facebook.react.uimanager.annotations.ReactProp;

public class SecureView extends FrameLayout {
  ReactApplicationContext reactContext;

  public SecureView(Context context, ReactApplicationContext reactContext) {
    super(context);
    this.reactContext = reactContext;
  }

  @Override
  public void requestLayout() {
    super.requestLayout();
    post(measureAndLayout);
  }

    @Override
    protected void onAttachedToWindow() {
      super.onAttachedToWindow();
      final Activity activity = reactContext.getCurrentActivity();
      if (activity != null) {
        activity.runOnUiThread(() -> {
          Window window = activity.getWindow();
          window.addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        });
      }
  }

    @Override
    protected void onDetachedFromWindow() {
      super.onDetachedFromWindow();
      final Activity activity = reactContext.getCurrentActivity();
      if (activity != null) {
        activity.runOnUiThread(() -> {
          Window window = activity.getWindow();
          window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE);
        });
      }
  }

  @Override
  public void addView(View child, int index) {
    super.addView(child, index);
  }

  private final Runnable measureAndLayout = () -> {
    measure(
            MeasureSpec.makeMeasureSpec(getWidth(), MeasureSpec.EXACTLY),
            MeasureSpec.makeMeasureSpec(getHeight(), MeasureSpec.EXACTLY));
    layout(getLeft(), getTop(), getRight(), getBottom());
  };

  @Override
  protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
    int width = MeasureSpec.getSize(widthMeasureSpec);
    int height = MeasureSpec.getSize(heightMeasureSpec);
    setMeasuredDimension(width, height);

    ThemedReactContext reactContext = (ThemedReactContext) getContext();
    UIManagerModule uiManagerModule = reactContext.getNativeModule(UIManagerModule.class);

    if (uiManagerModule != null) {
      reactContext.runOnNativeModulesQueueThread(() -> uiManagerModule.updateNodeSize(getId(), width, height));
    }
  }

  @ReactProp(name = "style")
  public void setStyle(ReadableMap style) {
    if (style.hasKey("backgroundColor")) {
      try {
        String color = style.getString("backgroundColor");
        setBackgroundColor(Color.parseColor(color));
      } catch (IllegalArgumentException e) {
        setBackgroundColor(Color.TRANSPARENT);
      }
    }

    if (style.hasKey("width")) {
      setViewSize("width", style);
    }

    if (style.hasKey("height")) {
      setViewSize("height", style);
    }
  }

  private void setViewSize(String prop, ReadableMap style) {
    try {
      if (style.getType(prop) == ReadableType.Number) {
        int value = style.getInt(prop);
        if (prop.equals("width")) {
          getLayoutParams().width = value;
        } else if (prop.equals("height")) {
          getLayoutParams().height = value;
        }
      } else if (style.getType(prop) == ReadableType.String) {
        String value = style.getString(prop);
        if (value.endsWith("%")) {
          float percent = Float.parseFloat(value.replace("%", "")) / 100;
          int parentSize = prop.equals("width") ? getRootView().getWidth() : getRootView().getHeight();
          int calculatedSize = (int) (percent * parentSize);
          if (prop.equals("width")) {
            getLayoutParams().width = calculatedSize;
          } else {
            getLayoutParams().height = calculatedSize;
          }
        }
      }
      requestLayout();
    } catch (Exception e) {
      e.printStackTrace();
    }
  }
}
