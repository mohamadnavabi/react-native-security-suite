package com.securitysuite;

import android.content.Context;
import android.view.View;
import android.widget.FrameLayout;

import com.facebook.react.uimanager.ThemedReactContext;
import com.facebook.react.uimanager.UIManagerModule;

public class SecureView extends FrameLayout {
  private View contentView;

  public SecureView(Context context) {
    super(context);
  }

  @Override
  public void requestLayout() {
    super.requestLayout();
    post(measureAndLayout);
  }

  private final Runnable measureAndLayout = () -> {
    measure(
      MeasureSpec.makeMeasureSpec(getWidth(), MeasureSpec.EXACTLY),
      MeasureSpec.makeMeasureSpec(getHeight(), MeasureSpec.EXACTLY));
    layout(getLeft(), getTop(), getRight(), getBottom());
  };

  @Override
  protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
    int maxWidth = 0;
    int maxHeight = 0;

    for (int i = 0; i < getChildCount(); i++) {
      View child = getChildAt(i);
      if (child.getVisibility() != GONE) {
        child.measure(widthMeasureSpec, MeasureSpec.UNSPECIFIED);

        maxWidth = Math.max(maxWidth, child.getMeasuredWidth());
        maxHeight = Math.max(maxHeight, child.getMeasuredHeight());
      }
    }

    int finalWidth = Math.max(maxWidth, getSuggestedMinimumWidth());
    int finalHeight = Math.max(maxHeight, getSuggestedMinimumHeight());

    setMeasuredDimension(finalWidth, finalHeight);

    ThemedReactContext reactContext = (ThemedReactContext) getContext();
    UIManagerModule uiManagerModule = reactContext.getNativeModule(UIManagerModule.class);

    if (uiManagerModule != null) {
      reactContext.runOnNativeModulesQueueThread(() -> uiManagerModule.updateNodeSize(getId(), finalWidth, finalHeight));
    }
  }


  public void setContentView(View view) {
    contentView = view;
    addView(contentView);
  }

  public View getContentView() {
    return contentView;
  }
}
