package com.securitysuite;

import android.util.Log;
import android.view.Choreographer;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.FragmentActivity;

import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReadableArray;
import com.facebook.react.common.MapBuilder;
import com.facebook.react.uimanager.annotations.ReactPropGroup;
import com.facebook.react.uimanager.ViewGroupManager;
import com.facebook.react.uimanager.ThemedReactContext;

import java.util.Map;

public class SecureViewManager extends ViewGroupManager<SecureView> {

  public static final String REACT_CLASS = "SecureView";
  public final int COMMAND_CREATE = 1;
  private int propWidth;
  private int propHeight;

  ReactApplicationContext reactContext;

  public SecureViewManager(ReactApplicationContext reactContext) {
    this.reactContext = reactContext;
  }

  @Override
  public String getName() {
    return REACT_CLASS;
  }

  @Override
  public SecureView createViewInstance(ThemedReactContext reactContext) {
    return new SecureView(reactContext);
  }

  @Nullable
  @Override
  public Map<String, Integer> getCommandsMap() {
    return MapBuilder.of("create", COMMAND_CREATE);
  }

  public void receiveCommand(
      @NonNull FrameLayout root,
      String commandId,
      @Nullable ReadableArray args) {
    super.receiveCommand((SecureView) root, commandId, args);
    int reactNativeViewId = args.getInt(0);
    int commandIdInt = Integer.parseInt(commandId);

    switch (commandIdInt) {
      case COMMAND_CREATE:
        createFragment(root, reactNativeViewId);
        break;
      default: {
      }
    }
  }

  @ReactPropGroup(names = { "width", "height" }, customType = "Style")
  public void setStyle(FrameLayout view, int index, Integer value) {
    if (index == 0) {
      propWidth = value == -1 ? ViewGroup.LayoutParams.MATCH_PARENT : value;
    }

    if (index == 1) {
      propHeight = value == -1 ? ViewGroup.LayoutParams.MATCH_PARENT : value;
    }
  }

  public void createFragment(FrameLayout root, int reactNativeViewId) {
    ViewGroup parentView = (ViewGroup) root.findViewById(reactNativeViewId);
    setupLayout(parentView);

    final SecureFragment myFragment = new SecureFragment();
    FragmentActivity activity = (FragmentActivity) reactContext.getCurrentActivity();
    activity.getSupportFragmentManager()
        .beginTransaction()
        .replace(reactNativeViewId, myFragment, String.valueOf(reactNativeViewId))
        .commit();
  }

  public void setupLayout(View view) {
    Choreographer.getInstance().postFrameCallback(new Choreographer.FrameCallback() {
      @Override
      public void doFrame(long frameTimeNanos) {
        manuallyLayoutChildren(view);
        view.getViewTreeObserver().dispatchOnGlobalLayout();
        Choreographer.getInstance().postFrameCallback(this);
      }
    });
  }

  public void manuallyLayoutChildren(View view) {
    int width = propWidth == ViewGroup.LayoutParams.MATCH_PARENT ? ViewGroup.LayoutParams.MATCH_PARENT : propWidth;
    int height = propHeight == ViewGroup.LayoutParams.MATCH_PARENT ? ViewGroup.LayoutParams.MATCH_PARENT : propHeight;

    view.measure(
        View.MeasureSpec.makeMeasureSpec(width, View.MeasureSpec.EXACTLY),
        View.MeasureSpec.makeMeasureSpec(height, View.MeasureSpec.EXACTLY));

    view.layout(0, 0, width, height);
  }
}
