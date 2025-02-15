package com.securitysuite

import android.graphics.Color
import android.view.View
import android.view.ViewTreeObserver
import com.facebook.react.uimanager.SimpleViewManager
import com.facebook.react.uimanager.ThemedReactContext
import com.facebook.react.uimanager.annotations.ReactProp

class ScreenGuard: SimpleViewManager<View>() {

  override fun getName(): String {
    return "SecureView"
  }

  override fun createViewInstance(reactContext: ThemedReactContext): View {
    val secureView = View(reactContext)
    secureView.setBackgroundColor(Color.TRANSPARENT)

    secureView.viewTreeObserver.addOnWindowVisibilityChangeListener { visibility ->
      if (visibility == View.VISIBLE) {
        secureView.setBackgroundColor(Color.TRANSPARENT)
      } else {
        secureView.setBackgroundColor(Color.BLACK)
      }
    }

    return secureView
  }

  fun addScreenGuard(view: View, secure: Boolean) {
    if (secure) {
      view.setBackgroundColor(Color.BLACK)
    } else {
      view.setBackgroundColor(Color.TRANSPARENT)
    }
  }
}
