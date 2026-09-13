package com.securitysuite;

import android.app.Activity;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Build;

import com.chuckerteam.chucker.api.Chucker;
import com.facebook.react.bridge.ReactApplicationContext;

/**
 * Persistent "Recording HTTP Activity" notification that opens Chucker when tapped.
 * Android counterpart of ios/PulseUINotification.swift.
 */
final class NetworkLoggerNotification {
  private static final String CHANNEL_ID = "security_suite_network_logger";
  private static final String POST_NOTIFICATIONS = "android.permission.POST_NOTIFICATIONS";
  private static final int NOTIFICATION_ID = 0x5EC1;
  private static boolean permissionRequested = false;

  private NetworkLoggerNotification() {}

  static void show(ReactApplicationContext context, String body) {
    if (!hasPermission(context)) {
      requestPermission(context);
      return;
    }

    NotificationManager manager =
        (NotificationManager) context.getSystemService(Context.NOTIFICATION_SERVICE);
    if (manager == null) {
      return;
    }

    Notification.Builder builder;
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
      manager.createNotificationChannel(new NotificationChannel(
          CHANNEL_ID, "Network Logger", NotificationManager.IMPORTANCE_LOW));
      builder = new Notification.Builder(context, CHANNEL_ID);
    } else {
      builder = new Notification.Builder(context).setPriority(Notification.PRIORITY_LOW);
    }

    PendingIntent contentIntent = PendingIntent.getActivity(
        context,
        NOTIFICATION_ID,
        Chucker.getLaunchIntent(context),
        PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);

    Notification notification = builder
        .setSmallIcon(com.chuckerteam.chucker.R.drawable.chucker_ic_transaction_notification)
        .setContentTitle("Recording HTTP Activity")
        .setContentText(body)
        .setContentIntent(contentIntent)
        .setOngoing(true)
        .setOnlyAlertOnce(true)
        .setShowWhen(false)
        .build();

    manager.notify(NOTIFICATION_ID, notification);
  }

  private static boolean hasPermission(Context context) {
    return Build.VERSION.SDK_INT < 33
        || context.checkSelfPermission(POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED;
  }

  private static synchronized void requestPermission(ReactApplicationContext context) {
    if (permissionRequested) {
      return;
    }
    final Activity activity = context.getCurrentActivity();
    if (activity == null) {
      return;
    }
    permissionRequested = true;
    activity.runOnUiThread(new Runnable() {
      @Override
      public void run() {
        activity.requestPermissions(new String[] {POST_NOTIFICATIONS}, NOTIFICATION_ID);
      }
    });
  }
}
