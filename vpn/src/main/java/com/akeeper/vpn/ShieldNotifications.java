package com.akeeper.vpn;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;

import java.util.List;

final class ShieldNotifications {

    static final int STATUS_ID = 1;
    private static final int ALERT_ID = 2;
    private static final int PRIVATE_DNS_ALERT_ID = 3;
    private static final String CHANNEL_STATUS = "status";
    private static final String CHANNEL_ALERTS = "alerts";

    private ShieldNotifications() {
    }

    static void createChannels(Context context) {
        var status = new NotificationChannel(CHANNEL_STATUS, context.getString(R.string.channel_status),
                NotificationManager.IMPORTANCE_LOW);
        status.setDescription(context.getString(R.string.channel_status_description));
        status.setShowBadge(false);
        var alerts = new NotificationChannel(CHANNEL_ALERTS, context.getString(R.string.channel_alerts),
                NotificationManager.IMPORTANCE_HIGH);
        alerts.setDescription(context.getString(R.string.channel_alerts_description));
        context.getSystemService(NotificationManager.class).createNotificationChannels(List.of(status, alerts));
    }

    static Notification persistent(Context context) {
        return new Notification.Builder(context, CHANNEL_STATUS)
                .setSmallIcon(R.drawable.ic_shield)
                .setContentTitle(context.getString(R.string.status_protected))
                .setContentText(context.getString(R.string.status_dns_filtering))
                .setCategory(Notification.CATEGORY_SERVICE)
                .setOngoing(true)
                .setContentIntent(openApp(context))
                .build();
    }

    static void alertPrivateDnsStrict(Context context) {
        var notification = new Notification.Builder(context, CHANNEL_ALERTS)
                .setSmallIcon(R.drawable.ic_shield)
                .setContentTitle(context.getString(R.string.alert_private_dns_title))
                .setContentText(context.getString(R.string.alert_private_dns_text))
                .setCategory(Notification.CATEGORY_ERROR)
                .setAutoCancel(true)
                .setContentIntent(openApp(context))
                .build();
        context.getSystemService(NotificationManager.class).notify(PRIVATE_DNS_ALERT_ID, notification);
    }

    static void alertRevoked(Context context) {
        var notification = new Notification.Builder(context, CHANNEL_ALERTS)
                .setSmallIcon(R.drawable.ic_shield)
                .setContentTitle(context.getString(R.string.alert_revoked_title))
                .setContentText(context.getString(R.string.alert_revoked_text))
                .setCategory(Notification.CATEGORY_ERROR)
                .setAutoCancel(true)
                .setContentIntent(openApp(context))
                .build();
        // Sans POST_NOTIFICATIONS, notify() est ignoré par le système : l'accueil affiche quand même l'état révoqué.
        context.getSystemService(NotificationManager.class).notify(ALERT_ID, notification);
    }

    private static PendingIntent openApp(Context context) {
        var launch = context.getPackageManager().getLaunchIntentForPackage(context.getPackageName());
        return launch == null ? null : PendingIntent.getActivity(context, 0, launch, PendingIntent.FLAG_IMMUTABLE);
    }
}
