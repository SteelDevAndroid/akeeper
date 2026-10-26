package com.akeeper.vpn;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.graphics.drawable.Icon;
import android.text.format.DateFormat;

import java.util.Date;
import java.util.List;

final class ShieldNotifications {

    static final int STATUS_ID = 1;
    private static final int ALERT_ID = 2;
    private static final int PRIVATE_DNS_ALERT_ID = 3;
    private static final int LOCKDOWN_ALERT_ID = 4;
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

    /**
     * @param pausedUntil fin de la pause (horloge murale), 0 sans pause
     * @param blocked     requêtes bloquées depuis le démarrage du moteur, négatif si inconnu
     */
    static Notification persistent(Context context, long pausedUntil, long blocked) {
        boolean paused = pausedUntil > 0;
        String text;
        if (paused) {
            text = context.getString(R.string.status_paused_until,
                    DateFormat.getTimeFormat(context).format(new Date(pausedUntil)));
        } else if (blocked >= 0) {
            int count = (int) Math.min(blocked, Integer.MAX_VALUE);
            text = context.getResources().getQuantityString(R.plurals.status_blocked, count, count);
        } else {
            text = context.getString(R.string.status_dns_filtering);
        }
        var action = paused
                ? action(context, ShieldVpnService.ACTION_RESUME, R.string.action_resume)
                : action(context, ShieldVpnService.ACTION_PAUSE, R.string.action_pause);
        return new Notification.Builder(context, CHANNEL_STATUS)
                .setSmallIcon(R.drawable.ic_shield)
                .setContentTitle(context.getString(paused ? R.string.status_paused : R.string.status_protected))
                .setContentText(text)
                .setCategory(Notification.CATEGORY_SERVICE)
                .setOngoing(true)
                .setOnlyAlertOnce(true)
                .setContentIntent(openApp(context))
                .addAction(action)
                .build();
    }

    static void updatePersistent(Context context, long pausedUntil, long blocked) {
        context.getSystemService(NotificationManager.class)
                .notify(STATUS_ID, persistent(context, pausedUntil, blocked));
    }

    static void alertPrivateDnsStrict(Context context) {
        alert(context, PRIVATE_DNS_ALERT_ID, R.string.alert_private_dns_title, R.string.alert_private_dns_text);
    }

    // Sans POST_NOTIFICATIONS, notify() est ignoré par le système : l'accueil affiche quand même l'état.
    static void alertRevoked(Context context) {
        alert(context, ALERT_ID, R.string.alert_revoked_title, R.string.alert_revoked_text);
    }

    static void alertStopped(Context context) {
        alert(context, ALERT_ID, R.string.alert_stopped_title, R.string.alert_stopped_text);
    }

    static void alertLockdownLost(Context context) {
        alert(context, LOCKDOWN_ALERT_ID, R.string.alert_lockdown_title, R.string.alert_lockdown_text);
    }

    private static void alert(Context context, int id, int title, int text) {
        var notification = new Notification.Builder(context, CHANNEL_ALERTS)
                .setSmallIcon(R.drawable.ic_shield)
                .setContentTitle(context.getString(title))
                .setContentText(context.getString(text))
                .setCategory(Notification.CATEGORY_ERROR)
                .setAutoCancel(true)
                .setContentIntent(openApp(context))
                .build();
        context.getSystemService(NotificationManager.class).notify(id, notification);
    }

    private static Notification.Action action(Context context, String action, int label) {
        // Intent explicite vers le service non exporté : aucune autre app ne peut le déclencher ni le modifier.
        var intent = new Intent(context, ShieldVpnService.class).setAction(action);
        var pending = PendingIntent.getService(context, action.hashCode(), intent, PendingIntent.FLAG_IMMUTABLE);
        return new Notification.Action.Builder(Icon.createWithResource(context, R.drawable.ic_shield),
                context.getString(label), pending).build();
    }

    static PendingIntent openApp(Context context) {
        var launch = context.getPackageManager().getLaunchIntentForPackage(context.getPackageName());
        return launch == null ? null : PendingIntent.getActivity(context, 0, launch, PendingIntent.FLAG_IMMUTABLE);
    }
}
