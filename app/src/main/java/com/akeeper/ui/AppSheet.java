package com.akeeper.ui;

import android.content.pm.PackageManager;
import android.text.format.Formatter;
import android.view.View;
import android.widget.ImageView;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import com.akeeper.R;
import com.akeeper.vpn.ActivityLog;
import com.google.android.material.bottomsheet.BottomSheetDialog;
import com.google.android.material.materialswitch.MaterialSwitch;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.function.BiConsumer;
import java.util.stream.Collectors;

/**
 * Détail d'une app (A3) : accès Internet, UID partagé et activité récente de l'UID. Les règles distinctes
 * Wi-Fi / mobile sont hors MVP, comme le précise la spec.
 */
final class AppSheet {

    private static final int LIMIT = 50;

    private AppSheet() {
    }

    /**
     * @param onToggle (app, accès Internet souhaité), le même chemin que l'interrupteur de la liste
     * @param worker   thread de travail de l'écran Apps
     */
    static void show(AppCompatActivity activity, View anchor, AppEntry app, List<AppEntry> all, boolean allowed,
                     BiConsumer<AppEntry, Boolean> onToggle, ExecutorService worker) {
        var dialog = new BottomSheetDialog(activity);
        var view = activity.getLayoutInflater().inflate(R.layout.sheet_app, null);
        var text = new EventText(activity);
        try {
            ((ImageView) view.findViewById(R.id.sheet_app_icon))
                    .setImageDrawable(activity.getPackageManager().getApplicationIcon(app.packageName()));
        } catch (PackageManager.NameNotFoundException uninstalled) {
            // Sans icône : l'en-tête garde le nom.
        }
        ((TextView) view.findViewById(R.id.sheet_app_label)).setText(app.label());
        ((TextView) view.findViewById(R.id.sheet_app_profile)).setText(switch (app.compatibilityProfile()) {
            case FINANCE -> R.string.app_detail_profile_finance;
            case PAYMENT -> R.string.app_detail_profile_payment;
            case SYSTEM_CONNECTIVITY -> R.string.app_detail_profile_connectivity;
            case DEFAULT -> app.system() ? R.string.app_detail_profile_system : R.string.app_detail_profile_standard;
        });
        view.findViewById(R.id.sheet_app_sensitive).setVisibility(
                app.system() || app.compatibilityProfile().requiresBlockWarning() ? View.VISIBLE : View.GONE);
        ((TextView) view.findViewById(R.id.sheet_app_access_state)).setText(
                allowed ? R.string.app_detail_access_allowed : R.string.app_detail_access_blocked);

        MaterialSwitch toggle = view.findViewById(R.id.sheet_app_toggle);
        toggle.setChecked(allowed);
        toggle.setOnCheckedChangeListener((button, checked) -> {
            dialog.dismiss();
            onToggle.accept(app, checked);
        });

        var others = all.stream().filter(a -> a.uid() == app.uid() && !a.packageName().equals(app.packageName()))
                .map(AppEntry::label).collect(Collectors.joining(", "));
        TextView shared = view.findViewById(R.id.sheet_app_shared);
        if (!others.isEmpty()) {
            shared.setText(activity.getString(R.string.app_detail_shared, others));
            shared.setVisibility(View.VISIBLE);
        }

        RecyclerView events = view.findViewById(R.id.sheet_app_events);
        events.setLayoutManager(new LinearLayoutManager(activity));
        var adapter = new EventAdapter(text, false, false, event -> EventSheet.show(activity, anchor, text, event, worker));
        events.setAdapter(adapter);
        dialog.setContentView(view);
        dialog.show();

        try {
            worker.execute(() -> {
                List<com.akeeper.engine.FlowEvent> loaded;
                try {
                    loaded = ActivityLog.get(activity)
                            .query(new ActivityLog.Query(false, app.uid(), LIMIT));
                } catch (GeneralSecurityException | IOException | RuntimeException unavailable) {
                    loaded = List.of();
                }
                var shown = loaded;
                int recentBlocked = loaded.stream().filter(com.akeeper.engine.FlowEvent::blocked)
                        .mapToInt(com.akeeper.engine.FlowEvent::count).sum();
                long now = System.currentTimeMillis();
                String volume = null;
                try {
                    var log = ActivityLog.get(activity);
                    long[] day = log.traffic(app.uid(), now - TimeUnit.DAYS.toMillis(1));
                    long[] week = log.traffic(app.uid(), now - TimeUnit.DAYS.toMillis(7));
                    if (week[0] + week[1] > 0) {
                        volume = activity.getString(R.string.app_detail_volume,
                                Formatter.formatShortFileSize(activity, day[0]),
                                Formatter.formatShortFileSize(activity, day[1]),
                                Formatter.formatShortFileSize(activity, week[0]),
                                Formatter.formatShortFileSize(activity, week[1]));
                    }
                } catch (GeneralSecurityException | IOException | RuntimeException unavailable) {
                    // Volumes indisponibles : le texte par défaut reste.
                }
                var shownVolume = volume;
                activity.runOnUiThread(() -> {
                    if (shownVolume != null) {
                        ((TextView) view.findViewById(R.id.sheet_app_volume)).setText(shownVolume);
                    }
                    ((TextView) view.findViewById(R.id.sheet_app_blocked)).setText(
                            activity.getString(R.string.app_detail_trackers, recentBlocked));
                    adapter.submit(shown);
                    view.findViewById(R.id.sheet_app_empty).setVisibility(shown.isEmpty() ? View.VISIBLE : View.GONE);
                    events.setVisibility(shown.isEmpty() ? View.GONE : View.VISIBLE);
                });
            });
        } catch (RejectedExecutionException closed) {
            // Écran Apps fermé entre-temps.
        }
    }
}
