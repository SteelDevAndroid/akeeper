package com.akeeper.ui;

import android.content.pm.PackageManager;
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
import java.util.function.BiConsumer;
import java.util.stream.Collectors;

/**
 * Détail d'une app (A3) : accès Internet, UID partagé et activité récente de l'UID. Hors MVP, comme le précise la
 * spec : volumes de données et règles distinctes Wi-Fi / mobile.
 */
final class AppSheet {

    private static final int LIMIT = 100;

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
        var adapter = new EventAdapter(text, false, event -> EventSheet.show(activity, anchor, text, event, worker));
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
                activity.runOnUiThread(() -> {
                    adapter.submit(shown);
                    view.findViewById(R.id.sheet_app_empty).setVisibility(shown.isEmpty() ? View.VISIBLE : View.GONE);
                });
            });
        } catch (RejectedExecutionException closed) {
            // Écran Apps fermé entre-temps.
        }
    }
}
