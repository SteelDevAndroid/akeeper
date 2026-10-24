package com.akeeper.ui;

import android.os.Handler;
import android.os.Looper;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.View;
import android.widget.EditText;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import com.akeeper.R;
import com.akeeper.engine.FlowEvent;
import com.akeeper.vpn.ActivityLog;
import com.akeeper.vpn.AppPrefs;
import com.google.android.material.chip.ChipGroup;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.time.LocalDate;
import java.time.ZoneId;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;

/**
 * Activité (A4) : le journal chiffré, plus récent d'abord. La base (Keystore, E/S) n'est ouverte et interrogée que sur
 * le thread de travail ; le résultat repasse par le thread principal. L'écran se recharge toutes les 2 s tant qu'il est
 * affiché, le service écrivant par lots chaque seconde.
 */
final class ActivityScreen implements AutoCloseable {

    private static final long REFRESH_MS = 2_000;
    private static final int LIMIT = 500;

    private enum Scope { BLOCKED, ALLOWED, ALL }

    private final AppCompatActivity activity;
    private final View root;
    private final EventText text;
    private final EventAdapter adapter;
    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private final Handler handler = new Handler(Looper.getMainLooper());
    private final Runnable tick = this::reload;
    private Scope scope = Scope.BLOCKED;
    private String query = "";
    private boolean closed;
    // Valeurs lues sur le thread de travail, affichées sur le principal.
    private volatile AppPrefs prefs;

    ActivityScreen(AppCompatActivity activity, View root) {
        this.activity = activity;
        this.root = root;
        this.text = new EventText(activity);
        this.adapter = new EventAdapter(text, true, event -> EventSheet.show(activity, root, text, event, worker));

        RecyclerView list = root.findViewById(R.id.activity_list);
        list.setLayoutManager(new LinearLayoutManager(activity));
        list.setAdapter(adapter);

        ChipGroup scopes = root.findViewById(R.id.activity_scopes);
        scopes.setOnCheckedStateChangeListener((group, checked) -> {
            int id = checked.isEmpty() ? R.id.activity_scope_blocked : checked.getFirst();
            scope = id == R.id.activity_scope_allowed ? Scope.ALLOWED
                    : id == R.id.activity_scope_all ? Scope.ALL : Scope.BLOCKED;
            reload();
        });
        EditText search = root.findViewById(R.id.activity_search);
        search.addTextChangedListener(new TextWatcher() {
            @Override
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {
            }

            @Override
            public void onTextChanged(CharSequence s, int start, int before, int count) {
            }

            @Override
            public void afterTextChanged(Editable s) {
                query = s.toString().trim().toLowerCase(Locale.ROOT);
                reload();
            }
        });
        root.findViewById(R.id.activity_enable).setOnClickListener(v -> setLogEnabled());
        reload();
    }

    private void reload() {
        handler.removeCallbacks(tick);
        if (closed) {
            return;
        }
        var wanted = scope;
        var needle = query;
        try {
            worker.execute(() -> load(wanted, needle));
        } catch (RejectedExecutionException closedWhileQueued) {
            // Écran fermé entre-temps.
        }
    }

    private void load(Scope wanted, String needle) {
        AppPrefs loaded = prefs;
        try {
            if (loaded == null) {
                loaded = AppPrefs.get(activity);
                prefs = loaded;
            }
            var log = ActivityLog.get(activity);
            var events = log.query(new ActivityLog.Query(wanted == Scope.BLOCKED, ActivityLog.Query.ANY_UID, LIMIT))
                    .stream()
                    .filter(e -> wanted != Scope.ALLOWED || !e.blocked())
                    .filter(e -> needle.isEmpty() || e.name().toLowerCase(Locale.ROOT).contains(needle))
                    .toList();
            long midnight = LocalDate.now().atStartOfDay(ZoneId.systemDefault()).toInstant().toEpochMilli();
            long blockedToday = log.blockedSince(midnight);
            var settings = loaded.settings();
            // Résolution des libellés ici : PackageManager n'a rien à faire sur le thread principal.
            events.forEach(e -> text.app(e.uid()));
            activity.runOnUiThread(() -> show(events, blockedToday, settings, true));
        } catch (GeneralSecurityException | IOException | RuntimeException unavailable) {
            var settings = loaded == null ? AppPrefs.Settings.DEFAULT : loaded.settings();
            activity.runOnUiThread(() -> show(List.of(), 0, settings, false));
        }
    }

    private void show(List<FlowEvent> events, long blockedToday, AppPrefs.Settings settings, boolean available) {
        if (closed) {
            return;
        }
        adapter.submit(events);
        ((TextView) root.findViewById(R.id.activity_summary)).setText(
                activity.getString(R.string.activity_blocked_today, (int) Math.min(blockedToday, Integer.MAX_VALUE)));
        var empty = root.findViewById(R.id.activity_empty);
        empty.setVisibility(events.isEmpty() ? View.VISIBLE : View.GONE);
        var enable = root.findViewById(R.id.activity_enable);
        enable.setVisibility(!settings.logEnabled() && prefs != null ? View.VISIBLE : View.GONE);
        ((TextView) root.findViewById(R.id.activity_empty_text)).setText(
                !available ? R.string.activity_unavailable
                        : !settings.logEnabled() ? R.string.activity_disabled : R.string.activity_empty);
        ((TextView) root.findViewById(R.id.activity_footer)).setText(
                activity.getString(R.string.activity_footer, settings.retentionDays()));
        handler.postDelayed(tick, REFRESH_MS);
    }

    private void setLogEnabled() {
        var store = prefs;
        if (store == null) {
            return;
        }
        try {
            worker.execute(() -> {
                try {
                    store.update(settings -> settings.withLogEnabled(true));
                } catch (IOException ignored) {
                    // Le bouton reste affiché : l'utilisateur peut réessayer.
                }
                reload();
            });
        } catch (RejectedExecutionException closedWhileQueued) {
            // Écran fermé entre-temps.
        }
    }

    @Override
    public void close() {
        closed = true;
        handler.removeCallbacks(tick);
        worker.shutdown();
    }
}
