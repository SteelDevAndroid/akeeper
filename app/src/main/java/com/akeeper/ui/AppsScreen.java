package com.akeeper.ui;

import android.text.Editable;
import android.text.TextWatcher;
import android.view.View;
import android.widget.EditText;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import com.akeeper.R;
import com.akeeper.ui.AppFilter.Scope;
import com.akeeper.vpn.AppRules;
import com.akeeper.vpn.ShieldStatus;
import com.google.android.material.chip.ChipGroup;
import com.google.android.material.dialog.MaterialAlertDialogBuilder;
import com.google.android.material.snackbar.Snackbar;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.stream.Collectors;

/**
 * Écran Apps (A2) : un interrupteur « Accès Internet » par app. Le chargement et l'écriture chiffrée
 * des règles tournent sur un thread dédié ; toute mise à jour de vue repasse par le thread principal.
 */
final class AppsScreen implements AutoCloseable {

    private final AppCompatActivity activity;
    private final View root;
    private final AppAdapter adapter;
    private final ExecutorService worker = Executors.newSingleThreadExecutor();

    private List<AppEntry> apps = List.of();
    private Set<String> blocked = Set.of();
    private Scope scope = Scope.ALL;
    private String query = "";
    private AppRules rules;
    private ShieldStatus.Subscription subscription;

    AppsScreen(AppCompatActivity activity, View root) {
        this.activity = activity;
        this.root = root;
        this.adapter = new AppAdapter(activity.getPackageManager(), this::onToggle);

        RecyclerView list = root.findViewById(R.id.apps_list);
        list.setLayoutManager(new LinearLayoutManager(activity));
        list.setAdapter(adapter);

        ChipGroup scopes = root.findViewById(R.id.apps_scopes);
        scopes.setOnCheckedStateChangeListener((group, checked) -> {
            int id = checked.isEmpty() ? R.id.apps_scope_all : checked.getFirst();
            scope = id == R.id.apps_scope_blocked ? Scope.BLOCKED
                    : id == R.id.apps_scope_system ? Scope.SYSTEM : Scope.ALL;
            refresh();
        });
        EditText search = root.findViewById(R.id.apps_search);
        search.addTextChangedListener(new TextWatcher() {
            @Override
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {
            }

            @Override
            public void onTextChanged(CharSequence s, int start, int before, int count) {
            }

            @Override
            public void afterTextChanged(Editable s) {
                query = s.toString();
                refresh();
            }
        });
        load();
    }

    private void load() {
        var packageManager = activity.getPackageManager();
        var ownPackage = activity.getPackageName();
        worker.execute(() -> {
            var loaded = AppCatalog.load(packageManager, ownPackage);
            AppRules opened;
            try {
                opened = AppRules.get(activity);
            } catch (GeneralSecurityException | IOException keystoreUnavailable) {
                opened = null;
            }
            var store = opened;
            activity.runOnUiThread(() -> {
                apps = loaded;
                root.findViewById(R.id.apps_loading).setVisibility(View.GONE);
                if (store == null) {
                    ((TextView) root.findViewById(R.id.apps_empty)).setText(R.string.apps_rules_unavailable);
                    refresh();
                    return;
                }
                rules = store;
                subscription = store.observe(next -> activity.runOnUiThread(() -> {
                    blocked = next;
                    refresh();
                }));
            });
        });
    }

    private void refresh() {
        var visible = rules == null ? List.<AppEntry>of() : AppFilter.apply(apps, query, scope, blocked);
        adapter.submit(visible, blocked);
        root.findViewById(R.id.apps_empty).setVisibility(visible.isEmpty() && !apps.isEmpty() || rules == null
                ? View.VISIBLE : View.GONE);
    }

    private void onToggle(AppEntry app, boolean allowed) {
        // UID partagé : le moteur bloque par UID, les apps du groupe sont donc basculées ensemble.
        var group = apps.stream().filter(a -> a.uid() == app.uid()).map(AppEntry::packageName)
                .collect(Collectors.toUnmodifiableSet());
        if (!allowed && app.system()) {
            new MaterialAlertDialogBuilder(activity)
                    .setTitle(activity.getString(R.string.apps_system_confirm_title, app.label()))
                    .setMessage(R.string.apps_system_confirm_body)
                    .setNegativeButton(R.string.action_cancel, (dialog, which) -> refresh())
                    .setPositiveButton(R.string.apps_system_confirm_action, (dialog, which) -> apply(app, group, false))
                    .setOnCancelListener(dialog -> refresh())
                    .show();
            return;
        }
        apply(app, group, allowed);
    }

    private void apply(AppEntry app, Set<String> group, boolean allowed) {
        var store = rules;
        if (store == null) {
            return;
        }
        worker.execute(() -> {
            try {
                store.setBlocked(group, !allowed);
            } catch (IOException e) {
                activity.runOnUiThread(() -> {
                    Snackbar.make(root, R.string.apps_save_failed, Snackbar.LENGTH_LONG).show();
                    refresh();
                });
                return;
            }
            activity.runOnUiThread(() -> Snackbar
                    .make(root, activity.getString(allowed ? R.string.apps_allowed : R.string.apps_blocked, app.label()),
                            Snackbar.LENGTH_LONG)
                    .setAction(R.string.action_undo, v -> apply(app, group, !allowed))
                    .show());
        });
    }

    @Override
    public void close() {
        if (subscription != null) {
            subscription.close();
        }
        worker.shutdown();
    }
}
