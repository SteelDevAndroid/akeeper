package com.akeeper.ui;

import android.text.Editable;
import android.text.TextWatcher;
import android.view.View;
import android.view.ViewGroup;
import android.view.inputmethod.EditorInfo;
import android.widget.LinearLayout;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;

import com.akeeper.R;
import com.akeeper.rules.RuleStore;
import com.akeeper.vpn.AppPrefs;
import com.akeeper.vpn.DomainRules;
import com.akeeper.vpn.RuleCategory;
import com.akeeper.vpn.ShieldStatus;
import com.akeeper.vpn.UserLists;
import com.google.android.material.button.MaterialButton;
import com.google.android.material.materialswitch.MaterialSwitch;
import com.google.android.material.snackbar.Snackbar;
import com.google.android.material.textfield.TextInputEditText;
import com.google.android.material.textfield.TextInputLayout;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.EnumMap;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;

/**
 * Listes de blocage (R2) : catégories, exceptions et domaines bloqués personnels. Les écritures (chiffrées pour les
 * préférences, atomiques pour les listes) et l'accès au Keystore tournent sur un thread dédié ; toute mise à jour de
 * vue repasse par le thread principal.
 */
final class ListsScreen implements AutoCloseable {

    private final AppCompatActivity activity;
    private final View root;
    private final UserLists userLists;
    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private final ShieldStatus.Subscription listChanges;
    private final Map<RuleCategory, View> categoryRows = new EnumMap<>(RuleCategory.class);
    private final Map<UserLists.Kind, LinearLayout> domainRows = new EnumMap<>(UserLists.Kind.class);
    // Écrit par le thread de travail, lu par le thread principal une fois les interrupteurs activés.
    private volatile AppPrefs prefs;
    private volatile boolean closed;

    ListsScreen(AppCompatActivity activity, View root, Runnable onBack) {
        this.activity = activity;
        this.root = root;
        this.userLists = UserLists.get(activity);

        root.findViewById(R.id.lists_back).setOnClickListener(v -> onBack.run());
        ViewGroup categories = root.findViewById(R.id.lists_categories);
        addCategory(categories, RuleCategory.ADS, R.string.category_ads, R.string.category_ads_sub);
        addCategory(categories, RuleCategory.PHISHING, R.string.category_phishing, R.string.category_phishing_sub);
        addCategory(categories, RuleCategory.MALWARE, R.string.category_malware, R.string.category_malware_sub);
        addBypassRow(categories);
        addDefaultExclusionsRow(categories);

        bindDomains(root.findViewById(R.id.lists_allowed), UserLists.Kind.ALLOWED);
        bindDomains(root.findViewById(R.id.lists_blocked), UserLists.Kind.BLOCKED);
        renderLists();
        listChanges = userLists.observe(lists -> onUi(this::renderLists));
        run(this::loadCategories);
    }

    private void addCategory(ViewGroup parent, RuleCategory category, int title, int subtitle) {
        var row = activity.getLayoutInflater().inflate(R.layout.item_switch_row, parent, false);
        ((TextView) row.findViewById(R.id.row_title)).setText(title);
        ((TextView) row.findViewById(R.id.row_subtitle)).setText(subtitle);
        // Inactif tant que l'on ignore ce que contiennent les règles et si les préférences sont lisibles.
        SwitchRow.bind(row).setEnabled(false);
        parent.addView(row);
        categoryRows.put(category, row);
    }

    private void addBypassRow(ViewGroup parent) {
        var row = activity.getLayoutInflater().inflate(R.layout.item_switch_row, parent, false);
        ((TextView) row.findViewById(R.id.row_title)).setText(R.string.lists_bypass_title);
        ((TextView) row.findViewById(R.id.row_subtitle)).setText(R.string.lists_bypass_sub);
        // Sans interrupteur : le désactiver viderait les autres règles de leur sens (docs/ui-ecrans.md, R2).
        row.findViewById(R.id.row_switch).setVisibility(View.GONE);
        parent.addView(row);
    }

    private void addDefaultExclusionsRow(ViewGroup parent) {
        var row = activity.getLayoutInflater().inflate(R.layout.item_switch_row, parent, false);
        ((TextView) row.findViewById(R.id.row_title)).setText(R.string.lists_default_title);
        ((TextView) row.findViewById(R.id.row_subtitle)).setText(R.string.lists_default_sub);
        // Sans interrupteur : une exclusion par défaut se contourne par une règle personnelle, pas en la désactivant.
        row.findViewById(R.id.row_switch).setVisibility(View.GONE);
        parent.addView(row);
    }

    /** Thread de travail : ce que contiennent les règles et les préférences, qui ouvrent le Keystore. */
    private void loadCategories() {
        var available = RuleStore.get(activity).categories();
        AppPrefs loaded = null;
        try {
            loaded = AppPrefs.get(activity);
        } catch (GeneralSecurityException | IOException keystoreUnavailable) {
            // Keystore indisponible : les interrupteurs restent inactifs, toutes les catégories restent actives.
        }
        prefs = loaded;
        var settings = loaded == null ? AppPrefs.Settings.DEFAULT : loaded.settings();
        onUi(() -> categoryRows.forEach((category, row) -> showCategory(category, row, available, settings)));
    }

    private void showCategory(RuleCategory category, View row, Set<Integer> available, AppPrefs.Settings settings) {
        MaterialSwitch toggle = row.findViewById(R.id.row_switch);
        TextView subtitle = row.findViewById(R.id.row_subtitle);
        boolean present = available.contains(category.id);
        if (!present) {
            subtitle.setText(R.string.category_unavailable);
        } else if (prefs == null) {
            subtitle.setText(R.string.category_prefs_unavailable);
        }
        toggle.setOnCheckedChangeListener(null);
        toggle.setChecked(!settings.disabledCategories().contains(category));
        toggle.setEnabled(present && prefs != null);
        toggle.setOnCheckedChangeListener((button, checked) -> run(() -> setCategory(category, checked, toggle)));
    }

    private void setCategory(RuleCategory category, boolean enabled, MaterialSwitch toggle) {
        try {
            prefs.update(settings -> settings.withCategory(category, enabled));
        } catch (IOException e) {
            onUi(() -> {
                toggle.setOnCheckedChangeListener(null);
                toggle.setChecked(!enabled);
                toggle.setOnCheckedChangeListener((button, checked) -> run(() -> setCategory(category, checked, toggle)));
                Snackbar.make(root, R.string.lists_save_failed, Snackbar.LENGTH_SHORT).show();
            });
        }
    }

    private void bindDomains(ViewGroup box, UserLists.Kind kind) {
        var rows = new LinearLayout(activity);
        rows.setOrientation(LinearLayout.VERTICAL);
        box.addView(rows);
        domainRows.put(kind, rows);

        var input = activity.getLayoutInflater().inflate(R.layout.view_domain_input, box, false);
        box.addView(input);
        TextInputLayout layout = input.findViewById(R.id.domain_input_layout);
        TextInputEditText field = input.findViewById(R.id.domain_input);
        MaterialButton add = input.findViewById(R.id.domain_add);
        add.setEnabled(false);
        field.addTextChangedListener(new TextWatcher() {
            @Override
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {
            }

            @Override
            public void onTextChanged(CharSequence s, int start, int before, int count) {
                boolean empty = s.toString().isBlank();
                boolean valid = DomainRules.normalize(s.toString()).isPresent();
                // Validation en direct : le bouton ne s'active que pour un domaine acceptable.
                layout.setError(empty || valid ? null : activity.getString(R.string.lists_domain_invalid));
                add.setEnabled(valid);
            }

            @Override
            public void afterTextChanged(Editable s) {
            }
        });
        View.OnClickListener submit = v -> {
            var text = String.valueOf(field.getText());
            if (DomainRules.normalize(text).isPresent()) {
                run(() -> addDomain(kind, text, field));
            }
        };
        add.setOnClickListener(submit);
        field.setOnEditorActionListener((view, action, event) -> {
            if (action == EditorInfo.IME_ACTION_DONE) {
                submit.onClick(view);
                return true;
            }
            return false;
        });
    }

    private void addDomain(UserLists.Kind kind, String text, TextInputEditText field) {
        try {
            if (userLists.add(kind, text).isPresent()) {
                onUi(() -> field.setText(""));
            }
        } catch (IOException e) {
            onUi(() -> Snackbar.make(root, R.string.lists_save_failed, Snackbar.LENGTH_SHORT).show());
        }
    }

    private void renderLists() {
        var lists = userLists.lists();
        for (var kind : UserLists.Kind.values()) {
            var rows = domainRows.get(kind);
            rows.removeAllViews();
            var domains = new TreeSet<>(lists.of(kind));
            if (domains.isEmpty()) {
                var empty = new TextView(activity);
                empty.setText(R.string.lists_empty);
                empty.setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_BodyMedium);
                empty.setPadding(dp(16), dp(12), dp(16), dp(4));
                rows.addView(empty);
            }
            domains.forEach(domain -> rows.addView(domainRow(kind, domain, rows)));
        }
    }

    private View domainRow(UserLists.Kind kind, String domain, ViewGroup parent) {
        var row = activity.getLayoutInflater().inflate(R.layout.item_domain_row, parent, false);
        ((TextView) row.findViewById(R.id.domain_name)).setText(domain);
        var remove = row.findViewById(R.id.domain_remove);
        remove.setContentDescription(activity.getString(R.string.lists_remove, domain));
        remove.setOnClickListener(v -> run(() -> removeDomain(kind, domain)));
        return row;
    }

    private void removeDomain(UserLists.Kind kind, String domain) {
        try {
            userLists.remove(kind, domain);
            // « Annuler » plutôt qu'une confirmation : le retrait s'applique tout de suite.
            onUi(() -> Snackbar.make(root, activity.getString(R.string.lists_removed, domain), Snackbar.LENGTH_LONG)
                    .setAction(R.string.lists_undo, v -> run(() -> restoreDomain(kind, domain)))
                    .show());
        } catch (IOException e) {
            onUi(() -> Snackbar.make(root, R.string.lists_save_failed, Snackbar.LENGTH_SHORT).show());
        }
    }

    private void restoreDomain(UserLists.Kind kind, String domain) {
        try {
            userLists.add(kind, domain);
        } catch (IOException e) {
            onUi(() -> Snackbar.make(root, R.string.lists_save_failed, Snackbar.LENGTH_SHORT).show());
        }
    }

    private void run(Runnable task) {
        try {
            worker.execute(task);
        } catch (RejectedExecutionException closedScreen) {
            // Écran fermé entre-temps : plus rien à faire.
        }
    }

    private void onUi(Runnable task) {
        activity.runOnUiThread(() -> {
            if (!closed) {
                task.run();
            }
        });
    }

    private int dp(int value) {
        return Math.round(value * activity.getResources().getDisplayMetrics().density);
    }

    @Override
    public void close() {
        closed = true;
        listChanges.close();
        worker.shutdown();
    }
}
