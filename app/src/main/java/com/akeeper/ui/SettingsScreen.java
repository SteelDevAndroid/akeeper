package com.akeeper.ui;

import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Build;
import android.provider.Settings;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;


import androidx.appcompat.app.AppCompatActivity;

import com.akeeper.R;
import com.akeeper.rules.RuleBundle;
import com.akeeper.rules.RuleStore;
import com.akeeper.rules.RuleUpdates;
import com.akeeper.vpn.ActivityLog;
import com.akeeper.vpn.AppPrefs;
import com.akeeper.vpn.ShieldStatus;
import com.google.android.material.dialog.MaterialAlertDialogBuilder;
import com.google.android.material.materialswitch.MaterialSwitch;
import com.google.android.material.snackbar.Snackbar;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.time.format.FormatStyle;
import java.util.Optional;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.function.UnaryOperator;

/**
 * Réglages (R1) avec les écrans R3 et « Licences » en boîtes de dialogue, et le guide batterie (O6) pour les
 * constructeurs concernés. La lecture du bundle de règles (fichier + signature) tourne hors du thread principal.
 */
final class SettingsScreen implements AutoCloseable {

    private static final DateTimeFormatter DATE =
            DateTimeFormatter.ofLocalizedDate(FormatStyle.MEDIUM).withZone(ZoneId.systemDefault());

    private final AppCompatActivity activity;
    private final RuleStore rules;
    private final Optional<OemGuide> oem;
    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private final RuleStore.Subscription ruleChanges;
    private final TextView rulesSummary;
    private final TextView lockdownSummary;

    SettingsScreen(AppCompatActivity activity, View root, Runnable onBack, Runnable onLists) {
        this.activity = activity;
        this.rules = RuleStore.get(activity);
        this.oem = OemGuide.of(Build.MANUFACTURER);

        root.findViewById(R.id.settings_back).setOnClickListener(v -> onBack.run());

        ViewGroup protection = root.findViewById(R.id.settings_protection);
        addRow(protection, 0, R.string.settings_lists_title, activity.getString(R.string.settings_lists_subtitle))
                .setOnClickListener(v -> onLists.run());
        var rulesRow = addRow(protection, 1, R.string.settings_rules_title, "");
        rulesRow.setClickable(false);
        rulesRow.findViewById(R.id.row_chevron).setVisibility(View.GONE);
        rulesSummary = rulesRow.findViewById(R.id.row_subtitle);
        var update = root.findViewById(R.id.settings_rules_update);
        update.setVisibility(RuleUpdates.configured() ? View.VISIBLE : View.GONE);
        update.setOnClickListener(v -> {
            RuleUpdates.updateNow(activity);
            Snackbar.make(root, R.string.settings_rules_checking, Snackbar.LENGTH_SHORT).show();
        });

        ViewGroup reliability = root.findViewById(R.id.settings_reliability);
        var lockdownRow = addRow(reliability, -1, R.string.settings_lockdown_title, "");
        lockdownRow.setOnClickListener(v -> activity.startActivity(new Intent(Settings.ACTION_VPN_SETTINGS)));
        lockdownSummary = lockdownRow.findViewById(R.id.row_subtitle);
        oem.ifPresent(guide -> {
            var row = addRow(reliability, -1, R.string.settings_battery_title,
                    activity.getString(R.string.settings_battery_subtitle));
            row.setOnClickListener(v -> showBatteryGuide(guide));
        });

        bindPrivacy(root.findViewById(R.id.settings_privacy), root);

        ViewGroup about = root.findViewById(R.id.settings_about);
        addRow(about, -1, R.string.settings_limits_title, null).setOnClickListener(v -> showLimits());
        addRow(about, -1, R.string.settings_licenses_title, null).setOnClickListener(v -> showLicenses());
        var versionRow = addRow(about, -1, R.string.settings_version_title, versionName());
        versionRow.setClickable(false);
        versionRow.findViewById(R.id.row_chevron).setVisibility(View.GONE);

        // L'activation d'un bundle arrive sur le thread de WorkManager.
        ruleChanges = rules.observe(this::refreshRules);
        refresh();
    }

    /** Journal d'activité : interrupteur, durée de conservation et effacement. Le Keystore n'est ouvert que hors UI. */
    private void bindPrivacy(ViewGroup privacy, View root) {
        var logRow = activity.getLayoutInflater().inflate(R.layout.item_switch_row, privacy, false);
        ((TextView) logRow.findViewById(R.id.row_title)).setText(R.string.settings_log_title);
        ((TextView) logRow.findViewById(R.id.row_subtitle)).setText(R.string.settings_log_subtitle);
        MaterialSwitch logSwitch = logRow.findViewById(R.id.row_switch);
        // Inactif tant que les préférences ne sont pas lues (et si le Keystore est indisponible).
        logSwitch.setEnabled(false);
        privacy.addView(logRow);
        var retentionRow = addRow(privacy, -1, R.string.settings_retention_title, "");
        retentionRow.findViewById(R.id.row_chevron).setVisibility(View.GONE);
        retentionRow.setEnabled(false);
        var retentionValue = (TextView) retentionRow.findViewById(R.id.row_subtitle);
        addRow(privacy, -1, R.string.settings_clear_title, null).setOnClickListener(v -> confirmClear(root));

        try {
            worker.execute(() -> {
                AppPrefs loaded;
                try {
                    loaded = AppPrefs.get(activity);
                } catch (GeneralSecurityException | IOException keystoreUnavailable) {
                    loaded = null;
                }
                var prefs = loaded;
                activity.runOnUiThread(() -> showPrivacy(prefs, logSwitch, retentionRow, retentionValue, root));
            });
        } catch (RejectedExecutionException closed) {
            // Écran fermé entre-temps.
        }
    }

    private void showPrivacy(AppPrefs prefs, MaterialSwitch logSwitch, View retentionRow, TextView retentionValue,
                             View root) {
        if (prefs == null) {
            retentionValue.setText(R.string.settings_log_unavailable);
            return;
        }
        logSwitch.setChecked(prefs.settings().logEnabled());
        logSwitch.setEnabled(true);
        logSwitch.setOnCheckedChangeListener((button, checked) -> save(prefs, root,
                settings -> settings.withLogEnabled(checked)));
        retentionValue.setText(activity.getString(R.string.settings_retention_value, prefs.settings().retentionDays()));
        retentionRow.setEnabled(true);
        retentionRow.setOnClickListener(v -> {
            var choices = AppPrefs.RETENTION_CHOICES;
            var labels = new String[choices.length];
            int checked = 0;
            for (int i = 0; i < choices.length; i++) {
                labels[i] = activity.getString(R.string.settings_retention_value, choices[i]);
                if (choices[i] == prefs.settings().retentionDays()) {
                    checked = i;
                }
            }
            new MaterialAlertDialogBuilder(activity)
                    .setTitle(R.string.settings_retention_title)
                    .setSingleChoiceItems(labels, checked, (dialog, which) -> {
                        dialog.dismiss();
                        retentionValue.setText(labels[which]);
                        save(prefs, root, settings -> settings.withRetentionDays(choices[which]));
                    })
                    .setNegativeButton(R.string.action_cancel, null)
                    .show();
        });
    }

    private void save(AppPrefs prefs, View root, UnaryOperator<AppPrefs.Settings> change) {
        try {
            worker.execute(() -> {
                try {
                    prefs.update(change);
                } catch (IOException e) {
                    activity.runOnUiThread(() ->
                            Snackbar.make(root, R.string.event_save_failed, Snackbar.LENGTH_SHORT).show());
                }
            });
        } catch (RejectedExecutionException closed) {
            // Écran fermé entre-temps.
        }
    }

    private void confirmClear(View root) {
        new MaterialAlertDialogBuilder(activity)
                .setTitle(R.string.settings_clear_confirm_title)
                .setMessage(R.string.settings_clear_confirm_body)
                .setNegativeButton(R.string.action_cancel, null)
                .setPositiveButton(R.string.settings_clear_action, (d, w) -> {
                    try {
                        worker.execute(() -> {
                            int message;
                            try {
                                ActivityLog.get(activity).clear();
                                message = R.string.settings_clear_done;
                            } catch (GeneralSecurityException | IOException | RuntimeException unavailable) {
                                message = R.string.event_save_failed;
                            }
                            int shown = message;
                            activity.runOnUiThread(() -> Snackbar.make(root, shown, Snackbar.LENGTH_SHORT).show());
                        });
                    } catch (RejectedExecutionException closed) {
                        // Écran fermé entre-temps.
                    }
                })
                .show();
    }

    /** Met à jour les valeurs qui changent hors de l'écran : verrouillage et règles. */
    void refresh() {
        lockdownSummary.setText(ShieldStatus.current().lockdown().lockdown()
                ? R.string.settings_lockdown_on : R.string.settings_lockdown_off);
        refreshRules();
    }

    private void refreshRules() {
        try {
            worker.execute(() -> {
                var active = rules.active();
                activity.runOnUiThread(() -> rulesSummary.setText(rulesSummary(active)));
            });
        } catch (RejectedExecutionException closed) {
            // Écran fermé entre-temps : plus rien à afficher.
        }
    }

    private String rulesSummary(Optional<RuleBundle> active) {
        if (active.isPresent()) {
            var bundle = active.get();
            return activity.getString(R.string.settings_rules_version, bundle.version(),
                    DATE.format(Instant.ofEpochSecond(bundle.createdAt())));
        }
        return activity.getString(RuleUpdates.configured()
                ? R.string.settings_rules_none : R.string.settings_rules_offline);
    }

    private void showLimits() {
        new MaterialAlertDialogBuilder(activity)
                .setTitle(R.string.settings_limits_title)
                .setMessage(activity.getString(R.string.limits_body))
                .setPositiveButton(R.string.action_close, null)
                .show();
    }

    private void showLicenses() {
        try {
            worker.execute(() -> {
                var notice = rules.notice();
                activity.runOnUiThread(() -> {
                    var message = activity.getString(R.string.licenses_app) + "\n\n"
                            + notice.orElse(activity.getString(R.string.licenses_sources_none));
                    new MaterialAlertDialogBuilder(activity)
                            .setTitle(R.string.settings_licenses_title)
                            .setMessage(message)
                            .setPositiveButton(R.string.action_close, null)
                            .show();
                });
            });
        } catch (RejectedExecutionException closed) {
            // Écran fermé entre-temps.
        }
    }

    private void showBatteryGuide(OemGuide guide) {
        int steps = switch (guide) {
            case XIAOMI -> R.string.battery_steps_xiaomi;
            case SAMSUNG -> R.string.battery_steps_samsung;
            case OPPO -> R.string.battery_steps_oppo;
            case VIVO -> R.string.battery_steps_vivo;
            case HONOR -> R.string.battery_steps_honor;
        };
        new MaterialAlertDialogBuilder(activity)
                .setTitle(R.string.battery_title)
                .setMessage(activity.getString(R.string.battery_intro) + "\n\n" + activity.getString(steps))
                // La fiche de l'app existe sur tous les appareils ; les écrans propres à chaque OEM n'ont pas d'intent stable.
                .setPositiveButton(R.string.battery_open, (d, w) -> activity.startActivity(
                        new Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
                                Uri.fromParts("package", activity.getPackageName(), null))))
                .setNegativeButton(R.string.battery_done, null)
                .show();
    }

    /** {@code subtitle} nul : pas de seconde ligne ; vide : renseignée plus tard. {@code index} -1 : en fin de liste. */
    private View addRow(ViewGroup parent, int index, int title, String subtitle) {
        var row = activity.getLayoutInflater().inflate(R.layout.item_setting_row, parent, false);
        ((TextView) row.findViewById(R.id.row_title)).setText(title);
        var subtitleView = (TextView) row.findViewById(R.id.row_subtitle);
        subtitleView.setText(subtitle);
        subtitleView.setVisibility(subtitle == null ? View.GONE : View.VISIBLE);
        parent.addView(row, index < 0 ? parent.getChildCount() : index);
        return row;
    }

    private String versionName() {
        try {
            return activity.getPackageManager().getPackageInfo(activity.getPackageName(), 0).versionName;
        } catch (PackageManager.NameNotFoundException unreachable) {
            return "";
        }
    }

    @Override
    public void close() {
        ruleChanges.close();
        worker.shutdown();
    }
}
