package com.akeeper.ui;

import android.Manifest;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.res.ColorStateList;
import android.net.VpnService;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.provider.Settings;
import android.view.View;
import android.view.WindowInsets;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;

import androidx.activity.OnBackPressedCallback;
import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.appcompat.app.AppCompatActivity;

import com.akeeper.R;
import com.akeeper.engine.NativeEngine;
import com.akeeper.ui.OnboardingFlow.Facts;
import com.akeeper.ui.OnboardingFlow.Step;
import com.akeeper.vpn.ShieldStatus;
import com.akeeper.vpn.ShieldVpnService;
import com.google.android.material.bottomnavigation.BottomNavigationView;
import com.google.android.material.button.MaterialButton;
import com.google.android.material.progressindicator.LinearProgressIndicator;

import java.io.File;
import java.io.IOException;
import java.text.NumberFormat;

/** Activité unique : onboarding (O1 à O4) puis onglets Accueil (A1) et Apps (A2). Thread principal uniquement. */
public final class MainActivity extends AppCompatActivity {

    private static final String STATE_DISCLOSURE = "disclosure_accepted";
    private static final String STATE_NOTIFICATIONS_ASKED = "notifications_asked";
    private static final String STATE_CONSENT_REFUSED = "consent_refused";
    private static final String STATE_APPS_TAB = "apps_tab";
    // Marqueur dans noBackupFilesDir : jamais sauvegardé ni transféré, aucune donnée sensible.
    private static final String ONBOARDING_MARKER = "onboarding_done";
    private static final int ONBOARDING_STEPS = 4;
    private static final long COUNTER_REFRESH_MS = 2_000;

    private final ActivityResultLauncher<Intent> vpnConsent = registerForActivityResult(
            new ActivityResultContracts.StartActivityForResult(), result -> onConsentResult());
    private final ActivityResultLauncher<String> notificationPermission = registerForActivityResult(
            new ActivityResultContracts.RequestPermission(), granted -> {
                notificationsAsked = true;
                render();
            });
    private final Handler handler = new Handler(Looper.getMainLooper());
    private final Runnable refreshCounters = new Runnable() {
        @Override
        public void run() {
            renderCounters();
            handler.postDelayed(this, COUNTER_REFRESH_MS);
        }
    };

    private boolean disclosureAccepted;
    private boolean notificationsAsked;
    private boolean consentRefused;
    private Step shown;
    private int shownLayout;
    private boolean appsTab;
    private AppsScreen appsScreen;
    // Retour depuis l'onglet Apps : revient à l'accueil au lieu de quitter l'app.
    private final OnBackPressedCallback backToHome = new OnBackPressedCallback(false) {
        @Override
        public void handleOnBackPressed() {
            selectTab(false);
        }
    };
    private ShieldStatus.Subscription subscription;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        getOnBackPressedDispatcher().addCallback(this, backToHome);
        if (savedInstanceState != null) {
            disclosureAccepted = savedInstanceState.getBoolean(STATE_DISCLOSURE);
            notificationsAsked = savedInstanceState.getBoolean(STATE_NOTIFICATIONS_ASKED);
            consentRefused = savedInstanceState.getBoolean(STATE_CONSENT_REFUSED);
            appsTab = savedInstanceState.getBoolean(STATE_APPS_TAB);
        }
    }

    @Override
    protected void onSaveInstanceState(Bundle outState) {
        super.onSaveInstanceState(outState);
        outState.putBoolean(STATE_DISCLOSURE, disclosureAccepted);
        outState.putBoolean(STATE_NOTIFICATIONS_ASKED, notificationsAsked);
        outState.putBoolean(STATE_CONSENT_REFUSED, consentRefused);
        outState.putBoolean(STATE_APPS_TAB, appsTab);
    }

    @Override
    protected void onStart() {
        super.onStart();
        subscription = ShieldStatus.observe(snapshot -> runOnUiThread(this::render));
    }

    @Override
    protected void onResume() {
        super.onResume();
        // Relance idempotente : le service republie l'état du verrouillage, modifié peut-être dans les réglages.
        if (hasVpnConsent()) {
            ShieldVpnService.start(this);
        }
        render();
        handler.post(refreshCounters);
    }

    @Override
    protected void onPause() {
        handler.removeCallbacks(refreshCounters);
        super.onPause();
    }

    @Override
    protected void onStop() {
        subscription.close();
        closeAppsScreen();
        // Force la reconstruction de l'écran au retour : l'écran Apps vient d'être libéré.
        shownLayout = 0;
        super.onStop();
    }

    private void render() {
        var marker = new File(getNoBackupFilesDir(), ONBOARDING_MARKER);
        var step = OnboardingFlow.next(new Facts(marker.exists(), disclosureAccepted, hasVpnConsent(),
                notificationsGranted(), notificationsAsked, ShieldStatus.current().lockdown()));
        if (step == Step.HOME && !marker.exists()) {
            markOnboardingDone(marker);
        }
        int layout = step != Step.HOME ? R.layout.screen_onboarding
                : appsTab ? R.layout.screen_apps : R.layout.screen_home;
        if (layout != shownLayout) {
            closeAppsScreen();
            setContentView(layout);
            View root = findViewById(R.id.root);
            applySystemBarInsets(root);
            shownLayout = layout;
            if (step == Step.HOME) {
                bindBottomNav();
            }
            if (layout == R.layout.screen_apps) {
                appsScreen = new AppsScreen(this, root);
            }
        }
        shown = step;
        backToHome.setEnabled(step == Step.HOME && appsTab);
        switch (step) {
            case DISCLOSURE -> renderDisclosure();
            case VPN_CONSENT -> renderConsent();
            case NOTIFICATIONS -> renderNotifications();
            case LOCKDOWN -> renderLockdown();
            case HOME -> {
                if (!appsTab) {
                    renderHome();
                }
            }
        }
    }

    private void bindBottomNav() {
        BottomNavigationView nav = findViewById(R.id.bottom_nav);
        nav.setSelectedItemId(appsTab ? R.id.nav_apps : R.id.nav_home);
        nav.setOnItemSelectedListener(item -> {
            selectTab(item.getItemId() == R.id.nav_apps);
            return true;
        });
    }

    private void selectTab(boolean apps) {
        if (apps != appsTab) {
            appsTab = apps;
            render();
        }
    }

    private void closeAppsScreen() {
        if (appsScreen != null) {
            appsScreen.close();
            appsScreen = null;
        }
    }

    private void renderDisclosure() {
        bindStep(1, R.drawable.ic_shield_check, R.string.disclosure_title, R.string.disclosure_data);
        var extra = (LinearLayout) findViewById(R.id.step_extra);
        if (extra.getChildCount() == 0) {
            addBullet(extra, R.drawable.ic_block, R.string.disclosure_block);
            addBullet(extra, R.drawable.ic_apps, R.string.disclosure_choose);
            addBullet(extra, R.drawable.ic_phone, R.string.disclosure_local);
        }
        primary(R.string.action_continue, v -> {
            disclosureAccepted = true;
            render();
        });
    }

    private void renderConsent() {
        bindStep(2, R.drawable.ic_lock, R.string.consent_title, R.string.consent_body);
        var extra = (LinearLayout) findViewById(R.id.step_extra);
        extra.removeAllViews();
        if (consentRefused) {
            addBullet(extra, R.drawable.ic_shield_alert, R.string.consent_refused);
        }
        primary(consentRefused ? R.string.consent_retry : R.string.consent_allow, v -> requestVpnConsent());
    }

    private void renderNotifications() {
        bindStep(3, R.drawable.ic_bell, R.string.notifications_title, R.string.notifications_body);
        primary(R.string.notifications_enable, v -> notificationPermission.launch(Manifest.permission.POST_NOTIFICATIONS));
        var later = (MaterialButton) findViewById(R.id.step_secondary);
        later.setVisibility(View.VISIBLE);
        later.setText(R.string.action_later);
        later.setOnClickListener(v -> {
            notificationsAsked = true;
            render();
        });
    }

    private void renderLockdown() {
        bindStep(4, R.drawable.ic_lock, R.string.lockdown_title, R.string.lockdown_body);
        var lockdown = ShieldStatus.current().lockdown();
        var extra = (LinearLayout) findViewById(R.id.step_extra);
        extra.removeAllViews();
        addLockdownRow(extra, R.string.lockdown_always_on, lockdown.alwaysOn());
        addLockdownRow(extra, R.string.lockdown_block, lockdown.lockdown());
        var hint = new TextView(this);
        hint.setText(R.string.lockdown_hint);
        hint.setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_BodySmall);
        hint.setTextColor(themeColor(com.google.android.material.R.attr.colorOnSurfaceVariant));
        extra.addView(hint);
        primary(R.string.lockdown_open_settings, v -> startActivity(new Intent(Settings.ACTION_VPN_SETTINGS)));
    }

    private void renderHome() {
        var state = HomeState.of(ShieldStatus.current());
        int fg;
        int bg;
        int level;
        int icon;
        switch (state.level) {
            case OK -> {
                fg = R.color.akeeper_state_ok;
                bg = R.color.akeeper_state_ok_container;
                level = R.string.home_level_ok;
                icon = R.drawable.ic_shield_check;
            }
            case WARN -> {
                fg = R.color.akeeper_state_warn;
                bg = R.color.akeeper_state_warn_container;
                level = R.string.home_level_warn;
                icon = R.drawable.ic_shield_alert;
            }
            default -> {
                fg = R.color.akeeper_state_danger;
                bg = R.color.akeeper_state_danger_container;
                level = R.string.home_level_danger;
                icon = R.drawable.ic_shield_off;
            }
        }
        var fgColor = ColorStateList.valueOf(getColor(fg));
        var bgColor = ColorStateList.valueOf(getColor(bg));

        ImageView statusIcon = findViewById(R.id.status_icon);
        statusIcon.setImageResource(icon);
        statusIcon.setImageTintList(fgColor);
        statusIcon.setBackgroundTintList(bgColor);
        TextView levelView = findViewById(R.id.status_level);
        levelView.setText(level);
        levelView.setTextColor(fgColor);
        levelView.setBackgroundTintList(bgColor);

        TextView title = findViewById(R.id.status_title);
        TextView sub = findViewById(R.id.status_sub);
        MaterialButton action = findViewById(R.id.status_action);
        switch (state) {
            case PROTECTED -> {
                title.setText(R.string.home_protected_title);
                sub.setText(R.string.home_protected_sub);
            }
            case NO_LOCKDOWN -> {
                title.setText(R.string.home_no_lockdown_title);
                sub.setText(R.string.home_no_lockdown_sub);
            }
            case PRIVATE_DNS_STRICT -> {
                title.setText(R.string.home_dns_strict_title);
                sub.setText(R.string.home_dns_strict_sub);
            }
            case REVOKED -> {
                title.setText(R.string.home_revoked_title);
                sub.setText(R.string.home_revoked_sub);
            }
            case STOPPED -> {
                title.setText(R.string.home_stopped_title);
                sub.setText(R.string.home_stopped_sub);
            }
        }
        switch (state.action) {
            case NONE -> action.setVisibility(View.GONE);
            case ENABLE_LOCKDOWN -> {
                action.setVisibility(View.VISIBLE);
                action.setText(R.string.home_no_lockdown_action);
                action.setOnClickListener(v -> startActivity(new Intent(Settings.ACTION_VPN_SETTINGS)));
            }
            case OPEN_NETWORK_SETTINGS -> {
                action.setVisibility(View.VISIBLE);
                action.setText(R.string.home_dns_strict_action);
                // Aucun intent public stable vers le réglage DNS privé : les réglages réseau en sont le plus proche.
                action.setOnClickListener(v -> startActivity(new Intent(Settings.ACTION_WIRELESS_SETTINGS)));
            }
            case REACTIVATE -> {
                action.setVisibility(View.VISIBLE);
                action.setText(R.string.home_reactivate);
                action.setOnClickListener(v -> requestVpnConsent());
            }
        }

        findViewById(R.id.notifications_card).setVisibility(notificationsGranted() ? View.GONE : View.VISIBLE);
        findViewById(R.id.notifications_action).setOnClickListener(v -> requestNotificationsFromHome());
        renderCounters();
    }

    private void renderCounters() {
        if (shownLayout != R.layout.screen_home) {
            return;
        }
        var blocked = ShieldStatus.counter(NativeEngine.Counter.DNS_BLOCKED);
        var queries = ShieldStatus.counter(NativeEngine.Counter.DNS_QUERIES);
        findViewById(R.id.stats_card).setVisibility(queries.isPresent() ? View.VISIBLE : View.GONE);
        var format = NumberFormat.getIntegerInstance();
        ((TextView) findViewById(R.id.stats_blocked)).setText(format.format(blocked.orElse(0)));
        ((TextView) findViewById(R.id.stats_queries)).setText(format.format(queries.orElse(0)));
    }

    private void requestVpnConsent() {
        var prepare = VpnService.prepare(this);
        if (prepare == null) {
            onConsentResult();
        } else {
            vpnConsent.launch(prepare);
        }
    }

    private void onConsentResult() {
        consentRefused = !hasVpnConsent();
        if (!consentRefused) {
            ShieldVpnService.start(this);
        }
        render();
    }

    private void requestNotificationsFromHome() {
        // Refus définitif : la boîte système ne s'affiche plus, seuls les réglages de l'app permettent de revenir dessus.
        if (notificationsAsked && !shouldShowRequestPermissionRationale(Manifest.permission.POST_NOTIFICATIONS)) {
            startActivity(new Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS)
                    .putExtra(Settings.EXTRA_APP_PACKAGE, getPackageName()));
        } else {
            notificationPermission.launch(Manifest.permission.POST_NOTIFICATIONS);
        }
    }

    private boolean hasVpnConsent() {
        return VpnService.prepare(this) == null;
    }

    private boolean notificationsGranted() {
        return checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED;
    }

    private void markOnboardingDone(File marker) {
        try {
            marker.createNewFile();
        } catch (IOException e) {
            // Échec sans gravité : l'onboarding sera simplement revalidé au prochain lancement.
        }
    }

    private void bindStep(int index, int icon, int title, int body) {
        ((TextView) findViewById(R.id.step_label)).setText(getString(R.string.onboarding_step, index, ONBOARDING_STEPS));
        ((LinearProgressIndicator) findViewById(R.id.step_progress)).setProgress(index);
        ((ImageView) findViewById(R.id.step_icon)).setImageResource(icon);
        ((TextView) findViewById(R.id.step_title)).setText(title);
        ((TextView) findViewById(R.id.step_body)).setText(body);
        findViewById(R.id.step_secondary).setVisibility(View.GONE);
    }

    private void primary(int label, View.OnClickListener listener) {
        MaterialButton button = findViewById(R.id.step_primary);
        button.setText(label);
        button.setOnClickListener(listener);
    }

    private void addBullet(LinearLayout parent, int icon, int text) {
        var view = new TextView(this);
        view.setText(text);
        view.setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_BodyLarge);
        view.setTextColor(themeColor(com.google.android.material.R.attr.colorOnSurface));
        view.setCompoundDrawablesRelativeWithIntrinsicBounds(icon, 0, 0, 0);
        view.setCompoundDrawableTintList(ColorStateList.valueOf(themeColor(com.google.android.material.R.attr.colorOnSurface)));
        view.setCompoundDrawablePadding(dp(14));
        view.setPadding(0, dp(8), 0, dp(8));
        parent.addView(view);
    }

    private void addLockdownRow(LinearLayout parent, int label, boolean enabled) {
        var row = getLayoutInflater().inflate(R.layout.item_lockdown_row, parent, false);
        ((TextView) row.findViewById(R.id.row_label)).setText(label);
        TextView state = row.findViewById(R.id.row_state);
        state.setText(enabled ? R.string.lockdown_enabled : R.string.lockdown_pending);
        state.setTextColor(enabled ? getColor(R.color.akeeper_state_ok)
                : themeColor(com.google.android.material.R.attr.colorOnSurfaceVariant));
        if (enabled) {
            state.setCompoundDrawablesRelativeWithIntrinsicBounds(R.drawable.ic_shield_check, 0, 0, 0);
            state.setCompoundDrawableTintList(ColorStateList.valueOf(getColor(R.color.akeeper_state_ok)));
        }
        parent.addView(row);
    }

    private int themeColor(int attr) {
        var typed = obtainStyledAttributes(new int[]{attr});
        try {
            return typed.getColor(0, 0);
        } finally {
            typed.recycle();
        }
    }

    private int dp(int value) {
        return Math.round(value * getResources().getDisplayMetrics().density);
    }

    private static void applySystemBarInsets(View root) {
        // targetSdk 36 impose l'edge-to-edge : le contenu doit s'écarter des barres système.
        int left = root.getPaddingLeft();
        int top = root.getPaddingTop();
        int right = root.getPaddingRight();
        int bottom = root.getPaddingBottom();
        root.setOnApplyWindowInsetsListener((v, insets) -> {
            var bars = insets.getInsets(WindowInsets.Type.systemBars() | WindowInsets.Type.displayCutout());
            v.setPadding(left + bars.left, top + bars.top, right + bars.right, bottom + bars.bottom);
            return insets;
        });
        root.requestApplyInsets();
    }
}
