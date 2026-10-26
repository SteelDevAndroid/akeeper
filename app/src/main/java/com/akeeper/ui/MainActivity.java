package com.akeeper.ui;

import android.Manifest;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.res.ColorStateList;
import android.net.VpnService;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.provider.Settings;
import android.text.format.DateFormat;
import android.view.HapticFeedbackConstants;
import android.view.View;
import android.view.WindowInsets;
import android.widget.Toast;
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
import com.akeeper.vpn.ActivityLog;
import com.akeeper.vpn.ShieldStatus;
import com.akeeper.vpn.ShieldVpnService;
import com.google.android.material.bottomnavigation.BottomNavigationView;
import com.google.android.material.button.MaterialButton;
import com.google.android.material.dialog.MaterialAlertDialogBuilder;
import com.google.android.material.progressindicator.LinearProgressIndicator;

import java.io.File;
import java.io.IOException;
import java.text.NumberFormat;
import java.util.Date;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;

/** Activité unique : onboarding (O1 à O4), onglets Accueil (A1) et Apps (A2), puis Réglages (R1). Thread principal uniquement. */
public final class MainActivity extends AppCompatActivity {

    private enum Tab {
        HOME, APPS, ACTIVITY;

        static Tab of(int ordinal) {
            return ordinal >= 0 && ordinal < values().length ? values()[ordinal] : HOME;
        }
    }

    private static final String STATE_DISCLOSURE = "disclosure_accepted";
    private static final String STATE_NOTIFICATIONS_ASKED = "notifications_asked";
    private static final String STATE_CONSENT_REFUSED = "consent_refused";
    private static final String STATE_TAB = "tab";
    private static final String STATE_SETTINGS = "settings_open";
    private static final String STATE_LISTS = "lists_open";
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
    private final ExecutorService homeWorker = Executors.newSingleThreadExecutor();
    private boolean homeRecentLoading;
    private HomeState lastHomeState;
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
    private Tab tab = Tab.HOME;
    private boolean settingsOpen;
    private boolean listsOpen;
    private AppsScreen appsScreen;
    private ActivityScreen activityScreen;
    private SettingsScreen settingsScreen;
    private ListsScreen listsScreen;
    // Retour depuis les Réglages ou l'onglet Apps : revient en arrière au lieu de quitter l'app.
    private final OnBackPressedCallback backToHome = new OnBackPressedCallback(false) {
        @Override
        public void handleOnBackPressed() {
            if (listsOpen) {
                setListsOpen(false);
            } else if (settingsOpen) {
                setSettingsOpen(false);
            } else {
                selectTab(Tab.HOME);
            }
        }
    };
    private ShieldStatus.Subscription subscription;
    // Tant qu'un rapport de plantage n'est pas acquitté, le service n'est pas relancé : il pourrait replanter aussitôt.
    private boolean crashDialogShown;
    private boolean crashPending;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        getOnBackPressedDispatcher().addCallback(this, backToHome);
        if (savedInstanceState != null) {
            disclosureAccepted = savedInstanceState.getBoolean(STATE_DISCLOSURE);
            notificationsAsked = savedInstanceState.getBoolean(STATE_NOTIFICATIONS_ASKED);
            consentRefused = savedInstanceState.getBoolean(STATE_CONSENT_REFUSED);
            tab = Tab.of(savedInstanceState.getInt(STATE_TAB));
            settingsOpen = savedInstanceState.getBoolean(STATE_SETTINGS);
            listsOpen = savedInstanceState.getBoolean(STATE_LISTS);
        }
    }

    @Override
    protected void onSaveInstanceState(Bundle outState) {
        super.onSaveInstanceState(outState);
        outState.putBoolean(STATE_DISCLOSURE, disclosureAccepted);
        outState.putBoolean(STATE_NOTIFICATIONS_ASKED, notificationsAsked);
        outState.putBoolean(STATE_CONSENT_REFUSED, consentRefused);
        outState.putInt(STATE_TAB, tab.ordinal());
        outState.putBoolean(STATE_SETTINGS, settingsOpen);
        outState.putBoolean(STATE_LISTS, listsOpen);
    }

    @Override
    protected void onStart() {
        super.onStart();
        subscription = ShieldStatus.observe(snapshot -> runOnUiThread(this::render));
    }

    @Override
    protected void onResume() {
        super.onResume();
        showPendingCrash();
        // Relance idempotente : le service republie l'état du verrouillage, modifié peut-être dans les réglages.
        if (hasVpnConsent() && !crashPending) {
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
        closeScreens();
        // Force la reconstruction de l'écran au retour : les écrans Apps et Réglages viennent d'être libérés.
        shownLayout = 0;
        super.onStop();
    }

    @Override
    protected void onDestroy() {
        homeWorker.shutdownNow();
        super.onDestroy();
    }

    private void showPendingCrash() {
        if (crashDialogShown) {
            return;
        }
        var report = CrashReport.pending(this);
        crashPending = report.isPresent();
        if (report.isEmpty()) {
            return;
        }
        crashDialogShown = true;
        var text = report.get().text();
        new MaterialAlertDialogBuilder(this)
                .setTitle(R.string.crash_title)
                .setMessage(getString(R.string.crash_intro) + "\n\n" + text)
                .setPositiveButton(R.string.crash_copy, (d, w) -> {
                    getSystemService(ClipboardManager.class).setPrimaryClip(ClipData.newPlainText("aKeeper", text));
                    Toast.makeText(this, R.string.crash_copied, Toast.LENGTH_SHORT).show();
                })
                .setNegativeButton(R.string.action_close, null)
                .setOnDismissListener(d -> {
                    CrashReport.acknowledge(this, report.get());
                    crashPending = false;
                    if (hasVpnConsent()) {
                        ShieldVpnService.start(this);
                    }
                    render();
                })
                .show();
    }

    private void render() {
        var marker = new File(getNoBackupFilesDir(), ONBOARDING_MARKER);
        var step = OnboardingFlow.next(new Facts(marker.exists(), disclosureAccepted, hasVpnConsent(),
                notificationsGranted(), notificationsAsked, ShieldStatus.current().lockdown()));
        if (step == Step.HOME && !marker.exists()) {
            markOnboardingDone(marker);
        }
        int layout = step != Step.HOME ? R.layout.screen_onboarding
                : listsOpen ? R.layout.screen_lists
                : settingsOpen ? R.layout.screen_settings
                : tab == Tab.APPS ? R.layout.screen_apps
                : tab == Tab.ACTIVITY ? R.layout.screen_activity : R.layout.screen_home;
        if (layout != shownLayout) {
            closeScreens();
            setContentView(layout);
            View root = findViewById(R.id.root);
            root.setAlpha(0f);
            root.setTranslationY(dp(8));
            root.animate().alpha(1f).translationY(0f).setDuration(180).start();
            applySystemBarInsets(root);
            shownLayout = layout;
            if (layout == R.layout.screen_home || layout == R.layout.screen_apps || layout == R.layout.screen_activity) {
                bindBottomNav();
                findViewById(R.id.settings_button).setOnClickListener(v -> setSettingsOpen(true));
            }
            if (layout == R.layout.screen_home) {
                findViewById(R.id.recent_all).setOnClickListener(v -> selectTab(Tab.ACTIVITY));
                findViewById(R.id.protection_details).setOnClickListener(v -> ProtectionSheet.show(this));
                findViewById(R.id.protection_hero).setOnClickListener(v -> ProtectionSheet.show(this));
            }
            if (layout == R.layout.screen_apps) {
                appsScreen = new AppsScreen(this, root);
            }
            if (layout == R.layout.screen_activity) {
                activityScreen = new ActivityScreen(this, root);
            }
            if (layout == R.layout.screen_settings) {
                settingsScreen = new SettingsScreen(this, root, () -> setSettingsOpen(false), () -> setListsOpen(true));
            }
            if (layout == R.layout.screen_lists) {
                listsScreen = new ListsScreen(this, root, () -> setListsOpen(false));
            }
        }
        shown = step;
        backToHome.setEnabled(step == Step.HOME && (tab != Tab.HOME || settingsOpen || listsOpen));
        switch (step) {
            case DISCLOSURE -> renderDisclosure();
            case VPN_CONSENT -> renderConsent();
            case NOTIFICATIONS -> renderNotifications();
            case LOCKDOWN -> renderLockdown();
            case HOME -> {
                if (listsOpen) {
                    // Les listes se tiennent à jour seules, par leurs observateurs.
                } else if (settingsOpen) {
                    settingsScreen.refresh();
                } else if (tab == Tab.HOME) {
                    renderHome();
                }
            }
        }
    }

    private void bindBottomNav() {
        BottomNavigationView nav = findViewById(R.id.bottom_nav);
        nav.setSelectedItemId(switch (tab) {
            case APPS -> R.id.nav_apps;
            case ACTIVITY -> R.id.nav_activity;
            case HOME -> R.id.nav_home;
        });
        nav.setOnItemSelectedListener(item -> {
            nav.performHapticFeedback(HapticFeedbackConstants.CONFIRM);
            selectTab(item.getItemId() == R.id.nav_apps ? Tab.APPS
                    : item.getItemId() == R.id.nav_activity ? Tab.ACTIVITY : Tab.HOME);
            return true;
        });
    }

    private void selectTab(Tab selected) {
        if (selected != tab) {
            tab = selected;
            render();
        }
    }

    private void setSettingsOpen(boolean open) {
        settingsOpen = open;
        render();
    }

    private void setListsOpen(boolean open) {
        listsOpen = open;
        render();
    }

    private void closeScreens() {
        if (appsScreen != null) {
            appsScreen.close();
            appsScreen = null;
        }
        if (activityScreen != null) {
            activityScreen.close();
            activityScreen = null;
        }
        if (settingsScreen != null) {
            settingsScreen.close();
            settingsScreen = null;
        }
        if (listsScreen != null) {
            listsScreen.close();
            listsScreen = null;
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
        // Politique Play (VpnService, données utilisateur) : consentement explicite avant prepare().
        primary(R.string.action_accept_continue, v -> {
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
        if (lastHomeState != state) {
            statusIcon.setScaleX(0.88f);
            statusIcon.setScaleY(0.88f);
            statusIcon.setAlpha(0.5f);
            statusIcon.animate().scaleX(1f).scaleY(1f).alpha(1f).setDuration(220).start();
            statusIcon.performHapticFeedback(state.level == HomeState.Level.DANGER
                    ? HapticFeedbackConstants.REJECT : HapticFeedbackConstants.CONFIRM);
            lastHomeState = state;
        }
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
            case PAUSED -> {
                title.setText(getString(R.string.home_paused_title,
                        DateFormat.getTimeFormat(this).format(new Date(ShieldStatus.current().pausedUntil()))));
                sub.setText(R.string.home_paused_sub);
                levelView.setText(R.string.home_level_paused);
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
            case PAUSE -> {
                action.setVisibility(View.VISIBLE);
                action.setText(R.string.home_pause_action);
                action.setOnClickListener(v -> ShieldVpnService.pause(this));
            }
            case RESUME -> {
                action.setVisibility(View.VISIBLE);
                action.setText(R.string.home_resume_action);
                action.setOnClickListener(v -> ShieldVpnService.resume(this));
            }
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
        renderRecentActivity();
    }

    private void renderCounters() {
        if (shownLayout != R.layout.screen_home) {
            return;
        }
        var blocked = ShieldStatus.counter(NativeEngine.Counter.DNS_BLOCKED);
        var queries = ShieldStatus.counter(NativeEngine.Counter.DNS_QUERIES);
        findViewById(R.id.stats_card).setVisibility(queries.isPresent() ? View.VISIBLE : View.GONE);
        long blockedValue = blocked.orElse(0);
        long queryValue = queries.orElse(0);
        int ratio = queryValue <= 0 ? 0 : (int) Math.min(100, Math.round(blockedValue * 100.0 / queryValue));
        var format = NumberFormat.getIntegerInstance();
        ((TextView) findViewById(R.id.stats_blocked)).setText(format.format(blockedValue));
        ((TextView) findViewById(R.id.stats_queries)).setText(format.format(queryValue));
        ((TextView) findViewById(R.id.stats_ratio)).setText(getString(R.string.home_blocked_ratio, ratio));
        ((LinearProgressIndicator) findViewById(R.id.stats_progress)).setProgressCompat(ratio, true);
    }

    private void renderRecentActivity() {
        if (shownLayout != R.layout.screen_home || homeRecentLoading) {
            return;
        }
        homeRecentLoading = true;
        findViewById(R.id.recent_container).setAlpha(0.45f);
        try {
            homeWorker.execute(() -> {
                try {
                    var log = ActivityLog.get(this);
                    var events = log.query(new ActivityLog.Query(true, ActivityLog.Query.ANY_UID, 3));
                    var hourly = log.blockedHourly(System.currentTimeMillis(), 24);
                    var text = new EventText(this);
                    events.forEach(event -> text.app(event.uid()));
                    runOnUiThread(() -> showRecentActivity(events, text, hourly));
                } catch (Exception unavailable) {
                    runOnUiThread(() -> showRecentActivity(java.util.List.of(), new EventText(this), new long[0]));
                }
            });
        } catch (RejectedExecutionException closed) {
            homeRecentLoading = false;
        }
    }

    private void showRecentActivity(java.util.List<com.akeeper.engine.FlowEvent> events, EventText text, long[] hourly) {
        homeRecentLoading = false;
        if (shownLayout != R.layout.screen_home) {
            return;
        }
        ((SparklineView) findViewById(R.id.stats_sparkline)).setValues(hourly);
        LinearLayout container = findViewById(R.id.recent_container);
        container.removeAllViews();
        container.animate().alpha(1f).setDuration(160).start();
        if (events.isEmpty()) {
            var empty = new TextView(this);
            empty.setText(R.string.home_recent_empty);
            empty.setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_BodyMedium);
            empty.setTextColor(themeColor(com.google.android.material.R.attr.colorOnSurfaceVariant));
            empty.setGravity(android.view.Gravity.CENTER);
            empty.setPadding(dp(20), dp(22), dp(20), dp(22));
            container.addView(empty);
            return;
        }
        for (var event : events) {
            View row = getLayoutInflater().inflate(R.layout.item_home_event, container, false);
            ((TextView) row.findViewById(R.id.home_event_title)).setText(event.name());
            ((TextView) row.findViewById(R.id.home_event_detail)).setText(
                    getString(R.string.home_event_detail, text.app(event.uid()), EventText.time(event.timestampMillis())));
            row.setContentDescription(event.name() + ", " + text.reason(event));
            row.setOnClickListener(v -> selectTab(Tab.ACTIVITY));
            container.addView(row);
        }
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
