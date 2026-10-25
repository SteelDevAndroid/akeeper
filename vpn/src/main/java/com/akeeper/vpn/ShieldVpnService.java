package com.akeeper.vpn;

import android.content.Context;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.VpnService;
import android.os.Handler;
import android.os.Looper;
import android.os.ParcelFileDescriptor;

import com.akeeper.engine.NativeEngine;
import com.akeeper.rules.RuleStore;
import com.akeeper.rules.RuleUpdates;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import com.akeeper.security.AdvancedProtectionPolicy;

import java.security.GeneralSecurityException;

/**
 * Toutes les méthodes s'exécutent sur le thread principal : aucun champ n'est partagé entre threads. Les rappels de
 * {@link UpstreamDns}, qui arrivent sur un autre thread, y reviennent par {@code main}, sauf {@code followUnderlying}
 * qui ne touche aucun champ.
 */
public final class ShieldVpnService extends VpnService {

    static final String DNS_V4 = "10.111.0.53";
    static final String DNS_V6 = "fd00:6d73::53";
    /** Liste personnelle de domaines bloqués, un par ligne, dans {@code filesDir}. */
    public static final String BLOCKLIST_FILE = "blocklist.txt";
    /** Durée de la pause proposée par l'accueil (docs/ui-ecrans.md, A1). */
    public static final long PAUSE_MILLIS = 15 * 60 * 1000L;
    private static final String ACTION_PAUSE = "com.akeeper.vpn.PAUSE";
    private static final String ACTION_RESUME = "com.akeeper.vpn.RESUME";

    // Les rappels réseau de UpstreamDns arrivent sur leur propre thread : l'état du service reste au thread principal.
    private final Handler main = new Handler(Looper.getMainLooper());
    private NativeEngine engine;
    private UpstreamDns upstream;
    private NetworkStateMonitor networkStateMonitor;
    private NetworkState networkState = NetworkState.NONE;
    private ShieldStatus.Subscription appRules;
    private RuleStore.Subscription ruleUpdates;
    private ShieldStatus.Subscription prefsChanges;
    private ShieldStatus.Subscription listsChanges;
    private AppPrefs prefs;
    private ActivityRecorder recorder;
    private boolean lanApplied;
    // Une lecture suivie de l'envoi au moteur ne doit pas s'entrecroiser avec une autre : la dernière gagne.
    private final Object reloadLock = new Object();
    private boolean privateDnsStrict;
    // Fin de la pause en horloge murale, pour l'affichage ; le moteur mesure la durée avec son horloge monotone.
    private long pausedUntil;
    private final Runnable endPause = this::endPause;

    /** Prérequis : {@link VpnService#prepare} a renvoyé {@code null} (consentement accordé). */
    public static void start(Context context) {
        context.startForegroundService(new Intent(context, ShieldVpnService.class));
    }

    /** Suspend les blocages pendant {@link #PAUSE_MILLIS} ; le service doit déjà tourner. */
    public static void pause(Context context) {
        context.startService(new Intent(context, ShieldVpnService.class).setAction(ACTION_PAUSE));
    }

    public static void resume(Context context) {
        context.startService(new Intent(context, ShieldVpnService.class).setAction(ACTION_RESUME));
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        ShieldNotifications.createChannels(this);
        try {
            startForeground(ShieldNotifications.STATUS_ID, ShieldNotifications.persistent(this),
                    ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED);
        } catch (SecurityException consentMissing) {
            // systemExempted exige le consentement VpnService.prepare() : sans lui, rien à protéger.
            stopSelf();
            return START_NOT_STICKY;
        }
        if (engine == null && !establish()) {
            shutdown();
            stopSelf();
            return START_NOT_STICKY;
        }
        // Seule l'action est lue : un Intent reçu n'est jamais relancé tel quel.
        var action = intent == null ? null : intent.getAction();
        if (ACTION_PAUSE.equals(action)) {
            startPause();
        } else if (ACTION_RESUME.equals(action)) {
            endPause();
        }
        ShieldStatus.publish(new ShieldStatus.Snapshot(true, new LockdownStatus(isAlwaysOn(), isLockdownEnabled()),
                privateDnsStrict, pausedUntil));
        return START_STICKY;
    }

    private void startPause() {
        if (engine == null || !engine.pause(PAUSE_MILLIS)) {
            return;
        }
        pausedUntil = System.currentTimeMillis() + PAUSE_MILLIS;
        main.removeCallbacks(endPause);
        main.postDelayed(endPause, PAUSE_MILLIS);
    }

    private void endPause() {
        main.removeCallbacks(endPause);
        pausedUntil = 0;
        if (engine != null) {
            engine.resume();
        }
        ShieldStatus.publish(ShieldStatus.current().withPausedUntil(0));
    }

    private boolean establish() {
        // allowBypass() et allowFamily() sont proscrits : ils ouvrent un canal de fuite hors tunnel.
        loadPrefs();
        // Protection avancée : l'option réseau local est ignorée, quoi que dise la préférence.
        var policy = new AdvancedProtectionPolicy(this).effective(new ShieldPolicy(
                prefs != null && prefs.settings().lanBypass() && networkState.allowsLanBypass(),
                LanRanges.prefixes(), false));
        lanApplied = policy.allowLanBypass();
        var builder = new Builder()
                .setSession(getString(R.string.vpn_session))
                .setMtu(1500)
                .addAddress("10.111.0.1", 32)
                .addAddress("fd00:6d73::1", 128)
                // Tunnel complet : ::/0 explicite, sinon l'IPv6 (464XLAT, réseaux v6 seuls) sortirait en clair.
                .addRoute("0.0.0.0", 0)
                .addRoute("::", 0)
                .addDnsServer(DNS_V4)
                .addDnsServer(DNS_V6)
                .setBlocking(false)
                .setMetered(false);
        // Les plages exclues ne contiennent jamais les adresses virtuelles du tunnel (voir LanRanges).
        policy.lanRoutes().forEach(builder::excludeRoute);

        var tun = builder.establish();
        if (tun == null) {
            return false;
        }
        var rules = RuleStore.get(this);
        try {
            engine = NativeEngine.start(tun.detachFd(), openBlocklist(), openBundle(rules), categoryMask(prefs),
                    new EngineHost(new FlowOwnerResolver(getSystemService(ConnectivityManager.class))));
        } catch (IllegalStateException e) {
            return false;
        }
        ShieldStatus.attach(engine);
        applyAppRules();
        // Moteur capturé, comme pour les règles par app : l'activation arrive sur le thread de WorkManager.
        // Valeurs capturées : ces observateurs tournent hors du thread principal, qui peut arrêter le service.
        var running = engine;
        var preferences = prefs;
        ruleUpdates = rules.observe(() -> reloadRules(running, rules, preferences));
        listsChanges = UserLists.get(this).observe(lists -> reloadRules(running, rules, preferences));
        if (preferences != null) {
            prefsChanges = preferences.observe(settings -> {
                reloadRules(running, rules, preferences);
                main.post(() -> onLanOption(settings));
            });
        }
        recorder = new ActivityRecorder(this, engine, preferences);
        // Planifiée ici et non dans l'UI : Always-on VPN démarre le service sans jamais ouvrir l'app.
        RuleUpdates.schedule(this);
        var connectivity = getSystemService(ConnectivityManager.class);
        upstream = new UpstreamDns(connectivity, engine, this::protect,
                this::followUnderlying, strict -> main.post(() -> onPrivateDnsStrict(strict)));
        upstream.start();
        networkStateMonitor = new NetworkStateMonitor(connectivity,
                state -> main.post(() -> onNetworkState(state)));
        networkStateMonitor.start();
        return true;
    }

    private void loadPrefs() {
        try {
            prefs = AppPrefs.get(this);
        } catch (GeneralSecurityException | IOException keystoreUnavailable) {
            // Keystore indisponible : préférences par défaut, donc toutes les catégories actives.
            prefs = null;
        }
    }

    /** Les routes d'un VPN sont fixées à l'établissement : changer l'option réseau local le reconstruit. */
    private void onLanOption(AppPrefs.Settings settings) {
        boolean wanted = settings.lanBypass() && networkState.allowsLanBypass()
                && !new AdvancedProtectionPolicy(this).active();
        if (wanted != lanApplied && engine != null) {
            rebuildForNetworkPolicy();
        }
    }

    private void onNetworkState(NetworkState state) {
        if (state.equals(networkState)) {
            return;
        }
        networkState = state;
        var settings = prefs == null ? AppPrefs.Settings.DEFAULT : prefs.settings();
        boolean wanted = settings.lanBypass() && state.allowsLanBypass()
                && !new AdvancedProtectionPolicy(this).active();
        if (wanted != lanApplied && engine != null) {
            rebuildForNetworkPolicy();
        }
    }

    private void rebuildForNetworkPolicy() {
        shutdown();
        if (!establish()) {
            ShieldStatus.publish(ShieldStatus.Snapshot.STOPPED);
            stopSelf();
            return;
        }
        ShieldStatus.publish(new ShieldStatus.Snapshot(true,
                new LockdownStatus(isAlwaysOn(), isLockdownEnabled()), privateDnsStrict, pausedUntil));
    }

    private void applyAppRules() {
        try {
            // Moteur capturé : l'observateur tourne sur le thread de l'UI qui écrit les règles, pendant qu'un
            // arrêt peut remettre le champ à null. Après close(), setBlockedUids() est simplement sans effet.
            var current = engine;
            appRules = AppRules.get(this).observe(packages ->
                    current.setBlockedUids(AppRules.uids(getPackageManager(), packages)));
        } catch (GeneralSecurityException | IOException keystoreUnavailable) {
            // Keystore indisponible : aucune règle par app, mais le filtrage DNS et l'anti-évasion restent actifs.
            appRules = null;
        }
    }

    /** Appelé depuis le thread natif : protect() et getConnectionOwnerUid() sont sûrs hors thread principal. */
    private final class EngineHost implements NativeEngine.Host {

        private final FlowOwnerResolver resolver;

        EngineHost(FlowOwnerResolver resolver) {
            this.resolver = resolver;
        }

        @Override
        public boolean protect(int fd) {
            return ShieldVpnService.this.protect(fd);
        }

        @Override
        public int ownerUid(int protocol, byte[] localAddress, int localPort, byte[] remoteAddress, int remotePort) {
            return resolver.ownerUid(protocol, localAddress, localPort, remoteAddress, remotePort);
        }
    }

    private void onPrivateDnsStrict(boolean strict) {
        if (strict == privateDnsStrict) {
            return;
        }
        privateDnsStrict = strict;
        ShieldStatus.publish(ShieldStatus.current().withPrivateDnsStrict(strict));
        if (strict) {
            ShieldNotifications.alertPrivateDnsStrict(this);
        }
    }

    private void followUnderlying(Network network) {
        // null : le système suit le réseau par défaut ; sinon le VPN hérite de l'état (débit, facturation) du réseau suivi.
        setUnderlyingNetworks(network == null ? null : new Network[]{network});
    }

    private int openBlocklist() {
        var file = new File(getFilesDir(), BLOCKLIST_FILE);
        try {
            return ParcelFileDescriptor.open(file, ParcelFileDescriptor.MODE_READ_ONLY).detachFd();
        } catch (FileNotFoundException absent) {
            return -1;
        }
    }

    private static int categoryMask(AppPrefs prefs) {
        return RuleCategory.mask((prefs == null ? AppPrefs.Settings.DEFAULT : prefs.settings()).disabledCategories());
    }

    /**
     * Relit la liste personnelle, le bundle et les catégories actives, et remplace les règles du moteur. Après
     * {@code close()}, {@code setRules} est simplement sans effet.
     */
    private void reloadRules(NativeEngine target, RuleStore rules, AppPrefs preferences) {
        synchronized (reloadLock) {
            target.setRules(openBlocklist(), openBundle(rules), categoryMask(preferences));
        }
    }

    /** Règles cédées au moteur : bundle signé, sinon liste intégrée à l'APK ; -1 si aucune n'est lisible. */
    private static int openBundle(RuleStore rules) {
        return rules.openRules().map(active -> {
            try (active) {
                // dup() partage la position du flux, laissée au début du fichier par openActive().
                return ParcelFileDescriptor.dup(active.stream().getFD()).detachFd();
            } catch (IOException e) {
                return -1;
            }
        }).orElse(-1);
    }

    @Override
    public void onRevoke() {
        // Un autre VPN a pris la main : sans lockdown, le trafic sort sans filtrage dès maintenant.
        ShieldStatus.publish(new ShieldStatus.Snapshot(false, LockdownStatus.REVOKED));
        ShieldNotifications.alertRevoked(this);
        shutdown();
        stopForeground(STOP_FOREGROUND_REMOVE);
        stopSelf();
    }

    @Override
    public void onDestroy() {
        shutdown();
        if (ShieldStatus.current().running()) {
            ShieldStatus.publish(ShieldStatus.Snapshot.STOPPED);
        }
        super.onDestroy();
    }

    private void shutdown() {
        main.removeCallbacks(endPause);
        pausedUntil = 0;
        for (var subscription : new ShieldStatus.Subscription[]{prefsChanges, listsChanges}) {
            if (subscription != null) {
                subscription.close();
            }
        }
        prefsChanges = null;
        listsChanges = null;
        if (recorder != null) {
            recorder.close();
            recorder = null;
        }
        if (ruleUpdates != null) {
            ruleUpdates.close();
            ruleUpdates = null;
        }
        if (appRules != null) {
            appRules.close();
            appRules = null;
        }
        if (networkStateMonitor != null) {
            networkStateMonitor.close();
            networkStateMonitor = null;
        }
        if (upstream != null) {
            upstream.close();
            upstream = null;
        }
        if (engine != null) {
            ShieldStatus.detach();
            engine.close();
            engine = null;
        }
    }
}
