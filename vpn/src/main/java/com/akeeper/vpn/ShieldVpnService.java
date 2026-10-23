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
import java.security.GeneralSecurityException;

/** Toutes les méthodes s'exécutent sur le thread principal : aucun champ n'est partagé entre threads. */
public final class ShieldVpnService extends VpnService {

    static final String DNS_V4 = "10.111.0.53";
    static final String DNS_V6 = "fd00:6d73::53";
    /** Liste personnelle de domaines bloqués, un par ligne, dans {@code filesDir}. */
    public static final String BLOCKLIST_FILE = "blocklist.txt";

    private NativeEngine engine;
    private UpstreamDns upstream;
    private ShieldStatus.Subscription appRules;
    private RuleStore.Subscription ruleUpdates;
    private boolean privateDnsStrict;

    /** Prérequis : {@link VpnService#prepare} a renvoyé {@code null} (consentement accordé). */
    public static void start(Context context) {
        context.startForegroundService(new Intent(context, ShieldVpnService.class));
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
        ShieldStatus.publish(new ShieldStatus.Snapshot(true, new LockdownStatus(isAlwaysOn(), isLockdownEnabled()),
                privateDnsStrict));
        return START_STICKY;
    }

    private boolean establish() {
        // allowBypass() et allowFamily() sont proscrits : ils ouvrent un canal de fuite hors tunnel.
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
        // Aucune exclusion LAN : l'option opt-in (R1) n'existe pas encore, le LAN passe donc par le filtre.

        var tun = builder.establish();
        if (tun == null) {
            return false;
        }
        var rules = RuleStore.get(this);
        try {
            engine = NativeEngine.start(tun.detachFd(), openBlocklist(), openBundle(rules),
                    new EngineHost(new FlowOwnerResolver(getSystemService(ConnectivityManager.class))));
        } catch (IllegalStateException e) {
            return false;
        }
        ShieldStatus.attach(engine);
        applyAppRules();
        // Moteur capturé, comme pour les règles par app : l'activation arrive sur le thread de WorkManager.
        var current = engine;
        ruleUpdates = rules.observe(() -> current.setRules(openBlocklist(), openBundle(rules)));
        // Planifiée ici et non dans l'UI : Always-on VPN démarre le service sans jamais ouvrir l'app.
        RuleUpdates.schedule(this);
        upstream = new UpstreamDns(getSystemService(ConnectivityManager.class), engine, this::protect,
                this::followUnderlying, this::onPrivateDnsStrict);
        upstream.start(new Handler(Looper.getMainLooper()));
        return true;
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

    /** Bundle vérifié, cédé au moteur ; -1 sans bundle valide (liste personnelle et repli DoH embarqué seuls). */
    private static int openBundle(RuleStore rules) {
        return rules.openActive().map(active -> {
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
        if (ruleUpdates != null) {
            ruleUpdates.close();
            ruleUpdates = null;
        }
        if (appRules != null) {
            appRules.close();
            appRules = null;
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
