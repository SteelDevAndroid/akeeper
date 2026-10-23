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

import java.io.File;
import java.io.FileNotFoundException;

/** Toutes les méthodes s'exécutent sur le thread principal : aucun champ n'est partagé entre threads. */
public final class ShieldVpnService extends VpnService {

    static final String DNS_V4 = "10.111.0.53";
    static final String DNS_V6 = "fd00:6d73::53";
    /** Liste personnelle de domaines bloqués, un par ligne, dans {@code filesDir}. */
    public static final String BLOCKLIST_FILE = "blocklist.txt";

    private NativeEngine engine;
    private UpstreamDns upstream;

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
        ShieldStatus.publish(new ShieldStatus.Snapshot(true, new LockdownStatus(isAlwaysOn(), isLockdownEnabled())));
        return START_STICKY;
    }

    private boolean establish() {
        // allowBypass() et allowFamily() sont proscrits : ils ouvrent un canal de fuite hors tunnel.
        var builder = new Builder()
                .setSession(getString(R.string.vpn_session))
                .setMtu(1500)
                .addAddress("10.111.0.1", 32)
                .addAddress("fd00:6d73::1", 128)
                // J1 : seul le résolveur local passe par le tunnel ; J2 routera 0.0.0.0/0 et ::/0.
                .addRoute(DNS_V4, 32)
                .addRoute(DNS_V6, 128)
                .addDnsServer(DNS_V4)
                .addDnsServer(DNS_V6)
                .setBlocking(false)
                .setMetered(false);

        var tun = builder.establish();
        if (tun == null) {
            return false;
        }
        try {
            engine = NativeEngine.start(tun.detachFd(), openBlocklist());
        } catch (IllegalStateException e) {
            return false;
        }
        upstream = new UpstreamDns(getSystemService(ConnectivityManager.class), engine, this::protect,
                this::followUnderlying);
        upstream.start(new Handler(Looper.getMainLooper()));
        return true;
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
        if (upstream != null) {
            upstream.close();
            upstream = null;
        }
        if (engine != null) {
            engine.close();
            engine = null;
        }
    }
}
