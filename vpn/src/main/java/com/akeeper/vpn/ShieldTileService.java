package com.akeeper.vpn;

import android.graphics.drawable.Icon;
import android.os.Handler;
import android.os.Looper;
import android.service.quicksettings.Tile;
import android.service.quicksettings.TileService;

/**
 * Tuile Réglages rapides : un appui bascule la pause, ou ouvre l'app si la protection est arrêtée (le
 * consentement VPN et le démarrage passent par l'UI). L'appui long ouvre l'accueil ({@code QS_TILE_PREFERENCES}).
 */
public final class ShieldTileService extends TileService {

    private final Handler main = new Handler(Looper.getMainLooper());
    private ShieldStatus.Subscription status;

    @Override
    public void onStartListening() {
        // L'état est publié par le service sur le thread principal ; la tuile s'y met à jour elle aussi.
        status = ShieldStatus.observe(snapshot -> main.post(() -> show(TileState.of(snapshot))));
    }

    @Override
    public void onStopListening() {
        if (status != null) {
            status.close();
            status = null;
        }
    }

    @Override
    public void onClick() {
        switch (TileState.of(ShieldStatus.current())) {
            case PROTECTED -> ShieldVpnService.pause(this);
            case PAUSED -> ShieldVpnService.resume(this);
            case STOPPED -> {
                var open = ShieldNotifications.openApp(this);
                if (open != null) {
                    startActivityAndCollapse(open);
                }
            }
        }
    }

    private void show(TileState state) {
        var tile = getQsTile();
        if (tile == null) {
            return;
        }
        tile.setIcon(Icon.createWithResource(this, R.drawable.ic_shield));
        tile.setLabel(getString(R.string.tile_label));
        tile.setState(state == TileState.PROTECTED ? Tile.STATE_ACTIVE : Tile.STATE_INACTIVE);
        tile.setSubtitle(getString(switch (state) {
            case PROTECTED -> R.string.tile_protected;
            case PAUSED -> R.string.tile_paused;
            case STOPPED -> R.string.tile_stopped;
        }));
        tile.updateTile();
    }
}
