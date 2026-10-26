package com.akeeper.vpn;

/** État affiché par la tuile Réglages rapides (docs/ui-ecrans.md §6). */
enum TileState {
    PROTECTED, PAUSED, STOPPED;

    static TileState of(ShieldStatus.Snapshot snapshot) {
        if (!snapshot.running()) {
            return STOPPED;
        }
        return snapshot.paused() ? PAUSED : PROTECTED;
    }
}
