package com.akeeper.ui;

import com.akeeper.vpn.ShieldStatus;

/** États de l'accueil A1 (docs/ui-ecrans.md §4), par priorité décroissante. */
enum HomeState {
    REVOKED(Level.DANGER, Action.REACTIVATE),
    STOPPED(Level.DANGER, Action.REACTIVATE),
    NO_LOCKDOWN(Level.WARN, Action.ENABLE_LOCKDOWN),
    PROTECTED(Level.OK, Action.NONE);

    enum Level { OK, WARN, DANGER }

    enum Action { NONE, REACTIVATE, ENABLE_LOCKDOWN }

    final Level level;
    final Action action;

    HomeState(Level level, Action action) {
        this.level = level;
        this.action = action;
    }

    static HomeState of(ShieldStatus.Snapshot snapshot) {
        if (snapshot.lockdown().revoked()) {
            return REVOKED;
        }
        if (!snapshot.running()) {
            return STOPPED;
        }
        return snapshot.lockdown().failClosed() ? PROTECTED : NO_LOCKDOWN;
    }
}
