package com.akeeper.ui;

import com.akeeper.vpn.LockdownStatus;
import com.akeeper.vpn.ShieldStatus.Snapshot;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class HomeStateTest {

    @Test
    void mapsSnapshotsByPriority() {
        assertThat(HomeState.of(new Snapshot(false, LockdownStatus.REVOKED))).isEqualTo(HomeState.REVOKED);
        assertThat(HomeState.of(Snapshot.STOPPED)).isEqualTo(HomeState.STOPPED);
        assertThat(HomeState.of(new Snapshot(true, new LockdownStatus(true, false)))).isEqualTo(HomeState.NO_LOCKDOWN);
        assertThat(HomeState.of(new Snapshot(true, new LockdownStatus(true, true)))).isEqualTo(HomeState.PROTECTED);
    }

    @Test
    void onlyDegradedStatesOfferAnAction() {
        assertThat(HomeState.PROTECTED.action).isEqualTo(HomeState.Action.NONE);
        assertThat(HomeState.NO_LOCKDOWN.action).isEqualTo(HomeState.Action.ENABLE_LOCKDOWN);
        assertThat(HomeState.REVOKED.level).isEqualTo(HomeState.Level.DANGER);
    }
}
