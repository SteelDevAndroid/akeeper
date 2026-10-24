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
        assertThat(HomeState.of(new Snapshot(true, new LockdownStatus(true, true), true)))
                .isEqualTo(HomeState.PRIVATE_DNS_STRICT);
        assertThat(HomeState.of(new Snapshot(true, new LockdownStatus(true, false), true)))
                .as("le verrouillage manquant prime sur le DNS strict")
                .isEqualTo(HomeState.NO_LOCKDOWN);
    }

    @Test
    void aPauseShowsOnlyWhenNothingMoreSeriousIsWrong() {
        var lockdown = new LockdownStatus(true, true);
        var until = 1_800_000_000_000L;
        assertThat(HomeState.of(new Snapshot(true, lockdown, false, until))).isEqualTo(HomeState.PAUSED);
        assertThat(HomeState.of(new Snapshot(true, lockdown, true, until))).isEqualTo(HomeState.PRIVATE_DNS_STRICT);
        assertThat(HomeState.of(new Snapshot(true, new LockdownStatus(true, false), false, until)))
                .isEqualTo(HomeState.NO_LOCKDOWN);
        assertThat(HomeState.of(new Snapshot(false, new LockdownStatus(true, true), false, until)))
                .isEqualTo(HomeState.STOPPED);
        assertThat(HomeState.of(new Snapshot(true, lockdown, false, 0))).isEqualTo(HomeState.PROTECTED);
    }

    @Test
    void protectedOffersThePauseAndPausedOffersTheResume() {
        assertThat(HomeState.PROTECTED.action).isEqualTo(HomeState.Action.PAUSE);
        assertThat(HomeState.PAUSED.action).isEqualTo(HomeState.Action.RESUME);
        assertThat(HomeState.PAUSED.level).isEqualTo(HomeState.Level.WARN);
    }

    @Test
    void onlyDegradedStatesOfferAnAction() {
        assertThat(HomeState.NO_LOCKDOWN.action).isEqualTo(HomeState.Action.ENABLE_LOCKDOWN);
        assertThat(HomeState.REVOKED.level).isEqualTo(HomeState.Level.DANGER);
    }
}
