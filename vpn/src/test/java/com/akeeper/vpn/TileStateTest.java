package com.akeeper.vpn;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class TileStateTest {

    private static final LockdownStatus LOCKED = new LockdownStatus(true, true);

    @Test
    void stoppedWheneverTheServiceIsNotRunning() {
        assertThat(TileState.of(ShieldStatus.Snapshot.STOPPED)).isEqualTo(TileState.STOPPED);
        assertThat(TileState.of(new ShieldStatus.Snapshot(false, LockdownStatus.REVOKED))).isEqualTo(TileState.STOPPED);
    }

    @Test
    void pausedOnlyWhilePausedAndRunning() {
        assertThat(TileState.of(new ShieldStatus.Snapshot(true, LOCKED, false, 1_000))).isEqualTo(TileState.PAUSED);
        assertThat(TileState.of(new ShieldStatus.Snapshot(true, LOCKED))).isEqualTo(TileState.PROTECTED);
    }

    @Test
    void degradedStatesStillToggleThePause() {
        assertThat(TileState.of(new ShieldStatus.Snapshot(true, new LockdownStatus(false, false), true)))
                .isEqualTo(TileState.PROTECTED);
    }
}
