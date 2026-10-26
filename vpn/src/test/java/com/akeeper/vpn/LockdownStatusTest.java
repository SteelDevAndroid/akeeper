package com.akeeper.vpn;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class LockdownStatusTest {

    @Test
    void failClosedOnlyWithAlwaysOnAndLockdown() {
        assertThat(new LockdownStatus(true, true).failClosed()).isTrue();
        assertThat(new LockdownStatus(true, false).failClosed()).isFalse();
        assertThat(new LockdownStatus(false, true).failClosed()).isFalse();
    }

    @Test
    void revokedIsNeverFailClosed() {
        assertThat(LockdownStatus.REVOKED.failClosed()).isFalse();
    }

    @Test
    void lockdownIsLostOnlyWhenItWasActive() {
        var locked = new LockdownStatus(true, true);
        assertThat(new LockdownStatus(true, false).lockdownLostSince(locked)).isTrue();
        assertThat(new LockdownStatus(false, false).lockdownLostSince(locked)).isTrue();
        assertThat(locked.lockdownLostSince(locked)).isFalse();
        assertThat(new LockdownStatus(true, false).lockdownLostSince(new LockdownStatus(true, false))).isFalse();
        assertThat(LockdownStatus.REVOKED.lockdownLostSince(locked)).as("la révocation a sa propre alerte").isFalse();
    }
}
