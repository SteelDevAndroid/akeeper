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
}
