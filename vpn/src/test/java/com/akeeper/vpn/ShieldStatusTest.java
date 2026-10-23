package com.akeeper.vpn;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;

import static org.assertj.core.api.Assertions.assertThat;

class ShieldStatusTest {

    @AfterEach
    void reset() {
        ShieldStatus.publish(ShieldStatus.Snapshot.STOPPED);
    }

    @Test
    void observerReceivesCurrentStateThenChangesUntilClosed() {
        var seen = new ArrayList<ShieldStatus.Snapshot>();
        var running = new ShieldStatus.Snapshot(true, new LockdownStatus(true, true));

        try (var ignored = ShieldStatus.observe(seen::add)) {
            ShieldStatus.publish(running);
        }
        ShieldStatus.publish(new ShieldStatus.Snapshot(false, LockdownStatus.REVOKED));

        assertThat(seen).containsExactly(ShieldStatus.Snapshot.STOPPED, running);
        assertThat(ShieldStatus.current().lockdown().revoked()).isTrue();
    }
}
