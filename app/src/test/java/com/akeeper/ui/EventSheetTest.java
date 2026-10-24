package com.akeeper.ui;

import static org.assertj.core.api.Assertions.assertThat;

import com.akeeper.engine.FlowEvent;
import com.akeeper.engine.FlowEvent.Kind;
import com.akeeper.engine.FlowEvent.Reason;

import org.junit.jupiter.api.Test;

class EventSheetTest {

    private static FlowEvent event(Kind kind, boolean blocked, Reason reason) {
        return new FlowEvent(0, kind, blocked, reason, 0, 10_001, "ads.example", 1);
    }

    @Test
    void domainsCanBeAllowedOrBlockedExceptDnsBypass() {
        assertThat(EventSheet.editable(event(Kind.DNS, true, Reason.CATEGORY))).isTrue();
        assertThat(EventSheet.editable(event(Kind.DNS, false, Reason.NONE))).isTrue();
        assertThat(EventSheet.editable(event(Kind.SNI, true, Reason.PERSONAL))).isTrue();
        assertThat(EventSheet.editable(event(Kind.DNS, true, Reason.EVASION))).isFalse();
    }

    @Test
    void addressesAndAppFirewallRefusalsHaveNoDomainAction() {
        assertThat(EventSheet.editable(event(Kind.IP, true, Reason.EVASION))).isFalse();
        assertThat(EventSheet.editable(event(Kind.APP, true, Reason.APP_FIREWALL))).isFalse();
    }
}
