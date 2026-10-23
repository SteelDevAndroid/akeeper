package com.akeeper.ui;

import com.akeeper.ui.OnboardingFlow.Facts;
import com.akeeper.ui.OnboardingFlow.Step;
import com.akeeper.vpn.LockdownStatus;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class OnboardingFlowTest {

    private static final LockdownStatus NO_LOCKDOWN = new LockdownStatus(false, false);
    private static final LockdownStatus LOCKED = new LockdownStatus(true, true);

    @Test
    void disclosureComesBeforeVpnConsent() {
        assertThat(OnboardingFlow.next(new Facts(false, false, false, false, false, NO_LOCKDOWN))).isEqualTo(Step.DISCLOSURE);
        assertThat(OnboardingFlow.next(new Facts(false, true, false, false, false, NO_LOCKDOWN))).isEqualTo(Step.VPN_CONSENT);
    }

    @Test
    void notificationsAreAskedOnceThenSkipped() {
        assertThat(OnboardingFlow.next(new Facts(false, true, true, false, false, NO_LOCKDOWN))).isEqualTo(Step.NOTIFICATIONS);
        assertThat(OnboardingFlow.next(new Facts(false, true, true, false, true, NO_LOCKDOWN))).isEqualTo(Step.LOCKDOWN);
    }

    @Test
    void lockdownBlocksUntilFailClosed() {
        assertThat(OnboardingFlow.next(new Facts(false, true, true, true, false, new LockdownStatus(true, false))))
                .isEqualTo(Step.LOCKDOWN);
        assertThat(OnboardingFlow.next(new Facts(false, true, true, true, false, LOCKED))).isEqualTo(Step.HOME);
    }

    @Test
    void finishedOnboardingAlwaysLandsHomeEvenWhenRevoked() {
        assertThat(OnboardingFlow.next(new Facts(true, false, false, false, false, LockdownStatus.REVOKED)))
                .isEqualTo(Step.HOME);
    }
}
