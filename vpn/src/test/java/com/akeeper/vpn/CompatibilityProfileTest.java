package com.akeeper.vpn;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class CompatibilityProfileTest {

    @Test
    void classifiesFinancePaymentAndCriticalConnectivityApps() {
        assertThat(CompatibilityProfile.classify("mobi.societegenerale.mobile.lapplipro"))
                .isEqualTo(CompatibilityProfile.FINANCE);
        assertThat(CompatibilityProfile.classify("com.google.android.apps.walletnfcrel"))
                .isEqualTo(CompatibilityProfile.PAYMENT);
        assertThat(CompatibilityProfile.classify("com.android.captiveportallogin"))
                .isEqualTo(CompatibilityProfile.SYSTEM_CONNECTIVITY);
        assertThat(CompatibilityProfile.classify("com.example.app"))
                .isEqualTo(CompatibilityProfile.DEFAULT);
    }
}
