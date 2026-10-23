package com.akeeper.security;

import android.content.Context;
import android.security.advancedprotection.AdvancedProtectionManager;

import com.akeeper.vpn.ShieldPolicy;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AdvancedProtectionPolicyTest {

    private final ShieldPolicy relaxed = new ShieldPolicy(true, List.of(), false);

    @Mock
    private Context context;

    @Mock
    private AdvancedProtectionManager manager;

    @Test
    void forcesHardenedPolicyWhenAdvancedProtectionIsOn() {
        when(context.getSystemService(AdvancedProtectionManager.class)).thenReturn(manager);
        when(manager.isAdvancedProtectionEnabled()).thenReturn(true);

        assertThat(new AdvancedProtectionPolicy(context).effective(relaxed)).isEqualTo(ShieldPolicy.hardened());
    }

    @Test
    void keepsUserPolicyWhenAdvancedProtectionIsOff() {
        when(context.getSystemService(AdvancedProtectionManager.class)).thenReturn(manager);
        when(manager.isAdvancedProtectionEnabled()).thenReturn(false);

        assertThat(new AdvancedProtectionPolicy(context).effective(relaxed)).isSameAs(relaxed);
    }

    @Test
    void keepsUserPolicyWhenServiceIsUnavailable() {
        when(context.getSystemService(AdvancedProtectionManager.class)).thenReturn(null);

        assertThat(new AdvancedProtectionPolicy(context).effective(relaxed)).isSameAs(relaxed);
    }
}
