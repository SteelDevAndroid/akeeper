package com.akeeper.vpn;

import android.net.IpPrefix;

import java.util.List;

public record ShieldPolicy(boolean allowLanBypass, List<IpPrefix> lanRoutes, boolean strictMode) {

    public ShieldPolicy {
        lanRoutes = List.copyOf(lanRoutes);
    }

    public static ShieldPolicy hardened() {
        return new ShieldPolicy(false, List.of(), true);
    }
}
