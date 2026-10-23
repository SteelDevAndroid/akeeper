package com.akeeper.vpn;

public record LockdownStatus(boolean alwaysOn, boolean lockdown, boolean revoked) {

    public static final LockdownStatus REVOKED = new LockdownStatus(false, false, true);

    public LockdownStatus(boolean alwaysOn, boolean lockdown) {
        this(alwaysOn, lockdown, false);
    }

    public boolean failClosed() {
        return alwaysOn && lockdown && !revoked;
    }
}
