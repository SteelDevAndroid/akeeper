package com.akeeper;

import android.app.Application;

import com.akeeper.ui.CrashReport;

public final class AKeeperApplication extends Application {

    @Override
    public void onCreate() {
        super.onCreate();
        // Même processus que le service VPN : un plantage du service est aussi consigné.
        CrashReport.install(this);
    }
}
