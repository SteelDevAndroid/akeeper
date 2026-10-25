package com.akeeper;

import android.app.Application;

import com.akeeper.ui.CrashReport;
import com.google.android.material.color.DynamicColors;
import com.google.android.material.color.DynamicColorsOptions;

public final class AKeeperApplication extends Application {

    public static final String UI_PREFS = "ui_preferences";
    public static final String PREF_DYNAMIC_COLOR = "dynamic_color";

    @Override
    public void onCreate() {
        super.onCreate();
        // Material You reste opt-in afin de préserver la palette aKeeper par défaut.
        var options = new DynamicColorsOptions.Builder()
                .setPrecondition((activity, theme) -> getSharedPreferences(UI_PREFS, MODE_PRIVATE)
                        .getBoolean(PREF_DYNAMIC_COLOR, false))
                .build();
        DynamicColors.applyToActivitiesIfAvailable(this, options);
        // Même processus que le service VPN : un plantage du service est aussi consigné.
        CrashReport.install(this);
    }
}
