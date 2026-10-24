package com.akeeper.ui;

import static org.assertj.core.api.Assertions.assertThat;

import android.view.View;

import com.akeeper.R;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.Robolectric;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

/** Chaque écran est gonflé avec le vrai thème, puis lié à sa logique : un attribut ou une ressource invalide plante ici. */
@RunWith(RobolectricTestRunner.class)
@Config(sdk = 36)
public class ScreensInflationTest {

    private MainActivity activity() {
        return Robolectric.buildActivity(MainActivity.class).setup().get();
    }

    @Test
    public void inflatesEveryLayout() {
        var activity = activity();
        for (int layout : new int[]{R.layout.screen_onboarding, R.layout.screen_home, R.layout.screen_apps,
                R.layout.screen_settings, R.layout.screen_lists, R.layout.screen_activity}) {
            activity.setContentView(layout);
            assertThat((View) activity.findViewById(R.id.root)).isNotNull();
        }
    }

    @Test
    public void bindsTheSettingsScreen() {
        var activity = activity();
        activity.setContentView(R.layout.screen_settings);
        var screen = new SettingsScreen(activity, activity.findViewById(R.id.root), () -> {
        }, () -> {
        });
        screen.refresh();
        screen.close();
    }

    @Test
    public void bindsTheListsScreen() {
        var activity = activity();
        activity.setContentView(R.layout.screen_lists);
        new ListsScreen(activity, activity.findViewById(R.id.root), () -> {
        }).close();
    }

    @Test
    public void inflatesTheSheetsAndRows() {
        var activity = activity();
        var inflater = activity.getLayoutInflater();
        for (int layout : new int[]{R.layout.sheet_event, R.layout.sheet_app, R.layout.item_event}) {
            assertThat(inflater.inflate(layout, null)).isNotNull();
        }
    }

    @Test
    public void bindsTheActivityScreenEvenWhenTheLogIsUnavailable() {
        var activity = activity();
        activity.setContentView(R.layout.screen_activity);
        // Sous Robolectric, SQLCipher n'a pas de bibliothèque native : l'écran doit l'absorber.
        new ActivityScreen(activity, activity.findViewById(R.id.root)).close();
    }

    @Test
    public void bindsTheAppsScreen() {
        var activity = activity();
        activity.setContentView(R.layout.screen_apps);
        new AppsScreen(activity, activity.findViewById(R.id.root)).close();
    }
}
