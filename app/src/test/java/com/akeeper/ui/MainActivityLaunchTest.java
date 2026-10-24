package com.akeeper.ui;

import static org.assertj.core.api.Assertions.assertThat;

import android.view.View;

import com.akeeper.R;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.Robolectric;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

/** Lance la vraie activité avec les vrais layouts et thèmes : un plantage d'inflation fait échouer le test. */
@RunWith(RobolectricTestRunner.class)
@Config(sdk = 36)
public class MainActivityLaunchTest {

    @Test
    public void startsOnTheDisclosureStep() {
        var controller = Robolectric.buildActivity(MainActivity.class).setup();
        View title = controller.get().findViewById(R.id.step_title);
        assertThat(title).isNotNull();
    }
}
