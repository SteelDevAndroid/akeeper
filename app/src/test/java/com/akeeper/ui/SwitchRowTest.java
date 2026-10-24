package com.akeeper.ui;

import static org.assertj.core.api.Assertions.assertThat;

import android.view.LayoutInflater;
import android.widget.TextView;

import com.akeeper.R;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.Robolectric;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

@RunWith(RobolectricTestRunner.class)
@Config(sdk = 36)
public class SwitchRowTest {

    private android.view.View row() {
        var activity = Robolectric.buildActivity(MainActivity.class).setup().get();
        return LayoutInflater.from(activity).inflate(R.layout.item_switch_row, null);
    }

    @Test
    public void theTitleNamesTheSwitchForScreenReaders() {
        var row = row();
        TextView title = row.findViewById(R.id.row_title);

        assertThat(title.getLabelFor()).isEqualTo(R.id.row_switch);
    }

    @Test
    public void touchingTheRowTogglesAnEnabledSwitchOnly() {
        var row = row();
        var toggle = SwitchRow.bind(row);

        row.performClick();
        assertThat(toggle.isChecked()).isTrue();

        toggle.setEnabled(false);
        row.performClick();
        assertThat(toggle.isChecked()).as("inactif : la ligne ne fait rien").isTrue();
    }
}
