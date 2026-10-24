package com.akeeper.ui;

import android.view.View;

import com.akeeper.R;
import com.google.android.material.materialswitch.MaterialSwitch;

/** Ligne à interrupteur ({@code item_switch_row}) : toute la ligne bascule, pas seulement l'interrupteur. */
final class SwitchRow {

    private SwitchRow() {
    }

    static MaterialSwitch bind(View row) {
        MaterialSwitch toggle = row.findViewById(R.id.row_switch);
        // Inactif (préférences pas encore lues, ou indisponibles) : un toucher sur la ligne ne fait rien.
        row.setOnClickListener(v -> {
            if (toggle.isEnabled()) {
                toggle.toggle();
            }
        });
        return toggle;
    }
}
