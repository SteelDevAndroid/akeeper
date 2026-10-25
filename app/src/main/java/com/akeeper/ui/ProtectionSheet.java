package com.akeeper.ui;

import android.view.View;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;

import com.akeeper.R;
import com.akeeper.vpn.ShieldStatus;
import com.google.android.material.bottomsheet.BottomSheetDialog;

/** Centre de protection : synthèse utilisateur, avec diagnostics techniques repliés par défaut. */
final class ProtectionSheet {

    private ProtectionSheet() {
    }

    static void show(AppCompatActivity activity) {
        var snapshot = ShieldStatus.current();
        var state = HomeState.of(snapshot);
        var dialog = new BottomSheetDialog(activity);
        var view = activity.getLayoutInflater().inflate(R.layout.sheet_protection, null);

        ((TextView) view.findViewById(R.id.protection_summary)).setText(switch (state.level) {
            case OK -> R.string.protection_summary_ok;
            case WARN -> R.string.protection_summary_warn;
            case DANGER -> R.string.protection_summary_danger;
        });

        bind(view, R.id.protection_vpn_state, snapshot.running(),
                R.string.protection_active, R.string.protection_inactive);
        bind(view, R.id.protection_dns_state, snapshot.running() && !snapshot.privateDnsStrict(),
                R.string.protection_active, R.string.protection_attention);
        bind(view, R.id.protection_lockdown_state, snapshot.lockdown().failClosed(),
                R.string.protection_active, R.string.protection_recommended);
        bind(view, R.id.protection_firewall_state, snapshot.running(),
                R.string.protection_active, R.string.protection_inactive);

        TextView technical = view.findViewById(R.id.protection_technical);
        technical.setText(activity.getString(R.string.protection_technical_value,
                yesNo(activity, snapshot.running()),
                yesNo(activity, snapshot.lockdown().alwaysOn()),
                yesNo(activity, snapshot.lockdown().lockdown()),
                yesNo(activity, snapshot.privateDnsStrict()),
                snapshot.pausedUntil()));
        view.findViewById(R.id.protection_technical_toggle).setOnClickListener(v -> {
            boolean open = technical.getVisibility() == View.VISIBLE;
            technical.setVisibility(open ? View.GONE : View.VISIBLE);
            ((TextView) v).setText(open ? R.string.protection_show_technical : R.string.protection_hide_technical);
        });

        dialog.setContentView(view);
        dialog.show();
    }

    private static void bind(View root, int id, boolean active, int activeText, int inactiveText) {
        TextView value = root.findViewById(id);
        value.setText(active ? activeText : inactiveText);
        value.setTextColor(root.getContext().getColor(active
                ? R.color.akeeper_state_ok : R.color.akeeper_state_warn));
    }

    private static String yesNo(AppCompatActivity activity, boolean value) {
        return activity.getString(value ? R.string.protection_yes : R.string.protection_no);
    }
}
