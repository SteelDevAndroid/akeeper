package com.akeeper.ui;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.view.View;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;

import com.akeeper.R;
import com.akeeper.engine.FlowEvent;
import com.akeeper.vpn.UserLists;
import com.google.android.material.bottomsheet.BottomSheetDialog;
import com.google.android.material.button.MaterialButton;
import com.google.android.material.snackbar.Snackbar;

import java.io.IOException;
import java.util.concurrent.ExecutorService;

/**
 * Détail d'un événement (A5). L'ajout aux listes personnelles est une écriture de fichier : il tourne sur le thread de
 * travail de l'écran appelant.
 */
final class EventSheet {

    private EventSheet() {
    }

    /** Le domaine d'une requête ou d'un SNI peut être autorisé ou bloqué ; une adresse ou un refus d'app non. */
    static boolean editable(FlowEvent event) {
        boolean domain = event.kind() == FlowEvent.Kind.DNS || event.kind() == FlowEvent.Kind.SNI;
        // Le contournement DNS ne s'autorise jamais (docs/ui-ecrans.md, A5).
        return domain && event.reason() != FlowEvent.Reason.EVASION;
    }

    static void show(AppCompatActivity activity, View anchor, EventText text, FlowEvent event, ExecutorService worker) {
        var dialog = new BottomSheetDialog(activity);
        var view = activity.getLayoutInflater().inflate(R.layout.sheet_event, null);
        ((TextView) view.findViewById(R.id.sheet_name)).setText(event.name());
        ((TextView) view.findViewById(R.id.sheet_verdict)).setText(text.verdict(event));
        ((TextView) view.findViewById(R.id.sheet_app)).setText(
                activity.getString(R.string.event_app) + " · " + text.app(event.uid()));
        ((TextView) view.findViewById(R.id.sheet_time)).setText(
                activity.getString(R.string.event_time) + " · " + EventText.dateTime(event.timestampMillis()));
        ((TextView) view.findViewById(R.id.sheet_reason)).setText(
                activity.getString(R.string.event_reason) + " · " + text.reason(event));

        MaterialButton primary = view.findViewById(R.id.sheet_primary);
        if (editable(event)) {
            primary.setText(event.blocked() ? R.string.event_allow : R.string.event_block);
            primary.setOnClickListener(v -> {
                dialog.dismiss();
                var kind = event.blocked() ? UserLists.Kind.ALLOWED : UserLists.Kind.BLOCKED;
                worker.execute(() -> save(activity, anchor, kind, event));
            });
        } else {
            primary.setVisibility(View.GONE);
        }
        view.findViewById(R.id.sheet_copy).setOnClickListener(v -> {
            var clipboard = activity.getSystemService(ClipboardManager.class);
            clipboard.setPrimaryClip(ClipData.newPlainText(event.name(), event.name()));
            dialog.dismiss();
            Snackbar.make(anchor, R.string.event_copied, Snackbar.LENGTH_SHORT).show();
        });
        dialog.setContentView(view);
        dialog.show();
    }

    private static void save(AppCompatActivity activity, View anchor, UserLists.Kind kind, FlowEvent event) {
        String message;
        try {
            var added = UserLists.get(activity).add(kind, event.name());
            message = added.isEmpty() ? activity.getString(R.string.event_save_failed)
                    : activity.getString(kind == UserLists.Kind.ALLOWED
                            ? R.string.event_allowed_done : R.string.event_blocked_done, event.name());
        } catch (IOException e) {
            message = activity.getString(R.string.event_save_failed);
        }
        var shown = message;
        activity.runOnUiThread(() -> Snackbar.make(anchor, shown, Snackbar.LENGTH_LONG).show());
    }
}
