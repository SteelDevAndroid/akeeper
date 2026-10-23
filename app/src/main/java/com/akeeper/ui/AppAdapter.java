package com.akeeper.ui;

import android.content.pm.PackageManager;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.recyclerview.widget.RecyclerView;

import com.akeeper.R;
import com.google.android.material.materialswitch.MaterialSwitch;

import java.util.List;
import java.util.Set;
import java.util.function.BiConsumer;

final class AppAdapter extends RecyclerView.Adapter<AppAdapter.Holder> {

    private final PackageManager packageManager;
    /** (app, accès Internet souhaité) */
    private final BiConsumer<AppEntry, Boolean> onToggle;
    private List<AppEntry> apps = List.of();
    private Set<String> blocked = Set.of();

    AppAdapter(PackageManager packageManager, BiConsumer<AppEntry, Boolean> onToggle) {
        this.packageManager = packageManager;
        this.onToggle = onToggle;
    }

    @SuppressWarnings("NotifyDataSetChanged") // Liste filtrée recalculée en bloc : quelques centaines d'éléments.
    void submit(List<AppEntry> apps, Set<String> blocked) {
        this.apps = apps;
        this.blocked = blocked;
        notifyDataSetChanged();
    }

    @Override
    public int getItemCount() {
        return apps.size();
    }

    @NonNull
    @Override
    public Holder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        return new Holder(LayoutInflater.from(parent.getContext()).inflate(R.layout.item_app, parent, false));
    }

    @Override
    public void onBindViewHolder(@NonNull Holder holder, int position) {
        var app = apps.get(position);
        var context = holder.itemView.getContext();
        holder.label.setText(app.label());
        holder.detail.setText(app.shared()
                ? context.getResources().getQuantityString(R.plurals.apps_shared, app.sharedWith(), app.sharedWith())
                : app.packageName());
        try {
            holder.icon.setImageDrawable(packageManager.getApplicationIcon(app.packageName()));
        } catch (PackageManager.NameNotFoundException uninstalled) {
            holder.icon.setImageDrawable(null);
        }
        boolean allowed = !blocked.contains(app.packageName());
        holder.toggle.setOnCheckedChangeListener(null);
        holder.toggle.setChecked(allowed);
        holder.toggle.setContentDescription(context.getString(R.string.apps_toggle_description, app.label()));
        holder.toggle.setOnCheckedChangeListener((button, checked) -> onToggle.accept(app, checked));
    }

    static final class Holder extends RecyclerView.ViewHolder {
        final ImageView icon;
        final TextView label;
        final TextView detail;
        final MaterialSwitch toggle;

        Holder(View view) {
            super(view);
            icon = view.findViewById(R.id.app_icon);
            label = view.findViewById(R.id.app_label);
            detail = view.findViewById(R.id.app_detail);
            toggle = view.findViewById(R.id.app_toggle);
        }
    }
}
