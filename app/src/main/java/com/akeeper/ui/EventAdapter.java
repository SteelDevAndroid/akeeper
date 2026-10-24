package com.akeeper.ui;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.recyclerview.widget.RecyclerView;

import com.akeeper.R;
import com.akeeper.engine.FlowEvent;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

final class EventAdapter extends RecyclerView.Adapter<RecyclerView.ViewHolder> {

    private static final int TYPE_EVENT = 0;
    private static final int TYPE_HEADER = 1;

    private static final long HOUR = 3_600_000L;

    private final EventText text;
    private final boolean showApp;
    private final Consumer<FlowEvent> onOpen;
    private final boolean grouped;
    // Ligne : un FlowEvent, ou le titre (String) d'une heure.
    private List<Object> rows = List.of();

    /**
     * @param showApp faux dans la fiche d'une app, où l'app est déjà connue
     * @param grouped un titre par heure, pour l'écran Activité
     */
    EventAdapter(EventText text, boolean showApp, boolean grouped, Consumer<FlowEvent> onOpen) {
        this.text = text;
        this.showApp = showApp;
        this.grouped = grouped;
        this.onOpen = onOpen;
    }

    @SuppressWarnings("NotifyDataSetChanged") // Liste rechargée en bloc, au plus 500 lignes.
    void submit(List<FlowEvent> events) {
        this.rows = grouped ? withHeaders(events) : List.copyOf(events);
        notifyDataSetChanged();
    }

    /** Les événements arrivent du plus récent au plus ancien : un titre à chaque changement d'heure. */
    static List<Object> withHeaders(List<FlowEvent> events) {
        var rows = new ArrayList<Object>();
        long lastHour = Long.MIN_VALUE;
        for (var event : events) {
            long hour = event.timestampMillis() / HOUR;
            if (hour != lastHour) {
                rows.add(EventText.hour(hour * HOUR));
                lastHour = hour;
            }
            rows.add(event);
        }
        return rows;
    }

    @Override
    public int getItemCount() {
        return rows.size();
    }

    @Override
    public int getItemViewType(int position) {
        return rows.get(position) instanceof String ? TYPE_HEADER : TYPE_EVENT;
    }

    @NonNull
    @Override
    public RecyclerView.ViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        var inflater = LayoutInflater.from(parent.getContext());
        return viewType == TYPE_HEADER
                ? new RecyclerView.ViewHolder(inflater.inflate(R.layout.item_event_header, parent, false)) {
                }
                : new Holder(inflater.inflate(R.layout.item_event, parent, false));
    }

    @Override
    public void onBindViewHolder(@NonNull RecyclerView.ViewHolder viewHolder, int position) {
        if (viewHolder.itemView instanceof TextView title && rows.get(position) instanceof String heading) {
            title.setText(heading);
            return;
        }
        var holder = (Holder) viewHolder;
        var event = (FlowEvent) rows.get(position);
        var context = holder.itemView.getContext();
        holder.name.setText(event.name());
        var time = EventText.time(event.timestampMillis());
        holder.detail.setText(showApp
                ? context.getString(R.string.activity_row_detail, text.app(event.uid()), text.verdict(event), time)
                : context.getString(R.string.activity_row_detail, text.verdict(event), text.reason(event), time));
        holder.count.setText(event.count() > 1 ? context.getString(R.string.activity_row_count, event.count()) : "");
        holder.itemView.setOnClickListener(v -> onOpen.accept(event));
    }

    static final class Holder extends RecyclerView.ViewHolder {
        final TextView name;
        final TextView detail;
        final TextView count;

        Holder(View view) {
            super(view);
            name = view.findViewById(R.id.event_name);
            detail = view.findViewById(R.id.event_detail);
            count = view.findViewById(R.id.event_count);
        }
    }
}
