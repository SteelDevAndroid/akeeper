package com.akeeper.ui;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.recyclerview.widget.RecyclerView;

import com.akeeper.R;
import com.akeeper.engine.FlowEvent;

import java.util.List;
import java.util.function.Consumer;

final class EventAdapter extends RecyclerView.Adapter<EventAdapter.Holder> {

    private final EventText text;
    private final boolean showApp;
    private final Consumer<FlowEvent> onOpen;
    private List<FlowEvent> events = List.of();

    /** {@code showApp} faux dans la fiche d'une app, où l'app est déjà connue. */
    EventAdapter(EventText text, boolean showApp, Consumer<FlowEvent> onOpen) {
        this.text = text;
        this.showApp = showApp;
        this.onOpen = onOpen;
    }

    @SuppressWarnings("NotifyDataSetChanged") // Liste rechargée en bloc, au plus 500 lignes.
    void submit(List<FlowEvent> events) {
        this.events = events;
        notifyDataSetChanged();
    }

    @Override
    public int getItemCount() {
        return events.size();
    }

    @NonNull
    @Override
    public Holder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        return new Holder(LayoutInflater.from(parent.getContext()).inflate(R.layout.item_event, parent, false));
    }

    @Override
    public void onBindViewHolder(@NonNull Holder holder, int position) {
        var event = events.get(position);
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
