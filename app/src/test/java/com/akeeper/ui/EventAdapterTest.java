package com.akeeper.ui;

import static org.assertj.core.api.Assertions.assertThat;

import com.akeeper.engine.FlowEvent;

import java.util.List;

import org.junit.jupiter.api.Test;

class EventAdapterTest {

    private static FlowEvent at(long millis) {
        return new FlowEvent(millis, FlowEvent.Kind.DNS, true, FlowEvent.Reason.PERSONAL, 0, 10_001, "a.example", 1);
    }

    @Test
    void insertsOneHeaderPerHourChange() {
        long hour = 3_600_000L * 400_000;
        var rows = EventAdapter.withHeaders(List.of(at(hour + 3_000), at(hour + 1_000), at(hour - 1_000)));

        assertThat(rows).hasSize(5);
        assertThat(rows.get(0)).isInstanceOf(String.class);
        assertThat(rows.get(1)).isInstanceOf(FlowEvent.class);
        assertThat(rows.get(3)).isInstanceOf(String.class);
        assertThat(EventAdapter.withHeaders(List.of())).isEmpty();
    }
}
