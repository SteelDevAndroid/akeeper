package com.akeeper.engine;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import org.junit.jupiter.api.Test;

class FlowEventTest {

    private static byte[] record(long ts, int kind, int flags, int reason, int uid, int count, String name) {
        var text = name.getBytes(StandardCharsets.UTF_8);
        return ByteBuffer.allocate(22 + text.length)
                .putLong(ts).put((byte) kind).put((byte) flags).put((byte) reason).put((byte) 0)
                .putInt(uid).putInt(count).putShort((short) text.length).put(text).array();
    }

    private static byte[] concat(byte[]... parts) {
        return Arrays.stream(parts).reduce(new byte[0], (a, b) -> {
            var out = Arrays.copyOf(a, a.length + b.length);
            System.arraycopy(b, 0, out, a.length, b.length);
            return out;
        });
    }

    @Test
    void decodesTheEngineLayout() {
        var events = FlowEvent.parse(concat(
                record(1_700_000_000_000L, 1, 1, 17, 10_123, 3, "ads.example"),
                record(1_700_000_001_000L, 4, 1, 3, -1, 1, "203.0.113.9"),
                record(1_700_000_002_000L, 1, 0, 0, 10_5, 1, "example.org")));

        assertThat(events).hasSize(3);
        assertThat(events.get(0)).isEqualTo(new FlowEvent(1_700_000_000_000L, FlowEvent.Kind.DNS, true,
                FlowEvent.Reason.CATEGORY, 1, 10_123, "ads.example", 3));
        assertThat(events.get(1).reason()).isEqualTo(FlowEvent.Reason.APP_FIREWALL);
        assertThat(events.get(1).uid()).isEqualTo(-1);
        assertThat(events.get(2).blocked()).isFalse();
        assertThat(events.get(2).reason()).isEqualTo(FlowEvent.Reason.NONE);
    }

    @Test
    void stopsAtATruncatedRecordAndSkipsUnknownKinds() {
        var good = record(1, 2, 1, 2, 7, 1, "dns.google");
        var unknown = record(2, 99, 1, 2, 7, 1, "x");
        var truncated = Arrays.copyOf(record(3, 1, 1, 1, 7, 1, "abcdef"), 22 + 2);

        assertThat(FlowEvent.parse(concat(good, unknown, truncated))).singleElement()
                .extracting(FlowEvent::name).isEqualTo("dns.google");
        assertThat(FlowEvent.parse(null)).isEmpty();
        assertThat(FlowEvent.parse(new byte[5])).isEmpty();
    }
}
