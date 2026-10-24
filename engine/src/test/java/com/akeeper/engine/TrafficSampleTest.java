package com.akeeper.engine;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.ByteBuffer;

import org.junit.jupiter.api.Test;

class TrafficSampleTest {

    @Test
    void decodesTheEngineLayoutAndIgnoresATruncatedTail() {
        var data = ByteBuffer.allocate(45)
                .putInt(10_001).putLong(1_000).putLong(2_000)
                .putInt(-1).putLong(3).putLong(4)
                .putInt(7).array();

        assertThat(TrafficSample.parse(data)).containsExactly(
                new TrafficSample(10_001, 1_000, 2_000), new TrafficSample(-1, 3, 4));
        assertThat(TrafficSample.parse(null)).isEmpty();
    }
}
