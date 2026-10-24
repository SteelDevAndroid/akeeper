package com.akeeper.engine;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

/**
 * Octets relayés pour une app depuis le dernier vidage.
 *
 * @param uid  UID de l'app, -1 si inconnu
 * @param sent octets envoyés vers Internet
 * @param received octets reçus
 */
public record TrafficSample(int uid, long sent, long received) {

    private static final int RECORD = 20;

    /** Décode {@code nativeDrainTraffic} ; un enregistrement tronqué met fin au décodage. */
    public static List<TrafficSample> parse(byte[] data) {
        var samples = new ArrayList<TrafficSample>();
        if (data == null) {
            return samples;
        }
        var buffer = ByteBuffer.wrap(data);
        while (buffer.remaining() >= RECORD) {
            samples.add(new TrafficSample(buffer.getInt(), buffer.getLong(), buffer.getLong()));
        }
        return samples;
    }
}
