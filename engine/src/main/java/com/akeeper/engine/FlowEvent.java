package com.akeeper.engine;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Événement du journal d'activité. Métadonnées seulement : jamais de contenu, jamais d'adresse source.
 *
 * @param timestampMillis date de la première occurrence (horloge murale)
 * @param kind            nature de l'événement
 * @param blocked         {@code true} si le flux ou la requête a été refusé
 * @param reason          {@link Reason} du verdict ; {@link Reason#NONE} pour un événement autorisé
 * @param categoryId      catégorie du bundle quand {@code reason} vaut {@link Reason#CATEGORY}, 0 sinon
 * @param uid             UID de l'app, -1 si inconnu
 * @param name            domaine, ou adresse pour {@link Kind#IP} et {@link Kind#APP}
 * @param count           occurrences identiques regroupées (moins de 10 s d'écart)
 */
public record FlowEvent(
        long timestampMillis, Kind kind, boolean blocked, Reason reason, int categoryId, int uid, String name,
        int count) {

    /** Codes de {@code akeeper_engine::events::EventKind}. */
    public enum Kind {
        DNS(1), SNI(2), IP(3), APP(4);

        final int code;

        Kind(int code) {
            this.code = code;
        }

        public int code() {
            return code;
        }

        public static Kind of(int code) {
            for (var kind : values()) {
                if (kind.code == code) {
                    return kind;
                }
            }
            return null;
        }
    }

    /** Pourquoi un nom ou un flux est refusé ; les codes 16 et plus portent la catégorie du bundle. */
    public enum Reason {
        NONE, PERSONAL, EVASION, APP_FIREWALL, CATEGORY
    }

    private static final int HEADER = 22;

    /**
     * Décode le tampon de {@code nativeDrainEvents}. Un enregistrement tronqué ou inconnu met fin au décodage : le
     * moteur est de confiance, mais un octet de travers ne doit jamais faire échouer le service.
     */
    public static List<FlowEvent> parse(byte[] data) {
        var events = new ArrayList<FlowEvent>();
        if (data == null) {
            return events;
        }
        var buffer = ByteBuffer.wrap(data);
        while (buffer.remaining() >= HEADER) {
            long timestamp = buffer.getLong();
            var kind = Kind.of(buffer.get() & 0xff);
            boolean blocked = (buffer.get() & 1) != 0;
            int code = buffer.get() & 0xff;
            buffer.get();
            int uid = buffer.getInt();
            long count = buffer.getInt() & 0xffffffffL;
            int length = buffer.getShort() & 0xffff;
            if (buffer.remaining() < length) {
                break;
            }
            var name = new byte[length];
            buffer.get(name);
            if (kind == null) {
                continue;
            }
            var reason = switch (code) {
                case 0 -> Reason.NONE;
                case 1 -> Reason.PERSONAL;
                case 2 -> Reason.EVASION;
                case 3 -> Reason.APP_FIREWALL;
                default -> code >= 16 ? Reason.CATEGORY : Reason.NONE;
            };
            int category = reason == Reason.CATEGORY ? code - 16 : 0;
            events.add(new FlowEvent(timestamp, kind, blocked, reason, category, uid,
                    new String(name, StandardCharsets.UTF_8), (int) Math.min(count, Integer.MAX_VALUE)));
        }
        return events;
    }
}
