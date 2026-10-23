package com.akeeper.rules;

import com.google.crypto.tink.subtle.Ed25519Verify;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;

/**
 * Vérifie l'enveloppe et la signature Ed25519 d'un bundle avant toute activation. Le moteur natif relit ensuite
 * le même fichier sans revérifier : ce contrôle est le seul point de confiance.
 */
public final class BundleVerifier {

    static final byte[] MAGIC = {'A', 'K', 'R', 'B'};
    static final int FORMAT = 1;
    static final int HEADER_LEN = 28;
    static final int SIGNATURE_LEN = 64;
    /** Même borne que {@code akeeper_proto::bundle::MAX_BUNDLE}. */
    public static final int MAX_BUNDLE = 32 * 1024 * 1024;
    private static final int PUBLIC_KEY_LEN = 32;

    // Indexé par key_id : la rotation ajoute la clé suivante sans retirer celle qui signe encore.
    private final List<Ed25519Verify> keys;

    /** @param publicKeys une ou deux clés publiques Ed25519 brutes de 32 octets ; vide = aucun bundle accepté */
    public BundleVerifier(List<byte[]> publicKeys) {
        if (publicKeys.size() > 2 || publicKeys.stream().anyMatch(k -> k.length != PUBLIC_KEY_LEN)) {
            throw new IllegalArgumentException("une ou deux clés Ed25519 de 32 octets");
        }
        this.keys = publicKeys.stream().map(Ed25519Verify::new).toList();
    }

    /** Clés de {@code BuildConfig.RULE_PUBLIC_KEYS} : hex séparées par des virgules, validées par Gradle. */
    public static BundleVerifier embedded() {
        var text = BuildConfig.RULE_PUBLIC_KEYS;
        var keys = text.isEmpty() ? List.<byte[]>of()
                : Arrays.stream(text.split(",")).map(HexFormat.of()::parseHex).toList();
        return new BundleVerifier(keys);
    }

    public RuleBundle verify(byte[] bundle) throws GeneralSecurityException {
        if (bundle.length < HEADER_LEN + SIGNATURE_LEN || bundle.length > MAX_BUNDLE) {
            throw new GeneralSecurityException("taille de bundle invalide");
        }
        var header = ByteBuffer.wrap(bundle, 0, HEADER_LEN);
        var magic = new byte[MAGIC.length];
        header.get(magic);
        if (!Arrays.equals(magic, MAGIC) || Short.toUnsignedInt(header.getShort()) != FORMAT) {
            throw new GeneralSecurityException("format de bundle inconnu");
        }
        int keyId = Byte.toUnsignedInt(header.get());
        int reserved = header.get();
        long version = header.getLong();
        long createdAt = header.getLong();
        long payloadLen = Integer.toUnsignedLong(header.getInt());
        // Taille exacte, comme côté Rust : aucun octet non signé ne peut suivre la signature.
        if (reserved != 0 || bundle.length != HEADER_LEN + payloadLen + SIGNATURE_LEN) {
            throw new GeneralSecurityException("enveloppe de bundle invalide");
        }
        // Les versions au-delà de Long.MAX_VALUE sont refusées plutôt que comparées en signé.
        if (version < 0 || keyId >= keys.size()) {
            throw new GeneralSecurityException("version ou clé de bundle invalide");
        }
        int signed = bundle.length - SIGNATURE_LEN;
        // Copie transitoire (≤ 32 Mio) : l'API Tink ne prend pas de sous-tableau.
        keys.get(keyId).verify(Arrays.copyOfRange(bundle, signed, bundle.length), Arrays.copyOf(bundle, signed));
        return new RuleBundle(keyId, version, createdAt);
    }
}
