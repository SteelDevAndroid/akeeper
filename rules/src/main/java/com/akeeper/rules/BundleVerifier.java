package com.akeeper.rules;

import com.google.crypto.tink.subtle.Ed25519Verify;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

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
    private static final int SECTION_HEADER = 8;
    private static final int KIND_DOMAINS = 1;
    private static final int KIND_NOTICE = 3;
    private static final int KIND_PROVENANCE = 4;
    private static final int CATEGORY_DOH = 4;

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

    /** Section d'un bundle déjà contrôlé : type, catégorie, et position de ses données. */
    private record Section(int kind, int category, int offset, int length) {
    }

    /**
     * Sections d'un bundle <b>déjà contrôlé</b> par {@link #parse}. Les longueurs sont rebornées ici : un découpage
     * incohérent arrête simplement la lecture.
     */
    private static List<Section> sections(byte[] bundle) {
        var sections = new ArrayList<Section>();
        int offset = HEADER_LEN;
        int end = bundle.length - SIGNATURE_LEN;
        while (offset + SECTION_HEADER <= end) {
            var header = ByteBuffer.wrap(bundle, offset, SECTION_HEADER);
            int kind = Byte.toUnsignedInt(header.get());
            int category = Byte.toUnsignedInt(header.get());
            header.getShort();
            long length = Integer.toUnsignedLong(header.getInt());
            offset += SECTION_HEADER;
            if (length > end - offset) {
                break;
            }
            sections.add(new Section(kind, category, offset, (int) length));
            offset += (int) length;
        }
        return sections;
    }

    /** Texte {@code NOTICE} (sources et licences) d'un bundle déjà contrôlé. */
    public static Optional<String> notice(byte[] checkedBundle) {
        return sections(checkedBundle).stream()
                .filter(section -> section.kind() == KIND_NOTICE)
                .findFirst()
                .map(section -> new String(checkedBundle, section.offset(), section.length(), StandardCharsets.UTF_8));
    }

    /** Métadonnées de provenance signées du bundle, une ligne tabulée par source. */
    public static List<RuleProvenance> provenance(byte[] checkedBundle) {
        return sections(checkedBundle).stream()
                .filter(section -> section.kind() == KIND_PROVENANCE)
                .flatMap(section -> new String(checkedBundle, section.offset(), section.length(), StandardCharsets.UTF_8)
                        .lines())
                .map(BundleVerifier::parseProvenance)
                .flatMap(Optional::stream)
                .toList();
    }

    private static Optional<RuleProvenance> parseProvenance(String line) {
        var fields = line.split("\\t", -1);
        if (fields.length != 7) {
            return Optional.empty();
        }
        try {
            int category = Integer.parseInt(fields[0]);
            long retrievedAt = Long.parseLong(fields[4]);
            long expiresAt = Long.parseLong(fields[5]);
            if (category < 0 || category > 255 || retrievedAt < 0 || expiresAt < 0
                    || fields[6].length() != 64 || !fields[6].matches("[0-9a-fA-F]{64}")) {
                return Optional.empty();
            }
            return Optional.of(new RuleProvenance(category, fields[1], fields[2], fields[3],
                    retrievedAt, expiresAt, fields[6].toLowerCase()));
        } catch (NumberFormatException invalid) {
            return Optional.empty();
        }
    }

    /** Catégories de domaines que contient un bundle déjà contrôlé, hors DoH, qui n'a pas d'interrupteur. */
    public static Set<Integer> categories(byte[] checkedBundle) {
        return sections(checkedBundle).stream()
                .filter(section -> section.kind() == KIND_DOMAINS && section.category() != CATEGORY_DOH)
                .map(Section::category)
                .collect(Collectors.toUnmodifiableSet());
    }

    /**
     * Contrôle l'enveloppe sans vérifier la signature : pour la liste intégrée à l'APK, dont l'authenticité est celle
     * de l'APK. Un bundle téléchargé passe toujours par {@link #verify}.
     */
    public static RuleBundle parse(byte[] bundle) throws GeneralSecurityException {
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
        if (version < 0) {
            throw new GeneralSecurityException("version de bundle invalide");
        }
        return new RuleBundle(keyId, version, createdAt);
    }

    public RuleBundle verify(byte[] bundle) throws GeneralSecurityException {
        var parsed = parse(bundle);
        if (parsed.keyId() >= keys.size()) {
            throw new GeneralSecurityException("clé de bundle inconnue");
        }
        int signed = bundle.length - SIGNATURE_LEN;
        // Copie transitoire (≤ 32 Mio) : l'API Tink ne prend pas de sous-tableau.
        keys.get(parsed.keyId()).verify(Arrays.copyOfRange(bundle, signed, bundle.length), Arrays.copyOf(bundle, signed));
        return parsed;
    }
}
