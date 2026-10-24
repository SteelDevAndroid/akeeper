package com.akeeper.rules;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.google.crypto.tink.subtle.Ed25519Sign;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;

class BundleVerifierTest {

    /** Clé publique de la graine de test {@code [1; 32]} de {@code akeeper-bundle} : jamais une clé de production. */
    private static final byte[] FIXTURE_KEY =
            HexFormat.of().parseHex("8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c");

    private Ed25519Sign.KeyPair first;
    private Ed25519Sign.KeyPair second;
    private BundleVerifier verifier;

    @BeforeEach
    void setUp() throws GeneralSecurityException {
        first = Ed25519Sign.KeyPair.newKeyPair();
        second = Ed25519Sign.KeyPair.newKeyPair();
        verifier = new BundleVerifier(List.of(first.getPublicKey(), second.getPublicKey()));
    }

    @Test
    void acceptsTheBundleBuiltAndSignedByTheRustTool() throws IOException, GeneralSecurityException {
        byte[] fixture;
        try (var in = getClass().getResourceAsStream("fixture-v5.akrb")) {
            fixture = in.readAllBytes();
        }
        var bundle = new BundleVerifier(List.of(FIXTURE_KEY)).verify(fixture);
        assertThat(bundle).isEqualTo(new RuleBundle(0, 5, 1_761_220_000L));
    }

    @Test
    void readsTheNoticeOfTheSharedFixture() throws IOException {
        try (var in = getClass().getResourceAsStream("fixture-v5.akrb")) {
            assertThat(BundleVerifier.notice(in.readAllBytes())).contains("Listes de test, domaine public.");
        }
    }

    @Test
    void readsTheNoticeOfAJavaBuiltBundleAndToleratesGarbage() throws GeneralSecurityException {
        assertThat(BundleVerifier.notice(TestBundles.signed(first, 0, 1, 0))).contains("test");
        assertThat(BundleVerifier.notice(new byte[10])).isEmpty();
        var oversized = TestBundles.signed(first, 0, 1, 0);
        oversized[BundleVerifier.HEADER_LEN + 7] = 100;
        assertThat(BundleVerifier.notice(oversized)).isEmpty();
    }

    @Test
    void parsesTheEnvelopeWithoutCheckingTheSignature() throws GeneralSecurityException {
        var unsigned = TestBundles.signed(first, 0, 4, 77);
        Arrays.fill(unsigned, unsigned.length - BundleVerifier.SIGNATURE_LEN, unsigned.length, (byte) 0);

        assertThat(BundleVerifier.parse(unsigned)).isEqualTo(new RuleBundle(0, 4, 77));
        assertThatThrownBy(() -> verifier.verify(unsigned)).isInstanceOf(GeneralSecurityException.class);
        assertThatThrownBy(() -> BundleVerifier.parse(new byte[10])).isInstanceOf(GeneralSecurityException.class);
    }

    @Test
    void selectsTheKeyNamedInTheHeader() throws GeneralSecurityException {
        assertThat(verifier.verify(TestBundles.signed(second, 1, 3, 0)).version()).isEqualTo(3);
        // key_id 0 désigne la première clé : la seconde ne peut pas signer en son nom.
        assertThatThrownBy(() -> verifier.verify(TestBundles.signed(second, 0, 3, 0)))
                .isInstanceOf(GeneralSecurityException.class);
    }

    @Test
    void rejectsTamperedOrExtendedBundles() throws GeneralSecurityException {
        var good = TestBundles.signed(first, 0, 9, 0);
        for (int offset : new int[]{0, 6, 10, 20, BundleVerifier.HEADER_LEN + 2, good.length - 1}) {
            var tampered = good.clone();
            tampered[offset] ^= 1;
            assertThatThrownBy(() -> verifier.verify(tampered)).isInstanceOf(GeneralSecurityException.class);
        }
        var extended = Arrays.copyOf(good, good.length + 1);
        assertThatThrownBy(() -> verifier.verify(extended)).isInstanceOf(GeneralSecurityException.class);
        assertThatThrownBy(() -> verifier.verify(new byte[10])).isInstanceOf(GeneralSecurityException.class);
    }

    @Test
    void rejectsVersionsBeyondSignedLongRange() throws GeneralSecurityException {
        assertThatThrownBy(() -> verifier.verify(TestBundles.signed(first, 0, -1, 0)))
                .isInstanceOf(GeneralSecurityException.class);
    }

    @Test
    void acceptsNothingWithoutEmbeddedKeys() throws GeneralSecurityException {
        var none = new BundleVerifier(List.of());
        assertThatThrownBy(() -> none.verify(TestBundles.signed(first, 0, 1, 0)))
                .isInstanceOf(GeneralSecurityException.class);
        assertThat(BundleVerifier.embedded()).isNotNull();
    }
}
