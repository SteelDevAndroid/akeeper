package com.akeeper.rules;

import com.google.crypto.tink.subtle.Ed25519Sign;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;

/** Bundles signés construits côté Java, au format de {@code akeeper_proto::bundle}. */
final class TestBundles {

    private TestBundles() {
    }

    static byte[] signed(Ed25519Sign.KeyPair key, int keyId, long version, long createdAt)
            throws GeneralSecurityException {
        return signedWithPayload(key, keyId, version, createdAt,
                section(3, 0, "test".getBytes(StandardCharsets.UTF_8)));
    }

    static byte[] signedWithProvenance(Ed25519Sign.KeyPair key, int keyId, long version, long createdAt)
            throws GeneralSecurityException {
        var notice = section(3, 0, "test".getBytes(StandardCharsets.UTF_8));
        var provenance = section(4, 0, ("1\tHaGeZi\tGPL-3.0\thttps://example.test/list\t100\t200\t"
                + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n")
                .getBytes(StandardCharsets.UTF_8));
        var payload = ByteBuffer.allocate(notice.length + provenance.length).put(notice).put(provenance).array();
        return signedWithPayload(key, keyId, version, createdAt, payload);
    }

    private static byte[] section(int kind, int category, byte[] data) {
        return ByteBuffer.allocate(8 + data.length)
                .put((byte) kind).put((byte) category).putShort((short) 0).putInt(data.length).put(data).array();
    }

    private static byte[] signedWithPayload(Ed25519Sign.KeyPair key, int keyId, long version, long createdAt,
                                            byte[] payload) throws GeneralSecurityException {
        var message = ByteBuffer.allocate(BundleVerifier.HEADER_LEN + payload.length)
                .put(BundleVerifier.MAGIC)
                .putShort((short) BundleVerifier.FORMAT)
                .put((byte) keyId)
                .put((byte) 0)
                .putLong(version)
                .putLong(createdAt)
                .putInt(payload.length)
                .put(payload)
                .array();
        var signature = new Ed25519Sign(key.getPrivateKey()).sign(message);
        return ByteBuffer.allocate(message.length + signature.length).put(message).put(signature).array();
    }
}
