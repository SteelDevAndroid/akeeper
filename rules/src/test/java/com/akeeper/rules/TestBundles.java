package com.akeeper.rules;

import com.google.crypto.tink.subtle.Ed25519Sign;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;

/** Bundles signés construits côté Java, au format de {@code akeeper_proto::bundle}. */
final class TestBundles {

    private TestBundles() {
    }

    static byte[] signed(Ed25519Sign.KeyPair key, int keyId, long version, long createdAt)
            throws GeneralSecurityException {
        byte[] payload = {3, 0, 0, 0, 0, 0, 0, 4, 't', 'e', 's', 't'};
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
