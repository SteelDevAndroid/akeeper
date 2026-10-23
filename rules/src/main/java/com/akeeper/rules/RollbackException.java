package com.akeeper.rules;

import java.security.GeneralSecurityException;

/** Bundle authentique mais pas plus récent que celui déjà vu : rejeu ou retour arrière, refusé. */
public final class RollbackException extends GeneralSecurityException {

    RollbackException(long version, long floor) {
        super("version " + version + " ≤ " + floor);
    }
}
