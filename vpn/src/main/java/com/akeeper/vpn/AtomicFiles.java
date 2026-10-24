package com.akeeper.vpn;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;

final class AtomicFiles {

    private AtomicFiles() {
    }

    /** Fichier temporaire, fsync, puis rename : une coupure ne laisse jamais un fichier tronqué. */
    static void write(File target, byte[] bytes) throws IOException {
        var temp = new File(target.getPath() + ".tmp");
        try (var out = new FileOutputStream(temp)) {
            out.write(bytes);
            out.getFD().sync();
        }
        Files.move(temp.toPath(), target.toPath(), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
    }
}
