package com.akeeper.rules;

import android.content.Context;

import java.io.Closeable;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.security.GeneralSecurityException;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArraySet;

/**
 * Bundle de règles actif et plancher anti-rollback. Activation atomique : fichier temporaire, vérification,
 * fsync, {@code rename}. Le plancher persiste la plus haute version activée et ne redescend jamais, même si le
 * bundle est supprimé. Partagé par le service VPN et la tâche de mise à jour.
 */
public final class RuleStore {

    private static final String DIR = "rules";
    private static final String BUNDLE = "bundle.akrb";
    private static final String FLOOR = "floor";

    private static volatile RuleStore instance;

    private final File dir;
    private final File bundle;
    private final File floor;
    private final BundleVerifier verifier;
    private final long embeddedFloor;
    private final Set<Runnable> listeners = new CopyOnWriteArraySet<>();

    RuleStore(File dir, BundleVerifier verifier, long embeddedFloor) {
        this.dir = dir;
        this.bundle = new File(dir, BUNDLE);
        this.floor = new File(dir, FLOOR);
        this.verifier = verifier;
        this.embeddedFloor = embeddedFloor;
    }

    public static RuleStore get(Context context) {
        var current = instance;
        if (current == null) {
            synchronized (RuleStore.class) {
                current = instance;
                if (current == null) {
                    // noBackupFilesDir : un bundle restauré d'une sauvegarde contournerait le plancher.
                    var dir = new File(context.getApplicationContext().getNoBackupFilesDir(), DIR);
                    current = new RuleStore(dir, BundleVerifier.embedded(), BuildConfig.MIN_RULE_VERSION);
                    instance = current;
                }
            }
        }
        return current;
    }

    /** Bundle ouvert et vérifié ; le flux est positionné au début du fichier, prêt à être cédé au moteur. */
    public record Active(RuleBundle bundle, FileInputStream stream) implements Closeable {
        @Override
        public void close() throws IOException {
            stream.close();
        }
    }

    /**
     * Vérifie et active un bundle téléchargé.
     *
     * @throws RollbackException        version non strictement supérieure à la dernière activée
     * @throws GeneralSecurityException enveloppe ou signature invalide
     */
    public synchronized RuleBundle install(InputStream source) throws IOException, GeneralSecurityException {
        var bytes = readBounded(source);
        var candidate = verifier.verify(bytes);
        long current = Math.max(floor(), activeVersion());
        if (candidate.version() <= current) {
            throw new RollbackException(candidate.version(), current);
        }
        writeAtomically(bundle, bytes);
        // Plancher écrit après l'activation : une coupure entre les deux laisse un bundle valide (version ≥ plancher).
        writeAtomically(floor, ByteBuffer.allocate(Long.BYTES).putLong(candidate.version()).array());
        listeners.forEach(Runnable::run);
        return candidate;
    }

    /**
     * Bundle actif s'il est authentique et pas plus ancien que le plancher. Le fichier est vérifié puis cédé tel
     * quel (même inode) : une activation concurrente le remplace par {@code rename} sans modifier ce descripteur.
     */
    public Optional<Active> openActive() {
        FileInputStream stream;
        try {
            stream = new FileInputStream(bundle);
        } catch (FileNotFoundException absent) {
            return Optional.empty();
        }
        try {
            var verified = verifier.verify(readBounded(stream));
            if (verified.version() < floor()) {
                stream.close();
                return Optional.empty();
            }
            stream.getChannel().position(0);
            return Optional.of(new Active(verified, stream));
        } catch (IOException | GeneralSecurityException invalid) {
            closeQuietly(stream);
            return Optional.empty();
        }
    }

    /** En-tête du bundle actif valide, sans garder le fichier ouvert. */
    public Optional<RuleBundle> active() {
        return openActive().map(active -> {
            closeQuietly(active);
            return active.bundle();
        });
    }

    /** Sources et licences du bundle actif, pour l'écran « Licences ». */
    public Optional<String> notice() {
        try (var active = openActive().orElse(null)) {
            if (active == null) {
                return Optional.empty();
            }
            return BundleVerifier.notice(readBounded(active.stream()));
        } catch (IOException unreadable) {
            return Optional.empty();
        }
    }

    /** L'observateur est appelé après chaque activation, sur le thread de la mise à jour. */
    public Subscription observe(Runnable listener) {
        listeners.add(listener);
        return () -> listeners.remove(listener);
    }

    @FunctionalInterface
    public interface Subscription extends AutoCloseable {
        @Override
        void close();
    }

    long floor() {
        long persisted;
        try (var in = new DataInputStream(new FileInputStream(floor))) {
            persisted = in.readLong();
        } catch (IOException absentOrTruncated) {
            persisted = 0;
        }
        return Math.max(embeddedFloor, persisted);
    }

    private long activeVersion() {
        try (var stream = new FileInputStream(bundle)) {
            return verifier.verify(readBounded(stream)).version();
        } catch (IOException | GeneralSecurityException absentOrInvalid) {
            return 0;
        }
    }

    private static byte[] readBounded(InputStream source) throws IOException {
        var bytes = source.readNBytes(BundleVerifier.MAX_BUNDLE + 1);
        if (bytes.length > BundleVerifier.MAX_BUNDLE) {
            throw new IOException("bundle trop volumineux");
        }
        return bytes;
    }

    private void writeAtomically(File target, byte[] bytes) throws IOException {
        if (!dir.isDirectory() && !dir.mkdirs()) {
            throw new IOException("création de " + dir + " impossible");
        }
        var temp = new File(dir, target.getName() + ".tmp");
        try (var out = new FileOutputStream(temp)) {
            out.write(bytes);
            out.getFD().sync();
        }
        Files.move(temp.toPath(), target.toPath(), StandardCopyOption.ATOMIC_MOVE,
                StandardCopyOption.REPLACE_EXISTING);
        // fsync du répertoire : sans lui, le rename peut être perdu à la coupure et le plancher revenir en arrière.
        try (var directory = FileChannel.open(dir.toPath(), StandardOpenOption.READ)) {
            directory.force(true);
        }
    }

    private static void closeQuietly(Closeable closeable) {
        try {
            closeable.close();
        } catch (IOException ignored) {
            // Descripteur en lecture seule : rien n'est perdu à la fermeture.
        }
    }
}
