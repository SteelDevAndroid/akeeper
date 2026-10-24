package com.akeeper.vpn;

import android.content.ContentValues;
import android.content.Context;

import com.akeeper.engine.FlowEvent;

import net.zetetic.database.sqlcipher.SQLiteDatabase;
import net.zetetic.database.sqlcipher.SQLiteOpenHelper;

import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.List;

/**
 * Journal d'activité : base SQLCipher dans {@code noBackupFilesDir}, jamais sauvegardée. Métadonnées seulement
 * (domaine ou adresse visée, UID, verdict) ; la conservation est bornée à 7 jours par {@link #purgeOlderThan}.
 */
public final class ActivityLog {

    /** Filtres de l'écran Activité (A4) et de la fiche d'une app (A3). */
    public record Query(boolean blockedOnly, int uid, int limit) {
        public static final int ANY_UID = Integer.MIN_VALUE;

        public static Query all(int limit) {
            return new Query(false, ANY_UID, limit);
        }
    }

    private static final String DATABASE = "activity.db";
    private static final int VERSION = 1;
    private static final String TABLE = "events";

    private static volatile ActivityLog instance;

    private final Helper helper;

    private ActivityLog(Context context, byte[] key) {
        try {
            System.loadLibrary("sqlcipher");
        } catch (UnsatisfiedLinkError missing) {
            // Un Error sur un thread de travail tuerait l'app : le journal est simplement indisponible.
            throw new IllegalStateException("SQLCipher indisponible", missing);
        }
        var path = new File(context.getNoBackupFilesDir(), DATABASE).getPath();
        var opened = new Helper(context, path, key);
        try {
            opened.getWritableDatabase();
        } catch (RuntimeException unreadable) {
            // Clé perdue ou base corrompue : le journal est un historique, pas une source de vérité. On le recrée.
            opened.close();
            for (var suffix : new String[]{"", "-wal", "-shm", "-journal"}) {
                new File(path + suffix).delete();
            }
            opened = new Helper(context, path, key);
        }
        helper = opened;
    }

    /** Ouvre la base au premier appel (Keystore, E/S) : jamais depuis le thread principal. */
    public static ActivityLog get(Context context) throws GeneralSecurityException, IOException {
        var current = instance;
        if (current == null) {
            synchronized (ActivityLog.class) {
                current = instance;
                if (current == null) {
                    var app = context.getApplicationContext();
                    current = new ActivityLog(app, DatabaseKey.load(app));
                    instance = current;
                }
            }
        }
        return current;
    }

    public void insert(List<FlowEvent> events) {
        if (events.isEmpty()) {
            return;
        }
        var db = helper.getWritableDatabase();
        db.beginTransaction();
        try {
            for (var event : events) {
                var values = new ContentValues();
                values.put("ts", event.timestampMillis());
                values.put("kind", event.kind().code());
                values.put("blocked", event.blocked() ? 1 : 0);
                values.put("reason", event.reason().ordinal());
                values.put("category", event.categoryId());
                values.put("uid", event.uid());
                values.put("name", event.name());
                values.put("count", event.count());
                db.insert(TABLE, null, values);
            }
            db.setTransactionSuccessful();
        } finally {
            db.endTransaction();
        }
    }

    /** Plus récents d'abord. */
    public List<FlowEvent> query(Query query) {
        var where = new ArrayList<String>();
        var args = new ArrayList<String>();
        if (query.blockedOnly()) {
            where.add("blocked = 1");
        }
        if (query.uid() != Query.ANY_UID) {
            where.add("uid = ?");
            args.add(Integer.toString(query.uid()));
        }
        var sql = "SELECT ts, kind, blocked, reason, category, uid, name, count FROM " + TABLE
                + (where.isEmpty() ? "" : " WHERE " + String.join(" AND ", where))
                + " ORDER BY ts DESC, id DESC LIMIT " + Math.max(1, Math.min(query.limit(), 1000));
        var events = new ArrayList<FlowEvent>();
        try (var cursor = helper.getReadableDatabase().rawQuery(sql, args.toArray(new String[0]))) {
            var reasons = FlowEvent.Reason.values();
            while (cursor.moveToNext()) {
                var kind = FlowEvent.Kind.of(cursor.getInt(1));
                int reason = cursor.getInt(3);
                if (kind == null || reason < 0 || reason >= reasons.length) {
                    continue;
                }
                events.add(new FlowEvent(cursor.getLong(0), kind, cursor.getInt(2) != 0, reasons[reason],
                        cursor.getInt(4), cursor.getInt(5), cursor.getString(6), cursor.getInt(7)));
            }
        }
        return events;
    }

    /** Requêtes et connexions refusées depuis {@code sinceMillis}, doublons regroupés comptés. */
    public long blockedSince(long sinceMillis) {
        try (var cursor = helper.getReadableDatabase().rawQuery(
                "SELECT COALESCE(SUM(count), 0) FROM " + TABLE + " WHERE blocked = 1 AND ts >= ?",
                new String[]{Long.toString(sinceMillis)})) {
            return cursor.moveToFirst() ? cursor.getLong(0) : 0;
        }
    }

    public void purgeOlderThan(long cutoffMillis) {
        helper.getWritableDatabase().delete(TABLE, "ts < ?", new String[]{Long.toString(cutoffMillis)});
    }

    public void clear() {
        helper.getWritableDatabase().delete(TABLE, null, null);
    }

    private static final class Helper extends SQLiteOpenHelper {

        Helper(Context context, String path, byte[] key) {
            super(context, path, key, null, VERSION, 0, null, null, false);
        }

        @Override
        public void onCreate(SQLiteDatabase db) {
            db.execSQL("CREATE TABLE " + TABLE + " (id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL,"
                    + " kind INTEGER NOT NULL, blocked INTEGER NOT NULL, reason INTEGER NOT NULL,"
                    + " category INTEGER NOT NULL, uid INTEGER NOT NULL, name TEXT NOT NULL,"
                    + " count INTEGER NOT NULL)");
            db.execSQL("CREATE INDEX events_ts ON " + TABLE + " (ts)");
            db.execSQL("CREATE INDEX events_uid ON " + TABLE + " (uid, ts)");
        }

        @Override
        public void onUpgrade(SQLiteDatabase db, int oldVersion, int newVersion) {
            // Version 1 : rien à migrer.
        }
    }
}
