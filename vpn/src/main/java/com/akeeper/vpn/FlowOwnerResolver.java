package com.akeeper.vpn;

import android.net.ConnectivityManager;

import java.net.InetSocketAddress;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.OptionalInt;

public final class FlowOwnerResolver {

    static final int INVALID_UID = -1;

    public record FlowKey(int protocol, InetSocketAddress local, InetSocketAddress remote) {
        public FlowKey {
            Objects.requireNonNull(local);
            Objects.requireNonNull(remote);
        }
    }

    private final ConnectivityManager connectivityManager;
    private final Map<FlowKey, Integer> cache;

    public FlowOwnerResolver(ConnectivityManager connectivityManager, int maxEntries) {
        this.connectivityManager = connectivityManager;
        this.cache = new LinkedHashMap<>(maxEntries, 0.75f, true) {
            @Override
            protected boolean removeEldestEntry(Map.Entry<FlowKey, Integer> eldest) {
                return size() > maxEntries;
            }
        };
    }

    // LinkedHashMap en ordre d'accès n'est pas thread-safe ; l'appel Binder reste hors verrou pour ne pas sérialiser les nouveaux flux.
    public OptionalInt resolve(FlowKey key) {
        synchronized (cache) {
            var cached = cache.get(key);
            if (cached != null) {
                return OptionalInt.of(cached);
            }
        }
        int uid;
        try {
            uid = connectivityManager.getConnectionOwnerUid(key.protocol(), key.local(), key.remote());
        } catch (SecurityException notActiveVpn) {
            return OptionalInt.empty();
        }
        if (uid == INVALID_UID) {
            return OptionalInt.empty();
        }
        synchronized (cache) {
            cache.put(key, uid);
        }
        return OptionalInt.of(uid);
    }

    public void evict(FlowKey key) {
        synchronized (cache) {
            cache.remove(key);
        }
    }
}
