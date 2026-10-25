package com.akeeper.vpn;

/** État du réseau physique sous-jacent au VPN, utilisé pour les décisions contextuelles de sécurité. */
public record NetworkState(Transport transport, boolean metered, boolean roaming, boolean validated,
                           boolean captivePortal) {

    public enum Transport { NONE, WIFI, CELLULAR, ETHERNET, OTHER }

    public static final NetworkState NONE = new NetworkState(Transport.NONE, true, false, false, false);

    /**
     * L'exclusion du LAN n'est sûre que sur un réseau local effectivement utilisable et validé. Elle reste
     * interdite sur le cellulaire, en itinérance, derrière un portail captif ou tant que la validation n'est pas faite.
     */
    public boolean allowsLanBypass() {
        return validated && !captivePortal && !roaming
                && (transport == Transport.WIFI || transport == Transport.ETHERNET);
    }
}
