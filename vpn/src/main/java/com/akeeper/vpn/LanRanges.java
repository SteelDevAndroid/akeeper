package com.akeeper.vpn;

import android.net.IpPrefix;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;

/**
 * Réseaux locaux exclus du tunnel quand l'option « Ne pas filtrer le réseau local » est active. Les plages privées
 * contiennent les adresses virtuelles du tunnel (DNS en 10.111.0.53 et fd00:6d73::53) : les exclure telles quelles
 * enverrait les requêtes DNS hors du tunnel, donc on retire de chaque plage le sous-réseau du tunnel.
 */
final class LanRanges {

    record Range(byte[] address, int prefix) {
    }

    private static final String[][] PRIVATE = {
            {"10.0.0.0", "8"}, {"172.16.0.0", "12"}, {"192.168.0.0", "16"}, {"169.254.0.0", "16"},
            {"fc00::", "7"}, {"fe80::", "10"},
    };
    private static final String[][] TUNNEL = {{"10.111.0.0", "16"}, {"fd00:6d73::", "32"}};

    private LanRanges() {
    }

    /** Les plages à passer à {@code VpnService.Builder.excludeRoute}. */
    static List<IpPrefix> prefixes() {
        var prefixes = new ArrayList<IpPrefix>();
        for (var range : privateRanges()) {
            try {
                prefixes.add(new IpPrefix(InetAddress.getByAddress(range.address()), range.prefix()));
            } catch (UnknownHostException impossible) {
                throw new IllegalStateException(impossible);
            }
        }
        return prefixes;
    }

    static List<Range> privateRanges() {
        var ranges = new ArrayList<Range>();
        for (var entry : PRIVATE) {
            var base = parse(entry[0]);
            int prefix = Integer.parseInt(entry[1]);
            var pieces = List.of(new Range(base, prefix));
            for (var tunnel : TUNNEL) {
                var hole = parse(tunnel[0]);
                if (hole.length != base.length) {
                    continue;
                }
                var next = new ArrayList<Range>();
                for (var piece : pieces) {
                    next.addAll(subtract(piece, new Range(hole, Integer.parseInt(tunnel[1]))));
                }
                pieces = next;
            }
            ranges.addAll(pieces);
        }
        return ranges;
    }

    /** {@code base} privée de {@code hole} : les plages sœurs de chaque ancêtre du trou, du plus large au plus étroit. */
    static List<Range> subtract(Range base, Range hole) {
        // Le trou englobe la base : plus rien ne reste.
        if (hole.prefix() <= base.prefix() && contains(hole, base.address())) {
            return List.of();
        }
        if (hole.prefix() <= base.prefix() || !contains(base, hole.address())) {
            return List.of(base);
        }
        var pieces = new ArrayList<Range>();
        for (int length = base.prefix() + 1; length <= hole.prefix(); length++) {
            var sibling = hole.address().clone();
            // Garde les `length` premiers bits du trou, inverse le dernier : c'est la moitié qui ne contient pas le trou.
            int bit = length - 1;
            sibling[bit / 8] ^= (byte) (0x80 >> (bit % 8));
            for (int i = length; i < sibling.length * 8; i++) {
                sibling[i / 8] &= (byte) ~(0x80 >> (i % 8));
            }
            pieces.add(new Range(sibling, length));
        }
        return pieces;
    }

    static boolean contains(Range range, byte[] address) {
        if (range.address().length != address.length) {
            return false;
        }
        for (int i = 0; i < range.prefix(); i++) {
            int mask = 0x80 >> (i % 8);
            if ((range.address()[i / 8] & mask) != (address[i / 8] & mask)) {
                return false;
            }
        }
        return true;
    }

    private static byte[] parse(String literal) {
        try {
            // Littéral numérique : aucune résolution DNS.
            return InetAddress.getByName(literal).getAddress();
        } catch (UnknownHostException impossible) {
            throw new IllegalStateException(literal, impossible);
        }
    }
}
