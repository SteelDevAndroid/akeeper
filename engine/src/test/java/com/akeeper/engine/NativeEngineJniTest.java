package com.akeeper.engine;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.nio.ByteBuffer;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.BooleanSupplier;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Exécute la vraie bibliothèque native depuis une JVM : démarrage, rappels {@code protect} et {@code ownerUid} depuis
 * le thread moteur, pare-feu par app, remplacement des règles, compteurs et arrêt. Une connexion TCP locale tient lieu de TUN.
 */
class NativeEngineJniTest {

    private static final byte[] CLIENT = {10, 111, 0, 1};
    private static final byte[] LOOPBACK = {127, 0, 0, 1};
    private static final int TCP = 6;
    private static final int SYN = 0x02;
    private static final int RST = 0x04;
    private static final int ACK = 0x10;

    private final List<Integer> protectedFds = new CopyOnWriteArrayList<>();
    private final List<String> lookups = new CopyOnWriteArrayList<>();
    private volatile int uid = 10_123;

    // Références gardées : le moteur ferme son extrémité, la JVM ne doit pas la refermer à la collecte.
    private SocketChannel app;
    private SocketChannel engineSide;
    private NativeEngine engine;
    private ServerSocket upstream;

    private final NativeEngine.Host host = new NativeEngine.Host() {
        @Override
        public boolean protect(int fd) {
            protectedFds.add(fd);
            return true;
        }

        @Override
        public int ownerUid(int protocol, byte[] local, int localPort, byte[] remote, int remotePort) {
            lookups.add(protocol + ":" + local.length + ":" + localPort + ">" + remote.length + ":" + remotePort);
            return uid;
        }
    };

    @BeforeEach
    void setUp() throws Exception {
        try (var server = ServerSocketChannel.open()) {
            server.bind(new InetSocketAddress(InetAddress.getByAddress(LOOPBACK), 0));
            app = SocketChannel.open(server.getLocalAddress());
            engineSide = server.accept();
        }
        upstream = new ServerSocket(0, 5, InetAddress.getByAddress(LOOPBACK));
        engine = NativeEngine.start(rawFd(engineSide), -1, -1, host);
    }

    @AfterEach
    void tearDown() throws IOException {
        engine.close();
        upstream.close();
        app.close();
    }

    @Test
    void relaysANewTcpFlowThroughProtectAndOwnerUid() throws Exception {
        app.write(ByteBuffer.wrap(tcpPacket(40_000, upstream.getLocalPort(), 1000, 0, SYN)));

        var reply = readPacket();
        assertThat(tcpFlags(reply)).isEqualTo(SYN | ACK);
        assertThat(lookups).containsExactly(TCP + ":4:40000>4:" + upstream.getLocalPort());
        assertThat(protectedFds).hasSize(1);
        upstream.setSoTimeout((int) Duration.ofSeconds(5).toMillis());
        try (var accepted = upstream.accept()) {
            assertThat(accepted.isConnected()).isTrue();
        }
        await(() -> engine.counter(NativeEngine.Counter.TCP_FLOWS) == 1);
    }

    @Test
    void refusesTheFlowsOfABlockedApp() throws Exception {
        assertThat(engine.setBlockedUids(new int[]{10_123})).isTrue();

        app.write(ByteBuffer.wrap(tcpPacket(40_001, upstream.getLocalPort(), 2000, 0, SYN)));

        assertThat(tcpFlags(readPacket()) & RST).isEqualTo(RST);
        assertThat(engine.counter(NativeEngine.Counter.APP_BLOCKED)).isEqualTo(1);
        assertThat(protectedFds).isEmpty();
    }

    @Test
    void resolvesAnUnknownOwnerAsAllowed() throws Exception {
        uid = -1;
        assertThat(engine.setBlockedUids(new int[]{10_123})).isTrue();

        app.write(ByteBuffer.wrap(tcpPacket(40_002, upstream.getLocalPort(), 3000, 0, SYN)));

        assertThat(tcpFlags(readPacket())).isEqualTo(SYN | ACK);
    }

    @Test
    void replacesTheRulesAndCountsPackets() throws Exception {
        assertThat(engine.setRules(-1, -1)).isTrue();
        app.write(ByteBuffer.wrap(new byte[]{0x45}));
        await(() -> engine.counter(NativeEngine.Counter.MALFORMED) == 1);
        assertThat(engine.counter(NativeEngine.Counter.PACKETS)).isEqualTo(1);
    }

    @Test
    void ignoresCallsOnceClosed() {
        engine.close();
        assertThat(engine.counter(NativeEngine.Counter.PACKETS)).isEqualTo(-1);
        assertThat(engine.setBlockedUids(new int[0])).isFalse();
        engine.close();
    }

    private byte[] readPacket() throws Exception {
        var buffer = ByteBuffer.allocate(2048);
        app.configureBlocking(false);
        long deadline = System.nanoTime() + Duration.ofSeconds(5).toNanos();
        while (System.nanoTime() < deadline) {
            if (app.read(buffer) > 0) {
                break;
            }
            Thread.sleep(10);
        }
        assertThat(buffer.position()).as("paquet reçu du moteur").isGreaterThan(0);
        var packet = new byte[buffer.position()];
        buffer.flip();
        buffer.get(packet);
        return packet;
    }

    private static int tcpFlags(byte[] packet) {
        int ihl = (packet[0] & 0x0f) * 4;
        return packet[ihl + 13] & 0xff;
    }

    private static void await(BooleanSupplier condition) throws InterruptedException {
        long deadline = System.nanoTime() + Duration.ofSeconds(5).toNanos();
        while (!condition.getAsBoolean()) {
            assertThat(System.nanoTime()).as("condition atteinte à temps").isLessThan(deadline);
            Thread.sleep(10);
        }
    }

    private static int rawFd(SocketChannel channel) throws Exception {
        var method = Class.forName("sun.nio.ch.SelChImpl").getMethod("getFDVal");
        return (int) method.invoke(channel);
    }

    /** Paquet IPv4 + TCP sans charge utile, avec les deux sommes de contrôle. */
    private static byte[] tcpPacket(int srcPort, int dstPort, long seq, long ack, int flags) {
        var buffer = ByteBuffer.allocate(40);
        buffer.put((byte) 0x45).put((byte) 0).putShort((short) 40).putShort((short) 1).putShort((short) 0x4000);
        buffer.put((byte) 64).put((byte) TCP).putShort((short) 0).put(CLIENT).put(LOOPBACK);
        buffer.putShort((short) srcPort).putShort((short) dstPort).putInt((int) seq).putInt((int) ack);
        buffer.put((byte) 0x50).put((byte) flags).putShort((short) 65_535).putShort((short) 0).putShort((short) 0);
        var packet = buffer.array();
        put16(packet, 10, checksum(packet, 0, 20, 0));
        long pseudo = sum(CLIENT, 0, 4) + sum(LOOPBACK, 0, 4) + TCP + 20;
        put16(packet, 36, checksum(packet, 20, 20, pseudo));
        return packet;
    }

    private static long sum(byte[] data, int offset, int length) {
        long total = 0;
        for (int i = 0; i < length; i += 2) {
            total += ((data[offset + i] & 0xff) << 8) | (data[offset + i + 1] & 0xff);
        }
        return total;
    }

    private static int checksum(byte[] data, int offset, int length, long initial) {
        long total = initial + sum(data, offset, length);
        while (total >> 16 != 0) {
            total = (total & 0xffff) + (total >> 16);
        }
        return (int) (~total & 0xffff);
    }

    private static void put16(byte[] data, int offset, int value) {
        data[offset] = (byte) (value >> 8);
        data[offset + 1] = (byte) value;
    }
}
