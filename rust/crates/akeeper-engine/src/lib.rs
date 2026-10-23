//! Moteur aKeeper. J1 : résolveur DNS local filtrant derrière les IP virtuelles du TUN.
//! Tout autre paquet est abandonné : rien ne ressort du tunnel sans verdict explicite (fail-closed).

mod blocklist;
mod dns;
mod stats;

pub use blocklist::Blocklist;
pub use dns::MAX_UPSTREAMS;
pub use stats::{Counter, Stats};

use std::fs::File;
use std::io::{self, ErrorKind, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, UdpSocket};
use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use akeeper_proto::{ip, tcp, udp};
use mio::unix::SourceFd;
use mio::{Events, Interest, Poll, Registry, Token, Waker};

use dns::{Outcome, Resolver};

/// Adresses du résolveur local annoncées par `VpnService.Builder.addDnsServer` (spec §4).
pub const DNS_V4: Ipv4Addr = Ipv4Addr::new(10, 111, 0, 53);
pub const DNS_V6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0x6d73, 0, 0, 0, 0, 0, 0x53);

const TUN: Token = Token(0);
const WAKE: Token = Token(1);
const UPSTREAM_BASE: usize = 2;
// Un datagramme TUN ne dépasse jamais 65 535 octets (longueur IP sur 16 bits).
const READ_BUFFER: usize = 65_535;
const EXPIRY_TICK: Duration = Duration::from_secs(1);

enum Command {
    Stop,
    SetUpstream(usize, Option<UdpSocket>),
}

pub struct Engine {
    commands: Sender<Command>,
    waker: Arc<Waker>,
    stats: Arc<Stats>,
    thread: Option<JoinHandle<io::Result<()>>>,
}

impl Engine {
    /// `tun` doit être en mode non bloquant : epoll est déclenché sur front, la boucle lit jusqu'à `WouldBlock`.
    pub fn start(tun: OwnedFd, blocklist: Blocklist) -> io::Result<Self> {
        let poll = Poll::new()?;
        let waker = Arc::new(Waker::new(poll.registry(), WAKE)?);
        poll.registry()
            .register(&mut SourceFd(&tun.as_raw_fd()), TUN, Interest::READABLE)?;

        let (commands, inbox) = mpsc::channel();
        let stats = Arc::new(Stats::default());
        let thread = thread::Builder::new()
            .name("akeeper-engine".into())
            .spawn({
                let stats = Arc::clone(&stats);
                move || {
                    run(
                        poll,
                        File::from(tun),
                        Resolver::new(blocklist),
                        &inbox,
                        &stats,
                    )
                }
            })?;

        Ok(Self {
            commands,
            waker,
            stats,
            thread: Some(thread),
        })
    }

    /// `socket` est connecté au serveur DNS amont et protégé (`VpnService.protect`) ; `None` vide le slot.
    pub fn set_upstream(&self, slot: usize, socket: Option<UdpSocket>) -> io::Result<()> {
        if slot >= MAX_UPSTREAMS {
            return Err(io::Error::from(ErrorKind::InvalidInput));
        }
        if let Some(s) = &socket {
            s.set_nonblocking(true)?;
        }
        self.send(Command::SetUpstream(slot, socket))
    }

    pub fn stats(&self) -> &Stats {
        &self.stats
    }

    /// Bloque jusqu'à l'arrêt de la boucle ; le TUN et les sockets amont sont fermés à la sortie du thread.
    pub fn stop(mut self) -> io::Result<()> {
        self.shutdown()
    }

    fn send(&self, command: Command) -> io::Result<()> {
        self.commands
            .send(command)
            .map_err(|_| io::Error::from(ErrorKind::BrokenPipe))?;
        self.waker.wake()
    }

    fn shutdown(&mut self) -> io::Result<()> {
        let Some(thread) = self.thread.take() else {
            return Ok(());
        };
        // Thread déjà sorti (TUN fermé) : le canal est rompu, seul le join compte.
        let _ = self.send(Command::Stop);
        thread
            .join()
            .map_err(|_| io::Error::other("le thread moteur a paniqué"))?
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        // Erreur déjà sans recours ici : le thread est arrêté ou mort, les fd sont fermés dans les deux cas.
        let _ = self.shutdown();
    }
}

fn run(
    mut poll: Poll,
    mut tun: File,
    mut resolver: Resolver,
    inbox: &Receiver<Command>,
    stats: &Stats,
) -> io::Result<()> {
    let mut events = Events::with_capacity(16);
    let mut buf = vec![0u8; READ_BUFFER];
    let mut out = Vec::with_capacity(1500);
    loop {
        let timeout = resolver.has_pending().then_some(EXPIRY_TICK);
        match poll.poll(&mut events, timeout) {
            Ok(()) => {}
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
        let now = Instant::now();
        resolver.expire(now, stats);
        for event in &events {
            match event.token() {
                WAKE => {
                    while let Ok(command) = inbox.try_recv() {
                        match command {
                            Command::Stop => return Ok(()),
                            Command::SetUpstream(slot, socket) => {
                                replace_upstream(poll.registry(), &mut resolver, slot, socket)?
                            }
                        }
                    }
                }
                TUN => {
                    if !drain_tun(&mut tun, &mut buf, &mut out, &mut resolver, now, stats)? {
                        return Ok(());
                    }
                }
                Token(t) => {
                    let slot = t - UPSTREAM_BASE;
                    resolver.drain_upstream(slot, &mut buf, |server, client, msg| {
                        if udp::build(server, client, msg, &mut out).is_ok() {
                            write_tun(&mut tun, &out);
                        }
                    })?;
                }
            }
        }
    }
}

fn replace_upstream(
    registry: &Registry,
    resolver: &mut Resolver,
    slot: usize,
    socket: Option<UdpSocket>,
) -> io::Result<()> {
    if let Some(old) = resolver.upstream(slot) {
        registry.deregister(&mut SourceFd(&old.as_raw_fd()))?;
    }
    if let Some(new) = &socket {
        registry.register(
            &mut SourceFd(&new.as_raw_fd()),
            Token(UPSTREAM_BASE + slot),
            Interest::READABLE,
        )?;
    }
    resolver.set_upstream(slot, socket);
    Ok(())
}

/// Renvoie `false` quand le TUN est fermé côté système (révocation du VPN).
fn drain_tun(
    tun: &mut File,
    buf: &mut [u8],
    out: &mut Vec<u8>,
    resolver: &mut Resolver,
    now: Instant,
    stats: &Stats,
) -> io::Result<bool> {
    loop {
        let n = match tun.read(buf) {
            Ok(0) => return Ok(false),
            Ok(n) => n,
            Err(e) if e.kind() == ErrorKind::WouldBlock => return Ok(true),
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        let Some(raw) = buf.get(..n) else {
            continue;
        };
        let parsed = ip::parse(raw);
        stats.record(&parsed, n);
        if let Ok(packet) = parsed
            && handle(&packet, resolver, now, stats, out)
        {
            write_tun(tun, out);
        }
    }
}

/// Seul le trafic destiné au résolveur local reçoit une réponse ; renvoie `true` si `out` est à écrire.
fn handle(
    packet: &ip::IpPacket<'_>,
    resolver: &mut Resolver,
    now: Instant,
    stats: &Stats,
    out: &mut Vec<u8>,
) -> bool {
    if packet.dst != IpAddr::V4(DNS_V4) && packet.dst != IpAddr::V6(DNS_V6) {
        return false;
    }
    match packet.protocol {
        ip::PROTO_UDP => {
            let Ok(datagram) = udp::parse(packet) else {
                return false;
            };
            if datagram.dst.port() != 53 {
                return false;
            }
            match resolver.handle_query(&datagram, now, stats) {
                Outcome::Reply(msg) => udp::build(datagram.dst, datagram.src, &msg, out).is_ok(),
                Outcome::Forwarded | Outcome::Dropped => false,
            }
        }
        // DoT (853) ou DNS/TCP : RST immédiat, Private DNS « automatique » se replie aussitôt sur UDP/53.
        ip::PROTO_TCP => tcp::parse(packet)
            .ok()
            .and_then(|segment| tcp::build_reset(&segment, out))
            .is_some_and(|built| built.is_ok()),
        _ => false,
    }
}

fn write_tun(tun: &mut File, packet: &[u8]) {
    // TUN saturé (WouldBlock) : la réponse est perdue, le client réémettra sa requête.
    let _ = tun.write(packet);
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use std::os::unix::net::UnixDatagram;

    const CLIENT: &str = "10.111.0.1:40000";

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    fn dns_query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
        let mut m = id.to_be_bytes().to_vec();
        m.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
        for label in name.split('.') {
            m.push(label.len() as u8);
            m.extend_from_slice(label.as_bytes());
        }
        m.push(0);
        m.extend_from_slice(&qtype.to_be_bytes());
        m.extend_from_slice(&[0, 1]);
        m
    }

    fn to_resolver(payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        udp::build(
            sa(CLIENT),
            SocketAddr::new(IpAddr::V4(DNS_V4), 53),
            payload,
            &mut out,
        )
        .unwrap();
        out
    }

    // Une paire de sockets datagramme reproduit la sémantique du TUN : un paquet par lecture.
    fn start(list: &str) -> (UnixDatagram, Engine) {
        let (app, engine_side) = UnixDatagram::pair().unwrap();
        engine_side.set_nonblocking(true).unwrap();
        app.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let engine =
            Engine::start(OwnedFd::from(engine_side), Blocklist::from_domains(list)).unwrap();
        (app, engine)
    }

    /// Charge utile UDP de la réponse écrite dans le TUN.
    fn reply(app: &UnixDatagram) -> Vec<u8> {
        let mut buf = [0u8; 2048];
        let n = app.recv(&mut buf).unwrap();
        let packet = ip::parse(&buf[..n]).unwrap();
        let datagram = udp::parse(&packet).unwrap();
        assert_eq!(datagram.src, SocketAddr::new(IpAddr::V4(DNS_V4), 53));
        assert_eq!(datagram.dst, sa(CLIENT));
        datagram.payload.to_vec()
    }

    fn assert_silent(app: &UnixDatagram) {
        app.set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        let mut buf = [0u8; 64];
        let err = app.recv(&mut buf).unwrap_err();
        assert!(matches!(
            err.kind(),
            ErrorKind::WouldBlock | ErrorKind::TimedOut
        ));
    }

    fn rcode(msg: &[u8]) -> u8 {
        msg[3] & 0x0f
    }

    fn wait_for(stats: &Stats, counter: Counter, expected: u64) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while stats.get(counter) < expected {
            assert!(
                Instant::now() < deadline,
                "{counter:?} = {}",
                stats.get(counter)
            );
            thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn answers_blocked_name_and_canary_with_nxdomain() {
        let (app, engine) = start("ads.example.net");

        app.send(&to_resolver(&dns_query(0x0101, "cdn.ads.example.net", 1)))
            .unwrap();
        let msg = reply(&app);
        assert_eq!(&msg[..2], &[0x01, 0x01]);
        assert_eq!(rcode(&msg), 3);

        app.send(&to_resolver(&dns_query(2, "use-application-dns.net", 1)))
            .unwrap();
        assert_eq!(rcode(&reply(&app)), 3);
        assert_eq!(engine.stats().get(Counter::DnsBlocked), 2);
        engine.stop().unwrap();
    }

    #[test]
    fn answers_https_record_with_nodata() {
        let (app, engine) = start("");
        app.send(&to_resolver(&dns_query(3, "www.example.org", 65)))
            .unwrap();
        let msg = reply(&app);
        assert_eq!(rcode(&msg), 0);
        assert_eq!(&msg[6..8], &[0, 0], "aucune réponse attendue");
        engine.stop().unwrap();
    }

    #[test]
    fn answers_servfail_without_upstream() {
        let (app, engine) = start("");
        app.send(&to_resolver(&dns_query(4, "example.org", 1)))
            .unwrap();
        assert_eq!(rcode(&reply(&app)), 2);
        assert_eq!(engine.stats().get(Counter::DnsUpstreamFailures), 1);
        engine.stop().unwrap();
    }

    #[test]
    fn forwards_allowed_query_and_relays_matching_answer_only() {
        let (app, engine) = start("ads.example.net");
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        upstream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let link = UdpSocket::bind("127.0.0.1:0").unwrap();
        link.connect(upstream.local_addr().unwrap()).unwrap();
        engine.set_upstream(0, Some(link)).unwrap();

        app.send(&to_resolver(&dns_query(0xbeef, "example.org", 1)))
            .unwrap();
        let mut buf = [0u8; 512];
        let (n, from) = upstream.recv_from(&mut buf).unwrap();
        let forwarded = buf[..n].to_vec();
        assert_eq!(&forwarded[2..], &dns_query(0xbeef, "example.org", 1)[2..]);

        // Réponse au bon identifiant mais pour une autre question : ignorée.
        let mut spoofed = dns_query(0, "evil.example", 1);
        spoofed[..2].copy_from_slice(&forwarded[..2]);
        spoofed[2] |= 0x80;
        upstream.send_to(&spoofed, from).unwrap();
        assert_silent(&app);

        let mut answer = forwarded.clone();
        answer[2] |= 0x80;
        upstream.send_to(&answer, from).unwrap();
        app.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let msg = reply(&app);
        assert_eq!(&msg[..2], &[0xbe, 0xef], "identifiant client restauré");
        assert_eq!(&msg[2..], &answer[2..]);
        engine.stop().unwrap();
    }

    #[test]
    fn resets_tcp_to_resolver() {
        let (app, engine) = start("");
        let mut tcp = vec![
            0x9c,
            0x40,
            0x03,
            0x55,
            0,
            0,
            0,
            7,
            0,
            0,
            0,
            0,
            0x50,
            tcp::SYN,
            0xff,
            0xff,
            0,
            0,
            0,
            0,
        ];
        let mut packet = Vec::new();
        // Somme TCP non vérifiée par le moteur : inutile de la calculer ici.
        ip::build(
            sa(CLIENT).ip(),
            IpAddr::V4(DNS_V4),
            ip::PROTO_TCP,
            &tcp,
            &mut packet,
        )
        .unwrap();
        tcp.clear();
        app.send(&packet).unwrap();

        let mut buf = [0u8; 128];
        let n = app.recv(&mut buf).unwrap();
        let segment = tcp::parse(&ip::parse(&buf[..n]).unwrap()).unwrap();
        assert_eq!(segment.flags, tcp::RST | tcp::ACK);
        assert_eq!(segment.ack, 8);
        engine.stop().unwrap();
    }

    #[test]
    fn drops_everything_else() {
        let (app, engine) = start("");
        let mut packet = Vec::new();
        udp::build(sa(CLIENT), sa("93.184.216.34:443"), &[0; 32], &mut packet).unwrap();
        app.send(&packet).unwrap();
        app.send(&[0x45, 0x00]).unwrap();
        wait_for(engine.stats(), Counter::Packets, 2);
        assert_eq!(engine.stats().get(Counter::Malformed), 1);
        assert_silent(&app);
        engine.stop().unwrap();
    }

    #[test]
    fn rejects_out_of_range_upstream_slot() {
        let (_app, engine) = start("");
        let err = engine.set_upstream(MAX_UPSTREAMS, None).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidInput);
        engine.stop().unwrap();
    }

    #[test]
    fn stops_promptly_while_idle() {
        let (_app, engine) = start("");
        let started = Instant::now();
        engine.stop().unwrap();
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn exits_when_tun_is_closed() {
        // Un pipe signale la fermeture par une lecture de 0 octet, comme le TUN révoqué.
        let (reader, writer) = std::io::pipe().unwrap();
        let engine = Engine::start(OwnedFd::from(reader), Blocklist::empty()).unwrap();
        drop(writer);
        let deadline = Instant::now() + Duration::from_secs(5);
        while !engine.thread.as_ref().unwrap().is_finished() {
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(5));
        }
        engine.stop().unwrap();
    }
}
