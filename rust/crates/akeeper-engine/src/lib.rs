//! Moteur aKeeper : résolveur DNS local filtrant, relais TCP et UDP protégés, neutralisation de l'évasion (spec §6).
//! Tout paquet sans verdict explicite est abandonné : rien ne ressort du tunnel par défaut (fail-closed).

mod blocklist;
mod dns;
mod events;
mod filter;
mod stats;
mod tcp_stack;
mod udp_nat;

pub use akeeper_proto::bundle::MAX_BUNDLE;
pub use blocklist::Blocklist;
pub use dns::MAX_UPSTREAMS;
pub use events::{Event, EventKind, EventLog};
pub use filter::{BundleRules, CategoryMask, Filter, Reason, RulesError};
pub use stats::{Counter, Stats};

use std::collections::HashSet;
use std::fs::File;
use std::io::{self, ErrorKind, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use akeeper_proto::{icmp, ip, tcp, udp};
use mio::unix::SourceFd;
use mio::{Events, Interest, Poll, Registry, Token, Waker};

use dns::{Outcome, Resolver};

use tcp_stack::TcpStack;
use udp_nat::UdpNat;

/// Adresses du résolveur local annoncées par `VpnService.Builder.addDnsServer` (spec §4).
pub const DNS_V4: Ipv4Addr = Ipv4Addr::new(10, 111, 0, 53);
pub const DNS_V6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0x6d73, 0, 0, 0, 0, 0, 0x53);

/// Services Android rendus au moteur ; appelés depuis le thread moteur, une fois par socket ou par nouveau flux.
pub trait Host: Send + Sync {
    /// Exclut un socket du tunnel (`VpnService.protect`) ; `false` si le système refuse.
    fn protect(&self, fd: RawFd) -> bool;
    /// UID de l'app propriétaire de la connexion (`ConnectivityManager.getConnectionOwnerUid`), `None` si inconnu.
    fn owner_uid(&self, protocol: u8, local: SocketAddr, remote: SocketAddr) -> Option<u32>;
}

pub type SharedHost = Arc<dyn Host>;

pub struct Config {
    pub filter: Filter,
    pub host: SharedHost,
}

const DNS_PORT: u16 = 53;
const DOT_PORT: u16 = 853;
const HTTPS_PORT: u16 = 443;

const TUN: Token = Token(0);
const WAKE: Token = Token(1);
const UPSTREAM_BASE: usize = 2;
// Un datagramme TUN ne dépasse jamais 65 535 octets (longueur IP sur 16 bits).
const READ_BUFFER: usize = 65_535;
const EXPIRY_TICK: Duration = Duration::from_secs(1);

enum Command {
    Stop,
    SetUpstream(usize, Option<UdpSocket>),
    SetBlockedUids(HashSet<u32>),
    SetFilter(Arc<Filter>),
    /// `Some` : pause des blocages pour cette durée ; `None` : reprise immédiate.
    SetPause(Option<Duration>),
}

/// Une pause ne dure jamais plus : l'appelant ne peut pas laisser la protection suspendue indéfiniment.
pub const MAX_PAUSE: Duration = Duration::from_secs(60 * 60);

pub struct Engine {
    commands: Sender<Command>,
    waker: Arc<Waker>,
    stats: Arc<Stats>,
    pause: Arc<AtomicBool>,
    events: Arc<EventLog>,
    thread: Option<JoinHandle<io::Result<()>>>,
}

impl Engine {
    /// `tun` doit être en mode non bloquant : epoll est déclenché sur front, la boucle lit jusqu'à `WouldBlock`.
    pub fn start(tun: OwnedFd, config: Config) -> io::Result<Self> {
        let poll = Poll::new()?;
        let waker = Arc::new(Waker::new(poll.registry(), WAKE)?);
        poll.registry()
            .register(&mut SourceFd(&tun.as_raw_fd()), TUN, Interest::READABLE)?;

        let (commands, inbox) = mpsc::channel();
        let stats = Arc::new(Stats::default());
        let pause = Arc::new(AtomicBool::new(false));
        let events = Arc::new(EventLog::default());
        let mut filter = config.filter;
        filter.share_pause(Arc::clone(&pause));
        let thread = thread::Builder::new()
            .name("akeeper-engine".into())
            .spawn({
                let stats = Arc::clone(&stats);
                let pause = Arc::clone(&pause);
                let events = Arc::clone(&events);
                move || {
                    let filter = Arc::new(filter);
                    let flows = Flows {
                        pause,
                        paused_until: None,
                        resolver: Resolver::new(
                            Arc::clone(&filter),
                            Arc::clone(&config.host),
                            Arc::clone(&events),
                        ),
                        nat: UdpNat::new(Arc::clone(&config.host), Arc::clone(&events)),
                        tcp: TcpStack::new(config.host, random_seed(), filter, events),
                        blocked: HashSet::new(),
                    };
                    run(poll, File::from(tun), flows, &inbox, &stats)
                }
            })?;

        Ok(Self {
            commands,
            waker,
            stats,
            pause,
            events,
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

    /// Remplace l'ensemble des apps privées d'Internet ; leurs flux ouverts sont coupés aussitôt.
    pub fn set_blocked_uids(&self, uids: impl IntoIterator<Item = u32>) -> io::Result<()> {
        self.send(Command::SetBlockedUids(uids.into_iter().collect()))
    }

    /// Remplace les règles d'un bloc. Le filtre est construit par l'appelant, hors du thread moteur ; les flux
    /// encore en inspection SNI sont jugés avec les nouvelles règles.
    pub fn set_filter(&self, mut filter: Filter) -> io::Result<()> {
        // Une pause en cours survit au remplacement des règles.
        filter.share_pause(Arc::clone(&self.pause));
        self.send(Command::SetFilter(Arc::new(filter)))
    }

    /// Suspend les blocages (noms, SNI, adresses DoH) pour `duration`, plafonnée à `MAX_PAUSE`, puis les rétablit
    /// d'elle-même : le moteur n'attend aucun appel pour reprendre. Le pare-feu par app et la neutralisation de
    /// l'évasion (NODATA type 65, canari DoH, QUIC) restent actifs.
    pub fn pause(&self, duration: Duration) -> io::Result<()> {
        self.send(Command::SetPause(Some(duration.min(MAX_PAUSE))))
    }

    pub fn resume(&self) -> io::Result<()> {
        self.send(Command::SetPause(None))
    }

    /// Active ou coupe le journal d'activité ; coupé, il se vide et les appels Binder qu'il impose cessent.
    pub fn set_logging(&self, enabled: bool) {
        self.events.set_enabled(enabled);
    }

    /// Événements accumulés depuis le dernier appel, au format de `events::encode`.
    pub fn drain_events(&self) -> Vec<u8> {
        events::encode(&self.events.drain())
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

/// État réseau détenu par le thread moteur seul : aucun verrou nécessaire.
struct Flows {
    /// Même drapeau que dans le filtre ; seul le thread moteur l'écrit.
    pause: Arc<AtomicBool>,
    paused_until: Option<Instant>,
    resolver: Resolver,
    nat: UdpNat,
    tcp: TcpStack,
    /// UID des apps privées d'Internet (pare-feu par app).
    blocked: HashSet<u32>,
}

fn random_seed() -> u64 {
    let mut seed = [0u8; 8];
    // Graine non cryptographique (numéros de port et de séquence de smoltcp) : l'horloge suffit en repli.
    if getrandom::fill(&mut seed).is_err() {
        return Instant::now().elapsed().as_nanos() as u64 ^ 0x9e37_79b9_7f4a_7c15;
    }
    u64::from_le_bytes(seed)
}

fn run(
    mut poll: Poll,
    mut tun: File,
    mut flows: Flows,
    inbox: &Receiver<Command>,
    stats: &Stats,
) -> io::Result<()> {
    let mut events = Events::with_capacity(64);
    let mut buf = vec![0u8; READ_BUFFER];
    let mut out = Vec::with_capacity(1500);
    loop {
        let tick = (flows.resolver.has_pending() || flows.nat.has_flows() || flows.tcp.has_flows())
            .then_some(EXPIRY_TICK);
        let timeout = [
            tick,
            flows.tcp.poll_delay(),
            flows
                .paused_until
                .map(|t| t.saturating_duration_since(Instant::now())),
        ]
        .into_iter()
        .flatten()
        .min();
        match poll.poll(&mut events, timeout) {
            Ok(()) => {}
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
        let now = Instant::now();
        if flows.paused_until.is_some_and(|until| now >= until) {
            flows.paused_until = None;
            flows.pause.store(false, Ordering::Relaxed);
        }
        flows.resolver.expire(now, stats);
        flows.nat.expire(poll.registry(), now);
        for event in &events {
            match event.token() {
                WAKE => {
                    while let Ok(command) = inbox.try_recv() {
                        match command {
                            Command::Stop => return Ok(()),
                            Command::SetUpstream(slot, socket) => replace_upstream(
                                poll.registry(),
                                &mut flows.resolver,
                                slot,
                                socket,
                            )?,
                            Command::SetBlockedUids(uids) => {
                                flows.nat.apply_policy(poll.registry(), &uids);
                                flows.tcp.apply_policy(&uids);
                                flows.blocked = uids;
                            }
                            Command::SetFilter(filter) => {
                                flows.resolver.set_filter(Arc::clone(&filter));
                                flows.tcp.set_filter(filter);
                            }
                            Command::SetPause(duration) => {
                                flows.paused_until = duration.map(|d| Instant::now() + d);
                                flows.pause.store(duration.is_some(), Ordering::Relaxed);
                            }
                        }
                    }
                }
                TUN => {
                    if !drain_tun(
                        &mut tun,
                        poll.registry(),
                        &mut buf,
                        &mut out,
                        &mut flows,
                        now,
                        stats,
                    )? {
                        return Ok(());
                    }
                }
                Token(t) if t >= tcp_stack::TOKEN_BASE => {
                    flows
                        .tcp
                        .upstream_event(t, event.is_readable(), event.is_writable());
                }
                Token(t) if t >= udp_nat::TOKEN_BASE => {
                    flows
                        .nat
                        .drain(t, &mut buf, now, |remote, client, payload| {
                            if udp::build(remote, client, payload, &mut out).is_ok() {
                                write_tun(&mut tun, &out);
                            }
                        });
                }
                Token(t) => {
                    let slot = t - UPSTREAM_BASE;
                    flows
                        .resolver
                        .drain_upstream(slot, &mut buf, |server, client, msg| {
                            if udp::build(server, client, msg, &mut out).is_ok() {
                                write_tun(&mut tun, &out);
                            }
                        })?;
                }
            }
        }
        flows
            .tcp
            .run(poll.registry(), stats, |packet| write_tun(&mut tun, packet));
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
    registry: &Registry,
    buf: &mut [u8],
    out: &mut Vec<u8>,
    flows: &mut Flows,
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
            && handle(raw, &packet, registry, flows, now, stats, out)
        {
            write_tun(tun, out);
        }
    }
}

fn is_resolver(addr: IpAddr) -> bool {
    addr == IpAddr::V4(DNS_V4) || addr == IpAddr::V6(DNS_V6)
}

/// Verdict d'un paquet sortant (spec §6) ; renvoie `true` si `out` contient une réponse à écrire dans le TUN.
fn handle(
    raw: &[u8],
    packet: &ip::IpPacket<'_>,
    registry: &Registry,
    flows: &mut Flows,
    now: Instant,
    stats: &Stats,
    out: &mut Vec<u8>,
) -> bool {
    match packet.protocol {
        ip::PROTO_UDP => {
            let Ok(datagram) = udp::parse(packet) else {
                return false;
            };
            match datagram.dst.port() {
                // Tout DNS en clair, quelle que soit sa destination, est servi par le résolveur local (DNAT) :
                // un DNS codé en dur dans une app ne contourne pas le filtrage. La réponse garde l'IP visée.
                DNS_PORT => match flows.resolver.handle_query(&datagram, now, stats) {
                    Outcome::Reply(msg) => {
                        udp::build(datagram.dst, datagram.src, &msg, out).is_ok()
                    }
                    Outcome::Forwarded | Outcome::Dropped => false,
                },
                _ if is_resolver(datagram.dst.ip()) => false,
                // QUIC (443) et DNS-over-QUIC (853) : refus immédiat, le client se replie sur TCP où le SNI est lisible.
                HTTPS_PORT | DOT_PORT => {
                    stats.add(Counter::QuicBlocked, 1);
                    icmp::build_port_unreachable(raw, packet, out).is_ok()
                }
                _ => match flows
                    .nat
                    .send(registry, &datagram, &flows.blocked, now, stats)
                {
                    // App privée d'Internet : refus immédiat plutôt qu'un délai d'expiration côté app.
                    udp_nat::Sent::Blocked => {
                        icmp::build_port_unreachable(raw, packet, out).is_ok()
                    }
                    udp_nat::Sent::Relayed | udp_nat::Sent::Failed => false,
                },
            }
        }
        ip::PROTO_TCP => {
            let Ok(segment) = tcp::parse(packet) else {
                return false;
            };
            // DNS/TCP ou DoT vers le résolveur, et DoT vers tout autre serveur : RST. Private DNS « automatique »
            // se replie aussitôt sur UDP/53 ; en mode strict la résolution échoue, ce qui reste visible (alerte J4).
            if segment.dst.port() == DOT_PORT && !is_resolver(segment.dst.ip()) {
                // DoT vers un serveur tiers : signe d'un DNS privé en mode strict (alerte côté app).
                stats.add(Counter::DotBlocked, 1);
            }
            if is_resolver(segment.dst.ip()) || segment.dst.port() == DOT_PORT {
                return tcp::build_reset(&segment, out).is_some_and(|built| built.is_ok());
            }
            if !tcp_stack::is_tunnel_address(segment.dst.ip()) {
                flows
                    .tcp
                    .ingest(registry, raw, &segment, &flows.blocked, stats);
            }
            false
        }
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

    struct TestHost {
        protect: bool,
        uid: Option<u32>,
    }

    impl Host for TestHost {
        fn protect(&self, _: RawFd) -> bool {
            self.protect
        }

        fn owner_uid(&self, _: u8, _: SocketAddr, _: SocketAddr) -> Option<u32> {
            self.uid
        }
    }

    const APP_UID: u32 = 10_123;

    fn config(list: &str, protect: bool) -> Config {
        Config {
            filter: Filter::new(Blocklist::from_domains(list), None),
            host: Arc::new(TestHost {
                protect,
                uid: Some(APP_UID),
            }),
        }
    }

    // Une paire de sockets datagramme reproduit la sémantique du TUN : un paquet par lecture.
    fn start(list: &str) -> (UnixDatagram, Engine) {
        let (app, engine_side) = UnixDatagram::pair().unwrap();
        engine_side.set_nonblocking(true).unwrap();
        app.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let engine = Engine::start(OwnedFd::from(engine_side), config(list, true)).unwrap();
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
    fn journals_dns_verdicts_only_while_logging_is_on() {
        let (app, engine) = start("ads.example.net");
        app.send(&to_resolver(&dns_query(5, "ads.example.net", 1)))
            .unwrap();
        reply(&app);
        assert!(engine.drain_events().is_empty(), "journal coupé par défaut");

        engine.set_logging(true);
        for id in [6, 7] {
            app.send(&to_resolver(&dns_query(id, "ads.example.net", 1)))
                .unwrap();
            reply(&app);
        }
        app.send(&to_resolver(&dns_query(8, "example.org", 1)))
            .unwrap();
        reply(&app);

        let bytes = engine.drain_events();
        // Deux requêtes bloquées regroupées + une autorisée .
        let mut names = Vec::new();
        let mut rest = &bytes[..];
        while !rest.is_empty() {
            let count = u32::from_be_bytes(rest[16..20].try_into().unwrap());
            let len = usize::from(u16::from_be_bytes(rest[20..22].try_into().unwrap()));
            names.push((
                String::from_utf8(rest[22..22 + len].to_vec()).unwrap(),
                rest[9],
                count,
            ));
            rest = &rest[22 + len..];
        }
        assert_eq!(
            names,
            vec![
                ("ads.example.net".into(), 1, 2),
                ("example.org".into(), 0, 1)
            ]
        );
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
    fn drops_traffic_without_verdict() {
        let (app, engine) = start("");
        // ICMP echo : ni relayé ni répondu, jamais de faux « ping » au nom d'un hôte distant.
        let mut packet = Vec::new();
        let echo = [8, 0, 0xf7, 0xfe, 0, 1, 0, 0];
        ip::build(
            sa(CLIENT).ip(),
            "93.184.216.34".parse().unwrap(),
            ip::PROTO_ICMP,
            &echo,
            &mut packet,
        )
        .unwrap();
        app.send(&packet).unwrap();
        app.send(&[0x45, 0x00]).unwrap();
        wait_for(engine.stats(), Counter::Packets, 2);
        assert_eq!(engine.stats().get(Counter::Malformed), 1);
        assert_silent(&app);
        engine.stop().unwrap();
    }

    #[test]
    fn answers_dns_sent_to_any_server_locally_from_that_server() {
        let (app, engine) = start("ads.example.net");
        let mut packet = Vec::new();
        udp::build(
            sa(CLIENT),
            sa("8.8.8.8:53"),
            &dns_query(9, "ads.example.net", 1),
            &mut packet,
        )
        .unwrap();
        app.send(&packet).unwrap();

        let mut buf = [0u8; 512];
        let n = app.recv(&mut buf).unwrap();
        let reply = ip::parse(&buf[..n]).unwrap();
        let datagram = udp::parse(&reply).unwrap();
        assert_eq!(
            datagram.src,
            sa("8.8.8.8:53"),
            "le client doit croire parler au serveur visé"
        );
        assert_eq!(rcode(datagram.payload), 3);
        engine.stop().unwrap();
    }

    #[test]
    fn refuses_quic_with_port_unreachable() {
        let (app, engine) = start("");
        let mut packet = Vec::new();
        udp::build(
            sa(CLIENT),
            sa("142.250.0.1:443"),
            &[0xc3; 1200],
            &mut packet,
        )
        .unwrap();
        app.send(&packet).unwrap();

        let mut buf = [0u8; 2048];
        let n = app.recv(&mut buf).unwrap();
        let reply = ip::parse(&buf[..n]).unwrap();
        assert_eq!(reply.protocol, ip::PROTO_ICMP);
        assert_eq!(&reply.payload[..2], &[3, 3]);
        assert_eq!(engine.stats().get(Counter::QuicBlocked), 1);
        engine.stop().unwrap();
    }

    #[test]
    fn resets_dot_to_third_party_server() {
        let (app, engine) = start("");
        let tcp = [
            0x9c,
            0x40,
            0x03,
            0x55,
            0,
            0,
            0,
            1,
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
        ip::build(
            sa(CLIENT).ip(),
            "1.1.1.1".parse().unwrap(),
            ip::PROTO_TCP,
            &tcp,
            &mut packet,
        )
        .unwrap();
        app.send(&packet).unwrap();

        let mut buf = [0u8; 128];
        let n = app.recv(&mut buf).unwrap();
        let segment = tcp::parse(&ip::parse(&buf[..n]).unwrap()).unwrap();
        assert_eq!(segment.flags, tcp::RST | tcp::ACK);
        assert_eq!(engine.stats().get(Counter::DotBlocked), 1);
        engine.stop().unwrap();
    }

    #[test]
    fn relays_udp_through_protected_socket_both_ways() {
        let (app, engine) = start("");
        let remote = UdpSocket::bind("127.0.0.1:0").unwrap();
        remote
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut packet = Vec::new();
        udp::build(
            sa(CLIENT),
            remote.local_addr().unwrap(),
            b"ping",
            &mut packet,
        )
        .unwrap();
        app.send(&packet).unwrap();

        let mut buf = [0u8; 64];
        let (n, from) = remote.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"ping");
        remote.send_to(b"pong", from).unwrap();

        let mut buf = [0u8; 128];
        let n = app.recv(&mut buf).unwrap();
        let reply = ip::parse(&buf[..n]).unwrap();
        let datagram = udp::parse(&reply).unwrap();
        assert_eq!(datagram.src, remote.local_addr().unwrap());
        assert_eq!(datagram.dst, sa(CLIENT));
        assert_eq!(datagram.payload, b"pong");
        engine.stop().unwrap();
    }

    #[test]
    fn never_sends_through_an_unprotected_socket() {
        let (app, engine_side) = UnixDatagram::pair().unwrap();
        engine_side.set_nonblocking(true).unwrap();
        let engine = Engine::start(OwnedFd::from(engine_side), config("", false)).unwrap();
        let remote = UdpSocket::bind("127.0.0.1:0").unwrap();
        remote
            .set_read_timeout(Some(Duration::from_millis(300)))
            .unwrap();
        let mut packet = Vec::new();
        udp::build(
            sa(CLIENT),
            remote.local_addr().unwrap(),
            b"leak?",
            &mut packet,
        )
        .unwrap();
        app.send(&packet).unwrap();

        wait_for(engine.stats(), Counter::UdpNatFailures, 1);
        let mut buf = [0u8; 16];
        assert!(
            remote.recv_from(&mut buf).is_err(),
            "aucun octet ne doit sortir sans protect()"
        );
        engine.stop().unwrap();
    }

    fn tcp_packet(
        src: SocketAddr,
        dst: SocketAddr,
        seq: u32,
        ack: u32,
        flags: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut out = Vec::new();
        let header = tcp::Header {
            src,
            dst,
            seq,
            ack,
            flags,
            window: 65_535,
        };
        tcp::build(&header, payload, &mut out).unwrap();
        out
    }

    /// Prochain segment TCP renvoyé à l'app, avec sa charge utile.
    fn next_segment(app: &UnixDatagram) -> (tcp::Segment, Vec<u8>) {
        let mut buf = [0u8; 4096];
        loop {
            let n = app.recv(&mut buf).unwrap();
            let packet = ip::parse(&buf[..n]).unwrap();
            if packet.protocol != ip::PROTO_TCP {
                continue;
            }
            let segment = tcp::parse(&packet).unwrap();
            let offset = usize::from(packet.payload[12] >> 4) * 4;
            return (segment, packet.payload[offset..].to_vec());
        }
    }

    #[test]
    fn relays_tcp_connection_through_userspace_stack() {
        let (app, engine) = start("");
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let remote = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            let mut request = [0u8; 3];
            std::io::Read::read_exact(&mut conn, &mut request).unwrap();
            std::io::Write::write_all(&mut conn, b"HELLO").unwrap();
            request
        });
        let client = sa("10.111.0.1:40001");

        app.send(&tcp_packet(client, remote, 1000, 0, tcp::SYN, &[]))
            .unwrap();
        let (syn_ack, _) = next_segment(&app);
        assert_eq!(syn_ack.flags & (tcp::SYN | tcp::ACK), tcp::SYN | tcp::ACK);
        assert_eq!(syn_ack.src, remote, "smoltcp répond au nom du serveur visé");
        assert_eq!(syn_ack.ack, 1001);

        let server_seq = syn_ack.seq.wrapping_add(1);
        app.send(&tcp_packet(
            client,
            remote,
            1001,
            server_seq,
            tcp::ACK | tcp::PSH,
            b"GET",
        ))
        .unwrap();

        let mut received = Vec::new();
        let mut ack = server_seq;
        while received.len() < 5 {
            let (segment, payload) = next_segment(&app);
            assert_eq!(segment.flags & tcp::RST, 0, "connexion réinitialisée");
            if !payload.is_empty() {
                received.extend_from_slice(&payload);
                ack = segment.seq.wrapping_add(payload.len() as u32);
                app.send(&tcp_packet(client, remote, 1004, ack, tcp::ACK, &[]))
                    .unwrap();
            }
        }
        assert_eq!(&received, b"HELLO");
        assert_eq!(&server.join().unwrap(), b"GET");
        assert_eq!(engine.stats().get(Counter::TcpFlows), 1);
        let _ = ack;
        engine.stop().unwrap();
    }

    #[test]
    fn streams_bulk_download_with_backpressure() {
        const SIZE: usize = 2 * 1024 * 1024;
        let (app, engine) = start("");
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let remote = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            let body: Vec<u8> = (0..SIZE).map(|i| (i % 251) as u8).collect();
            std::io::Write::write_all(&mut conn, &body).unwrap();
        });
        let client = sa("10.111.0.1:40010");
        app.send(&tcp_packet(client, remote, 1, 0, tcp::SYN, &[]))
            .unwrap();
        let (syn_ack, _) = next_segment(&app);
        let mut expected = syn_ack.seq.wrapping_add(1);
        app.send(&tcp_packet(client, remote, 2, expected, tcp::ACK, &[]))
            .unwrap();

        let mut received = Vec::with_capacity(SIZE);
        let mut fin = false;
        while !fin {
            let (segment, payload) = next_segment(&app);
            assert_eq!(segment.flags & tcp::RST, 0);
            // Client minimal : n'accepte que les segments dans l'ordre, ACK cumulatif à chaque segment.
            if segment.seq == expected {
                received.extend_from_slice(&payload);
                expected = expected.wrapping_add(payload.len() as u32);
                if segment.flags & tcp::FIN != 0 {
                    expected = expected.wrapping_add(1);
                    fin = true;
                }
            }
            app.send(&tcp_packet(client, remote, 2, expected, tcp::ACK, &[]))
                .unwrap();
        }
        server.join().unwrap();
        assert_eq!(received.len(), SIZE);
        assert!(
            received
                .iter()
                .enumerate()
                .all(|(i, &b)| b == (i % 251) as u8)
        );
        engine.stop().unwrap();
    }

    #[test]
    fn resets_app_when_server_refuses() {
        let (app, engine) = start("");
        let closed = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        let client = sa("10.111.0.1:40002");
        app.send(&tcp_packet(client, closed, 5000, 0, tcp::SYN, &[]))
            .unwrap();
        loop {
            let (segment, _) = next_segment(&app);
            if segment.flags & tcp::RST != 0 {
                break;
            }
        }
        engine.stop().unwrap();
    }

    #[test]
    fn refuses_tcp_when_protect_fails() {
        let (app, engine_side) = UnixDatagram::pair().unwrap();
        engine_side.set_nonblocking(true).unwrap();
        app.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let engine = Engine::start(OwnedFd::from(engine_side), config("", false)).unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let client = sa("10.111.0.1:40003");
        app.send(&tcp_packet(
            client,
            listener.local_addr().unwrap(),
            1,
            0,
            tcp::SYN,
            &[],
        ))
        .unwrap();

        let (segment, _) = next_segment(&app);
        assert_ne!(segment.flags & tcp::RST, 0);
        assert_eq!(engine.stats().get(Counter::TcpFailures), 1);
        assert!(
            listener.accept().is_err(),
            "aucune connexion amont sans protect()"
        );
        engine.stop().unwrap();
    }

    #[test]
    fn refuses_connections_of_a_blocked_app() {
        let (app, engine) = start("");
        engine.set_blocked_uids([APP_UID]).unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let client = sa("10.111.0.1:40020");
        app.send(&tcp_packet(
            client,
            listener.local_addr().unwrap(),
            1,
            0,
            tcp::SYN,
            &[],
        ))
        .unwrap();
        let (segment, _) = next_segment(&app);
        assert_ne!(segment.flags & tcp::RST, 0);
        assert!(
            listener.accept().is_err(),
            "aucune connexion amont pour une app bloquée"
        );

        let remote = UdpSocket::bind("127.0.0.1:0").unwrap();
        remote
            .set_read_timeout(Some(Duration::from_millis(300)))
            .unwrap();
        let mut packet = Vec::new();
        udp::build(sa(CLIENT), remote.local_addr().unwrap(), b"x", &mut packet).unwrap();
        app.send(&packet).unwrap();
        let mut buf = [0u8; 256];
        let n = app.recv(&mut buf).unwrap();
        assert_eq!(ip::parse(&buf[..n]).unwrap().protocol, ip::PROTO_ICMP);
        assert!(remote.recv_from(&mut buf).is_err());
        assert_eq!(engine.stats().get(Counter::AppBlocked), 2);
        engine.stop().unwrap();
    }

    #[test]
    fn cuts_open_connection_when_app_gets_blocked() {
        let (app, engine) = start("");
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let remote = listener.local_addr().unwrap();
        let server = thread::spawn(move || listener.accept().unwrap());
        let client = sa("10.111.0.1:40021");
        app.send(&tcp_packet(client, remote, 1, 0, tcp::SYN, &[]))
            .unwrap();
        let (syn_ack, _) = next_segment(&app);
        app.send(&tcp_packet(
            client,
            remote,
            2,
            syn_ack.seq.wrapping_add(1),
            tcp::ACK,
            &[],
        ))
        .unwrap();
        let _conn = server.join().unwrap();

        engine.set_blocked_uids([APP_UID]).unwrap();
        loop {
            let (segment, _) = next_segment(&app);
            if segment.flags & tcp::RST != 0 {
                break;
            }
        }
        engine.stop().unwrap();
    }

    /// ClientHello minimal portant `host` en SNI.
    fn client_hello(host: &str) -> Vec<u8> {
        let mut sni = vec![0];
        sni.extend_from_slice(&(host.len() as u16).to_be_bytes());
        sni.extend_from_slice(host.as_bytes());
        let mut ext = vec![0, 0];
        ext.extend_from_slice(&((sni.len() + 2) as u16).to_be_bytes());
        ext.extend_from_slice(&(sni.len() as u16).to_be_bytes());
        ext.extend_from_slice(&sni);
        let mut hello = vec![3, 3];
        hello.extend_from_slice(&[7; 32]);
        hello.extend_from_slice(&[0, 0, 2, 0x13, 1, 1, 0]);
        hello.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        hello.extend_from_slice(&ext);
        let mut handshake = vec![1];
        handshake.extend_from_slice(&(hello.len() as u32).to_be_bytes()[1..]);
        handshake.extend_from_slice(&hello);
        let mut record = vec![22, 3, 1];
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    /// Établit une connexion TCP vers un serveur local et envoie `payload` ; renvoie ce que le serveur a reçu
    /// et si l'app a été réinitialisée.
    fn send_through_tcp(list: &str, port: u16, payload: &[u8]) -> (Vec<u8>, bool, Engine) {
        let (app, engine) = start(list);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let remote = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            conn.set_read_timeout(Some(Duration::from_millis(500)))
                .unwrap();
            let mut got = Vec::new();
            let _ = std::io::Read::read_to_end(&mut conn, &mut got);
            got
        });
        let client = SocketAddr::new(sa(CLIENT).ip(), port);
        app.send(&tcp_packet(client, remote, 1, 0, tcp::SYN, &[]))
            .unwrap();
        let (syn_ack, _) = next_segment(&app);
        let server_seq = syn_ack.seq.wrapping_add(1);
        app.send(&tcp_packet(
            client,
            remote,
            2,
            server_seq,
            tcp::ACK | tcp::PSH,
            payload,
        ))
        .unwrap();
        let mut reset = false;
        app.set_read_timeout(Some(Duration::from_millis(700)))
            .unwrap();
        let mut buf = [0u8; 2048];
        while let Ok(n) = app.recv(&mut buf) {
            if let Ok(packet) = ip::parse(&buf[..n])
                && let Ok(segment) = tcp::parse(&packet)
                && segment.flags & tcp::RST != 0
            {
                reset = true;
                break;
            }
        }
        (server.join().unwrap(), reset, engine)
    }

    #[test]
    fn cuts_tls_to_blocked_sni_before_any_byte_reaches_the_server() {
        let (received, reset, engine) = send_through_tcp(
            "tracker.example",
            40030,
            &client_hello("cdn.tracker.example"),
        );
        assert!(reset, "l'app doit recevoir un RST");
        assert!(
            received.is_empty(),
            "aucun octet du ClientHello ne doit sortir"
        );
        assert_eq!(engine.stats().get(Counter::SniBlocked), 1);
        engine.stop().unwrap();
    }

    #[test]
    fn cuts_tls_to_known_doh_endpoint() {
        let (received, reset, engine) = send_through_tcp("", 40031, &client_hello("dns.google"));
        assert!(reset && received.is_empty());
        engine.stop().unwrap();
    }

    #[test]
    fn relays_allowed_tls_and_plain_protocols_unchanged() {
        let hello = client_hello("www.example.org");
        let (received, reset, engine) = send_through_tcp("tracker.example", 40032, &hello);
        assert!(!reset);
        assert_eq!(received, hello);
        engine.stop().unwrap();

        let (received, reset, engine) =
            send_through_tcp("tracker.example", 40033, b"GET / HTTP/1.1\r\n\r\n");
        assert!(!reset);
        assert_eq!(received, b"GET / HTTP/1.1\r\n\r\n");
        engine.stop().unwrap();
    }

    #[test]
    fn answers_doh_hostname_with_nxdomain() {
        let (app, engine) = start("");
        app.send(&to_resolver(&dns_query(5, "dns.google", 1)))
            .unwrap();
        assert_eq!(rcode(&reply(&app)), 3);
        engine.stop().unwrap();
    }

    /// Code de réponse DNS du nom demandé, avec un identifiant neuf à chaque appel.
    fn dns_rcode(app: &UnixDatagram, name: &str) -> u8 {
        static NEXT_ID: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(100);
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        app.send(&to_resolver(&dns_query(id, name, 1))).unwrap();
        rcode(&reply(app))
    }

    /// Les commandes et les paquets arrivent par deux sources distinctes : l'ordre n'est pas garanti.
    fn eventually(app: &UnixDatagram, name: &str, expected: u8) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while dns_rcode(app, name) != expected {
            assert!(
                Instant::now() < deadline,
                "rcode {expected} attendu pour {name}"
            );
            thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn a_pause_lets_blocked_names_through_until_resumed() {
        let (app, engine) = start("ads.example.net");
        assert_eq!(dns_rcode(&app, "ads.example.net"), 3);

        engine.pause(Duration::from_secs(600)).unwrap();
        // Sans résolveur amont, un nom autorisé reçoit SERVFAIL : le blocage (NXDOMAIN) est bien levé.
        eventually(&app, "ads.example.net", 2);

        engine.resume().unwrap();
        eventually(&app, "ads.example.net", 3);
        engine.stop().unwrap();
    }

    #[test]
    fn a_pause_ends_by_itself() {
        let (app, engine) = start("ads.example.net");
        engine.pause(Duration::from_millis(400)).unwrap();
        eventually(&app, "ads.example.net", 2);
        eventually(&app, "ads.example.net", 3);
        engine.stop().unwrap();
    }

    #[test]
    fn a_pause_survives_a_rules_replacement_and_keeps_the_evasion_defences() {
        let (app, engine) = start("ads.example.net");
        engine.pause(Duration::MAX).unwrap();
        eventually(&app, "ads.example.net", 2);

        engine
            .set_filter(Filter::new(Blocklist::from_domains("other.example"), None))
            .unwrap();
        // Le canari DoH reste refusé pendant la pause ; l'ancien nom reste autorisé.
        eventually(&app, "use-application-dns.net", 3);
        // Le nouveau filtre bloque `other.example`, mais la pause en cours l'emporte : à aucun moment NXDOMAIN.
        for _ in 0..20 {
            assert_eq!(dns_rcode(&app, "other.example"), 2);
            thread::sleep(Duration::from_millis(10));
        }
        engine.stop().unwrap();
    }

    fn start_with_bundle(bundle: &[u8]) -> (UnixDatagram, Engine) {
        let (app, engine_side) = UnixDatagram::pair().unwrap();
        engine_side.set_nonblocking(true).unwrap();
        app.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut config = config("", true);
        config.filter = Filter::new(
            Blocklist::empty(),
            Some(BundleRules::parse(bundle, CategoryMask::ALL).unwrap()),
        );
        let engine = Engine::start(OwnedFd::from(engine_side), config).unwrap();
        (app, engine)
    }

    #[test]
    fn resets_https_to_signed_doh_address_without_opening_upstream() {
        let doh = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let (app, engine) = start_with_bundle(&filter::tests::bundle_bytes("", None, &[(32, doh)]));
        let client = sa("10.111.0.1:40010");
        app.send(&tcp_packet(
            client,
            SocketAddr::new(doh, HTTPS_PORT),
            9000,
            0,
            tcp::SYN,
            &[],
        ))
        .unwrap();
        let (segment, _) = next_segment(&app);
        assert_ne!(segment.flags & tcp::RST, 0);
        assert_eq!(engine.stats().get(Counter::IpBlocked), 1);
        assert_eq!(engine.stats().get(Counter::TcpFlows), 0);
        engine.stop().unwrap();
    }

    #[test]
    fn applies_bundle_categories_and_replaces_rules_live() {
        let (app, engine) = start("");
        app.send(&to_resolver(&dns_query(6, "a.tracker.example", 1)))
            .unwrap();
        assert_eq!(
            rcode(&reply(&app)),
            2,
            "pas encore bloqué : SERVFAIL faute d'amont"
        );

        let bundle = filter::tests::bundle_bytes("tracker.example", None, &[]);
        engine
            .set_filter(Filter::new(
                Blocklist::empty(),
                Some(BundleRules::parse(&bundle, CategoryMask::ALL).unwrap()),
            ))
            .unwrap();
        // La commande et le paquet arrivent par deux sources epoll distinctes : l'ordre n'est pas garanti.
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            app.send(&to_resolver(&dns_query(7, "a.tracker.example", 1)))
                .unwrap();
            if rcode(&reply(&app)) == 3 {
                break;
            }
            assert!(Instant::now() < deadline);
        }
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
        let engine = Engine::start(OwnedFd::from(reader), config("", true)).unwrap();
        drop(writer);
        let deadline = Instant::now() + Duration::from_secs(5);
        while !engine.thread.as_ref().unwrap().is_finished() {
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(5));
        }
        engine.stop().unwrap();
    }
}
