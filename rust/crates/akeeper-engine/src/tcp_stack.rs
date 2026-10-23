//! Terminaison TCP en espace utilisateur : chaque connexion d'une app vers Internet est acceptée par smoltcp
//! côté TUN et relayée par un socket système protégé. Aucun MITM : les octets passent tels quels.

use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{self, ErrorKind, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr};
use std::os::fd::AsRawFd;

use std::sync::Arc;

use akeeper_proto::tcp::{self, Segment};
use akeeper_proto::tls::{self, Sni, TlsError};
use mio::net::TcpStream;
use mio::{Interest, Registry, Token};
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp as smol;
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpCidr, IpListenEndpoint};
use socket2::{Domain, Protocol, Socket, Type};

use crate::filter::Filter;
use crate::stats::{Counter, Stats};
use crate::{HTTPS_PORT, SharedHost};

/// Jetons mio des sockets amont TCP ; ceux de l'UDP NAT restent en dessous.
pub(crate) const TOKEN_BASE: usize = 1 << 24;
// Borne mémoire : 512 flux × (rx + tx) 64 KiB = 64 MiB au pire.
const MAX_FLOWS: usize = 512;
const SOCKET_BUFFER: usize = 64 * 1024;
const CHUNK: usize = 16 * 1024;
const MTU: usize = 1500;

/// Périphérique smoltcp en mémoire : paquets lus du TUN en entrée, paquets à écrire dans le TUN en sortie.
#[derive(Default)]
struct Queue {
    rx: VecDeque<Vec<u8>>,
    tx: Vec<Vec<u8>>,
}

struct Rx(Vec<u8>);
struct Tx<'a>(&'a mut Vec<Vec<u8>>);

impl RxToken for Rx {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

impl TxToken for Tx<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut packet = vec![0u8; len];
        let result = f(&mut packet);
        self.0.push(packet);
        result
    }
}

impl Device for Queue {
    type RxToken<'a> = Rx;
    type TxToken<'a> = Tx<'a>;

    fn receive(&mut self, _: SmolInstant) -> Option<(Rx, Tx<'_>)> {
        let packet = self.rx.pop_front()?;
        Some((Rx(packet), Tx(&mut self.tx)))
    }

    fn transmit(&mut self, _: SmolInstant) -> Option<Tx<'_>> {
        Some(Tx(&mut self.tx))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = MTU;
        caps
    }
}

struct Flow {
    handle: SocketHandle,
    /// Verdict SNI rendu : tant que faux, aucun octet de l'app ne part vers le serveur.
    inspected: bool,
    uid: Option<u32>,
    upstream: TcpStream,
    client: SocketAddr,
    remote: SocketAddr,
    connected: bool,
    readable: bool,
    writable: bool,
    to_upstream: Vec<u8>,
    to_client: Vec<u8>,
    upstream_eof: bool,
    upstream_shut: bool,
    failed: bool,
}

pub(crate) struct TcpStack {
    host: SharedHost,
    filter: Arc<Filter>,
    iface: Interface,
    device: Queue,
    sockets: SocketSet<'static>,
    flows: HashMap<usize, Flow>,
    by_endpoints: HashMap<(SocketAddr, SocketAddr), usize>,
    next_token: usize,
    scratch: Vec<u8>,
}

impl TcpStack {
    pub(crate) fn new(host: SharedHost, seed: u64, filter: Arc<Filter>) -> Self {
        let mut device = Queue::default();
        let mut config = Config::new(HardwareAddress::Ip);
        config.random_seed = seed;
        let mut iface = Interface::new(config, &mut device, SmolInstant::now());
        // Toute IP de destination est acceptée : smoltcp répond au nom du serveur visé.
        iface.set_any_ip(true);
        iface.update_ip_addrs(|addrs| {
            // Sous-réseaux du TUN : les réponses vers 10.111.0.1 et fd00:6d73::1 sont « sur le lien ».
            let _ = addrs.push(IpCidr::new(Ipv4Addr::new(10, 111, 0, 2).into(), 24));
            let _ = addrs.push(IpCidr::new(
                Ipv6Addr::new(0xfd00, 0x6d73, 0, 0, 0, 0, 0, 2).into(),
                64,
            ));
        });
        Self {
            host,
            filter,
            iface,
            device,
            sockets: SocketSet::new(Vec::new()),
            flows: HashMap::new(),
            by_endpoints: HashMap::new(),
            next_token: TOKEN_BASE,
            scratch: vec![0u8; CHUNK],
        }
    }

    pub(crate) fn set_filter(&mut self, filter: Arc<Filter>) {
        self.filter = filter;
    }

    pub(crate) fn has_flows(&self) -> bool {
        !self.flows.is_empty()
    }

    /// Délai avant le prochain temporisateur TCP (retransmission, TIME-WAIT…).
    pub(crate) fn poll_delay(&mut self) -> Option<std::time::Duration> {
        self.iface
            .poll_delay(SmolInstant::now(), &self.sockets)
            .map(|d| std::time::Duration::from_micros(d.total_micros()))
    }

    /// Paquet TCP sortant d'une app ; un SYN vers une nouvelle destination ouvre d'abord le socket amont.
    pub(crate) fn ingest(
        &mut self,
        registry: &Registry,
        raw: &[u8],
        segment: &Segment,
        blocked: &HashSet<u32>,
        stats: &Stats,
    ) {
        let is_new_syn = segment.flags & tcp::SYN != 0 && segment.flags & tcp::ACK == 0;
        if is_new_syn && !self.by_endpoints.contains_key(&(segment.src, segment.dst)) {
            // HTTPS vers un résolveur DoH connu (liste signée) : RST avant tout appel Binder ou socket amont.
            if segment.dst.port() == HTTPS_PORT && self.filter.blocks_ip(segment.dst.ip()) {
                stats.add(Counter::IpBlocked, 1);
                self.device.rx.push_back(raw.to_vec());
                return;
            }
            // Attribution une seule fois, au SYN : l'UID reste dans l'entrée de flux.
            let uid = self.host.owner_uid(tcp::PROTO, segment.src, segment.dst);
            if uid.is_some_and(|u| blocked.contains(&u)) {
                // Sans listener, smoltcp répond RST : l'app privée d'Internet échoue aussitôt.
                stats.add(Counter::AppBlocked, 1);
                self.device.rx.push_back(raw.to_vec());
                return;
            }
            match self.open(registry, segment.src, segment.dst, uid) {
                Ok(()) => stats.add(Counter::TcpFlows, 1),
                Err(_) => {
                    // Sans listener, smoltcp répond RST au SYN : l'app échoue vite au lieu d'attendre.
                    stats.add(Counter::TcpFailures, 1);
                }
            }
        }
        self.device.rx.push_back(raw.to_vec());
    }

    fn open(
        &mut self,
        registry: &Registry,
        client: SocketAddr,
        remote: SocketAddr,
        uid: Option<u32>,
    ) -> io::Result<()> {
        if self.flows.len() >= MAX_FLOWS {
            return Err(io::Error::from(ErrorKind::OutOfMemory));
        }
        let socket = Socket::new(
            Domain::for_address(remote),
            Type::STREAM,
            Some(Protocol::TCP),
        )?;
        // Sans protect(), la connexion amont repartirait dans le tunnel : jamais de connexion non protégée.
        if !self.host.protect(socket.as_raw_fd()) {
            return Err(io::Error::from(ErrorKind::PermissionDenied));
        }
        socket.set_nonblocking(true)?;
        socket.set_tcp_nodelay(true)?;
        match socket.connect(&remote.into()) {
            Ok(()) => {}
            // Connexion non bloquante : EINPROGRESS est le cas nominal, l'issue arrive par epoll.
            Err(e) if e.raw_os_error() == Some(libc::EINPROGRESS) => {}
            Err(e) => return Err(e),
        }
        let mut upstream = TcpStream::from_std(std::net::TcpStream::from(socket));
        let token = self.next_token;
        registry.register(
            &mut upstream,
            Token(token),
            Interest::READABLE | Interest::WRITABLE,
        )?;

        let mut listener = smol::Socket::new(
            smol::SocketBuffer::new(vec![0u8; SOCKET_BUFFER]),
            smol::SocketBuffer::new(vec![0u8; SOCKET_BUFFER]),
        );
        // Sans ACK de l'app pendant 60 s (poignée de main abandonnée, pair disparu), smoltcp ferme le flux.
        listener.set_timeout(Some(smoltcp::time::Duration::from_secs(60)));
        let endpoint = IpListenEndpoint {
            addr: Some(remote.ip().into()),
            port: remote.port(),
        };
        if listener.listen(endpoint).is_err() {
            let _ = registry.deregister(&mut upstream);
            return Err(io::Error::from(ErrorKind::InvalidInput));
        }
        let handle = self.sockets.add(listener);
        self.next_token += 1;
        self.by_endpoints.insert((client, remote), token);
        self.flows.insert(
            token,
            Flow {
                handle,
                inspected: false,
                uid,
                upstream,
                client,
                remote,
                connected: false,
                readable: false,
                writable: false,
                to_upstream: Vec::new(),
                to_client: Vec::new(),
                upstream_eof: false,
                upstream_shut: false,
                failed: false,
            },
        );
        Ok(())
    }

    /// Coupe (RST) les connexions des apps nouvellement privées d'Internet ; le nettoyage suit au prochain `run`.
    pub(crate) fn apply_policy(&mut self, blocked: &HashSet<u32>) {
        for flow in self.flows.values_mut() {
            if flow.uid.is_some_and(|u| blocked.contains(&u)) {
                flow.failed = true;
            }
        }
    }

    pub(crate) fn upstream_event(&mut self, token: usize, readable: bool, writable: bool) {
        if let Some(flow) = self.flows.get_mut(&token) {
            flow.readable |= readable;
            flow.writable |= writable;
        }
    }

    /// Fait avancer smoltcp et tous les flux ; les paquets à écrire dans le TUN sont passés à `emit`.
    pub(crate) fn run(&mut self, registry: &Registry, stats: &Stats, mut emit: impl FnMut(&[u8])) {
        let now = SmolInstant::now();
        self.iface.poll(now, &mut self.device, &mut self.sockets);
        for flow in self.flows.values_mut() {
            pump(
                flow,
                self.sockets.get_mut::<smol::Socket>(flow.handle),
                &mut self.scratch,
                &self.filter,
                stats,
            );
        }
        self.iface.poll(now, &mut self.device, &mut self.sockets);
        self.reap(registry);
        for packet in self.device.tx.drain(..) {
            emit(&packet);
        }
    }

    fn reap(&mut self, registry: &Registry) {
        let finished: Vec<usize> = self
            .flows
            .iter()
            .filter(|(_, f)| {
                let state = self.sockets.get::<smol::Socket>(f.handle).state();
                matches!(state, smol::State::Closed | smol::State::TimeWait)
            })
            .map(|(&t, _)| t)
            .collect();
        for token in finished {
            if let Some(mut flow) = self.flows.remove(&token) {
                // Désinscription best effort : le fd est fermé juste après, epoll l'oublie de toute façon.
                let _ = registry.deregister(&mut flow.upstream);
                self.sockets.remove(flow.handle);
                self.by_endpoints.remove(&(flow.client, flow.remote));
            }
        }
    }
}

/// Avance un flux d'un pas dans les deux sens, sans jamais bloquer.
fn pump(
    flow: &mut Flow,
    socket: &mut smol::Socket<'static>,
    scratch: &mut [u8],
    filter: &Filter,
    stats: &Stats,
) {
    if flow.failed {
        socket.abort();
        return;
    }
    if !flow.connected {
        match flow.upstream.take_error() {
            Ok(None) if flow.upstream.peer_addr().is_ok() => {
                flow.connected = true;
                flow.readable = true;
                flow.writable = true;
            }
            Ok(None) => return,
            // Connexion amont refusée ou injoignable : RST côté app.
            Ok(Some(_)) | Err(_) => {
                flow.failed = true;
                socket.abort();
                return;
            }
        }
    }

    // Avant l'établissement, may_recv()/may_send() sont faux : les lire ici fermerait la connexion à tort.
    if matches!(
        socket.state(),
        smol::State::Listen | smol::State::SynReceived | smol::State::SynSent
    ) {
        return;
    }

    // App → serveur, seulement une fois le SNI jugé ; l'autre sens continue (protocoles où le serveur parle d'abord).
    let may_forward = flow.inspected || inspect(flow, socket, scratch, filter, stats);
    if flow.failed {
        return;
    }
    if may_forward {
        refill_from_app(flow, socket, scratch);
        while flow.writable && !flow.to_upstream.is_empty() {
            match flow.upstream.write(&flow.to_upstream) {
                Ok(n) => {
                    flow.to_upstream.drain(..n);
                    refill_from_app(flow, socket, scratch);
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => flow.writable = false,
                Err(e) if e.kind() == ErrorKind::Interrupted => {}
                Err(_) => {
                    flow.failed = true;
                    socket.abort();
                    return;
                }
            }
        }
        if !socket.may_recv() && flow.to_upstream.is_empty() && !flow.upstream_shut {
            // L'app a fermé son sens d'émission (FIN) : on le propage au serveur.
            let _ = flow.upstream.shutdown(Shutdown::Write);
            flow.upstream_shut = true;
        }
    }

    // Serveur → app.
    loop {
        if !flow.to_client.is_empty() {
            if !socket.can_send() {
                break;
            }
            match socket.send_slice(&flow.to_client) {
                Ok(n) if n > 0 => {
                    flow.to_client.drain(..n);
                }
                _ => break,
            }
            continue;
        }
        if !flow.readable || flow.upstream_eof {
            break;
        }
        match flow.upstream.read(scratch) {
            Ok(0) => flow.upstream_eof = true,
            Ok(n) => flow
                .to_client
                .extend_from_slice(scratch.get(..n).unwrap_or_default()),
            Err(e) if e.kind() == ErrorKind::WouldBlock => flow.readable = false,
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(_) => {
                flow.failed = true;
                socket.abort();
                return;
            }
        }
    }
    if flow.upstream_eof && flow.to_client.is_empty() && socket.may_send() {
        socket.close();
    }
}

/// Accumule le début du flux de l'app jusqu'à pouvoir lire le SNI d'un ClientHello. Renvoie `true` une fois
/// le flux autorisé ; un nom bloqué (liste ou DoH connu) coupe la connexion avant tout octet envoyé au serveur.
/// Un ClientHello illisible ou réparti sur plusieurs enregistrements TLS passe : le serveur le rejettera s'il
/// est forgé, et le filtrage DNS reste en amont.
fn inspect(
    flow: &mut Flow,
    socket: &mut smol::Socket<'static>,
    scratch: &mut [u8],
    filter: &Filter,
    stats: &Stats,
) -> bool {
    while socket.can_recv() && flow.to_upstream.len() < tls::MAX_RECORD {
        let room = (tls::MAX_RECORD - flow.to_upstream.len()).min(scratch.len());
        let Some(window) = scratch.get_mut(..room) else {
            break;
        };
        match socket.recv_slice(window) {
            Ok(n) if n > 0 => flow
                .to_upstream
                .extend_from_slice(window.get(..n).unwrap_or_default()),
            _ => break,
        }
    }
    match tls::client_hello_sni(&flow.to_upstream) {
        Ok(Sni::Host(host)) if filter.blocks(&host) => {
            stats.add(Counter::SniBlocked, 1);
            flow.failed = true;
            socket.abort();
            false
        }
        Err(TlsError::Incomplete)
            if flow.to_upstream.len() < tls::MAX_RECORD && socket.may_recv() =>
        {
            false
        }
        _ => {
            flow.inspected = true;
            true
        }
    }
}

/// Un seul bloc en attente vers le serveur à la fois : la fenêtre TCP de l'app absorbe la contre-pression.
fn refill_from_app(flow: &mut Flow, socket: &mut smol::Socket<'static>, scratch: &mut [u8]) {
    if flow.to_upstream.is_empty()
        && socket.can_recv()
        && let Ok(n) = socket.recv_slice(scratch)
    {
        flow.to_upstream
            .extend_from_slice(scratch.get(..n).unwrap_or_default());
    }
}

/// Une connexion TCP amont ne doit jamais viser les adresses virtuelles du tunnel.
pub(crate) fn is_tunnel_address(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, c, _] = v4.octets();
            [a, b, c] == [10, 111, 0]
        }
        IpAddr::V6(v6) => {
            let [a, b, c, d, ..] = v6.segments();
            [a, b, c, d] == [0xfd00, 0x6d73, 0, 0]
        }
    }
}
