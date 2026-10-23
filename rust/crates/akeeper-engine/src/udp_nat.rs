use std::collections::HashMap;
use std::io::{self, ErrorKind};
use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::time::{Duration, Instant};

use akeeper_proto::udp::Datagram;
use mio::net::UdpSocket;
use mio::{Interest, Registry, Token};

use crate::Protector;
use crate::stats::{Counter, Stats};

/// Premier jeton mio réservé aux flux UDP ; ceux d'en dessous appartiennent au TUN, au réveil et aux DNS amont.
pub(crate) const TOKEN_BASE: usize = 16;
// Borne les fd ouverts : au-delà, un nouveau flux est refusé plutôt que d'épuiser la table de fd du processus.
const MAX_FLOWS: usize = 1024;
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);

struct Flow {
    socket: UdpSocket,
    client: SocketAddr,
    remote: SocketAddr,
    last_active: Instant,
}

/// NAT UDP : un socket protégé et connecté par couple (client, destination).
pub(crate) struct UdpNat {
    protector: Protector,
    by_endpoints: HashMap<(SocketAddr, SocketAddr), usize>,
    flows: HashMap<usize, Flow>,
    next_token: usize,
}

impl UdpNat {
    pub(crate) fn new(protector: Protector) -> Self {
        Self {
            protector,
            by_endpoints: HashMap::new(),
            flows: HashMap::new(),
            next_token: TOKEN_BASE,
        }
    }

    pub(crate) fn has_flows(&self) -> bool {
        !self.flows.is_empty()
    }

    pub(crate) fn send(
        &mut self,
        registry: &Registry,
        datagram: &Datagram<'_>,
        now: Instant,
        stats: &Stats,
    ) {
        let key = (datagram.src, datagram.dst);
        let token = match self.by_endpoints.get(&key) {
            Some(&token) => token,
            None => match self.open(registry, datagram, now) {
                Ok(token) => token,
                Err(_) => {
                    stats.add(Counter::UdpNatFailures, 1);
                    return;
                }
            },
        };
        if let Some(flow) = self.flows.get_mut(&token) {
            flow.last_active = now;
            // Tampon d'émission plein : perte assumée, comme sur un vrai lien UDP.
            let _ = flow.socket.send(datagram.payload);
        }
    }

    fn open(
        &mut self,
        registry: &Registry,
        datagram: &Datagram<'_>,
        now: Instant,
    ) -> io::Result<usize> {
        if self.flows.len() >= MAX_FLOWS {
            self.expire(registry, now);
            if self.flows.len() >= MAX_FLOWS {
                return Err(io::Error::from(ErrorKind::OutOfMemory));
            }
        }
        let socket = std::net::UdpSocket::bind(if datagram.dst.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        })?;
        // Sans protect(), le datagramme repartirait dans le tunnel : boucle infinie, jamais d'envoi non protégé.
        if !(self.protector)(socket.as_raw_fd()) {
            return Err(io::Error::from(ErrorKind::PermissionDenied));
        }
        socket.connect(datagram.dst)?;
        socket.set_nonblocking(true)?;
        let mut socket = UdpSocket::from_std(socket);
        let token = self.next_token;
        registry.register(&mut socket, Token(token), Interest::READABLE)?;
        self.next_token += 1;
        self.by_endpoints
            .insert((datagram.src, datagram.dst), token);
        self.flows.insert(
            token,
            Flow {
                socket,
                client: datagram.src,
                remote: datagram.dst,
                last_active: now,
            },
        );
        Ok(token)
    }

    /// Relaie vers le client toutes les réponses disponibles du flux `token`, sous la forme (source, client, charge utile).
    pub(crate) fn drain(
        &mut self,
        token: usize,
        buf: &mut [u8],
        now: Instant,
        mut deliver: impl FnMut(SocketAddr, SocketAddr, &[u8]),
    ) {
        let Some(flow) = self.flows.get_mut(&token) else {
            return;
        };
        loop {
            match flow.socket.recv(buf) {
                Ok(n) => {
                    flow.last_active = now;
                    if let Some(payload) = buf.get(..n) {
                        deliver(flow.remote, flow.client, payload);
                    }
                }
                Err(e) if e.kind() == ErrorKind::Interrupted => {}
                // ICMP « port inaccessible » distant : ignoré, l'application client gère son propre délai.
                Err(e) if e.kind() == ErrorKind::ConnectionRefused => {}
                Err(_) => return,
            }
        }
    }

    pub(crate) fn expire(&mut self, registry: &Registry, now: Instant) {
        let stale: Vec<usize> = self
            .flows
            .iter()
            .filter(|(_, f)| now.duration_since(f.last_active) >= IDLE_TIMEOUT)
            .map(|(&t, _)| t)
            .collect();
        for token in stale {
            if let Some(mut flow) = self.flows.remove(&token) {
                // Désinscription best effort : le fd est fermé juste après, epoll l'oublie de toute façon.
                let _ = registry.deregister(&mut flow.socket);
                self.by_endpoints.remove(&(flow.client, flow.remote));
            }
        }
    }
}
