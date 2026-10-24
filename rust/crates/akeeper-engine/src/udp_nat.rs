use std::collections::{HashMap, HashSet};
use std::io::{self, ErrorKind};
use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::time::{Duration, Instant};

use akeeper_proto::udp::Datagram;
use mio::net::UdpSocket;
use mio::{Interest, Registry, Token};

use akeeper_proto::ip::PROTO_UDP;

use crate::SharedHost;
use crate::events::{EventKind, EventLog, REASON_APP};
use crate::stats::{Counter, Stats};

/// Premier jeton mio réservé aux flux UDP ; ceux d'en dessous appartiennent au TUN, au réveil et aux DNS amont.
pub(crate) const TOKEN_BASE: usize = 16;
// Borne les fd ouverts : au-delà, un nouveau flux est refusé plutôt que d'épuiser la table de fd du processus.
const MAX_FLOWS: usize = 1024;
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);

pub(crate) enum Sent {
    Relayed,
    /// L'app émettrice est privée d'Internet.
    Blocked,
    Failed,
}

struct Flow {
    socket: UdpSocket,
    uid: Option<u32>,
    client: SocketAddr,
    remote: SocketAddr,
    last_active: Instant,
}

/// NAT UDP : un socket protégé et connecté par couple (client, destination).
pub(crate) struct UdpNat {
    host: SharedHost,
    events: Arc<EventLog>,
    by_endpoints: HashMap<(SocketAddr, SocketAddr), usize>,
    flows: HashMap<usize, Flow>,
    next_token: usize,
}

impl UdpNat {
    pub(crate) fn new(host: SharedHost, events: Arc<EventLog>) -> Self {
        Self {
            host,
            events,
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
        blocked: &HashSet<u32>,
        now: Instant,
        stats: &Stats,
    ) -> Sent {
        let key = (datagram.src, datagram.dst);
        let token = match self.by_endpoints.get(&key) {
            Some(&token) => token,
            None => {
                // Attribution une seule fois, à l'ouverture : l'UID reste dans l'entrée de flux.
                let uid = self.host.owner_uid(PROTO_UDP, datagram.src, datagram.dst);
                if uid.is_some_and(|u| blocked.contains(&u)) {
                    stats.add(Counter::AppBlocked, 1);
                    self.events.record(
                        EventKind::App,
                        true,
                        REASON_APP,
                        uid,
                        &datagram.dst.ip().to_string(),
                    );
                    return Sent::Blocked;
                }
                match self.open(registry, datagram, uid, now) {
                    Ok(token) => token,
                    Err(_) => {
                        stats.add(Counter::UdpNatFailures, 1);
                        return Sent::Failed;
                    }
                }
            }
        };
        if let Some(flow) = self.flows.get_mut(&token) {
            flow.last_active = now;
            // Tampon d'émission plein : perte assumée, comme sur un vrai lien UDP.
            if flow.socket.send(datagram.payload).is_ok() {
                self.events.traffic(flow.uid, datagram.payload.len(), 0);
            }
        }
        Sent::Relayed
    }

    /// Ferme les flux des apps nouvellement privées d'Internet.
    pub(crate) fn apply_policy(&mut self, registry: &Registry, blocked: &HashSet<u32>) {
        self.remove_where(registry, |flow| {
            flow.uid.is_some_and(|u| blocked.contains(&u))
        });
    }

    fn open(
        &mut self,
        registry: &Registry,
        datagram: &Datagram<'_>,
        uid: Option<u32>,
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
        if !self.host.protect(socket.as_raw_fd()) {
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
                uid,
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
                        self.events.traffic(flow.uid, 0, n);
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
        self.remove_where(registry, |flow| {
            now.duration_since(flow.last_active) >= IDLE_TIMEOUT
        });
    }

    fn remove_where(&mut self, registry: &Registry, condition: impl Fn(&Flow) -> bool) {
        let doomed: Vec<usize> = self
            .flows
            .iter()
            .filter(|(_, f)| condition(f))
            .map(|(&t, _)| t)
            .collect();
        for token in doomed {
            if let Some(mut flow) = self.flows.remove(&token) {
                // Désinscription best effort : le fd est fermé juste après, epoll l'oublie de toute façon.
                let _ = registry.deregister(&mut flow.socket);
                self.by_endpoints.remove(&(flow.client, flow.remote));
            }
        }
    }
}
