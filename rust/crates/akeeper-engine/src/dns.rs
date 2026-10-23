use std::collections::HashMap;
use std::io::{self, ErrorKind};
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use akeeper_proto::dns::{self, Query, Rcode};
use akeeper_proto::udp::Datagram;

use std::sync::Arc;

use crate::filter::Filter;
use crate::stats::{Counter, Stats};

pub const MAX_UPSTREAMS: usize = 4;
const MAX_PENDING: usize = 1024;
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(5);
/// Canari de Firefox : NXDOMAIN désactive son DoH par défaut.
const DOH_CANARY: &str = "use-application-dns.net";

pub enum Outcome {
    /// Réponse immédiate à renvoyer au client dans le TUN.
    Reply(Vec<u8>),
    Forwarded,
    Dropped,
}

struct Pending {
    client: SocketAddr,
    server: SocketAddr,
    client_id: u16,
    question: Vec<u8>,
    deadline: Instant,
}

pub struct Resolver {
    filter: Arc<Filter>,
    upstreams: [Option<UdpSocket>; MAX_UPSTREAMS],
    next_upstream: usize,
    pending: HashMap<u16, Pending>,
}

impl Resolver {
    pub(crate) fn new(filter: Arc<Filter>) -> Self {
        Self {
            filter,
            upstreams: Default::default(),
            next_upstream: 0,
            pending: HashMap::new(),
        }
    }

    pub(crate) fn set_filter(&mut self, filter: Arc<Filter>) {
        self.filter = filter;
    }

    pub fn upstream(&self, slot: usize) -> Option<&UdpSocket> {
        self.upstreams.get(slot)?.as_ref()
    }

    /// Remplace le socket du slot ; l'ancien est fermé au retour.
    pub fn set_upstream(&mut self, slot: usize, socket: Option<UdpSocket>) -> Option<UdpSocket> {
        self.upstreams
            .get_mut(slot)
            .and_then(|s| std::mem::replace(s, socket))
    }

    pub fn has_pending(&self) -> bool {
        !self.pending.is_empty()
    }

    pub fn expire(&mut self, now: Instant, stats: &Stats) {
        let before = self.pending.len();
        self.pending.retain(|_, p| p.deadline > now);
        stats.add(
            Counter::DnsUpstreamFailures,
            (before - self.pending.len()) as u64,
        );
    }

    pub fn handle_query(
        &mut self,
        datagram: &Datagram<'_>,
        now: Instant,
        stats: &Stats,
    ) -> Outcome {
        let Ok(query) = dns::parse_query(datagram.payload) else {
            stats.add(Counter::Malformed, 1);
            return Outcome::Dropped;
        };
        stats.add(Counter::DnsQueries, 1);

        // HTTPS/SVCB porte la configuration ECH : sans elle, le SNI reste lisible.
        if query.qtype == dns::TYPE_HTTPS {
            return Outcome::Reply(negative(&query, Rcode::NoError));
        }
        if query.name == DOH_CANARY || self.filter.blocks(&query.name) {
            stats.add(Counter::DnsBlocked, 1);
            return Outcome::Reply(negative(&query, Rcode::NxDomain));
        }
        if self.forward(&query, datagram, now) {
            Outcome::Forwarded
        } else {
            stats.add(Counter::DnsUpstreamFailures, 1);
            Outcome::Reply(negative(&query, Rcode::ServFail))
        }
    }

    fn forward(&mut self, query: &Query<'_>, datagram: &Datagram<'_>, now: Instant) -> bool {
        if self.pending.len() >= MAX_PENDING {
            self.pending.retain(|_, p| p.deadline > now);
            if self.pending.len() >= MAX_PENDING {
                return false;
            }
        }
        // Identifiant amont aléatoire : un identifiant prévisible faciliterait l'empoisonnement hors chemin.
        let Some(id) = (0..8)
            .filter_map(|_| random_id())
            .find(|id| !self.pending.contains_key(id))
        else {
            return false;
        };
        let mut wire = datagram.payload.to_vec();
        dns::set_id(&mut wire, id);

        for attempt in 0..MAX_UPSTREAMS {
            let slot = (self.next_upstream + attempt) % MAX_UPSTREAMS;
            let Some(Some(socket)) = self.upstreams.get(slot) else {
                continue;
            };
            if socket.send(&wire).is_ok() {
                self.next_upstream = (slot + 1) % MAX_UPSTREAMS;
                self.pending.insert(
                    id,
                    Pending {
                        client: datagram.src,
                        server: datagram.dst,
                        client_id: query.id,
                        question: query.question.to_vec(),
                        deadline: now + UPSTREAM_TIMEOUT,
                    },
                );
                return true;
            }
        }
        false
    }

    /// Lit toutes les réponses disponibles sur un slot ; chaque réponse acceptée est renvoyée avec (serveur, client).
    pub fn drain_upstream(
        &mut self,
        slot: usize,
        buf: &mut [u8],
        mut deliver: impl FnMut(SocketAddr, SocketAddr, &[u8]),
    ) -> io::Result<()> {
        loop {
            let Some(socket) = self.upstream(slot) else {
                return Ok(());
            };
            let n = match socket.recv(buf) {
                Ok(n) => n,
                Err(e) if e.kind() == ErrorKind::WouldBlock => return Ok(()),
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                // ICMP port unreachable remonte ici en ConnectionRefused : le timeout s'en charge.
                Err(e) if e.kind() == ErrorKind::ConnectionRefused => continue,
                Err(e) => return Err(e),
            };
            let Some(msg) = buf.get_mut(..n) else {
                continue;
            };
            let Ok((id, question)) = dns::parse_response_key(msg) else {
                continue;
            };
            // Identifiant et question doivent correspondre : sinon réponse usurpée ou tardive, ignorée.
            if self.pending.get(&id).is_none_or(|p| p.question != question) {
                continue;
            }
            if let Some(pending) = self.pending.remove(&id) {
                dns::set_id(msg, pending.client_id);
                deliver(pending.server, pending.client, msg);
            }
        }
    }
}

fn negative(query: &Query<'_>, rcode: Rcode) -> Vec<u8> {
    let mut out = Vec::with_capacity(12 + query.question.len());
    dns::negative_response(query, rcode, &mut out);
    out
}

fn random_id() -> Option<u16> {
    let mut b = [0u8; 2];
    getrandom::fill(&mut b).ok()?;
    Some(u16::from_be_bytes(b))
}
