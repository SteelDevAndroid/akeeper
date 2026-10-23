//! J0 : le moteur lit le TUN, compte et **abandonne** chaque paquet.
//! Tant qu'aucun verdict « autoriser » n'existe, rien ne ressort du tunnel (fail-closed par construction).

mod stats;

pub use stats::{Counter, Stats};

use std::fs::File;
use std::io::{self, ErrorKind, Read};
use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};

use akeeper_proto::ip;
use mio::unix::SourceFd;
use mio::{Events, Interest, Poll, Token, Waker};

const TUN: Token = Token(0);
const WAKE: Token = Token(1);
// Un datagramme TUN ne dépasse jamais 65 535 octets (longueur IP sur 16 bits).
const READ_BUFFER: usize = 65_535;

pub struct Engine {
    waker: Arc<Waker>,
    stopping: Arc<AtomicBool>,
    stats: Arc<Stats>,
    thread: Option<JoinHandle<io::Result<()>>>,
}

impl Engine {
    /// `tun` doit être en mode non bloquant : epoll est déclenché sur front, la boucle lit jusqu'à `WouldBlock`.
    pub fn start(tun: OwnedFd) -> io::Result<Self> {
        let poll = Poll::new()?;
        let waker = Arc::new(Waker::new(poll.registry(), WAKE)?);
        poll.registry()
            .register(&mut SourceFd(&tun.as_raw_fd()), TUN, Interest::READABLE)?;

        let stopping = Arc::new(AtomicBool::new(false));
        let stats = Arc::new(Stats::default());
        let thread = thread::Builder::new()
            .name("akeeper-engine".into())
            .spawn({
                let stopping = Arc::clone(&stopping);
                let stats = Arc::clone(&stats);
                move || run(poll, File::from(tun), &stopping, &stats)
            })?;

        Ok(Self {
            waker,
            stopping,
            stats,
            thread: Some(thread),
        })
    }

    pub fn stats(&self) -> &Stats {
        &self.stats
    }

    /// Bloque jusqu'à l'arrêt de la boucle ; le fd TUN est fermé à la sortie du thread.
    pub fn stop(mut self) -> io::Result<()> {
        self.shutdown()
    }

    fn shutdown(&mut self) -> io::Result<()> {
        let Some(thread) = self.thread.take() else {
            return Ok(());
        };
        self.stopping.store(true, Ordering::Release);
        self.waker.wake()?;
        thread
            .join()
            .map_err(|_| io::Error::other("le thread moteur a paniqué"))?
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        // Erreur déjà sans recours ici : le thread est arrêté ou mort, le fd est fermé dans les deux cas.
        let _ = self.shutdown();
    }
}

fn run(mut poll: Poll, mut tun: File, stopping: &AtomicBool, stats: &Stats) -> io::Result<()> {
    let mut events = Events::with_capacity(16);
    let mut buf = vec![0u8; READ_BUFFER];
    loop {
        match poll.poll(&mut events, None) {
            Ok(()) => {}
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
        if stopping.load(Ordering::Acquire) {
            return Ok(());
        }
        if events.iter().any(|e| e.token() == TUN) && !drain(&mut tun, &mut buf, stats)? {
            return Ok(());
        }
    }
}

/// Renvoie `false` quand le TUN est fermé côté système (révocation du VPN).
fn drain(tun: &mut File, buf: &mut [u8], stats: &Stats) -> io::Result<bool> {
    loop {
        match tun.read(buf) {
            Ok(0) => return Ok(false),
            Ok(n) => stats.record(
                buf.get(..n)
                    .map_or(Err(ip::ParseError::Truncated), ip::parse),
                n,
            ),
            Err(e) if e.kind() == ErrorKind::WouldBlock => return Ok(true),
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixDatagram;
    use std::time::{Duration, Instant};

    fn ipv4_udp() -> Vec<u8> {
        let mut p = vec![
            0x45,
            0,
            0,
            28,
            0,
            0,
            0,
            0,
            64,
            ip::PROTO_UDP,
            0,
            0,
            10,
            111,
            0,
            1,
            10,
            111,
            0,
            53,
        ];
        p.extend_from_slice(&[0; 8]);
        p
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

    // Une paire de sockets datagramme reproduit la sémantique du TUN : un paquet par lecture.
    fn fake_tun() -> (UnixDatagram, OwnedFd) {
        let (app, engine_side) = UnixDatagram::pair().unwrap();
        engine_side.set_nonblocking(true).unwrap();
        (app, OwnedFd::from(engine_side))
    }

    #[test]
    fn counts_and_drops_every_packet() {
        let (app, tun) = fake_tun();
        let engine = Engine::start(tun).unwrap();

        app.send(&ipv4_udp()).unwrap();
        app.send(&ipv4_udp()).unwrap();
        app.send(&[0x45, 0x00]).unwrap();

        wait_for(engine.stats(), Counter::Packets, 3);
        assert_eq!(engine.stats().get(Counter::Udp), 2);
        assert_eq!(engine.stats().get(Counter::Malformed), 1);
        assert_eq!(engine.stats().get(Counter::Bytes), 58);

        app.set_nonblocking(true).unwrap();
        let mut back = [0u8; 64];
        assert_eq!(
            app.recv(&mut back).unwrap_err().kind(),
            ErrorKind::WouldBlock
        );

        engine.stop().unwrap();
    }

    #[test]
    fn stops_promptly_while_idle() {
        let (_app, tun) = fake_tun();
        let engine = Engine::start(tun).unwrap();
        let started = Instant::now();
        engine.stop().unwrap();
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn exits_when_tun_is_closed() {
        // Un pipe signale la fermeture par une lecture de 0 octet, comme le TUN révoqué.
        let (reader, writer) = std::io::pipe().unwrap();
        let engine = Engine::start(OwnedFd::from(reader)).unwrap();
        drop(writer);
        let deadline = Instant::now() + Duration::from_secs(5);
        while !engine.thread.as_ref().unwrap().is_finished() {
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(5));
        }
        engine.stop().unwrap();
    }
}
