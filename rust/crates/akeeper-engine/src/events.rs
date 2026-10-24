//! Journal d'activité du moteur : événements bornés, regroupés quand ils se répètent, vidés par Java toutes les
//! secondes. Le moteur ne garde rien d'autre : l'historique vit dans la base chiffrée côté Java.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Au-delà, les plus anciens événements sont perdus : Java vide le tampon chaque seconde.
pub const MAX_EVENTS: usize = 4096;
/// Deux événements identiques à moins de 10 s l'un de l'autre n'en font qu'un, avec un compteur.
const COALESCE_WINDOW_MS: u64 = 10_000;
const COALESCE_SCAN: usize = 64;
const MAX_NAME: usize = 253;
/// Code de raison d'un refus par le pare-feu par app (les autres viennent de `Reason::code`).
pub const REASON_APP: u8 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EventKind {
    /// Requête DNS ; `name` est le domaine demandé.
    Dns = 1,
    /// Connexion TLS refusée d'après son SNI ; `name` est le domaine.
    Sni = 2,
    /// Connexion refusée vers une adresse de résolveur DoH ; `name` est l'adresse.
    Ip = 3,
    /// Connexion refusée à une app privée d'Internet ; `name` est l'adresse visée.
    App = 4,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    pub ts_ms: u64,
    pub kind: EventKind,
    pub blocked: bool,
    /// 0 pour un événement autorisé.
    pub reason: u8,
    pub uid: Option<u32>,
    pub name: String,
    pub count: u32,
}

#[derive(Default)]
pub struct EventLog {
    enabled: AtomicBool,
    queue: Mutex<VecDeque<Event>>,
}

impl EventLog {
    /// Désactivé, le journal ne stocke rien et les appelants n'ont pas à chercher le propriétaire d'un flux.
    pub fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::Relaxed);
        if !enabled && let Ok(mut queue) = self.queue.lock() {
            queue.clear();
        }
    }

    pub fn enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    pub fn record(&self, kind: EventKind, blocked: bool, reason: u8, uid: Option<u32>, name: &str) {
        if !self.enabled() {
            return;
        }
        let name: String = name.chars().take(MAX_NAME).collect();
        let ts_ms = now_ms();
        let Ok(mut queue) = self.queue.lock() else {
            return;
        };
        let repeated = queue.iter_mut().rev().take(COALESCE_SCAN).find(|e| {
            e.kind == kind
                && e.blocked == blocked
                && e.reason == reason
                && e.uid == uid
                && e.name == name
                && ts_ms.saturating_sub(e.ts_ms) <= COALESCE_WINDOW_MS
        });
        if let Some(event) = repeated {
            event.count = event.count.saturating_add(1);
            return;
        }
        if queue.len() >= MAX_EVENTS {
            queue.pop_front();
        }
        queue.push_back(Event {
            ts_ms,
            kind,
            blocked,
            reason,
            uid,
            name,
            count: 1,
        });
    }

    pub fn drain(&self) -> Vec<Event> {
        self.queue
            .lock()
            .map(|mut queue| queue.drain(..).collect())
            .unwrap_or_default()
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// Format transmis à Java, gros-boutiste, événements mis bout à bout :
/// `ts u64 · kind u8 · flags u8 (bit 0 : bloqué) · reason u8 · 0 u8 · uid i32 (-1 inconnu) · count u32 ·
/// name_len u16 · name`.
pub fn encode(events: &[Event]) -> Vec<u8> {
    let mut out = Vec::new();
    for event in events {
        out.extend_from_slice(&event.ts_ms.to_be_bytes());
        out.extend_from_slice(&[event.kind as u8, u8::from(event.blocked), event.reason, 0]);
        let uid = event.uid.and_then(|u| i32::try_from(u).ok()).unwrap_or(-1);
        out.extend_from_slice(&uid.to_be_bytes());
        out.extend_from_slice(&event.count.to_be_bytes());
        let name = event.name.as_bytes();
        let len = u16::try_from(name.len()).unwrap_or(u16::MAX);
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(name.get(..usize::from(len)).unwrap_or_default());
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn enabled() -> EventLog {
        let log = EventLog::default();
        log.set_enabled(true);
        log
    }

    #[test]
    fn records_nothing_while_disabled_and_forgets_what_it_held() {
        let log = EventLog::default();
        log.record(EventKind::Dns, true, 17, Some(10_001), "ads.example");
        assert!(log.drain().is_empty());

        log.set_enabled(true);
        log.record(EventKind::Dns, true, 17, Some(10_001), "ads.example");
        log.set_enabled(false);
        assert!(log.drain().is_empty(), "désactiver vide le tampon");
    }

    #[test]
    fn repeated_events_are_merged_with_a_count() {
        let log = enabled();
        for _ in 0..3 {
            log.record(EventKind::Dns, true, 17, Some(10_001), "ads.example");
        }
        log.record(EventKind::Dns, true, 17, Some(10_002), "ads.example");
        log.record(EventKind::Dns, false, 0, Some(10_001), "ads.example");

        let events = log.drain();
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].count, 3);
        assert_eq!((events[1].uid, events[1].count), (Some(10_002), 1));
        assert!(!events[2].blocked);
        assert!(log.drain().is_empty());
    }

    #[test]
    fn keeps_only_the_most_recent_events_when_full() {
        let log = enabled();
        for i in 0..MAX_EVENTS + 10 {
            log.record(EventKind::Dns, false, 0, None, &format!("host{i}.example"));
        }
        let events = log.drain();
        assert_eq!(events.len(), MAX_EVENTS);
        assert_eq!(events[0].name, "host10.example");
    }

    #[test]
    fn truncates_overlong_names() {
        let log = enabled();
        log.record(EventKind::Ip, true, 2, None, &"a".repeat(400));
        assert_eq!(log.drain()[0].name.len(), MAX_NAME);
    }

    #[test]
    fn encodes_to_the_documented_layout() {
        let events = [Event {
            ts_ms: 0x0102_0304_0506_0708,
            kind: EventKind::Sni,
            blocked: true,
            reason: 17,
            uid: Some(10_123),
            name: "ads.example".into(),
            count: 2,
        }];
        let bytes = encode(&events);
        assert_eq!(&bytes[..8], &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(&bytes[8..12], &[2, 1, 17, 0]);
        assert_eq!(
            i32::from_be_bytes(bytes[12..16].try_into().unwrap()),
            10_123
        );
        assert_eq!(u32::from_be_bytes(bytes[16..20].try_into().unwrap()), 2);
        assert_eq!(u16::from_be_bytes(bytes[20..22].try_into().unwrap()), 11);
        assert_eq!(&bytes[22..], b"ads.example");
        let unknown = Event {
            uid: None,
            ..events[0].clone()
        };
        assert_eq!(&encode(&[unknown])[12..16], &(-1i32).to_be_bytes());
    }
}
