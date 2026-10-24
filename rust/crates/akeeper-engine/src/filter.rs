use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use akeeper_proto::bundle::{self, BundleError, category, kind};

use crate::Blocklist;

/// Points d'accès DoH publics les plus répandus. Repli embarqué, utilisé seulement tant qu'aucun bundle signé
/// ne fournit sa propre liste DoH.
const DOH_HOSTS: &str = "
cloudflare-dns.com
one.one.one.one
dns.google
dns.quad9.net
dns9.quad9.net
dns10.quad9.net
dns11.quad9.net
doh.opendns.com
doh.familyshield.opendns.com
dns.adguard-dns.com
dns.adguard.com
dns.nextdns.io
doh.cleanbrowsing.org
doh.mullvad.net
dns.mullvad.net
freedns.controld.com
dns.controld.com
doh.dns.sb
dns.alidns.com
doh.pub
";

#[derive(Debug)]
pub enum RulesError {
    Envelope(BundleError),
    Fst(fst::Error),
}

impl From<BundleError> for RulesError {
    fn from(e: BundleError) -> Self {
        Self::Envelope(e)
    }
}

impl From<fst::Error> for RulesError {
    fn from(e: fst::Error) -> Self {
        Self::Fst(e)
    }
}

/// Contenu d'un bundle de règles. La signature a déjà été vérifiée côté Java (`BundleVerifier`) sur ce même fichier.
pub struct BundleRules {
    version: u64,
    domains: Vec<Blocklist>,
    doh_domains: Option<Blocklist>,
    doh_ips: Vec<Cidr>,
}

impl BundleRules {
    pub fn parse(bytes: &[u8]) -> Result<Self, RulesError> {
        let envelope = bundle::parse(bytes)?;
        let mut rules = Self {
            version: envelope.version,
            domains: Vec::new(),
            doh_domains: None,
            doh_ips: Vec::new(),
        };
        for section in &envelope.sections {
            match (section.kind, section.category) {
                (kind::DOMAINS, category::DOH) => {
                    rules.doh_domains = Some(Blocklist::from_fst(section.data.to_vec())?);
                }
                (kind::DOMAINS, _) => rules
                    .domains
                    .push(Blocklist::from_fst(section.data.to_vec())?),
                (kind::CIDRS, category::DOH) => rules.doh_ips.extend(
                    bundle::cidrs(section.data)?
                        .into_iter()
                        .map(|(prefix, addr)| Cidr::new(prefix, u128::from_be_bytes(addr))),
                ),
                // Type ou catégorie inconnus (bundle plus récent que l'app) et NOTICE : sans effet sur le filtrage.
                _ => {}
            }
        }
        Ok(rules)
    }

    pub fn version(&self) -> u64 {
        self.version
    }
}

#[derive(Debug, Clone, Copy)]
struct Cidr {
    net: u128,
    mask: u128,
}

impl Cidr {
    fn new(prefix: u8, addr: u128) -> Self {
        let mask = u128::MAX
            .checked_shl(u32::from(128 - prefix.min(128)))
            .unwrap_or(0);
        Self {
            net: addr & mask,
            mask,
        }
    }

    fn contains(&self, addr: u128) -> bool {
        addr & self.mask == self.net
    }
}

/// Noms et adresses bloqués, partagés par le résolveur DNS et l'inspection TCP. Construit hors du thread moteur
/// puis remplacé d'un bloc (`Engine::set_filter`).
pub struct Filter {
    user: Blocklist,
    domains: Vec<Blocklist>,
    doh: Blocklist,
    doh_ips: Vec<Cidr>,
    /// Pause demandée par l'utilisateur : plus aucun nom ni adresse n'est bloqué. Partagé avec le moteur, qui le
    /// conserve d'un filtre au suivant quand les règles sont remplacées.
    paused: Arc<AtomicBool>,
}

impl Filter {
    pub fn new(user: Blocklist, bundle: Option<BundleRules>) -> Self {
        match bundle {
            Some(b) => Self {
                user,
                domains: b.domains,
                doh: b
                    .doh_domains
                    .unwrap_or_else(|| Blocklist::from_domains(DOH_HOSTS)),
                doh_ips: b.doh_ips,
                paused: Arc::default(),
            },
            None => Self {
                user,
                domains: Vec::new(),
                doh: Blocklist::from_domains(DOH_HOSTS),
                doh_ips: Vec::new(),
                paused: Arc::default(),
            },
        }
    }

    pub(crate) fn share_pause(&mut self, paused: Arc<AtomicBool>) {
        self.paused = paused;
    }

    fn is_paused(&self) -> bool {
        self.paused.load(Ordering::Relaxed)
    }

    /// `name` est déjà en minuscules (normalisé par le parseur DNS ou TLS).
    pub(crate) fn blocks(&self, name: &str) -> bool {
        !self.is_paused()
            && (self.user.blocks(name)
                || self.doh.blocks(name)
                || self.domains.iter().any(|list| list.blocks(name)))
    }

    /// Adresse d'un résolveur DoH connu. Parcours linéaire : quelques centaines de plages, une fois par flux.
    pub(crate) fn blocks_ip(&self, ip: IpAddr) -> bool {
        if self.is_paused() {
            return false;
        }
        let addr = match ip {
            IpAddr::V4(v4) => u128::from(v4.to_ipv6_mapped()),
            IpAddr::V6(v6) => u128::from(v6),
        };
        self.doh_ips.iter().any(|cidr| cidr.contains(addr))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
pub(crate) mod tests {
    use super::*;
    use akeeper_proto::bundle::{SIGNATURE_LEN, Section};
    use std::net::Ipv4Addr;

    /// Bundle de test (signature factice : la vérification est faite côté Java).
    pub(crate) fn bundle_bytes(
        ads: &str,
        doh: Option<&str>,
        doh_cidrs: &[(u8, IpAddr)],
    ) -> Vec<u8> {
        let ads = Blocklist::from_domains(ads);
        let doh = doh.map(Blocklist::from_domains);
        let cidrs: Vec<u8> = doh_cidrs
            .iter()
            .flat_map(|&(prefix, ip)| {
                let (prefix, addr) = match ip {
                    IpAddr::V4(v4) => (prefix + 96, v4.to_ipv6_mapped().octets()),
                    IpAddr::V6(v6) => (prefix, v6.octets()),
                };
                std::iter::once(prefix).chain(addr)
            })
            .collect();
        let mut sections = vec![
            Section {
                kind: kind::DOMAINS,
                category: category::ADS,
                data: ads.as_bytes(),
            },
            Section {
                kind: kind::CIDRS,
                category: category::DOH,
                data: &cidrs,
            },
            Section {
                kind: kind::NOTICE,
                category: 0,
                data: b"HaGeZi GPL-3.0",
            },
        ];
        if let Some(doh) = &doh {
            sections.push(Section {
                kind: kind::DOMAINS,
                category: category::DOH,
                data: doh.as_bytes(),
            });
        }
        let mut bytes = bundle::signed_message(0, 7, 0, &sections).unwrap();
        bytes.extend_from_slice(&[0; SIGNATURE_LEN]);
        bytes
    }

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn blocks_user_list_and_embedded_doh_without_bundle() {
        let filter = Filter::new(Blocklist::from_domains("ads.example.net"), None);
        assert!(filter.blocks("cdn.ads.example.net"));
        assert!(filter.blocks("dns.google"));
        assert!(filter.blocks("mozilla.cloudflare-dns.com"));
        assert!(!filter.blocks("www.google.com"));
        assert!(!filter.blocks_ip(v4(1, 1, 1, 1)));
    }

    #[test]
    fn bundle_adds_categories_doh_names_and_addresses() {
        let bytes = bundle_bytes(
            "tracker.example",
            Some("doh.example.org"),
            &[
                (24, v4(1, 1, 1, 0)),
                (128, "2606:4700:4700::1111".parse().unwrap()),
            ],
        );
        let rules = BundleRules::parse(&bytes).unwrap();
        assert_eq!(rules.version(), 7);
        let filter = Filter::new(Blocklist::from_domains("mine.example"), Some(rules));
        assert!(filter.blocks("mine.example"));
        assert!(filter.blocks("a.tracker.example"));
        assert!(filter.blocks("doh.example.org"));
        // La liste DoH du bundle remplace le repli embarqué.
        assert!(!filter.blocks("dns.google"));
        assert!(filter.blocks_ip(v4(1, 1, 1, 1)));
        assert!(!filter.blocks_ip(v4(1, 1, 2, 1)));
        assert!(filter.blocks_ip("2606:4700:4700::1111".parse().unwrap()));
        assert!(!filter.blocks_ip("2606:4700:4700::1001".parse().unwrap()));
    }

    #[test]
    fn bundle_without_doh_names_keeps_embedded_fallback() {
        let rules = BundleRules::parse(&bundle_bytes("tracker.example", None, &[])).unwrap();
        assert!(Filter::new(Blocklist::empty(), Some(rules)).blocks("dns.google"));
    }

    #[test]
    fn rejects_corrupted_fst_section() {
        let mut bytes = bundle_bytes("tracker.example", None, &[]);
        // Premier octet de données de la première section (FST) : la somme de contrôle ne correspond plus.
        let fst_start = bundle::HEADER_LEN + 8 + 10;
        bytes[fst_start] ^= 0xff;
        assert!(BundleRules::parse(&bytes).is_err());
    }

    #[test]
    fn a_pause_lifts_every_block_and_a_resume_restores_it() {
        let bytes = bundle_bytes("tracker.example", None, &[(32, v4(192, 0, 2, 1))]);
        let mut filter = Filter::new(
            Blocklist::from_domains("mine.example"),
            Some(BundleRules::parse(&bytes).unwrap()),
        );
        let paused = Arc::new(AtomicBool::new(false));
        filter.share_pause(Arc::clone(&paused));
        assert!(
            filter.blocks("mine.example")
                && filter.blocks("a.tracker.example")
                && filter.blocks("dns.google")
        );
        assert!(filter.blocks_ip(v4(192, 0, 2, 1)));

        paused.store(true, Ordering::Relaxed);
        assert!(
            !filter.blocks("mine.example")
                && !filter.blocks("a.tracker.example")
                && !filter.blocks("dns.google")
        );
        assert!(!filter.blocks_ip(v4(192, 0, 2, 1)));

        paused.store(false, Ordering::Relaxed);
        assert!(filter.blocks("mine.example"));
    }

    /// La liste livrée dans l'APK : elle doit se charger et bloquer sans fausse alerte sur les sites courants.
    #[test]
    fn the_shipped_default_list_blocks_ad_domains_and_spares_common_sites() {
        let bytes = include_bytes!("../../../../rules/src/main/assets/default-rules.akrb");
        let rules = BundleRules::parse(bytes).unwrap();
        assert_eq!(rules.version(), 0);
        let filter = Filter::new(Blocklist::empty(), Some(rules));
        assert!(filter.blocks("googlesyndication.com"));
        assert!(filter.blocks("pagead2.googlesyndication.com"));
        for site in [
            "example.org",
            "wikipedia.org",
            "github.com",
            "www.google.com",
            "mozilla.org",
            "lemonde.fr",
        ] {
            assert!(!filter.blocks(site), "{site} ne doit pas être bloqué");
        }
    }

    #[test]
    fn prefix_zero_matches_everything() {
        assert!(Cidr::new(0, 0).contains(u128::MAX));
        assert!(Cidr::new(128, 5).contains(5));
        assert!(!Cidr::new(128, 5).contains(4));
    }
}
